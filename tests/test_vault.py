"""Vault and session-registry properties (build doc sections 8, 9.4, 10.1, 10.6).

Every test here asserts a *security* property, not an API shape. The set maps
one-to-one onto the crypto spec:

===============================  ==========================================
Property                          Test
===============================  ==========================================
Round-trip                        ``test_vault_entry_round_trip``
AAD binding                       ``test_aad_binding_*``
Cross-session non-determinism     ``test_cross_session_non_determinism``
Within-session determinism        ``test_within_session_determinism``
Destruction / erasure             ``test_destroy_*``
Collision re-derivation           ``test_token_id_collision_re_derivation``
Lookup latency                    ``test_lookup_latency_p99``
Expiry                            ``test_expired_session``
Session isolation                 ``test_concurrent_session_isolation``
===============================  ==========================================

Tests that need to prove something about the *ciphertext* talk to SQLite
directly with the stdlib driver -- splicing rows, reading blobs -- because the
claim being made is about what an attacker with database write access can do.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import inspect
import itertools
import logging
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from httpx import ASGITransport, AsyncClient

from secure_context_pipeline.api.app import create_app
from secure_context_pipeline.audit import logger as audit_logger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto import aead
from secure_context_pipeline.crypto.keys import derive_token_id, derive_vault_key, normalize
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.errors import (
    CryptoAuthError,
    PipelineError,
    SessionExpiredError,
    VaultMissError,
)
from secure_context_pipeline.models import EntityCategory, TokenRecord
from secure_context_pipeline.vault import session_registry as registry_module
from secure_context_pipeline.vault import session_vault as vault_module
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

# Synthetic values only -- nothing in this file resembles real personal data.
VALUE_A = "Jordan Alvarez"
VALUE_B = "Priya Raghunathan"


class FakeClock:
    """Injectable clock so TTL behaviour is testable without sleeping."""

    def __init__(self, now: float | None = None) -> None:
        self.now = time.time() if now is None else now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def session_registry(settings: Settings, clock: FakeClock) -> SessionRegistry:
    return SessionRegistry(settings, clock=clock)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "vault" / "vault.db"


@pytest.fixture
async def vault(db_path: Path, session_registry: SessionRegistry) -> AsyncIterator[SessionVault]:
    instance = await SessionVault.open(db_path, session_registry)
    try:
        yield instance
    finally:
        await instance.close()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def make_record(
    registry: SessionRegistry,
    session_id: str,
    value: str,
    *,
    entity_type: str = "PATIENT_NAME",
    category: EntityCategory = EntityCategory.PHI,
    surrogate: str | None = None,
) -> TokenRecord:
    """Build a ``TokenRecord`` the way the obfuscation engine will.

    The engine derives the token ID from the session key, then hands the record
    plus the original to the vault.
    """
    session_key = await registry.key(session_id)
    token_id = derive_token_id(session_key, entity_type, value)
    return TokenRecord(
        session_id=session_id,
        token_id=token_id,
        entity_type=entity_type,
        category=category,
        surrogate=surrogate if surrogate is not None else f"[{category}_{entity_type}_{token_id}]",
        created_at=time.time(),
    )


async def put_value(
    vault: SessionVault,
    registry: SessionRegistry,
    session_id: str,
    value: str,
    *,
    entity_type: str = "PATIENT_NAME",
    surrogate: str | None = None,
) -> TokenRecord:
    """Put a value and return the *authoritative* record (post collision resolution)."""
    record = await make_record(
        registry, session_id, value, entity_type=entity_type, surrogate=surrogate
    )
    await vault.put(session_id, record, value)
    stored = await vault.get_by_original(session_id, entity_type, normalize(value))
    assert stored is not None
    return stored


def lock_waiters(lock: asyncio.Lock) -> int:
    """How many coroutines are currently parked on ``lock``.

    ``asyncio.Lock`` publishes no waiter count, and the race tests below need
    one. Without it, "this task is queued on the lock" can only be *inferred*
    from "it has not finished yet", which is the same inference that made
    ``test_destroy_races_concurrent_writes`` depend on how many event-loop steps
    each coroutine happened to spend before its acquire. Reading the deque turns
    that inference into an observation, so the queue order becomes a property of
    the test rather than of the scheduler.

    ``_waiters`` is private, but this is a mechanism test that already reaches
    for ``vault._lock`` directly; a cancelled future stays in the deque until
    the next release, so cancelled entries are not counted.
    """
    waiters = getattr(lock, "_waiters", None) or ()
    return sum(1 for waiter in waiters if not waiter.cancelled())


async def park_on_lock(lock: asyncio.Lock, expected: int, *, what: str) -> None:
    """Run the event loop until ``expected`` coroutines are queued on ``lock``.

    Bounded rather than unbounded so a coroutine that never reaches the acquire
    fails the test with a message instead of hanging until the suite timeout.
    """
    for _ in range(10_000):
        if lock_waiters(lock) >= expected:
            return
        await asyncio.sleep(0)
    raise AssertionError(
        f"{what}: {lock_waiters(lock)} coroutines queued on the lock, expected {expected}"
    )


def read_rows(db_path: Path, session_id: str) -> list[sqlite3.Row]:
    """All rows for a session, straight off disk."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return list(
            conn.execute(
                "SELECT session_id, token_id, entity_type, surrogate, nonce, ciphertext,"
                " created_at FROM vault_entries WHERE session_id = ?",
                (session_id,),
            )
        )
    finally:
        conn.close()


def read_row(db_path: Path, session_id: str, token_id: str) -> sqlite3.Row | None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT session_id, token_id, entity_type, surrogate, nonce, ciphertext, created_at"
            " FROM vault_entries WHERE session_id = ? AND token_id = ?",
            (session_id, token_id),
        ).fetchone()
    finally:
        conn.close()


def reinsert_row(db_path: Path, row: sqlite3.Row) -> None:
    """Put a row back byte for byte, under its own identity.

    Models the two ordinary ways a row outlives ``destroy``'s best-effort
    DELETE: a backup restored over the file, or the DELETE simply failing.
    Unlike :func:`splice_row` it does not rename the surrogate, so the row is
    still reachable by *every* accessor -- which is what makes it usable for
    testing the surrogate lookup rather than only the token one.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO vault_entries"
            " (session_id, token_id, entity_type, surrogate, nonce, ciphertext, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            tuple(row),
        )
        conn.commit()
    finally:
        conn.close()


def splice_row(db_path: Path, row: sqlite3.Row, *, session_id: str, token_id: str) -> None:
    """Copy a row's ``(nonce, ciphertext)`` under a different identity.

    This is exactly the attacker capability the AAD binding is defined against:
    write access to the vault database.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO vault_entries"
            " (session_id, token_id, entity_type, surrogate, nonce, ciphertext, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                token_id,
                row["entity_type"],
                row["surrogate"] + "-spliced",
                row["nonce"],
                row["ciphertext"],
                row["created_at"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. round-trip
# ---------------------------------------------------------------------------


async def test_vault_entry_round_trip(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    assert await vault.get_by_token(session_id, record.token_id) == VALUE_A
    assert await vault.get_by_surrogate(session_id, record.surrogate) == VALUE_A

    found = await vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_A))
    assert found is not None
    assert found.token_id == record.token_id
    assert vault.originals_for_session(session_id) == frozenset({VALUE_A})

    # Durable copy is ciphertext: the plaintext appears nowhere on disk.
    rows = read_rows(db_path, session_id)
    assert len(rows) == 1
    assert VALUE_A.encode() not in bytes(rows[0]["ciphertext"])
    # 12, spelled out rather than read from ``aead.NONCE_LEN``: asserting a
    # module's output against that module's own constant would hold just as well
    # if the constant were wrong. 12 bytes is the AES-GCM standard nonce, and it
    # is the value the ciphertext has to be judged against.
    assert len(bytes(rows[0]["nonce"])) == 12
    assert aead.NONCE_LEN == 12
    # The tag is authenticated overhead on top of the plaintext, so a row can
    # never be shorter than what it is supposed to be protecting.
    assert len(bytes(rows[0]["ciphertext"])) >= len(VALUE_A.encode()) + 16


async def test_round_trip_survives_cache_loss(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """The DB copy is a real copy: a cold cache still decrypts while the key lives."""
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    cold = await SessionVault.open(db_path, session_registry)
    try:
        assert cold.originals_for_session(session_id) == frozenset()
        assert await cold.get_by_token(session_id, record.token_id) == VALUE_A
        # Read-through repopulated the hot index.
        assert cold.originals_for_session(session_id) == frozenset({VALUE_A})
    finally:
        await cold.close()


async def test_unknown_token_is_a_vault_miss(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    session_id, _ = await session_registry.create("test-user")
    await put_value(vault, session_registry, session_id, VALUE_A)
    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_id, "00000000")
    with pytest.raises(VaultMissError):
        await vault.get_by_surrogate(session_id, "[PHI_PATIENT_NAME_00000000]")
    assert await vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_B)) is None


# ---------------------------------------------------------------------------
# 2. AAD binding
# ---------------------------------------------------------------------------


async def test_aad_binding_across_sessions(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """A row spliced into another *live* session fails authentication."""
    session_a, _ = await session_registry.create("test-user")
    session_b, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_a, VALUE_A)

    row = read_row(db_path, session_a, record.token_id)
    assert row is not None
    splice_row(db_path, row, session_id=session_b, token_id=record.token_id)

    # The row is really there -- this is a decryption failure, not an absence.
    assert read_row(db_path, session_b, record.token_id) is not None

    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_b, record.token_id)
    # ...and the failure is not merely reported: nothing was cached.
    assert vault.originals_for_session(session_b) == frozenset()

    # Isolate the AAD from the key: even with session A's *correct* vault key,
    # authenticating under session B's AAD fails.
    key_a = derive_vault_key(await session_registry.key(session_a), session_a)
    with pytest.raises(CryptoAuthError):
        aead.decrypt_split(
            key_a,
            bytes(row["nonce"]),
            bytes(row["ciphertext"]),
            aead.vault_aad(session_b, record.token_id),
            scope="vault",
        )


async def test_aad_binding_across_token_ids(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """A row re-labelled with another token ID *in the same session* fails too."""
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)
    forged_token = "ffffffff"

    row = read_row(db_path, session_id, record.token_id)
    assert row is not None
    splice_row(db_path, row, session_id=session_id, token_id=forged_token)
    assert read_row(db_path, session_id, forged_token) is not None

    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_id, forged_token)

    key = derive_vault_key(await session_registry.key(session_id), session_id)
    with pytest.raises(CryptoAuthError):
        aead.decrypt_split(
            key,
            bytes(row["nonce"]),
            bytes(row["ciphertext"]),
            aead.vault_aad(session_id, forged_token),
            scope="vault",
        )
    # Same key, correct AAD -- proving only the AAD changed.
    assert (
        aead.decrypt_split(
            key,
            bytes(row["nonce"]),
            bytes(row["ciphertext"]),
            aead.vault_aad(session_id, record.token_id),
            scope="vault",
        ).decode()
        == VALUE_A
    )


async def test_a_cross_session_read_never_retrieves_the_other_sessions_row(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """The SQL scope is the *first* isolation layer, and it is asserted here on its own.

    Isolation between sessions is two independent layers: the ``WHERE session_id
    = ?`` in both row SELECTs, and the AAD binding that makes a row useless once
    retrieved. Every cross-session test in this file -- ``test_aad_binding_across
    _sessions``, ``test_cross_session_non_determinism``, ``test_concurrent_session
    _isolation`` -- resolves through the second layer, because an authentication
    failure and an absent row raise the identical ``VaultMissError`` on purpose
    (the error must not be an oracle for "exists but is not yours"). So the
    outcome is the same whichever layer refuses, and widening the predicate to
    ``WHERE (session_id = ? OR 1=1) AND token_id = ?`` left the whole suite green
    while the read path was being handed another session's ciphertext.

    That is defence in depth rather than an open hole -- the per-session vault key
    still refuses the row -- which is exactly why it needs its own assertion: a
    layer whose only evidence is another layer is not evidence. This one looks at
    what the SELECT *returned*, by recording the row handed to ``_decrypt_row``,
    so it can tell "never retrieved" from "retrieved and rejected".
    """
    session_a, _ = await session_registry.create("test-user")
    session_b, _ = await session_registry.create("test-user")
    by_token = await put_value(vault, session_registry, session_a, VALUE_A)
    by_surrogate = await put_value(vault, session_registry, session_a, VALUE_B)

    # A cold instance: every read has to reach SQLite, which is the only path
    # that reaches _decrypt_row at all.
    cold = await SessionVault.open(db_path, session_registry)
    try:
        seen: list[sqlite3.Row | None] = []
        real_decrypt = cold._decrypt_row

        def recording_decrypt(
            session_id: str,
            session_key: bytes,
            row: Any,
            *,
            token_id: str | None,
        ) -> str:
            seen.append(row)
            return real_decrypt(session_id, session_key, row, token_id=token_id)

        cold._decrypt_row = recording_decrypt  # type: ignore[method-assign]

        # Control: in scope, the SELECT does return the row. Without this the
        # assertions below would also pass against a SELECT that never matches.
        assert read_row(db_path, session_a, by_token.token_id) is not None
        assert await cold.get_by_token(session_a, by_token.token_id) == VALUE_A
        assert seen[-1] is not None and str(seen[-1]["token_id"]) == by_token.token_id

        with pytest.raises(VaultMissError):
            await cold.get_by_token(session_b, by_token.token_id)
        assert seen[-1] is None, (
            "the token SELECT handed the read path another session's row; only the "
            "AAD refused it, so the SQL scope is unasserted"
        )

        # The surrogate SELECT carries the same predicate and the same argument.
        assert await cold.get_by_surrogate(session_a, by_surrogate.surrogate) == VALUE_B
        assert seen[-1] is not None

        with pytest.raises(VaultMissError):
            await cold.get_by_surrogate(session_b, by_surrogate.surrogate)
        assert seen[-1] is None, "the surrogate SELECT was not scoped to the session"

        # Nothing was cached for session B by either attempt.
        assert cold.originals_for_session(session_b) == frozenset()
        assert session_b not in cold.cached_session_ids()
    finally:
        await cold.close()


# ---------------------------------------------------------------------------
# 3. cross-session non-determinism
# ---------------------------------------------------------------------------


async def test_cross_session_non_determinism(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    session_a, _ = await session_registry.create("test-user")
    session_b, _ = await session_registry.create("test-user")

    rec_a = await put_value(vault, session_registry, session_a, VALUE_A)
    rec_b = await put_value(vault, session_registry, session_b, VALUE_A)

    assert rec_a.token_id != rec_b.token_id

    row_a = read_row(db_path, session_a, rec_a.token_id)
    row_b = read_row(db_path, session_b, rec_b.token_id)
    assert row_a is not None and row_b is not None
    assert bytes(row_a["ciphertext"]) != bytes(row_b["ciphertext"])
    assert bytes(row_a["nonce"]) != bytes(row_b["nonce"])

    # Neither session can read the other's token.
    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_a, rec_b.token_id)
    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_b, rec_a.token_id)


# ---------------------------------------------------------------------------
# 4. within-session determinism
# ---------------------------------------------------------------------------


async def test_within_session_determinism(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    session_id, _ = await session_registry.create("test-user")
    first = await put_value(vault, session_registry, session_id, VALUE_A)
    second = await put_value(vault, session_registry, session_id, VALUE_A)

    assert first.token_id == second.token_id
    assert len(read_rows(db_path, session_id)) == 1
    assert await vault.row_count(session_id) == 1


async def test_normalization_dedupes_variants(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """NFKC + whitespace collapse + casefold: five spellings, one row, one token."""
    session_id, _ = await session_registry.create("test-user")
    variants = [
        VALUE_A,
        VALUE_A.upper(),
        VALUE_A.lower(),
        f"  {VALUE_A}  ",
        VALUE_A.replace(" ", "  "),
    ]
    tokens = {
        (await put_value(vault, session_registry, session_id, variant)).token_id
        for variant in variants
    }
    assert len(tokens) == 1
    assert len(read_rows(db_path, session_id)) == 1


# ---------------------------------------------------------------------------
# 5. destruction
# ---------------------------------------------------------------------------


async def test_destroy_makes_tokens_unreadable(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)
    assert await vault.get_by_token(session_id, record.token_id) == VALUE_A

    await vault.destroy(session_id)

    assert read_rows(db_path, session_id) == []
    assert vault.originals_for_session(session_id) == frozenset()
    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_id, record.token_id)
    with pytest.raises(VaultMissError):
        await vault.get_by_surrogate(session_id, record.surrogate)
    assert await vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_A)) is None


async def test_destroy_surviving_row_is_undecryptable(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """Key erasure, not row deletion, is the control.

    A row that outlives ``destroy()`` -- a failed DELETE, a filesystem snapshot,
    a backup -- is still garbage once the session key is popped.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)
    survivor = read_row(db_path, session_id, record.token_id)
    assert survivor is not None

    await vault.destroy(session_id)
    assert await session_registry.destroy(session_id) is True

    # Simulate the best-effort delete having failed / a backup copy existing.
    splice_row(db_path, survivor, session_id=session_id, token_id=record.token_id)
    assert read_row(db_path, session_id, record.token_id) is not None

    # No accessor can reach it: the key is gone, so the session is gone.
    with pytest.raises(SessionExpiredError):
        await vault.get_by_token(session_id, record.token_id)

    # And the bytes themselves are unrecoverable: the plaintext is not in them,
    # and no key we can still construct authenticates them.
    blob = bytes(survivor["ciphertext"])
    assert VALUE_A.encode() not in blob
    fresh_id, _ = await session_registry.create("test-user")
    for wrong_key in (
        derive_vault_key(await session_registry.key(fresh_id), session_id),
        derive_vault_key(secrets.token_bytes(32), session_id),
    ):
        with pytest.raises(CryptoAuthError):
            aead.decrypt_split(
                wrong_key,
                bytes(survivor["nonce"]),
                blob,
                aead.vault_aad(session_id, record.token_id),
                scope="vault",
            )


async def test_destroy_is_cryptographic_erasure_by_every_route_we_can_construct(
    vault: SessionVault,
    session_registry: SessionRegistry,
    settings: Settings,
    db_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Irreversibility is a headline claim, so attack it rather than assert it.

    ``test_destroy_surviving_row_is_undecryptable`` shows one route: a random
    key and a *different* session's key both fail. That leaves the routes an
    actual attacker would reach for, and each is tried here against a row
    deliberately preserved from before the destroy:

    1. **The files on disk**, not the table. A ``SELECT`` cannot see the
       write-ahead log or the shared-memory sidecar, and a DELETE leaves freed
       pages behind; every byte the store ever wrote is swept instead.
    2. **A cached object** -- the hot index, the memoised egress view, and the
       ``repr`` of both components.
    3. **A session re-created under the same ID.** Session IDs are the only
       identifier an attacker sees, so "make another session called that" is the
       obvious move; it must not reconstitute the key.
    4. **The process master key.** This is the sharpest of the four: a session
       key is fresh entropy, *not* an HKDF of the master, so compromising the
       env key and stealing the database still yields nothing. Deriving session
       keys from the master would be a natural-looking "simplification" that
       silently converts erasure into "we deleted the row", and this is what
       would notice.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)
    survivor = read_row(db_path, session_id, record.token_id)
    assert survivor is not None

    await vault.destroy(session_id)
    assert await session_registry.destroy(session_id) is True
    # The confidentiality control is the key, not the DELETE -- so put the row
    # back and let it survive everything below.
    reinsert_row(db_path, survivor)
    assert read_row(db_path, session_id, record.token_id) is not None

    # -- route 1: every byte the store ever wrote, sidecars included ---------
    files = sorted(p for p in db_path.parent.rglob("*") if p.is_file())
    assert files, "expected at least the database file"
    for path in files:
        assert VALUE_A.encode() not in path.read_bytes(), f"plaintext survived in {path.name}"

    # -- route 2: a cached object -------------------------------------------
    assert vault.originals_for_session(session_id) == frozenset()
    assert vault.cached_session_ids() == frozenset()
    rendered = f"{vault!r} {vault} {session_registry!r} {session_registry}"
    assert VALUE_A not in rendered

    # -- route 3: a new session claiming the same ID -------------------------
    monkeypatch.setattr(registry_module.uuid, "uuid4", lambda: uuid.UUID(hex=session_id))
    reborn, _ = await session_registry.create("test-user")
    assert reborn == session_id, "the session ID was not actually reused"
    reborn_key = await session_registry.key(reborn)

    # -- route 4: the master key -------------------------------------------
    master = settings.master_key_bytes()
    assert len(master) == 32
    assert master != reborn_key, "a session key must not be the master key"

    blob = bytes(survivor["ciphertext"])
    assert VALUE_A.encode() not in blob
    candidates = {
        "a same-ID session re-created after the destroy": reborn_key,
        "the process master key": master,
    }
    for label, candidate in candidates.items():
        try:
            aead.decrypt_split(
                derive_vault_key(candidate, session_id),
                bytes(survivor["nonce"]),
                blob,
                aead.vault_aad(session_id, record.token_id),
                scope="vault",
            )
        except CryptoAuthError:
            continue
        raise AssertionError(f"{label} decrypted a destroyed session's row")

    # And the vault itself will not serve it either: the reborn session is a
    # different session that happens to share a name.
    with pytest.raises(VaultMissError):
        await vault.get_by_token(reborn, record.token_id)
    assert vault.originals_for_session(reborn) == frozenset()


async def test_destroy_is_final_for_later_writes(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """A ``put`` that arrives after ``destroy`` must not resurrect the session.

    Logout is two awaits -- ``vault.destroy()`` then ``registry.destroy()`` --
    and a pipeline run that already holds the session key can land a write
    between them. Such a write used to recreate the plaintext cache *and* a
    durable row for a session that was already gone, and because the registry
    entry disappears a moment later nothing would ever collect either one.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    await vault.destroy(session_id)
    # The key is still live: this is precisely the logout window.
    assert await session_registry.key(session_id)

    with pytest.raises(SessionExpiredError):
        await vault.put(session_id, record, VALUE_A)

    assert vault.originals_for_session(session_id) == frozenset()
    assert vault.cached_session_ids() == frozenset()
    assert read_rows(db_path, session_id) == []
    assert await vault.row_count(session_id) == 0

    # Reads stay shut too, and stay indistinguishable from an absent entry.
    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_id, record.token_id)
    with pytest.raises(VaultMissError):
        await vault.get_by_surrogate(session_id, record.surrogate)
    assert await vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_A)) is None

    # Popping the key afterwards leaves nothing behind either.
    assert await session_registry.destroy(session_id) is True
    assert vault.originals_for_session(session_id) == frozenset()


async def test_a_late_note_unrestorable_cannot_resurrect_a_destroyed_session(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """The redact-band note is the *sixth* cache mutator, and it lands after logout too.

    ``note_unrestorable`` is the one cache-creating entry point that is
    synchronous and therefore cannot ``await self._registry.key(...)`` to
    re-validate the session -- its own docstring says so, and the EgressGate's
    read side is why. That makes its tombstone check the only thing standing
    between "logout happened" and "a redact-band original is back in RAM", and
    until this test nothing in the suite read it: ``grep -rn note_unrestorable
    tests/`` returned no vault-side test at all, and deleting the two guard lines
    left every other test in the repo green.

    The window is the documented vault-first logout order that
    ``test_destroy_is_final_for_later_writes`` pins for ``put``: ``vault.destroy()``
    lands, the key is still live, and an obfuscation run already in flight calls
    back in. Without the guard the call *re-creates* the ``_SessionCache`` --
    ``setdefault`` is deliberately creating, because a document whose every
    detection fell in the redact band has no cache otherwise -- and that rebuilt
    cache holds the original for the life of the process. It survives
    ``registry.destroy()`` too, because the registry has no reference to it, so
    nothing downstream ever reports the leak: it is the silent direction.
    """
    session_id, _ = await session_registry.create("test-user")

    # Non-vacuity: while the session is live the note really does reach the
    # gate's needle set and really does create a cache. Otherwise every
    # assertion below would hold for a method that does nothing at all.
    vault.note_unrestorable(session_id, VALUE_A)
    assert vault.originals_for_session(session_id) == frozenset({VALUE_A})
    assert vault.cached_session_ids() == frozenset({session_id})

    await vault.destroy(session_id)
    assert vault.originals_for_session(session_id) == frozenset()
    assert vault.cached_session_ids() == frozenset()

    # The key is still live -- this is precisely the logout window.
    assert await session_registry.key(session_id)
    vault.note_unrestorable(session_id, VALUE_B)
    assert vault.originals_for_session(session_id) == frozenset(), (
        "a late redact-band note rebuilt a destroyed session's plaintext cache"
    )
    assert vault.cached_session_ids() == frozenset(), (
        "a destroyed session was re-created by note_unrestorable"
    )
    assert VALUE_B not in f"{vault!r} {vault}"

    # And once the key is gone the note is still refused. Nothing collects a
    # cache created here: the registry entry it belonged to no longer exists.
    assert await session_registry.destroy(session_id) is True
    vault.note_unrestorable(session_id, VALUE_B)
    assert vault.originals_for_session(session_id) == frozenset()
    assert vault.cached_session_ids() == frozenset()


async def test_a_late_note_unrestorable_is_refused_after_the_apis_logout_order(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """The same guard, in the order the shipped product actually logs out in.

    The test above destroys the vault *first*, with the key still live -- the
    order ``destroy``'s tombstone was written for, and an order nothing in the
    product uses. ``DELETE /sessions/{id}`` pops the key and then calls the vault
    (``routes/sessions.py``), the TTL reaper reaches ``vault.destroy`` through
    ``sessions.sweep()`` with the key already dropped, and ``demo.py`` does the
    same. So every shipped path arrived at ``destroy`` with ``registry.key()``
    already raising, ``if key_still_live`` recorded nothing, and the guard the
    test above proves out was inert in production.

    Measured on these objects before the fix: after a complete key-first logout,
    ``originals_for_session`` was empty and ``_destroyed`` was empty, and one late
    ``note_unrestorable`` put the value straight back --
    ``frozenset({'Priya Raghunathan'})`` -- in a cache that no destroy path will
    ever visit again, held until the process exits. Plaintext surviving logout is
    the one thing this module exists to prevent, and it survived *silently*: the
    registry holds no reference to that cache, so nothing downstream reports it.

    ``destroy`` therefore tombstones when the session had a live key **or** a
    cache. Both halves are asserted here: the tombstone is the mechanism, and the
    empty ``originals_for_session`` is the property.
    """
    session_id, _ = await session_registry.create("test-user")

    # A cache exists before logout -- this is the redact-band needle the gate
    # reads, and the thing a late call would rebuild.
    vault.note_unrestorable(session_id, VALUE_A)
    assert vault.originals_for_session(session_id) == frozenset({VALUE_A})

    # The API's order, exactly: key first, vault second.
    assert await session_registry.destroy(session_id) is True
    await vault.destroy(session_id)
    assert session_id in vault._destroyed, "the key-first logout recorded no tombstone"
    assert vault.originals_for_session(session_id) == frozenset()

    vault.note_unrestorable(session_id, VALUE_B)
    assert vault.originals_for_session(session_id) == frozenset(), (
        "a late redact-band note rebuilt the cache of a session logged out via the API"
    )
    assert vault.cached_session_ids() == frozenset(), (
        "a destroyed session was re-created by note_unrestorable"
    )
    assert VALUE_B not in f"{vault!r} {vault}"


def _is_self_caches(node: ast.expr) -> bool:
    """Whether ``node`` is the expression ``self._caches``."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "_caches"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _cache_creating_methods() -> frozenset[str]:
    """``SessionVault`` methods that can bring a ``_SessionCache`` into existence.

    Found by walking the module's own AST for ``self._caches.setdefault(...)``
    and ``self._caches[...] = ...``, which shares no helper and no constant with
    the vault -- the enumeration is a second, independent reading of the source
    rather than something the vault hands out about itself.
    """
    tree = ast.parse(inspect.getsource(vault_module))
    class_def = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "SessionVault"
    )
    found: set[str] = set()
    for method in class_def.body:
        if not isinstance(method, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(method):
            creates = (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "setdefault"
                and _is_self_caches(node.func.value)
            ) or (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Subscript) and _is_self_caches(target.value)
                    for target in node.targets
                )
            )
            if creates:
                found.add(method.name)
    return frozenset(found)


def test_every_method_that_can_create_a_plaintext_cache_has_a_destroy_test() -> None:
    """A newly added cache creator must not be able to join the class unnoticed.

    Three methods can bring a ``_SessionCache`` into existence, and each one is a
    route by which a session that was destroyed a moment ago gets its plaintext
    back in RAM for the life of the process. Each has a test that lands a call in
    the logout window and asserts the cache stays gone:

    ==================  ======================================================
    ``put``             ``test_destroy_is_final_for_later_writes``
    ``_decrypt_row``    ``test_a_destroy_landing_mid_read_cannot_recache_the_session``
    ``note_unrestorable``  ``test_a_late_note_unrestorable_cannot_resurrect_a_destroyed_session``
    ==================  ======================================================

    That correspondence is exactly the kind of thing that is true when written
    and false a month later: ``note_unrestorable`` was itself added as a fourth
    cache mutator with no destroy test, and it stayed that way through a full
    green suite. This asserts the enumeration itself -- a fourth creator, or a
    rename, fails here and forces the pairing to be re-stated rather than
    silently lost.
    """
    covered = {"put", "_decrypt_row", "note_unrestorable"}
    actual = _cache_creating_methods()
    assert actual == covered, (
        f"the methods that can create a plaintext cache are {sorted(actual)}; the ones "
        f"with a test proving they refuse a destroyed session are {sorted(covered)}. "
        f"Add the missing destroy test and update this list."
    )


async def test_surviving_row_cannot_repopulate_a_destroyed_cache(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """A row that outlived the best-effort DELETE must not read back as plaintext.

    ``destroy`` documents its DELETE as best effort -- a backup, a snapshot or a
    failed statement can leave rows behind. While the session key is still live
    those rows are decryptable, so the read path has to refuse them rather than
    decrypt them and re-cache the result.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)
    survivor = read_row(db_path, session_id, record.token_id)
    assert survivor is not None

    await vault.destroy(session_id)
    splice_row(db_path, survivor, session_id=session_id, token_id=record.token_id)
    assert read_row(db_path, session_id, record.token_id) is not None

    with pytest.raises(VaultMissError):
        await vault.get_by_token(session_id, record.token_id)
    assert vault.originals_for_session(session_id) == frozenset()
    assert vault.cached_session_ids() == frozenset()


async def test_a_destroy_landing_mid_read_cannot_recache_the_session(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """The *read-through* refuses a tombstoned session, not just the accessors.

    ``get_by_token`` checks the tombstone on entry, so every test that destroys
    and then reads is answered by that check and never reaches the decrypt. The
    guard one layer down -- ``_decrypt_row`` declining to populate the cache for
    a destroyed session -- was therefore unreachable from the suite and could be
    deleted with everything still green.

    It is reachable in the one interleaving that matters: a read that is already
    past its own check when ``destroy`` lands, against a row that outlived the
    best-effort DELETE. Both are ordinary -- ``destroy`` documents the DELETE as
    best effort, and a read in flight at logout is the whole reason the tombstone
    exists. Here the DELETE is made to fail so the row survives, and the reader
    is parked on the vault's own lock so the destroy provably lands *between* its
    check and its decrypt rather than by luck.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    # A cold instance: the read must miss the cache and go to SQLite, which is
    # the only path that reaches _decrypt_row at all.
    cold = await SessionVault.open(db_path, session_registry)
    try:
        conn = cold._conn
        assert conn is not None
        real_execute = conn.execute

        async def failing_delete(sql: str, *args: Any, **kwargs: Any) -> Any:
            if sql.strip().upper().startswith("DELETE"):
                raise sqlite3.OperationalError("database is locked")
            return await real_execute(sql, *args, **kwargs)

        conn.execute = failing_delete  # type: ignore[method-assign]
        try:
            # Hold the vault lock so both coroutines queue on it instead of
            # racing: destroy first, then the reader, which by then is already
            # past its own tombstone check.
            await cold._lock.acquire()
            destroyer = asyncio.create_task(cold.destroy(session_id))
            reader = asyncio.create_task(cold.get_by_token(session_id, record.token_id))
            for _ in range(20):
                await asyncio.sleep(0)
            cold._lock.release()
            recovered = await reader
            await destroyer
        finally:
            conn.execute = real_execute  # type: ignore[method-assign]

        # The read got past its own check and really did decrypt a surviving row
        # -- otherwise this would be a VaultMissError and the guard below would
        # be asserted vacuously.
        assert recovered == VALUE_A
        assert read_row(db_path, session_id, record.token_id) is not None, (
            "the DELETE was supposed to fail, leaving a row for the read to find"
        )
        assert session_id in cold._destroyed

        # ...and the destroyed session was not rebuilt out of it.
        assert cold.cached_session_ids() == frozenset(), "a destroyed session was re-cached"
        assert cold.originals_for_session(session_id) == frozenset()
        assert await cold.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_A)) is None
    finally:
        await cold.close()


async def test_close_releases_the_tombstone_set(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """Tombstones are per-instance bookkeeping and must not outlive the instance.

    Every accessor raises ``vault_closed`` once the connection is gone, so there
    is no read left for a tombstone to refuse; keeping them would be an entry per
    logout retained for the life of the process. Reopening the same file is a
    fresh instance with a cold cache -- the documented cold-start path -- and the
    key is what makes that safe, not the tombstone.
    """
    session_id, _ = await session_registry.create("test-user")
    await put_value(vault, session_registry, session_id, VALUE_A)

    await vault.destroy(session_id)
    assert vault._destroyed == {session_id}, "the tombstone was never recorded"

    await vault.close()
    assert vault._destroyed == set(), "tombstones survived close()"
    # Vacuous as cache coverage and kept only as a consistency check: the
    # ``destroy`` above already popped this session's cache, so this line holds
    # whether or not ``close`` clears anything. The cache half of ``close`` is
    # pinned by ``test_close_erases_a_live_sessions_plaintext`` below.
    assert vault.cached_session_ids() == frozenset()

    # And the session really is unreachable afterwards -- by closure, not by
    # tombstone: every accessor fails before it can consult one.
    with pytest.raises(PipelineError):
        await vault.row_count(session_id)


async def test_close_erases_a_live_sessions_plaintext(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """``close`` must drop the caches of sessions that were never destroyed.

    The session that matters here is the one nobody logged out. ``close`` is the
    shutdown path -- the lifespan handler, ``__aexit__``, a reopen against the
    same file -- and its docstring makes the erasure claim in full: "plaintext
    lives exactly as long as the process holds a live session". A session with no
    ``destroy`` behind it is the only case that tests that claim, because
    ``destroy`` pops the cache itself.

    ``test_close_releases_the_tombstone_set`` above looks like it covers this and
    does not: it destroys first, so ``self._caches`` is already empty when
    ``close`` runs and its ``cached_session_ids()`` assertion passes with
    ``self._caches.clear()`` deleted outright. That is the shape this repo has
    shipped before -- a test filtered to a set the bug empties by construction --
    so the distinguishing case is asserted here instead.

    The plaintext containers are read directly rather than through
    ``cached_session_ids``/``originals_for_session``, which both derive from the
    same dict: a leak here is originals sitting in a ``_SessionCache`` that no
    accessor will ever hand out again, which is exactly the state no accessor can
    report.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    # Non-vacuity: there is a populated cache to erase.
    assert vault.cached_session_ids() == frozenset({session_id})
    assert vault.originals_for_session(session_id) == frozenset({VALUE_A})
    assert dict(vault.surrogates_for_session(session_id)) == {record.surrogate: VALUE_A}

    await vault.close()

    held = sorted(
        value
        for cache in vault._caches.values()
        for value in (cache.view() | frozenset(cache.by_token.values()))
    )
    assert held == [], f"{len(held)} originals survived close() in the plaintext caches"
    assert vault.cached_session_ids() == frozenset()
    assert vault.originals_for_session(session_id) == frozenset()
    assert dict(vault.surrogates_for_session(session_id)) == {}
    assert VALUE_A not in f"{vault!r} {vault}"


async def test_destroy_races_concurrent_writes(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """40 writers against a destroy: whoever loses the race must lose it completely.

    The destroy has to land *between* two writes, and that used to be luck. Every
    coroutine here reaches ``SessionVault._lock`` and queues on it, so the
    interleaving was decided by how many event-loop steps each one happened to
    spend getting there -- and one extra ``await`` anywhere ahead of the lock
    (an audit emit, a metric, a differently-implemented registry) let all 40
    writes complete before the destroy arrived. The test then asserted nothing
    about the race it is named for; only its own ``"the race did not happen"``
    guard stopped that from passing silently.

    Holding the lock while the tasks are created removes the guesswork: each one
    runs exactly as far as the acquire and stops there, so releasing the lock
    replays them in queue order. The outcome is then pinned position-by-position
    rather than as "both values appear somewhere", which is what makes a change
    in wakeup order a failure instead of a weaker test.

    **Queue order is established, not assumed.** An earlier version of this test
    created all 41 tasks, spun the loop 20 times, and took *creation* order to be
    *queue* order. That held only while neither ``put`` nor ``destroy`` yielded
    on its way to ``self._lock``, and it was one ``await`` away from evaporating
    on **either** side of the race -- both directions measured, not reasoned
    about, by injecting a single ``await asyncio.sleep(0)`` before each acquire
    in turn:

    * before ``put``'s acquire, the destroyer queues first, all forty writes are
      refused, and the test failed on ``assert "stored" in outcomes``;
    * before ``SessionVault.destroy``'s acquire, the destroyer queues *last*, all
      forty writes are stored, and the test failed on the opposite guard,
      ``"no write landed after the destroy; the race did not happen"``.

    Neither failure was the vault breaking -- in both the security block at the
    bottom still held -- but in both the test stopped testing the race it is
    named for, and a maintainer looking at a red ordering assertion is one step
    from relaxing it. So each task is now driven onto the lock's wait queue and
    *observed* there (``park_on_lock``) before the next one is created. Queue
    order is a property of this code, and no number of awaits added ahead of
    either acquire can change it.
    """
    session_id, _ = await session_registry.create("test-user")
    values = [f"Synthetic Subject {index:02d}" for index in range(40)]
    records = {value: await make_record(session_registry, session_id, value) for value in values}

    async def writer(value: str) -> str:
        try:
            await vault.put(session_id, records[value], value)
        except SessionExpiredError:
            return "refused"
        return "stored"

    async def destroyer() -> str:
        await vault.destroy(session_id)
        return "destroyed"

    # Queued in the middle of the writers so the destroy genuinely lands between
    # two writes rather than after all of them.
    await vault._lock.acquire()
    scheduled: list[asyncio.Task[str]] = []

    async def enqueue(coro: Any, what: str) -> None:
        """Start ``coro`` and do not return until it is parked on the vault lock."""
        scheduled.append(asyncio.create_task(coro))
        await park_on_lock(vault._lock, len(scheduled), what=what)

    try:
        for value in values[:20]:
            await enqueue(writer(value), f"writer for {value!r} before the destroy")
        await enqueue(destroyer(), "the destroyer")
        for value in values[20:]:
            await enqueue(writer(value), f"writer for {value!r} after the destroy")

        assert not any(task.done() for task in scheduled), (
            "a coroutine got past the vault lock while the test held it"
        )
    finally:
        # Released in a ``finally`` because ``SessionVault.close`` -- which the
        # fixture calls on teardown -- takes this same lock. Any assertion above
        # firing while the test still holds it deadlocks the teardown, and the
        # run then dies on the suite-wide timeout instead of reporting a red
        # test. ``pyproject.toml`` calls that out as the one failure mode a
        # security suite cannot afford; measured, not assumed.
        vault._lock.release()

    outcomes = await asyncio.gather(*scheduled)
    assert "stored" in outcomes, "no write landed before the destroy"
    assert "refused" in outcomes, "no write landed after the destroy; the race did not happen"
    # Sharper than "both appear": every write before the destroy is kept and
    # every write after it is refused, with nothing straddling the boundary.
    assert outcomes == ["stored"] * 20 + ["destroyed"] + ["refused"] * 20

    # Whatever the interleaving, destruction wins: no cache, no rows, no reads.
    assert vault.originals_for_session(session_id) == frozenset()
    assert vault.cached_session_ids() == frozenset()
    assert read_rows(db_path, session_id) == []
    for record in records.values():
        with pytest.raises(VaultMissError):
            await vault.get_by_token(session_id, record.token_id)


async def test_logout_in_api_order_is_final_for_in_flight_writes(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """The API pops the key *first*, so ``put``'s refusal cannot come from a tombstone.

    ``DELETE /session/{id}`` runs ``registry.destroy()`` then ``vault.destroy()``,
    which is the opposite of the order the tombstone was written for -- by the
    time ``destroy`` runs, ``registry.key()`` already raises. The property has to
    come from somewhere other than the tombstone, and it does: ``put`` reads the
    key and queues on ``self._lock`` in one scheduling step, and ``asyncio.Lock``
    wakes waiters FIFO, so a write either lands before this ``destroy`` (and is
    cleaned up by it) or finds the key already gone.

    Yields are swept on **both** sides, and that is not symmetry for its own
    sake. Sweeping only the logout side measures the race from one end: a single
    ``await asyncio.sleep(0)`` injected before ``SessionRegistry.destroy``'s lock
    acquire pushed every one of the six interleavings onto the "stored" side, and
    the run ended on this test's own coverage guard
    (``the sweep did not exercise both sides of the race: {'stored'}``) -- not
    because the vault had regressed, but because the sweep could no longer reach
    the other side. Delaying the *writer* is the compensating direction, so one
    added ``await`` in either destroy path shifts which cell of the grid produces
    which outcome without emptying either side of it.

    The security block runs on every cell, so it is the coverage guard -- never
    the confidentiality assertions -- that a scheduling change can reach.
    """
    outcomes: set[str] = set()
    for writer_yields, logout_yields in itertools.product(range(4), range(4)):
        session_id, _ = await session_registry.create("test-user")
        await put_value(vault, session_registry, session_id, VALUE_A)
        record = await make_record(session_registry, session_id, VALUE_B)
        cell = f"writer_yields={writer_yields} logout_yields={logout_yields}"

        async def write(
            sid: str = session_id, rec: TokenRecord = record, steps: int = writer_yields
        ) -> None:
            for _ in range(steps):
                await asyncio.sleep(0)
            await vault.put(sid, rec, VALUE_B)

        async def logout(sid: str = session_id, steps: int = logout_yields) -> None:
            for _ in range(steps):
                await asyncio.sleep(0)
            await session_registry.destroy(sid)
            await vault.destroy(sid)

        writer = asyncio.create_task(write())
        await logout()
        try:
            await writer
        except SessionExpiredError:
            outcomes.add("refused")
        else:
            outcomes.add("stored")

        # Whatever the interleaving, the session is gone: no plaintext in RAM,
        # no ciphertext on disk, no readable token.
        assert vault.originals_for_session(session_id) == frozenset(), cell
        assert session_id not in vault.cached_session_ids(), cell
        assert read_rows(db_path, session_id) == [], cell
        # The surrogate the writer minted is unreadable in every cell. In this
        # order the refusal comes from the *key* being gone rather than from a
        # tombstone -- which is the whole claim of this test -- so the error is
        # ``SessionExpiredError`` from ``registry.key()``, not ``VaultMissError``.
        with pytest.raises(SessionExpiredError):
            await vault.get_by_surrogate(session_id, record.surrogate)
        # This read ``assert not vault._destroyed`` -- "the API order must not
        # accumulate tombstones" -- and that premise is what the tombstone fix
        # deliberately changed, so the assertion is inverted rather than dropped.
        # It was never one of this test's confidentiality claims (those are the
        # four above, and every one of them is untouched); it recorded that the
        # key-first order left ``_destroyed`` empty. That emptiness is exactly what
        # made ``note_unrestorable``'s guard inert in every shipped destruction
        # path, so ``destroy`` now tombstones a session that had a cache whichever
        # order it is logged out in -- and this session had one, from ``put_value``
        # above. Asserting the ID *is* present is strictly the stronger claim: it
        # pins the guard's precondition instead of pinning its absence.
        assert session_id in vault._destroyed, (
            "a logged-out session that held a cache must be tombstoned in either order"
        )

    assert outcomes == {"stored", "refused"}, (
        f"the sweep did not exercise both sides of the race: {outcomes}"
    )


async def test_put_reads_the_session_key_inside_the_lock(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """A yield between the key read and the tombstone check must not exist.

    ``put``'s docstring says the key read is inside ``self._lock`` because
    "anything added there (an audit emit, a metric, a thread hop) would have let
    a write land after logout and rebuild the plaintext cache for a destroyed
    session". Every other test takes that on trust: hoisting the read back out
    of the lock leaves all of ``test_vault.py`` green, because none of them puts
    an ``await`` in the gap the ordering exists to close, and without one the
    hoisted version *happens* to behave identically. Correct by accident is not
    correct.

    So this test supplies the missing await, exactly as described -- a yield
    immediately after ``registry.key()`` returns -- and then runs the API's
    logout order (key first, vault second) inside it. Where that yield lands
    relative to ``self._lock`` is the entire question:

    * key read **inside** the lock: the writer is parked while *holding* the
      lock, so ``vault.destroy`` cannot start. The write lands first and the
      destroy that follows collects it.
    * key read **outside** the lock: the writer is parked holding nothing, the
      whole logout completes -- recording no tombstone, because in this order
      the key is already gone *and* the write that would have left a cache has
      not happened yet -- and the write then acquires a free lock, sees an empty
      ``_destroyed``, and files a durable row plus a plaintext cache for a
      session that no longer exists, with nothing left to collect either.

    The assertions are therefore on the *residue*, not on which side won the
    race: either interleaving may store the value, but neither may leave it
    behind.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await make_record(session_registry, session_id, VALUE_A)

    parked = asyncio.Event()
    resume = asyncio.Event()
    real_key = session_registry.key

    async def key_then_yield(sid: str) -> bytes:
        key = await real_key(sid)
        # Only the first caller parks; ``destroy`` also asks for the key and
        # must be free to discover that it is gone.
        if not parked.is_set():
            parked.set()
            await resume.wait()
        return key

    session_registry.key = key_then_yield  # type: ignore[method-assign]

    writer = asyncio.create_task(vault.put(session_id, record, VALUE_A))
    await parked.wait()
    assert not writer.done(), "the writer was supposed to park on the injected yield"

    # The API's logout order, in full, while the writer sits in that gap.
    await session_registry.destroy(session_id)
    destroyer = asyncio.create_task(vault.destroy(session_id))
    for _ in range(20):
        await asyncio.sleep(0)

    resume.set()
    try:
        await writer
    except SessionExpiredError:
        pass
    await destroyer

    # This read ``assert not vault._destroyed`` and was a premise, not a claim:
    # under the old ``if key_still_live`` condition the key-first order recorded
    # nothing. It records one now whenever the session had a cache, and in the
    # *correct* (inside-the-lock) arrangement it does: the writer parks holding
    # the lock, so its ``put`` lands before ``destroy`` can start and ``destroy``
    # finds the cache it created. Hoist the key read back out of the lock and this
    # goes the other way -- no cache at destroy, so no tombstone -- which makes the
    # assertion a second, independent discriminator for the very ordering defect
    # this test exists for, on top of the residue checks below.
    assert session_id in vault._destroyed, (
        "the write did not land inside the lock, so destroy saw no cache to tombstone"
    )
    assert vault.originals_for_session(session_id) == frozenset(), (
        "a write that lost the race rebuilt the plaintext cache of a destroyed session"
    )
    assert session_id not in vault.cached_session_ids()
    assert read_rows(db_path, session_id) == [], (
        "a write that lost the race left a durable row for a destroyed session"
    )


async def test_get_by_original_refuses_a_tombstoned_session_with_a_live_cache(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """The last of three layers, tested by making the first two fail.

    ``get_by_original``'s tombstone check is defence in depth and its docstring
    says so: the method answers only out of the cache, and no public sequence
    can produce a destroyed session that still *has* a cache, because
    ``destroy`` pops it, ``put`` refuses to recreate it and ``_decrypt_row``
    declines to repopulate it. That honesty is worth keeping -- but "unreachable
    today" is a statement about the other two layers, and the way to test a
    third layer is to break the two above it rather than to delete the test.

    So the disagreement is manufactured directly: tombstone the session *without*
    popping its cache, which is precisely the state a future edit reordering
    ``destroy`` (tombstone before pop, with an ``await`` in between) would make
    reachable. The record must still not come back.

    Reaching into ``_destroyed`` is deliberate and is the only way to reach this
    branch; a test that could get here through the public API would be evidence
    that one of the other two layers had already failed.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    found = await vault.get_by_original(session_id, record.entity_type, normalize(VALUE_A))
    assert found is not None and found.token_id == record.token_id

    # Layers one and two fail: the session is tombstoned, the cache survives.
    vault._destroyed.add(session_id)
    assert session_id in vault.cached_session_ids(), (
        "this test is vacuous unless the cache really is still populated"
    )
    assert vault._caches[session_id].by_original, "the cache still holds the by_original index"

    assert (
        await vault.get_by_original(session_id, record.entity_type, normalize(VALUE_A))
    ) is None, "a destroyed session's record was handed back out of a surviving cache"


async def test_get_by_surrogate_refuses_a_row_that_outlived_destroy(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """The surrogate lookup needs its *own* tombstone check, not the token path's.

    Every other destroy test reaches ``get_by_surrogate`` only once the rows are
    already gone, so the miss comes from an empty table and the tombstone check
    above it never answers. Deleting that check therefore left the whole suite
    green -- while a row that outlived the best-effort DELETE (a backup, a
    snapshot, a statement that failed) decrypted straight back into the cache of
    a session that had already been destroyed.

    The premise is established before the assertion: the row is put back
    verbatim and shown to be genuinely decryptable under the still-live session
    key, so the refusal below is the vault declining a value it *could* have
    returned, not an absence dressed up as a policy.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)
    survivor = read_row(db_path, session_id, record.token_id)
    assert survivor is not None

    await vault.destroy(session_id)
    reinsert_row(db_path, survivor)

    restored = read_row(db_path, session_id, record.token_id)
    assert restored is not None, "the row was not actually restored"
    assert str(restored["surrogate"]) == record.surrogate
    vault_key = derive_vault_key(await session_registry.key(session_id), session_id)
    assert (
        aead.decrypt_split(
            vault_key,
            bytes(restored["nonce"]),
            bytes(restored["ciphertext"]),
            aead.vault_aad(session_id, record.token_id),
            scope="vault",
        ).decode()
        == VALUE_A
    ), "the surviving row is not decryptable, so the refusal below proves nothing"

    with pytest.raises(VaultMissError):
        await vault.get_by_surrogate(session_id, record.surrogate)
    assert vault.cached_session_ids() == frozenset(), "a destroyed session was re-cached"
    assert vault.originals_for_session(session_id) == frozenset()


async def test_destroy_records_no_tombstone_for_a_key_that_died_while_it_queued(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """``destroy`` must read liveness under the lock, not before queuing on it.

    The tombstone set answers "was the key still live when I destroyed this?",
    and that is only meaningful read at the moment it is acted on. Read before
    the acquire it is stale: a ``registry.destroy()`` landing in the gap records
    a tombstone for a session whose key is already gone -- per-session state
    retained until ``close`` for a session no accessor can reach anyway. Since
    ``destroy`` sits behind ``DELETE /session/{id}``, that is a caller-driven
    growth lever.

    ``test_logout_in_api_order_is_final_for_in_flight_writes`` cannot see this:
    its logout awaits ``registry.destroy`` to completion *before* calling
    ``vault.destroy``, so the two never overlap and the stale read never
    happens.

    **The session deliberately holds no cache**, and that is what keeps the
    tombstone a discriminator here. ``destroy``'s condition is ``key_still_live or
    cache is not None``: with a cache present both the stale and the correct
    liveness read tombstone, and the assertion below would hold for the broken
    ordering too. This test used to ``put_value`` first, which under the current
    condition would have made it vacuous rather than failing -- the worst
    direction. Removing that line is what preserves the property it was written
    for; the control at the end keeps the assertion from passing merely because
    nothing tombstones at all.
    """
    session_id, _ = await session_registry.create("test-user")

    await vault._lock.acquire()
    destroyer = asyncio.create_task(vault.destroy(session_id))
    for _ in range(10):
        await asyncio.sleep(0)
    assert not destroyer.done(), "the destroy got past the lock while the test held it"

    # The key dies while the destroy is parked -- exactly the window a liveness
    # read taken before the acquire would have missed.
    assert await session_registry.destroy(session_id) is True
    vault._lock.release()
    await destroyer

    assert vault._destroyed == set(), "a tombstone was recorded for an already-dead key"
    assert vault.cached_session_ids() == frozenset()

    # Control: the same destroy on a session whose key IS still live does record
    # one, so the assertion above is measuring the liveness read rather than a
    # guard that never fires.
    live_id, _ = await session_registry.create("test-user")
    await vault.destroy(live_id)
    assert vault._destroyed == {live_id}


async def test_a_close_queued_ahead_of_a_write_fails_closed(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """A connection handle must be resolved under the lock that ``close`` takes.

    ``put``, ``_fetch_one`` and ``sweep_orphans`` each reach for ``self._conn``
    and then queue on ``self._lock``; ``close`` takes that same lock. So a close
    already queued on it runs *first*, and a handle resolved before the acquire
    was live when it was read and closed by the time it was used. The result was
    a bare ``sqlite3.ProgrammingError`` escaping a module whose entire contract
    for this state is ``PipelineError(reason="vault_closed")`` -- an
    unstructured 500 in place of a structured refusal.

    Nothing is patched and no ``sleep`` is inserted: this interleaving is
    reachable in the shipped code. Holding the lock only makes the queue order
    deterministic instead of a function of how many scheduling steps each
    coroutine happens to spend getting there.
    """
    session_id, _ = await session_registry.create("test-user")
    await put_value(vault, session_registry, session_id, VALUE_A)
    later = await make_record(session_registry, session_id, VALUE_B)

    await vault._lock.acquire()
    closer = asyncio.create_task(vault.close())
    for _ in range(10):
        await asyncio.sleep(0)
    victims: list[asyncio.Task[Any]] = [
        asyncio.create_task(vault.put(session_id, later, VALUE_B)),
        asyncio.create_task(vault.row_count(session_id)),
        asyncio.create_task(vault.sweep_orphans([session_id])),
    ]
    for _ in range(10):
        await asyncio.sleep(0)
    assert not any(task.done() for task in victims), (
        "a caller got past the vault lock while the test held it"
    )
    assert not closer.done()
    vault._lock.release()

    await closer
    outcomes = await asyncio.gather(*victims, return_exceptions=True)
    for outcome in outcomes:
        assert isinstance(outcome, PipelineError), (
            f"an unstructured {type(outcome).__name__} escaped the vault: {outcome!r}"
        )
        assert outcome.detail["reason"] == "vault_closed"


async def test_destroying_an_unknown_session_stores_no_state(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """``destroy`` on a session the registry never had must not accumulate anything.

    ``DELETE /session/{id}`` is caller-reachable, so per-session bookkeeping kept
    for an arbitrary ID would be an unbounded-growth lever.
    """
    for index in range(50):
        await vault.destroy(f"never-existed-{index}")
    assert vault.cached_session_ids() == frozenset()
    assert vault._destroyed == set()

    # A real session still tombstones, so the guard is not simply switched off.
    session_id, _ = await session_registry.create("test-user")
    await vault.destroy(session_id)
    assert vault._destroyed == {session_id}


async def test_sweep_orphans_deletes_unknown_sessions(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """Startup sweep: rows from sessions the (restarted) process cannot know."""
    live, _ = await session_registry.create("test-user")
    dead, _ = await session_registry.create("test-user")
    await put_value(vault, session_registry, live, VALUE_A)
    await put_value(vault, session_registry, dead, VALUE_B)

    # Emulate a restart: keys for `dead` are gone, its ciphertext is not.
    await session_registry.destroy(dead)
    known = await session_registry.active_ids()

    deleted = await vault.sweep_orphans(known)
    assert deleted == 1
    assert read_rows(db_path, dead) == []
    assert len(read_rows(db_path, live)) == 1


# ---------------------------------------------------------------------------
# 6. token-ID collision
# ---------------------------------------------------------------------------


async def test_token_id_collision_re_derivation(
    vault: SessionVault,
    session_registry: SessionRegistry,
    db_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force the 4-byte truncation to collide; the counter must break the tie."""
    real_derive = derive_token_id
    collided = "deadbeef"

    def colliding_derive(
        session_key: bytes, entity_type: str, value: str, *, counter: int = 0
    ) -> str:
        # Every distinct value truncates to the same prefix until the vault
        # re-derives with a counter -- the exact birthday-collision scenario.
        if counter == 0:
            return collided
        return real_derive(session_key, entity_type, value, counter=counter)

    monkeypatch.setattr(vault_module, "derive_token_id", colliding_derive)

    session_id, _ = await session_registry.create("test-user")
    session_key = await session_registry.key(session_id)

    # Both records arrive claiming the same token ID.
    for value in (VALUE_A, VALUE_B):
        record = TokenRecord(
            session_id=session_id,
            token_id=collided,
            entity_type="PATIENT_NAME",
            category=EntityCategory.PHI,
            surrogate=f"[PHI_PATIENT_NAME_{collided}_{value[:1]}]",
            created_at=time.time(),
        )
        await vault.put(session_id, record, value)

    rec_a = await vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_A))
    rec_b = await vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_B))
    assert rec_a is not None and rec_b is not None

    # Re-derivation happened, and it used the counter path.
    assert rec_a.token_id == collided
    assert rec_b.token_id != collided
    assert rec_b.token_id == real_derive(session_key, "PATIENT_NAME", VALUE_B, counter=1)

    # Two distinct rows, both originals independently recoverable.
    assert len(read_rows(db_path, session_id)) == 2
    assert await vault.get_by_token(session_id, rec_a.token_id) == VALUE_A
    assert await vault.get_by_token(session_id, rec_b.token_id) == VALUE_B
    assert vault.originals_for_session(session_id) == frozenset({VALUE_A, VALUE_B})


async def test_the_collision_retry_budget_survives_eight_consecutive_collisions(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """``MAX_COLLISION_RETRIES`` is load-bearing at 8, not decoration.

    ``test_token_id_collision_re_derivation`` above only ever needs *one*
    re-derivation, so it passes with the budget set to 1 -- the constant could be
    cut to a single retry and the whole suite stayed green. That matters because
    the budget is what stands between a truncation collision and a
    ``token_collision_unresolved`` outage: at 4-byte token IDs a session with a
    few thousand entities has a ~0.1% chance of one collision, and the counter
    path is the only thing that resolves it.

    So this walks the budget to its documented end. Counters 0..7 for one value
    are pre-occupied by *other* originals, which forces the resolver to reach
    counter 8 -- the last candidate a budget of 8 offers. No monkeypatching: the
    collisions are manufactured by handing real derived IDs to real ``put``
    calls, so what is exercised is the shipped derivation, not a stub of it.

    Deliberately hard-coded rather than written against ``MAX_COLLISION_RETRIES``:
    a test that indexes the constant it is guarding moves with it and guards
    nothing.
    """
    session_id, _ = await session_registry.create("test-user")
    session_key = await session_registry.key(session_id)
    victim = "Marisol Okonkwo-Bright"

    # The eight IDs the resolver will try before counter 8: the value's own
    # counter-0 ID plus its counters 1..7.
    blocked = [
        derive_token_id(session_key, "PATIENT_NAME", victim, counter=counter)
        for counter in range(8)
    ]
    assert len(set(blocked)) == 8, "the counter must change the derived ID"

    # Occupy every one of them with a *different* original, which is what makes
    # them collisions rather than this value seen before.
    for index, token_id in enumerate(blocked):
        decoy = f"Decoy Original {index:02d}"
        await vault.put(
            session_id,
            TokenRecord(
                session_id=session_id,
                token_id=token_id,
                entity_type="PATIENT_NAME",
                category=EntityCategory.PHI,
                surrogate=f"[PHI_PATIENT_NAME_{token_id}]",
                created_at=time.time(),
            ),
            decoy,
        )
    assert len(read_rows(db_path, session_id)) == 8

    await vault.put(
        session_id,
        TokenRecord(
            session_id=session_id,
            token_id=blocked[0],
            entity_type="PATIENT_NAME",
            category=EntityCategory.PHI,
            surrogate=f"[PHI_PATIENT_NAME_{blocked[0]}]",
            created_at=time.time(),
        ),
        victim,
    )

    stored = await vault.get_by_original(session_id, "PATIENT_NAME", normalize(victim))
    assert stored is not None
    assert stored.token_id == derive_token_id(session_key, "PATIENT_NAME", victim, counter=8), (
        "the eighth re-derivation must still be inside the budget"
    )
    assert stored.token_id not in blocked

    # Nine rows, nine originals, none overwritten: a budget that ran out would
    # have raised, and a budget that wrapped would have replaced a decoy's row.
    assert len(read_rows(db_path, session_id)) == 9
    assert await vault.get_by_token(session_id, stored.token_id) == victim
    for index, token_id in enumerate(blocked):
        assert await vault.get_by_token(session_id, token_id) == f"Decoy Original {index:02d}"


async def test_an_exhausted_collision_budget_raises_instead_of_reusing_an_id(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """Past the budget the vault fails loudly. Reusing an ID would mis-restore.

    The companion to the test above: that one pins the floor (the budget really
    does reach counter 8), this one pins that the loop is *bounded* and that its
    end is an error rather than a silently duplicated token ID -- two originals
    on one ID means ``get_by_token`` returns the wrong person's value with
    nothing red anywhere.

    The band assertion is the upper guard. A budget of 8 is "absurd headroom" as
    the constant's own note says; a budget of 10**9 turns a collision storm into
    a hang, and this test would be the thing that hangs, so state the bound.
    """
    assert 2 <= vault_module.MAX_COLLISION_RETRIES <= 64, (
        "the retry budget must stay a small bounded number"
    )

    session_id, _ = await session_registry.create("test-user")
    session_key = await session_registry.key(session_id)
    victim = "Anselm Fairweather-Nkemdirim"

    # Every candidate the resolver can produce -- counter 0 through the budget --
    # is already held by another original.
    for counter in range(vault_module.MAX_COLLISION_RETRIES + 1):
        token_id = derive_token_id(session_key, "PATIENT_NAME", victim, counter=counter)
        await vault.put(
            session_id,
            TokenRecord(
                session_id=session_id,
                token_id=token_id,
                entity_type="PATIENT_NAME",
                category=EntityCategory.PHI,
                surrogate=f"[PHI_PATIENT_NAME_{token_id}]",
                created_at=time.time(),
            ),
            f"Blocker {counter:02d}",
        )
    rows_before = len(read_rows(db_path, session_id))

    with pytest.raises(PipelineError) as excinfo:
        await vault.put(
            session_id,
            TokenRecord(
                session_id=session_id,
                token_id=derive_token_id(session_key, "PATIENT_NAME", victim),
                entity_type="PATIENT_NAME",
                category=EntityCategory.PHI,
                surrogate="[PHI_PATIENT_NAME_blocked]",
                created_at=time.time(),
            ),
            victim,
        )

    detail = excinfo.value.detail
    assert detail["reason"] == "token_collision_unresolved"
    assert detail["entity_type"] == "PATIENT_NAME"
    assert detail["attempts"] == vault_module.MAX_COLLISION_RETRIES
    # Section 16: the original must not ride out on the exception.
    rendered = f"{excinfo.value!r} {excinfo.value}"
    assert victim not in rendered

    # Nothing was written and nothing was overwritten.
    assert len(read_rows(db_path, session_id)) == rows_before
    assert victim not in vault.originals_for_session(session_id)


async def test_read_through_does_not_fork_a_value_into_two_tokens(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """A value recovered from a row must not look like a collision when re-put.

    This is the one place the cache and the database can disagree. Read-through
    fills ``by_token`` but cannot fill ``by_original`` -- the schema has no
    ``category`` column, so a full ``TokenRecord`` cannot be rebuilt from a row.
    A re-put of that value therefore skipped the idempotence check *and* found
    its own token ID occupied, so the collision path minted a second token: two
    rows, two surrogates and one original, with the returned record's
    ``token_id`` no longer matching the ``token_id`` embedded in its own
    ``surrogate``. Within-session determinism is the guarantee that breaks.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    cold = await SessionVault.open(db_path, session_registry)
    try:
        assert await cold.get_by_token(session_id, record.token_id) == VALUE_A
        assert cold.originals_for_session(session_id) == frozenset({VALUE_A})

        # What the obfuscation engine does next for the same value.
        again = await make_record(session_registry, session_id, VALUE_A)
        await cold.put(session_id, again, VALUE_A)

        stored = await cold.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_A))
        assert stored is not None
        assert stored.token_id == record.token_id, "the value was forked onto a second token"
        assert stored.surrogate == record.surrogate
        assert stored.token_id in stored.surrogate, "record and surrogate disagree on the token"
    finally:
        await cold.close()

    # One value, one row, still exactly one original on the wire-scan set.
    assert len(read_rows(db_path, session_id)) == 1
    assert await vault.get_by_token(session_id, record.token_id) == VALUE_A
    assert vault.originals_for_session(session_id) == frozenset({VALUE_A})


# ---------------------------------------------------------------------------
# 7. lookup latency
# ---------------------------------------------------------------------------


async def test_lookup_latency_p99(vault: SessionVault, session_registry: SessionRegistry) -> None:
    """1,000 cached lookups, p99 < 5 ms (build doc section 10.1)."""
    session_id, _ = await session_registry.create("test-user")
    records = [
        await put_value(vault, session_registry, session_id, f"Synthetic Subject {i:03d}")
        for i in range(50)
    ]

    samples: list[float] = []
    for i in range(1000):
        record = records[i % len(records)]
        start = time.perf_counter()
        await vault.get_by_token(session_id, record.token_id)
        samples.append((time.perf_counter() - start) * 1000.0)

    samples.sort()
    p99 = samples[int(len(samples) * 0.99) - 1]
    print(f"\nget_by_token p99 = {p99:.4f} ms (n=1000, max={samples[-1]:.4f} ms)")
    assert p99 < 5.0, f"p99 lookup latency {p99:.4f} ms exceeds the 5 ms budget"


def test_originals_for_session_is_sync_and_cache_backed(vault: SessionVault) -> None:
    """The EgressGate hot path must not await and must not raise on an unknown session."""
    assert vault.originals_for_session("never-existed") == frozenset()


async def test_the_egress_view_is_rebuilt_by_a_put_that_follows_a_read(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """A ``put`` after a gate read must invalidate the memo. A stale memo is a leak.

    ``originals_for_session`` memoises its frozenset, and the EgressGate scans
    outbound payloads for exactly the values it returns. So a memo that is not
    invalidated on write does not fail loudly -- it silently narrows the gate's
    search set, which is the one failure direction that ends in an original
    reaching the provider.

    Every other test in this file reads the view only *after* all of its puts,
    so the memo is always still cold when it is first built and the invalidation
    in ``_SessionCache.add`` is never exercised *here*. It was not, however,
    unobserved repo-wide, and saying so was wrong: deleting the line also turns
    ``tests/test_obfuscation.py::test_tokens_declare_every_surrogate_in_the_payload``
    red, and that test predates this one. The reason is the second half of the
    contract, below -- the pseudonymisation strategy reads the view, puts, and
    reads again inside a single obfuscation run, so it is the one existing caller
    that could see a stale memo. What this test adds is a *local* pin: the vault's
    own file should not need a strategy test to notice its cache going stale.

    **Two properties, not one, and the second has a real consumer.**
    ``ObfuscationStrategy._normalized_originals`` caches its normalised copy on
    the *identity* of the frozenset this method returns -- ``if current is not
    self._originals_source`` -- so the vault owes it both directions: a new
    object whenever the contents change, and the *same* object when they have
    not. Returning a fresh ``frozenset`` each call would keep every equality
    assertion above green while silently making that cache never hit.
    """
    session_id, _ = await session_registry.create("test-user")
    await put_value(vault, session_registry, session_id, VALUE_A)

    first = vault.originals_for_session(session_id)
    assert first == frozenset({VALUE_A}), "the memo was not built by the first read"
    assert vault.originals_for_session(session_id) is first, (
        "the memo is not being reused; a caller keyed on its identity would never hit"
    )

    await put_value(vault, session_registry, session_id, VALUE_B)

    second = vault.originals_for_session(session_id)
    assert second == frozenset({VALUE_A, VALUE_B}), (
        "the gate would have gone on scanning for a stale set of originals"
    )
    assert second is not first, "the write must hand out a new object, not mutate the old one"
    # The snapshot already handed to a caller is immutable, which is what lets
    # the gate hold one across a payload without copying it.
    assert first == frozenset({VALUE_A})


async def test_the_egress_view_is_rebuilt_by_a_read_through_that_follows_a_read(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """The *other* writer into the memo is ``note``, and it needs its own test.

    ``_SessionCache`` has two write paths -- ``add`` from ``put`` and ``note``
    from ``_decrypt_row``'s read-through -- and both must invalidate the memoised
    frozenset. The test above pins only ``add``. Deleting the invalidation from
    ``note`` instead left all 139 tests in this section green, because every
    other test that exercises read-through either never reads the view first or
    never reads it again afterwards.

    The consequence is identical to the one the ``add`` test exists for, and it
    is the leak direction rather than the loud one: the EgressGate scans outbound
    payloads for exactly the originals this view reports, so a memo that misses a
    value recovered from a row means the gate never looks for that value. It does
    not fail; it passes a payload it should have blocked.

    The interleaving is the cold-start one, which is ordinary rather than exotic:
    the process restarted (or a second instance picked up the session), so the
    cache is empty and is filled only by decrypting rows. Gate turn one, recover
    another entity for turn two, gate again.
    """
    session_id, _ = await session_registry.create("test-user")
    first_record = await put_value(vault, session_registry, session_id, VALUE_A)
    second_record = await put_value(vault, session_registry, session_id, VALUE_B)

    cold = await SessionVault.open(db_path, session_registry)
    try:
        assert cold.originals_for_session(session_id) == frozenset(), "cold cache, nothing yet"

        # Turn one: one value recovered from a row, then the gate reads the view.
        assert await cold.get_by_token(session_id, first_record.token_id) == VALUE_A
        built = cold.originals_for_session(session_id)
        assert built == frozenset({VALUE_A}), "the memo was not built by the first gate read"

        # Turn two: a second value arrives by read-through, not by put.
        assert await cold.get_by_token(session_id, second_record.token_id) == VALUE_B

        refreshed = cold.originals_for_session(session_id)
        assert refreshed == frozenset({VALUE_A, VALUE_B}), (
            "the gate would scan for a stale, narrower set and pass an original through"
        )
        assert refreshed is not built, "a changed set must be a new object; callers key on identity"
    finally:
        await cold.close()


async def test_the_egress_view_is_rebuilt_by_a_redact_band_note_that_follows_a_read(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """The third writer is ``add_gate_only``, and it is the one the gate needs most.

    ``_SessionCache`` has three write paths into the memoised egress view --
    ``add`` from ``put``, ``note`` from the read-through, and ``add_gate_only``
    from ``note_unrestorable`` -- and the two tests above pin the first two.
    Dropping ``self._view = None`` from ``add_gate_only`` left the whole suite
    green, and the value it drops is precisely the one with no other line of
    defence: a redact-band original has no token, no surrogate and no row, so the
    gate needle *is* the control. Tokenized values that go missing from the view
    are still caught downstream by the surrogate accounting; these are not.

    The window is ordinary rather than contrived. ``_resolve_groups`` performs
    every ``put`` for a turn *before* the splice loop, and ``note_unrestorable``
    is called from inside that loop, so in a turn whose detections all land in the
    redact band nothing between the gate's last read and the note invalidates
    anything -- the memo built for the previous payload is still there and still
    answers. Stale, it hands the gate a needle set that never contained the
    redacted value, and the leak is the measured one in ``note_unrestorable``'s
    own docstring: the same nine digits reaching the provider inside
    ``ledgerref452189376x`` with the gate reporting clean.
    """
    # Synthetic, SSN-shaped: the redact band is where this method's leak lived.
    unrestorable = "452189376"
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    first = vault.originals_for_session(session_id)
    assert first == frozenset({VALUE_A}), "the memo was not built by the first gate read"
    assert vault.originals_for_session(session_id) is first, "the memo is not being reused"

    vault.note_unrestorable(session_id, unrestorable)

    second = vault.originals_for_session(session_id)
    assert second == frozenset({VALUE_A, unrestorable}), (
        "the gate would go on scanning a needle set that never saw the redacted value"
    )
    assert second is not first, "the write must hand out a new object, not mutate the old one"

    # ...and the needle is still not a restore path: no token, no surrogate, no row.
    assert dict(vault.surrogates_for_session(session_id)) == {record.surrogate: VALUE_A}
    assert await vault.get_by_original(session_id, "SSN", normalize(unrestorable)) is None
    with pytest.raises(VaultMissError):
        await vault.get_by_surrogate(session_id, unrestorable)


def _cache_writer_methods() -> frozenset[str]:
    """``_SessionCache`` methods that add a value to one of the plaintext containers.

    Read off the module's AST -- ``self.<container>[...] = ...`` and
    ``self.<container>.add(...)`` -- so the enumeration is derived independently
    of anything ``_SessionCache`` says about itself. Memo assignments
    (``self._view = None``) are plain attribute stores and are deliberately not
    matched: the point is to find the writers, not the invalidations.
    """
    tree = ast.parse(inspect.getsource(vault_module))
    class_def = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_SessionCache"
    )
    containers = {"by_token", "by_surrogate", "by_original", "originals", "gate_only"}

    def _is_container(node: ast.expr) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr in containers
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        )

    found: set[str] = set()
    for method in class_def.body:
        if not isinstance(method, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(method):
            writes = (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add"
                and _is_container(node.func.value)
            ) or (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Subscript) and _is_container(target.value)
                    for target in node.targets
                )
            )
            if writes:
                found.add(method.name)
    return frozenset(found)


async def test_every_session_cache_writer_invalidates_the_memoised_egress_view(
    session_registry: SessionRegistry,
) -> None:
    """The invalidation is a property of *every* writer, asserted as one table.

    The three tests above each pin one writer, which is how ``add_gate_only``
    came to be the writer with no test: it was added later and the pattern was
    not extended. Here the writers are enumerated from the class's own source, so
    a fourth one cannot be added and left out -- the enumeration assertion goes
    red before any leak does.

    Driven directly against ``_SessionCache`` rather than through the vault
    because the property belongs to the cache: a memo that survives a write is a
    narrower needle set for the EgressGate, whichever call reached it.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await make_record(session_registry, session_id, VALUE_B)
    index = ("PATIENT_NAME", normalize(VALUE_B))
    writers: dict[str, Callable[[Any], None]] = {
        "add": lambda cache: cache.add(index, record, VALUE_B),
        "note": lambda cache: cache.note(record.token_id, record.surrogate, VALUE_B),
        "add_gate_only": lambda cache: cache.add_gate_only(VALUE_B),
    }

    actual = _cache_writer_methods()
    assert set(writers) == actual, (
        f"_SessionCache writes plaintext from {sorted(actual)}; this table drives "
        f"{sorted(writers)}. Every writer owes the gate a fresh view."
    )

    for name, write in writers.items():
        cache = vault_module._SessionCache()
        cache.add_gate_only(VALUE_A)
        memo = cache.view()
        assert memo == frozenset({VALUE_A}), f"{name}: the memo was not built before the write"

        write(cache)
        rebuilt = cache.view()
        assert VALUE_B in rebuilt, f"{name} left a stale memo; the gate would not scan for it"
        assert rebuilt is not memo, f"{name}: a changed set must be a new object"
        assert VALUE_A in rebuilt, f"{name} dropped a value the gate already had"


async def test_read_through_populates_both_lookup_indexes(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """One decrypt must fill ``by_token`` *and* ``by_surrogate``, or the hot path re-reads disk.

    Dropping the surrogate half of ``_SessionCache.note`` is invisible to any
    correctness assertion: ``get_by_surrogate`` still returns the right value,
    it just fetches and decrypts a row every single time. ``get_by_surrogate``
    is the de-obfuscation hot path and the p99 budget in build doc section 10.1
    is the cached path's, not SQLite's -- so what is asserted here is that the
    second lookup does not touch the database at all.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A)

    cold = await SessionVault.open(db_path, session_registry)
    try:
        fetches = 0
        real_fetch = cold._fetch_one

        async def counting_fetch(sql: str, params: tuple[object, ...]) -> Any:
            nonlocal fetches
            fetches += 1
            return await real_fetch(sql, params)

        cold._fetch_one = counting_fetch  # type: ignore[method-assign]

        assert await cold.get_by_token(session_id, record.token_id) == VALUE_A
        assert fetches == 1, "the cold read was not served from SQLite"

        assert await cold.get_by_surrogate(session_id, record.surrogate) == VALUE_A
        assert fetches == 1, "the surrogate index was not filled by the read-through"

        # ...and the token index too, from that same single decrypt.
        assert await cold.get_by_token(session_id, record.token_id) == VALUE_A
        assert fetches == 1
    finally:
        await cold.close()


async def test_a_cold_cache_collision_replaces_a_row_rather_than_re_deriving(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """The collision guard reads the cache, never the database. Pinned, not claimed.

    ``_resolve_token_id`` asks ``_SessionCache.taken()``, and ``put`` writes with
    ``INSERT OR REPLACE``. A row this *instance* has neither written nor read
    back is therefore invisible to the guard, so a genuine 4-byte HMAC collision
    against such a row silently overwrites it instead of re-deriving: one value
    becomes permanently unrecoverable and its surrogate stops resolving.

    Two things bound it. It needs a real truncation collision -- ~n²/2³³, so
    ~10⁻³ at the few thousand entities per session the build doc anticipates --
    *and* a second ``SessionVault`` over the same file with a cold cache. The
    shipped app builds exactly one vault per process and session keys do not
    survive a restart, so the second condition does not arise in the deployed
    configuration; it is reachable here only because the tests open a second
    instance deliberately.

    ``INSERT OR REPLACE`` is not the bug and must not be "fixed" to a plain
    ``INSERT``: ``test_read_through_does_not_fork_a_value_into_two_tokens``
    depends on a cold re-put of the *same* value rewriting its own row. This
    test exists so that the guard's scope cannot quietly be restated as
    "collisions are handled" -- narrowing it has to change a test, not a
    docstring.
    """
    session_id, _ = await session_registry.create("test-user")
    collided = "deadbeef"

    def colliding_record(value: str) -> TokenRecord:
        return TokenRecord(
            session_id=session_id,
            token_id=collided,
            entity_type="PATIENT_NAME",
            category=EntityCategory.PHI,
            surrogate=f"[PHI_PATIENT_NAME_{collided}_{value[:1]}]",
            created_at=time.time(),
        )

    first = colliding_record(VALUE_A)
    await vault.put(session_id, first, VALUE_A)
    assert await vault.get_by_token(session_id, collided) == VALUE_A

    # In-process the cache *is* authoritative, so the guard works: a second
    # value claiming the same token is re-derived onto its own row.
    await vault.put(session_id, colliding_record(VALUE_B), VALUE_B)
    assert len(read_rows(db_path, session_id)) == 2
    assert await vault.get_by_token(session_id, collided) == VALUE_A

    # A cold instance cannot see either row until it reads one, so the same
    # collision now replaces rather than re-derives.
    cold = await SessionVault.open(db_path, session_registry)
    try:
        third = colliding_record("Rowan Delacroix-Sung")
        await cold.put(session_id, third, "Rowan Delacroix-Sung")
        assert await cold.get_by_token(session_id, collided) == "Rowan Delacroix-Sung"
        with pytest.raises(VaultMissError):
            await cold.get_by_surrogate(session_id, first.surrogate)
    finally:
        await cold.close()

    assert len(read_rows(db_path, session_id)) == 2, (
        "the colliding put should have replaced a row, not added one"
    )


# ---------------------------------------------------------------------------
# 8. expiry
# ---------------------------------------------------------------------------


async def test_expired_session(
    vault: SessionVault,
    session_registry: SessionRegistry,
    clock: FakeClock,
    db_path: Path,
) -> None:
    """TTL elapsed => ``SessionExpiredError`` everywhere, and the vault is destroyed."""
    # A zero TTL is expired the instant it is asked for.
    zero_ttl, _ = await session_registry.create("test-user", ttl_seconds=0)
    with pytest.raises(SessionExpiredError):
        await session_registry.key(zero_ttl)
    with pytest.raises(SessionExpiredError):
        await vault.get_by_token(zero_ttl, "00000000")

    # A session that expires *after* it has stored entries.
    session_id, expires_at = await session_registry.create("test-user", ttl_seconds=60)
    record = await put_value(vault, session_registry, session_id, VALUE_A)
    assert await vault.get_by_token(session_id, record.token_id) == VALUE_A

    clock.advance(61)
    assert clock() > expires_at

    # The sweep reports it (nothing has touched the registry since expiry, so
    # this is the sweep's own detection, not an access-time one).
    expired = await session_registry.sweep()
    assert session_id in expired
    assert await session_registry.active_ids() == frozenset()

    # Every accessor propagates the registry's error -- the vault never swallows it.
    for accessor in (
        vault.get_by_token(session_id, record.token_id),
        vault.get_by_surrogate(session_id, record.surrogate),
        vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_A)),
        vault.put(session_id, record, VALUE_A),
    ):
        with pytest.raises(SessionExpiredError):
            await accessor

    # The destruction path is the same as logout: sweep the registry, then the vault.
    for dead_session in expired:
        await vault.destroy(dead_session)

    assert read_rows(db_path, session_id) == []
    assert vault.originals_for_session(session_id) == frozenset()


# ---------------------------------------------------------------------------
# 8b. session -> user binding (the registry half; the routes are in test_api)
# ---------------------------------------------------------------------------


async def test_a_session_is_bound_to_the_user_that_created_it(
    session_registry: SessionRegistry,
) -> None:
    """Without the binding a session ID is a bearer credential for *any* user."""
    session_id, _ = await session_registry.create("alice")

    assert await session_registry.owner(session_id) == "alice"
    assert await session_registry.belongs_to(session_id, "alice") is True
    assert await session_registry.belongs_to(session_id, "mallory") is False
    # Neither a prefix nor a superstring of the owner is the owner.
    for near_miss in ("alic", "alice2", "alice ", "ALICE", ""):
        assert await session_registry.belongs_to(session_id, near_miss) is False


async def test_belongs_to_is_total_over_non_ascii_identifiers(
    session_registry: SessionRegistry,
) -> None:
    """``compare_digest`` on ``str`` raises for non-ASCII -- and that is an oracle.

    Nothing upstream constrains an identifier's character set, so the ownership
    check has to answer rather than raise for every ``str``. It did not: a live
    session owned by ``"josé"`` raised ``TypeError`` while an *unknown* session
    returned ``False``, so the two were distinguishable -- which is precisely the
    existence oracle the uniform answer exists to deny. A user with an accent in
    their ID also could not log out at all.
    """
    accented_owner, _ = await session_registry.create("josé")
    ascii_owner, _ = await session_registry.create("alice")
    unknown = uuid.uuid4().hex

    # The owner can still spend their own session.
    assert await session_registry.belongs_to(accented_owner, "josé") is True

    # Every combination answers instead of raising...
    for session_id, claim in (
        (accented_owner, "alice"),
        (accented_owner, "アリス"),
        (ascii_owner, "ålice"),
        (unknown, "josé"),
    ):
        assert await session_registry.belongs_to(session_id, claim) is False

    # ...and a live session is indistinguishable from an absent one to a caller
    # presenting the wrong ID, whatever alphabet either side is written in.
    assert await session_registry.belongs_to(ascii_owner, "é") is (
        await session_registry.belongs_to(unknown, "é")
    )


async def test_belongs_to_compares_in_constant_time(
    session_registry: SessionRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timing property cannot be observed from a unit test, so pin the mechanism.

    ``user_id`` is attacker-supplied and is compared against the owner this
    process recorded; a byte-by-byte early exit leaks that owner one character at
    a time. Wall-clock assertions on a comparison this short are pure noise, so
    what is asserted is that the constant-time comparator is the thing actually
    called -- and called on ``bytes``, which is the form that never raises.
    """
    calls: list[tuple[object, object]] = []
    real = secrets.compare_digest

    def spy(left: Any, right: Any) -> bool:
        calls.append((left, right))
        return bool(real(left, right))

    monkeypatch.setattr(registry_module.secrets, "compare_digest", spy)

    session_id, _ = await session_registry.create("alice")
    assert await session_registry.belongs_to(session_id, "alice") is True
    assert await session_registry.belongs_to(session_id, "mallory") is False

    assert len(calls) == 2, "the ownership check did not go through compare_digest"
    for left, right in calls:
        assert isinstance(left, bytes) and isinstance(right, bytes), (
            "compare_digest was handed str, which raises on any non-ASCII identifier"
        )


async def test_owner_gives_no_existence_oracle(session_registry: SessionRegistry) -> None:
    """An unknown, an expired and a hostile session ID all fail identically."""
    live, _ = await session_registry.create("alice")
    expired, _ = await session_registry.create("alice", ttl_seconds=0)

    errors = []
    for session_id in (uuid.uuid4().hex, expired, "../../etc/passwd", "x" * 4096):
        with pytest.raises(SessionExpiredError) as err:
            await session_registry.owner(session_id)
        errors.append(err.value)
        # A caller-supplied ID is clamped, so a hostile one cannot turn the
        # error into a ValueError from PipelineError's own length guard.
        detail = err.value.detail["session_id"]
        assert isinstance(detail, str)
        assert len(detail) <= 64

    assert {type(e) for e in errors} == {SessionExpiredError}
    assert {e.code for e in errors} == {errors[0].code}
    # The live session is the only one that answers, and it never leaks the key.
    assert await session_registry.owner(live) == "alice"
    assert (await session_registry.key(live)).hex() not in str(errors[0])


async def test_registry_never_reveals_keys_in_repr(session_registry: SessionRegistry) -> None:
    """A key must not reach a log line, a traceback or a REPL -- in *any* rendering.

    ``key.hex()`` is not how Python prints ``bytes``. A ``__repr__`` that leaked
    the session map would render ``_Session(key=b'\\x8f\\xa2...', ...)``, and the
    hex string appears nowhere in that -- so a test that greps only for the hex
    form is a checker carrying the same blind spot as the thing it checks, and it
    passes while the key goes to disk in a log. The byte rendering is asserted
    alongside it, and it is the one that actually catches the mistake.
    """
    session_id, _ = await session_registry.create("test-user")
    key = await session_registry.key(session_id)
    rendered = f"{session_registry!r} {session_registry}"
    assert key.hex() not in rendered
    assert repr(key) not in rendered, "the session key was rendered as bytes"
    assert repr(key)[2:-1] not in rendered, "the escaped key body was rendered"
    assert "_Session" not in rendered, "the session map itself was rendered"
    assert "active=1" in rendered
    assert await session_registry.destroy(session_id) is True
    assert await session_registry.destroy(session_id) is False


def _log_render(fmt: str, value: object) -> str:
    """Exactly what ``logger.debug(fmt, value)`` would write to a handler.

    ``logging`` defers formatting to ``LogRecord.getMessage()``, so this is the
    real interpolation path rather than a hand-rolled ``%`` that only resembles
    it.
    """
    record = logging.LogRecord("t", logging.DEBUG, __file__, 0, fmt, (value,), None)
    return record.getMessage()


async def test_session_entry_itself_never_reveals_the_key_in_any_rendering(
    session_registry: SessionRegistry,
) -> None:
    """The *entry* must mask too, not just the registry that holds it.

    ``test_registry_never_reveals_keys_in_repr`` above pins
    ``repr(SessionRegistry)``. That is the object a caller usually has, but it is
    not the object a key escapes through. ``_Session`` was a ``NamedTuple``,
    which *generates* a ``__repr__`` rendering every field, so ``repr(entry)``
    -- and therefore ``repr`` of the ``_sessions`` dict, and therefore one
    ``logger.debug("%r", self._sessions)`` -- printed the raw 32-byte session key
    as a ``bytes`` literal. The registry's mask hid the map, so nothing observed
    it: every other key-bearing object in the codebase opts out of its default
    repr, and this was the single one that did not.

    The assertions deliberately do **not** stop at ``key.hex()``. Python does not
    print ``bytes`` as hex, so a test that greps only the hex form is a checker
    carrying the same blind spot as the thing it checks -- the exact defect class
    this project has hit repeatedly -- and it would pass while the key went to
    disk. ``repr(key)`` and the escaped body are the renderings that actually
    catch it.

    The tuple check is the structural half. A masked ``__repr__`` on a
    ``NamedTuple`` would satisfy every string assertion here and still leak,
    because a ``NamedTuple`` *is* a ``tuple``: ``tuple(entry)``, ``entry[0]`` and
    unpacking all route around ``__repr__`` and hand the key back to a default
    renderer. Only the non-tuple form closes that.
    """
    session_id, _ = await session_registry.create("test-user")
    key = await session_registry.key(session_id)
    entry = session_registry._sessions[session_id]

    # The key is genuinely in there -- otherwise this test proves nothing.
    assert entry.key == key
    assert len(key) == 32

    forbidden = {
        "hex": key.hex(),
        "bytes repr": repr(key),
        "escaped body": repr(key)[2:-1],
    }
    # Every ordinary way an object reaches a log line or a traceback.
    renderings = {
        "repr(entry)": repr(entry),
        "str(entry)": str(entry),
        "f-string !r": f"{entry!r}",
        "repr(_sessions)": repr(session_registry._sessions),
        "inside a list": repr([entry]),
        # The accident this guard exists for, driven through the real formatter
        # rather than imitated: ``logger.debug("%r", entry)`` renders lazily via
        # ``LogRecord.getMessage()``, which is where a key would actually reach a
        # log file. Both the entry and the whole session map go through it.
        "logging %r of the entry": _log_render("%r", entry),
        "logging %s of the entry": _log_render("%s", entry),
        "logging %r of the map": _log_render("%r", session_registry._sessions),
    }
    for how, rendered in renderings.items():
        for form, secret in forbidden.items():
            assert secret not in rendered, f"the session key leaked as {form} via {how}"

    # Masked, not merely truncated: the non-secret fields still render, so the
    # guard cannot be satisfied by an empty repr that hides a future field too.
    assert "key='***'" in repr(entry)
    assert "test-user" in repr(entry)

    assert not isinstance(entry, tuple), (
        "_Session must not be a tuple: the tuple protocol re-exposes the key regardless of __repr__"
    )


async def test_concurrent_open_creates_exactly_one_connection(
    db_path: Path, session_registry: SessionRegistry
) -> None:
    """Racing ``_connect`` must not leak a connection.

    ``aiosqlite`` backs every connection with a **non-daemon** thread, so a
    connection that is opened, overwritten and never closed keeps the interpreter
    alive at shutdown -- the process simply hangs. The two openers also collide
    on ``PRAGMA journal_mode=WAL``, which surfaces as a spurious
    ``database is locked``.
    """
    instance = SessionVault(db_path, session_registry)
    # ``aiosqlite.Connection`` *is* the thread, so the objects handed out here
    # are exactly the threads that would be stranded.
    connections: list[threading.Thread] = []
    real_connect = vault_module.aiosqlite.connect

    def counting_connect(*args: Any, **kwargs: Any) -> Any:
        connection = real_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(vault_module.aiosqlite, "connect", counting_connect)
        await asyncio.gather(*(instance._connect() for _ in range(6)))

    assert len(connections) == 1, f"{len(connections)} connections opened, expected 1"

    # The one connection is the one the vault actually uses.
    session_id, _ = await session_registry.create("test-user")
    await put_value(instance, session_registry, session_id, VALUE_A)
    await instance.close()

    deadline = time.monotonic() + 5.0
    while any(connection.is_alive() for connection in connections):
        assert time.monotonic() < deadline, "an aiosqlite thread outlived close()"
        await asyncio.sleep(0.01)


async def test_vault_repr_holds_no_originals(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    session_id, _ = await session_registry.create("test-user")
    await put_value(vault, session_registry, session_id, VALUE_A)
    rendered = f"{vault!r} {vault}"
    assert VALUE_A not in rendered
    assert "cached_entries=1" in rendered


# ---------------------------------------------------------------------------
# 8c. the reaper's explanatory prose, pinned to the real call graph
# ---------------------------------------------------------------------------

#: ``_sweep_locked``'s docstring writes its caller count as an English word.
_COUNT_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
}


def _self_calls(function: ast.AST, attribute: str) -> bool:
    """Whether ``function``'s body contains a ``self.<attribute>(...)`` call.

    Derived from the AST of the module source, not from anything
    ``session_registry.py`` exports. The point of this test is that the docstring
    and the code are checked against each other by two independent readings; a
    helper imported from the module under test would collapse them into one.
    """
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == attribute
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
        for node in ast.walk(function)
    )


def _registry_methods() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(inspect.getsource(registry_module))
    class_def = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "SessionRegistry"
    )
    return {
        node.name: node
        for node in class_def.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def test_the_sweep_caller_enumeration_in_the_docstring_is_the_real_one() -> None:
    """``_sweep_locked``'s docstring names its callers; those names must be real.

    That docstring is the only place the reaper's failure mode is explained -- why
    a method that returns a list every caller discards is nonetheless the hinge of
    the destruction path -- so the enumeration in it is read by humans as fact. It
    had drifted: it claimed **six** accessors and named ``expires_at``, which is a
    ``_Session`` field and an element of ``create``'s return tuple but has never
    been a method on ``SessionRegistry``, and ``belongs_to``, which does not call
    ``_sweep_locked`` at all (it calls ``owner``, which does). The truth is five
    direct callers: ``create``, ``sweep``, ``key``, ``owner``, ``active_ids``.

    Both errors survived every green run because no assertion had ever read the
    sentence. This one parses the names back out of the docstring and compares
    them against call sites it locates itself, by walking the module's AST -- two
    readings that share no code, so agreement is evidence rather than tautology.
    The indirect claim is checked too, in both directions: ``belongs_to`` must
    reach the sweep through the method the prose names, and must not be a direct
    caller.
    """
    doc = registry_module.SessionRegistry._sweep_locked.__doc__
    assert doc is not None, "the docstring under test was stripped (python -OO?)"

    # The claim is one bolded sentence followed by a dash-delimited enumeration
    # that ends at " -- so ". Split it into the direct names and the indirect aside.
    bold = re.search(r"\*\*(.+?)\*\*", doc, re.S)
    assert bold is not None, "the caller-count sentence is no longer bolded"
    count_word = re.split(r"\s+", bold.group(1).strip())[0].lower()
    assert count_word in _COUNT_WORDS, f"unparseable caller count {count_word!r}"

    clause = doc.split("**")[2].partition(" -- so ")[0]
    direct_part, _, indirect_part = clause.partition(", with ")
    documented_direct = re.findall(r"``(\w+)``", direct_part)
    documented_indirect = re.findall(r"``(\w+)``", indirect_part)
    assert len(documented_direct) == len(set(documented_direct)), "a name is listed twice"

    methods = _registry_methods()
    actual_direct = sorted(
        name
        for name, node in methods.items()
        if name != "_sweep_locked" and _self_calls(node, "_sweep_locked")
    )

    # Every name the prose uses must exist. This is the assertion `expires_at`
    # would have failed; it is a property (the attribute resolves to a method),
    # not a spelling, so widening or renaming the API cannot make it wrong.
    for name in documented_direct + documented_indirect:
        assert callable(getattr(registry_module.SessionRegistry, name, None)), (
            f"the docstring names `{name}` as part of the sweep call graph, but "
            f"SessionRegistry has no such method"
        )

    assert sorted(documented_direct) == actual_direct, (
        f"the docstring lists {sorted(documented_direct)} as the direct callers of "
        f"_sweep_locked; the module source actually calls it from {actual_direct}"
    )
    assert _COUNT_WORDS[count_word] == len(actual_direct), (
        f"the docstring says {count_word} callers; there are {len(actual_direct)}"
    )

    # The aside: "<method> reaching it indirectly through <route>".
    assert len(documented_indirect) == 2, "the indirect-caller aside no longer names two methods"
    indirect_name, route = documented_indirect
    assert indirect_name not in actual_direct, (
        f"`{indirect_name}` is documented as an indirect caller but calls _sweep_locked directly"
    )
    assert _self_calls(methods[indirect_name], route), (
        f"the docstring says `{indirect_name}` reaches the sweep through `{route}`, "
        f"but it does not call `{route}`"
    )
    assert route in actual_direct, f"`{route}` is the documented route but does not sweep"


def test_sweeps_inline_comment_names_the_other_sweepers_correctly() -> None:
    """``sweep``'s body carries a second copy of the same enumeration; it rots too.

    The comment above ``_drain_unreaped_locked()`` explains why ``sweep`` returns
    everything outstanding rather than what this call observed, and it does so by
    naming the *other* methods that may have dropped the session first. It said
    "six other accessors" while five methods in total sweep -- the same miscount as
    the docstring, in the one place a reader looking at the return value will see
    it. Asserted as a property (the named set is exactly the direct callers other
    than ``sweep`` itself) so rewording the comment cannot break it, only getting
    the call graph wrong can.
    """
    methods = _registry_methods()
    actual_direct = {
        name
        for name, node in methods.items()
        if name != "_sweep_locked" and _self_calls(node, "_sweep_locked")
    }
    source = inspect.getsource(registry_module.SessionRegistry.sweep)

    # Single-backtick names only: the lookarounds skip ``VAULT_DESTROY`` and any
    # other reST double-backtick literal in the docstring above the comment.
    named = re.findall(r"(?<!`)`(\w+)`(?!`)", source)
    assert set(named) == actual_direct - {"sweep"}, (
        f"sweep's comment names {sorted(set(named))} as the other methods that "
        f"sweep; the module source says {sorted(actual_direct - {'sweep'})}"
    )

    count = re.search(r"\b(\w+) other\b", source)
    assert count is not None, "sweep's comment no longer counts the other sweepers"
    word = count.group(1).lower()
    assert word in _COUNT_WORDS, f"unparseable count {word!r}"
    assert _COUNT_WORDS[word] == len(actual_direct - {"sweep"}), (
        f"sweep's comment says {word} other sweepers; there are {len(actual_direct - {'sweep'})}"
    )


# ---------------------------------------------------------------------------
# 9. concurrent session isolation (build doc section 10.6)
# ---------------------------------------------------------------------------


async def test_surrogates_for_session_is_scoped_to_its_own_session(
    vault: SessionVault, session_registry: SessionRegistry
) -> None:
    """The collision guard's input must be one session's pairs, not the process's.

    ``surrogates_for_session`` hands the Tier-1 pseudonymisation collision guard
    ``surrogate -> original`` -- both halves, because whether a candidate fake
    makes an already-issued surrogate un-restorable depends on how the
    *originals* nest. Its whole appearance in the suite was
    ``assert env.vault.surrogates_for_session(env.session_id) == {}`` in a session
    that had vaulted nothing, which cannot distinguish "scoped correctly" from
    "not scoped at all": replacing the body with a merge over every live session's
    cache left the whole suite green.

    The consequence is not a direct disclosure -- the guard only returns a bool --
    but session B's fake selection would become a function of session A's
    plaintext, which is the same cross-session coupling the vault key and the AAD
    exist to prevent. Asserted here as exact mapping equality in two directions,
    the shape ``test_cross_session_non_determinism`` already uses: a merged
    mapping fails both halves.
    """
    session_a, _ = await session_registry.create("test-user")
    session_b, _ = await session_registry.create("test-user")
    record_a = await put_value(vault, session_registry, session_a, VALUE_A)
    record_b = await put_value(vault, session_registry, session_b, VALUE_B)
    assert record_a.surrogate != record_b.surrogate

    assert dict(vault.surrogates_for_session(session_a)) == {record_a.surrogate: VALUE_A}
    assert dict(vault.surrogates_for_session(session_b)) == {record_b.surrogate: VALUE_B}
    assert dict(vault.surrogates_for_session("never-existed")) == {}

    # Memoised like the egress view, and invalidated by the next write: a guard
    # reading a stale mapping fails permissive, which is the quiet direction.
    memo = vault.surrogates_for_session(session_a)
    assert vault.surrogates_for_session(session_a) is memo, "the mapping is not memoised"
    later = await put_value(vault, session_registry, session_a, "Marisol Quintanilla")
    assert dict(vault.surrogates_for_session(session_a)) == {
        record_a.surrogate: VALUE_A,
        later.surrogate: "Marisol Quintanilla",
    }
    # ...and session B is untouched by A's write, in both directions.
    assert dict(vault.surrogates_for_session(session_b)) == {record_b.surrogate: VALUE_B}

    await vault.destroy(session_a)
    assert dict(vault.surrogates_for_session(session_a)) == {}
    assert dict(vault.surrogates_for_session(session_b)) == {record_b.surrogate: VALUE_B}


async def test_concurrent_session_isolation(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """Two sessions, 50 interleaved puts of the *same* values, via ``asyncio.gather``."""
    session_a, _ = await session_registry.create("test-user")
    session_b, _ = await session_registry.create("test-user")
    values = [f"Synthetic Subject {i:02d}" for i in range(25)]

    async def op(session_id: str, value: str) -> TokenRecord:
        return await put_value(vault, session_registry, session_id, value)

    # Interleave so both sessions are writing at the same time.
    coros = []
    for value in values:
        coros.append(op(session_a, value))
        coros.append(op(session_b, value))
    assert len(coros) == 50

    results = await asyncio.gather(*coros)
    records_a = {r.token_id for r in results[0::2]}
    records_b = {r.token_id for r in results[1::2]}

    assert len(records_a) == len(values)
    assert len(records_b) == len(values)
    assert records_a.isdisjoint(records_b)

    # No cross-session read succeeds, by token or by surrogate.
    by_surrogate_a = {
        (await vault.get_by_original(session_a, "PATIENT_NAME", normalize(v))) for v in values
    }
    for token_id in records_a:
        with pytest.raises(VaultMissError):
            await vault.get_by_token(session_b, token_id)
    for token_id in records_b:
        with pytest.raises(VaultMissError):
            await vault.get_by_token(session_a, token_id)
    for record in by_surrogate_a:
        assert record is not None
        with pytest.raises(VaultMissError):
            await vault.get_by_surrogate(session_b, record.surrogate)

    # Identical inputs, disjoint ciphertexts.
    ct_a = {bytes(row["ciphertext"]) for row in read_rows(db_path, session_a)}
    ct_b = {bytes(row["ciphertext"]) for row in read_rows(db_path, session_b)}
    assert len(ct_a) == len(values)
    assert ct_a.isdisjoint(ct_b)

    # Each session sees only its own originals, and destroying one leaves the other intact.
    assert vault.originals_for_session(session_a) == frozenset(values)
    assert vault.originals_for_session(session_b) == frozenset(values)
    await vault.destroy(session_a)
    assert vault.originals_for_session(session_a) == frozenset()
    assert vault.originals_for_session(session_b) == frozenset(values)
    assert len(read_rows(db_path, session_b)) == len(values)


# ---------------------------------------------------------------------------
# 15. a vault.db this process cannot read
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent

API_OWNER = "alice"

#: One occurrence of each entity, no value that is a substring of another -- the
#: same shape ``tests/test_api.py`` uses, so what the ASGI test below measures is
#: the refusal and not the detector.
API_DOC_TEXT = """CLINIC INTAKE RECORD

Patient name: David Ochoa.

MRN: 9224297.

Phone: (704) 555-0151.
"""


async def api_session(http: AsyncClient, user_id: str = API_OWNER) -> str:
    response = await http.post("/sessions", json={"user_id": user_id})
    assert response.status_code == 200, response.text
    session_id: str = response.json()["session_id"]
    return session_id


async def api_run(http: AsyncClient, session_id: str, doc_id: str) -> Any:
    return await http.post(
        "/pipeline/run",
        json={
            "user_id": API_OWNER,
            "doc_id": doc_id,
            "prompt": "Summarise this record in two sentences.",
            "session_id": session_id,
        },
    )


def wreck_every_page_but_the_header(path: Path) -> None:
    """Garbage every page of a real SQLite file except page 1, keeping its length.

    Genuinely corrupt, not a patched raise. The length is what gets past ``open``:
    the header records the database size in pages, so a *short* file is rejected
    outright while a full-length file whose data pages are dead is opened happily
    and fails only when something reads one. Page 1 survives because that is where
    the schema lives, and ``SessionVault._connect`` runs ``CREATE TABLE IF NOT
    EXISTS`` and has to parse it.

    :func:`integrity_check` on the result reports ``database disk image is
    malformed``, and every test below calls it rather than trusting this function
    -- a corruption that SQLite shrugged off would make the refusals it measures
    prove nothing.
    """
    data = bytearray(path.read_bytes())
    page = 4096
    assert len(data) >= 2 * page, "database is too small for this corruption to be meaningful"
    for start in range(page, len(data), page):
        data[start : start + page] = (b"\xde\xad\xbe\xef" * (page // 4))[: len(data) - start]
    path.write_bytes(bytes(data))


def integrity_check(path: Path) -> str:
    """``PRAGMA integrity_check`` through the stdlib driver, errors included."""
    conn = sqlite3.connect(path)
    try:
        try:
            return str(conn.execute("PRAGMA integrity_check").fetchone())
        except sqlite3.DatabaseError as exc:
            return f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()


async def fill_and_wreck(
    vault: SessionVault,
    session_registry: SessionRegistry,
    db_path: Path,
    *,
    surrogate: str | None = None,
) -> tuple[str, TokenRecord]:
    """Store one entity, then physically wreck the file underneath the vault.

    Closed and re-opened around the corruption rather than written behind SQLite's
    back, so the page cache cannot mask it: the returned vault reads the same bytes
    a restarted process would.
    """
    session_id, _ = await session_registry.create("test-user")
    record = await put_value(vault, session_registry, session_id, VALUE_A, surrogate=surrogate)
    await vault.close()
    wreck_every_page_but_the_header(db_path)
    assert "malformed" in integrity_check(db_path), (
        f"the file is still readable, so nothing below is measuring a refusal: "
        f"{integrity_check(db_path)}"
    )
    await vault._connect()
    return session_id, record


async def test_a_corrupt_vault_refuses_the_read_rather_than_reporting_a_miss(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """An unreadable row is not an absent row, and the difference is the whole fix.

    Every other read failure in this module collapses into ``VaultMissError`` on
    purpose -- absent, wrong session, spliced AAD -- because distinguishing them is
    an oracle. A file SQLite cannot parse is not in that family: the restorer
    *degrades* on ``VaultMissError`` (``restorer.py`` catches it and appends to
    ``unresolved``), so folding this into it answers ``200 OK`` with every original
    replaced by ``[UNRESOLVED_ENTITY]`` -- measured on the real pipeline, 0 of 4
    restored, provider called, nothing in the response saying the vault was
    unreadable.

    A *cold* instance is used because a warm cache would answer from RAM and never
    reach SQLite -- the read path this test exists for is the one the restorer takes
    after a process restart or a cache drop.
    """
    session_id, record = await fill_and_wreck(vault, session_registry, db_path)
    cold = await SessionVault.open(db_path, session_registry)
    try:
        with pytest.raises(vault_module.VaultUnavailableError) as by_token:
            await cold.get_by_token(session_id, record.token_id)
        with pytest.raises(vault_module.VaultUnavailableError) as by_surrogate:
            await cold.get_by_surrogate(session_id, record.surrogate)
    finally:
        await cold.close()

    for caught, operation in ((by_token, "get_by_token"), (by_surrogate, "get_by_surrogate")):
        error = caught.value
        # The load-bearing negative: a subclass check would let a future
        # `VaultUnavailableError(VaultMissError)` pass this test while the restorer
        # went on degrading, which is the exact fail-open being closed here.
        assert not isinstance(error, VaultMissError)
        assert error.code == "VAULT_UNAVAILABLE"
        assert error.detail["reason"] == "vault_unreadable"
        assert error.detail["operation"] == operation
        assert error.detail["vault_db"] == "vault.db"
        assert error.detail["error"] == "DatabaseError"
        assert isinstance(error.__cause__, sqlite3.DatabaseError)
        # Nothing derived from the driver or the filesystem: `api/errors.py` writes
        # this map into the HTTP body verbatim.
        rendered = f"{error!r} {error} {sorted(error.detail.items())}"
        assert str(db_path) not in rendered
        assert str(db_path.parent) not in rendered
        assert "malformed" not in rendered
        # ...and the remedy is something an operator can act on, spelled out here
        # rather than compared to the imported constant, which would pass against
        # `remedy: ""`.
        remedy = str(error.detail["remedy"])
        assert remedy == vault_module.UNREADABLE_VAULT_REMEDY
        assert "fresh data directory" in remedy and "new session" in remedy


async def test_a_corrupt_vault_refuses_the_write_and_leaves_no_phantom_cache_entry(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """``put`` must refuse, and must not record the entity as vaulted anyway.

    The failure lands between the encrypt and ``cache.add``. Logging it and
    continuing -- the shape a "resilient" store invites -- leaves a session whose
    plaintext index says the value is vaulted while no row exists: restorable for
    the life of this process and gone for ever after it, with the audit log
    recording a successful obfuscation either way.
    """
    session_id, _ = await fill_and_wreck(vault, session_registry, db_path)
    later = await make_record(session_registry, session_id, VALUE_B)

    with pytest.raises(vault_module.VaultUnavailableError) as caught:
        await vault.put(session_id, later, VALUE_B)

    assert caught.value.detail["operation"] == "put"
    assert isinstance(caught.value.__cause__, sqlite3.DatabaseError)
    # The refused value is not in the index, so nothing downstream can believe it
    # was stored. `get_by_original` is cache-only, so this reads the exact
    # structure the engine consults.
    assert await vault.get_by_original(session_id, "PATIENT_NAME", normalize(VALUE_B)) is None
    assert VALUE_B not in vault.originals_for_session(session_id)


async def test_a_corrupt_vault_refuses_the_startup_sweep_rather_than_deleting_blind(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path
) -> None:
    """``sweep_orphans`` is a bulk DELETE driven by a SELECT, so it must not degrade.

    Startup is where a corrupt data directory is first met. A sweep that swallowed
    the read failure would start the server against a database it cannot use and
    defer the discovery to the first request -- and, worse, its DELETEs are driven
    by the list the failed SELECT was supposed to produce.
    """
    session_id, _ = await fill_and_wreck(vault, session_registry, db_path)
    with pytest.raises(vault_module.VaultUnavailableError) as caught:
        await vault.sweep_orphans([session_id])
    assert caught.value.detail["operation"] == "sweep_orphans"
    assert isinstance(caught.value.__cause__, sqlite3.DatabaseError)


async def test_a_corrupt_vault_still_lets_logout_finish(
    vault: SessionVault,
    session_registry: SessionRegistry,
    db_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``destroy`` is the one caller that degrades, and this pins that it still does.

    The real erasure at logout is the caller popping the session key, which turns
    every surviving row into undecryptable garbage; the DELETE is hygiene. Raising
    here would make an unreadable ``vault.db`` turn the logout button into an error
    the user cannot clear, while the cache pop and the tombstone -- the parts that
    stop a late ``note_unrestorable`` from resurrecting plaintext -- have already
    happened. Asserted, not assumed, because it is the one asymmetry in the module.
    """
    session_id, _ = await fill_and_wreck(vault, session_registry, db_path)
    # ``close()`` inside the helper drops every cache, so one is rebuilt the way a
    # live run does -- otherwise ``destroy`` would have no cache to pop and the
    # assertion below would hold vacuously.
    vault.note_unrestorable(session_id, VALUE_A)
    assert vault.cached_session_ids() == frozenset({session_id})

    with caplog.at_level(logging.WARNING, logger="secure_context_pipeline.vault.session_vault"):
        await vault.destroy(session_id)

    # The DELETE really did fail -- without this the whole test would pass against
    # a database that was never corrupted.
    assert "vault row delete failed" in caplog.text
    assert vault.cached_session_ids() == frozenset()
    assert session_id in vault._destroyed
    # And the tombstone is real: a late redact-band needle cannot rebuild the cache.
    vault.note_unrestorable(session_id, VALUE_A)
    assert vault.originals_for_session(session_id) == frozenset()


async def test_an_unreadable_vault_refuses_restoration_instead_of_half_restoring(
    vault: SessionVault, session_registry: SessionRegistry, db_path: Path, settings: Settings
) -> None:
    """The real :class:`Restorer` over a real corrupt file: refuse, do not degrade.

    This is the fail-closed claim proved at the component that would otherwise
    swallow it, rather than inferred from the exception type. ``Restorer.restore``
    catches ``VaultMissError`` by design -- an unknown token degrades, never crashes
    -- so if an unreadable vault reached it as a miss the call would *succeed* and
    hand back a response with ``[UNRESOLVED_ENTITY]`` where the patient's name was.
    Here the same call over a genuinely malformed file raises instead, and the
    control below shows the degrade path is otherwise live in this exact setup.
    """
    # A pseudonym rather than the default ``[PHI_..._<token>]`` surrogate, so the
    # response carries nothing token-shaped and the *surrogate* pass -- the one
    # ``restorer.py`` degrades in -- is what reaches the vault.
    pseudonym = "Marguerite Okonkwo"
    session_id, _record = await fill_and_wreck(
        vault, session_registry, db_path, surrogate=pseudonym
    )
    response = f"The record for {pseudonym} was reviewed."
    call = {
        "strategy": "pseudonymization",
        # Present as a key with no usable original, which is the documented way to
        # force the vault lookup instead of answering from the run's own map.
        "surrogates": {pseudonym: ""},
        "issued": set[str](),
    }

    cold = await SessionVault.open(db_path, session_registry)
    healthy = await SessionVault.open(db_path.parent / "healthy.db", session_registry)
    try:
        with pytest.raises(vault_module.VaultUnavailableError) as caught:
            await Restorer(vault=cold, settings=settings).restore(session_id, response, **call)

        # Control: the degrade path IS live for this exact call. The same restore
        # against a HEALTHY vault that simply has no such surrogate returns a
        # result -- with the placeholder -- rather than raising. Without it, the
        # raise above could be any refusal on any earlier line.
        degraded = await Restorer(vault=healthy, settings=settings).restore(
            session_id, response, **call
        )
    finally:
        await cold.close()
        await healthy.close()

    assert caught.value.detail["operation"] == "get_by_surrogate"
    assert "UNRESOLVED" not in str(caught.value)
    assert degraded.vault_misses == 1
    assert "UNRESOLVED_ENTITY" in degraded.text, degraded.text
    assert pseudonym not in degraded.text


def test_the_vault_and_the_audit_log_share_one_unreadable_rule() -> None:
    """One rule for three files, checked rather than asserted in a comment.

    This proves agreement, not correctness -- the corrupt-file tests above are what
    prove the rule is right. It exists because ``vault.db`` reproduced the audit
    log's defect exactly, months after that one was fixed, and a tuple copied into
    a second module with no link between them is how that happens again.
    """
    assert vault_module._UNREADABLE == audit_logger._UNREADABLE
    assert vault_module._UNREADABLE == (sqlite3.Error, ValueError, TypeError)


async def test_a_corrupt_vault_refuses_a_pipeline_run_over_the_real_asgi_app(
    tmp_path: Path,
) -> None:
    """The reported defect at the boundary a reviewer actually sees.

    The sibling of ``test_api.py::test_a_corrupt_audit_log_refuses_the_run_as_a_typed_503``,
    on the second of the three SQLite stores. A fresh app on its own data
    directory, a healthy run first, then the live ``vault.db`` physically wrecked
    on disk and the same request repeated. Nothing is monkeypatched -- no patched
    accessor, no injected raise -- so what is asserted is the behaviour of the
    shipped code on a file SQLite genuinely cannot read.

    ``raise_app_exceptions`` is left at its default ``True``, which is load-bearing:
    anything still escaping unhandled makes this test *error* with that exception
    rather than read a status code off a Starlette-generated 500. The old behaviour
    -- ``sqlite3.DatabaseError`` out of ``get_by_token``, rendered as ``500
    text/plain Internal Server Error`` with no CSP and no ``nosniff`` -- cannot pass
    this test by accident.

    A fresh session is used so the first vault touch is a cold-cache read, which is
    deterministic. The warm case was measured too and is not a hole: repeating the
    run on the *original* session refuses identically, because the engine's
    collision check asks the vault about token IDs this run has not seen.
    """
    settings = Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path / "corrupt-vault-data",
        registry_path=REPO_ROOT / "entities.yaml",
        llm_provider="mock",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        services = app.state.services
        provider_calls = 0
        real_complete = services.orchestrator._provider.complete_detailed

        async def counting(*args: Any, **kwargs: Any) -> Any:
            nonlocal provider_calls
            provider_calls += 1
            return await real_complete(*args, **kwargs)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://scp.test") as http:
            with mock.patch.object(
                services.orchestrator._provider, "complete_detailed", counting
            ):
                doc_id = (
                    await http.post(
                        "/documents",
                        files={"file": ("intake.txt", API_DOC_TEXT.encode(), "text/plain")},
                        data={"user_id": API_OWNER, "doc_category": "medical"},
                    )
                ).json()["doc_id"]

                # Control: the identical request succeeds on a healthy vault.
                # Without it the refusal below could come from a broken fixture.
                healthy = await api_run(http, await api_session(http), doc_id)
                assert healthy.status_code == 200, healthy.text
                assert provider_calls == 1, "premise: a healthy run reaches the provider"
                assert "David Ochoa" in healthy.json()["restored_text"]

                # Wreck the file under the live app. Closed and reopened rather
                # than written behind SQLite's back, so the page cache cannot mask
                # it: this is the same file the next request opens.
                await services.vault.close()
                wreck_every_page_but_the_header(settings.data_dir / "vault.db")
                assert "malformed" in integrity_check(settings.data_dir / "vault.db")
                await services.vault._connect()

                refused = await api_run(http, await api_session(http), doc_id)

    # FIRST, before anything about the shape of the answer: the run was refused
    # before the payload was sent.
    assert provider_calls == 1, "the refused run must not have reached the provider"

    body = refused.json()
    assert body["code"] == "VAULT_UNAVAILABLE"
    assert body["detail"]["reason"] == "vault_unreadable"
    assert body["detail"]["vault_db"] == "vault.db"
    assert body["detail"]["error"] == "DatabaseError"
    assert body["detail"]["remedy"] == vault_module.UNREADABLE_VAULT_REMEDY

    # 500 is what the `PipelineError` catch-all in `api/errors.py` answers, and it
    # is pinned rather than loosened to `>= 500` so the remaining gap is visible:
    # the audit sibling answers **503** because that module registers
    # `AuditUnavailableError` explicitly, and registering these two classes the same
    # way is a change in `api/errors.py`, outside this change's grant. When that
    # registration lands this line becomes 503 -- deliberately, not by accident.
    # Everything else asserted here is already true and stays true either way.
    assert refused.status_code == 500, refused.text

    # Fail CLOSED: no answer at all, rather than an answer with the originals
    # missing from it. `[UNRESOLVED_ENTITY]` is what a degrading vault produces.
    assert "restored_text" not in refused.text
    assert "UNRESOLVED_ENTITY" not in refused.text
    assert "David Ochoa" not in refused.text

    # The bare 500 was `text/plain`, carried no `code`, and had none of these
    # headers, because ServerErrorMiddleware renders outside the middleware that
    # adds them. A typed refusal is an ordinary response and gets the same
    # hardening as every other one.
    assert refused.headers["content-type"].startswith("application/json")
    assert "Internal Server Error" not in refused.text
    assert refused.headers["x-content-type-options"] == "nosniff"
    csp = refused.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp

    # No filesystem path and no driver text in the body. The file NAME is what an
    # operator acts on; the path is a description of the server's disk.
    assert str(settings.data_dir) not in refused.text
    assert "malformed" not in refused.text
    assert "sqlite" not in refused.text.lower()
    assert "Traceback" not in refused.text
