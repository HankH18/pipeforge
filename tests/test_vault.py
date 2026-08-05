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

import asyncio
import itertools
import logging
import secrets
import sqlite3
import threading
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto import aead
from secure_context_pipeline.crypto.keys import derive_token_id, derive_vault_key, normalize
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
    assert vault.cached_session_ids() == frozenset()

    # And the session really is unreachable afterwards -- by closure, not by
    # tombstone: every accessor fails before it can consult one.
    with pytest.raises(PipelineError):
        await vault.row_count(session_id)


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
    """The API pops the key *first*, so no tombstone is recorded. It must still hold.

    ``DELETE /session/{id}`` runs ``registry.destroy()`` then ``vault.destroy()``,
    which is the opposite of the order the tombstone was written for -- by the
    time ``destroy`` runs, ``registry.key()`` already raises and nothing is
    tombstoned. The property has to come from somewhere else, and it does:
    ``put`` reads the key and queues on ``self._lock`` in one scheduling step,
    and ``asyncio.Lock`` wakes waiters FIFO, so a write either lands before this
    ``destroy`` (and is cleaned up by it) or finds the key already gone.

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
        assert not vault._destroyed, "the API order must not accumulate tombstones"

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
      the key is already gone by the time ``destroy`` looks -- and the write
      then acquires a free lock, sees an empty ``_destroyed``, and files a
      durable row plus a plaintext cache for a session that no longer exists,
      with nothing left to collect either.

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

    assert not vault._destroyed, "the API order records no tombstone; that is the premise here"
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
    """
    session_id, _ = await session_registry.create("test-user")
    await put_value(vault, session_registry, session_id, VALUE_A)

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
        "_Session must not be a tuple: the tuple protocol re-exposes the key "
        "regardless of __repr__"
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
# 9. concurrent session isolation (build doc section 10.6)
# ---------------------------------------------------------------------------


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
