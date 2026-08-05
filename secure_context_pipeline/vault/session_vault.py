"""Session vault: encrypted durable store + hot in-memory index (build doc section 9.4).

The vault is the only place an original entity value is ever written down, and it
is written down twice, in two forms with two different jobs:

* **SQLite is the durable copy, and it is ciphertext.** Every row is AES-256-GCM
  under a vault key ``HKDF(session_key, "vault:" + session_id)``, with
  ``AAD = session_id || ':' || token_id``. The AAD binding is what makes row
  splicing useless: a row copied into another session, or onto another token ID,
  fails authentication even for an attacker with write access to the database.
* **A per-session in-memory cache is the read path.** ``token_id -> original``,
  ``surrogate -> original``, ``(entity_type, normalized) -> TokenRecord`` and the
  originals frozenset. This is what makes lookups sub-millisecond and what makes
  :meth:`SessionVault.originals_for_session` -- called by the EgressGate on the
  hot path for every outbound payload -- synchronous and O(1).

**The vault never stores a key.** It holds a reference to the
:class:`~secure_context_pipeline.vault.session_registry.SessionRegistry` and asks
for the session key on every operation, which means (a) an expired session raises
:class:`SessionExpiredError` from the registry on *every* accessor, and (b)
destroying the registry key destroys the vault's ability to read its own rows.

Session-lifetime plaintext in RAM is accepted and documented: the threat model
covers at-rest, cross-session, and in-transit exposure; a memory-scraping
adversary on the app host is out of scope for this tier.

No original value ever reaches a log line or an exception. Everything emitted
here is a count, a session ID, a token ID, or a short machine code.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Self

import aiosqlite

from secure_context_pipeline.crypto import aead
from secure_context_pipeline.crypto.keys import derive_token_id, derive_vault_key, normalize
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
    CryptoAuthError,
    PipelineError,
    SessionExpiredError,
    VaultMissError,
)
from secure_context_pipeline.models import TokenRecord
from secure_context_pipeline.vault.session_registry import SessionRegistry

logger = logging.getLogger(__name__)

__all__ = ["DEFAULT_DB_FILENAME", "MAX_COLLISION_RETRIES", "SessionVault"]

DEFAULT_DB_FILENAME = "vault.db"

#: Truncating HMAC-SHA256 to 4 bytes collides with probability ~n^2/2^33; at a
#: few thousand entities per session that is vanishingly rare, but it is handled
#: rather than assumed away. Eight re-derivations is already absurd headroom.
MAX_COLLISION_RETRIES = 8

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_entries (
  session_id TEXT NOT NULL,
  token_id   TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  surrogate  TEXT NOT NULL,
  nonce      BLOB NOT NULL,
  ciphertext BLOB NOT NULL,   -- AES-GCM(original), AAD = session_id || ':' || token_id
  created_at REAL NOT NULL,
  PRIMARY KEY (session_id, token_id)
);
CREATE INDEX IF NOT EXISTS idx_vault_surrogate ON vault_entries(session_id, surrogate);
"""

# Static, fully parameterised SQL. Nothing is interpolated anywhere in this
# module, so no caller-supplied value can reach query construction.
_INSERT_SQL = """
INSERT OR REPLACE INTO vault_entries
  (session_id, token_id, entity_type, surrogate, nonce, ciphertext, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_ROW_SQL = """
SELECT token_id, surrogate, nonce, ciphertext
FROM vault_entries WHERE session_id = ? AND token_id = ?
"""

_SELECT_SURROGATE_ROW_SQL = """
SELECT token_id, surrogate, nonce, ciphertext
FROM vault_entries WHERE session_id = ? AND surrogate = ? LIMIT 1
"""

_DELETE_SESSION_SQL = "DELETE FROM vault_entries WHERE session_id = ?"

_DISTINCT_SESSIONS_SQL = "SELECT DISTINCT session_id FROM vault_entries"

_COUNT_SESSION_SQL = "SELECT COUNT(*) AS n FROM vault_entries WHERE session_id = ?"


def _short(value: str) -> str:
    """Clamp an identifier to the error-detail ceiling (see ``errors.PipelineError``)."""
    return value[:MAX_DETAIL_VALUE_LEN]


@dataclass(slots=True)
class _SessionCache:
    """Plaintext working set for one live session.

    Exists only while the session does: :meth:`SessionVault.destroy` drops it,
    which is what makes a post-destroy read fall through to a DB that no longer
    has the rows (and could not decrypt them if it did).
    """

    by_token: dict[str, str] = field(default_factory=dict)
    by_surrogate: dict[str, str] = field(default_factory=dict)
    by_original: dict[tuple[str, str], TokenRecord] = field(default_factory=dict)
    originals: set[str] = field(default_factory=set)
    #: Memoised immutable view handed to the EgressGate; invalidated on write.
    _view: frozenset[str] | None = field(default=None, init=False, repr=False)
    #: Memoised immutable view of ``by_surrogate``; invalidated on write. Separate
    #: from ``_view`` because the two answer different questions and are read by
    #: different stages -- see :meth:`SessionVault.surrogates_for_session`.
    _issued: Mapping[str, str] | None = field(default=None, init=False, repr=False)

    def add(self, index: tuple[str, str], record: TokenRecord, original: str) -> None:
        self.by_token[record.token_id] = original
        self.by_surrogate[record.surrogate] = original
        self.by_original[index] = record
        self.originals.add(original)
        self._view = None
        self._issued = None

    def note(self, token_id: str, surrogate: str, original: str) -> None:
        """Read-through population from a decrypted row.

        ``by_original`` is deliberately *not* filled here: the frozen schema has
        no ``category`` column, so a full :class:`TokenRecord` cannot be rebuilt
        from a row -- and indexing plaintext-derived keys on disk would be a
        searchable-plaintext oracle anyway.

        That asymmetry is the one place the cache and the database can disagree,
        so :meth:`taken` -- not ``by_original`` -- is what the write path uses to
        decide whether a token ID is free.
        """
        self.by_token[token_id] = original
        self.by_surrogate[surrogate] = original
        self.originals.add(original)
        self._view = None
        self._issued = None

    def taken(self, token_id: str, original: str) -> bool:
        """Whether ``token_id`` is already spoken for by a *different* original.

        A token ID that already maps to this same value is not a collision --
        it is this value, seen before. The distinction matters because
        :meth:`note` populates ``by_token`` without ``by_original``, so a value
        read back from a row reaches the write path looking unregistered while
        its token ID looks occupied.
        """
        existing = self.by_token.get(token_id)
        return existing is not None and existing != original

    def view(self) -> frozenset[str]:
        """Immutable snapshot of the originals. O(1) except for the first read after a write."""
        cached = self._view
        if cached is None:
            cached = frozenset(self.originals)
            self._view = cached
        return cached

    def issued(self) -> Mapping[str, str]:
        """Immutable snapshot of ``surrogate -> original``.

        A snapshot rather than a proxy over the live dict: the collision guard
        walks every entry, and a mapping that can grow mid-walk is a
        ``RuntimeError`` waiting for the first caller that awaits inside the loop.
        """
        cached = self._issued
        if cached is None:
            cached = MappingProxyType(dict(self.by_surrogate))
            self._issued = cached
        return cached

    def __repr__(self) -> str:
        """Counts only -- this object is entirely made of original values."""
        return f"_SessionCache(entries={len(self.by_token)})"


class SessionVault:
    """Encrypted per-session token vault over SQLite (WAL, one connection per instance).

    Entry point is the :meth:`open` classmethod::

        vault = await SessionVault.open(settings.data_dir / DEFAULT_DB_FILENAME, registry)
        try:
            await vault.put(session_id, record, original)
        finally:
            await vault.close()

    It is also an async context manager for scoped use.
    """

    def __init__(self, db_path: str | Path, registry: SessionRegistry) -> None:
        self._db_path = Path(db_path)
        self._registry = registry
        self._conn: aiosqlite.Connection | None = None
        self._caches: dict[str, _SessionCache] = {}
        #: Sessions this instance has destroyed. See :meth:`destroy`.
        self._destroyed: set[str] = set()
        self._lock = asyncio.Lock()
        # Separate from ``_lock`` so opening never contends with the read/write
        # path, and so ``close`` can serialise against a concurrent ``_connect``
        # without either taking the other's lock.
        self._open_lock = asyncio.Lock()

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    async def open(cls, db_path: str | Path, registry: SessionRegistry) -> Self:
        """Connect, enable WAL, and create the schema if it does not exist."""
        instance = cls(db_path, registry)
        await instance._connect()
        return instance

    async def _connect(self) -> None:
        """Open the single connection. Idempotent and safe to call concurrently.

        The double-check under ``_open_lock`` is load-bearing: without it two
        concurrent ``open()``/``__aenter__`` calls each run
        ``await aiosqlite.connect(...)``, the loser's connection is overwritten
        and never closed, and its non-daemon thread then keeps the interpreter
        alive at exit. The two also race on ``PRAGMA journal_mode=WAL``, which
        surfaces as a spurious ``database is locked``.
        """
        async with self._open_lock:
            if self._conn is not None:
                return
            parent = self._db_path.parent
            if str(parent):
                await asyncio.to_thread(parent.mkdir, parents=True, exist_ok=True)
            conn = await aiosqlite.connect(self._db_path)
            conn.row_factory = aiosqlite.Row
            # WAL so a reader never blocks the single writer; NORMAL sync is the
            # standard WAL durability trade and this data is disposable by design.
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA synchronous=NORMAL")
            await conn.executescript(_SCHEMA)
            await conn.commit()
            self._conn = conn
            logger.debug("vault opened", extra={"vault_db": str(self._db_path)})

    async def close(self) -> None:
        """Close the connection and drop every cache. Idempotent.

        Dropping the caches on close is the same erasure argument as
        :meth:`SessionRegistry.destroy`: plaintext lives exactly as long as the
        process holds a live session.
        """
        async with self._open_lock:
            async with self._lock:
                conn, self._conn = self._conn, None
                self._caches.clear()
                # Every accessor raises ``vault_closed`` from here on, so there
                # is no read left for a tombstone to refuse. Reopening the same
                # file is a fresh instance with a cold cache, which is the
                # documented cold-start path rather than a resurrection.
                self._destroyed.clear()
            if conn is not None:
                await conn.close()

    async def __aenter__(self) -> Self:
        await self._connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    def _require_conn(self) -> aiosqlite.Connection:
        conn = self._conn
        if conn is None:
            raise PipelineError(reason="vault_closed")
        return conn

    # -- write -------------------------------------------------------------

    async def put(self, session_id: str, record: TokenRecord, original: str) -> None:
        """Store one entity: encrypt to SQLite and write through to the cache.

        Idempotent per ``(entity_type, normalize(original))``: putting the same
        value twice in one session is a no-op, so a value appearing five times in
        a document produces exactly one row and one token.

        If ``record.token_id`` is already taken *by a different original*, the
        token is re-derived with an incrementing counter until it is unique
        (build doc section 8). The authoritative record -- with the possibly
        re-derived token ID -- is then available from :meth:`get_by_original`.

        Raises :class:`SessionExpiredError` if the session is gone.
        """
        index = (record.entity_type, normalize(original))

        # Connection handle, liveness check, collision check, encryption and
        # insert are one critical section. Two coroutines racing on the same
        # token ID must not both take it -- and the session must be *checked*
        # live under the same lock that ``destroy`` takes, not merely have been
        # live when this coroutine started. Reading the key outside the lock
        # happened to be safe only because there was no ``await`` between the
        # read and the acquire; anything added there (an audit emit, a metric, a
        # thread hop) would have let a write land after logout and rebuild the
        # plaintext cache for a destroyed session. ``SessionRegistry`` never
        # calls back into the vault, so taking its lock from inside ours cannot
        # deadlock.
        #
        # ``_require_conn`` is called *here*, not before the acquire, for the
        # same class of reason -- and that one was not merely fragile, it was
        # reachable with no edit at all. ``close`` takes this lock, so a ``close``
        # already queued on it runs first: a handle resolved before the acquire
        # was live when it was read and dead by the time it was used, and the
        # INSERT raised a bare ``sqlite3.ProgrammingError`` out of a method whose
        # whole contract is ``PipelineError(reason="vault_closed")``. Resolving
        # it under the lock makes "the connection I use is the connection that
        # was open while I held the lock" a property of the code.
        async with self._lock:
            conn = self._require_conn()
            session_key = await self._registry.key(session_id)
            if session_id in self._destroyed:
                # A write that lost the race with logout. See destroy().
                raise SessionExpiredError(session_id=_short(session_id))
            cache = self._caches.setdefault(session_id, _SessionCache())
            if index in cache.by_original:
                return
            vault_key = derive_vault_key(session_key, session_id)
            token_id = self._resolve_token_id(cache, session_key, record, original)
            stored = record.model_copy(update={"session_id": session_id, "token_id": token_id})
            nonce, ciphertext = aead.encrypt_split(
                vault_key,
                original.encode("utf-8"),
                aead.vault_aad(session_id, token_id),
            )
            await conn.execute(
                _INSERT_SQL,
                (
                    session_id,
                    token_id,
                    stored.entity_type,
                    stored.surrogate,
                    nonce,
                    ciphertext,
                    stored.created_at,
                ),
            )
            await conn.commit()
            cache.add(index, stored, original)

    @staticmethod
    def _resolve_token_id(
        cache: _SessionCache,
        session_key: bytes,
        record: TokenRecord,
        original: str,
    ) -> str:
        """Return a token ID this session can use for ``original``.

        A collision is another *original* holding the ID, not the ID being
        present: :meth:`_SessionCache.note` fills ``by_token`` on read-through
        but cannot fill ``by_original``, so a value recovered from a row arrives
        here looking unregistered while its own token ID looks occupied.
        Re-deriving in that case minted a second token for a value that already
        had one -- two rows, two surrogates and one original, which is exactly
        the within-session determinism this vault guarantees. Hence
        :meth:`_SessionCache.taken` rather than a bare membership test.
        """
        token_id = record.token_id
        if not cache.taken(token_id, original):
            return token_id
        for counter in range(1, MAX_COLLISION_RETRIES + 1):
            candidate = derive_token_id(session_key, record.entity_type, original, counter=counter)
            if not cache.taken(candidate, original):
                logger.warning(
                    "token id collision re-derived",
                    extra={
                        "entity_type": _short(record.entity_type),
                        "collision_counter": counter,
                        "session_entries": len(cache.by_token),
                    },
                )
                return candidate
        raise PipelineError(
            reason="token_collision_unresolved",
            entity_type=_short(record.entity_type),
            attempts=MAX_COLLISION_RETRIES,
        )

    # -- read --------------------------------------------------------------

    async def get_by_token(self, session_id: str, token_id: str) -> str:
        """Original value for a token ID.

        Cache hit is the normal path. A miss falls through to SQLite and
        decrypts under ``AAD = session_id || ':' || token_id``; a row that fails
        authentication -- spliced from another session or another token -- is
        reported as :class:`VaultMissError`, identical to an absent row, so the
        error is never an oracle for "exists but is not yours".
        """
        session_key = await self._registry.key(session_id)
        if session_id in self._destroyed:
            raise VaultMissError(session_id=_short(session_id), token_id=_short(token_id))
        cache = self._caches.get(session_id)
        if cache is not None:
            hit = cache.by_token.get(token_id)
            if hit is not None:
                return hit
        row = await self._fetch_one(_SELECT_ROW_SQL, (session_id, token_id))
        return self._decrypt_row(session_id, session_key, row, token_id=token_id)

    async def get_by_surrogate(self, session_id: str, surrogate: str) -> str:
        """Original value for a surrogate (token string or pseudonym)."""
        session_key = await self._registry.key(session_id)
        if session_id in self._destroyed:
            raise VaultMissError(session_id=_short(session_id))
        cache = self._caches.get(session_id)
        if cache is not None:
            hit = cache.by_surrogate.get(surrogate)
            if hit is not None:
                return hit
        row = await self._fetch_one(_SELECT_SURROGATE_ROW_SQL, (session_id, surrogate))
        return self._decrypt_row(session_id, session_key, row, token_id=None)

    async def get_by_original(
        self, session_id: str, entity_type: str, normalized: str
    ) -> TokenRecord | None:
        """The record for an already-seen value, or ``None``.

        Cache-only by design. Reversing this index on disk would require either
        storing a plaintext-derived key next to the ciphertext -- a searchable
        oracle -- or decrypting every row in the session; neither is acceptable
        on the obfuscation hot path. ``normalized`` is re-normalised defensively;
        :func:`normalize` is idempotent.

        The tombstone check below is **belt and braces, and is currently
        unreachable**: this method only ever answers out of the cache, and the
        cache for a destroyed session cannot exist -- :meth:`destroy` pops it,
        :meth:`put` refuses to recreate it, and :meth:`_decrypt_row` declines to
        repopulate it on read-through. Deleting the check therefore breaks no
        test, which is stated here rather than left for the next reader to
        rediscover. It is kept because it is free and because it is the last of
        the three that would have to fail silently for a destroyed session's
        record to be handed back.
        """
        await self._registry.key(session_id)
        if session_id in self._destroyed:
            return None
        cache = self._caches.get(session_id)
        if cache is None:
            return None
        return cache.by_original.get((entity_type, normalize(normalized)))

    def originals_for_session(self, session_id: str) -> frozenset[str]:
        """Every original held for this session. **Synchronous, amortised O(1).**

        The frozenset is memoised and invalidated on write, so the first call
        after a batch of ``put``s rebuilds it in O(entries) and every call until
        the next write is a dict lookup. Obfuscation writes in a burst and the
        gate then reads repeatedly, which is the shape that makes this pay.

        The EgressGate calls this for every outbound payload, so it must not
        await, must not touch SQLite, and must not decrypt. Returns an empty set
        for an unknown or destroyed session; an expired-but-unswept session still
        returns its originals, which fails *safe* -- the gate scans for more
        values, never fewer.
        """
        cache = self._caches.get(session_id)
        if cache is None:
            return frozenset()
        return cache.view()

    def surrogates_for_session(self, session_id: str) -> Mapping[str, str]:
        """``surrogate -> original`` for this session. **Synchronous, amortised O(1).**

        The mirror of :meth:`originals_for_session`, memoised and invalidated the
        same way, and it exists for one caller: the pseudonymization collision
        guard, which cannot decide whether a candidate fake is safe from the
        surrogate alone.

        The question it answers is *"would this fake make an already-issued
        surrogate un-restorable?"*, and that needs both halves of the pair. Two
        surrogates where one occurs as a unit inside the other are restored
        longest-first, so the short one never matches inside the long one; whether
        that is correct or a lost value depends entirely on whether the *originals*
        nest the same way. Written in this method's own direction, surrogate first:
        ``{'Nathaniel Brightwater': 'Chelsea Hammond', 'Brightwater': 'Hammond'}``
        is name-component linking working exactly as designed -- restoring the long
        fake yields ``Chelsea Hammond``, which still carries the short one's
        original as a unit. ``{'Daniel White': 'Thomas Duncan', 'White':
        'Sherryside'}`` is two unrelated entities whose fakes collided, and there
        the short original is simply gone from the answer. Only the pairing
        distinguishes them, which is why this returns a mapping rather than the key
        set.

        Cache-only and never decrypts, for the same reason
        :meth:`originals_for_session` is: it is read once per Tier-1 candidate on
        the obfuscation hot path. An unknown or destroyed session returns empty,
        which fails *permissive* rather than safe -- with no issued surrogates
        there is nothing to collide with, and the caller's other guards are
        unaffected.
        """
        cache = self._caches.get(session_id)
        if cache is None:
            return MappingProxyType({})
        return cache.issued()

    # -- destruction -------------------------------------------------------

    async def destroy(self, session_id: str) -> None:
        """Drop the cache, tombstone the session, and delete its rows.

        The rows are deleted best-effort *after* the cache: the real erasure is
        the caller popping the session key from the registry, which turns any
        surviving ciphertext into undecryptable garbage. A failed DELETE is
        therefore a hygiene problem, not a confidentiality one, and must not
        propagate into a logout path.

        **The tombstone covers the vault-first logout order.** Logout is two
        awaits, and a caller that runs ``vault.destroy()`` before
        ``registry.destroy()`` leaves a window in which the key is still live: a
        pipeline run already holding it can land a ``put()`` in between, which
        used to recreate the plaintext cache and a durable row for a session
        that was already gone, with nothing left to collect them. With the
        tombstone every accessor treats the session as dead -- writes raise
        :class:`SessionExpiredError`, reads raise :class:`VaultMissError`, and a
        surviving row can never repopulate the cache on read-through.

        The API logs out the other way round (``registry.destroy()`` first), so
        in that path the key is already gone and no tombstone is recorded. That
        is correct rather than a gap: with the key gone every accessor fails at
        ``registry.key()``, and :meth:`put` reads that key *inside* ``self._lock``
        -- so a write that acquires the lock after this ``destroy`` finds the key
        already gone, and one that acquired it before is cleaned up here. No
        appeal to how many event-loop steps separate two statements is needed.
        Skipping the tombstone there also means a caller cannot grow the set by
        destroying session IDs that never existed.

        **The liveness read is inside the lock for the same reason.** Taken
        outside it, ``key_still_live`` was a stale answer by the time it was
        acted on: a ``registry.destroy()`` landing in between recorded a
        tombstone for a session whose key was already gone. The set is therefore
        bounded by the sessions that were live at some ``destroy`` -- and in the
        API's key-first order it stays empty, which
        ``test_logout_in_api_order_is_final_for_in_flight_writes`` pins. Entries
        are released wholesale by :meth:`close`; a process that logs out
        vault-first retains one session ID per logout until then, which is
        accepted at this tier and stated here rather than left to be discovered.
        """
        deleted = 0
        async with self._lock:
            try:
                await self._registry.key(session_id)
            except SessionExpiredError:
                key_still_live = False
            else:
                key_still_live = True
            cache = self._caches.pop(session_id, None)
            cached_entries = len(cache.by_token) if cache is not None else 0
            if key_still_live:
                self._destroyed.add(session_id)
            conn = self._conn
            if conn is not None:
                try:
                    cursor = await conn.execute(_DELETE_SESSION_SQL, (session_id,))
                    deleted = cursor.rowcount
                    await cursor.close()
                    await conn.commit()
                except (sqlite3.Error, ValueError):
                    logger.warning(
                        "vault row delete failed; rows are undecryptable once the key is gone",
                        extra={"session_id": _short(session_id)},
                    )
        logger.info(
            "vault destroyed",
            extra={
                "session_id": _short(session_id),
                "cached_entries": cached_entries,
                "rows_deleted": deleted,
                "tombstoned": key_still_live,
            },
        )

    async def sweep_orphans(self, known_session_ids: Iterable[str]) -> int:
        """Delete rows whose session is unknown; return the row count removed.

        Run at startup. Session keys never survive a process restart, so every
        row left behind by the previous process is undecryptable garbage taking
        up disk -- and, worse, would otherwise make a session ID look live to a
        naive query.
        """
        known = frozenset(known_session_ids)
        deleted = 0
        orphan_count = 0
        # Resolved under the lock, not before it: see the note in :meth:`put`.
        async with self._lock:
            conn = self._require_conn()
            cursor = await conn.execute(_DISTINCT_SESSIONS_SQL)
            rows = await cursor.fetchall()
            await cursor.close()
            orphans = [str(row["session_id"]) for row in rows if row["session_id"] not in known]
            orphan_count = len(orphans)
            for session_id in orphans:
                cursor = await conn.execute(_DELETE_SESSION_SQL, (session_id,))
                deleted += cursor.rowcount
                await cursor.close()
                self._caches.pop(session_id, None)
            if orphans:
                await conn.commit()
        logger.info(
            "orphan vault rows swept",
            extra={"orphan_sessions": orphan_count, "rows_deleted": deleted},
        )
        return deleted

    # -- introspection (counts only) --------------------------------------

    async def row_count(self, session_id: str) -> int:
        """Number of persisted rows for a session. Diagnostics and tests."""
        row = await self._fetch_one(_COUNT_SESSION_SQL, (session_id,))
        return 0 if row is None else int(row["n"])

    def cached_session_ids(self) -> frozenset[str]:
        """Sessions with a live plaintext cache. Counts/IDs only, never values."""
        return frozenset(self._caches)

    # -- internals ---------------------------------------------------------

    async def _fetch_one(self, sql: str, params: tuple[object, ...]) -> aiosqlite.Row | None:
        # Resolved under the lock, not before it: see the note in :meth:`put`.
        async with self._lock:
            conn = self._require_conn()
            cursor = await conn.execute(sql, params)
            row = await cursor.fetchone()
            await cursor.close()
        return row

    def _decrypt_row(
        self,
        session_id: str,
        session_key: bytes,
        row: aiosqlite.Row | None,
        *,
        token_id: str | None,
    ) -> str:
        """Authenticate and decrypt one row, or raise :class:`VaultMissError`.

        Absence and authentication failure are deliberately the same error.
        """
        if row is None:
            raise VaultMissError(session_id=_short(session_id), token_id=_short(token_id or ""))
        row_token = str(row["token_id"])
        vault_key = derive_vault_key(session_key, session_id)
        try:
            plaintext = aead.decrypt_split(
                vault_key,
                bytes(row["nonce"]),
                bytes(row["ciphertext"]),
                aead.vault_aad(session_id, row_token),
                scope="vault",
            )
        except CryptoAuthError as exc:
            # Wrong session key or spliced AAD. Log the scope, never the row.
            logger.warning(
                "vault row failed authentication",
                extra={"session_id": _short(session_id), "token_id": _short(row_token)},
            )
            raise VaultMissError(session_id=_short(session_id), token_id=_short(row_token)) from exc
        original = plaintext.decode("utf-8")
        if session_id not in self._destroyed:
            # Never resurrect a destroyed session's plaintext from a row that
            # outlived the best-effort DELETE. The callers already refuse a
            # tombstoned session; this keeps the invariant local to the write.
            cache = self._caches.setdefault(session_id, _SessionCache())
            cache.note(row_token, str(row["surrogate"]), original)
        return original

    def __repr__(self) -> str:
        """Counts only. The caches are made entirely of original values."""
        entries = sum(len(cache.by_token) for cache in self._caches.values())
        return (
            f"SessionVault(db={str(self._db_path)!r}, sessions={len(self._caches)}, "
            f"cached_entries={entries}, open={self._conn is not None})"
        )

    __str__ = __repr__
