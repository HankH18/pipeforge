"""Hash-chained, append-only audit log (build doc section 9.8).

Every pipeline stage writes here. Three properties are load-bearing:

1. **No originals -- by call site and by measurement, not by schema.** The only
   payload field is :attr:`AuditEvent.detail`, a ``dict[str, int | float | str]``
   whose validator rejects string values over 64 characters (section 7), and the
   label columns cap at 128. Those ceilings make the log incapable of holding
   *content* -- a paragraph, a note, a document -- which is the bulk-exfiltration
   shape, and they are re-enforced at the write boundary by
   :func:`_reject_content_sized_fields` because the model's own validators are
   bypassable via ``model_construct``.

   They do **not** make it incapable of holding an original: ``"John Smith"`` and
   ``"MRN 4823910"`` fit inside 64 characters, and no length check can recognise a
   name. Saying otherwise was an overclaim this project shipped for a while. What
   actually holds is narrower and is measured rather than asserted: no call site
   in this package writes a value -- every ``emit`` carries token IDs, entity
   *types*, counts, latencies and digests -- and the 100-run leakage harness scans
   the raw SQLite file as **bytes** against every vaulted original on every run.
2. **Tamper evidence.** ``entry_hash = sha256(prev_hash + canonical_json(event
   without hashes))``, chained across the whole log in ``seq`` order.
   :meth:`AuditLogger.verify_chain` recomputes every hash and re-checks every
   link, so an in-place ``UPDATE`` of any persisted column is detectable.
3. **Queryable, and checkably so.** :meth:`AuditLogger.query` filters by session,
   run, event type, and time range -- the compliance-reporting requirement --
   and pages, defaulting to ``limit=1000``. :meth:`AuditLogger.length` takes the
   *same* filter set, which is the part that makes a compliance answer verifiable
   rather than plausible: a full page and a complete result look identical
   otherwise, so a 30-day sweep could silently return a prefix.

The chain is *global*, not per-session: that is what makes deletion or
reordering of any row detectable. ``verify_chain(session_id=...)`` still walks
the whole chain (it has to, to know each row's expected predecessor) but only
asserts on rows belonging to that session, so it answers "is this session's
slice intact" rather than "is the whole log intact".

Concurrency, stated precisely because the previous wording was wrong. ``emit`` is
safe under ``asyncio.gather``: reading the previous hash, computing the new one,
and inserting is one critical section guarded by an :class:`asyncio.Lock`, so the
chain stays linear no matter how many coroutines race **inside one event loop**.
An :class:`asyncio.Lock` is an in-process object and serialises nothing across OS
processes, so two workers sharing one ``audit.db`` used to compute the same
``seq`` and the loser's ``INSERT`` died on the ``seq`` PRIMARY KEY -- a *dropped*
audit event, which no chain check can notice because it was never written.
:meth:`AuditLogger.emit` now sets ``busy_timeout`` and retries a lost race by
re-reading the tail and re-chaining, so a second writer serialises instead of
losing its event. The shipped container runs one uvicorn process, so this was
latent rather than active; it stops being latent the moment anyone adds
``--workers``. All I/O is ``aiosqlite`` (WAL, one connection per instance);
nothing here blocks the event loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Self

import aiosqlite

from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.models import (
    MAX_AUDIT_LABEL_LEN,
    MAX_DETAIL_VALUE_LEN,
    AuditEvent,
    DetailMap,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_DB_FILENAME",
    "DEOBFUSCATE",
    "DETECT",
    "EGRESS_BLOCK",
    "EGRESS_PASS",
    "EVENT_TYPES",
    "GENESIS_HASH",
    "LLM_CALL",
    "OBFUSCATE",
    "REDACT",
    "SESSION_CREATE",
    "SESSION_EXPIRE",
    "STRIP",
    "VAULT_DESTROY",
    "VAULT_MISS",
    "AuditLogger",
    "canonical_json",
    "chain_payload",
    "compute_entry_hash",
]

# --------------------------------------------------------------------------
# Event types -- the build doc section 7 vocabulary, verbatim and complete.
#
# These are convenience constants, not a constraint: ``emit`` accepts any
# ``event_type`` string. Restricting inserts to an enum would make adding a
# stage a schema change, and the audit log is the last place that should refuse
# to record something it did not expect.
#
# Eleven of the twelve are emitted somewhere in the package. ``SESSION_EXPIRE``
# is **declared but never emitted**, and that is a real gap rather than a spare
# constant: TTL lapse is discovered lazily, by the next accessor to ask
# ``SessionRegistry`` for a key, so the moment a session dies is not a moment any
# code is running. Logout does emit ``VAULT_DESTROY`` (section 4 step 10), so the
# explicit teardown path is covered and only the passive one is silent. Closing it
# means giving the registry a sweeper and an audit handle -- see README Deviations.
# The constant stays because ``query(event_type=SESSION_EXPIRE)`` returning an
# empty list is the honest answer, and deleting it would hide the gap instead.
# --------------------------------------------------------------------------
SESSION_CREATE = "SESSION_CREATE"
DETECT = "DETECT"
OBFUSCATE = "OBFUSCATE"
REDACT = "REDACT"
STRIP = "STRIP"
EGRESS_PASS = "EGRESS_PASS"  # noqa: S105 -- an event-type name, not a credential
EGRESS_BLOCK = "EGRESS_BLOCK"
LLM_CALL = "LLM_CALL"
DEOBFUSCATE = "DEOBFUSCATE"
VAULT_MISS = "VAULT_MISS"
VAULT_DESTROY = "VAULT_DESTROY"
SESSION_EXPIRE = "SESSION_EXPIRE"

EVENT_TYPES: frozenset[str] = frozenset(
    {
        SESSION_CREATE,
        DETECT,
        OBFUSCATE,
        REDACT,
        STRIP,
        EGRESS_PASS,
        EGRESS_BLOCK,
        LLM_CALL,
        DEOBFUSCATE,
        VAULT_MISS,
        VAULT_DESTROY,
        SESSION_EXPIRE,
    }
)

DEFAULT_DB_FILENAME = "audit.db"

#: How long SQLite waits for another *process*'s write lock before giving up.
#: Only reachable when the audit DB is shared across workers or replicas, which
#: the shipped single-process container does not do -- see the module docstring.
BUSY_TIMEOUT_MS = 5_000

#: How many times :meth:`AuditLogger.emit` re-reads the tail and re-chains after
#: losing a ``seq`` race to another process. Small on purpose: each attempt costs a
#: round trip, and if a writer loses this many in a row the contention is not
#: transient and the caller should hear about it rather than wait.
MAX_EMIT_ATTEMPTS = 5

#: Attempts, and the linear backoff step, for putting a *new* database into WAL
#: mode while another process is doing the same thing. See :func:`_enable_wal`:
#: this is the one lock ``busy_timeout`` does not cover. Worst case here is
#: 0.05 + 0.10 + 0.15 + 0.20 = 0.5 s before ``open()`` gives up and raises.
WAL_SETUP_ATTEMPTS = 5
WAL_SETUP_BACKOFF_S = 0.05

#: ``prev_hash`` of the first row. Empty string, not NULL, so the hash input of
#: the genesis entry is as well-defined as every other entry's.
GENESIS_HASH = ""

#: What "this database is unreadable" looks like when raised from inside a row
#: walk. **One definition, used by every reader**, because this codebase has
#: already been bitten by a rule that was correct in one copy and stale in
#: another: ``_watermark`` (then named ``_high_water_seq``) degraded on
#: ``sqlite3.Error`` while the main chain walk did not, and the asymmetry was the bug.
#:
#: ``ValueError``/``TypeError`` belong here alongside ``sqlite3.Error`` because a
#: row is not trustworthy just because SQLite handed it over. A tampered ``ts``
#: holding ``'not-a-number'`` reaches ``float()`` as a ``ValueError``, and a page
#: that a truncated file returns as ``NULL`` reaches it as a ``TypeError`` -- both
#: are crashes *on the tamper-detection path, caused by the tamper being looked
#: for*. ``tests/test_audit.py::test_every_audit_reader_shares_one_unreadable_rule``
#: fails if a reader stops using this tuple.
_UNREADABLE = (sqlite3.Error, ValueError, TypeError)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, session_id TEXT NOT NULL, run_id TEXT, event_type TEXT NOT NULL,
  entity_type TEXT, token_id TEXT,
  detail TEXT NOT NULL,          -- JSON; counts/latencies/hashes only
  prev_hash TEXT, entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events (session_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_run ON audit_events (run_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events (ts);

-- The second, independent high-water mark. See _watermark: sqlite_sequence alone
-- was not enough, because a freed tail seq was handed out again by the next
-- ordinary emit and the evidence of the truncation erased itself.
CREATE TABLE IF NOT EXISTS audit_chain_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  max_seq INTEGER NOT NULL
);
-- "Only ever grows" is enforced by the database, not only by the writer, so a
-- lowering UPDATE is refused rather than trusted not to happen. An attacker with
-- file access can DROP these -- SQLite has no protected schema -- but that is one
-- more statement they have to know to run, and the point of this whole mechanism
-- is raising the number of statements a silent truncation costs.
CREATE TRIGGER IF NOT EXISTS audit_chain_meta_is_monotonic
BEFORE UPDATE ON audit_chain_meta
WHEN NEW.max_seq < OLD.max_seq
BEGIN
  SELECT RAISE(ABORT, 'audit_chain_meta.max_seq may not decrease');
END;
CREATE TRIGGER IF NOT EXISTS audit_chain_meta_is_not_deletable
BEFORE DELETE ON audit_chain_meta
BEGIN
  SELECT RAISE(ABORT, 'audit_chain_meta may not be deleted');
END;
"""

_INSERT_SQL = """
INSERT INTO audit_events
  (seq, ts, session_id, run_id, event_type, entity_type, token_id, detail, prev_hash, entry_hash)
VALUES
  (:seq, :ts, :session_id, :run_id, :event_type, :entity_type, :token_id,
   :detail, :prev_hash, :entry_hash)
"""

_LAST_ENTRY_SQL = "SELECT seq, entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1"

# SQLite's own AUTOINCREMENT bookkeeping: the highest rowid ever allocated for this
# table. DELETE does not lower it, which is what makes tail truncation visible.
_HIGH_WATER_SQL = "SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'"

# Our own copy of the same fact, in a table SQLite does not manage. Two rows in two
# tables have to be reset in step for a truncation to heal; see _watermark.
_META_SQL = "SELECT max_seq FROM audit_chain_meta WHERE id = 1"

# Raise the mark, never lower it. `max_seq` on the right is the stored value, so
# this is a MAX and not an assignment even if a caller ever passes a stale seq.
_META_BUMP_SQL = """
INSERT INTO audit_chain_meta (id, max_seq) VALUES (1, :seq)
ON CONFLICT(id) DO UPDATE SET max_seq = MAX(max_seq, excluded.max_seq)
"""

_CHAIN_SQL = """
SELECT seq, ts, session_id, run_id, event_type, entity_type, token_id, detail, prev_hash, entry_hash
FROM audit_events
ORDER BY seq ASC
"""

# Static SQL with NULL-guarded optional filters: nothing is interpolated, so
# there is no query-construction path a caller-supplied filter could reach.
_QUERY_SQL = """
SELECT seq, ts, session_id, run_id, event_type, entity_type, token_id, detail, prev_hash, entry_hash
FROM audit_events
WHERE (:session_id IS NULL OR session_id = :session_id)
  AND (:run_id IS NULL OR run_id = :run_id)
  AND (:event_type IS NULL OR event_type = :event_type)
  AND (:since IS NULL OR ts >= :since)
  AND (:until IS NULL OR ts <= :until)
ORDER BY seq ASC
LIMIT :limit OFFSET :offset
"""

# Deliberately the same WHERE clause as _QUERY_SQL, minus the paging. ``length``
# is what tells a caller whether a paged ``query`` saw everything, so the two must
# select the same rows; writing the predicate twice with a different shape is how
# that stops being true.
_COUNT_SQL = """
SELECT COUNT(*) AS n FROM audit_events
WHERE (:session_id IS NULL OR session_id = :session_id)
  AND (:run_id IS NULL OR run_id = :run_id)
  AND (:event_type IS NULL OR event_type = :event_type)
  AND (:since IS NULL OR ts >= :since)
  AND (:until IS NULL OR ts <= :until)
"""


def canonical_json(payload: Mapping[str, object]) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, valid JSON.

    The hash chain is only reproducible if this is byte-stable across processes
    and Python versions, hence the explicit ``sort_keys``/``separators``.

    ``allow_nan=False`` matters for the same reason. Python's default emits the
    bare words ``NaN``/``Infinity``, which are *not* JSON: the chain would still
    verify inside this process, but the entire value of publishing the hash
    formula is that a third party can recompute it, and a conforming JSON parser
    rejects those tokens. Refusing to write a non-finite float is the fail-loud
    choice -- an audit record no auditor can verify is not an audit record.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


def chain_payload(
    *,
    seq: int,
    ts: float,
    session_id: str,
    run_id: str | None,
    event_type: str,
    entity_type: str | None,
    token_id: str | None,
    detail: DetailMap,
) -> dict[str, object]:
    """The event *without* its hashes -- the exact input to :func:`compute_entry_hash`.

    Both the write path and the verify path go through this function; if they
    ever disagreed the chain would be unverifiable the moment it was written.
    """
    return {
        "seq": seq,
        "ts": ts,
        "session_id": session_id,
        "run_id": run_id,
        "event_type": event_type,
        "entity_type": entity_type,
        "token_id": token_id,
        "detail": dict(detail),
    }


def compute_entry_hash(prev_hash: str, payload: Mapping[str, object]) -> str:
    """``sha256(prev_hash + canonical_json(event_without_hashes)).hexdigest()``."""
    return hashlib.sha256((prev_hash + canonical_json(payload)).encode("utf-8")).hexdigest()


class AuditLogger:
    """Append-only, hash-chained audit log over SQLite (WAL, one connection).

    Entry point is the :meth:`open` classmethod::

        audit = await AuditLogger.open(settings.data_dir / DEFAULT_DB_FILENAME)
        try:
            await audit.emit(event)
        finally:
            await audit.close()

    The instance is also an async context manager for scoped use::

        async with await AuditLogger.open(path) as audit:
            await audit.emit(event)
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    @property
    def db_path(self) -> Path:
        """Where the log lives. Useful for backup/attestation tooling."""
        return self._db_path

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    async def open(cls, db_path: str | Path) -> Self:
        """Connect, enable WAL, and create the schema if it does not exist.

        Propagates ``sqlite3.DatabaseError`` if the file is not a database this
        process can set up -- but does not leak the connection on the way out; see
        :meth:`_connect`.
        """
        instance = cls(db_path)
        await instance._connect()
        return instance

    async def _connect(self) -> None:
        """Open the connection and run the setup statements, or close it and re-raise.

        ``aiosqlite.connect`` starts a **non-daemon** worker thread and hands back a
        connection object before any of the setup below has touched the file, so
        the first statement that reads a page is the first that can fail. On a
        corrupt or truncated file that is ``PRAGMA journal_mode=WAL`` -- verified,
        not assumed: see
        ``test_a_failed_open_does_not_leak_the_connection_thread``.

        Without the ``try`` that failure escaped ``open()`` with ``self._conn``
        still ``None``, so the caller held no handle to the live connection and had
        no way to close it. The worker thread is not a daemon, so it kept the
        interpreter alive: a process that opened a corrupt audit DB could not exit,
        and each retry leaked another thread. Closing here is the only place with a
        reference to ``conn``, which is what makes this the fix rather than
        something the caller could have done.
        """
        if self._conn is not None:
            return
        parent = self._db_path.parent
        if str(parent):
            await asyncio.to_thread(parent.mkdir, parents=True, exist_ok=True)
        # ``isolation_level=None`` puts this connection in SQLite's own autocommit
        # mode and hands transaction control to us. ``emit`` needs it: the read of
        # the chain tail and the insert that extends it have to be one transaction
        # that holds the *write* lock from the start (``BEGIN IMMEDIATE``), or a
        # second process reads the same tail and one of the two writes is lost.
        # Python's implicit transactions are deferred, and a deferred transaction
        # upgrading to a write lock in WAL mode fails immediately with
        # SQLITE_BUSY_SNAPSHOT -- the busy handler is not even consulted -- so
        # ``busy_timeout`` alone does not close this.
        conn = await aiosqlite.connect(self._db_path, isolation_level=None)
        try:
            conn.row_factory = aiosqlite.Row
            # FIRST, before any statement that can contend. Without it a second
            # writer holding the write lock makes ours fail instantly with
            # SQLITE_BUSY and the event is dropped -- and setting it after
            # ``journal_mode`` is not "first enough": that pragma takes a lock of its
            # own, so opening a log while another process was mid-write raised
            # ``database is locked`` out of ``open()`` itself. Measured, not
            # reasoned: two writers, one failed to open on 2 of 3 runs with the
            # pragmas in the other order. Bounded, so a wedged writer cannot hang a
            # request past the caller's own timeout.
            await conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            # WAL: concurrent readers (the API's /audit endpoints) never block the
            # single writer. NORMAL sync is the standard WAL durability trade.
            await _enable_wal(conn)
            await conn.execute("PRAGMA synchronous=NORMAL")
            await conn.executescript(_SCHEMA)
            await conn.commit()
        except BaseException:
            # BaseException, not Exception: a CancelledError here leaks the thread
            # exactly as a DatabaseError does, and cancellation of an open() is the
            # realistic case (a startup timeout) rather than the exotic one.
            with contextlib.suppress(Exception):
                await conn.close()
            raise
        self._conn = conn
        logger.debug("audit log opened", extra={"audit_db": str(self._db_path)})

    async def close(self) -> None:
        """Close the connection. Idempotent."""
        conn, self._conn = self._conn, None
        if conn is not None:
            await conn.close()
            logger.debug("audit log closed", extra={"audit_db": str(self._db_path)})

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

    def _connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise PipelineError(reason="audit_logger_not_open")
        return self._conn

    # -- write path --------------------------------------------------------

    async def emit(self, event: AuditEvent) -> int:
        """Assign ``seq``, extend the hash chain, insert, and return the ``seq``.

        The supplied ``event`` is not mutated; ``seq``/``prev_hash``/``entry_hash``
        on it are ignored. Read ``query()`` back for the persisted form.

        Raises :class:`PipelineError` if any string field exceeds its ceiling -- see
        :func:`_reject_content_sized_fields`, which re-checks at the write boundary
        because the schema's own validators are bypassable by assignment.

        **``seq`` is allocated above the watermark, not above the surviving tail**,
        and that one-word difference is what stops a truncation healing itself.
        ``MAX(seq)+1`` over the surviving rows re-issues a *freed* number: delete the
        newest three events and the next three ordinary emits land on 6, 7, 8 again,
        ``last_seq`` climbs back to the high-water mark, and :meth:`verify_chain`
        -- which was correctly reporting ``False`` a moment earlier -- goes back to
        ``True`` with the original events permanently gone. The attacker needs no
        second statement for that; they need only wait for traffic, which the public
        API lets them generate. Allocating above the watermark turns the same
        truncation into a permanent ``seq`` gap, which the continuity check reports
        forever.

        A watermark this method cannot read degrades to the old behaviour rather
        than refusing to log: an audit writer that fails closed is an audit writer
        that silences the pipeline, and the *verifier* already resolves an
        unreadable watermark to ``False``, so the tamper is still reported by the
        component whose job that is.
        """
        conn = self._connection()
        _reject_content_sized_fields(event)
        detail = dict(event.detail)
        detail_json = canonical_json(detail)

        async with self._lock:
            for attempt in range(MAX_EMIT_ATTEMPTS):
                # The write lock is taken BEFORE the tail is read, so no other
                # process can allocate the same seq in between. This is the line
                # that makes the retry below a belt-and-braces path rather than the
                # mechanism -- with a deferred transaction the read is unprotected
                # and the collision is routine.
                await conn.execute("BEGIN IMMEDIATE")
                try:
                    try:
                        watermark = await self._watermark()
                    except _UNREADABLE as exc:
                        # Writer degrades, verifier does not. See the docstring.
                        logger.warning(
                            "audit watermark unreadable; falling back to the surviving tail",
                            extra={"error": type(exc).__name__},
                        )
                        watermark = None

                    async with conn.execute(_LAST_ENTRY_SQL) as cursor:
                        row = await cursor.fetchone()
                    if row is None:
                        last_seq = 0
                        prev_hash = GENESIS_HASH
                    else:
                        last_seq = int(row["seq"])
                        prev_hash = str(row["entry_hash"])
                    seq = max(last_seq, 0 if watermark is None else watermark) + 1

                    payload = chain_payload(
                        seq=seq,
                        ts=event.ts,
                        session_id=event.session_id,
                        run_id=event.run_id,
                        event_type=event.event_type,
                        entity_type=event.entity_type,
                        token_id=event.token_id,
                        detail=detail,
                    )
                    entry_hash = compute_entry_hash(prev_hash, payload)

                    await conn.execute(
                        _INSERT_SQL,
                        {
                            "seq": seq,
                            "ts": event.ts,
                            "session_id": event.session_id,
                            "run_id": event.run_id,
                            "event_type": event.event_type,
                            "entity_type": event.entity_type,
                            "token_id": event.token_id,
                            "detail": detail_json,
                            "prev_hash": prev_hash,
                            "entry_hash": entry_hash,
                        },
                    )
                    try:
                        await conn.execute(_META_BUMP_SQL, {"seq": seq})
                    except sqlite3.Error as exc:
                        # Best-effort, and deliberately so. If the second mark cannot
                        # be advanced -- the table was dropped out from under this
                        # connection, say -- the event itself still has to be
                        # recorded: an audit writer that refuses to log because its
                        # own bookkeeping is damaged converts a tampered mark into a
                        # blind spot with no events in it at all, which is the
                        # outcome the attacker wanted. sqlite_sequence still carries
                        # a mark, and verify_chain still reads it.
                        logger.warning(
                            "audit watermark not advanced; the event was still recorded",
                            extra={"audit_seq": seq, "error": type(exc).__name__},
                        )
                    await conn.commit()
                except sqlite3.IntegrityError:
                    # Another *process* took this seq between our read and our
                    # insert; the asyncio lock above does not reach it. Roll back so
                    # the next attempt reads a fresh snapshot, then re-chain onto the
                    # tail they left. Dropping the event instead -- which is what this
                    # did before -- is the one audit failure nothing can detect
                    # afterwards, because the row was never written.
                    await conn.rollback()
                    if attempt == MAX_EMIT_ATTEMPTS - 1:
                        raise PipelineError(
                            reason="audit_seq_contention",
                            attempts=MAX_EMIT_ATTEMPTS,
                        ) from None
                    logger.warning(
                        "audit seq collided with another writer; re-chaining",
                        extra={"audit_seq": seq, "attempt": attempt + 1},
                    )
                    continue
                except BaseException:
                    # Never leave the write transaction open: this connection is
                    # reused for every later emit, and an open transaction turns one
                    # failed write into "cannot start a transaction within a
                    # transaction" on every write after it.
                    with contextlib.suppress(Exception):
                        await conn.rollback()
                    raise
                break

        # Token IDs and counts only -- never a value, never the detail payload's
        # provenance beyond its key count.
        logger.info(
            "audit event recorded",
            extra={
                "audit_seq": seq,
                "audit_event_type": event.event_type,
                "session_id": event.session_id,
                "run_id": event.run_id,
                "entity_type": event.entity_type,
                "token_id": event.token_id,
                "detail_keys": len(detail),
            },
        )
        return seq

    # -- read path ---------------------------------------------------------

    async def query(
        self,
        *,
        session_id: str | None = None,
        run_id: str | None = None,
        event_type: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Compliance query. ``since``/``until`` are inclusive ``ts`` bounds.

        Results are ordered by ``seq`` ascending -- i.e. chain order, which is
        also insertion order.

        A database this method cannot read raises :class:`PipelineError` with
        ``reason="audit_log_unreadable"`` rather than letting a raw
        ``sqlite3.DatabaseError`` -- or, on a partially readable file, a bare
        ``TypeError`` from ``float(row["ts"])`` where a page came back as ``NULL``
        -- escape from the middle of a row loop. Both were observed on a
        physically corrupted file that ``open()`` accepted; see
        ``test_query_reports_an_unreadable_database_as_a_typed_error``.

        It does **not** return the rows it managed to read before the failure.
        Truncation is precisely the attack the chain verifier exists to catch, and
        a partial answer with a 200 on it is indistinguishable from a complete one
        to every caller. Never returning a silently short log is the same
        fail-closed direction :meth:`verify_chain` resolves in; the difference is
        only that "no opinion" is expressible as ``False`` there and is not
        expressible as a ``list`` here.
        """
        if limit < 1:
            raise PipelineError(reason="audit_query_limit_out_of_range", limit=limit)
        if offset < 0:
            raise PipelineError(reason="audit_query_offset_out_of_range", offset=offset)

        conn = self._connection()
        params: dict[str, str | float | int | None] = {
            "session_id": session_id,
            "run_id": run_id,
            "event_type": event_type,
            "since": since,
            "until": until,
            "limit": limit,
            "offset": offset,
        }
        events: list[AuditEvent] = []
        try:
            async with conn.execute(_QUERY_SQL, params) as cursor:
                async for row in cursor:
                    events.append(_row_to_event(row))
        except _UNREADABLE as exc:
            raise PipelineError(
                reason="audit_log_unreadable", error=type(exc).__name__
            ) from exc
        return events

    async def verify_chain(self, session_id: str | None = None) -> bool:
        """Recompute every ``entry_hash`` in ``seq`` order and re-check every link.

        Nothing here trusts a stored value to vouch for itself: each row's hash is
        recomputed from its own persisted columns via the same
        :func:`chain_payload` the writer used, and compared against the stored
        digest. ``prev_hash`` is likewise re-derived from the walk rather than read
        back and believed.

        ``session_id=None`` verifies the whole log. With a ``session_id`` the walk
        still covers every row, and the two kinds of check are scoped differently
        on purpose:

        * **content** -- recomputing a row's own ``entry_hash`` asks "was *this*
          record altered", which is a per-session question, so it is asserted only
          for in-scope rows. That is what lets one session's edited ``detail`` fail
          its own check without failing an unrelated session's.
        * **structure** -- link continuity and ``seq`` continuity are checked for
          **every** row regardless of scope. An insertion, a deletion, or a reorder
          moves the rows that a session's slice is chained *to*; it cannot be
          attributed to a session, and reporting a session as clean while the log
          it lives in has a hole would be exactly the wrong answer. Before this was
          global, deleting every row of session X made ``verify_chain("X")`` return
          ``True`` -- erasure read as cleanliness.

        Finally the tail is checked against the **watermark** -- the highest ``seq``
        ever allocated, according to two bookkeeping rows in two different tables
        (:meth:`_watermark`). Truncating the newest rows is the obvious move for an
        attacker who wants the incriminating events gone, and it leaves the
        surviving chain internally perfect, so without a watermark it is
        undetectable.

        Two shapes of that attack are worth naming because both used to end in
        ``True``:

        * **A missing bookkeeping row is evidence, not silence.** ``None`` from
          :meth:`_watermark` means "no mark at all", which is the truth on a log
          that has never been written -- and was previously treated as "no opinion"
          on every log. So an attacker who truncated the tail and then deleted the
          bookkeeping row out of ``sqlite_sequence`` got a clean bill of health,
          without touching a hash and without knowing how many rows had survived. A
          written log always has a mark, so no mark **on a non-empty log** now
          resolves to ``False``.
        * **A deleted tail no longer heals itself.** See :meth:`emit`: ``seq`` is
          allocated above the watermark, so the truncation leaves a permanent gap
          instead of being papered over by the next few ordinary events.

        Like the rest of this scheme it is tamper *evidence*, not tamper proofing:
        the digests are unkeyed, so anyone who can write to the file can rewrite the
        whole chain and both marks. What it buys is arithmetic on the attacker's
        side -- a silent truncation now costs a ``DELETE``, a write to
        ``sqlite_sequence``, a ``DROP TRIGGER`` and a write to ``audit_chain_meta``,
        all four, in step. Detecting the attacker who runs all four needs an off-box
        anchor -- publishing the head hash, or an HMAC under a key the app host does
        not hold -- and is listed as production work.

        Returns ``False`` rather than raising: this is a health check, and the
        callers (``GET /audit/verify``, ``demo.py --verify``) report it as data.

        **That contract holds on a corrupt database too**, which it previously did
        not. Truncating the DB file mid-page -- a torn write, a full disk, a partial
        restore, or an attacker simply lopping bytes off the end -- made
        ``conn.execute`` raise ``sqlite3.DatabaseError`` straight through this
        method. The verifier that exists to answer "has this log been tampered
        with" therefore answered with a 500 from ``GET /audit/verify`` instead of
        ``{"valid": false}``, on an input that is *precisely* the tampering it is
        meant to report. ``_watermark`` already degraded gracefully on
        ``sqlite3.Error``; the main walk did not, and the asymmetry was the bug.

        A database this method cannot read is not a database it can vouch for, so
        the unreadable case resolves to ``False`` -- the fail-closed answer, and the
        same direction every other doubt in this codebase resolves in.
        """
        conn = self._connection()
        expected_prev = GENESIS_HASH
        expected_seq = 1
        last_seq = 0
        valid = True

        try:
            async with conn.execute(_CHAIN_SQL) as cursor:
                async for row in cursor:
                    seq = int(row["seq"])
                    stored_hash = str(row["entry_hash"])
                    stored_prev = "" if row["prev_hash"] is None else str(row["prev_hash"])

                    # Structural: global, whatever the scope.
                    if stored_prev != expected_prev:
                        valid = False
                        _log_break(seq, "prev_hash_mismatch")
                    if seq != expected_seq:
                        valid = False
                        _log_break(seq, "seq_discontinuity")

                    # Content: scoped.
                    if session_id is None or str(row["session_id"]) == session_id:
                        detail = _load_detail(row["detail"])
                        if detail is None:
                            valid = False
                            _log_break(seq, "detail_not_json")
                        else:
                            payload = chain_payload(
                                seq=seq,
                                ts=float(row["ts"]),
                                session_id=str(row["session_id"]),
                                run_id=None if row["run_id"] is None else str(row["run_id"]),
                                event_type=str(row["event_type"]),
                                entity_type=(
                                    None
                                    if row["entity_type"] is None
                                    else str(row["entity_type"])
                                ),
                                token_id=(
                                    None if row["token_id"] is None else str(row["token_id"])
                                ),
                                detail=detail,
                            )
                            if compute_entry_hash(stored_prev, payload) != stored_hash:
                                valid = False
                                _log_break(seq, "entry_hash_mismatch")

                    expected_prev = stored_hash
                    expected_seq = seq + 1
                    last_seq = seq
        except _UNREADABLE as exc:
            # The shared rule -- see _UNREADABLE. Unreadable is not clean.
            _log_break(last_seq, f"chain_unreadable:{type(exc).__name__}")
            return False

        # Outside the walk's try on purpose, so it needs its own. A watermark that is
        # *present but not a number* is tamper evidence, not absence: the attacker
        # who deletes the newest rows has every reason to blank this value too,
        # because it is the only thing that notices. Letting it degrade to "no
        # opinion" would hand them a clean bill of health, and letting it propagate
        # would break "returns False rather than raising" -- turning GET
        # /audit/verify into a 500 on precisely the tamper it exists to report,
        # which is the bug the walk above was already fixed for.
        try:
            watermark = await self._watermark()
        except _UNREADABLE as exc:
            _log_break(last_seq, f"watermark_unreadable:{type(exc).__name__}")
            return False
        if watermark is None:
            # No mark at all. True on a log that was never written; on a log that
            # holds rows it means the bookkeeping was erased, which is the whole
            # point of erasing it.
            if last_seq > 0:
                valid = False
                _log_break(last_seq, "watermark_missing")
        elif last_seq != watermark:
            valid = False
            _log_break(last_seq, "tail_truncated")

        if valid:
            logger.debug(
                "audit chain verified", extra={"session_id": session_id, "chain_ok": True}
            )
        return valid

    async def _watermark(self) -> int | None:
        """Highest ``seq`` ever allocated, or ``None`` if there is no mark at all.

        Two independent sources, and the answer is the larger of the ones that
        exist:

        * ``sqlite_sequence`` -- SQLite's own ``AUTOINCREMENT`` bookkeeping, which
          ``DELETE`` does not roll back. Free, and maintained by code an attacker
          cannot patch out of this process.
        * ``audit_chain_meta`` -- the same fact in a table this module owns, bumped
          by :meth:`emit` and guarded by triggers that refuse a lowering ``UPDATE``
          or a ``DELETE``.

        One would be enough if either were tamper-proof; neither is, and their
        weaknesses are not the same weakness, which is the point of keeping both.
        ``sqlite_sequence`` is re-created automatically by the next ``INSERT``, so an
        attacker who deletes that row has it silently restored -- at the *new*, lower
        value -- by ordinary traffic. ``audit_chain_meta`` is not re-created behind
        our back, and its triggers mean the attacker cannot lower it without
        dropping them first. Taking the maximum means a truncation is hidden only if
        **every** mark is reset in step, and a mark that is left behind at the old
        value is permanent evidence.

        ``None`` means neither row exists, which is the honest state of a log that
        has never been written and the state an attacker has to manufacture.
        :meth:`verify_chain` resolves it to ``False`` on any log that still holds
        rows.

        **A row that exists but does not hold an integer raises**, deliberately.
        ``sqlite_sequence`` is an ordinary writable table: ``UPDATE sqlite_sequence
        SET seq = NULL`` is accepted by SQLite, and it is the natural move for an
        attacker who has just deleted the newest rows. Folding that into the ``None``
        above would make erasure read as cleanliness. :meth:`verify_chain` catches it
        and returns ``False``; see
        ``test_verify_chain_survives_a_tampered_high_water_mark``.
        """
        conn = self._connection()
        marks: list[int] = []
        for sql in (_HIGH_WATER_SQL, _META_SQL):
            try:
                async with conn.execute(sql) as cursor:
                    row = await cursor.fetchone()
            except sqlite3.Error:
                # The bookkeeping table itself is gone or unreadable. Not an opinion
                # on its own -- the other source may still have one, and a log with
                # no source at all is resolved by the caller.
                continue
            if row is not None:
                marks.append(int(row[0]))
        return max(marks) if marks else None

    async def length(
        self,
        session_id: str | None = None,
        *,
        run_id: str | None = None,
        event_type: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> int:
        """How many rows match -- the same filters :meth:`query` accepts.

        Two callers, one of which is the reason the filters exist.
        ``GET /audit/verify`` wants the unfiltered chain length for its
        ``{valid, length}`` response, and passes nothing.

        The other is a compliance query, and it needs this to be *answerable*.
        ``query`` pages, defaulting to ``limit=1000``, and a page that comes back
        full is indistinguishable from a complete result: a HIPAA reviewer asking
        "what happened in the last 30 days" would get exactly 1000 events and no
        signal that there were more. Comparing ``len(events)`` against
        ``length(**same_filters)`` is what turns that into a checkable answer, and
        it is why the count carries the whole filter set rather than just
        ``session_id``::

            since = time.time() - 30 * 86400
            total = await audit.length(since=since)
            events = await audit.query(since=since, limit=500)
            complete = len(events) == total   # otherwise: keep paging

        ``since``/``until`` are inclusive ``ts`` bounds, matching :meth:`query`.

        Unreadable resolves the same way :meth:`query` resolves it -- a typed
        :class:`PipelineError` with ``reason="audit_log_unreadable"`` rather than a
        raw ``sqlite3.DatabaseError`` from inside the row fetch. Worth stating
        because ``GET /audit/verify`` calls :meth:`verify_chain` and *then* this,
        so hardening only the first one leaves the endpoint failing on the same
        corrupt file for the second reason; ``/health`` already treats any
        exception here as ``db_reachable=False``.
        """
        conn = self._connection()
        params: dict[str, str | float | None] = {
            "session_id": session_id,
            "run_id": run_id,
            "event_type": event_type,
            "since": since,
            "until": until,
        }
        try:
            async with conn.execute(_COUNT_SQL, params) as cursor:
                row = await cursor.fetchone()
            return 0 if row is None else int(row["n"])
        except _UNREADABLE as exc:
            raise PipelineError(
                reason="audit_log_unreadable", error=type(exc).__name__
            ) from exc


async def _enable_wal(conn: aiosqlite.Connection) -> None:
    """Put the database into WAL mode, tolerating a concurrent opener.

    ``busy_timeout`` does not cover this one. Converting a database *into* WAL needs
    a moment of exclusive access, and SQLite returns ``SQLITE_BUSY`` for that
    conversion **without consulting the busy handler** -- so two processes opening a
    brand-new audit DB at the same instant produce ``database is locked`` out of
    ``open()`` itself, on a database that is about to be perfectly fine. Observed as
    a flake, not predicted: the cross-process writer test passed five runs in
    isolation and failed once under full-suite load.

    Two mitigations, in order:

    * **Read before writing.** An already-WAL database answers ``PRAGMA
      journal_mode`` without needing any lock at all, so the common path -- every
      reopen of an existing log -- stops contending entirely.
    * **Retry the conversion.** Only the very first connection converts, and the
      window is one statement wide, so a few short waits cover it.

    Errors other than a lock are re-raised on the first attempt: a corrupt file must
    still fail ``open()`` promptly rather than being retried into a slow failure, and
    ``test_a_failed_open_does_not_leak_the_connection_thread`` depends on that.
    """
    async with conn.execute("PRAGMA journal_mode") as cursor:
        row = await cursor.fetchone()
    if row is not None and str(row[0]).lower() == "wal":
        return
    for attempt in range(WAL_SETUP_ATTEMPTS):
        try:
            await conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            if attempt == WAL_SETUP_ATTEMPTS - 1:
                raise
            await asyncio.sleep(WAL_SETUP_BACKOFF_S * (attempt + 1))
        else:
            return


def _log_break(seq: int, reason: str) -> None:
    logger.warning("audit chain broken", extra={"audit_seq": seq, "chain_break": reason})


def _reject_content_sized_fields(event: AuditEvent) -> None:
    """Re-check the size ceilings at the write boundary, where they are enforceable.

    :class:`AuditEvent` declares them -- ``max_length`` on every string column and a
    validator on ``detail`` -- and that is the right place to *state* the invariant.
    Two of the three ways past it are now closed *in the model*: it is ``frozen``, so
    ``event.entity_type = original`` raises, and ``detail`` is a read-only
    :class:`~types.MappingProxyType` over a copy, so ``event.detail["value"] =
    original`` raises too. Both of those reached SQLite untouched before that change.

    The third is not closable there. ``AuditEvent.model_construct(...)`` skips
    validation outright by design, and it is the *normal* path for rebuilding a model
    from data already believed to be trusted -- deserialisation, a cache, a queue. So
    the ceiling still has to be enforced where the value is written, not only where it
    was first built. That is not a hypothetical shape: ``entity_type`` and ``token_id``
    are written from values parsed out of untrusted LLM output, and this function is
    the last code that runs before the INSERT.

    Refusing beats truncating: a silently clipped original is still a compliance log
    full of original. Every legitimate value here is small and bounded -- registry
    type names, 8-hex token IDs, uuid4 hex identifiers, event-type constants,
    latencies, counts and sha256 digests -- so this only ever fires on content.
    """
    for field, value in (
        ("session_id", event.session_id),
        ("run_id", event.run_id),
        ("event_type", event.event_type),
        ("entity_type", event.entity_type),
        ("token_id", event.token_id),
    ):
        if value is not None and len(value) > MAX_AUDIT_LABEL_LEN:
            raise PipelineError(
                reason="audit_field_exceeds_ceiling", field=field, length=len(value)
            )
    for key, detail_value in event.detail.items():
        # The key is bounded here as well as in `AuditEvent`'s validator, and the
        # duplication is the point: this is the last check before the row is written,
        # and a caller can reach it with an event built by `model_construct` (which
        # skips validators entirely). A ceiling enforced in only one of two places is
        # a ceiling the other path does not have.
        if len(key) > MAX_DETAIL_VALUE_LEN:
            raise PipelineError(
                reason="audit_detail_key_exceeds_ceiling",
                field=key[:MAX_DETAIL_VALUE_LEN],
                length=len(key),
            )
        if isinstance(detail_value, str) and len(detail_value) > MAX_DETAIL_VALUE_LEN:
            raise PipelineError(
                reason="audit_detail_exceeds_ceiling",
                field=key[:MAX_DETAIL_VALUE_LEN],
                length=len(detail_value),
            )


def _load_detail(raw: object) -> dict[str, int | float | str] | None:
    """Parse a stored ``detail`` column, or ``None`` if it is not a JSON object.

    A tampered row may hold anything at all, so this must not raise -- a
    malformed ``detail`` is itself evidence of tampering.
    """
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    detail: dict[str, int | float | str] = {}
    for key, value in parsed.items():
        if not isinstance(value, int | float | str):
            return None
        detail[str(key)] = value
    return detail


def _row_to_event(row: aiosqlite.Row) -> AuditEvent:
    detail = _load_detail(row["detail"])
    return AuditEvent(
        seq=int(row["seq"]),
        ts=float(row["ts"]),
        session_id=str(row["session_id"]),
        run_id=None if row["run_id"] is None else str(row["run_id"]),
        event_type=str(row["event_type"]),
        entity_type=None if row["entity_type"] is None else str(row["entity_type"]),
        token_id=None if row["token_id"] is None else str(row["token_id"]),
        detail={} if detail is None else detail,
        prev_hash="" if row["prev_hash"] is None else str(row["prev_hash"]),
        entry_hash=str(row["entry_hash"]),
    )
