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
slice intact" rather than "is the whole log intact". Stated that precisely
because the difference is load-bearing and one shape of it is a residual:
rewriting a row's ``session_id`` moves it out of a session as completely as
``DELETE`` removes it, and the *scoped* form cannot see that. Only the unscoped
form answers "was anything in this log altered"; see
:meth:`AuditLogger.verify_chain` for why no scoped rule can close it.

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
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Self

import aiosqlite

from secure_context_pipeline.errors import AuditUnavailableError, PipelineError
from secure_context_pipeline.models import (
    AUDIT_ACTION_KEY,
    AUDIT_ACTIONS,
    MAX_AUDIT_LABEL_LEN,
    MAX_DETAIL_VALUE_LEN,
    AuditEvent,
    DetailMap,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ACTION_KEY",
    "DEFAULT_DB_FILENAME",
    "DEOBFUSCATE",
    "DETECT",
    "EGRESS_BLOCK",
    "EGRESS_PASS",
    "EVENT_ACTIONS",
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
# All twelve are now emitted. ``SESSION_EXPIRE`` was declared and never emitted for
# a long time, and the reason it stayed unemitted is worth keeping: TTL lapse is
# discovered lazily, by the next accessor to ask ``SessionRegistry`` for a key, so
# the moment a session dies is not a moment any code is running. Logout emitted
# ``VAULT_DESTROY`` (section 4 step 10), so the explicit teardown path was covered
# and only the passive one was silent.
#
# ``deps.reap_expired_sessions`` closes it: the request that *discovers* an expiry
# finishes the destruction path and emits both events -- ``SESSION_EXPIRE`` for the
# death and ``VAULT_DESTROY`` for the teardown it triggered, because an auditor
# asking "when did this session end, and was it torn down" wants both facts and
# they are not the same fact.
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

# --------------------------------------------------------------------------
# ``detail['action']`` -- the explicitly-named required field
# --------------------------------------------------------------------------
#: Re-exported from :mod:`~secure_context_pipeline.models`, where it is applied.
#:
#: The action label is stamped onto :class:`AuditEvent` at construction rather than
#: here, so that a row read back still equals the event that was emitted -- this
#: module does not alter what it is handed. See
#: :data:`~secure_context_pipeline.models.AUDIT_ACTIONS` for the requirement, the
#: measurement, and the placement argument; the vocabulary is re-exported under this
#: module's names because this is where a reader looking for audit event semantics
#: goes first.
EVENT_ACTIONS = AUDIT_ACTIONS
ACTION_KEY = AUDIT_ACTION_KEY

# The vocabulary is written down in two modules -- the event-type constants here,
# the action labels next to the model that applies them, because that module cannot
# import this one. The duplication is made checkable rather than hoped for: a
# thirteenth event type, or a renamed one, is an import-time failure here instead of
# a row that quietly ships without the field requirement 7 names. Same technique as
# `_UNREADABLE`: one rule, asserted rather than trusted to stay in step.
assert EVENT_TYPES == frozenset(EVENT_ACTIONS), (
    "every audit event type needs exactly one action label in models.AUDIT_ACTIONS"
)
assert all(0 < len(action) <= MAX_DETAIL_VALUE_LEN for action in EVENT_ACTIONS.values()), (
    "an action label must fit the audit detail ceiling, or the writer would start "
    "refusing rows because of its own constant"
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
#:
#: ``emit`` is on this list too, and reads *twice* under it -- the watermark and the
#: chain tail -- resolving the two in opposite directions: the watermark degrades to
#: the surviving tail, an unreadable tail refuses the write. Both are argued where
#: they are caught.
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

    def _unreadable(self, exc: BaseException, *, operation: str) -> AuditUnavailableError:
        """The one refusal every entry point raises on a database it cannot read.

        A companion to :data:`_UNREADABLE` and built for the same reason: that tuple
        makes the three sites agree on *what* unreadable means, and this makes them
        agree on what to *answer*. Two of them already did -- ``query`` and ``length``
        each hand-built ``PipelineError(reason="audit_log_unreadable", ...)``, which is
        two copies of one rule, the shape this file has been bitten by twice.

        The full path goes to the server log and only the file **name** goes into the
        exception, which ``api/errors.py`` writes into an HTTP body verbatim. The name
        is what an operator needs (``data/audit.db`` is a bind mount they configured);
        the absolute path is a description of the server's filesystem that no client
        is owed, and under a pytest ``tmp_path`` it is also routinely longer than the
        64-character detail ceiling that would then raise *from inside the error
        path*.
        """
        logger.error(
            "audit log unreadable; the operation was refused",
            extra={
                "audit_db": str(self._db_path),
                "audit_operation": operation,
                "error": type(exc).__name__,
            },
        )
        return AuditUnavailableError(
            operation=operation,
            audit_db=self._db_path.name,
            error=type(exc).__name__,
        )

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

        A batch of one. Every line of the write path lives in :meth:`emit_many`, and
        this delegates rather than duplicating it, because "the single-event path and
        the batch path agree" is not something a reviewer should have to check by
        reading two implementations of a hash chain. One row through this method and
        one row through ``emit_many`` produce the same ``seq``, the same
        ``prev_hash`` and the same ``entry_hash``, by construction rather than by
        care -- see ``test_emit_and_emit_many_write_byte_identical_rows``.

        The supplied ``event`` is not mutated; ``seq``/``prev_hash``/``entry_hash``
        on it are ignored. Read ``query()`` back for the persisted form.

        Raises :class:`PipelineError` if any field exceeds its ceiling, or if a
        ``detail`` key is not a string or a ``detail`` value is not a scalar -- see
        :func:`_reject_content_sized_fields`, which re-checks at the write boundary
        because the schema's own validators are bypassable by assignment. Those two
        checks run **before** the ``try`` below, deliberately: a caller that hands
        this method content is not a database that cannot be read, and folding the
        two together would file the first under the second's error code.

        A database this method cannot read raises
        :class:`~secure_context_pipeline.errors.AuditUnavailableError` -- the refusal
        ``query`` and ``length`` already answered with, and the reason it now has a
        code of its own. What escaped here instead was the raw
        ``sqlite3.DatabaseError``: measured through the real ASGI app on a file with
        one 4 KiB page overwritten, ``POST /pipeline/run`` answered ``500``
        ``text/plain`` ``Internal Server Error``, with no ``code``, no CSP and no
        ``nosniff`` -- Starlette renders an unhandled exception outside the
        middleware that adds them. The run was refused either way and must stay
        refused; only the shape of the refusal changed. See
        :meth:`_unreadable`, and ``verify_chain``'s "unreadable is not clean" rule
        for the other half of the same argument.

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
        return (await self.emit_many((event,)))[0]

    async def emit_many(self, events: Sequence[AuditEvent]) -> list[int]:
        """Append every event in ``events`` in **one** transaction. Returns their ``seq``s.

        Same rows, written more cheaply. This is not a different chain, a summarised
        chain, or a reordered one: ``events`` is appended in the order given, each
        row's ``prev_hash`` is the row before it, and the ``entry_hash`` formula is
        untouched. What changes is that ``BEGIN IMMEDIATE``, the watermark read, the
        chain-tail read, the high-water bump and the ``COMMIT`` are paid **once for
        the batch** instead of once per row.

        **Why it exists.** ``deobfuscation/restorer.py`` writes one ``DEOBFUSCATE``
        row per distinct token ID restored, capped at 512, and each one was its own
        transaction. Measured on the 500-token restore benchmark on this machine,
        that put the stage at **252-289 ms against a 500 ms budget** -- 1.7-2.0x
        headroom on the tightest budget in the product, with the audit writer, not
        the vault or the regex work, as the dominant term. The engine's
        ``OBFUSCATE`` rows have the same shape and the same fix available.

        **Atomic, and that is a change worth naming.** N separate ``emit`` calls that
        fail on row K leave K-1 rows committed; one ``emit_many`` that fails leaves
        none. For a per-entity itemisation that is the better failure: a half-written
        itemisation is indistinguishable from a complete one for a document with
        fewer entities, whereas an absent one is visibly absent next to the stage row
        that says how many were restored.

        Everything else is :meth:`emit`'s contract, unchanged and argued there: the
        ceilings are re-checked **before** the transaction opens (a caller handing us
        content is not a database we cannot read); ``seq`` is allocated above the
        watermark rather than above the surviving tail; an unreadable watermark
        degrades and an unreadable chain tail refuses; a ``seq`` lost to another
        *process* rolls the whole batch back and re-chains onto the tail they left.

        An empty ``events`` writes nothing and opens no transaction.
        """
        conn = self._connection()
        if not events:
            return []

        # Validated, action-stamped and serialised BEFORE the write lock: a refusal
        # here must not have taken a transaction, and `canonical_json` is pure CPU
        # that has no business inside one.
        #
        # The stamp is on a COPY. The caller's event is not mutated (`emit` promises
        # that and `test_emit_does_not_mutate_the_caller_event` pins it), and it lands
        # before `canonical_json`, so `action` is inside the digest rather than beside
        # it -- a field added after the hash was taken would be one an attacker could
        # rewrite freely with `verify_chain()` still returning True.
        prepared: list[tuple[AuditEvent, dict[str, int | float | str], str]] = []
        for event in events:
            _reject_content_sized_fields(event)
            detail = dict(event.detail)
            action = EVENT_ACTIONS.get(event.event_type)
            # `setdefault`, not assignment: a call site that already said what it did
            # keeps saying it. Today the only emitter that names an action is
            # `restorer.py`, and it writes "restore" -- which is what this map holds
            # for DEOBFUSCATE anyway, so the two are indistinguishable in the shipped
            # code and a test written against that pairing pins nothing (it did not:
            # swapping this for a plain assignment left the suite green until
            # `test_a_caller_that_already_named_its_action_keeps_it` was rewritten to
            # use a value that differs). The rule is kept because the field's whole
            # value is a caller being able to say something narrower than its event
            # type -- a partial restore, a replay, a compensating write -- and a
            # writer that overwrites would erase exactly that, silently.
            if action is not None:
                detail.setdefault(ACTION_KEY, action)
            prepared.append((event, detail, canonical_json(detail)))

        seqs: list[int] = []
        try:
            async with self._lock:
                for attempt in range(MAX_EMIT_ATTEMPTS):
                    # The write lock is taken BEFORE the tail is read, so no other
                    # process can allocate the same seq in between. This is the line
                    # that makes the retry below a belt-and-braces path rather than the
                    # mechanism -- with a deferred transaction the read is unprotected
                    # and the collision is routine.
                    await conn.execute("BEGIN IMMEDIATE")
                    seqs = []
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
                        seq = max(last_seq, 0 if watermark is None else watermark)

                        for event, detail, detail_json in prepared:
                            seq += 1
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
                            # The chain is carried forward in memory rather than
                            # re-read: inside one transaction this connection is the
                            # only writer, so the row we just inserted IS the tail.
                            # Re-reading it would be the same value at the cost of a
                            # round trip per row, which is the cost this method exists
                            # to remove.
                            prev_hash = entry_hash
                            seqs.append(seq)

                        try:
                            # Once, with the batch's highest seq. The mark only ever
                            # grows (the table's own trigger enforces it), so bumping
                            # to the last is bumping past every one before it.
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
        except _UNREADABLE as exc:
            # The shared rule -- see _UNREADABLE -- resolved in the writer's
            # direction: refuse, typed. The two readers already answered a
            # database they cannot read with this error; `emit` let the raw
            # `sqlite3.DatabaseError` reach the ASGI layer, which is a bare 500.
            #
            # It stays a raise. `_watermark` above degrades because a lost
            # high-water mark still leaves a log that can be appended to, and a
            # writer that fails closed on that silences the pipeline. A tail this
            # method cannot read is the other case: there is no chain to extend,
            # so the alternative to raising is releasing a run with no record of
            # it -- which
            # `test_no_release_survives_an_audit_write_that_failed_before_it`
            # exists to forbid.
            #
            # ``operation="emit"`` for a batch too, and that is the answer rather
            # than an oversight: this string is written into an HTTP body, where its
            # job is to tell an operator that the audit *write* refused the run.
            # Whether the writer was holding one row or five hundred is not a fact
            # the client can act on, and splitting it would give the API two codes
            # for one failure.
            raise self._unreadable(exc, operation="emit") from exc

        # Token IDs and counts only -- never a value, never the detail payload's
        # provenance beyond its key count. One line per row, batched or not: this is
        # the operator-facing record of what was written, and thinning it for a batch
        # would make the log stream depend on how the caller happened to group its
        # writes.
        for (event, detail, _json), seq in zip(prepared, seqs, strict=True):
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
        return seqs

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

        A database this method cannot read raises
        :class:`~secure_context_pipeline.errors.AuditUnavailableError` (which is a
        :class:`PipelineError` carrying ``reason="audit_log_unreadable"``, as it did
        before it had a code of its own) rather than letting a raw
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
            raise self._unreadable(exc, operation="query") from exc
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

        **Erasure by relabelling is a residual of that split, and is not closed.** An
        ``UPDATE`` against the events table that rewrites ``session_id`` from ``X`` to
        ``Y`` erases X's history exactly as a ``DELETE`` of those rows does, and unlike
        a ``DELETE`` it moves nothing: every link and every ``seq`` still holds, so the
        structural checks have nothing to report. The relabelled rows do fail their own
        ``entry_hash``
        (``session_id`` is inside the hashed payload), and both checks that can see
        that report it -- the unscoped walk returns ``False``, and so does
        ``verify_chain("Y")``, the scope the rows were moved into. What returns
        ``True`` is ``verify_chain("X")``, and the reason is not an oversight in the
        rule above but an absence of information. A relabelled row is, column for
        column, a row whose stored ``session_id`` names some other session and whose
        hash does not recompute -- the *identical* input class as an ordinary
        tampered row that genuinely belongs to that other session, which the content
        rule deliberately does not charge against an unrelated scope. The pre-tamper
        ``session_id`` is inside the digest the tamper invalidated, so nothing in the
        walk can recover it, and no rule can separate the two cases. Failing every
        scope on any unattributable hash break would close this and would also make
        one session's edited ``detail`` fail every other session -- a different
        design, not a fix, and the opposite of what the content bullet argues for.

        So the honest reading of the scoped form is "the rows *labelled* with this
        session are intact, and the log they sit in is structurally whole" -- never
        "no record of this session has been taken out of it". That second question
        has one answer here and it is the unscoped one. Pinned by
        ``test_relabelling_a_session_out_of_itself_is_a_known_residual`` and
        ``test_a_partial_relabel_is_invisible_to_the_scope_it_left`` -- the second
        because it rules out the tempting narrow fix: an empty in-scope slice is
        *not* the signal, since moving two of a session's three rows leaves the
        third behind and the scope still answers ``True``.

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
        :class:`~secure_context_pipeline.errors.AuditUnavailableError` rather than a
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
            raise self._unreadable(exc, operation="length") from exc


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
    """Re-check the model's ``detail`` contract at the write boundary, where it is enforceable.

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

    **The whole contract, not only the ceilings.** What ``model_construct`` skips is
    the model, so re-checking only the ceilings leaves the type rule -- ``detail`` is
    ``Mapping[str, int | float | str]`` -- unenforced on the one path that needs it.
    See the comments below: a nested dict, a list, or a ``None`` has a short rendered
    width, passed a width-only check, and reached the INSERT, after which
    :func:`_load_detail` refused the stored column and :meth:`AuditLogger.verify_chain`
    reported the log as tampered forever. Every refusal here is a typed
    :class:`PipelineError` and leaves the chain untouched; see
    ``test_a_refused_event_does_not_disturb_the_chain``.
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
        # TYPE BEFORE WIDTH, and the order is the fix rather than a tidy-up.
        #
        # `model_construct` skips the *whole* model, not just the ceilings, and this
        # function used to re-enforce only the half of the contract that is about
        # length. `AuditEvent.detail` is typed `Mapping[str, int | float | str]`, so
        # the type rule is as much a part of the contract as the 64-character one --
        # and a container value slipped past a width-only check because its rendered
        # width is tiny: `detail={"k": {"a": 1}}` is 13 characters of JSON. It was
        # accepted, chained, and INSERTed, and then `_load_detail` refused the stored
        # column as "not a detail map" on every later read -- so `verify_chain()`
        # returned `False` *permanently*, on a row this module wrote itself, while
        # `query()` handed the row back with `detail={}` and said nothing. A write
        # boundary that admits a value the reader cannot parse does not fail closed;
        # it manufactures the tamper evidence it exists to report. `None` had the
        # same shape (`str(None)` is 4 chars, `null` is not a detail value).
        if not isinstance(key, str):
            raise PipelineError(
                reason="audit_detail_key_not_a_string", key_type=type(key).__name__
            )
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
        if not isinstance(detail_value, int | float | str):
            raise PipelineError(
                reason="audit_detail_value_not_scalar",
                field=key[:MAX_DETAIL_VALUE_LEN],
                value_type=type(detail_value).__name__,
            )
        # Rendered width, every type -- see `AuditEvent._reject_long_values`. This is
        # the write boundary, reachable with an event built by `model_construct`,
        # which skips the model validator entirely; a ceiling enforced in only one of
        # the two places is a ceiling the other path does not have.
        try:
            rendered_len = len(str(detail_value))
        except ValueError:
            # An integer too large for Python to render *at all*: `str()` refuses
            # past `sys.get_int_max_str_digits()` (4,300 by default) and raises
            # `ValueError`, which escaped this function raw. That is the same
            # document-encoded-as-an-integer shape the ceiling exists for, only
            # larger than the 3,709-digit fixture
            # `test_a_document_encoded_as_an_integer_is_refused_at_the_write_boundary`
            # uses -- so the bigger document got a bare interpreter error where the
            # smaller one got the documented `PipelineError`. Refusing past the
            # interpreter's own rendering limit is a fortiori refusing past 64
            # characters, so it is the same `reason`. The exact width is unknowable
            # without raising a global interpreter limit, so the floor is reported
            # rather than a guess.
            raise PipelineError(
                reason="audit_detail_exceeds_ceiling",
                field=key[:MAX_DETAIL_VALUE_LEN],
                min_length=sys.get_int_max_str_digits(),
            ) from None
        if rendered_len > MAX_DETAIL_VALUE_LEN:
            raise PipelineError(
                reason="audit_detail_exceeds_ceiling",
                field=key[:MAX_DETAIL_VALUE_LEN],
                length=rendered_len,
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
