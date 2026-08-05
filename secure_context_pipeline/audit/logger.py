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

Concurrency: ``emit`` is safe under ``asyncio.gather``. Reading the previous
hash, computing the new one, and inserting is one critical section guarded by an
:class:`asyncio.Lock`, so the chain stays linear no matter how many coroutines
race. All I/O is ``aiosqlite`` (WAL, one connection per instance); nothing here
blocks the event loop.
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

#: ``prev_hash`` of the first row. Empty string, not NULL, so the hash input of
#: the genesis entry is as well-defined as every other entry's.
GENESIS_HASH = ""

#: What "this database is unreadable" looks like when raised from inside a row
#: walk. **One definition, used by every reader**, because this codebase has
#: already been bitten by a rule that was correct in one copy and stale in
#: another: ``_high_water_seq`` degraded on ``sqlite3.Error`` while the main
#: chain walk did not, and the asymmetry was the bug.
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
        conn = await aiosqlite.connect(self._db_path)
        try:
            conn.row_factory = aiosqlite.Row
            # WAL: concurrent readers (the API's /audit endpoints) never block the
            # single writer. NORMAL sync is the standard WAL durability trade.
            await conn.execute("PRAGMA journal_mode=WAL")
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
        """
        conn = self._connection()
        _reject_content_sized_fields(event)
        detail = dict(event.detail)
        detail_json = canonical_json(detail)

        async with self._lock:
            async with conn.execute(_LAST_ENTRY_SQL) as cursor:
                row = await cursor.fetchone()
            if row is None:
                seq = 1
                prev_hash = GENESIS_HASH
            else:
                seq = int(row["seq"]) + 1
                prev_hash = str(row["entry_hash"])

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
            await conn.commit()

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

        Finally the tail is checked against SQLite's ``sqlite_sequence`` high-water
        mark, which ``AUTOINCREMENT`` maintains and ``DELETE`` does not roll back.
        Truncating the newest rows -- the obvious move for an attacker who wants the
        incriminating events gone -- leaves the surviving chain internally perfect
        and is otherwise undetectable. Like the rest of this scheme it is tamper
        *evidence*, not tamper proofing: the digests are unkeyed, so anyone who can
        write to the file can also rewrite the whole chain (and this row). Detecting
        that needs an off-box anchor -- publishing the head hash, or an HMAC under a
        key the app host does not hold -- and is listed as production work.

        Returns ``False`` rather than raising: this is a health check, and the
        callers (``GET /audit/verify``, ``demo.py --verify``) report it as data.

        **That contract holds on a corrupt database too**, which it previously did
        not. Truncating the DB file mid-page -- a torn write, a full disk, a partial
        restore, or an attacker simply lopping bytes off the end -- made
        ``conn.execute`` raise ``sqlite3.DatabaseError`` straight through this
        method. The verifier that exists to answer "has this log been tampered
        with" therefore answered with a 500 from ``GET /audit/verify`` instead of
        ``{"valid": false}``, on an input that is *precisely* the tampering it is
        meant to report. ``_high_water_seq`` already degraded gracefully on
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

        # Outside the walk's try on purpose, so it needs its own. A high-water mark
        # that is *present but not a number* is tamper evidence, not absence: the
        # attacker who deletes the newest rows has every reason to blank this value
        # too, because it is the only thing that notices. Letting it degrade to
        # "no opinion" would hand them a clean bill of health, and letting it
        # propagate would break "returns False rather than raising" -- turning
        # GET /audit/verify into a 500 on precisely the tamper it exists to report,
        # which is the bug the walk above was already fixed for.
        try:
            high_water = await self._high_water_seq()
        except _UNREADABLE as exc:
            _log_break(last_seq, f"high_water_unreadable:{type(exc).__name__}")
            return False
        if high_water is not None and last_seq != high_water:
            valid = False
            _log_break(last_seq, "tail_truncated")

        if valid:
            logger.debug(
                "audit chain verified", extra={"session_id": session_id, "chain_ok": True}
            )
        return valid

    async def _high_water_seq(self) -> int | None:
        """Highest ``seq`` SQLite has ever handed out, or ``None`` if never written.

        ``AUTOINCREMENT`` keeps this in the ``sqlite_sequence`` table and does not
        lower it on ``DELETE``, which is exactly the property tail-truncation
        detection needs. ``None`` on a log that has never been written to (the row
        does not exist yet) and on any SQLite error, so a missing or unreadable
        bookkeeping table degrades to "no opinion" rather than a false alarm.

        **A row that exists but does not hold an integer is a different case and
        raises**, deliberately. ``sqlite_sequence`` is an ordinary writable table:
        ``UPDATE sqlite_sequence SET seq = NULL`` is accepted by SQLite, and it is
        the natural second move for an attacker who has just deleted the newest
        rows, since this mark is the only thing that notices. Folding that into the
        ``None`` above would make erasure read as cleanliness. :meth:`verify_chain`
        catches it and returns ``False``; see
        ``test_verify_chain_survives_a_tampered_high_water_mark``.
        """
        conn = self._connection()
        try:
            async with conn.execute(_HIGH_WATER_SQL) as cursor:
                row = await cursor.fetchone()
        except sqlite3.Error:
            return None
        return None if row is None else int(row["seq"])

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
