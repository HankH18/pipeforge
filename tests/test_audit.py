"""Audit log tests (build doc sections 9.8, 10).

Covers the four properties the audit trail is graded on: round-trip fidelity,
chain verification, tamper detection, and queryability -- plus the concurrency
guarantee (50 racing emits still produce one linear, verifiable chain) and the
schema-level refusal to carry content.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path

import aiosqlite
import pytest
from pydantic import ValidationError

from secure_context_pipeline.audit.logger import (
    DEOBFUSCATE,
    DETECT,
    EGRESS_PASS,
    EVENT_TYPES,
    GENESIS_HASH,
    LLM_CALL,
    OBFUSCATE,
    SESSION_CREATE,
    VAULT_MISS,
    AuditLogger,
    canonical_json,
    chain_payload,
    compute_entry_hash,
)
from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.models import (
    MAX_AUDIT_LABEL_LEN,
    MAX_DETAIL_VALUE_LEN,
    AuditEvent,
)


@pytest.fixture
async def audit(tmp_path: Path) -> AsyncIterator[AuditLogger]:
    log = await AuditLogger.open(tmp_path / "audit.db")
    try:
        yield log
    finally:
        await log.close()


def make_event(
    *,
    ts: float | None = None,
    session_id: str = "sess-1",
    run_id: str | None = "run-1",
    event_type: str = DETECT,
    entity_type: str | None = "PHI_NAME",
    token_id: str | None = "1a2b3c4d",
    detail: dict[str, int | float | str] | None = None,
) -> AuditEvent:
    return AuditEvent(
        ts=time.time() if ts is None else ts,
        session_id=session_id,
        run_id=run_id,
        event_type=event_type,
        entity_type=entity_type,
        token_id=token_id,
        detail={"count": 3, "elapsed_ms": 12.5} if detail is None else detail,
    )


async def tamper_detail(db_path: Path, seq: int, new_detail: str) -> None:
    """Rewrite one row's ``detail`` behind the logger's back, as an attacker would."""
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("UPDATE audit_events SET detail = ? WHERE seq = ?", (new_detail, seq))
        await conn.commit()


# --------------------------------------------------------------------------
# 1. Round trip
# --------------------------------------------------------------------------


async def test_emit_and_query_round_trip(audit: AuditLogger) -> None:
    originals = [
        make_event(
            ts=1000.0 + i,
            event_type=event_type,
            token_id=f"{i:08x}",
            detail={"count": i, "elapsed_ms": i / 4, "code": "ok"},
        )
        for i, event_type in enumerate([SESSION_CREATE, DETECT, OBFUSCATE, LLM_CALL, DEOBFUSCATE])
    ]

    seqs = [await audit.emit(event) for event in originals]
    assert seqs == [1, 2, 3, 4, 5]

    stored = await audit.query(session_id="sess-1")
    assert len(stored) == len(originals)

    for original, row, seq in zip(originals, stored, seqs, strict=True):
        assert row.seq == seq
        assert row.ts == original.ts
        assert row.session_id == original.session_id
        assert row.run_id == original.run_id
        assert row.event_type == original.event_type
        assert row.entity_type == original.entity_type
        assert row.token_id == original.token_id
        assert row.detail == original.detail
        assert row.entry_hash is not None
        assert len(row.entry_hash) == 64

    # The chain is linear and starts from the genesis hash.
    assert stored[0].prev_hash == GENESIS_HASH
    for previous, current in itertools.pairwise(stored):
        assert current.prev_hash == previous.entry_hash

    assert await audit.length() == 5


async def test_emit_does_not_mutate_the_caller_event(audit: AuditLogger) -> None:
    event = make_event()
    await audit.emit(event)
    assert event.seq is None
    assert event.entry_hash is None


async def test_nullable_columns_round_trip(audit: AuditLogger) -> None:
    await audit.emit(
        make_event(run_id=None, entity_type=None, token_id=None, detail={}),
    )
    (row,) = await audit.query()
    assert row.run_id is None
    assert row.entity_type is None
    assert row.token_id is None
    assert row.detail == {}
    assert await audit.verify_chain() is True


async def test_all_spec_event_types_are_accepted(audit: AuditLogger) -> None:
    assert len(EVENT_TYPES) == 12
    for event_type in sorted(EVENT_TYPES):
        await audit.emit(make_event(event_type=event_type))
    assert len(await audit.query()) == 12
    assert await audit.verify_chain() is True


# --------------------------------------------------------------------------
# 2. Chain verifies
# --------------------------------------------------------------------------


async def test_verify_chain_on_empty_log(audit: AuditLogger) -> None:
    assert await audit.verify_chain() is True


async def test_verify_chain_after_normal_sequence(audit: AuditLogger) -> None:
    for i, event_type in enumerate([SESSION_CREATE, DETECT, OBFUSCATE, EGRESS_PASS, LLM_CALL]):
        await audit.emit(make_event(ts=2000.0 + i, event_type=event_type))
    assert await audit.verify_chain() is True
    assert await audit.verify_chain(session_id="sess-1") is True
    assert await audit.verify_chain(session_id="no-such-session") is True


async def test_chain_survives_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    first = await AuditLogger.open(db_path)
    await first.emit(make_event())
    await first.emit(make_event(event_type=OBFUSCATE))
    await first.close()

    async with await AuditLogger.open(db_path) as second:
        seq = await second.emit(make_event(event_type=LLM_CALL))
        assert seq == 3
        assert await second.verify_chain() is True
        rows = await second.query()
        assert rows[2].prev_hash == rows[1].entry_hash


# --------------------------------------------------------------------------
# 3. Tamper detection
# --------------------------------------------------------------------------


async def test_tampered_detail_breaks_the_chain(audit: AuditLogger, tmp_path: Path) -> None:
    for i in range(4):
        await audit.emit(make_event(ts=3000.0 + i, detail={"count": i}))
    assert await audit.verify_chain() is True

    await tamper_detail(tmp_path / "audit.db", seq=2, new_detail=json.dumps({"count": 999}))

    assert await audit.verify_chain() is False
    assert await audit.verify_chain(session_id="sess-1") is False


async def test_tampered_detail_that_is_not_json_breaks_the_chain(
    audit: AuditLogger, tmp_path: Path
) -> None:
    await audit.emit(make_event())
    await tamper_detail(tmp_path / "audit.db", seq=1, new_detail="not json at all")
    assert await audit.verify_chain() is False


async def test_tamper_is_scoped_to_the_affected_session(
    audit: AuditLogger, tmp_path: Path
) -> None:
    await audit.emit(make_event(session_id="sess-a"))
    await audit.emit(make_event(session_id="sess-b"))
    await audit.emit(make_event(session_id="sess-a"))

    await tamper_detail(tmp_path / "audit.db", seq=2, new_detail=json.dumps({"count": -1}))

    assert await audit.verify_chain() is False
    assert await audit.verify_chain(session_id="sess-b") is False
    # sess-a's own rows are still internally consistent and still linked.
    assert await audit.verify_chain(session_id="sess-a") is True


async def test_deleted_row_breaks_the_chain(audit: AuditLogger, tmp_path: Path) -> None:
    for _ in range(3):
        await audit.emit(make_event())
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("DELETE FROM audit_events WHERE seq = 2")
        await conn.commit()
    assert await audit.verify_chain() is False


async def test_truncating_the_tail_breaks_the_chain(audit: AuditLogger, tmp_path: Path) -> None:
    """Deleting the newest rows is the obvious attack, and it leaves no gap.

    Every surviving row still hashes correctly and still links to its predecessor,
    so a walk of the chain alone reports a perfectly intact log -- which is exactly
    what an attacker who wants the last few events gone would rely on. SQLite's
    ``AUTOINCREMENT`` high-water mark is not rolled back by ``DELETE``, so the
    missing tail is still visible.
    """
    for i in range(5):
        await audit.emit(make_event(ts=6000.0 + i))
    assert await audit.verify_chain() is True

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("DELETE FROM audit_events WHERE seq >= 4")
        await conn.commit()

    assert await audit.verify_chain() is False
    assert await audit.verify_chain(session_id="sess-1") is False
    assert await audit.length() == 3


async def test_erasing_a_whole_session_is_not_reported_as_that_session_being_clean(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """The scoped check must not confuse "nothing wrong here" with "nothing here".

    Deleting every row belonging to a session leaves no in-scope row left to fail a
    content check, so a purely scoped walk answered ``True`` for the very session
    that had just been erased. Link continuity is therefore verified globally: the
    hole is visible from any scope, including the victim's.
    """
    await audit.emit(make_event(session_id="sess-keep"))
    await audit.emit(make_event(session_id="sess-victim"))
    await audit.emit(make_event(session_id="sess-victim"))
    await audit.emit(make_event(session_id="sess-keep"))

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("DELETE FROM audit_events WHERE session_id = 'sess-victim'")
        await conn.commit()

    assert await audit.verify_chain() is False
    assert await audit.verify_chain(session_id="sess-victim") is False
    assert await audit.verify_chain(session_id="sess-keep") is False


async def test_verify_chain_recomputes_rather_than_trusting_the_stored_hash(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """A self-consistent forgery must still fail.

    Here the attacker rewrites ``detail`` *and* the row's own ``entry_hash`` so the
    row vouches for itself, but does not fix the successor's ``prev_hash``. A
    verifier that read ``entry_hash`` back and believed it would pass this; one that
    recomputes from the persisted columns does not.
    """
    for i in range(3):
        await audit.emit(make_event(ts=7000.0 + i, detail={"count": i}))

    rows = await audit.query()
    forged_detail = json.dumps({"count": 999})
    payload = chain_payload(
        seq=2,
        ts=rows[1].ts,
        session_id=rows[1].session_id,
        run_id=rows[1].run_id,
        event_type=rows[1].event_type,
        entity_type=rows[1].entity_type,
        token_id=rows[1].token_id,
        detail=json.loads(forged_detail),
    )
    forged_hash = compute_entry_hash(rows[0].entry_hash or "", payload)

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute(
            "UPDATE audit_events SET detail = ?, entry_hash = ? WHERE seq = 2",
            (forged_detail, forged_hash),
        )
        await conn.commit()

    assert await audit.verify_chain() is False


async def test_an_inserted_row_breaks_the_chain(audit: AuditLogger, tmp_path: Path) -> None:
    """Appending a fabricated event past the end must not verify."""
    for _ in range(2):
        await audit.emit(make_event())
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute(
            "INSERT INTO audit_events"
            " (seq, ts, session_id, run_id, event_type, detail, prev_hash, entry_hash)"
            " VALUES (99, 1.0, 'sess-1', 'run-1', ?, '{}', 'nope', 'also-nope')",
            (DETECT,),
        )
        await conn.commit()
    assert await audit.verify_chain() is False


async def test_reordering_two_rows_breaks_the_chain(audit: AuditLogger, tmp_path: Path) -> None:
    """Swapping the sequence numbers of two events must not verify."""
    for i in range(3):
        await audit.emit(make_event(ts=8000.0 + i, detail={"count": i}))
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("UPDATE audit_events SET seq = 90 WHERE seq = 2")
        await conn.execute("UPDATE audit_events SET seq = 2 WHERE seq = 3")
        await conn.execute("UPDATE audit_events SET seq = 3 WHERE seq = 90")
        await conn.commit()
    assert await audit.verify_chain() is False


# --------------------------------------------------------------------------
# 4. Query filters
# --------------------------------------------------------------------------


@pytest.fixture
async def populated(audit: AuditLogger) -> AuditLogger:
    await audit.emit(
        make_event(ts=100.0, session_id="sess-a", run_id="run-a", event_type=SESSION_CREATE)
    )
    await audit.emit(make_event(ts=200.0, session_id="sess-a", run_id="run-a", event_type=DETECT))
    await audit.emit(make_event(ts=300.0, session_id="sess-a", run_id="run-b", event_type=DETECT))
    await audit.emit(
        make_event(ts=400.0, session_id="sess-b", run_id="run-c", event_type=VAULT_MISS)
    )
    return audit


async def test_query_filter_by_session_id(populated: AuditLogger) -> None:
    assert [e.seq for e in await populated.query(session_id="sess-a")] == [1, 2, 3]
    assert [e.seq for e in await populated.query(session_id="sess-b")] == [4]
    assert await populated.query(session_id="nobody") == []


async def test_query_filter_by_run_id(populated: AuditLogger) -> None:
    assert [e.seq for e in await populated.query(run_id="run-a")] == [1, 2]
    assert [e.seq for e in await populated.query(run_id="run-b")] == [3]


async def test_query_filter_by_event_type(populated: AuditLogger) -> None:
    assert [e.seq for e in await populated.query(event_type=DETECT)] == [2, 3]
    assert [e.seq for e in await populated.query(event_type=SESSION_CREATE)] == [1]


async def test_query_filter_by_time_range(populated: AuditLogger) -> None:
    assert [e.seq for e in await populated.query(since=200.0)] == [2, 3, 4]
    assert [e.seq for e in await populated.query(until=200.0)] == [1, 2]
    assert [e.seq for e in await populated.query(since=150.0, until=350.0)] == [2, 3]
    assert await populated.query(since=1000.0) == []


async def test_query_filters_combine(populated: AuditLogger) -> None:
    found = await populated.query(session_id="sess-a", run_id="run-a", event_type=DETECT)
    assert [e.seq for e in found] == [2]


async def test_query_pagination(populated: AuditLogger) -> None:
    assert [e.seq for e in await populated.query(limit=2)] == [1, 2]
    assert [e.seq for e in await populated.query(limit=2, offset=2)] == [3, 4]
    assert await populated.query(limit=2, offset=99) == []


async def test_query_rejects_bad_pagination(populated: AuditLogger) -> None:
    with pytest.raises(PipelineError):
        await populated.query(limit=0)
    with pytest.raises(PipelineError):
        await populated.query(offset=-1)


async def test_length_filters_by_session(populated: AuditLogger) -> None:
    assert await populated.length() == 4
    assert await populated.length(session_id="sess-a") == 3


@pytest.mark.parametrize(
    "filters",
    [
        {},
        {"session_id": "sess-a"},
        {"session_id": "sess-b"},
        {"run_id": "run-a"},
        {"event_type": DETECT},
        {"since": 200.0},
        {"until": 200.0},
        {"since": 150.0, "until": 350.0},
        {"session_id": "sess-a", "run_id": "run-a", "event_type": DETECT},
        {"session_id": "nobody"},
    ],
)
async def test_length_counts_exactly_what_query_returns(
    populated: AuditLogger, filters: dict[str, object]
) -> None:
    """``length`` and ``query`` must select the same rows, filter for filter.

    The two carry the predicate separately, so this is the only thing stopping them
    drifting -- and a count that disagrees with the query it is meant to describe is
    worse than no count, because it is a completeness signal that lies.
    """
    counted = await populated.length(**filters)  # type: ignore[arg-type]
    returned = await populated.query(**filters)  # type: ignore[arg-type]
    assert counted == len(returned)


# --------------------------------------------------------------------------
# 4b. The Q5 auditor story: "what happened over the last 30 days"
# --------------------------------------------------------------------------


async def test_a_thirty_day_range_query_returns_the_window_and_only_the_window(
    audit: AuditLogger,
) -> None:
    """The literal query README section 5 Q5 promises an auditor can run.

    A range query is only useful if the boundary is exact in both directions, so
    events either side of the 30-day mark are placed deliberately: one 31 days old
    (out), one exactly 30 days old (in -- ``since`` is inclusive), and one in the
    future relative to ``until``.
    """
    now = 1_700_000_000.0
    day = 86_400.0
    ages = {"d45": 45.0, "d31": 31.0, "d30": 30.0, "d15": 15.0, "d1": 1.0, "d0": 0.0}
    for label, age in ages.items():
        await audit.emit(
            make_event(ts=now - age * day, session_id=f"sess-{label}", event_type=EGRESS_PASS)
        )

    since = now - 30.0 * day
    window = await audit.query(since=since, until=now)

    assert [e.session_id for e in window] == [
        "sess-d30",
        "sess-d15",
        "sess-d1",
        "sess-d0",
    ], "the 30-day boundary is not inclusive-exact"
    assert await audit.length(since=since, until=now) == len(window)
    assert await audit.length() == len(ages)
    # ...and the window really is a filter, not the whole log.
    assert await audit.length(since=since, until=now) < await audit.length()


async def test_a_full_page_is_distinguishable_from_a_complete_answer(
    audit: AuditLogger,
) -> None:
    """A 30-day sweep must not be able to look complete when it was truncated.

    ``query`` pages and defaults to ``limit=1000``. A reviewer who runs the range
    query and gets a full page back has no way to tell "that is everything" from
    "that is the first 1000 of many" -- and silently answering a compliance question
    with a prefix is the failure mode this pair of calls exists to prevent.
    """
    now = 1_700_000_000.0
    since = now - 30.0 * 86_400.0
    for i in range(7):
        await audit.emit(make_event(ts=since + float(i), session_id="sess-window"))

    page = await audit.query(since=since, limit=3)
    total = await audit.length(since=since)
    assert len(page) == 3
    assert total == 7
    assert len(page) < total, "a truncated page is indistinguishable from a complete one"

    collected: list[int] = []
    offset = 0
    while True:
        chunk = await audit.query(since=since, limit=3, offset=offset)
        collected.extend(e.seq for e in chunk if e.seq is not None)
        if len(chunk) < 3:
            break
        offset += 3
    assert len(collected) == total
    assert collected == sorted(collected)


async def test_the_audit_log_has_no_unscoped_range_count_that_disagrees_with_verify(
    audit: AuditLogger,
) -> None:
    """``verify_chain`` answers about the whole log; ``length`` can answer about a slice.

    Worth pinning because the two are reported together by ``GET /audit/verify`` and
    an auditor will read them as one statement. The chain check is deliberately
    *not* range-scoped -- integrity is a property of the whole chain, and a "valid"
    for a 30-day slice of a tampered log would be exactly the wrong answer.
    """
    now = 1_700_000_000.0
    for age in (45.0, 5.0):
        await audit.emit(make_event(ts=now - age * 86_400.0))

    assert await audit.verify_chain() is True
    assert await audit.length() == 2
    assert await audit.length(since=now - 30.0 * 86_400.0) == 1


# --------------------------------------------------------------------------
# 5. Concurrency
# --------------------------------------------------------------------------


async def test_fifty_concurrent_emits_keep_the_chain_linear(audit: AuditLogger) -> None:
    events = [
        make_event(
            ts=5000.0 + i,
            session_id=f"sess-{i % 3}",
            run_id=f"run-{i % 5}",
            event_type=LLM_CALL,
            token_id=f"{i:08x}",
            detail={"i": i},
        )
        for i in range(50)
    ]

    seqs = await asyncio.gather(*(audit.emit(event) for event in events))

    assert sorted(seqs) == list(range(1, 51))
    assert len(set(seqs)) == 50
    assert await audit.verify_chain() is True

    rows = await audit.query(limit=100)
    assert len(rows) == 50
    expected_prev = GENESIS_HASH
    for row in rows:
        assert row.prev_hash == expected_prev
        expected_prev = row.entry_hash

    # Every emitted event landed exactly once, none clobbered by a racing write.
    assert {int(row.detail["i"]) for row in rows} == set(range(50))
    for session_id in ("sess-0", "sess-1", "sess-2"):
        assert await audit.verify_chain(session_id=session_id) is True


# --------------------------------------------------------------------------
# 6. Schema refuses to carry content
# --------------------------------------------------------------------------


async def test_detail_rejects_long_string_values() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            ts=1.0,
            session_id="sess-1",
            event_type=DETECT,
            detail={"leaked": "x" * (MAX_DETAIL_VALUE_LEN + 1)},
        )


async def test_detail_accepts_short_machine_codes() -> None:
    event = AuditEvent(
        ts=1.0,
        session_id="sess-1",
        event_type=DETECT,
        detail={"reason": "x" * MAX_DETAIL_VALUE_LEN, "count": 2, "elapsed_ms": 0.5},
    )
    assert event.detail["count"] == 2


async def test_persisted_rows_carry_no_free_text_columns(audit: AuditLogger) -> None:
    """The table has no column an original value could hide in."""
    await audit.emit(make_event())
    async with aiosqlite.connect(audit.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute("PRAGMA table_info(audit_events)") as cursor:
            columns = {str(row["name"]) async for row in cursor}
    assert columns == {
        "seq",
        "ts",
        "session_id",
        "run_id",
        "event_type",
        "entity_type",
        "token_id",
        "detail",
        "prev_hash",
        "entry_hash",
    }


@pytest.mark.parametrize("field", ["session_id", "run_id", "event_type", "entity_type", "token_id"])
async def test_emit_refuses_a_content_sized_label_column(
    audit: AuditLogger, field: str
) -> None:
    """The size ceiling has to hold at the write boundary, not only at construction.

    ``AuditEvent`` is now frozen, which closes the post-construction *assignment*
    route this test originally exercised. It does not close the general problem:
    ``model_construct()`` skips validation entirely by design, and it is the normal
    path for rebuilding a model from already-trusted data -- deserialisation, a
    cache, a queue. ``entity_type`` and ``token_id`` are written from values parsed
    out of untrusted LLM output, so the value that reaches SQLite must be checked
    where it is written, not only where it was first built.
    """
    oversized = "x" * (MAX_AUDIT_LABEL_LEN + 1)
    event = AuditEvent.model_construct(**{**make_event().model_dump(), field: oversized})

    with pytest.raises(PipelineError):
        await audit.emit(event)
    assert await audit.length() == 0


async def test_emit_refuses_a_detail_value_mutated_past_the_ceiling(
    audit: AuditLogger,
) -> None:
    """``detail`` must be bounded where it is WRITTEN, not only where it was built.

    The in-place mutation this test used to perform is now impossible: ``detail`` is
    stored as a read-only mapping over a copy of the caller's dict. ``model_construct``
    still skips validation entirely, which is the path that keeps this check earning
    its place -- deserialisation and cache rehydration both take it.
    """
    event = AuditEvent.model_construct(
        **{
            **make_event().model_dump(),
            "detail": {"reason": "x" * (MAX_DETAIL_VALUE_LEN + 1)},
        }
    )

    with pytest.raises(PipelineError):
        await audit.emit(event)
    assert await audit.length() == 0


async def test_a_refused_event_does_not_disturb_the_chain(audit: AuditLogger) -> None:
    """A rejected write must leave no gap and no half-extended chain behind it."""
    await audit.emit(make_event())
    bad = AuditEvent.model_construct(
        **{**make_event().model_dump(), "entity_type": "y" * (MAX_AUDIT_LABEL_LEN + 1)}
    )
    with pytest.raises(PipelineError):
        await audit.emit(bad)

    assert await audit.emit(make_event()) == 2
    assert await audit.verify_chain() is True


async def test_canonical_json_is_deterministic_and_parseable() -> None:
    """Byte-stability and validity: a third party must be able to recompute this.

    Key order must not depend on insertion order, non-ASCII must be escaped the same
    way every time, and the result must round-trip through a conforming JSON parser
    -- publishing the hash formula is pointless if only this process can evaluate it.
    """
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert canonical_json({"k": "José"}) == '{"k":"Jos\\u00e9"}'
    assert json.loads(canonical_json({"k": 0.1 + 0.2, "j": -1, "i": "s"}))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
async def test_canonical_json_refuses_non_finite_floats(bad: float) -> None:
    """``NaN``/``Infinity`` are Python's JSON extension, not JSON.

    Left enabled, a non-finite latency would be hashed into the chain as a token no
    conforming parser accepts -- the record would verify here and be unverifiable
    anywhere else, which is the opposite of tamper evidence.
    """
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_json({"elapsed_ms": bad})


# --------------------------------------------------------------------------
# 6b. The model-level guards, pinned. Each of these closes a route by which a
#     value could reach the INSERT, and none of them had a test before.
# --------------------------------------------------------------------------


async def test_audit_event_is_frozen_and_its_detail_is_read_only() -> None:
    """The two post-construction escapes, closed in the model and pinned here.

    ``AuditEvent`` validates its ceilings at construction. On a mutable model that
    guards nothing, because pydantic does not re-validate on assignment and a plain
    ``dict`` can be mutated through the reference the caller still holds::

        event.entity_type = original       # assignment
        event.detail["value"] = original   # in-place

    Both reached SQLite untouched. ``frozen=True`` and a ``MappingProxyType`` over a
    *copy* close them, and until this test existed, deleting either one broke
    nothing in the suite -- the write-boundary check in ``emit`` uses
    ``model_construct``, so it passes with or without the model guards. A fix with
    no test that goes red for it is a fix waiting to be reverted.
    """
    event = make_event()

    with pytest.raises(ValidationError):
        event.entity_type = "reassigned"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        event.detail = {"count": 1}  # type: ignore[misc]

    # In-place mutation of the detail mapping.
    with pytest.raises(TypeError):
        event.detail["leaked"] = "Marguerite Vandenberg"  # type: ignore[index]

    # And the caller's own dict is not a back door into the event.
    supplied: dict[str, int | float | str] = {"count": 1}
    built = AuditEvent(ts=1.0, session_id="s", event_type=DETECT, detail=supplied)
    supplied["leaked"] = "Marguerite Vandenberg"
    assert "leaked" not in built.detail, (
        "detail must be a copy; the caller kept a reference and reached through it"
    )

    # It still serializes as a plain object, so the wire format is unchanged.
    assert built.model_dump()["detail"] == {"count": 1}


async def test_the_schema_bounds_a_value_but_does_not_forbid_a_short_one(
    audit: AuditLogger,
) -> None:
    """What "no originals in the audit log" actually rests on -- stated exactly.

    It is tempting to write, and this project's own docs did write, that the schema
    "has no field capable of holding an original value". That is **not true**, and a
    reviewer will find it in one line: ``detail`` accepts any string up to 64
    characters and the label columns up to 128, so ``"John Smith"``, ``"MRN
    4823910"``, an SSN, a phone number and an e-mail address all fit comfortably.

    What the ceilings actually buy is that the log cannot hold *content* -- a
    paragraph, a document, a free-text note -- which is the bulk-exfiltration shape.
    The guarantee against a short identifier is different in kind and is worth
    naming precisely, because it is the one a reviewer should probe:

    1. **No code path writes one.** Every ``emit`` call site passes counts,
       latencies, hashes, entity *type* names and 8-hex token IDs.
    2. **It is measured, not asserted.** The leakage harness scans the raw SQLite
       file -- bytes, not the query API -- against every vaulted original, on all
       100 runs.

    This test pins the honest version so the overclaim cannot come back.
    """
    for value in ("John Smith", "MRN 4823910", "900-12-3456", "ada@example.com"):
        accepted = AuditEvent(
            ts=1.0, session_id="sess-1", event_type=DETECT, detail={"v": value}
        )
        assert accepted.detail["v"] == value, (
            "the schema does bound length, but it does not and cannot recognise an "
            "original -- the guarantee is that nothing writes one, not that this "
            "would be refused"
        )

    # The bound that IS real: content-sized values are refused, at the model...
    with pytest.raises(ValidationError):
        AuditEvent(
            ts=1.0,
            session_id="sess-1",
            event_type=DETECT,
            detail={"v": "x" * (MAX_DETAIL_VALUE_LEN + 1)},
        )
    # ...and again at the write boundary, which is the one that cannot be skipped.
    with pytest.raises(PipelineError):
        await audit.emit(
            AuditEvent.model_construct(
                **{**make_event().model_dump(), "detail": {"v": "x" * 5_000}}
            )
        )
    assert await audit.length() == 0


async def test_the_logger_exposes_no_update_or_delete_path(audit: AuditLogger) -> None:
    """Append-only is a property of the API surface, and that is worth pinning.

    There is no SQLite trigger enforcing append-only -- the log is a plain table, and
    anyone with the file can rewrite it (that is the documented tamper-*evidence*
    boundary). What this class guarantees is narrower and still load-bearing: no
    caller holding an ``AuditLogger`` can amend history through it, because there is
    no method that emits ``UPDATE`` or ``DELETE``. A convenience ``purge_session``
    added later for GDPR reasons would silently retire that property, so it is
    asserted rather than assumed.
    """
    import inspect

    source = inspect.getsource(AuditLogger)
    upper = source.upper()
    for forbidden in ("UPDATE AUDIT_EVENTS", "DELETE FROM", "DROP TABLE", "TRUNCATE TABLE"):
        assert forbidden not in upper, (
            f"AuditLogger now contains {forbidden!r}; the log is no longer append-only "
            "through its own API"
        )

    public = {
        name
        for name, _ in inspect.getmembers(AuditLogger, callable)
        if not name.startswith("_")
    }
    assert public == {"close", "emit", "length", "open", "query", "verify_chain"}, (
        f"the AuditLogger surface changed to {sorted(public)} -- if a mutation method "
        "was added, the append-only claim in the README must change with it"
    )


# --------------------------------------------------------------------------
# 6c. Attacks on verify_chain beyond the ones above.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("session_id", "attacker"),
        ("run_id", "other-run"),
        ("event_type", OBFUSCATE),
        ("entity_type", "SSN"),
        ("token_id", "deadbeef"),
        ("ts", 0.0),
    ],
)
async def test_an_in_place_update_of_any_persisted_column_breaks_the_chain(
    audit: AuditLogger, tmp_path: Path, column: str, value: object
) -> None:
    """Every column that feeds ``chain_payload`` must be covered by the digest.

    ``detail`` was the only one with a tamper test, and it is the obvious one. The
    interesting rewrites for an attacker are the *other* columns -- moving an event
    to a different session, relabelling an ``EGRESS_BLOCK`` as an ``EGRESS_PASS``,
    or backdating a ``ts`` to drop a row out of a 30-day compliance window. A field
    omitted from ``chain_payload`` would be freely editable and the chain would keep
    verifying, which is a hole no amount of hash strength compensates for.
    """
    for i in range(4):
        await audit.emit(make_event(ts=9000.0 + i, detail={"count": i}))
    assert await audit.verify_chain() is True

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute(
            f"UPDATE audit_events SET {column} = ? WHERE seq = 2", (value,)
        )
        await conn.commit()

    assert await audit.verify_chain() is False, (
        f"{column!r} can be rewritten without breaking the chain, so it is not "
        "covered by chain_payload"
    )


async def test_replaying_an_earlier_row_at_the_tail_breaks_the_chain(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """A valid, correctly-hashed row copied to a new ``seq`` must not verify.

    Replay is the attack that a per-row signature would *not* stop: every field is
    genuine and the digest is the one this system computed. Only the link to the
    predecessor makes it detectable, which is the reason the chain exists rather
    than a per-row MAC.
    """
    for i in range(4):
        await audit.emit(make_event(ts=9100.0 + i, detail={"count": i}))

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute("SELECT * FROM audit_events WHERE seq = 2") as cursor:
            row = dict(await cursor.fetchone())  # type: ignore[arg-type]
        await conn.execute(
            "INSERT INTO audit_events (seq, ts, session_id, run_id, event_type,"
            " entity_type, token_id, detail, prev_hash, entry_hash)"
            " VALUES (5,?,?,?,?,?,?,?,?,?)",
            (
                row["ts"], row["session_id"], row["run_id"], row["event_type"],
                row["entity_type"], row["token_id"], row["detail"],
                row["prev_hash"], row["entry_hash"],
            ),
        )
        await conn.commit()

    assert await audit.verify_chain() is False


async def test_forging_a_new_genesis_row_breaks_the_chain(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """Prepending a correctly-hashed genesis and shifting everything up must fail.

    The forged row is internally perfect -- ``prev_hash`` is the real genesis value
    and ``entry_hash`` is computed with the shipped formula -- so it is only the
    *successor's* stale ``prev_hash`` that gives it away. That is the property being
    checked: the chain is verified as a walk, not as a set of self-consistent rows.
    """
    for i in range(3):
        await audit.emit(make_event(ts=9200.0 + i, detail={"count": i}))

    forged = compute_entry_hash(
        GENESIS_HASH,
        chain_payload(
            seq=1, ts=1.0, session_id="attacker", run_id=None,
            event_type=DETECT, entity_type=None, token_id=None, detail={},
        ),
    )
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        # Shift via a disjoint range: a row-by-row +1 collides with the UNIQUE seq.
        await conn.execute("UPDATE audit_events SET seq = seq + 100000")
        await conn.execute("UPDATE audit_events SET seq = seq - 99999")
        await conn.execute(
            "INSERT INTO audit_events (seq, ts, session_id, run_id, event_type,"
            " entity_type, token_id, detail, prev_hash, entry_hash)"
            " VALUES (1, 1.0, 'attacker', NULL, ?, NULL, NULL, '{}', '', ?)",
            (DETECT, forged),
        )
        await conn.commit()

    assert await audit.verify_chain() is False


async def test_deleting_every_row_is_not_reported_as_a_clean_log(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """Total erasure must not read as "nothing wrong here".

    An empty log verifies ``True`` -- correctly, on a log that was never written. The
    high-water mark is what separates that from a log that *was* written and then
    emptied, and getting this wrong means the most complete tamper possible is also
    the quietest.
    """
    for i in range(4):
        await audit.emit(make_event(ts=9300.0 + i))

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("DELETE FROM audit_events")
        await conn.commit()

    assert await audit.length() == 0
    assert await audit.verify_chain() is False


async def test_tail_truncation_is_only_caught_while_sqlite_sequence_is_intact(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """The exact edge of the truncation defence, pinned rather than glossed.

    The README credits ``sqlite_sequence`` with catching a deleted tail, and it does.
    But ``sqlite_sequence`` is an ordinary table in the same file, so an attacker who
    can run the ``DELETE`` can run one more ``UPDATE`` and the truncation becomes
    invisible. That is a *one-statement* extension of the attack, not the "rewrite
    the entire chain" effort the unkeyed-chain caveat describes, and the difference
    matters to anyone deciding how much the high-water check is worth.

    This is the honest boundary of the mechanism: it raises the cost of a silent
    truncation from one statement to two, and the real fix is an off-box anchor.
    Pinned so the README's wording stays accurate and so a future keyed or
    externally-anchored scheme has a test that changes when the property does.
    """
    for i in range(5):
        await audit.emit(make_event(ts=9400.0 + i))

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("DELETE FROM audit_events WHERE seq >= 4")
        await conn.commit()
    assert await audit.verify_chain() is False, "the high-water check must catch this"

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute(
            "UPDATE sqlite_sequence SET seq = 3 WHERE name = 'audit_events'"
        )
        await conn.commit()
    assert await audit.verify_chain() is True, (
        "if this now returns False the truncation defence got stronger -- good, and "
        "the README's 'unkeyed, so a full rewrite verifies' caveat should be revisited"
    )


async def test_verify_chain_reports_an_unreadable_database_rather_than_raising(
    audit: AuditLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read failure mid-walk resolves to ``False``, not to an exception.

    ``verify_chain`` is documented to return ``False`` rather than raise, because
    ``GET /audit/verify`` and ``demo.py --verify`` report it as data. A
    ``sqlite3.DatabaseError`` raised while walking the chain -- a file truncated
    underneath a running service, a disk I/O error, a page that fails its checksum
    -- used to propagate straight through, so the endpoint that exists to answer
    "has this log been tampered with" returned a 500 on exactly the input it exists
    to report on. ``_high_water_seq`` already degraded to "no opinion" on
    ``sqlite3.Error``; the main walk did not, and that asymmetry was the bug.

    Driven through a patched cursor rather than a corrupted file on purpose: a file
    mangled badly enough to fail the walk also fails ``AuditLogger.open`` (which
    runs ``PRAGMA journal_mode`` and the schema script), so a file-level test would
    prove something about ``open`` instead of about this method.
    """
    for i in range(4):
        await audit.emit(make_event(ts=9500.0 + i))
    assert await audit.verify_chain() is True

    conn = audit._connection()
    real_execute = conn.execute

    def failing(sql: str, *args: object, **kwargs: object) -> object:
        if "FROM audit_events" in sql and "ORDER BY seq ASC" in sql:
            raise sqlite3.DatabaseError("database disk image is malformed")
        return real_execute(sql, *args, **kwargs)

    monkeypatch.setattr(conn, "execute", failing)
    assert await audit.verify_chain() is False


async def test_verify_chain_survives_a_non_numeric_tampered_timestamp(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """A tampered row holding a non-numeric ``ts`` is a finding, not a crash.

    SQLite columns are dynamically typed, so ``ts`` -- declared ``REAL`` -- happily
    accepts the string ``'not-a-number'``. ``float(row["ts"])`` inside the walk then
    raises ``ValueError``, crashing the tamper detector by means of the very tamper
    it is looking for. Backdating or blanking a timestamp is a realistic move: it is
    how a row drops out of a 30-day compliance window.

    ``seq`` is not tested the same way because it *cannot* take this value --
    ``INTEGER PRIMARY KEY`` makes it the rowid, and SQLite rejects a non-integer
    with ``datatype mismatch``. The type system closes that one, which is worth
    knowing rather than assuming.
    """
    for i in range(3):
        await audit.emit(make_event(ts=9600.0 + i))
    assert await audit.verify_chain() is True

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("UPDATE audit_events SET ts = 'not-a-number' WHERE seq = 2")
        await conn.commit()

    assert await audit.verify_chain() is False

    # And the premise: seq really is protected by the rowid type constraint.
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        with pytest.raises(sqlite3.IntegrityError):
            await conn.execute("UPDATE audit_events SET seq = 'not-a-number' WHERE seq = 3")


async def test_operations_on_a_closed_logger_raise(tmp_path: Path) -> None:
    log = await AuditLogger.open(tmp_path / "audit.db")
    await log.emit(make_event())
    await log.close()
    await log.close()  # idempotent
    with pytest.raises(PipelineError):
        await log.query()
    with pytest.raises(PipelineError):
        await log.verify_chain()
