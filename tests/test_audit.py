"""Audit log tests (build doc sections 9.8, 10).

Covers the four properties the audit trail is graded on: round-trip fidelity,
chain verification, tamper detection, and queryability -- plus the concurrency
guarantee (50 racing emits still produce one linear, verifiable chain) and the
schema-level refusal to carry content.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import importlib
import itertools
import json
import logging
import re
import sqlite3
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple

import aiosqlite
import pytest
from pydantic import ValidationError
from starlette.requests import Request

import secure_context_pipeline.audit.logger as logger_module
from secure_context_pipeline.audit.logger import (
    ACTION_KEY,
    DEOBFUSCATE,
    DETECT,
    EGRESS_BLOCK,
    EGRESS_PASS,
    EVENT_ACTIONS,
    EVENT_TYPES,
    GENESIS_HASH,
    LLM_CALL,
    OBFUSCATE,
    SESSION_CREATE,
    VAULT_MISS,
    AuditLogger,
    _legacy_unkeyed_entry_hash,
    canonical_json,
    chain_payload,
    compute_entry_hash,
    default_chain_key,
)
from secure_context_pipeline.crypto.keys import _hkdf, derive_audit_chain_key
from secure_context_pipeline.errors import (
    UNREADABLE_AUDIT_REMEDY,
    AuditUnavailableError,
    ConfigError,
    PipelineError,
)
from secure_context_pipeline.models import (
    AUDIT_ACTION_KEY,
    AUDIT_ACTIONS,
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


def stolen_chain_key() -> bytes:
    """The key the fixture's logger writes under -- i.e. an attacker who has the master key.

    Several tamper tests below forge a *self-consistent* chain and assert
    ``verify_chain`` catches it anyway. Since the chain was keyed those forgeries
    need the key, and handing it over is deliberate rather than a workaround: it
    makes each of those tests strictly stronger than it was. They used to say "a
    re-chained log is caught"; they now say "a re-chained log is caught **even when
    the attacker holds the master key**", which is the only version of the claim
    that survives after the key removes the easy forgeries.

    ``default_chain_key`` reads process settings, exactly as ``AuditLogger`` does, so
    this is the same key without the logger having to expose it.
    """
    return default_chain_key()


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
        # SUPERSEDED CONTRACT. This was `row.detail == original.detail`, i.e. "the
        # writer adds nothing", and that is exactly what let one half of the round
        # trip ship without the `action` core requirement 7 names by name (measured
        # end to end: OBFUSCATE 0/8 rows, DEOBFUSCATE 8/10, DETECT/EGRESS_PASS/
        # LLM_CALL 0 of everything). The writer now stamps the event type's action
        # before the digest is taken.
        #
        # NOT loosened: still exact equality over the whole dict, and the one added
        # key is named rather than allowed for. `| ` rather than a `>=` subset check
        # deliberately -- a subset check would also pass if the writer started adding
        # anything else at all, which is the thing worth catching next time.
        assert dict(row.detail) == dict(original.detail) | {
            ACTION_KEY: EVENT_ACTIONS[original.event_type]
        }
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
    # SUPERSEDED CONTRACT -- same change as `test_emit_and_query_round_trip`, argued
    # there in full: the writer stamps `detail['action']`, so no row of a known event
    # type has an empty detail any more. What this test is *about* -- the three
    # nullable columns above surviving a round trip as NULL -- is untouched, and the
    # detail is still asserted exactly rather than merely "non-empty".
    assert dict(row.detail) == {ACTION_KEY: EVENT_ACTIONS[DETECT]}
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
    forged_hash = compute_entry_hash(rows[0].entry_hash or "", payload, key=stolen_chain_key())

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute(
            "UPDATE audit_events SET detail = ?, entry_hash = ? WHERE seq = 2",
            (forged_detail, forged_hash),
        )
        await conn.commit()

    assert await audit.verify_chain() is False


async def test_an_inserted_row_breaks_the_chain(audit: AuditLogger, tmp_path: Path) -> None:
    """A row inserted WITHOUT recomputing the chain must not verify.

    The docstring used to say "appending a fabricated event past the end must not
    verify", and that is not what this proves. The row below carries
    ``prev_hash='nope'`` and ``entry_hash='also-nope'`` -- it fails on the link
    check, on the ``seq`` continuity check and on its own content hash, three ways
    at once, none of which an attacker who has read ``compute_entry_hash`` would
    walk into. What it establishes is the real and narrower thing: an ``INSERT``
    that does not maintain the chain is caught.

    The append that *does* maintain it is a different matter and is not detectable
    here at all. See
    :func:`test_a_correctly_hashed_tail_append_is_a_known_residual` immediately
    below, which pins that as an accepted limitation rather than leaving the gap
    between the two shapes to be inferred from this test's name.
    """
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


async def test_a_correctly_hashed_tail_append_is_a_known_residual(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """A competently forged tail append verifies True **for an attacker with the key**.

    This test asserts the *opposite* of what the neighbouring tamper tests assert,
    on purpose. It is here so the boundary of the tamper-evidence claim is a fact
    the suite states rather than a sentence in the README that nothing checks.

    The forgery: read the tail row, take its ``entry_hash`` as ``prev_hash``,
    allocate ``seq = tail + 1``, and compute ``entry_hash`` with
    :func:`compute_entry_hash` **under the chain key**. Every check in
    ``verify_chain`` then passes, and none of them can do otherwise:

    * the link check passes -- ``prev_hash`` genuinely is the previous row's hash;
    * the ``seq`` continuity check passes -- the row is the next number;
    * the content MAC recomputes correctly -- the attacker computed it with our key;
    * both watermarks agree -- ``sqlite_sequence`` is bumped by the ``INSERT``
      itself, and ``audit_chain_meta``'s trigger forbids only a *decrease*.

    **The precondition is new and it is the point.** Until the chain was keyed
    (README section 7 gap 16) this forgery needed nothing but file access, because
    the digest formula was published and held no secret. It now needs
    ``SCP_MASTER_KEY`` as well, which is asserted below rather than asserted about:
    the same append computed *without* the key is rejected. So the residual is no
    longer "anyone who can write the file can append history", it is "anyone who can
    write the file **and** holds the app's master key can append history" -- the
    difference between a stolen volume and a compromised host.

    What is still true of the narrowed residual: no check inside this process can
    close it, because a row minted with our key by someone else is our key's output.
    Closing it needs an anchor outside the writer's reach -- an off-box append-only
    sink, or a MAC key the auditor holds and the application host does not. Both are
    listed in README section 5 Q5 as production work, and neither is shipped here.

    Note what this is not. Truncation, mid-chain ``INSERT``, reorder, ``UPDATE`` of
    any persisted column, replay at a new ``seq``, a forged genesis, and deleting a
    session's rows are all caught, each by its own test above -- and every one of
    those is now caught for a *keyless* attacker at the first row they touch.
    """
    for i in range(3):
        await audit.emit(make_event(ts=7000.0 + i, detail={"i": i}))
    assert await audit.verify_chain() is True, "premise: a clean log verifies"

    forged = {"forged": "this event never happened"}
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT seq, entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        )
        tail = await cursor.fetchone()
        assert tail is not None
        seq, prev = int(tail["seq"]) + 1, str(tail["entry_hash"])
        forged_payload = chain_payload(
            seq=seq,
            ts=9999.0,
            session_id="sess-1",
            run_id="run-1",
            event_type=DETECT,
            entity_type=None,
            token_id=None,
            detail=forged,
        )
        entry_hash = compute_entry_hash(prev, forged_payload, key=stolen_chain_key())
        await conn.execute(
            "INSERT INTO audit_events"
            " (seq, ts, session_id, run_id, event_type, entity_type, token_id,"
            "  detail, prev_hash, entry_hash)"
            " VALUES (?, 9999.0, 'sess-1', 'run-1', ?, NULL, NULL, ?, ?, ?)",
            (seq, DETECT, json.dumps(forged), prev, entry_hash),
        )
        await conn.commit()

    # The residual, asserted rather than described.
    assert await audit.verify_chain() is True, (
        "a correctly-hashed tail append is now detected -- if this is a deliberate "
        "improvement, delete this test and update README section 5 Q5, which "
        "documents the gap it pins"
    )
    # And it really is a forgery: the fabricated row is readable as a genuine event.
    rows = await audit.query()
    assert [dict(event.detail) for event in rows][-1] == forged

    # THE PRECONDITION, asserted rather than described: the same append attempted
    # WITHOUT the key produces a different digest, so the attacker who has file
    # access and nothing else cannot mint the row this test just minted. Before the
    # chain was keyed there was no such precondition -- the formula was public --
    # and this assertion is what stops that quietly coming back.
    keyless = _legacy_unkeyed_entry_hash(prev, forged_payload)
    assert keyless != entry_hash
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute(
            "UPDATE audit_events SET entry_hash = ? WHERE seq = ?", (keyless, seq)
        )
        await conn.commit()
    assert await audit.verify_chain() is False, (
        "an append forged without the chain key must be rejected"
    )


async def test_a_rewritten_chain_is_rejected_because_the_digest_is_keyed(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """The attack the whole tamper-evidence claim rested on not existing.

    Every other tamper test here edits a row and leaves the chain inconsistent. That
    is not what an attacker does. An attacker who can write the database edits the
    row **and then recomputes every hash after it**, and until the chain was keyed
    they could: the formula was published in this module's own docstring and needed
    no secret. Reproduced before the fix, verbatim -- five rows, the ``EGRESS_BLOCK``
    at ``seq`` 3 rewritten into a routine ``DETECT``, the whole log re-chained with
    ``sha256(prev_hash + canonical_json(payload))``::

        verify_chain()             -> True
        verify_chain('sess-victim')-> True

    The record of a blocked egress was gone and the log said it was intact. Against
    a store compromise -- which is precisely when an auditor needs this -- an unkeyed
    chain proved nothing.

    So the rewrite is performed here in full, with the *public* algorithm and no
    access to the key, and it is asserted to be internally perfect first: every link
    holds, every row recomputes under the published formula. That premise is what
    makes the failure below attributable to the key and to nothing else.
    """
    for i in range(5):
        await audit.emit(
            make_event(
                ts=1_700_000_000.0 + i,
                session_id="sess-victim",
                event_type=EGRESS_BLOCK if i == 2 else DETECT,
                token_id=f"tok{i:05d}",
                detail={"count": i, "note": "incriminating" if i == 2 else "routine"},
            )
        )
    assert await audit.verify_chain() is True, "premise: a clean log verifies"

    def rows_of(conn: sqlite3.Connection) -> list[dict[str, object]]:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY seq ASC")]

    db = tmp_path / "audit.db"
    with sqlite3.connect(db) as conn:
        rows = rows_of(conn)
        assert rows[2]["event_type"] == EGRESS_BLOCK, "premise: the row to erase is there"

        # The edit: the incriminating event becomes a routine one.
        rows[2]["event_type"] = DETECT
        rows[2]["detail"] = canonical_json(
            {"action": EVENT_ACTIONS[DETECT], "count": 2, "note": "routine"}
        )

        # The repair: re-chain the ENTIRE log with the published formula. No key.
        prev = GENESIS_HASH
        for row in rows:
            payload = chain_payload(
                seq=int(row["seq"]),
                ts=float(row["ts"]),
                session_id=str(row["session_id"]),
                run_id=row["run_id"],
                event_type=str(row["event_type"]),
                entity_type=row["entity_type"],
                token_id=row["token_id"],
                detail=json.loads(str(row["detail"])),
            )
            row["prev_hash"] = prev
            row["entry_hash"] = _legacy_unkeyed_entry_hash(prev, payload)
            prev = str(row["entry_hash"])
            conn.execute(
                "UPDATE audit_events SET event_type = ?, detail = ?, prev_hash = ?,"
                " entry_hash = ? WHERE seq = ?",
                (
                    row["event_type"],
                    row["detail"],
                    row["prev_hash"],
                    row["entry_hash"],
                    row["seq"],
                ),
            )

    # PREMISE: the forgery succeeded on its own terms. This is the state that
    # returned True before the chain was keyed, so if this block ever stops holding
    # the assertions below stop proving anything.
    with sqlite3.connect(db) as conn:
        forged = rows_of(conn)
    assert all(row["event_type"] == DETECT for row in forged), "the block event is erased"
    expected_prev = GENESIS_HASH
    for row in forged:
        assert row["prev_hash"] == expected_prev, "premise: every link holds"
        payload = chain_payload(
            seq=int(row["seq"]),
            ts=float(row["ts"]),
            session_id=str(row["session_id"]),
            run_id=row["run_id"],
            event_type=str(row["event_type"]),
            entity_type=row["entity_type"],
            token_id=row["token_id"],
            detail=json.loads(str(row["detail"])),
        )
        assert _legacy_unkeyed_entry_hash(expected_prev, payload) == row["entry_hash"], (
            "premise: every row recomputes under the PUBLIC formula"
        )
        expected_prev = str(row["entry_hash"])

    # ... and it is caught anyway, in both scopes, because the digest is a MAC.
    assert await audit.verify_chain() is False
    assert await audit.verify_chain("sess-victim") is False


async def test_a_pre_keying_log_fails_and_says_which(
    audit: AuditLogger, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The migration, and it must fail *honestly* rather than confusingly.

    Rows written before the chain was keyed carry a plain ``sha256`` digest. They
    cannot be vouched for under the key and must not be: accepting them would be a
    downgrade an attacker can choose, since writing the unkeyed form needs no key.
    They are therefore reported invalid -- but with their own break reason, so a
    mixed log names its oldest rows instead of returning an undifferentiated wall of
    ``entry_hash_mismatch``.

    The label says "written without the key", which a forgery also is. It is a shape,
    not an exoneration, and
    ``test_a_rewritten_chain_is_rejected_because_the_digest_is_keyed`` produces the
    same label from an attack -- deliberately, because the two are the same bytes and
    no code can separate them.
    """
    for i in range(5):
        await audit.emit(make_event(ts=1_700_000_000.0 + i, detail={"count": i}))

    # Rewrite the first three rows in the pre-keying form, as an old file holds them,
    # leaving rows 4 and 5 keyed -- the shape of a redeployed app appending to a log
    # it inherited.
    db = tmp_path / "audit.db"
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY seq ASC")]
        prev = GENESIS_HASH
        for row in rows[:3]:
            payload = chain_payload(
                seq=int(row["seq"]),
                ts=float(row["ts"]),
                session_id=str(row["session_id"]),
                run_id=row["run_id"],
                event_type=str(row["event_type"]),
                entity_type=row["entity_type"],
                token_id=row["token_id"],
                detail=json.loads(str(row["detail"])),
            )
            legacy = _legacy_unkeyed_entry_hash(prev, payload)
            conn.execute(
                "UPDATE audit_events SET prev_hash = ?, entry_hash = ? WHERE seq = ?",
                (prev, legacy, row["seq"]),
            )
            prev = legacy
        # Row 4 keeps its keyed digest but must chain onto row 3's new one, or the
        # failure would be a link break rather than the digest question under test.
        conn.execute("UPDATE audit_events SET prev_hash = ? WHERE seq = 4", (prev,))
        payload4 = chain_payload(
            seq=4,
            ts=float(rows[3]["ts"]),
            session_id=str(rows[3]["session_id"]),
            run_id=rows[3]["run_id"],
            event_type=str(rows[3]["event_type"]),
            entity_type=rows[3]["entity_type"],
            token_id=rows[3]["token_id"],
            detail=json.loads(str(rows[3]["detail"])),
        )
        rehashed = compute_entry_hash(prev, payload4, key=stolen_chain_key())
        conn.execute(
            "UPDATE audit_events SET entry_hash = ? WHERE seq = 4", (rehashed,)
        )
        conn.execute("UPDATE audit_events SET prev_hash = ? WHERE seq = 5", (rehashed,))
        payload5 = chain_payload(
            seq=5,
            ts=float(rows[4]["ts"]),
            session_id=str(rows[4]["session_id"]),
            run_id=rows[4]["run_id"],
            event_type=str(rows[4]["event_type"]),
            entity_type=rows[4]["entity_type"],
            token_id=rows[4]["token_id"],
            detail=json.loads(str(rows[4]["detail"])),
        )
        conn.execute(
            "UPDATE audit_events SET entry_hash = ? WHERE seq = 5",
            (compute_entry_hash(rehashed, payload5, key=stolen_chain_key()),),
        )

    with caplog.at_level(logging.WARNING, logger=logger_module.__name__):
        assert await audit.verify_chain() is False

    breaks = [
        (record.audit_seq, record.chain_break)  # type: ignore[attr-defined]
        for record in caplog.records
        if hasattr(record, "chain_break")
    ]
    assert breaks == [
        (1, "entry_hash_unkeyed_legacy"),
        (2, "entry_hash_unkeyed_legacy"),
        (3, "entry_hash_unkeyed_legacy"),
    ], (
        "a mixed log must name exactly its pre-keying rows: the two keyed rows are "
        "clean and the three legacy ones are diagnosed, not lumped in with tampering"
    )


async def test_a_log_written_under_a_different_key_does_not_verify(tmp_path: Path) -> None:
    """The property a key has, stated as itself rather than inferred from an attack.

    Two loggers, two keys, one file. The second cannot vouch for what the first
    wrote, and that is not a bug to be smoothed over -- it is the entire mechanism.
    A regression that ignored ``chain_key`` and hashed unkeyed would make both of
    these verify, which is why the negative assertion is the one that matters.
    """
    db = tmp_path / "audit.db"
    first = await AuditLogger.open(db, chain_key=bytes(range(32)))
    try:
        for i in range(3):
            await first.emit(make_event(ts=5000.0 + i, detail={"count": i}))
        assert await first.verify_chain() is True, "premise: its own key verifies"
    finally:
        await first.close()

    second = await AuditLogger.open(db, chain_key=bytes(range(1, 33)))
    try:
        assert await second.verify_chain() is False
    finally:
        await second.close()


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
        event.entity_type = "reassigned"
    with pytest.raises(ValidationError):
        event.detail = {"count": 1}

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
    # `emit_many` joined the surface, and this allow-list is doing exactly the job its
    # docstring describes: forcing that addition to be argued rather than noticed. It
    # is an APPEND method -- one transaction, N inserts, no UPDATE and no DELETE -- so
    # the append-only claim is unchanged, which the forbidden-SQL scan above re-checks
    # against the source rather than taking on trust. The set stays exact: a
    # `purge_session` added later for GDPR reasons still fails here.
    assert public == {
        "close",
        "emit",
        "emit_many",
        "length",
        "open",
        "query",
        "verify_chain",
    }, (
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
        key=stolen_chain_key(),
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


async def test_deleting_a_middle_row_and_relinking_the_chain_is_still_caught(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """The attack that defeats every check in :meth:`verify_chain` except one.

    A naive middle deletion leaves the successor's ``prev_hash`` pointing at a row
    that is gone, which ``test_deleted_row_breaks_the_chain`` already covers. The
    competent version does not stop there: having deleted the row, the attacker
    **re-links** -- walks the survivors in order and recomputes ``prev_hash`` and
    ``entry_hash`` for every one of them with the shipped formula. The digests are
    unkeyed, so this costs nothing and nothing prevents it.

    What is left is a chain in which every row's hash recomputes correctly from its
    own columns and every link matches its predecessor. The content check passes.
    The link check passes. The high-water check passes too, because ``seq`` values
    were left as they were, so the tail is still the highest ``seq`` SQLite ever
    handed out. **The one surviving witness is that ``seq`` now skips a number**, and
    the ``seq != expected_seq`` comparison is the only line in the method that looks.

    That is why this test exists as its own case rather than as a variation of the
    others. Every previously existing chain test breaks *at least two* checks at
    once, so removing the ``seq`` continuity comparison entirely left all 100 audit
    tests green -- measured, by deleting it in a scratch copy -- while this exact
    attack went from ``valid=False`` to ``valid=True``. A check that no test isolates
    is a check that can be removed by accident, which is the same shape of silence
    that left ``prev_hash`` and ``entry_hash`` uncapped.

    The renumbering variant (re-link *and* compact ``seq`` to 1..n) is a different
    attack caught by a different witness -- the ``sqlite_sequence`` high-water mark --
    and is asserted below so the two are not confused for one another.
    """
    for i in range(6):
        await audit.emit(make_event(ts=9400.0 + i, detail={"count": i}))
    assert await audit.verify_chain() is True

    async def relink(*, renumber: bool) -> None:
        """Rebuild a perfectly self-consistent chain over the surviving rows."""
        async with aiosqlite.connect(tmp_path / "audit.db") as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT * FROM audit_events ORDER BY seq ASC"
            ) as cursor:
                survivors = [dict(row) for row in await cursor.fetchall()]
            await conn.execute("DELETE FROM audit_events")
            prev = GENESIS_HASH
            for position, row in enumerate(survivors, start=1):
                seq = position if renumber else int(row["seq"])
                entry_hash = compute_entry_hash(
                    prev,
                    chain_payload(
                        seq=seq,
                        ts=float(row["ts"]),
                        session_id=str(row["session_id"]),
                        run_id=row["run_id"],
                        event_type=str(row["event_type"]),
                        entity_type=row["entity_type"],
                        token_id=row["token_id"],
                        detail=json.loads(row["detail"]),
                    ),
                    key=stolen_chain_key(),
                )
                await conn.execute(
                    "INSERT INTO audit_events (seq, ts, session_id, run_id, event_type,"
                    " entity_type, token_id, detail, prev_hash, entry_hash)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (seq, row["ts"], row["session_id"], row["run_id"], row["event_type"],
                     row["entity_type"], row["token_id"], row["detail"], prev, entry_hash),
                )
                prev = entry_hash
            await conn.commit()

    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        await conn.execute("DELETE FROM audit_events WHERE seq = 3")
        await conn.commit()
    await relink(renumber=False)

    # Premise: the attacker's work really did succeed on its own terms -- every row
    # now recomputes, and every link matches. If this premise ever fails the test
    # below stops proving what it claims, so it is asserted rather than assumed.
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute("SELECT * FROM audit_events ORDER BY seq ASC") as cursor:
            rows = [dict(row) for row in await cursor.fetchall()]
    expected_prev = GENESIS_HASH
    for row in rows:
        assert row["prev_hash"] == expected_prev, "premise: the re-link left the links intact"
        recomputed = compute_entry_hash(
            expected_prev,
            chain_payload(
                seq=int(row["seq"]), ts=float(row["ts"]), session_id=str(row["session_id"]),
                run_id=row["run_id"], event_type=str(row["event_type"]),
                entity_type=row["entity_type"], token_id=row["token_id"],
                detail=json.loads(row["detail"]),
            ),
            key=stolen_chain_key(),
        )
        assert recomputed == row["entry_hash"], "premise: every row's own hash recomputes"
        expected_prev = row["entry_hash"]
    assert [int(row["seq"]) for row in rows] == [1, 2, 4, 5, 6], "premise: seq skips the hole"

    # ... and it is still caught, by the seq continuity check and nothing else.
    assert await audit.verify_chain() is False

    # The compacting variant renumbers the hole away, so seq is continuous again --
    # and is caught instead by the high-water mark, which DELETE never rolls back.
    await relink(renumber=True)
    async with aiosqlite.connect(tmp_path / "audit.db") as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute("SELECT seq FROM audit_events ORDER BY seq ASC") as cursor:
            seqs = [int(row["seq"]) for row in await cursor.fetchall()]
    assert seqs == [1, 2, 3, 4, 5], "premise: seq is now continuous, so that witness is gone"
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


async def _statements(db_path: Path, *sql: str) -> None:
    """Run raw SQL against the audit DB behind the logger's back, as an attacker would."""
    async with aiosqlite.connect(db_path) as conn:
        for statement in sql:
            await conn.execute(statement)
        await conn.commit()


async def test_a_silent_tail_truncation_costs_four_statements_and_all_four_are_needed(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """The exact edge of the truncation defence, measured one statement at a time.

    This test previously stopped after two statements and asserted ``True``, with a
    note saying that if it ever became ``False`` the defence had got stronger. It
    has. The whole ladder is now walked, because "how many statements does a silent
    truncation cost" is the only honest way to state what an unkeyed in-file scheme
    buys, and a single ``True``/``False`` at one rung does not say it:

    1. ``DELETE`` the newest rows -- caught. Every surviving row still hashes and
       still links; the *watermark* is the only witness.
    2. ...plus ``UPDATE sqlite_sequence`` to the surviving count -- **still caught**,
       and this rung is the change. SQLite's bookkeeping row is no longer the only
       mark: ``audit_chain_meta`` holds the same fact in a table this module owns.
    3. ...plus deleting or lowering that row directly -- **refused by the database**,
       not by the writer. Two triggers enforce "only ever grows", so the attacker
       cannot simply write the number they want.
    4. ...plus ``DROP TRIGGER`` and *then* the lowering ``UPDATE`` -- not caught.
       That is the residual, and it is what the README must say.

    The digests are unkeyed, so an attacker who gets to rung 4 was always going to
    win; the value of the ladder is that rungs 1-3 are where a *casual* truncation
    stops, and that the evidence at those rungs is durable (see
    ``test_a_truncated_tail_does_not_heal_when_the_log_advances``) rather than
    something ordinary traffic erases.
    """
    db = tmp_path / "audit.db"
    for i in range(5):
        await audit.emit(make_event(ts=9400.0 + i))
    assert await audit.verify_chain() is True

    # 1. The DELETE on its own.
    await _statements(db, "DELETE FROM audit_events WHERE seq >= 4")
    assert await audit.verify_chain() is False, "the watermark check must catch this"

    # 2. Plus SQLite's own bookkeeping row, which used to be the whole defence.
    await _statements(db, "UPDATE sqlite_sequence SET seq = 3 WHERE name = 'audit_events'")
    assert await audit.verify_chain() is False, (
        "rewriting sqlite_sequence alone now hides nothing -- audit_chain_meta still "
        "holds the real high-water mark. If this returns True the second mark is gone "
        "and the truncation defence is back to costing two statements"
    )

    # 3. The second mark cannot just be written: the database refuses.
    for refused in (
        "DELETE FROM audit_chain_meta",
        "UPDATE audit_chain_meta SET max_seq = 3 WHERE id = 1",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            await _statements(db, refused)
    assert await audit.verify_chain() is False

    # 4. The residual: drop the guard, then lower the mark. Four statements, in step.
    await _statements(
        db,
        "DROP TRIGGER audit_chain_meta_is_monotonic",
        "UPDATE audit_chain_meta SET max_seq = 3 WHERE id = 1",
    )
    assert await audit.verify_chain() is True, (
        "if this now returns False the truncation defence got stronger again -- good, "
        "and the README's 'unkeyed, so a full rewrite verifies' caveat and the "
        "statement count quoted there should be revisited"
    )


async def test_a_truncated_tail_does_not_heal_when_the_log_advances(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """Truncation evidence must be durable, not a window that ordinary traffic closes.

    The attack needs **no** second statement and no hash work. ``emit`` used to
    allocate ``seq = MAX(seq) + 1`` over the surviving rows, so a freed tail number
    was handed straight back out. Delete the newest three events -- ``verify_chain``
    correctly says ``False`` -- then let three ordinary events flow through the
    pipeline, which an attacker can drive through the public API. The seqs become
    contiguous ``1..N`` again, ``last_seq`` climbs back to the high-water mark, and
    the verifier returns ``True``. ``length()`` and ``query()`` agree, so the
    documented completeness check (``len(page) == length``) also reads clean: a
    compliance reviewer sees a COMPLETE, VALID log with the original tail events
    permanently gone.

    Every other tail test in this file checks ``verify_chain`` *immediately* after
    the delete, which is exactly the window in which the defence still works, so the
    entire suite stayed green while the one control the README markets for tail
    truncation silently expired.

    The fix is that ``seq`` is allocated above the watermark rather than above the
    surviving tail, so the deleted numbers are never re-issued and the hole is
    permanent. That is asserted here as a *property of the seqs*, not only as the
    verifier's answer, so the mechanism is visible in the failure message.
    """
    db = tmp_path / "audit.db"
    for i in range(8):
        await audit.emit(make_event(ts=9900.0 + i))
    assert await audit.verify_chain() is True
    assert await audit.length() == 8

    await _statements(db, "DELETE FROM audit_events WHERE seq >= 6")
    assert await audit.verify_chain() is False, "premise: the truncation is caught at first"
    assert await audit.length() == 5

    # Ordinary, benign traffic -- the only capability this attack needs.
    for i in range(3):
        await audit.emit(make_event(ts=9950.0 + i))

    seqs = [event.seq for event in await audit.query(limit=100)]
    assert seqs == [1, 2, 3, 4, 5, 9, 10, 11], (
        f"a freed tail seq was re-issued ({seqs}); the truncation has been papered "
        "over by ordinary traffic and nothing records that it happened"
    )
    assert await audit.verify_chain() is False, (
        "three benign events restored a clean bill of health to a log whose tail was "
        "deleted -- the truncation evidence erased itself"
    )

    # And the reviewer's documented completeness check no longer reads as clean.
    page = await audit.query(limit=1000)
    assert len(page) == await audit.length(), "premise: the page really does look complete"
    assert await audit.verify_chain() is False, (
        "a complete-looking page plus a valid chain is exactly what the attacker "
        "wanted a compliance reviewer to see"
    )


async def test_deleting_the_sqlite_sequence_row_does_not_launder_a_truncation(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """A *missing* bookkeeping row on a non-empty log is evidence, not "no opinion".

    The code's own asymmetry was the bug. A ``NULL`` or non-numeric value in
    ``sqlite_sequence`` was treated as tamper evidence (``False``, and tested); a
    **missing row** degraded to "no opinion" and returned ``True``, untested. Both
    are one statement, and the untested one is the *easier* of the two -- the tested
    ``UPDATE ... SET seq = 3`` needs the attacker to know how many rows survived,
    while the delete needs no arithmetic at all.

    ``None`` from ``_watermark`` genuinely is the right answer on a log that has
    never been written, which is why the degradation looked reasonable. The
    distinguisher is that a log which still holds rows has certainly been written, so
    no mark at all on a non-empty log is a manufactured state.

    ``DROP TABLE sqlite_sequence`` is asserted to be impossible rather than assumed:
    SQLite refuses it outright, so the delete is the strongest form of this move.
    """
    db = tmp_path / "audit.db"
    for i in range(5):
        await audit.emit(make_event(ts=9850.0 + i))

    await _statements(db, "DELETE FROM audit_events WHERE seq >= 4")
    assert await audit.verify_chain() is False

    await _statements(db, "DELETE FROM sqlite_sequence WHERE name = 'audit_events'")
    assert await audit.verify_chain() is False, (
        "deleting the high-water row laundered a tail truncation into a clean bill "
        "of health"
    )

    # The other mark is still there and still says 5, which is why this is caught
    # even before the empty-vs-written distinction is reached.
    async with aiosqlite.connect(db) as conn:
        async with conn.execute("SELECT max_seq FROM audit_chain_meta") as cursor:
            row = await cursor.fetchone()
    assert row is not None and int(row[0]) == 5

    # Both marks gone: still caught, because a log holding rows has been written.
    await _statements(
        db,
        "DROP TRIGGER audit_chain_meta_is_not_deletable",
        "DELETE FROM audit_chain_meta",
    )
    assert await audit.verify_chain() is False, (
        "a non-empty log with no high-water mark of any kind must read as tampered; "
        "'no opinion' here is the same as 'clean' to every caller"
    )

    # The premise that makes the delete the strongest form of this attack.
    async with aiosqlite.connect(db) as conn:
        with pytest.raises(sqlite3.OperationalError, match="may not be dropped"):
            await conn.execute("DROP TABLE sqlite_sequence")


async def test_an_empty_log_with_no_watermark_is_still_clean(tmp_path: Path) -> None:
    """The case the "no opinion" degradation was protecting, kept working.

    A log that has never been written has no ``sqlite_sequence`` row and no
    ``audit_chain_meta`` row, and it must verify ``True`` -- otherwise every fresh
    deployment starts life reporting a tampered audit trail, and the signal is worth
    nothing. This is the boundary the fix above had to not cross, so it is asserted
    rather than left to the one existing empty-log test to imply.
    """
    log = await AuditLogger.open(tmp_path / "fresh.db")
    try:
        assert await log.verify_chain() is True
        assert await log.length() == 0
        async with aiosqlite.connect(tmp_path / "fresh.db") as conn:
            for table, where in (
                ("sqlite_sequence", " WHERE name = 'audit_events'"),
                ("audit_chain_meta", ""),
            ):
                async with conn.execute(f"SELECT COUNT(*) FROM {table}{where}") as cursor:
                    row = await cursor.fetchone()
                assert row is not None and int(row[0]) == 0, (
                    f"premise: {table} really is empty on a log that was never written"
                )
        # ...and a total erasure of a log that WAS written is still not clean.
        await log.emit(make_event())
        async with aiosqlite.connect(tmp_path / "fresh.db") as conn:
            await conn.execute("DELETE FROM audit_events")
            await conn.commit()
        assert await log.verify_chain() is False
    finally:
        await log.close()


async def test_an_unreadable_watermark_degrades_the_writer_and_still_fails_the_verifier(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """The writer and the verifier resolve the same doubt in opposite directions.

    ``emit`` and ``verify_chain`` both read the watermark, and both use the shared
    ``_UNREADABLE`` rule to decide what "cannot read it" means -- but an audit writer
    that fails closed silences the pipeline it is supposed to be recording, so the
    writer degrades to the surviving tail and keeps logging while the verifier
    resolves the same input to ``False``. Getting this backwards in either direction
    is a real failure: a raising ``emit`` turns a tampered bookkeeping row into an
    outage, and a passing ``verify_chain`` turns it into a clean bill of health.

    Blanking ``sqlite_sequence.seq`` is the tamper used here because it is the one an
    attacker actually runs, and because it reaches ``int(None)`` as a ``TypeError``
    -- the crash-on-the-detection-path shape this file has been bitten by twice.

    The second half is the one worth reading. SQLite **repairs** its own bookkeeping
    row on the next ``INSERT``, so blanking it is only transient evidence -- and on a
    log where nothing was actually deleted, going back to ``True`` is the *correct*
    answer, because the log genuinely holds every row it ever held. What must not
    happen is the same repair laundering a real truncation, and it does not: the
    second mark is not maintained by SQLite, so it still remembers the deleted tail
    even while the writer is degraded and blind.
    """
    db = tmp_path / "audit.db"
    for i in range(3):
        await audit.emit(make_event(ts=9750.0 + i))

    await _statements(db, "UPDATE sqlite_sequence SET seq = NULL WHERE name = 'audit_events'")
    assert await audit.verify_chain() is False, "the verifier reports the blanked mark"

    # The writer keeps working rather than turning a tampered row into an outage.
    seq = await audit.emit(make_event(ts=9760.0))
    assert seq == 4, "a tampered bookkeeping row must not stop the audit log recording"
    assert await audit.length() == 4

    # SQLite rewrote its row on that INSERT, and with nothing deleted the log really
    # is intact, so clean is the honest answer here.
    async with aiosqlite.connect(db) as conn:
        async with conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'"
        ) as cursor:
            row = await cursor.fetchone()
    assert row is not None and int(row[0]) == 4, "premise: the INSERT repaired the row"
    assert await audit.verify_chain() is True
    assert [event.seq for event in await audit.query()] == [1, 2, 3, 4]

    # The half that matters: the same repair must not launder a real truncation.
    second = await AuditLogger.open(tmp_path / "truncated.db")
    try:
        for i in range(5):
            await second.emit(make_event(ts=9770.0 + i))
        await _statements(
            tmp_path / "truncated.db",
            "DELETE FROM audit_events WHERE seq >= 4",
            "UPDATE sqlite_sequence SET seq = NULL WHERE name = 'audit_events'",
        )
        for i in range(2):
            await second.emit(make_event(ts=9780.0 + i))
        assert await second.verify_chain() is False, (
            "blanking the mark the writer reads let two benign events repair it at a "
            "lower value, and the deleted tail went with it"
        )
    finally:
        await second.close()


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
    to report on. ``_watermark`` already degraded to "no opinion" on
    ``sqlite3.Error``; the main walk did not, and that asymmetry was the bug.

    Driven through a patched cursor because that is the *cheap and deterministic*
    way to reach the handler, and for no other reason.

    This docstring used to justify the patched cursor by claiming a file-level test
    was impossible -- "a file mangled badly enough to fail the walk also fails
    ``AuditLogger.open``, so a file-level test would prove something about ``open``
    instead of about this method". **That was false, and it was the kind of false
    that stops a test from being written.** Measured: zeroing one 4 KiB page of a
    120-row audit database leaves ``open`` perfectly happy -- the file length still
    matches the header's page count, so nothing reads the damaged page until the
    walk does -- and ``verify_chain`` then returns ``False`` off a genuinely
    corrupted file. Truncation, the shape the old claim was written from, is also
    not the wall it describes: a 5-row database truncated to 90% opens *and*
    verifies ``True``, because the bytes removed were unused tail.

    The real file-level test is
    :func:`test_verify_chain_reports_a_physically_corrupted_file_that_open_accepts`,
    and it found three defects this patched-cursor test could not see: ``query``
    and ``length`` crashing on the same input, and ``AuditLogger.open`` leaking its
    connection thread on the input that *does* make it fail.
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


#: Repo root, for the out-of-process leak probe below.
REPO_ROOT = Path(__file__).resolve().parent.parent


async def _build_log(path: Path, rows: int) -> None:
    """Write ``rows`` events to a fresh log at ``path`` and close it cleanly."""
    log = await AuditLogger.open(path)
    try:
        for i in range(rows):
            await log.emit(make_event(ts=9700.0 + i))
    finally:
        await log.close()


def _zero_one_page(path: Path, *, page_from_end: int = 1) -> None:
    """Overwrite one 4 KiB page with zeros, leaving the file's length untouched.

    Length matters: SQLite's header records the database size in pages, so a file
    that is *short* is rejected at open, while a file of the right length holding a
    dead page is accepted and only fails when something reads that page. That is
    what makes this the deterministic way to corrupt a database at the file level
    and still get past ``open`` -- confirmed on 60-, 120- and 200-row logs at four
    different page offsets each, 12 of 12 accepted by ``open`` and reported ``False``
    by ``verify_chain``.
    """
    data = bytearray(path.read_bytes())
    page = 4096
    start = len(data) - page_from_end * page
    assert start >= page, "database is too small for this corruption to be meaningful"
    data[start : start + page] = b"\x00" * page
    path.write_bytes(bytes(data))


async def test_verify_chain_reports_a_physically_corrupted_file_that_open_accepts(
    tmp_path: Path,
) -> None:
    """The file-level corruption test a docstring above once argued was impossible.

    No patched cursor, no monkeypatched connection: a real audit database on disk
    with one of its 4 KiB pages zeroed, opened by the real ``AuditLogger.open``.

    Three separate contracts are asserted, because the value of this test is that
    it reaches *every* reader with one input rather than one reader with a mock:

    * ``open`` accepts the file -- the premise the old docstring denied.
    * ``verify_chain`` returns ``False`` and does not raise. This is the contract
      ``GET /audit/verify`` depends on to answer ``{"valid": false}`` instead of
      returning a 500 on exactly the tampering it exists to report.
    * ``query`` and ``length`` fail *typed*. Both used to escape with a raw
      ``sqlite3.DatabaseError``, and ``query`` could also escape with a bare
      ``TypeError`` from ``float(row["ts"])`` when a lost page returned ``NULL``
      -- an unhandled crash from the middle of a row loop, on the same file
      ``verify_chain`` was carefully hardened for.

    ``query`` deliberately does not return the rows it read before the failure: a
    short list with a 200 on it is indistinguishable from a complete one, and
    truncation is the attack the chain verifier exists to catch.
    """
    db = tmp_path / "corrupt.db"
    await _build_log(db, rows=120)
    intact_bytes = db.stat().st_size
    _zero_one_page(db)
    assert db.stat().st_size == intact_bytes, "corruption must not change the length"

    log = await AuditLogger.open(db)  # the premise: this does NOT raise
    try:
        assert await log.verify_chain() is False, (
            "a physically corrupted file must read as invalid, not as clean and not "
            "as an exception"
        )
        with pytest.raises(PipelineError) as query_err:
            await log.query(limit=10_000)
        assert query_err.value.detail["reason"] == "audit_log_unreadable"

        with pytest.raises(PipelineError) as length_err:
            await log.length()
        assert length_err.value.detail["reason"] == "audit_log_unreadable"

        # Added with the writer's own refusal (below): both readers now carry the
        # code the HTTP layer answers 503 with, and they name which call failed.
        # `reason` above is unchanged and stays asserted -- it is what the API's
        # own tests and the module docstrings have always keyed on.
        for err, operation in ((query_err, "query"), (length_err, "length")):
            assert isinstance(err.value, AuditUnavailableError), type(err.value)
            assert err.value.code == "AUDIT_UNAVAILABLE"
            assert err.value.detail["operation"] == operation
            assert err.value.detail["audit_db"] == "corrupt.db", (
                "the file NAME belongs in the body; the absolute path does not"
            )
            assert err.value.detail["remedy"] == UNREADABLE_AUDIT_REMEDY
    finally:
        await log.close()


async def test_emit_refuses_a_corrupt_database_with_a_typed_error(tmp_path: Path) -> None:
    """The writer's half of the rule the readers already followed.

    Same input as the test above -- a real 120-row log with one 4 KiB page zeroed,
    accepted by the real ``open`` -- driven at ``emit`` instead of at the readers.
    What escaped was ``sqlite3.DatabaseError: database disk image is malformed``
    from ``conn.execute(_LAST_ENTRY_SQL)``, i.e. from the chain-tail read, which is
    the same class of failure ``verify_chain`` goes to trouble over and ``emit``
    did nothing about. Through the ASGI app that was a bare
    ``500 Internal Server Error``; ``tests/test_api.py`` pins the HTTP half.

    Three assertions and each one is a separate claim:

    * it **raises** -- "no release without a record" is the property, and a writer
      that swallowed this would release runs with no record of them
      (``integration/test_pipeline.py::test_no_release_survives_an_audit_write_that_failed_before_it``);
    * it raises the **typed** error, with the operation named, so a client can tell
      a corrupt data directory from a bug in the pipeline;
    * the ``sqlite3`` exception is the ``__cause__`` and not the thing that escapes.
      Asserting the cause is what keeps this test honest about *where* the failure
      came from: a future implementation that raised the typed error for some
      unrelated reason would satisfy the first two and fail here.

    The corruption is a real file with real dead bytes rather than a monkeypatched
    ``raise``: ``PRAGMA integrity_check`` on it reports ``database disk image is
    malformed`` before this test ever calls ``emit``.
    """
    db = tmp_path / "audit.db"
    await _build_log(db, rows=120)
    _zero_one_page(db)

    log = await AuditLogger.open(db)  # the premise: this does NOT raise
    try:
        with pytest.raises(AuditUnavailableError) as caught:
            await log.emit(make_event(ts=9999.0))
    finally:
        await log.close()

    error = caught.value
    assert isinstance(error, PipelineError), "must stay inside the one hierarchy"
    assert error.code == "AUDIT_UNAVAILABLE"
    assert error.detail == {
        "reason": "audit_log_unreadable",
        "operation": "emit",
        "audit_db": "audit.db",
        "error": "DatabaseError",
        "remedy": UNREADABLE_AUDIT_REMEDY,
    }
    assert isinstance(error.__cause__, sqlite3.DatabaseError), error.__cause__
    assert "malformed" in str(error.__cause__)

    # `api/errors.py` writes `dict(exc.detail)` into an HTTP body verbatim, so the
    # server's directory layout must not be in it. The name is; the path is not.
    assert str(tmp_path) not in str(error)


async def test_the_unreadable_refusal_cannot_itself_raise_on_a_long_path(
    tmp_path: Path,
) -> None:
    """The error path's own error path. Not hypothetical -- it is one ``str()`` away.

    ``PipelineError.__init__`` *raises* ``ValueError`` when a detail value renders
    longer than the 64-character ceiling, and this constructor runs while the
    database is already on fire. Had ``_unreadable`` passed ``str(self._db_path)``
    -- the obvious choice, and what the log line correctly does use -- then any
    deployment whose data directory sits deeper than 64 characters would get a
    ``ValueError`` out of the refusal and land back at the bare 500 the typed error
    exists to remove. A pytest ``tmp_path`` alone is around 80.

    So the ceiling is respected by construction, and this drives it with a 200-
    character file name -- the longest this filesystem will accept, against a 64-
    character ceiling -- to prove the clip is real rather than incidental.
    """
    deep = tmp_path / ("a" * 200 + ".db")
    await _build_log(deep, rows=120)
    _zero_one_page(deep)

    log = await AuditLogger.open(deep)
    try:
        with pytest.raises(AuditUnavailableError) as caught:
            await log.emit(make_event(ts=9999.0))
    finally:
        await log.close()

    for key, value in caught.value.detail.items():
        assert len(str(value)) <= MAX_DETAIL_VALUE_LEN, (key, value)
    assert caught.value.detail["audit_db"] == "a" * MAX_DETAIL_VALUE_LEN


async def test_a_truncated_file_either_verifies_honestly_or_refuses_to_open(
    tmp_path: Path,
) -> None:
    """Truncation is size-dependent, so the property is asserted, not one outcome.

    Lopping bytes off the end is the obvious physical attack, and the tempting
    assertion -- "a truncated database fails" -- is simply untrue: a 5-row log cut
    to 90% opens and verifies ``True``, because the bytes removed were unused tail
    and nothing was lost. Asserting the failure would therefore have been asserting
    a falsehood, and asserting nothing was how the false docstring survived.

    The property that *is* always true, and is the one worth having: whenever the
    verifier is willing to call a truncated file valid, the file must still hold
    every row it held before, byte-identically. ``True`` is never allowed to mean
    "I could not tell". Any outcome that is not clean must be either a refusal to
    open or a ``False`` -- never a crash out of ``verify_chain``.
    """
    src = tmp_path / "src.db"
    await _build_log(src, rows=5)
    intact = src.read_bytes()

    reference = await AuditLogger.open(src)
    try:
        expected = await reference.query(limit=10_000)
    finally:
        await reference.close()
    assert len(expected) == 5

    saw_valid = False
    saw_refusal = False
    for pct in (99, 97, 95, 93, 90, 85, 50, 10):
        target = tmp_path / f"cut_{pct}.db"
        target.write_bytes(intact[: len(intact) * pct // 100])
        try:
            log = await AuditLogger.open(target)
        except sqlite3.DatabaseError:
            saw_refusal = True
            continue
        try:
            # Never a crash: this is the contract the endpoint reports as data.
            valid = await log.verify_chain()
            if valid:
                saw_valid = True
                rows = await log.query(limit=10_000)
                assert rows == expected, (
                    f"truncating to {pct}% was called VALID while the log no longer "
                    f"holds what it held ({len(rows)} of {len(expected)} rows) -- "
                    "verify_chain must never let loss read as cleanliness"
                )
        finally:
            await log.close()

    assert saw_refusal, "no truncation ratio was rejected at open; sweep is not biting"
    assert saw_valid, (
        "no truncation ratio was accepted as valid -- if this now fails, truncation "
        "detection got strictly stronger and the docstring above should be revisited"
    )


#: Counts ``aiosqlite.Connection`` threads specifically, not "threads that appeared".
#: ``_connect`` also runs ``asyncio.to_thread(parent.mkdir)``, which starts the
#: default executor's worker on first use; that thread is benign -- the executor
#: registers an atexit join, so it never blocks shutdown -- and counting it made an
#: earlier version of this test fail against correct code. ``aiosqlite.Connection``
#: subclasses ``Thread``, so the leaked object is directly identifiable and there is
#: no need to infer it from a population difference.
_LEAK_PROBE = '''
import asyncio, sqlite3, sys, threading
from pathlib import Path
sys.path.insert(0, {repo!r})
import aiosqlite
from secure_context_pipeline.audit.logger import AuditLogger

def live_connections():
    return [t for t in threading.enumerate()
            if isinstance(t, aiosqlite.Connection) and t.is_alive()]

async def main():
    bad = Path({bad!r})
    for _ in range(10):
        try:
            await AuditLogger.open(bad)
        except sqlite3.DatabaseError:
            pass
        else:
            print("NO_RAISE"); return
    for _ in range(50):
        if not live_connections():
            break
        await asyncio.sleep(0.02)
    print("LEAKED=%d" % len(live_connections()), flush=True)

asyncio.run(main())
'''


async def test_a_failed_open_does_not_leak_the_connection_thread(tmp_path: Path) -> None:
    """A refused ``open`` must not leave a live connection nobody can close.

    ``aiosqlite.connect`` starts a **non-daemon** worker thread and returns before
    any setup statement has touched the file, so the first statement that reads a
    page -- ``PRAGMA journal_mode=WAL`` -- is the first that can fail. When that
    raised, it escaped ``open`` with ``self._conn`` still ``None``: the caller got
    an exception and no handle, the thread stayed alive, and because it is not a
    daemon the interpreter could never exit. Every retry leaked another one.

    Not a hypothetical tidiness point. It was found by a probe script that hung
    forever after opening a corrupt database and had to be killed, and the same
    shape hangs an API process during startup on a damaged audit file -- a failure
    with no error message, which is the worst kind to ship.

    **Run in a subprocess, which is the whole point rather than an inconvenience.**
    The harm *is* "the interpreter cannot exit", so the assertion has to be about a
    process actually exiting; a thread count in this process would describe the
    symptom and not the damage. It also keeps the failure clean: asserting in-process
    was tried first and made pytest itself unable to shut down, so the regression
    signal was a hung CI job rather than a red test -- the leak would have suppressed
    the report of its own detection.

    Ten failed opens rather than one, so a single thread reaped by chance elsewhere
    cannot satisfy it.
    """
    src = tmp_path / "src.db"
    await _build_log(src, rows=5)
    bad = tmp_path / "bad.db"
    bad.write_bytes(src.read_bytes()[: src.stat().st_size // 2])

    script = tmp_path / "leak_probe.py"
    script.write_text(
        _LEAK_PROBE.format(repo=str(REPO_ROOT), bad=str(bad)), encoding="utf-8"
    )

    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode(errors="replace") if exc.stdout else ""
        pytest.fail(
            "a process that made 10 failed AuditLogger.open() calls could not exit "
            f"within 60s -- the connection thread is leaking and it is not a daemon "
            f"(probe stdout: {out.strip()!r})"
        )

    assert proc.stdout.strip() == "LEAKED=0", (
        f"failed opens left connection threads alive: {proc.stdout.strip()!r} "
        f"(stderr: {proc.stderr.strip()[:400]!r})"
    )
    assert proc.returncode == 0, f"probe exited {proc.returncode}: {proc.stderr[:400]}"


#: One worker of the cross-process write test below. Emits ``count`` events into a
#: shared audit.db through the real ``AuditLogger`` and reports what happened, so the
#: assertion is about events that were *accepted*, not about a thread count.
_WRITER_PROBE = '''
import asyncio, collections, sys, time
sys.path.insert(0, {repo!r})
from secure_context_pipeline.audit.logger import AuditLogger
from secure_context_pipeline.models import AuditEvent

async def main():
    db, tag, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    log = await AuditLogger.open(db)
    ok = 0
    errs = collections.Counter()
    for i in range(count):
        try:
            await log.emit(AuditEvent(ts=time.time(), session_id=tag,
                                      event_type="DETECT", detail={{"i": i}}))
            ok += 1
        except BaseException as exc:
            errs[type(exc).__name__] += 1
    await log.close()
    print("%s ok=%d err=%d kinds=%s" % (tag, ok, sum(errs.values()), dict(errs)), flush=True)

asyncio.run(main())
'''

_WRITERS_PER_PROBE = 2
_EVENTS_PER_WRITER = 40


async def test_two_processes_sharing_one_audit_db_lose_no_events(tmp_path: Path) -> None:
    """The concurrency claim, checked across OS processes and not only coroutines.

    ``emit`` is guarded by an :class:`asyncio.Lock`, and the module docstring used to
    say that made the chain linear "no matter how many coroutines race". True, and
    it says nothing about two *processes*: an ``asyncio.Lock`` is an in-process
    object. Two workers sharing one ``audit.db`` each read ``MAX(seq)``, computed the
    same next value, and the loser's ``INSERT`` died on the ``seq`` PRIMARY KEY.

    The damage is specifically that the event is **dropped**. Chain integrity
    survives -- the surviving rows are contiguous, every link matches, and
    ``verify_chain`` returns ``True`` -- which is what makes this worth a test rather
    than a note: the log is *valid* and *incomplete*, and no chain check can ever
    report a row that was never written. Measured on the shipped code before the fix:
    two workers, 60 events each, 15 of 120 lost to ``sqlite3.IntegrityError``.

    Latent rather than active in the graded artifact -- the Dockerfile runs one
    uvicorn process with no ``--workers`` -- but it becomes real the moment anyone
    scales out onto a shared audit volume, which is the ordinary thing to do.

    Two fixes, and the test would pass with only the weaker one, so both are worth
    naming: ``BEGIN IMMEDIATE`` takes the write lock *before* the tail is read, so
    the collision does not happen; ``busy_timeout`` plus the re-chaining retry in
    ``emit`` catches whatever slips past that. Run out of process because the bug
    only exists out of process.
    """
    db = tmp_path / "shared.db"
    script = tmp_path / "writer_probe.py"
    script.write_text(_WRITER_PROBE.format(repo=str(REPO_ROOT)), encoding="utf-8")

    def run_writers() -> list[subprocess.CompletedProcess[str]]:
        procs = [
            subprocess.Popen(
                [sys.executable, str(script), str(db), f"writer-{n}", str(_EVENTS_PER_WRITER)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for n in range(_WRITERS_PER_PROBE)
        ]
        done = []
        for proc in procs:
            out, err = proc.communicate(timeout=90)
            done.append(
                subprocess.CompletedProcess(proc.args, proc.returncode, out, err)
            )
        return done

    results = await asyncio.to_thread(run_writers)

    expected = _WRITERS_PER_PROBE * _EVENTS_PER_WRITER
    for result in results:
        assert result.returncode == 0, f"writer exited {result.returncode}: {result.stderr[:400]}"
        assert f"ok={_EVENTS_PER_WRITER} err=0" in result.stdout, (
            f"a writer sharing the audit DB lost events: {result.stdout.strip()!r} "
            f"(stderr: {result.stderr.strip()[:300]!r})"
        )

    log = await AuditLogger.open(db)
    try:
        rows = await log.query(limit=10_000)
        assert len(rows) == expected, (
            f"{expected - len(rows)} of {expected} audit events were dropped by "
            "cross-process contention -- and a dropped event is the one audit "
            "failure no chain check can report afterwards"
        )
        assert [row.seq for row in rows] == list(range(1, expected + 1))
        assert await log.verify_chain() is True
        # Both writers really did interleave, or the test proved nothing about racing.
        sessions = [row.session_id for row in rows]
        assert len(set(sessions)) == _WRITERS_PER_PROBE
        assert any(a != b for a, b in itertools.pairwise(sessions)), (
            "the two writers ran end to end rather than concurrently, so no seq was "
            "ever contended and this run measured nothing"
        )
    finally:
        await log.close()


async def test_a_lost_seq_race_is_retried_rather_than_dropped(
    audit: AuditLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retry handler itself, driven deterministically.

    ``test_two_processes_sharing_one_audit_db_lose_no_events`` proves the *outcome*
    across processes, but ``BEGIN IMMEDIATE`` is what fixes that case, so the retry
    underneath it can go entirely unexercised -- untested defensive code that reads
    like a guarantee. Branch coverage said exactly that: the whole handler was
    unvisited by every in-process test.

    So the collision is injected. One ``IntegrityError`` from the ``INSERT``, then a
    normal write, and the contract is that the event **lands** rather than being
    dropped: the row is there, the chain is linear, and the seq is the one it would
    always have had.
    """
    await audit.emit(make_event(ts=1000.0))
    conn = audit._connection()
    real_execute = conn.execute
    failures = {"left": 1}

    def flaky(sql: str, *args: object, **kwargs: object) -> object:
        if "INSERT INTO audit_events" in sql and failures["left"]:
            failures["left"] -= 1
            raise sqlite3.IntegrityError("UNIQUE constraint failed: audit_events.seq")
        return real_execute(sql, *args, **kwargs)

    monkeypatch.setattr(conn, "execute", flaky)
    seq = await audit.emit(make_event(ts=1001.0))
    monkeypatch.undo()

    assert failures["left"] == 0, "premise: the injected collision really did fire"
    assert seq == 2
    assert await audit.length() == 2
    assert await audit.verify_chain() is True


async def test_exhausting_the_seq_retries_fails_typed_and_leaves_the_log_usable(
    audit: AuditLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sustained contention gives up loudly, and the logger keeps working afterwards.

    Two contracts, and the second is the one worth the test. A writer that cannot
    win the race after ``MAX_EMIT_ATTEMPTS`` must say so with a typed
    :class:`PipelineError` rather than an opaque ``sqlite3`` error -- but it must
    also leave no transaction open behind it, because this connection is reused for
    every later emit and a leaked ``BEGIN IMMEDIATE`` turns one failed write into
    "cannot start a transaction within a transaction" on every write after it. That
    turns a transient contention spike into a permanently silent audit log, which is
    strictly worse than the dropped event it was introduced to prevent.
    """
    await audit.emit(make_event(ts=2000.0))
    conn = audit._connection()
    real_execute = conn.execute
    attempts = {"n": 0}

    def always_colliding(sql: str, *args: object, **kwargs: object) -> object:
        if "INSERT INTO audit_events" in sql:
            attempts["n"] += 1
            raise sqlite3.IntegrityError("UNIQUE constraint failed: audit_events.seq")
        return real_execute(sql, *args, **kwargs)

    monkeypatch.setattr(conn, "execute", always_colliding)
    with pytest.raises(PipelineError) as excinfo:
        await audit.emit(make_event(ts=2001.0))
    monkeypatch.undo()

    assert excinfo.value.detail["reason"] == "audit_seq_contention"
    assert attempts["n"] == logger_module.MAX_EMIT_ATTEMPTS

    # The log is still usable, which is the half that would otherwise fail silently.
    assert await audit.emit(make_event(ts=2002.0)) == 2
    assert await audit.length() == 2
    assert await audit.verify_chain() is True


async def test_a_failed_write_does_not_wedge_every_later_write(
    audit: AuditLogger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any failure inside the write transaction must roll it back, not only the race.

    The ``IntegrityError`` path is the expected one and has its own rollback. Every
    *other* error inside the critical section -- a disk error, a cancelled request,
    a bug -- would leave ``BEGIN IMMEDIATE`` open on a connection this class reuses
    forever. The next emit then fails with ``cannot start a transaction within a
    transaction``, and so does every emit after it: one transient fault silences the
    audit log for the life of the process.

    Cancellation is included deliberately: it is a ``BaseException``, not an
    ``Exception``, and it is the *realistic* case -- an API request timing out
    mid-write -- rather than the exotic one.

    **The two arms no longer surface the same way, and the difference is the
    contract.** The sqlite fault is now the typed ``AuditUnavailableError`` -- 503
    ``AUDIT_UNAVAILABLE`` at the HTTP boundary -- because a ``sqlite3.Error`` out of
    the audit writer is *always* "this deployment's audit log cannot be used", and
    the four realistic shapes on a bind-mounted file are one ``DatabaseError``
    (a corrupt page: the reported defect) and three ``OperationalError``s (disk
    full, a read-only mount, and ``database is locked`` from the several processes
    sharing one file -- which is what actually happened to the demo). Narrowing the
    refusal to ``DatabaseError`` would have fixed the one that was reported and
    left the other three answering a bare ``500 Internal Server Error``.
    Cancellation stays raw: it is a ``BaseException``, it means *this request* went
    away rather than the log being unusable, and swallowing it into a domain error
    would report a caller-side timeout as a server-side outage.

    What this test is *about* is unchanged, and both arms still assert it: the
    transaction is rolled back and the next write succeeds. The sqlite arm also
    pins the identity of the original exception as ``__cause__``, which is stricter
    than the bare ``type(injected)`` check it replaces -- the typed error must be
    carrying the failure that actually happened, not merely be of the right class.
    """
    await audit.emit(make_event(ts=3000.0))
    conn = audit._connection()
    real_execute = conn.execute

    def make_failing(exc: BaseException) -> Callable[..., object]:
        def failing(sql: str, *args: object, **kwargs: object) -> object:
            if "INSERT INTO audit_events" in sql:
                raise exc
            return real_execute(sql, *args, **kwargs)

        return failing

    injections: tuple[tuple[BaseException, type[BaseException]], ...] = (
        # (what fails inside the transaction, what the caller must see)
        (sqlite3.OperationalError("disk I/O error"), AuditUnavailableError),
        (asyncio.CancelledError(), asyncio.CancelledError),
    )
    for injected, surfaced in injections:
        monkeypatch.setattr(conn, "execute", make_failing(injected))
        with pytest.raises(surfaced) as caught:
            await audit.emit(make_event(ts=3001.0))
        if surfaced is AuditUnavailableError:
            assert caught.value.__cause__ is injected, (
                "the typed refusal must carry the failure that actually happened"
            )
        monkeypatch.undo()

        # The transaction was rolled back, so this is an ordinary write and not
        # "cannot start a transaction within a transaction".
        assert await audit.emit(make_event(ts=3002.0)) is not None
        assert await audit.verify_chain() is True


async def test_one_unreadable_watermark_source_does_not_silence_the_other(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """Two marks means one can be destroyed outright and the other still speaks.

    Dropping ``audit_chain_meta`` is the attacker's answer to a table they cannot
    lower and cannot delete a row from -- the triggers refuse both, but nothing stops
    ``DROP TABLE``. The read then fails with an ``sqlite3.Error`` rather than
    returning no row, which is a different code path from "the row is missing", and
    it must not be allowed to take the surviving mark down with it.

    So the truncation is still caught, by ``sqlite_sequence`` alone, exactly as it
    was before the second mark existed.
    """
    db = tmp_path / "audit.db"
    for i in range(5):
        await audit.emit(make_event(ts=4000.0 + i))

    await _statements(db, "DROP TABLE audit_chain_meta")
    assert await audit.verify_chain() is True, (
        "dropping one bookkeeping table must not, on its own, read as tampering -- "
        "the surviving mark still agrees with the tail"
    )

    await _statements(db, "DELETE FROM audit_events WHERE seq >= 4")
    assert await audit.verify_chain() is False, (
        "with audit_chain_meta gone the sqlite_sequence mark is the whole defence "
        "again, and it must still catch a truncated tail"
    )

    # And the writer keeps working with one source missing.
    assert await audit.emit(make_event(ts=4100.0)) == 6, (
        "seq must still be allocated above the surviving mark, or dropping the meta "
        "table is enough to re-enable heal-by-append"
    )


@pytest.mark.parametrize(
    ("tampered", "why"),
    [
        ("[1, 2, 3]", "valid JSON but not an object"),
        ('{"k": {"nested": 1}}', "an object whose value is not a scalar"),
        ('"just a string"', "valid JSON scalar, not an object"),
    ],
)
async def test_a_detail_column_that_is_json_but_not_a_detail_map_is_tamper_evidence(
    audit: AuditLogger, tmp_path: Path, tampered: str, why: str
) -> None:
    """``detail`` must be a flat object of scalars, and anything else is evidence.

    ``test_tampered_detail_that_is_not_json_breaks_the_chain`` covers the obvious
    case -- bytes that are not JSON at all. The interesting rewrites are the ones
    that *parse*: an array, a nested object, a bare string. Each reaches
    ``_load_detail`` through a different branch, each returns ``None``, and a
    ``None`` that was treated as an empty map instead would let an attacker rewrite
    the payload of any row into a shape the chain check skips.
    """
    for i in range(3):
        await audit.emit(make_event(ts=5000.0 + i, detail={"count": i}))
    assert await audit.verify_chain() is True

    await tamper_detail(tmp_path / "audit.db", seq=2, new_detail=tampered)
    assert await audit.verify_chain() is False, f"{why} was not reported as tampering"


async def test_enabling_wal_retries_a_concurrent_opener_but_not_a_broken_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one lock ``busy_timeout`` does not cover, and its two outcomes.

    Converting a database *into* WAL needs a moment of exclusive access, and SQLite
    answers ``SQLITE_BUSY`` for that conversion **without consulting the busy
    handler**. Two processes opening a brand-new audit DB at the same instant
    therefore got ``database is locked`` out of ``open()`` itself, on a database
    about to be perfectly fine. Found as a flake, honestly: the cross-process writer
    test passed five runs in isolation and failed once under full-suite load.

    Retrying it is defensive code, and defensive code nobody drives is a comment
    with a syntax highlighter, so both directions are exercised here rather than
    left to a race that reproduces once in twenty runs:

    * a lock that clears is retried and ``open()`` succeeds;
    * a lock that never clears is given up on rather than retried forever;
    * a *non-lock* error is not retried at all, because a corrupt file has to fail
      ``open()`` promptly -- ``test_a_failed_open_does_not_leak_the_connection_thread``
      depends on that failure arriving rather than being slept on five times.
    """
    real_connect = logger_module.aiosqlite.connect
    calls = {"busy": 0, "fail_for": 2}

    def flaky_connect(*args: object, **kwargs: object) -> object:
        connection = real_connect(*args, **kwargs)
        real_execute = connection.execute

        def execute(sql: str, *rest: object, **kw: object) -> object:
            if sql == "PRAGMA journal_mode=WAL" and calls["busy"] < calls["fail_for"]:
                calls["busy"] += 1
                raise sqlite3.OperationalError("database is locked")
            return real_execute(sql, *rest, **kw)

        connection.execute = execute
        return connection

    monkeypatch.setattr(logger_module.aiosqlite, "connect", flaky_connect)
    log = await AuditLogger.open(tmp_path / "contended.db")
    try:
        assert calls["busy"] == 2, "premise: the conversion really was refused twice"
        assert await log.emit(make_event()) == 1
        assert await log.verify_chain() is True
    finally:
        await log.close()

    # A lock that never clears gives up, bounded, rather than retrying forever.
    calls["busy"] = 0
    calls["fail_for"] = 999
    monkeypatch.setattr(logger_module, "WAL_SETUP_BACKOFF_S", 0.001)
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        await AuditLogger.open(tmp_path / "wedged.db")
    assert calls["busy"] >= logger_module.WAL_SETUP_ATTEMPTS, (
        "the conversion was abandoned before every attempt was used"
    )

    # A non-lock failure is fatal on the first attempt, not retried into a slow one.
    def broken_connect(*args: object, **kwargs: object) -> object:
        connection = real_connect(*args, **kwargs)
        real_execute = connection.execute

        def execute(sql: str, *rest: object, **kw: object) -> object:
            if sql.startswith("PRAGMA journal_mode"):
                raise sqlite3.DatabaseError("file is not a database")
            return real_execute(sql, *rest, **kw)

        connection.execute = execute
        return connection

    monkeypatch.setattr(logger_module.aiosqlite, "connect", broken_connect)
    with pytest.raises(sqlite3.DatabaseError, match="not a database"):
        await AuditLogger.open(tmp_path / "corrupt.db")


async def test_verify_chain_survives_a_tampered_high_water_mark(
    audit: AuditLogger, tmp_path: Path
) -> None:
    """The tail-truncation sentinel itself is attacker-writable, and was a crash.

    ``sqlite_sequence`` is an ordinary table.
    ``test_a_silent_tail_truncation_costs_four_statements_and_all_four_are_needed``
    already pins what happens when an attacker rewrites it to a *plausible* number.
    This pins the other move -- blanking it -- which is strictly easier, since it
    needs no knowledge of how many rows survived.

    Both ``NULL`` and a non-numeric string were accepted by SQLite and reached
    ``int(row["seq"])`` inside ``_watermark``, which runs *after*
    ``verify_chain``'s try block. So the verifier raised ``TypeError`` /
    ``ValueError`` instead of returning ``False``: ``GET /audit/verify`` answered a
    500, and the answer to "has this log been tampered with" became an error page,
    on an input that is itself the tampering.

    Note this is the same bug shape as ``test_verify_chain_survives_a_non_numeric
    _tampered_timestamp`` one table over. That test enumerated the columns of
    ``audit_events`` and stopped there; the bookkeeping table the truncation
    defence actually depends on was never in the enumeration.

    ``False``, not ``True``: a sentinel that exists but holds garbage is evidence,
    not absence, and must not degrade to the "no opinion" that a *missing* row
    correctly gets -- otherwise erasure reads as cleanliness.
    """
    for i in range(5):
        await audit.emit(make_event(ts=9800.0 + i))
    assert await audit.verify_chain() is True

    for tampered in ("NULL", "'not-a-number'"):
        async with aiosqlite.connect(tmp_path / "audit.db") as conn:
            await conn.execute(
                f"UPDATE sqlite_sequence SET seq = {tampered} WHERE name = 'audit_events'"
            )
            await conn.commit()
        assert await audit.verify_chain() is False, (
            f"sqlite_sequence.seq = {tampered} must read as tampered, not raise "
            "and not pass"
        )


def test_every_audit_reader_shares_one_unreadable_rule() -> None:
    """The three readers must not drift apart on what "unreadable" means.

    This codebase's recurring defect is a rule written out twice and fixed once:
    ``_watermark`` (then ``_high_water_seq``) degraded on ``sqlite3.Error`` while the
    chain walk did not, and later ``verify_chain`` was hardened while ``query`` and
    ``length`` -- which read the same rows out of the same file -- were left raising.

    So the tuple is defined once, and this asserts the shape of that definition
    rather than trusting three ``except`` clauses to stay in step. It fails if a
    reader is added that catches its own hand-written tuple, and it fails if the
    shared tuple loses a member: ``ValueError`` and ``TypeError`` are load-bearing,
    not defensive padding -- a tampered ``ts`` reaches ``float()`` as the first and
    a lost page reaches it as the second.

    **The count went 4 -> 5 when ``emit`` gained a watermark read**, and that is the
    considered decision this assertion exists to force rather than an accounting
    detail. ``emit`` reads the same tampered ``sqlite_sequence`` row the verifier
    reads, so it needs the same definition of unreadable -- but it resolves it in the
    *opposite* direction, degrading to the surviving tail instead of failing. That
    asymmetry is deliberate and is asserted behaviourally by
    ``test_an_unreadable_watermark_degrades_the_writer_and_still_fails_the_verifier``:
    a writer that fails closed silences the pipeline, and the verifier is the
    component whose job it is to report the tamper.

    **And 5 -> 6 when ``emit``'s chain-tail read started refusing typed**, which is
    the second time this counter has done its job. The number is a census of
    implementation sites, so it goes stale whenever a site is legitimately added --
    the contract it guards (one shared definition, no hand-written tuple, a count
    nobody changed by accident) is untouched, and the sixth site is argued in the
    same breath as the fifth because the two sit in the *same method* and resolve
    in *opposite directions*. An unreadable watermark degrades: the log can still
    be appended to, and a writer that fails closed on a lost high-water mark
    silences the pipeline. An unreadable chain tail refuses: there is nothing to
    chain onto, so the only alternative to raising is releasing a run with no
    record of it. What it must NOT do is what it did -- let ``sqlite3.DatabaseError``
    escape to the ASGI layer as a bare ``500 Internal Server Error``. Asserted
    behaviourally by ``test_emit_refuses_a_corrupt_database_with_a_typed_error``
    and, at the HTTP boundary, by ``test_api.py``'s corrupt-log test.
    """
    source = Path(logger_module.__file__).read_text(encoding="utf-8")

    assert set(logger_module._UNREADABLE) == {sqlite3.Error, ValueError, TypeError}

    handlers = re.findall(r"except\s+([^\n:]+?)\s+as\s+\w+:", source)
    tuple_handlers = [h for h in handlers if h.startswith("(") or "," in h]
    assert not tuple_handlers, (
        f"a reader is catching its own hand-written tuple {tuple_handlers} instead of "
        "_UNREADABLE; that is exactly how the last two versions of this rule drifted"
    )
    # 5 -> 6: the writer's chain-tail read joined the list (see the docstring). The
    # equality is deliberately still exact -- the point of the number is that it
    # cannot move without somebody arguing for the site that moved it.
    assert source.count("except _UNREADABLE") == 6, (
        "expected the shared rule at all six sites (chain walk, the verifier's "
        "watermark call, the writer's watermark call, the writer's chain-tail read, "
        "query, length); a changed count means a reader was added or removed without "
        "this test being considered"
    )
    # The three entry points must also *answer* alike, which a source census cannot
    # see: one refusal, built in one place, so the two readers and the writer cannot
    # drift on the code a client branches on.
    assert source.count("self._unreadable(") == 3, (
        "expected emit, query and length to share one refusal constructor; a fourth "
        "call site or a hand-built AuditUnavailableError means they can drift again"
    )


def test_the_audit_emit_budget_has_a_magnitude_and_not_just_a_mechanism() -> None:
    """``AUDIT_EMIT_TIMEOUT_S`` is a *budget*, and nothing pinned how big it was.

    Both tests that exercise the gate's block-path audit write monkeypatch this
    constant to ``0.05`` so they can finish quickly. That pins the ``asyncio.timeout``
    wiring -- that a hung audit writer is interrupted at all -- and pins nothing
    about the shipped number. Raising it to ``1e9`` left the whole suite green while
    deleting the guarantee: a wedged audit writer would once again hold a request
    open forever with the block already decided, which is the exact failure the
    constant was introduced to close.

    Asserted as a *relationship* rather than a magic ceiling, because a magic
    ceiling is another unpinned number. ``AUDIT_EMIT_TIMEOUT_S`` bounds a write that
    happens after ``check()`` has already decided to block, and it is only a bound
    on anything if it is shorter than the budget of the request it is delaying --
    otherwise the caller has blown ``DEFAULT_TIMEOUT_S`` before this timer is even
    consulted, and the guarantee is vacuous.

    It is a constant assertion and not a wall-clock one on purpose: proving the
    magnitude behaviourally means stalling a sink and waiting out the entire real
    budget, which buys a slow test for a property two existing tests already cover
    the mechanism of. The gap was the number, so the number is what is pinned.

    (Lives here rather than beside the gate tests because those files belong to
    another agent in this pass. The constant is an audit-write budget, so this is
    not an unnatural home, but it is a placement to revisit.)
    """
    from secure_context_pipeline.pipeline.egress_gate import (
        AUDIT_EMIT_TIMEOUT_S,
        DEFAULT_TIMEOUT_S,
    )

    assert AUDIT_EMIT_TIMEOUT_S > 0, "a non-positive budget would fire instantly"
    assert AUDIT_EMIT_TIMEOUT_S < DEFAULT_TIMEOUT_S, (
        f"the block-path audit write may wait {AUDIT_EMIT_TIMEOUT_S}s, which is not "
        f"shorter than the request budget it delays ({DEFAULT_TIMEOUT_S}s) -- so it "
        "bounds nothing a caller can observe"
    )


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


# ---------------------------------------------------------------------------
# Golden vectors -- the one check in this file that does not import the thing
# it is checking.
# ---------------------------------------------------------------------------

#: `HMAC-SHA256(key, prev_hash + canonical_json(event_without_hashes))`, computed
#: **outside Python** -- `openssl dgst -sha256 -mac HMAC -macopt hexkey:...` fed the
#: canonical message on stdin -- and pasted here as literals.
#:
#: Every other hash assertion in this file builds its expectation by calling
#: `compute_entry_hash`/`chain_payload` -- the same functions under test -- so the
#: expectation moves with the implementation and the pair agrees no matter what the
#: implementation does. That is not a hypothetical weakness. Deleting `prev_hash +`
#: from `compute_entry_hash` leaves 88 audit tests, 164 broader tests and `demo.py`
#: 20/20 GREEN, while reducing a mid-chain forgery from re-writing every following
#: row to two UPDATE statements -- and `verify_chain()` still returns True. Dropping
#: `seq` from `chain_payload` is green the same way.
#:
#: These literals are the fixed point that cannot move with the code. If this test
#: fails, either the hash construction changed (and every previously published chain
#: is now unverifiable, which is a decision, not a refactor) or something is wrong.
#:
#: They were replaced once, and that is the decision the paragraph above anticipates:
#: the chain was keyed (README section 7 gap 16), so the pre-keying vectors
#: `ac56c5d5...` / `f72105f8...` -- plain `sha256` over the same two messages -- no
#: longer describe what the writer writes. They survive here as
#: `test_the_unkeyed_formula_is_no_longer_what_the_writer_writes`, which asserts the
#: *old* digests are now absent, so the migration is pinned in both directions
#: rather than quietly forgotten.
_CHAIN_KEY = bytes(range(32))
_GENESIS_HASH = "d908d4c89a9ded4a0caac9ff272a867811a43d9ae6933b51e7f7d1853d97a89b"
_SECOND_HASH = "0b707319d8450a813407973223d12c850db271c1a1c9cf23af8acb45b841c74c"

#: The pre-keying literals, kept as the thing that must NOT be produced.
_LEGACY_GENESIS_HASH = "ac56c5d58eed16433b8f0246c624febbf49b2b678c0e9df12641479fe241a062"
_LEGACY_SECOND_HASH = "f72105f8937439d0cec68297d7962f9afbce80d6ce2147bf4ca57a4f2e37846e"

#: `HKDF-SHA256(ikm=_GOLDEN_MASTER_KEY, salt=b"scp-v1", info=b"audit-chain")`,
#: computed by a hand-written RFC 5869 extract/expand over stdlib `hmac` -- i.e. not
#: by `cryptography`'s `HKDF`, which is what the implementation calls. Pins the
#: `info` label as well as the construction: change `b"audit-chain"` to anything
#: else and this literal stops matching, which matters because a silently different
#: label is a silently different key and every prior chain becomes unverifiable.
_GOLDEN_MASTER_KEY = bytes(range(32, 64))
_GOLDEN_AUDIT_CHAIN_KEY = "26a94a2881d0fde8681974b82af7316b9d52e8c2535656a1875c29e07435767f"


def _golden_payloads() -> tuple[dict[str, object], dict[str, object]]:
    """The two events the golden vectors above were computed over."""
    first = chain_payload(
        seq=1,
        ts=1700000000.5,
        session_id="sess-golden",
        run_id="run-golden",
        event_type="EGRESS_PASS",
        entity_type=None,
        token_id=None,
        detail={"payload_chars": 42, "reason": "ok"},
    )
    second = chain_payload(
        seq=2,
        ts=1700000000.5,
        session_id="sess-golden",
        run_id="run-golden",
        event_type="LLM_CALL",
        entity_type=None,
        token_id=None,
        detail={"payload_chars": 42, "reason": "ok"},
    )
    return first, second


def test_the_entry_hash_matches_a_hand_computed_golden_vector() -> None:
    """Pins the published formula against literals, not against itself."""
    payload, second = _golden_payloads()
    assert compute_entry_hash("", payload, key=_CHAIN_KEY) == _GENESIS_HASH

    # The link itself: the second digest is a function of the FIRST one. This is the
    # assertion that dies when `prev_hash +` is deleted.
    assert compute_entry_hash(_GENESIS_HASH, second, key=_CHAIN_KEY) == _SECOND_HASH


def test_the_entry_hash_is_a_function_of_the_key() -> None:
    """A digest that ignores the key is the scheme this replaced, wearing an argument.

    The golden vector above pins one key's output and would stay green if the key
    were accepted and dropped on the floor -- `hmac.new(key, ...)` swapped back for
    `hashlib.sha256(...)` fails it, but so does any *other* wrong construction, so it
    cannot say which. This says the specific thing: two keys, same message, two
    digests, and neither of them the unkeyed one.
    """
    payload, _ = _golden_payloads()
    other = bytes(range(1, 33))

    # The load-bearing form. Written first as `!= _GENESIS_HASH`, which was green
    # under a `hashlib.sha256(message)` mutation that ignored `key` entirely -- the
    # exact regression this test is named for -- because the unkeyed digest is also
    # not the golden literal. Two keys against each other is the only comparison a
    # key-dropping implementation cannot satisfy.
    assert compute_entry_hash("", payload, key=other) != compute_entry_hash(
        "", payload, key=_CHAIN_KEY
    )
    assert compute_entry_hash("", payload, key=other) == compute_entry_hash(
        "", payload, key=other
    ), "premise: the digest is deterministic, so the difference above is the key"


def test_the_unkeyed_formula_is_no_longer_what_the_writer_writes() -> None:
    """The migration, pinned from the other side: the old digests must not come back.

    `ac56c5d5...` is `sha256("" + canonical_json(payload))` -- the formula this
    project shipped until the chain was keyed, and the one an attacker with database
    write access can compute for themselves. A regression that dropped the key would
    reproduce it exactly, and would look like a passing suite everywhere else,
    because every other hash assertion in this file supplies whatever key the
    implementation asks for.
    """
    payload, second = _golden_payloads()

    assert hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest() == (
        _LEGACY_GENESIS_HASH
    ), "premise: the legacy literal really is the plain sha256 of this message"

    assert compute_entry_hash("", payload, key=_CHAIN_KEY) != _LEGACY_GENESIS_HASH
    assert compute_entry_hash(_GENESIS_HASH, second, key=_CHAIN_KEY) != _LEGACY_SECOND_HASH


def test_the_audit_chain_key_matches_a_hand_computed_hkdf_vector() -> None:
    """Pins the derivation and its `info` label against an independent RFC 5869 run.

    Two things could change the key without changing any behaviour the rest of this
    file can see: the `info` label, and the salt. Either one silently invalidates
    every chain written before it, which is the same class of event as changing the
    digest formula -- so it gets the same treatment, a literal computed somewhere
    else.
    """
    assert derive_audit_chain_key(_GOLDEN_MASTER_KEY).hex() == _GOLDEN_AUDIT_CHAIN_KEY

    # And it is domain-separated from the key the same master key produces for
    # documents: one leaked document key must not be a licence to rewrite history.
    assert derive_audit_chain_key(_GOLDEN_MASTER_KEY) != _hkdf(
        _GOLDEN_MASTER_KEY, b"doc:" + b"sess-golden"
    )


def test_a_short_or_empty_chain_key_is_refused_rather_than_used(tmp_path: Path) -> None:
    """`hmac.new(b"", ...)` is a publicly computable function, so the length is checked.

    An empty key is accepted without complaint by `hmac`, and a chain under one is
    exactly the unkeyed chain that was the defect -- reachable through a misread env
    var or a provider that returned `b""`. It has to fail closed at construction,
    before a single row is written under it.
    """
    for bad in (b"", bytes(31), bytes(33)):
        with pytest.raises(ConfigError) as excinfo:
            AuditLogger(tmp_path / "never-written.db", chain_key=bad)
        assert excinfo.value.detail["reason"] == "audit_chain_key_wrong_length"
    assert not (tmp_path / "never-written.db").exists()


def test_the_chain_covers_prev_hash_and_seq_behaviourally() -> None:
    """The same two properties as an attack, so neither can be argued away.

    A digest that ignores `prev_hash` is not a chain -- it is a per-row checksum, and
    every row's digest is then independent of its position and of every row before
    it. The observable consequence is the one an auditor cares about: an attacker who
    can write to the database can alter a row in the middle and repair the log by
    touching only that row.
    """
    base = dict(
        ts=1700000000.5,
        session_id="sess-golden",
        run_id=None,
        event_type="DETECT",
        entity_type=None,
        token_id=None,
        detail={"n": 1},
    )
    first = compute_entry_hash("", chain_payload(seq=1, **base), key=_CHAIN_KEY)
    # Same event content, different predecessor -> must be a different digest.
    assert compute_entry_hash("deadbeef", chain_payload(seq=1, **base), key=_CHAIN_KEY) != first
    # Same event content and predecessor, different position -> likewise.
    assert compute_entry_hash("", chain_payload(seq=2, **base), key=_CHAIN_KEY) != first


# ---------------------------------------------------------------------------
# The detail ceilings, at BOTH enforcement points and for every value type.
# ---------------------------------------------------------------------------

#: 1,540 characters of clinical note, encoded as a single integer. This is the
#: shape that walked through: `detail` is typed `int | float | str`, the ceiling
#: tested `isinstance(value, str)`, and an integer has no length.
_DOC = "Clinical note: patient Margaret Chen, MRN 40281993, dx metastatic carcinoma. " * 20
_DOC_AS_INT = int.from_bytes(_DOC.encode("utf-8"), "big")


def test_a_document_encoded_as_an_integer_is_refused_by_the_model() -> None:
    """`AuditEvent` must not accept content in any renderable type.

    Three written guarantees rested on this and all three were false: `models.py`'s
    docstring ("no field capable of holding an original value ... enforced by the
    schema rather than by convention"), `AuditEvent`'s own ("this schema *cannot
    hold* an original value"), and the README's ("the log cannot hold **content** --
    a paragraph, a note, a document").

    A 1,540-character note became a 3,709-digit int, which validated, chained,
    persisted, and came back out of `GET /audit` recoverable with one `to_bytes`.
    The quantified test that was supposed to cover this iterates `model_fields` but
    only ever tried a *string* payload -- a checker sharing the implementation's
    blind spot.
    """
    with pytest.raises(ValidationError):
        make_event(detail={"n": _DOC_AS_INT})

    # And the recovery that made it a disclosure rather than a curiosity.
    recovered = _DOC_AS_INT.to_bytes((_DOC_AS_INT.bit_length() + 7) // 8, "big").decode()
    assert recovered.startswith("Clinical note"), "premise: the int really is the document"


async def test_a_document_encoded_as_an_integer_is_refused_at_the_write_boundary(
    tmp_path: Path,
) -> None:
    """The same ceiling, on the path that skips the model validator.

    `model_construct` bypasses validation entirely, so the write boundary is the
    only thing standing between a constructed event and the row.
    """
    log = await AuditLogger.open(tmp_path / "audit.db")
    try:
        event = AuditEvent.model_construct(
            ts=1.0,
            session_id="sess-int",
            event_type=DETECT,
            detail={"n": _DOC_AS_INT},
        )
        with pytest.raises(PipelineError) as raised:
            await log.emit(event)
        assert raised.value.detail["reason"] == "audit_detail_exceeds_ceiling"
        assert await log.length() == 0, "nothing was written"
    finally:
        await log.close()


def test_an_oversized_detail_key_is_refused_by_the_model() -> None:
    """Both halves of a dict entry are bounded, not just the value."""
    with pytest.raises(ValidationError):
        make_event(detail={"k" * (MAX_DETAIL_VALUE_LEN + 1): 1})


async def test_an_oversized_detail_key_is_refused_at_the_write_boundary(tmp_path: Path) -> None:
    """The key ceiling, on the `model_construct` path. Untested at both points before."""
    log = await AuditLogger.open(tmp_path / "audit.db")
    try:
        event = AuditEvent.model_construct(
            ts=1.0,
            session_id="sess-key",
            event_type=DETECT,
            detail={"k" * (MAX_DETAIL_VALUE_LEN + 1): 1},
        )
        with pytest.raises(PipelineError) as raised:
            await log.emit(event)
        assert raised.value.detail["reason"] == "audit_detail_key_exceeds_ceiling"
        assert await log.length() == 0
    finally:
        await log.close()


# --------------------------------------------------------------------------
# 10. The write boundary re-enforces the model's TYPE rule, not only its widths.
#
# `_reject_content_sized_fields` exists because `model_construct` skips the model.
# It skips all of the model, so re-checking only the ceilings left the other half of
# `detail`'s contract -- `Mapping[str, int | float | str]` -- unenforced on the one
# path that needs it. The consequence is worse than a leak: a value the *writer*
# accepts and the *reader* refuses turns `verify_chain()` False forever, on a row
# this package wrote itself.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("shape", "value"),
    [
        ("nested dict", {"a": 1}),
        ("list", [1, 2, 3]),
        ("null", None),
    ],
)
async def test_a_non_scalar_detail_value_is_refused_at_the_write_boundary(
    tmp_path: Path, shape: str, value: object
) -> None:
    """A container `detail` value was written, and then poisoned the chain forever.

    The width check could not see it, and that is the whole mechanism: `{"k": {"a":
    1}}` renders as 13 characters of JSON and `{"k": [1,2,3]}` as 13 -- both far
    under the 64-character ceiling -- so a width-only boundary passed them and the
    INSERT ran. `_load_detail` then refused the stored column ("not a detail map"),
    which `verify_chain` reports as `detail_not_json`, so the verifier called the log
    tampered from that row onward for the rest of its life while `query()` handed the
    same row back with `detail={}` and reported nothing. `None` is the same shape by a
    different route: `str(None)` is 4 characters, and JSON `null` is not a detail
    value either.

    That is a self-inflicted denial of the audit trail's only security property, and
    it is the reverse of fail-closed: refusing the write costs one event, while
    accepting it costs every later verification. `detail` is typed `Mapping[str, int
    | float | str]`, so the type rule is as much of the contract as the ceiling, and
    the boundary now re-enforces both.

    No shipped call site uses `model_construct`, so this is a hardening gap inside the
    threat model `_reject_content_sized_fields` declares for itself -- which is
    exactly the kind that survives, because nothing exercises it.
    """
    log = await AuditLogger.open(tmp_path / "audit.db")
    try:
        await log.emit(make_event(detail={"ok": 1}))
        assert await log.verify_chain() is True, "premise: a clean log verifies"

        event = AuditEvent.model_construct(
            ts=2.0,
            session_id="sess-1",
            event_type=DETECT,
            detail={"k": value},
        )
        with pytest.raises(PipelineError) as raised:
            await log.emit(event)
        assert raised.value.detail["reason"] == "audit_detail_value_not_scalar", shape
        assert raised.value.detail["value_type"] == type(value).__name__
        assert await log.length() == 1, "nothing was written"

        # The reason refusing matters, asserted rather than described: had the row
        # landed, this assertion would be False here and on every later call.
        await log.emit(make_event(detail={"ok": 2}))
        assert await log.verify_chain() is True, (
            "a row this module wrote itself must never be one its own verifier "
            "refuses to parse"
        )
    finally:
        await log.close()


async def test_a_non_string_detail_key_is_refused_with_a_typed_error(tmp_path: Path) -> None:
    """A non-string key crashed the boundary on `len(key)` instead of refusing it.

    `TypeError: object of type 'int' has no len()` fails closed -- nothing is written
    -- but it is a raw interpreter error escaping a function whose documented
    contract is a `PipelineError`, and `api/errors.py` maps only the latter. The
    neighbouring key-ceiling test asserts the typed shape for an oversized *string*
    key; an integer key never reached that check at all.
    """
    log = await AuditLogger.open(tmp_path / "audit.db")
    try:
        event = AuditEvent.model_construct(
            ts=1.0,
            session_id="sess-key",
            event_type=DETECT,
            detail={7: 1},
        )
        with pytest.raises(PipelineError) as raised:
            await log.emit(event)
        assert raised.value.detail["reason"] == "audit_detail_key_not_a_string"
        assert raised.value.detail["key_type"] == "int"
        assert await log.length() == 0, "nothing was written"
    finally:
        await log.close()


async def test_an_integer_too_large_to_render_is_refused_as_a_ceiling_breach(
    tmp_path: Path,
) -> None:
    """The document-as-an-integer ceiling, past the size Python will render at all.

    `test_a_document_encoded_as_an_integer_is_refused_at_the_write_boundary` uses a
    1,540-character note, which encodes to 3,709 digits -- just under CPython's 4,300
    digit cap on `int` -> `str`. Triple the note and `str(value)` itself raises
    `ValueError: Exceeds the limit (4300 digits) for integer string conversion`, from
    inside the very expression that measures the width. So the *larger* smuggled
    document produced a bare interpreter error where the smaller one produced the
    documented `PipelineError` -- a boundary that gets less typed as the payload gets
    worse.

    Refusing past the interpreter's own rendering limit is a fortiori refusing past 64
    characters, so it carries the same `reason`. The exact rendered width cannot be
    reported without raising a global interpreter limit, so the floor is reported
    instead of a guess.
    """
    log = await AuditLogger.open(tmp_path / "audit.db")
    try:
        huge = int.from_bytes((_DOC * 3).encode("utf-8"), "big")
        with pytest.raises(ValueError, match="4300 digits"):
            str(huge)  # premise: this is the int the old code measured with len(str(...))

        event = AuditEvent.model_construct(
            ts=1.0,
            session_id="sess-huge",
            event_type=DETECT,
            detail={"n": huge},
        )
        with pytest.raises(PipelineError) as raised:
            await log.emit(event)
        assert raised.value.detail["reason"] == "audit_detail_exceeds_ceiling"
        assert raised.value.detail["min_length"] == sys.get_int_max_str_digits()
        assert await log.length() == 0, "nothing was written"
    finally:
        await log.close()


# --------------------------------------------------------------------------
# 11. The residual in the scoped verify: erasure by relabelling.
# --------------------------------------------------------------------------


async def _relabelled_log(path: Path, where: str) -> AuditLogger:
    """Build a six-row two-session log, then move rows out of `sess-a` behind its back."""
    log = await AuditLogger.open(path)
    for i in range(6):
        await log.emit(make_event(ts=8000.0 + i, session_id="sess-a" if i % 2 == 0 else "sess-b"))
    assert await log.verify_chain() is True, "premise: a clean log verifies"
    await log.close()

    async with aiosqlite.connect(path) as conn:
        await conn.execute(f"UPDATE audit_events SET session_id = 'sess-z' WHERE {where}")
        await conn.commit()
    return await AuditLogger.open(path)


async def test_relabelling_a_session_out_of_itself_is_a_known_residual(tmp_path: Path) -> None:
    """`verify_chain("sess-a")` is True after every one of sess-a's rows was rewritten away.

    Asserted rather than described, in the same spirit as
    `test_a_correctly_hashed_tail_append_is_a_known_residual`: the boundary of a
    security claim should be a fact the suite states.

    `UPDATE audit_events SET session_id='sess-z' WHERE session_id='sess-a'` erases
    sess-a's history as completely as `DELETE` does, and unlike `DELETE` it moves
    nothing -- every `prev_hash` link and every `seq` still holds. The structural
    checks are global precisely so a deletion is visible from the victim's scope, and
    here they have nothing to report.

    The relabelled rows do fail their own `entry_hash`, because `session_id` is inside
    the hashed payload, and *both* checks that can see that failure report it: the
    unscoped walk, and the scope of the session the rows were moved into. Only the
    victim's own scope answers True.

    That is not a patchable oversight. A relabelled row is, column for column, a row
    whose stored `session_id` names another session and whose hash does not recompute
    -- the identical input class as an ordinary tampered row genuinely belonging to
    that other session, which `test_tamper_is_scoped_to_the_affected_session` pins as
    *not* failing an unrelated scope. The pre-tamper `session_id` is inside the digest
    the tamper destroyed, so no walk can recover it and no rule can tell the two
    apart. Charging every unattributable hash break against every scope would close
    this and would flip that test's third assertion: a different design, not a fix.

    So the scoped form's honest contract is "the rows *labelled* with this session are
    intact, and the log they sit in is structurally whole" -- not "no record of this
    session has been taken out of it". Only the unscoped form answers the second.
    """
    log = await _relabelled_log(tmp_path / "audit.db", "session_id = 'sess-a'")
    try:
        # The checks that can see it, and must keep seeing it.
        assert await log.verify_chain() is False, (
            "the whole-log answer is the one a compliance check must rely on"
        )
        assert await log.verify_chain(session_id="sess-z") is False, (
            "the receiving scope holds rows whose hashes do not recompute"
        )
        # An untouched bystander is unaffected, which is the scoping rule working.
        assert await log.verify_chain(session_id="sess-b") is True

        # The residual, asserted rather than described.
        assert await log.length(session_id="sess-a") == 0, "premise: sess-a was erased"
        assert await log.verify_chain(session_id="sess-a") is True, (
            "erasure-by-relabel is now detected from the victim's own scope -- if that "
            "is a deliberate improvement, delete this test and update the "
            "verify_chain docstring and README section 5 Q5, which document the gap "
            "it pins"
        )
    finally:
        await log.close()


async def test_a_partial_relabel_is_invisible_to_the_scope_it_left(tmp_path: Path) -> None:
    """Two of sess-a's three rows moved away, and sess-a still verifies True.

    This exists to kill the tempting narrow fix. "The scope has no rows left, so it
    has no positive evidence about itself" looks like a usable signal -- it is the
    difference between the deletion case (caught globally, by structure) and the
    relabel case -- and it would close the total erasure in the test above.

    It closes nothing. Relabel two of a session's three rows and the survivor is still
    in scope, still hashes correctly, and still links, so an emptiness rule never
    fires while two thirds of the session's history has been rewritten away. The
    scoped answer degrades continuously, not at zero, which is why the residual is a
    property of what a hashed `session_id` can be asked after it has been overwritten
    and not a threshold anyone can pick.
    """
    log = await _relabelled_log(tmp_path / "audit.db", "seq IN (1, 3)")
    try:
        assert await log.length(session_id="sess-a") == 1, "premise: one row was left behind"
        assert await log.verify_chain() is False, "the whole-log answer still catches it"
        assert await log.verify_chain(session_id="sess-a") is True, (
            "a non-empty in-scope slice is why 'the scope is empty' cannot be the rule"
        )
    finally:
        await log.close()


# ---------------------------------------------------------------------------
# detail['action'] -- the explicitly-named required field, on BOTH halves
# ---------------------------------------------------------------------------


async def test_every_event_type_carries_an_explicit_action(audit: AuditLogger) -> None:
    """Requirement 7 names five fields; ``action`` was written by one half of the pair.

    Measured before the fix, on a two-run session driven end to end: ``OBFUSCATE``
    rows with ``detail['action']`` **0 of 8**, ``DEOBFUSCATE`` **8 of 10** (the
    per-entity rows had it, the stage rows did not), ``DETECT`` / ``EGRESS_PASS`` /
    ``LLM_CALL`` **0 of everything**. "``event_type`` is the action" is a defensible
    reading; a reader diffing the two halves of the round trip and finding the field
    populated on one and absent on the other cannot tell that reading from a missing
    write.

    Quantified over ``EVENT_TYPES`` rather than over a hand-written list, for the
    same reason the ceiling test enumerates ``model_fields``: a thirteenth event type
    must fail this until somebody decides what its action is called.
    """
    for event_type in sorted(EVENT_TYPES):
        await audit.emit(make_event(event_type=event_type, detail={"count": 1}))

    rows = await audit.query(limit=1000)
    assert {row.event_type for row in rows} == EVENT_TYPES
    missing = [row.event_type for row in rows if ACTION_KEY not in row.detail]
    assert not missing, f"event types written with no action: {missing}"
    for row in rows:
        assert row.detail[ACTION_KEY] == EVENT_ACTIONS[row.event_type]
        # It is a label, never content: the schema's own ceiling has to hold for it.
        assert len(str(row.detail[ACTION_KEY])) <= MAX_DETAIL_VALUE_LEN


async def test_a_caller_that_already_named_its_action_keeps_it(audit: AuditLogger) -> None:
    """The default fills a gap; it does not overwrite an answer.

    The value used here is deliberately **not** one of the defaults, and the first
    version of this test was worthless for exactly that reason: it emitted a
    ``DEOBFUSCATE`` row carrying ``action='restore'``, which is what
    ``EVENT_ACTIONS[DEOBFUSCATE]`` already is -- so an implementation that
    *overwrote* every caller's value was byte-identical to one that respected it, and
    a sabotage swapping ``setdefault`` for a plain assignment left the suite green.

    The rule being pinned is the writer's, not any current call site's: a caller that
    says what it did keeps saying it. Today only ``restorer.py`` names an action and
    it happens to agree with the default; the moment one does not -- a partial
    restore, a replay, a compensating write -- the distinction is the whole value of
    the field, and nothing else in the suite would notice it being erased.
    """
    await audit.emit(
        make_event(
            event_type=DEOBFUSCATE, detail={"action": "restore_partial", "occurrences": 2}
        )
    )
    await audit.emit(make_event(event_type=OBFUSCATE, detail={"occurrences": 2}))

    restore_row, obfuscate_row = await audit.query(limit=10)
    assert restore_row.detail[ACTION_KEY] == "restore_partial", (
        "the writer clobbered a caller-supplied action with the event type's default"
    )
    assert restore_row.detail[ACTION_KEY] != EVENT_ACTIONS[DEOBFUSCATE], (
        "this assertion is only binding while the value differs from the default"
    )
    assert obfuscate_row.detail[ACTION_KEY] == "obfuscate"


async def test_the_action_is_inside_the_hash_chain_not_beside_it(audit: AuditLogger) -> None:
    """The filled-in field is part of what is signed, or it is not tamper-evident.

    An ``action`` added to the column after the digest was computed would be a field
    an attacker could rewrite freely while ``verify_chain()`` stayed ``True``. The
    check here is the published formula recomputed by hand over the row as stored.
    """
    await audit.emit(make_event(event_type=OBFUSCATE, detail={"occurrences": 2}))
    (row,) = await audit.query(limit=10)

    assert row.detail[ACTION_KEY] == "obfuscate"
    recomputed = compute_entry_hash(
        GENESIS_HASH,
        chain_payload(
            seq=row.seq or 0,
            ts=row.ts,
            session_id=row.session_id,
            run_id=row.run_id,
            event_type=row.event_type,
            entity_type=row.entity_type,
            token_id=row.token_id,
            detail=dict(row.detail),
        ),
        key=stolen_chain_key(),
    )
    assert recomputed == row.entry_hash
    # And the same digest is NOT reachable from the detail the caller passed in.
    without_action = {k: v for k, v in row.detail.items() if k != ACTION_KEY}
    assert (
        compute_entry_hash(
            GENESIS_HASH,
            chain_payload(
                seq=row.seq or 0,
                ts=row.ts,
                session_id=row.session_id,
                run_id=row.run_id,
                event_type=row.event_type,
                entity_type=row.entity_type,
                token_id=row.token_id,
                detail=without_action,
            ),
            key=stolen_chain_key(),
        )
        != row.entry_hash
    )
    assert await audit.verify_chain() is True


# ---------------------------------------------------------------------------
# emit_many -- one transaction per batch, the same chain
# ---------------------------------------------------------------------------


async def test_emit_and_emit_many_write_byte_identical_rows(tmp_path: Path) -> None:
    """The batch path is not a second implementation of the chain.

    ``emit`` is a batch of one, so this is a regression test on the delegation as
    much as on ``emit_many``: two fresh logs, the same events, one written row by
    row and one in a single transaction, compared column by column -- ``seq``,
    ``prev_hash`` and ``entry_hash`` included. If a future edit gives the batch path
    its own tail read or its own hash input, this is what notices.
    """
    events = [
        make_event(
            ts=1000.0 + i,
            event_type=OBFUSCATE if i % 2 else DEOBFUSCATE,
            token_id=f"{i:08x}",
            detail={"occurrences": i, "strategy": "tokenization"},
        )
        for i in range(40)
    ]

    def columns(event: AuditEvent) -> tuple[object, ...]:
        return (
            event.seq, event.ts, event.session_id, event.run_id, event.event_type,
            event.entity_type, event.token_id, tuple(sorted(event.detail.items())),
            event.prev_hash, event.entry_hash,
        )

    one = await AuditLogger.open(tmp_path / "one.db")
    try:
        seqs_one = [await one.emit(event) for event in events]
        rows_one = [columns(row) for row in await one.query(limit=1000)]
        assert await one.verify_chain() is True
    finally:
        await one.close()

    many = await AuditLogger.open(tmp_path / "many.db")
    try:
        seqs_many = await many.emit_many(events)
        rows_many = [columns(row) for row in await many.query(limit=1000)]
        assert await many.verify_chain() is True
        assert await many.verify_chain(session_id="sess-1") is True
    finally:
        await many.close()

    assert seqs_one == seqs_many == list(range(1, len(events) + 1))
    assert rows_one == rows_many


async def test_a_batch_preserves_order_and_chains_onto_what_came_before(
    audit: AuditLogger,
) -> None:
    """Batching must not reorder, merge, or drop -- and must extend the tail it found.

    The failure this forbids is the tempting one: sorting, de-duplicating, or
    collapsing "identical" rows inside the transaction. Every event goes in, in the
    order given, and the first row of the batch chains onto the row that was already
    the tail.
    """
    first = await audit.emit(make_event(ts=1.0, event_type=SESSION_CREATE))
    batch = [
        make_event(ts=2.0 + i, event_type=DEOBFUSCATE, token_id=f"{i:08x}")
        for i in range(5)
    ]
    # A deliberate duplicate: two rows describing the same token must stay two rows.
    batch.append(batch[0])
    seqs = await audit.emit_many(batch)

    assert seqs == list(range(first + 1, first + 1 + len(batch)))
    rows = await audit.query(limit=100)
    assert len(rows) == 1 + len(batch)
    assert [row.token_id for row in rows[1:]] == [e.token_id for e in batch]
    assert rows[1].prev_hash == rows[0].entry_hash, "the batch chained onto the old tail"
    for previous, current in itertools.pairwise(rows):
        assert current.prev_hash == previous.entry_hash
    assert await audit.verify_chain() is True

    # A second batch keeps going from there, and an empty one writes nothing.
    assert await audit.emit_many([]) == []
    assert await audit.length() == 1 + len(batch)
    more = await audit.emit_many(batch[:2])
    assert more == [seqs[-1] + 1, seqs[-1] + 2]
    assert await audit.verify_chain() is True


async def test_a_batch_opens_one_transaction_rather_than_one_per_row(
    audit: AuditLogger,
) -> None:
    """The cost claim, measured on the mechanism rather than on a stopwatch.

    A latency number belongs in ``test_benchmarks.py`` and moves with the machine.
    What does not move is the transaction count: 512 per-entity ``DEOBFUSCATE`` rows
    cost 512 ``BEGIN IMMEDIATE``/``COMMIT`` cycles, each with its own watermark read
    and chain-tail read, and that -- not the vault or the string rebuild -- was the
    dominant term in the restore stage. Counting the statements is what keeps the
    fix from being silently undone by a refactor that reintroduces a per-row loop.
    """
    conn = audit._connection()
    statements: list[str] = []
    original_execute = conn.execute

    def recording_execute(sql: str, *args: object, **kwargs: object) -> object:
        statements.append(" ".join(str(sql).split())[:40])
        return original_execute(sql, *args, **kwargs)

    events = [make_event(ts=float(i), event_type=OBFUSCATE) for i in range(50)]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(conn, "execute", recording_execute)
        await audit.emit_many(events)

    assert statements.count("BEGIN IMMEDIATE") == 1, statements[:8]
    assert sum(s.startswith("INSERT INTO audit_events") for s in statements) == len(events)
    # The high-water mark is bumped once, with the batch's last seq -- the table's
    # own trigger makes the mark monotonic, so bumping to the last covers them all.
    assert sum(s.startswith("INSERT INTO audit_chain_meta") for s in statements) == 1
    assert await audit.verify_chain() is True
    assert await audit.length() == len(events)


async def test_a_batch_that_is_refused_writes_none_of_its_rows(audit: AuditLogger) -> None:
    """Validation runs before the transaction opens, so a bad row leaves no partial log.

    The ceilings are re-checked at the write boundary because ``model_construct``
    skips the model's own validators. In a batch that check has to run over *every*
    event before anything is inserted -- otherwise a document-sized value in row 400
    leaves 399 rows committed and the caller with an exception, which is the shape
    that makes a truncated itemisation look like a complete one.
    """
    good = make_event(ts=1.0, event_type=OBFUSCATE)
    poisoned = AuditEvent.model_construct(
        ts=2.0,
        session_id="sess-1",
        run_id="run-1",
        event_type=OBFUSCATE,
        entity_type="PHI_NAME",
        token_id="1a2b3c4d",
        detail={"note": "x" * (MAX_DETAIL_VALUE_LEN + 1)},
    )

    with pytest.raises(PipelineError) as excinfo:
        await audit.emit_many([good, poisoned, good])
    assert excinfo.value.detail["reason"] == "audit_detail_exceeds_ceiling"
    assert await audit.length() == 0, "the good rows must not have been committed"
    assert await audit.verify_chain() is True


def test_the_action_vocabulary_cannot_drift_from_the_event_vocabulary() -> None:
    """One rule, two modules, asserted rather than trusted to stay in step.

    The event-type constants live here in ``audit/logger.py``; the action labels live
    beside the model that the writer stamps them onto, because ``models.py`` cannot
    import this module. That duplication is the shape this codebase has been bitten
    by before (``_UNREADABLE``), so it is closed the same way: an import-time
    assertion, plus this test, so a thirteenth event type is a hard failure rather
    than a row that quietly ships without the field requirement 7 names.

    The ceiling matters as much as the coverage. ``_reject_content_sized_fields``
    refuses any detail value over 64 rendered characters, and the writer adds this one
    itself -- a label that broke the ceiling would make the audit writer start
    refusing rows because of its own constant, on the write path, in production.
    """
    assert frozenset(EVENT_ACTIONS) == EVENT_TYPES
    assert EVENT_ACTIONS is AUDIT_ACTIONS, "logger must re-export, not re-declare"
    assert ACTION_KEY == AUDIT_ACTION_KEY == "action"
    for event_type, action in EVENT_ACTIONS.items():
        assert action, event_type
        assert len(action) <= MAX_DETAIL_VALUE_LEN, (event_type, action)
        assert len(ACTION_KEY) <= MAX_DETAIL_VALUE_LEN
    # The two halves of the round trip must be distinguishable, or "action" carries
    # nothing a reader could filter on.
    assert EVENT_ACTIONS[OBFUSCATE] != EVENT_ACTIONS[DEOBFUSCATE]


def test_the_stage_row_and_the_itemisation_do_not_share_one_action_label() -> None:
    """``DEOBFUSCATE`` is written in two shapes, and the action must tell them apart.

    Regression test for a defect this file's own change introduced. ``DEOBFUSCATE``
    covers both a per-entity itemisation (one row per restored token ID, naming its
    own ``action`` via ``restorer.RESTORE_ACTION``) and a *stage* row summarising the
    whole restore -- counts, outcome, latency, both label columns NULL. Readers
    separate the two by that field, because a query by event type returns them
    together.

    Defaulting the stage row to the same ``"restore"`` collapsed the discriminator,
    and seven tests in ``test_deobfuscation.py`` started counting the stage row as an
    entity. Requirement 7 wants *both* shapes to carry an action; it does not want
    them to carry the *same* one. Asserted against the restorer's own constant rather
    than a repeated literal, so renaming either side fails here instead of silently
    re-colliding.
    """
    from secure_context_pipeline.deobfuscation.restorer import RESTORE_ACTION

    assert EVENT_ACTIONS[DEOBFUSCATE] != RESTORE_ACTION, (
        "the stage row's default action must differ from the per-entity rows', or the "
        "only thing separating the two shapes of a DEOBFUSCATE row is gone"
    )
    # Both still readable as de-obfuscation, so a compliance filter on the action
    # prefix sees the whole half of the round trip.
    assert EVENT_ACTIONS[DEOBFUSCATE].startswith("restore")
    assert RESTORE_ACTION.startswith("restore")


# ---------------------------------------------------------------------------
# The event types OUTSIDE `EVENT_TYPES` -- requirement 7 does not stop at twelve
# ---------------------------------------------------------------------------


class _EmitSite(NamedTuple):
    """One ``AuditEvent(...)`` construction the package performs."""

    event_type: str
    file: str
    line: int
    #: Keys of the ``detail`` dict *literal* at this site, or ``None`` when the
    #: argument is not a literal (a variable, a comprehension) and so cannot be read.
    detail_keys: frozenset[str] | None


def _emit_sites() -> tuple[list[_EmitSite], list[tuple[str, int, str]]]:
    """Every ``event_type=`` the PACKAGE passes, discovered from its own source.

    ``test_every_event_type_carries_an_explicit_action`` quantifies over
    :data:`EVENT_TYPES`, and that is exactly as far as it can see.
    ``AUDIT_ACCESS_DENIED`` goes through the same writer and is chained like any
    other row, but is deliberately **not** in that frozenset -- so it sat outside the
    coverage of every action test in this file and shipped without the field.

    Nothing about "twelve" is load-bearing here. What is load-bearing is that the set
    is *discovered from the code that emits*, so a fourteenth type added tomorrow is
    caught by this sweep rather than by somebody remembering to extend a list.

    Two kinds of call site, told apart rather than lumped together:

    *Decisions* -- the ``event_type`` argument is a string literal or a module-level
    constant, i.e. this line CHOOSES the type. These are what the caller checks.

    *Forwarding* -- the argument is a parameter, an attribute or a value read back
    out of a row (``str(row["event_type"])``). The choice was made by whoever called
    it, and that caller is itself in this sweep. Returned separately so a caller can
    assert none of them is a literal: that is what stops a new event type hiding in
    the bucket this function admits it cannot resolve.
    """
    package_root = Path(logger_module.__file__).resolve().parents[1]
    decisions: list[_EmitSite] = []
    forwarded: list[tuple[str, int, str]] = []
    for path in sorted(package_root.rglob("*.py")):
        relative = str(path.relative_to(package_root))
        module_name = "secure_context_pipeline." + relative.removesuffix(".py").replace("/", ".")
        module_name = module_name.removesuffix(".__init__")
        namespace: dict[str, object] | None = None
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        # A loop variable bound to a tuple of module constants is still a decision --
        # `for event_type in (SESSION_EXPIRE, VAULT_DESTROY)` chooses two types in one
        # statement, and reading it as "forwarding" would have hidden SESSION_EXPIRE,
        # the one type in the vocabulary emitted this way. Scoped per function so a
        # same-named parameter elsewhere in the module cannot borrow the binding.
        loop_bindings: dict[ast.AST, dict[str, list[str]]] = {}
        for scope in ast.walk(tree):
            if not isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef | ast.Module):
                continue
            bound: dict[str, list[str]] = {}
            for node in ast.walk(scope):
                if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
                    continue
                if not isinstance(node.iter, ast.Tuple | ast.List):
                    continue
                if namespace is None:
                    namespace = vars(importlib.import_module(module_name))
                values = [
                    str(namespace[element.id])
                    for element in node.iter.elts
                    if isinstance(element, ast.Name) and isinstance(namespace.get(element.id), str)
                ]
                if len(values) == len(node.iter.elts):
                    bound[node.target.id] = values
            if bound:
                loop_bindings[scope] = bound
        in_scope: dict[str, list[str]] = {}
        for bound in loop_bindings.values():
            in_scope.update(bound)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            argument = next((kw.value for kw in node.keywords if kw.arg == "event_type"), None)
            if argument is None:
                continue
            if namespace is None:
                namespace = vars(importlib.import_module(module_name))
            values: list[str] = []
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                values = [argument.value]
            elif isinstance(argument, ast.Name):
                resolved = namespace.get(argument.id)
                if isinstance(resolved, str):
                    values = [resolved]
                else:
                    values = list(in_scope.get(argument.id, ()))
            if not values:
                forwarded.append((relative, argument.lineno, type(argument).__name__))
                continue
            detail = next((kw.value for kw in node.keywords if kw.arg == "detail"), None)
            keys: frozenset[str] | None = None
            if isinstance(detail, ast.Dict):
                literal: set[str] = set()
                for key in detail.keys:
                    # Both spellings a detail key can take at a call site: the string
                    # itself, and a module constant holding it. Resolving the second
                    # is what stops `EMITTED_STRATEGY_KEY: ...` style keys -- which
                    # this package uses -- from reading as "no such key".
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        literal.add(key.value)
                    elif isinstance(key, ast.Name) and isinstance(namespace.get(key.id), str):
                        literal.add(str(namespace[key.id]))
                keys = frozenset(literal)
            decisions.extend(
                _EmitSite(value, relative, argument.lineno, keys) for value in values
            )
    return decisions, forwarded


def test_the_emit_site_sweep_sees_the_whole_vocabulary_and_the_outsider() -> None:
    """Premise of the test below, held separately so it cannot go vacuous.

    A sweep that silently stopped resolving names would return no decision sites, and
    "every discovered type carries an action" would then pass by finding nothing. So
    the sweep's own coverage is asserted first: every one of the twelve found at a
    real emit site, at least one type outside them, and -- the part that matters --
    **no forwarding site is a literal**, because a literal in that bucket would be an
    event type the sweep decided not to look at.
    """
    decisions, forwarded = _emit_sites()
    literal_forwards = [entry for entry in forwarded if entry[2] == "Constant"]
    assert not literal_forwards, (
        f"an event_type literal landed in the forwarding bucket, so the sweep is "
        f"not seeing every decision: {literal_forwards}"
    )
    found = {site.event_type for site in decisions}
    assert EVENT_TYPES <= found, (
        f"types in EVENT_TYPES that nothing in the package emits: {sorted(EVENT_TYPES - found)}"
    )
    assert found - EVENT_TYPES, (
        "no emitted event type sits outside EVENT_TYPES any more; if that is a "
        "deliberate change the test below has nothing left to guard"
    )


def test_an_event_type_outside_the_vocabulary_names_its_own_action() -> None:
    """A type the writer cannot default for must name ``action`` at every emit site.

    ``AuditLogger.emit`` fills ``detail['action']`` from
    :data:`~secure_context_pipeline.models.AUDIT_ACTIONS`, which is keyed by
    :data:`EVENT_TYPES`. A type outside that vocabulary gets **nothing**, and that is
    what ``AUDIT_ACCESS_DENIED`` shipped as: driven through the production emitter
    ``deps._deny_audit_scope``, the written row was
    ``{'claimed_user_id', 'route', 'scope_resolved'}`` -- the one of the thirteen
    types reaching the writer without the field core requirement 7 names.

    Adding it to ``EVENT_TYPES`` would supply the action and falsify that frozenset's
    own "section 7 vocabulary, verbatim and complete", which ``test_readme_claims.py``
    asserts. The resolution is the one the writer already allows for (``setdefault``,
    not assignment): the emitter names it. Held structurally, at every construction
    site, because "the one emitter remembers" is precisely the property that was
    already false once -- and a second emitter added later would be a second silent
    row rather than a failure here.
    """
    decisions, _ = _emit_sites()
    outside = [site for site in decisions if site.event_type not in EVENT_TYPES]
    assert outside, "premise: at least one emit site is outside the writer's vocabulary"
    silent = [
        f"{site.file}:{site.line} ({site.event_type})"
        for site in outside
        if site.detail_keys is None or ACTION_KEY not in site.detail_keys
    ]
    assert not silent, (
        f"emit sites for a type the writer cannot default an action for, whose detail "
        f"does not name one: {silent}"
    )


async def test_the_thirteenth_event_type_is_written_with_an_action(tmp_path: Path) -> None:
    """The behaviour, driven through the production emitter rather than a stand-in.

    The structural test above reads the source; this one runs
    ``deps._deny_audit_scope`` -- the only code path that writes this event type --
    against a real hash-chained log and reads the stored row back. A synthetic
    ``audit.emit(AuditEvent(event_type=AUDIT_ACCESS_DENIED, ...))`` would prove the
    opposite of what is wanted: it *still* comes out without an action, because the
    writer has no default for this type and never will. The action is the emitter's.

    Also pinned here: the row stays outside ``EVENT_TYPES``, the label respects the
    writer's own detail ceiling, and the chain still verifies with the extra field
    inside the digest.
    """
    from secure_context_pipeline.api import deps
    from secure_context_pipeline.api.constants import AUDIT_ACCESS_DENIED

    log = await AuditLogger.open(tmp_path / "denied.db")
    try:
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/audit",
                "raw_path": b"/audit",
                "query_string": b"",
                "headers": [],
                "client": ("203.0.113.7", 51234),
                "server": ("testserver", 80),
                "scheme": "http",
                "root_path": "",
                "app": SimpleNamespace(state=SimpleNamespace()),
            }
        )
        await deps._deny_audit_scope(
            request,
            SimpleNamespace(audit=log),  # type: ignore[arg-type]
            deps._AuditScope(session_id=None, owner=None),
            user_id="mallory",
            run_id=None,
        )

        rows = await log.query(limit=10)
        assert len(rows) == 1, rows
        row = rows[0]
        assert row.event_type == AUDIT_ACCESS_DENIED
        assert AUDIT_ACCESS_DENIED not in EVENT_TYPES, (
            "the type moved into the writer's vocabulary; README section 2 and "
            "test_readme_claims.py both say it is deliberately outside it"
        )
        assert ACTION_KEY in row.detail, (
            f"the deny row still ships without an action: {dict(row.detail)}"
        )
        action = str(row.detail[ACTION_KEY])
        assert action, "an empty action is not an action"
        assert len(action) <= MAX_DETAIL_VALUE_LEN
        # A fixed label, not anything the caller supplied: the claimed user_id is in
        # its own clamped field and must not be smuggled into this one.
        assert "mallory" not in action
        assert await log.verify_chain() is True
    finally:
        await log.close()
