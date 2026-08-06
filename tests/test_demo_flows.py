"""``demo.py``'s flows -- the artefact a reviewer runs first, and its exit code.

``tests/test_demo.py`` pins one function (the leak scanner's classification rule).
This module covers the rest of the file: the probe selection that decides *what*
the destruction check proves, the fail-closed and destruction demonstrations
themselves, the wire-dump scan, the chain-only entry point, and ``main`` -- above
all the property the whole file exists to provide, that **a failed assertion is a
non-zero exit status**. A demo that printed ``FAIL`` and exited 0 would be worse
than no smoke test at all, because CI would be green.

Everything here runs on ``MockProvider`` with ``data_dir`` under ``tmp_path``; no
network, no API key, and nothing written to the repository's real ``./data`` or to
``wire_dump.txt``.
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from secure_context_pipeline.audit.logger import (
    DEFAULT_DB_FILENAME as AUDIT_DB_FILENAME,
)
from secure_context_pipeline.audit.logger import (
    SESSION_CREATE,
    AuditLogger,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import ConfigError, PipelineError
from secure_context_pipeline.llm.mock_provider import MockProvider
from secure_context_pipeline.models import AuditEvent

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_demo() -> ModuleType:
    """Import ``demo.py`` by path -- it is a root script, not a package member."""
    spec = importlib.util.spec_from_file_location("_demo_flows_under_test", REPO_ROOT / "demo.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_demo_flows_under_test"] = module
    spec.loader.exec_module(module)
    return module


demo = _load_demo()

#: A literal that is in ``fixtures/medical_note.txt`` and must never be in a payload.
#: Written out here rather than parsed from the file, so this module never agrees
#: with the demo about what it is looking for.
MEDICAL_EMAIL = "david.ochoa@example.com"

#: Process prose with no names, numbers, dates or identifiers -- what a
#: reviewer-supplied file with nothing to detect looks like to the pipeline.
NO_ENTITY_DOCUMENT = (
    "Operational Checklist\n\n"
    "The quarterly review process was completed.\n"
    "All procedures followed the standard operating guidelines.\n"
    "Recommendations will be circulated after the next scheduled meeting.\n"
    "No further action is required at this time.\n"
)


@pytest.fixture
async def harness(settings: Settings) -> AsyncIterator[Any]:
    """The demo's own wiring, on the mock provider and an isolated data dir."""
    built = await demo.build_harness(settings, MockProvider())
    try:
        yield built
    finally:
        await built.close()


def _fake_outcome(
    *,
    response: str,
    payload: str,
    strategy: str,
    surrogates: tuple[str, ...] = (),
) -> Any:
    """A stand-in ``RunOutcome`` carrying only the fields ``build_probe`` reads."""
    return demo.RunOutcome(
        result=SimpleNamespace(
            raw_llm_response=response,
            obfuscated_payload=payload,
            strategy=strategy,
            detections=[SimpleNamespace(surrogate=s) for s in surrogates],
        ),
        doc_id="doc-1",
        wall_s=0.0,
    )


# ---------------------------------------------------------------------------
# ScanResult arithmetic and the text a reviewer reads off the screen
# ---------------------------------------------------------------------------
def test_leaks_subtracts_the_substring_only_hits_from_the_raw_hits() -> None:
    """``hits`` is what the scan found; ``leaks`` is what is actually a disclosure.

    ``dump_wire`` asserted on the wrong one of these two and failed a real
    ``--real --dump-wire`` run over a non-leak, so the arithmetic is pinned here.
    """
    result = demo.ScanResult(hits=5, scanned=9, skipped_short=1, substring_only=2)
    assert result.leaks == 3
    assert "3 found" in result.detail


def test_the_detail_line_reports_scanned_and_skipped_as_separate_counts() -> None:
    """The exclusion of short values is printed, not folded into the scanned count."""
    result = demo.scan_for_originals(
        "Prepared by Vandenberg for Dr Li.", frozenset({"Vandenberg", "Li", "Ochoa"})
    )
    assert result.skipped_short == 1
    assert result.scanned == 2
    assert "2 vault originals scanned" in result.detail
    assert "1 skipped" in result.detail
    assert "not counted as a leak" not in result.detail


def test_a_value_that_matches_only_after_normalisation_is_still_a_leak() -> None:
    """Case and whitespace differences do not hide an original from the scan.

    The vault keys on the normalised form, so a payload carrying ``john smith``
    while the vault holds ``John  SMITH`` is the same disclosure.
    """
    result = demo.scan_for_originals(
        "The referring clinician was john smith.", frozenset({"John  SMITH"})
    )
    assert result.leaks == 1, result.detail
    assert result.substring_only == 0, result.detail


# ---------------------------------------------------------------------------
# residual_tokens
# ---------------------------------------------------------------------------
def test_residual_tokens_returns_every_surviving_surrogate_and_nothing_else() -> None:
    """Restored output must contain no surrogates; redaction markers are not surrogates.

    A ``[REDACTED_...]`` marker is a deliberate, permanent removal -- reporting it
    as residue would fail every run that redacted anything.
    """
    text = (
        "Seen by [PHI_NAME_a1b2c3d4] on Tuesday; contact [PII_EMAIL_00ff11ee] "
        "or the desk. Address [REDACTED_ADDRESS] withheld."
    )
    assert demo.residual_tokens(text) == ["[PHI_NAME_a1b2c3d4]", "[PII_EMAIL_00ff11ee]"]
    assert demo.residual_tokens("Seen by David Ochoa on Tuesday. [REDACTED_ADDRESS]") == []


# ---------------------------------------------------------------------------
# build_probe -- what the destruction check is allowed to prove
# ---------------------------------------------------------------------------
def test_build_probe_prefers_a_response_carrying_tokens_over_one_carrying_pseudonyms() -> None:
    """A token forces a vault lookup on restore; a pseudonym only might.

    The token-bearing run is chosen even when a pseudonym-bearing run comes first
    in the list, because the whole point of the probe is that the post-destroy
    attempt *has* to reach the vault.
    """
    pseudonym_only = _fake_outcome(
        response="Alan Browning signed it.",
        payload="Alan Browning signed it.",
        strategy="pseudonymization",
        surrogates=("Alan Browning",),
    )
    with_tokens = _fake_outcome(
        response="[PHI_NAME_ff00aa11] and [PHI_NAME_0011bbcc] were discussed.",
        payload="[PHI_NAME_ff00aa11], [PHI_NAME_0011bbcc] and [PII_EMAIL_9999dddd].",
        strategy="tokenization",
    )

    probe = demo.build_probe([pseudonym_only, with_tokens])

    assert probe is not None
    assert probe.strategy == "tokenization"
    assert probe.token_id == "0011bbcc"  # sorted first of the two in the response
    assert probe.surrogate is None
    assert probe.surrogate_map is None
    # `minted` is what the *payload* issued, not what the response echoed: the
    # restorer is gated on it, and a response-derived set would drop the third
    # token and leave the gate wider than the producing run.
    assert probe.minted == frozenset({"ff00aa11", "0011bbcc", "9999dddd"})
    assert "tokenization" in probe.source


def test_build_probe_falls_back_to_a_pseudonym_the_model_echoed_back() -> None:
    """With no tokens anywhere, the probe is a pseudonym that is actually in the response.

    An empty mapped value is the restorer's documented "look it up in the vault"
    fallback, so the lookup -- and therefore the post-destroy failure -- still happens.
    """
    outcome = _fake_outcome(
        response="Alan Browning met the auditor in March.",
        payload="Alan Browning met the auditor in March.",
        strategy="pseudonymization",
        surrogates=("Marguerite Delacroix", "Alan Browning"),
    )

    probe = demo.build_probe([outcome])

    assert probe is not None
    assert probe.token_id is None
    assert probe.surrogate == "Alan Browning"
    assert probe.surrogate_map == {"Alan Browning": ""}
    assert probe.minted == frozenset()
    assert "pseudonym" in probe.source


def test_build_probe_returns_none_when_no_run_would_reach_the_vault() -> None:
    """No token, no echoed pseudonym -- no probe, rather than a probe that proves nothing.

    ``demonstrate_destruction`` turns this ``None`` into a recorded failure; a probe
    invented here would "succeed" after destruction for the wrong reason.
    """
    outcome = _fake_outcome(
        response="The summary is unremarkable.",
        payload="Marguerite Delacroix filed it.",
        strategy="pseudonymization",
        surrogates=("Marguerite Delacroix",),
    )
    assert demo.build_probe([outcome]) is None
    assert demo.build_probe([]) is None


# ---------------------------------------------------------------------------
# The assertion ledger -- where the exit code comes from
# ---------------------------------------------------------------------------
def test_a_failed_fatal_check_makes_the_banner_return_a_nonzero_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The ledger is the exit code. One fatal failure is enough to fail the run."""
    checks = demo.CheckList()
    checks.record("this one holds", True, "detail")
    checks.record("this one does not", False, "why not")

    code = checks.banner(1.0)

    assert code == demo.EXIT_ASSERTION_FAILED
    assert code != 0
    assert [c.name for c in checks.failures] == ["this one does not"]
    assert checks.warnings == []
    out = capsys.readouterr().out
    assert "FAIL -- 1 assertion(s) failed" in out
    assert "1/2 checks passed" in out


def test_a_non_fatal_check_is_a_warning_and_does_not_change_the_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A reviewer-supplied file with nothing to detect must not fail the demo."""
    checks = demo.CheckList()
    checks.record("nothing to detect here", False, "0 originals", fatal=False)

    code = checks.banner(1.0)

    assert code == demo.EXIT_OK
    assert checks.failures == []
    assert [c.name for c in checks.warnings] == ["nothing to detect here"]
    out = capsys.readouterr().out
    assert "[WARN]" in out
    assert "1 warning(s)" in out
    assert "FAIL" not in out


# ---------------------------------------------------------------------------
# Layout logic that decides what the reviewer is shown
# ---------------------------------------------------------------------------
def test_document_body_extracts_the_fenced_document_and_falls_back_to_the_payload() -> None:
    """The panes align on document lines, so the system prompt has to come off first."""
    payload = "SYSTEM RULES\n<DOCUMENT>\nline one\nline two\n</DOCUMENT>\ntrailing instructions"
    assert demo.document_body(payload) == "line one\nline two"
    assert demo.document_body("no fence here") == "no fence here"


def test_pick_window_opens_a_little_before_the_first_obfuscated_row() -> None:
    """Opening the pane on the letterhead would waste the screen; two lines of run-up."""
    rows = [(f"line {i}", f"line {i}") for i in range(10)]
    rows[5] = ("Patient David Ochoa", "Patient [PHI_NAME_a1b2c3d4]")
    assert demo.pick_window(rows, frozenset(), 4) == (3, 7)


def test_pick_window_finds_a_pseudonym_that_is_neither_a_token_nor_a_redaction() -> None:
    """Under pseudonymization the only marker on the wire is the fake itself."""
    rows = [(f"line {i}", f"line {i}") for i in range(10)]
    rows[4] = ("Patient David Ochoa", "Patient Alan Browning")
    assert demo.pick_window(rows, frozenset({"Alan Browning"}), 6) == (2, 8)
    # Nothing obfuscated anywhere: show the top of the document rather than nothing.
    assert demo.pick_window(rows, frozenset({"Someone Else"}), 6) == (0, 6)


def test_align_rows_re_anchors_when_one_side_gains_a_line() -> None:
    """A restored value can put back a newline the token swallowed.

    Naive index pairing drifts from that point on and the pane stops being a diff,
    so the lines that survived unchanged must still face themselves.
    """
    rows = demo.align_rows(
        ["ALPHA", "beta gamma", "DELTA"],
        ["ALPHA", "beta", "gamma", "DELTA"],
    )
    assert ("ALPHA", "ALPHA") in rows
    assert ("DELTA", "DELTA") in rows
    assert [left for left, _right in rows if left] == ["ALPHA", "beta gamma", "DELTA"]
    assert [right for _left, right in rows if right] == ["ALPHA", "beta", "gamma", "DELTA"]


def test_display_path_shortens_a_path_under_the_cwd_and_leaves_others_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The data-dir line stays readable when the demo is run from the repo root."""
    monkeypatch.chdir(tmp_path)
    assert demo._display_path(tmp_path / "data") == "data"
    outside = (tmp_path / ".." / "elsewhere").resolve()
    assert demo._display_path(outside) == str(outside)


# ---------------------------------------------------------------------------
# load_settings
# ---------------------------------------------------------------------------
def test_load_settings_generates_an_ephemeral_key_only_when_none_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A clean clone with no ``.env`` must still run; a real key must still win.

    ``monkeypatch`` restores the environment afterwards, including the key this
    call plants in it.
    """
    monkeypatch.chdir(tmp_path)  # no .env within reach
    monkeypatch.delenv("SCP_MASTER_KEY", raising=False)

    settings, generated = demo.load_settings("mock")
    assert generated is True
    assert len(settings.master_key_bytes()) == 32

    # The key is now in the environment, so the next load must adopt it rather
    # than mint a second one -- two keys in one process means nothing decrypts.
    again, generated_again = demo.load_settings("mock")
    assert generated_again is False
    assert again.master_key == settings.master_key


def test_load_settings_re_raises_a_config_error_that_is_not_a_missing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed key is a configuration bug, not something to paper over."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SCP_MASTER_KEY", "not-valid-base64!!")

    with pytest.raises(ConfigError) as caught:
        demo.load_settings("mock")
    assert caught.value.detail.get("reason") == "master_key_not_base64"


# ---------------------------------------------------------------------------
# run_case -- one document, end to end, on the mock provider
# ---------------------------------------------------------------------------
async def test_run_case_passes_every_assertion_on_the_shipped_medical_fixture(
    harness: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The demo's first leg, checked on its own evidence and on independent evidence.

    The independent half matters: a demo that graded itself entirely with its own
    scanner would pass if that scanner broke.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()

    outcome = await demo.run_case(
        harness,
        checks,
        session_id=session_id,
        path=demo.PRIMARY_FIXTURE,
        category=demo.PRIMARY_CATEGORY,
        strategy="tokenization",
        prompt=demo.DEFAULT_PROMPT,
        panes=True,
        nonvacuity_fatal=True,
    )

    assert [c.name for c in checks.records if not c.ok] == []
    assert len(checks.records) == 6
    assert outcome.result.strategy == "tokenization"
    assert outcome.wall_s > 0

    original_text = await harness.store.get_text(demo.USER_ID, outcome.doc_id)
    assert MEDICAL_EMAIL in original_text  # the assertion below is not vacuous
    assert MEDICAL_EMAIL not in outcome.result.obfuscated_payload
    assert "[PHI_" not in outcome.result.restored_text
    assert "[PII_" not in outcome.result.restored_text

    out = capsys.readouterr().out
    assert "ORIGINAL DOCUMENT (at rest)" in out
    assert "OUTBOUND PAYLOAD (on the wire)" in out
    assert "RESTORED ANSWER (to the user)" in out
    assert MEDICAL_EMAIL not in out.split("RAW LLM RESPONSE")[-1]


async def test_run_case_without_panes_still_asserts_but_prints_no_diff(
    harness: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The second strategy on the second fixture, with the pane rendering suppressed."""
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()

    outcome = await demo.run_case(
        harness,
        checks,
        session_id=session_id,
        path=demo.SECONDARY_FIXTURE,
        category=demo.SECONDARY_CATEGORY,
        strategy="pseudonymization",
        prompt=demo.DEFAULT_PROMPT,
        panes=False,
        nonvacuity_fatal=True,
    )

    assert [c.name for c in checks.records if not c.ok] == []
    assert outcome.result.strategy == "pseudonymization"
    assert all(name.startswith("[pseudonymization]") for name in (c.name for c in checks.records))
    out = capsys.readouterr().out
    assert "ORIGINAL DOCUMENT (at rest)" not in out
    assert "entities" in out  # the tables and timings are printed regardless


async def test_a_document_with_nothing_to_detect_is_a_warning_not_a_failure(
    harness: Any, tmp_path: Path
) -> None:
    """``--file`` may legitimately contain no entities; that is vacuous, not broken.

    The run must stay green -- exit 0 -- while still *saying* the leak scan had
    nothing to scan for.
    """
    path = tmp_path / "checklist.txt"
    path.write_text(NO_ENTITY_DOCUMENT, encoding="utf-8")
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()

    await demo.run_case(
        harness,
        checks,
        session_id=session_id,
        path=path,
        category="general",
        strategy="tokenization",
        prompt=demo.DEFAULT_PROMPT,
        panes=False,
        nonvacuity_fatal=False,
    )

    assert checks.failures == []
    assert [c.name for c in checks.warnings] == [
        "[tokenization] vault holds entities -- the leak scan is not vacuous"
    ]
    assert checks.banner(1.0) == demo.EXIT_OK


# ---------------------------------------------------------------------------
# The two demonstrations the live review turns on
# ---------------------------------------------------------------------------
async def test_the_gate_refuses_a_payload_carrying_a_planted_original(
    harness: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The half a gate that always passes cannot fake, plus its own control.

    A prior passing run in the same session is what makes "no LLM_CALL for the
    blocked run" mean the gate stopped it rather than the provider being unwired.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()
    await demo.run_case(
        harness,
        checks,
        session_id=session_id,
        path=demo.PRIMARY_FIXTURE,
        category=demo.PRIMARY_CATEGORY,
        strategy="tokenization",
        prompt=demo.DEFAULT_PROMPT,
        panes=False,
        nonvacuity_fatal=True,
    )
    before = len(checks.records)

    await demo.demonstrate_fail_closed(
        harness, checks, session_id=session_id, prompt=demo.DEFAULT_PROMPT
    )

    added = checks.records[before:]
    assert [c.name for c in added if not c.ok] == []
    assert len(added) == 4
    assert any("BLOCKS" in c.name for c in added)
    assert any("NEVER called" in c.name for c in added)

    # The refused value is never printed, and never travels in the error detail.
    out = capsys.readouterr().out
    assert demo.LEAK_SENTINEL not in out
    assert all(demo.LEAK_SENTINEL not in c.detail for c in added)
    assert "caller receives:" in out
    assert "EGRESS_BLOCKED" in out


async def test_a_restore_that_worked_a_moment_ago_is_impossible_after_destruction(
    harness: Any,
) -> None:
    """Cryptographic erasure, demonstrated in both directions.

    The pre-destroy restore is the control: without it, "restoration failed" could
    just mean there was nothing to restore.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()
    outcome = await demo.run_case(
        harness,
        checks,
        session_id=session_id,
        path=demo.PRIMARY_FIXTURE,
        category=demo.PRIMARY_CATEGORY,
        strategy="tokenization",
        prompt=demo.DEFAULT_PROMPT,
        panes=False,
        nonvacuity_fatal=True,
    )
    probe = demo.build_probe([outcome])
    assert probe is not None and probe.token_id is not None
    assert harness.vault.originals_for_session(session_id)

    destruction = demo.CheckList()
    await demo.demonstrate_destruction(
        harness, destruction, session_id=session_id, probe=probe
    )

    assert [c.name for c in destruction.records if not c.ok] == []
    assert len(destruction.records) == 2
    assert destruction.banner(1.0) == demo.EXIT_OK
    # Independent of the demo's own checks: the vault holds nothing for this
    # session and the key cannot be popped twice.
    assert not harness.vault.originals_for_session(session_id)
    assert await harness.sessions.destroy(session_id) is False


async def test_a_pseudonym_is_also_unrestorable_once_the_session_is_destroyed(
    harness: Any,
) -> None:
    """The other probe shape: no token ID, so the whole demonstration is the surrogate pass.

    Tokenization keys restoration on an 8-hex ID; a pseudonym is restored by
    looking the fake up in the vault. Both have to become impossible after
    destruction, and only the token half is exercised by the default run.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()
    outcome = await demo.run_case(
        harness,
        checks,
        session_id=session_id,
        path=demo.SECONDARY_FIXTURE,
        category=demo.SECONDARY_CATEGORY,
        strategy="pseudonymization",
        prompt=demo.DEFAULT_PROMPT,
        panes=False,
        nonvacuity_fatal=True,
    )
    echoed = [
        span.surrogate
        for span in outcome.result.detections
        if span.surrogate and span.surrogate in outcome.result.raw_llm_response
    ]
    assert echoed, "the mock provider echoed no pseudonym back; nothing to restore"
    probe = demo.DestroyProbe(
        token_id=None,
        surrogate=echoed[0],
        text=outcome.result.raw_llm_response,
        strategy="pseudonymization",
        surrogate_map={echoed[0]: ""},
        minted=frozenset(),
        source="hand-built pseudonym probe",
    )

    destruction = demo.CheckList()
    await demo.demonstrate_destruction(
        harness, destruction, session_id=session_id, probe=probe
    )

    assert [c.name for c in destruction.records if not c.ok] == []
    assert destruction.banner(1.0) == demo.EXIT_OK


async def test_destruction_records_a_failure_when_no_probe_was_produced(harness: Any) -> None:
    """No probe means the destruction claim was never tested -- that is a failure.

    Reporting it as a pass would let the demo's headline claim go unexercised while
    still printing ``PASS``.
    """
    checks = demo.CheckList()
    await demo.demonstrate_destruction(
        harness, checks, session_id="no-such-session", probe=None
    )

    assert len(checks.records) == 1
    assert checks.records[0].ok is False
    assert checks.records[0].fatal is True
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


# ---------------------------------------------------------------------------
# --dump-wire's scan (the --real half cannot run here; the scan can)
# ---------------------------------------------------------------------------
async def test_wire_capture_records_the_request_body_and_never_the_headers() -> None:
    """The API key lives in the headers, so only ``request.content`` may be read."""
    import httpx

    capture = demo.WireCapture()
    request = httpx.Request(
        "POST",
        "https://api.example.invalid/v1/messages",
        headers={"x-api-key": "sk-ant-not-a-real-key"},
        content=b'{"model":"claude","messages":[]}',
    )

    await capture.on_request(request)

    assert capture.bodies == [b'{"model":"claude","messages":[]}']
    assert all(b"sk-ant-not-a-real-key" not in body for body in capture.bodies)


async def test_dump_wire_fails_on_a_readable_original_and_passes_on_a_substring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wire check must use ``leaks``, not ``hits``.

    Asserting on ``hits`` failed a real ``--real --dump-wire`` run over the
    documented Brown/Browning coincidence, which is not a disclosure. Both
    directions are pinned so neither the leak nor the false positive can come back.
    """
    dump = tmp_path / "wire_dump.txt"
    monkeypatch.setattr(demo, "WIRE_DUMP_PATH", dump)

    clean = demo.WireCapture()
    clean.bodies = [b'{"text":"Prepared by accountant Alan Browning."}']
    passing = demo.CheckList()
    await demo.dump_wire(clean, passing, frozenset({"Brown"}))
    assert passing.failures == []
    assert "not counted as a leak" in passing.records[0].detail

    leaking = demo.WireCapture()
    leaking.bodies = [
        b'{"text":"Prepared by accountant Alan Browning."}',
        b'{"text":"Countersigned by Brown on Tuesday."}',
    ]
    failing = demo.CheckList()
    await demo.dump_wire(leaking, failing, frozenset({"Brown"}))
    assert len(failing.failures) == 1
    assert failing.banner(1.0) == demo.EXIT_ASSERTION_FAILED

    written = dump.read_text(encoding="utf-8")
    assert "Headers are deliberately NOT captured" in written
    assert "Countersigned by Brown on Tuesday." in written
    assert "----- request 2 " in written


async def test_dump_wire_fails_when_nothing_was_captured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zero bodies scanned is zero evidence -- it must not read as a clean wire."""
    monkeypatch.setattr(demo, "WIRE_DUMP_PATH", tmp_path / "wire_dump.txt")
    checks = demo.CheckList()

    await demo.dump_wire(demo.WireCapture(), checks, frozenset({"Brown"}))

    assert len(checks.failures) == 1
    assert "no request bodies were captured" in checks.records[0].detail


# ---------------------------------------------------------------------------
# verify_chain_only
# ---------------------------------------------------------------------------
async def _seed_audit_log(settings: Settings, count: int) -> Path:
    path = Path(settings.data_dir) / AUDIT_DB_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    audit = await AuditLogger.open(path)
    try:
        for index in range(count):
            await audit.emit(
                AuditEvent(
                    ts=time.time(),
                    session_id=f"seed-{index}",
                    event_type=SESSION_CREATE,
                    detail={"n": index},
                )
            )
    finally:
        await audit.close()
    return path


async def test_verify_chain_only_reports_an_intact_log_and_exits_zero(
    settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``--verify-chain`` entry point over a log this test wrote itself."""
    await _seed_audit_log(settings, 3)

    code = await demo.verify_chain_only(settings)

    assert code == demo.EXIT_OK
    out = capsys.readouterr().out
    assert "verify_chain() -> True" in out
    assert "(3 events in" in out


async def test_verify_chain_only_exits_nonzero_when_a_row_has_been_edited(
    settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    """Tamper with one persisted row; the chain check must notice and fail the run.

    This is the assertion that makes ``--verify-chain`` worth running in CI -- a
    check that returned 0 unconditionally would look identical on a clean log.
    """
    path = await _seed_audit_log(settings, 3)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE audit_events SET detail = ? WHERE seq = 2", ('{"n": 99}',))
        conn.commit()

    code = await demo.verify_chain_only(settings)

    assert code == demo.EXIT_ASSERTION_FAILED
    assert code != 0
    assert "verify_chain() -> False" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Argument parsing and usage errors
# ---------------------------------------------------------------------------
def test_the_documented_flags_parse_to_the_documented_defaults() -> None:
    """The defaults are the contract ``python demo.py`` with no arguments relies on."""
    args = demo.parse_args([])
    assert args.strategy == "tokenization"
    assert args.category == "general"
    assert args.file is None
    assert args.prompt == demo.DEFAULT_PROMPT
    assert args.real is False
    assert args.dump_wire is False
    assert args.verify_chain is False


def test_every_flag_reaches_the_namespace_under_its_own_name() -> None:
    """``--dump-wire`` in particular has to arrive as ``dump_wire``, not ``dump-wire``."""
    args = demo.parse_args(
        [
            "--strategy",
            "pseudonymization",
            "--file",
            "/tmp/their.pdf",
            "--category",
            "legal",
            "--prompt",
            "List the parties.",
            "--real",
            "--dump-wire",
            "--verify-chain",
        ]
    )
    assert args.strategy == "pseudonymization"
    assert args.file == "/tmp/their.pdf"
    assert args.category == "legal"
    assert args.prompt == "List the parties."
    assert args.real is True
    assert args.dump_wire is True
    assert args.verify_chain is True


@pytest.mark.parametrize(
    "argv",
    [
        ["--strategy", "redaction"],  # not one of the two shipped strategies
        ["--category", "astrology"],  # not one of the store's document categories
    ],
)
def test_an_unsupported_choice_is_refused_at_the_command_line(argv: list[str]) -> None:
    """argparse rejects it before any pipeline is built, with the usage exit code."""
    with pytest.raises(SystemExit) as caught:
        demo.parse_args(argv)
    assert caught.value.code == demo.EXIT_USAGE


def test_dump_wire_without_real_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    """There is no HTTP request to capture on the mock path, so this must not run."""
    code = demo.main(["--dump-wire"])
    assert code == demo.EXIT_USAGE
    assert "requires --real" in capsys.readouterr().err


def test_real_without_an_api_key_is_a_usage_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail with a usage message, not a provider exception halfway through a run."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code = demo.main(["--real"])
    assert code == demo.EXIT_USAGE
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_a_missing_file_is_a_usage_error_naming_the_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Checked before the pipeline starts, so the reviewer sees the typo immediately."""
    missing = tmp_path / "not_here.pdf"
    code = demo.main(["--file", str(missing)])
    assert code == demo.EXIT_USAGE
    assert str(missing) in capsys.readouterr().err


def test_a_missing_fixture_is_a_usage_error_that_names_the_cause(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run from the wrong directory and you get a usage message, not a traceback.

    The fixtures are the demo's inputs; a clone that lost them must say so before
    it builds a pipeline it cannot feed.
    """
    monkeypatch.setattr(demo, "PRIMARY_FIXTURE", tmp_path / "gone" / "medical_note.txt")

    code = demo.main([])

    assert code == demo.EXIT_USAGE
    assert "run from the repository root" in capsys.readouterr().err


def test_a_broken_master_key_is_reported_as_a_configuration_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``ConfigError`` reaching ``main`` is a usage exit, not an unhandled traceback."""
    monkeypatch.chdir(tmp_path)  # no .env within reach
    monkeypatch.setenv("SCP_MASTER_KEY", "not-valid-base64!!")

    code = demo.main([])

    assert code == demo.EXIT_USAGE
    err = capsys.readouterr().err
    assert "configuration problem" in err
    assert "master_key_not_base64" in err


def test_verify_chain_exits_before_any_document_is_processed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--verify-chain`` is a chain check and nothing else -- no upload, no LLM call."""
    monkeypatch.setenv("SCP_DATA_DIR", str(tmp_path / "data"))

    code = demo.main(["--verify-chain"])

    out = capsys.readouterr().out
    assert code == demo.EXIT_OK
    assert "verify_chain() -> True" in out
    assert "SECURE CONTEXT PIPELINE" not in out
    assert "EGRESS GATE" not in out


# ---------------------------------------------------------------------------
# main() end to end -- the smoke-test contract
# ---------------------------------------------------------------------------
def test_the_whole_demo_runs_green_and_prints_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``python demo.py`` on the shipped fixtures: exit 0, every check passed.

    Also the printing rules from build doc section 16, checked on the real output
    rather than argued: the master key never appears, and neither does the value
    the fail-closed section plants in the vault.
    """
    monkeypatch.setenv("SCP_DATA_DIR", str(tmp_path / "data"))

    code = demo.main([])

    out = capsys.readouterr().out
    assert code == demo.EXIT_OK, out[-3000:]
    assert "[FAIL]" not in out
    assert "0 failures" in out
    assert "== 2-5. RUN A: TOKENIZATION" in out
    assert "== 6. RUN B: PSEUDONYMIZATION" in out
    assert "== 6C. FAIL-CLOSED" in out
    assert os.environ["SCP_MASTER_KEY"] not in out
    assert demo.LEAK_SENTINEL not in out
    assert not (tmp_path / "data" / "wire_dump.txt").exists()


def test_a_failed_check_makes_the_process_exit_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The property that lets this file double as the CI smoke test.

    One check is forced to fail -- the restored output is reported as still
    carrying a surrogate -- and the whole run must come back non-zero. Without
    this, a demo that printed ``FAIL`` and returned 0 would be green in CI.
    """
    monkeypatch.setenv("SCP_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(demo, "residual_tokens", lambda _text: ["[PHI_NAME_a1b2c3d4]"])

    code = demo.main([])

    out = capsys.readouterr().out
    assert code == demo.EXIT_ASSERTION_FAILED
    assert code != 0
    assert "[FAIL]" in out
    assert "ZERO residual surrogate tokens in the restored output" in out
    assert "assertion(s) failed" in out


def test_the_file_strategy_and_category_flags_reach_run_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--file``/``--category``/``--strategy``/``--prompt`` select the first leg.

    ``run_case`` is replaced by a recorder that then raises, which also pins the
    other half: a pipeline error is recorded as a failed check, so the process
    still exits non-zero rather than reporting the run it never finished.
    """
    monkeypatch.setenv("SCP_DATA_DIR", str(tmp_path / "data"))
    document = tmp_path / "their_memo.txt"
    document.write_text(NO_ENTITY_DOCUMENT, encoding="utf-8")
    seen: list[dict[str, Any]] = []

    async def _recording_run_case(_harness: Any, _checks: Any, **kwargs: Any) -> None:
        seen.append(kwargs)
        raise PipelineError(reason="stopped_by_test")

    monkeypatch.setattr(demo, "run_case", _recording_run_case)

    code = demo.main(
        [
            "--file",
            str(document),
            "--category",
            "legal",
            "--strategy",
            "pseudonymization",
            "--prompt",
            "Who is involved?",
        ]
    )

    assert code == demo.EXIT_ASSERTION_FAILED
    assert len(seen) == 1
    call = seen[0]
    assert call["path"] == document
    assert call["category"] == "legal"
    assert call["strategy"] == "pseudonymization"
    assert call["prompt"] == "Who is involved?"
    # A reviewer's own file may legitimately contain nothing to detect.
    assert call["nonvacuity_fatal"] is False
