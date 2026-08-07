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
    EGRESS_PASS,
    LLM_CALL,
    SESSION_CREATE,
    AuditLogger,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import ConfigError, EgressBlockedError, PipelineError
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

#: Every assertion ``python demo.py`` with no arguments must make, in order.
#:
#: The section headings the demo prints come from :func:`demo.section` calls and
#: survive the work under them being deleted, so a smoke test that greps for
#: headings is not evidence that any demonstration ran. Measured: with the whole
#: pseudonymization leg and the whole fail-closed section removed from
#: ``run_demo``, all three headings were still printed, the banner still read
#: ``PASS -- 10/10 checks passed, 0 failures`` and the exit status was still 0.
#: The ledger is what cannot be faked -- it is also the thing the exit code is
#: computed from -- so the smoke test asserts the ledger.
FULL_RUN_LEDGER = (
    "[tokenization] vault holds entities -- the leak scan is not vacuous",
    "[tokenization] ZERO originals in the outbound payload",
    "[tokenization] ZERO originals in the raw provider response",
    "[tokenization] ZERO residual surrogate tokens in the restored output",
    "[tokenization] EGRESS_PASS is audited before the provider call",
    "[tokenization] egress gate scanned the exact bytes that were sent",
    "[pseudonymization] vault holds entities -- the leak scan is not vacuous",
    "[pseudonymization] ZERO originals in the outbound payload",
    "[pseudonymization] ZERO originals in the raw provider response",
    "[pseudonymization] ZERO residual surrogate tokens in the restored output",
    "[pseudonymization] EGRESS_PASS is audited before the provider call",
    "[pseudonymization] egress gate scanned the exact bytes that were sent",
    "EGRESS GATE BLOCKS a payload that still carries an original",
    "the provider was NEVER called for the blocked run",
    "control: the same session's passing runs DO reach the provider",
    "the block itself leaks nothing -- the refused value is not in the error",
    "restoration WORKS before destruction (control for the next check)",
    "restoration FAILS after destruction (irreversible across sessions)",
    "vault reports zero originals for the destroyed session",
    "audit hash chain verifies (whole log and this session's slice)",
)


@pytest.fixture
async def harness(settings: Settings) -> AsyncIterator[Any]:
    """The demo's own wiring, on the mock provider and an isolated data dir."""
    built = await demo.build_harness(settings, MockProvider())
    try:
        yield built
    finally:
        await built.close()


@pytest.fixture(autouse=True)
def wire_dump_under_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ``WIRE_DUMP_PATH`` so no test in this module can write the real file.

    The module docstring promises nothing is written to ``wire_dump.txt``. That
    promise was prose: ``demo.WIRE_DUMP_PATH`` is ``REPO_ROOT / "wire_dump.txt"``
    and no code path in the repository ever builds a ``wire_dump.txt`` under
    ``data_dir``, so the assertion that used to back it named a path nothing could
    create. A ``run_demo`` that wrote the real repo-root file passed that
    assertion and left the file in the working tree.

    Autouse rather than per-test because the claim is module-wide, and structural
    rather than asserted: with the path pointed at ``tmp_path`` a test *cannot*
    write the repository's copy even if the assertion is later removed.
    """
    redirected = tmp_path / "wire_dump.txt"
    monkeypatch.setattr(demo, "WIRE_DUMP_PATH", redirected)
    return redirected


def capture_ledger(monkeypatch: pytest.MonkeyPatch) -> list[list[Any]]:
    """Record the ``CheckList`` behind every banner ``run_demo`` prints.

    ``main`` returns only an exit code and prints only a rendering, so a test that
    wants the assertions themselves has to take them off the object the exit code
    is computed from. Returns a list appended to once per :meth:`CheckList.banner`
    call; the last entry is the run's final ledger.
    """
    banners: list[list[Any]] = []
    original = demo.CheckList.banner

    def _recording_banner(self: Any, elapsed_s: float) -> int:
        banners.append(list(self.records))
        return original(self, elapsed_s)  # type: ignore[no-any-return]

    monkeypatch.setattr(demo.CheckList, "banner", _recording_banner)
    return banners


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
# run_case's negative direction -- one sabotage per graded condition
#
# The green run above records six passing checks, which is satisfied just as well
# by a check whose condition is the literal ``True``. Four of the six were exactly
# that: replacing ``payload_scan.leaks == 0``, ``response_scan.leaks == 0``, the
# EGRESS_PASS/LLM_CALL ordering expression and the ``payload_sha256`` comparison
# with ``True`` left all 41 tests in this file passing. Each test below arranges
# the world so that one of those conditions is false and asserts that *that named
# check* -- and only it -- goes red, which no hardwired condition can do.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("leaking_scan", "expected_failure"),
    [
        (0, "[tokenization] ZERO originals in the outbound payload"),
        (1, "[tokenization] ZERO originals in the raw provider response"),
    ],
)
async def test_run_case_fails_the_check_whose_scan_reported_a_leak(
    harness: Any,
    monkeypatch: pytest.MonkeyPatch,
    leaking_scan: int,
    expected_failure: str,
) -> None:
    """A leak the scanner found has to reach the ledger as a failed assertion.

    ``run_case`` scans twice -- the outbound payload first, the raw provider
    response second -- and the two are separate claims. Making exactly one of the
    two report a leak pins each check to its own scan: a check that graded the
    other scan's result, or graded nothing at all, cannot produce this ledger.
    """
    real_scan = demo.scan_for_originals
    scans_done = 0

    def _scan(haystack: str, originals: frozenset[str]) -> Any:
        nonlocal scans_done
        index = scans_done
        scans_done += 1
        if index == leaking_scan:
            return demo.ScanResult(hits=1, scanned=1, skipped_short=0)
        return real_scan(haystack, originals)

    monkeypatch.setattr(demo, "scan_for_originals", _scan)
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

    assert scans_done == 2
    assert [c.name for c in checks.records if not c.ok] == [expected_failure]
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


async def test_run_case_fails_when_the_provider_call_was_audited_before_the_gate_pass(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """"Gate before provider" is an ordering claim, so it is pinned out of order.

    The two events exist on every run; only their ``seq`` order carries the
    property. Swapping the first ``EGRESS_PASS`` with the first ``LLM_CALL`` in
    what the log returns leaves every other check's inputs untouched -- including
    the ``payload_sha256`` check, which reads the same event list -- so exactly
    one check may move.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    real_query = harness.audit.query

    async def _reordered_query(**kwargs: Any) -> list[AuditEvent]:
        events = await real_query(**kwargs)
        gate = min(
            (e.seq for e in events if e.event_type == EGRESS_PASS and e.seq is not None),
            default=None,
        )
        call = min(
            (e.seq for e in events if e.event_type == LLM_CALL and e.seq is not None),
            default=None,
        )
        if gate is None or call is None:
            return events
        swapped = {gate: call, call: gate}
        return [e.model_copy(update={"seq": swapped.get(e.seq, e.seq)}) for e in events]

    monkeypatch.setattr(harness.audit, "query", _reordered_query)
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

    assert [c.name for c in checks.records if not c.ok] == [
        "[tokenization] EGRESS_PASS is audited before the provider call"
    ]
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


async def test_run_case_fails_when_no_audited_digest_matches_the_payload_that_was_sent(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The byte-identity check is what makes the leak scans about the *sent* bytes.

    Without it the demo could scan a payload the gate never saw. Rewriting every
    audited ``payload_sha256`` to a digest of nothing is the exact regression --
    the gate scanned something other than what went out -- and it must be the only
    check that moves, since the ordering check reads the same events.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    real_query = harness.audit.query

    async def _rewritten_query(**kwargs: Any) -> list[AuditEvent]:
        events = await real_query(**kwargs)
        return [
            e.model_copy(update={"detail": {**e.detail, "payload_sha256": "0" * 64}})
            if "payload_sha256" in e.detail
            else e
            for e in events
        ]

    monkeypatch.setattr(harness.audit, "query", _rewritten_query)
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

    assert [c.name for c in checks.records if not c.ok] == [
        "[tokenization] egress gate scanned the exact bytes that were sent"
    ]
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


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


# ---------------------------------------------------------------------------
# The fail-closed section's negative direction
#
# The test above asserts four check *names* and that none of them is red, which
# is satisfied by four checks whose conditions are the literal ``True`` -- and all
# four survived being replaced by it. Sabotaging the behaviour instead (never
# planting the sentinel) is caught, but that is the demonstration failing, not the
# assertion noticing. Each test below falsifies one condition while leaving the
# other three true, so the ledger it asserts is reachable only by a check that
# still computes something.
# ---------------------------------------------------------------------------
async def _passing_run(harness: Any, checks: Any, session_id: str) -> None:
    """One green run_case, so the fail-closed control has a provider call to find."""
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


async def test_the_fail_closed_checks_go_red_when_the_gate_releases_the_payload(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate that lets the planted payload through must fail, loudly, by name.

    The sentinel is planted in the vault and read out of ``LEAK_SENTINEL``, but
    ``LEAK_DOC`` interpolated the *original* value at import time. Repointing
    ``LEAK_SENTINEL`` therefore vaults a value the document does not contain --
    the gate has nothing to match, releases the payload, and the run completes.
    That is precisely "the gate did not refuse", staged without touching the gate.

    Three of the four checks are then false together, because with no
    ``EgressBlockedError`` there is no blocked run to query and no error to scan.
    The fourth stays green: the session's earlier run really did reach the
    provider, which is the control doing its job.
    """
    monkeypatch.setattr(demo, "LEAK_SENTINEL", "9ZY-OMEGA-0000")
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()
    await _passing_run(harness, checks, session_id)
    before = len(checks.records)

    await demo.demonstrate_fail_closed(
        harness, checks, session_id=session_id, prompt=demo.DEFAULT_PROMPT
    )

    added = checks.records[before:]
    assert [c.name for c in added if not c.ok] == [
        "EGRESS GATE BLOCKS a payload that still carries an original",
        "the provider was NEVER called for the blocked run",
        "the block itself leaks nothing -- the refused value is not in the error",
    ]
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


async def test_the_never_called_check_goes_red_when_the_blocked_run_reached_the_provider(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate blocking is not the property; the provider not being called is.

    A gate that raised ``EGRESS_BLOCKED`` *after* handing the payload to the
    provider would satisfy every other check in the section. Here the blocked
    run's own audit slice is made to carry an ``LLM_CALL``, so only the check that
    reads that slice may move -- the session-scoped control query is left alone.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()
    await _passing_run(harness, checks, session_id)
    before = len(checks.records)
    real_query = harness.audit.query

    async def _query_with_a_provider_call(**kwargs: Any) -> list[AuditEvent]:
        events = await real_query(**kwargs)
        run_id = kwargs.get("run_id")
        if isinstance(run_id, str):
            events.append(
                AuditEvent(
                    ts=time.time(),
                    session_id=session_id,
                    run_id=run_id,
                    event_type=LLM_CALL,
                    detail={"planted_by": "test"},
                )
            )
        return events

    monkeypatch.setattr(harness.audit, "query", _query_with_a_provider_call)

    await demo.demonstrate_fail_closed(
        harness, checks, session_id=session_id, prompt=demo.DEFAULT_PROMPT
    )

    added = checks.records[before:]
    assert [c.name for c in added if not c.ok] == [
        "the provider was NEVER called for the blocked run"
    ]
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


async def test_the_control_check_goes_red_when_no_run_in_the_session_reached_the_provider(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control exists because an unwired provider also produces no LLM_CALL.

    With the session's ``LLM_CALL`` history emptied, "no provider call for the
    blocked run" is no longer evidence of anything -- and the check whose whole
    job is to say so has to be the one that goes red.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()
    await _passing_run(harness, checks, session_id)
    before = len(checks.records)
    real_query = harness.audit.query

    async def _query_hiding_the_provider_calls(**kwargs: Any) -> list[AuditEvent]:
        if kwargs.get("event_type") == LLM_CALL:
            return []
        return await real_query(**kwargs)

    monkeypatch.setattr(harness.audit, "query", _query_hiding_the_provider_calls)

    await demo.demonstrate_fail_closed(
        harness, checks, session_id=session_id, prompt=demo.DEFAULT_PROMPT
    )

    added = checks.records[before:]
    assert [c.name for c in added if not c.ok] == [
        "control: the same session's passing runs DO reach the provider"
    ]
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


async def test_the_no_leak_check_goes_red_when_the_error_detail_carries_the_value(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A block that names the value it refused is a worse hole than the one it closed.

    ``EgressBlockedError`` already has a field that could carry it --
    ``entity_types`` is a free string -- so the regression is one careless line in
    the gate, not a hypothetical. The real error is caught and re-raised with the
    sentinel in that field, preserving ``run_id`` so the audit-backed checks are
    untouched and only the leak check may move.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    checks = demo.CheckList()
    await _passing_run(harness, checks, session_id)
    before = len(checks.records)
    real_run = harness.orchestrator.run

    async def _leaky_run(*args: Any, **kwargs: Any) -> Any:
        try:
            return await real_run(*args, **kwargs)
        except EgressBlockedError as exc:
            raise EgressBlockedError(
                session_id=str(exc.detail["session_id"]),
                reason=str(exc.detail["reason"]),
                hit_count=int(exc.detail["hit_count"]),
                entity_types=demo.LEAK_SENTINEL,
                run_id=str(exc.detail["run_id"]),
            ) from None

    monkeypatch.setattr(harness.orchestrator, "run", _leaky_run)

    await demo.demonstrate_fail_closed(
        harness, checks, session_id=session_id, prompt=demo.DEFAULT_PROMPT
    )

    added = checks.records[before:]
    assert [c.name for c in added if not c.ok] == [
        "the block itself leaks nothing -- the refused value is not in the error"
    ]
    assert checks.banner(1.0) == demo.EXIT_ASSERTION_FAILED


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


async def test_the_pre_destroy_control_goes_red_when_the_restore_put_nothing_back(
    harness: Any,
) -> None:
    """The control's own condition, which was as unpinned as the thing it controls.

    ``demonstrate_destruction`` says the pre-destroy restore is what stops
    "restoration failed" from meaning "there was nothing to restore" -- and then
    graded that control with ``before.restored_count > 0``, which could be
    replaced with ``True`` without a single test noticing. A probe whose text
    carries no surrogate restores zero occurrences, which is exactly the degenerate
    case the control exists to reject, so it has to be recorded as a failure.
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
    real_probe = demo.build_probe([outcome])
    assert real_probe is not None and real_probe.token_id is not None
    empty_probe = demo.DestroyProbe(
        token_id=real_probe.token_id,
        surrogate=None,
        text="This answer carries nothing the restorer would look up.",
        strategy="tokenization",
        surrogate_map=None,
        minted=real_probe.minted,
        source="degenerate probe: a response with nothing to restore",
    )

    destruction = demo.CheckList()
    await demo.demonstrate_destruction(
        harness, destruction, session_id=session_id, probe=empty_probe
    )

    control = destruction.records[0]
    assert control.name == "restoration WORKS before destruction (control for the next check)"
    assert control.ok is False
    assert control.detail == "0 occurrence(s) restored from the vault"
    assert destruction.banner(1.0) == demo.EXIT_ASSERTION_FAILED


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
# print_audit_tail -- the demo's last check, and the one with no test at all
# ---------------------------------------------------------------------------
async def test_the_audit_chain_check_passes_on_an_intact_log_and_fails_on_an_edited_row(
    harness: Any, settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both directions of the demo's final assertion, over a log this test wrote.

    ``print_audit_tail`` records ``whole and scoped`` and was reached by nothing in
    the suite -- no test named it, so replacing that condition with ``True`` left
    every test green while the demo's closing claim, that the log a reviewer is
    about to read verifies, became unconditional.

    The tamper is an ``UPDATE`` from a second connection, the shape a reviewer
    would try by hand: the log is WAL with one connection per logger, so the
    harness's own reader sees the edited row on its next query rather than a
    cached copy of the clean one.
    """
    session_id, _expires = await harness.sessions.create(demo.USER_ID)
    for index in range(3):
        await harness.audit.emit(
            AuditEvent(
                ts=time.time(),
                session_id=session_id,
                event_type=SESSION_CREATE,
                detail={"n": index},
            )
        )

    intact = demo.CheckList()
    await demo.print_audit_tail(harness, intact, session_id)

    assert [c.name for c in intact.records] == [
        "audit hash chain verifies (whole log and this session's slice)"
    ]
    assert intact.records[0].ok is True
    assert "verify_chain()" in capsys.readouterr().out

    with sqlite3.connect(Path(settings.data_dir) / AUDIT_DB_FILENAME) as conn:
        conn.execute("UPDATE audit_events SET detail = ? WHERE seq = 2", ('{"n": 99}',))
        conn.commit()

    tampered = demo.CheckList()
    await demo.print_audit_tail(harness, tampered, session_id)

    assert tampered.records[0].ok is False
    assert tampered.banner(1.0) == demo.EXIT_ASSERTION_FAILED


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


async def test_dump_wire_carries_substring_only_hits_across_every_captured_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The false-positive suppression has to survive a wire with more than one body.

    ``dump_wire`` folds each body's scan into a running total, and ``leaks`` is
    ``hits - substring_only``. Summing ``hits`` while keeping only the *last*
    body's ``substring_only`` is not a rounding error -- it turns every earlier
    body's coincidence into a counted leak. Measured on the two bodies below with
    the carry dropped: ``1 found`` instead of ``0 found``, one recorded failure,
    and ``--real --dump-wire`` exits 1 on a wire that disclosed nothing.

    The single-body case above cannot see this: with one body the accumulator has
    nothing to carry, so both the shipped code and the broken code agree.
    """
    monkeypatch.setattr(demo, "WIRE_DUMP_PATH", tmp_path / "wire_dump.txt")
    clean = demo.WireCapture()
    clean.bodies = [
        b'{"text":"Prepared by accountant Alan Browning."}',
        b'{"text":"Reviewed by auditor Dana Brownlee."}',
    ]
    checks = demo.CheckList()

    await demo.dump_wire(clean, checks, frozenset({"Brown"}))

    assert checks.failures == []
    assert checks.banner(1.0) == demo.EXIT_OK
    detail = checks.records[0].detail
    assert "0 found" in detail
    assert "2 more present only inside a longer word" in detail


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

    "Every check passed" is asserted against the ledger, not against the screen.
    The headings below come from :func:`demo.section` and the banner recomputes
    itself from whatever records happen to exist, so both go on reading green when
    a demonstration is deleted outright: with RUN B and the fail-closed section
    removed the run still printed all three headings, still reported
    ``PASS -- 10/10 checks passed, 0 failures`` and still exited 0.
    :data:`FULL_RUN_LEDGER` is the part that cannot be satisfied by less work.

    Also the printing rules from build doc section 16, checked on the real output
    rather than argued: the master key never appears, and neither does the value
    the fail-closed section plants in the vault.
    """
    monkeypatch.setenv("SCP_DATA_DIR", str(tmp_path / "data"))
    ledger = capture_ledger(monkeypatch)

    code = demo.main([])

    out = capsys.readouterr().out
    assert code == demo.EXIT_OK, out[-3000:]
    assert "[FAIL]" not in out
    assert "0 failures" in out
    assert "== 2-5. RUN A: TOKENIZATION" in out
    assert "== 6. RUN B: PSEUDONYMIZATION" in out
    assert "== 6C. FAIL-CLOSED" in out
    assert len(ledger) == 1, "run_demo banners exactly once"
    assert tuple(c.name for c in ledger[0]) == FULL_RUN_LEDGER
    assert [c.name for c in ledger[0] if not c.ok] == []
    assert os.environ["SCP_MASTER_KEY"] not in out
    assert demo.LEAK_SENTINEL not in out
    # Narrowed from `not (tmp_path / "data" / "wire_dump.txt").exists()`, which
    # could not fail: WIRE_DUMP_PATH is REPO_ROOT / "wire_dump.txt" and no code
    # path in the repository ever builds a wire_dump.txt under data_dir, so the
    # old form asserted the absence of a file nothing could create. A run_demo
    # that wrote the real wire dump on the mock path passed it and left the file
    # in the working tree. `wire_dump_under_tmp_path` puts the path demo.py
    # actually writes under tmp_path, so this now checks the module docstring's
    # guarantee instead of restating it.
    assert not demo.WIRE_DUMP_PATH.exists()


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


def test_the_vault_zero_check_goes_red_when_the_session_was_never_destroyed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``run_demo``'s own closing assertion, asserted against from the outside.

    "The vault reports zero originals for the destroyed session" is recorded by
    ``run_demo`` itself rather than by either demonstration, so no test of
    ``demonstrate_destruction`` could reach it and the condition survived being
    replaced with ``True``. Skipping the destruction leaves the session's vault
    rows in place -- the fixture run holds tens of them -- so the check has the
    one input that makes it false, and it must be the only check that moves.
    """
    monkeypatch.setenv("SCP_DATA_DIR", str(tmp_path / "data"))
    ledger = capture_ledger(monkeypatch)

    async def _skip_destruction(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(demo, "demonstrate_destruction", _skip_destruction)

    code = demo.main([])

    out = capsys.readouterr().out
    assert code == demo.EXIT_ASSERTION_FAILED, out[-3000:]
    assert [c.name for c in ledger[-1] if not c.ok] == [
        "vault reports zero originals for the destroyed session"
    ]


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


async def test_the_destruction_check_goes_red_when_nothing_was_actually_destroyed(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The demo's central security claim, which was the one condition still unpinned.

    ``demonstrate_destruction`` grades irreversibility with
    ``not successes and bool(refusals)``, and that expression could be replaced with
    the literal ``True`` while the entire suite stayed green -- measured: 53 passed.
    Every other graded condition in ``demo.py`` is killed by some test; this one, the
    claim the whole demonstration exists to make, was not. A demo that destroyed
    nothing would have printed ``PASS`` and exited 0.

    Its sibling ``test_the_pre_destroy_control_goes_red_when_the_restore_put_nothing_back``
    pins the *control* -- "there was something to restore" -- which is a different
    claim, and its own docstring says the control "was as unpinned as the thing it
    controls". The thing it controls is pinned here.

    The sabotage is the honest one: leave the run completely real and neuter only the
    erasure, so the probe, the token and the response are exactly what a genuine run
    produces and the only difference is that the key was never popped. Restoration
    then succeeds, which is precisely the state the check exists to report as a
    failure. Patching the restorer instead would prove nothing -- it would test the
    test.
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
    assert probe is not None and probe.token_id is not None, "premise: a real probe"

    # Neuter BOTH halves of the erasure. Popping the key alone would still make the
    # vault unreadable, so a half-sabotage would leave the check green and prove
    # nothing about what it grades.
    async def no_destroy_session(_session_id: str) -> bool:
        return True

    async def no_destroy_vault(_session_id: str) -> None:
        return None

    monkeypatch.setattr(harness.sessions, "destroy", no_destroy_session)
    monkeypatch.setattr(harness.vault, "destroy", no_destroy_vault)

    destruction = demo.CheckList()
    await demo.demonstrate_destruction(
        harness, destruction, session_id=session_id, probe=probe
    )

    graded = {record.name: record for record in destruction.records}
    irreversible = graded["restoration FAILS after destruction (irreversible across sessions)"]
    assert irreversible.ok is False, (
        "the session was never destroyed and the check still passed: "
        f"{irreversible.detail}"
    )
    assert "unexpectedly succeeded" in irreversible.detail
    assert destruction.banner(1.0) == demo.EXIT_ASSERTION_FAILED

    # And the control stays GREEN -- it reads the pre-destroy restore, which the
    # sabotage does not touch. That is what makes this test about irreversibility
    # alone rather than about the whole section going red together.
    control = graded["restoration WORKS before destruction (control for the next check)"]
    assert control.ok is True, control.detail
