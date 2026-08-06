#!/usr/bin/env python3
"""Headless end-to-end demonstration of the secure context pipeline (build doc section 9.11).

This is the artifact to run first. It walks the whole round trip --

    upload -> detect -> obfuscate -> EGRESS GATE -> LLM -> restore -> destroy

-- printing the original document, the literal outbound payload, the raw model
response and the restored answer side by side, and then *proving* the two claims
the system is graded on:

1. **Nothing sensitive leaves the process.** Every original value the vault holds
   for the session is searched for in the outbound payload, raw and normalised.
   Zero hits is the pass condition. ``--dump-wire`` (with ``--real``) does the
   same scan against the literal bytes of the HTTP request body, so the claim is
   demonstrated on the wire rather than argued.
2. **Restoration is reversible in-session and irreversible across it.** A token
   is resolved through the vault, the session is destroyed, and the same lookup
   is attempted again -- it must fail. That failure is the live-review moment.

Every claim above is an assertion. **The process exits non-zero if any of them
fails**, which is what lets this file double as the CI smoke test.

Printing rules honoured here (build doc section 16): the master key, session keys
and the API key are never printed -- not even truncated. Original entity values
appear only inside the labelled document/answer panes, which are the artifact the
reviewer asked for; every other line reports counts, token IDs, hashes and
timings. ``print()`` is allowed in this file and nowhere else in the repo.

Usage::

    python demo.py                                    # mock provider, tokenization
    python demo.py --strategy pseudonymization
    python demo.py --file /path/to/their.pdf --category legal
    python demo.py --real                             # needs ANTHROPIC_API_KEY
    python demo.py --real --dump-wire                 # + capture the HTTP body
    python demo.py --verify-chain                     # audit chain check, then exit
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import difflib
import hashlib
import math
import os
import re
import secrets
import sys
import textwrap
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

import httpx

from secure_context_pipeline.audit.logger import (
    DEFAULT_DB_FILENAME as AUDIT_DB_FILENAME,
)
from secure_context_pipeline.audit.logger import (
    EGRESS_BLOCK,
    EGRESS_PASS,
    LLM_CALL,
    VAULT_DESTROY,
    AuditLogger,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import normalize
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector, warm_up
from secure_context_pipeline.detection.registry import load_registry
from secure_context_pipeline.errors import ConfigError, EgressBlockedError, PipelineError
from secure_context_pipeline.llm.anthropic_provider import AnthropicProvider
from secure_context_pipeline.llm.base import DetailedLLMProvider, build_provider
from secure_context_pipeline.models import (
    AuditEvent,
    EntityCategory,
    PipelineResult,
    TokenRecord,
)
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import MIN_ORIGINAL_LEN, EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import DOC_CATEGORIES, EncryptedDocumentStore
from secure_context_pipeline.surrogates import (
    REDACTION_RE,
    TOKEN_RE,
    extract_token_ids,
    format_surrogate,
)
from secure_context_pipeline.textrules import occurs_as_a_unit
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import (
    DEFAULT_DB_FILENAME as VAULT_DB_FILENAME,
)
from secure_context_pipeline.vault.session_vault import SessionVault

REPO_ROOT: Final = Path(__file__).resolve().parent

# --- presentation constants -------------------------------------------------
WIDTH: Final = 80  # every line this file prints fits in 80 columns
LEFT_W: Final = 38  # 1 + 38 + 1 + 39 + 1 == 80
RIGHT_W: Final = 39
EXCERPT_LINES: Final = 16
RESPONSE_LINES: Final = 12
AUDIT_TAIL: Final = 14

# --- demo inputs ------------------------------------------------------------
USER_ID: Final = "demo-reviewer"
PRIMARY_FIXTURE: Final = REPO_ROOT / "fixtures" / "medical_note.txt"
PRIMARY_CATEGORY: Final = "medical"
#: Build doc section 9.11 fixes the second leg of the sequence: pseudonymization
#: on the legal memo. It stays put even when ``--file`` replaces the first leg,
#: so both strategies are always exercised in one run.
SECONDARY_FIXTURE: Final = REPO_ROOT / "fixtures" / "legal_memo.txt"
SECONDARY_CATEGORY: Final = "legal"
DEFAULT_PROMPT: Final = (
    "Summarise this document: who is involved, the key dates, and the most "
    "important figures. Answer in short bullet points."
)
WIRE_DUMP_PATH: Final = REPO_ROOT / "wire_dump.txt"

#: The stand-in for an entity the detector missed, used by
#: :func:`demonstrate_fail_closed`. Deliberately something the shipped registry
#: classifies as nothing -- verified against ``entities.yaml`` in every category
#: -- because the whole demonstration rests on obfuscation leaving it alone. If a
#: future registry rule starts matching it, the fail-closed check goes red rather
#: than quietly passing for the wrong reason, and the fix is a new sentinel.
LEAK_SENTINEL: Final = "8QX-DELTA-4471"
#: 8 hex characters, the shape ``format_surrogate`` requires. Not a secret: a
#: token ID is a public label that names a vault row, never a key.
LEAK_TOKEN_ID: Final = "5e17a0c3"  # noqa: S105 -- a surrogate label, not a credential
LEAK_DOC: Final = (
    "OPERATIONS MEMO\n\n"
    "This file is an internal working note. It records one item only.\n\n"
    f"Ledger tag {LEAK_SENTINEL} is cited on every page of the reconciliation.\n\n"
    "Nothing further is recorded here.\n"
)
#: Page size for the demo's own audit reads. The log is append-only and shared
#: across runs, so a fixed ceiling keeps the scan bounded on a well-used data dir.
MAX_AUDIT_SCAN: Final = 1000
#: Build doc section 12: the full-pipeline budget, checked under ``--real``.
REAL_BUDGET_S: Final = 15.0

# --- exit codes -------------------------------------------------------------
EXIT_OK: Final = 0
EXIT_ASSERTION_FAILED: Final = 1
EXIT_USAGE: Final = 2


# ---------------------------------------------------------------------------
# Colour -- only when stdout is a terminal, never in CI logs or pipes
# ---------------------------------------------------------------------------
_ANSI = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
}
_RESET = "\033[0m"
_COLOUR_ENABLED = False


def _paint(text: str, colour: str) -> str:
    if not _COLOUR_ENABLED or not text:
        return text
    return f"{_ANSI[colour]}{text}{_RESET}"


def bold(text: str) -> str:
    return _paint(text, "bold")


def dim(text: str) -> str:
    return _paint(text, "dim")


def green(text: str) -> str:
    return _paint(text, "green")


def red(text: str) -> str:
    return _paint(text, "red")


def yellow(text: str) -> str:
    return _paint(text, "yellow")


def cyan(text: str) -> str:
    return _paint(text, "cyan")


def _highlight(line: str) -> str:
    """Colour surrogate tokens and redaction markers inside an already-padded row.

    Applied *after* padding, so the inserted escape sequences cannot disturb the
    column arithmetic -- a terminal gives them zero width.
    """
    if not _COLOUR_ENABLED:
        return line
    line = TOKEN_RE.sub(lambda m: cyan(m.group(0)), line)
    return REDACTION_RE.sub(lambda m: yellow(m.group(0)), line)


# ---------------------------------------------------------------------------
# Layout primitives -- plain ASCII, no external deps
# ---------------------------------------------------------------------------
def hr(char: str = "=") -> None:
    print(char * WIDTH)


def section(title: str) -> None:
    head = f"== {title.upper()} "
    print()
    print(bold(head + "=" * max(0, WIDTH - len(head))))


def wrapped(prefix: str, body: str, *, style: Callable[[str], str] | None = None) -> None:
    """Print ``prefix + body``, wrapped to 80 columns and hanging-indented.

    ``prefix`` must be plain text -- its length is the column arithmetic. Colour
    is applied per output line afterwards, where it cannot affect the width.
    """
    width = max(20, WIDTH - len(prefix))
    chunks = textwrap.wrap(body, width=width, break_long_words=False, break_on_hyphens=False)
    pad = " " * len(prefix)
    for index, chunk in enumerate(chunks or [""]):
        line = (prefix if index == 0 else pad) + chunk
        print(style(line) if style else line)


def kv(key: str, value: str) -> None:
    wrapped(f"  {key:<14}", value)


def _clean(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in text.expandtabs(4)).rstrip()


def _cell(text: str, width: int, offset: int = 0) -> str:
    """One pane cell: printable characters only, windowed, truncated and padded.

    ``offset`` scrolls the cell horizontally. Both cells of a row always share
    one offset, so a row still shows the *same* stretch of text on both sides.
    """
    body = _clean(text)
    if offset and len(body) > offset:
        body = "<" + body[offset:]
    elif offset:
        body = ""
    inner = width - 2
    if len(body) > inner:
        body = body[: inner - 1] + ">"
    return " " + body.ljust(inner) + " "


def _focus_offset(left: str, right: str, inner: int) -> int:
    """Scroll far enough right that the first difference is on screen.

    Without this, a long line whose only change is at column 90 shows two
    identical-looking cells -- the opposite of what the pane is for.
    """
    left, right = _clean(left), _clean(right)
    if not left or not right:
        return 0
    limit = min(len(left), len(right))
    first = next((i for i in range(limit) if left[i] != right[i]), limit)
    if first == limit and len(left) == len(right):
        return 0
    context = 8
    if first < inner - context:
        return 0
    return first - context


#: Cost of leaving a line unpaired in :func:`_align_block`. Two gaps (-0.7) must
#: cost more than pairing two merely dissimilar lines, or the aligner would
#: rather stagger the panes than admit two lines correspond.
_GAP_PENALTY: Final = -0.35


def _similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    return difflib.SequenceMatcher(None, left, right).quick_ratio()


def _align_block(left: list[str], right: list[str]) -> list[tuple[str, str]]:
    """Best monotone pairing of two changed blocks, by line similarity.

    Needleman-Wunsch over line similarity. Blocks are a handful of lines, so the
    O(n*m) cost is nothing, and it is the only thing that keeps a pane honest
    when one side gains a line -- which happens whenever a restored value
    contains the newline the original span straddled.
    """
    n, m = len(left), len(right)
    if not n or not m:
        return [(line, "") for line in left] + [("", line) for line in right]

    score = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        score[i][0] = score[i - 1][0] + _GAP_PENALTY
    for j in range(1, m + 1):
        score[0][j] = score[0][j - 1] + _GAP_PENALTY
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            score[i][j] = max(
                score[i - 1][j - 1] + _similarity(left[i - 1], right[j - 1]),
                score[i - 1][j] + _GAP_PENALTY,
                score[i][j - 1] + _GAP_PENALTY,
            )

    rows: list[tuple[str, str]] = []
    i, j = n, m
    while i > 0 or j > 0:
        diagonal = (
            score[i - 1][j - 1] + _similarity(left[i - 1], right[j - 1])
            if i > 0 and j > 0
            else None
        )
        if diagonal is not None and math.isclose(score[i][j], diagonal, abs_tol=1e-9):
            rows.append((left[i - 1], right[j - 1]))
            i -= 1
            j -= 1
        elif i > 0 and math.isclose(score[i][j], score[i - 1][j] + _GAP_PENALTY, abs_tol=1e-9):
            rows.append((left[i - 1], ""))
            i -= 1
        else:
            rows.append(("", right[j - 1]))
            j -= 1
    rows.reverse()
    return rows


def align_rows(left_lines: list[str], right_lines: list[str]) -> list[tuple[str, str]]:
    """Pair the two texts line-for-line, tolerating inserted and removed lines.

    A detected span can swallow a newline (a name wrapped across two lines
    becomes one token, and restoring it puts the newline back), so the two sides
    do not always have the same line count. Naive index pairing drifts from that
    point on and the panes stop being a diff. :mod:`difflib` re-anchors on the
    lines that survived unchanged; :func:`_align_block` pairs the rest by
    similarity, which is what the answer panes need -- there, *every* interesting
    line differs, so there is nothing for exact matching to anchor on.
    """
    matcher = difflib.SequenceMatcher(a=left_lines, b=right_lines, autojunk=False)
    rows: list[tuple[str, str]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            # get_opcodes guarantees i2 - i1 == j2 - j1 for an "equal" block.
            rows.extend(
                (left_lines[i], right_lines[j])
                for i, j in zip(range(i1, i2), range(j1, j2), strict=True)
            )
            continue
        rows.extend(_align_block(left_lines[i1:i2], right_lines[j1:j2]))
    return rows


def _pane_rule() -> str:
    return "+" + "-" * LEFT_W + "+" + "-" * RIGHT_W + "+"


def two_pane(
    left_title: str,
    right_title: str,
    rows: list[tuple[str, str]],
    *,
    footer: str | None = None,
) -> None:
    """The 80-column side-by-side view (build doc section 9.11).

    Lines are truncated, never wrapped: the pane is only useful if row *i* on the
    left is the same source line as row *i* on the right.
    """
    rule = _pane_rule()
    print(rule)
    print("|" + bold(_cell(left_title, LEFT_W)) + "|" + bold(_cell(right_title, RIGHT_W)) + "|")
    print(rule)
    for left, right in rows:
        offset = _focus_offset(left, right, LEFT_W - 2)
        print(_highlight(
            "|" + _cell(left, LEFT_W, offset) + "|" + _cell(right, RIGHT_W, offset) + "|"
        ))
    print(rule)
    if footer:
        wrapped("  ", footer, style=dim)


def bullet_list(items: list[str], indent: str = "  ") -> None:
    """Print short items packed into 80-column lines."""
    line = indent
    for item in items:
        if len(line) + len(item) + 2 > WIDTH and line.strip():
            print(line.rstrip())
            line = indent
        line += item + "  "
    if line.strip():
        print(line.rstrip())


# ---------------------------------------------------------------------------
# Assertion ledger -- this is what the exit code is computed from
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Check:
    name: str
    ok: bool
    detail: str
    fatal: bool


@dataclass(slots=True)
class CheckList:
    """Every assertion the demo makes, in the order it made them."""

    records: list[Check] = field(default_factory=list)

    def record(self, name: str, ok: bool, detail: str = "", *, fatal: bool = True) -> bool:
        self.records.append(Check(name=name, ok=ok, detail=detail, fatal=fatal))
        plain = "[PASS]" if ok else ("[FAIL]" if fatal else "[WARN]")
        colour = green if ok else (red if fatal else yellow)
        prefix = f"  {plain} "
        if detail and len(prefix) + len(name) + len(detail) + 2 <= WIDTH:
            print(f"  {colour(plain)} {name}  {dim(detail)}")
            return ok
        wrapped(prefix, name, style=lambda line: line.replace(plain, colour(plain), 1))
        if detail:
            wrapped(" " * len(prefix), detail, style=dim)
        return ok

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.records if not c.ok and c.fatal]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.records if not c.ok and not c.fatal]

    def banner(self, elapsed_s: float) -> int:
        failures = self.failures
        warnings = self.warnings
        print()
        hr()
        passed = sum(1 for c in self.records if c.ok)
        summary = f"{passed}/{len(self.records)} checks passed"
        if warnings:
            summary += f", {len(warnings)} warning(s)"
        if failures:
            print(red(bold(f"  FAIL -- {len(failures)} assertion(s) failed ({summary})")))
            for check in failures:
                wrapped("         - ", check.name, style=red)
        else:
            print(green(bold(f"  PASS -- {summary}, 0 failures  [{elapsed_s:.1f}s]")))
        hr()
        return EXIT_ASSERTION_FAILED if failures else EXIT_OK


# ---------------------------------------------------------------------------
# Leak scanning -- the demo's own copy, deliberately independent of the gate
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ScanResult:
    hits: int
    scanned: int
    skipped_short: int
    #: Of ``hits``, how many occur only *inside a longer word*. Split out because
    #: the two are different findings -- see :func:`scan_for_originals`.
    substring_only: int = 0

    @property
    def leaks(self) -> int:
        """Hits that occur as a unit -- the ones that are actually leaks."""
        return self.hits - self.substring_only

    @property
    def detail(self) -> str:
        base = (
            f"{self.scanned} vault originals scanned, {self.leaks} found, "
            f"{self.skipped_short} skipped (<{MIN_ORIGINAL_LEN} chars)"
        )
        if self.substring_only:
            base += (
                f"; {self.substring_only} more present only inside a longer word "
                "(reported separately, not counted as a leak)"
            )
        return base


def scan_for_originals(haystack: str, originals: frozenset[str]) -> ScanResult:
    """Count vault originals present in ``haystack``, raw and normalised.

    **Deliberately independent of the gate, and deliberately stricter**: plain
    containment, no boundary rule. That is the point -- if this imported
    :func:`~secure_context_pipeline.textrules.occurs_as_a_unit` it could only ever
    agree with the control it exists to re-check, which is the failure mode that
    let a leak sit behind a green ``100/100`` for three audit loops.

    Being stricter means it sees things the gate deliberately ignores, so a raw hit
    is classified rather than reported flat:

    * **occurs as a unit** -- a real leak. Fatal.
    * **present only inside a longer word** -- the ``Brown``/``Browning`` case: a
      *generated fake* surname happens to contain a real vaulted one. The value is
      not readable as itself and the gate is right not to block it, but it is worth
      seeing, so it is reported separately and does not fail the run.

    That distinction is not cosmetic. Pseudonyms are drawn from a random per-session
    key, so the second case appears on roughly one run in a few hundred; counting it
    as a leak made this demo fail intermittently for a reason that was not a leak --
    the worst possible behaviour for the one artefact a reviewer runs live. (An
    earlier version of this docstring claimed to mirror
    ``EgressGate._scan_originals``. It never did: the gate applies a word-boundary
    rule, plus identifier needles and folded forms. Saying so was itself an instance
    of the recurring defect this project documents.)

    Values shorter than :data:`MIN_ORIGINAL_LEN` are skipped -- a two-character value
    matches inside almost any text and carries no re-identification signal on its own
    -- and the skipped count is printed so the exclusion is visible rather than hidden.
    """
    normalised_haystack = normalize(haystack)
    hits = 0
    substring_only = 0
    skipped = 0
    for original in originals:
        if len(original.strip()) < MIN_ORIGINAL_LEN:
            skipped += 1
            continue
        normalised = normalize(original)
        raw_hit = original in haystack
        normalised_hit = len(normalised) >= MIN_ORIGINAL_LEN and normalised in normalised_haystack
        if not (raw_hit or normalised_hit):
            continue
        hits += 1
        # Classified with the shared rule, which is exactly the question "is this
        # value readable as itself here?" -- not used to *find* the hit, only to
        # grade one this module found on its own.
        as_a_unit = occurs_as_a_unit(original, haystack) or occurs_as_a_unit(
            normalised, normalised_haystack
        )
        if not as_a_unit:
            substring_only += 1
    return ScanResult(
        hits=hits,
        scanned=len(originals) - skipped,
        skipped_short=skipped,
        substring_only=substring_only,
    )


def residual_tokens(text: str) -> list[str]:
    """Surrogate tokens still present in restored output. Must be empty."""
    return [match.group(0) for match in TOKEN_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Wire capture (--dump-wire)
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class WireCapture:
    """Captures the literal outbound HTTP request body via an httpx event hook.

    Only ``request.content`` is read. Headers are never touched, so the API key
    cannot reach the dump file.
    """

    bodies: list[bytes] = field(default_factory=list)

    async def on_request(self, request: httpx.Request) -> None:
        try:
            body = request.content
        except (httpx.StreamConsumed, httpx.RequestNotRead):  # pragma: no cover -- non-streaming
            body = await request.aread()
        self.bodies.append(bytes(body))


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Harness:
    settings: Settings
    audit: AuditLogger
    store: EncryptedDocumentStore
    sessions: SessionRegistry
    vault: SessionVault
    restorer: Restorer
    orchestrator: PipelineOrchestrator
    provider_name: str

    async def close(self) -> None:
        """Close every aiosqlite connection.

        Not optional: an unclosed connection keeps a non-daemon worker thread
        alive and the process hangs at exit instead of returning its status code
        -- which would quietly break the smoke-test contract this file exists to
        provide. Each close is independent so one failure cannot skip the rest.
        """
        for label, closer in (
            ("vault", self.vault.close),
            ("store", self.store.close),
            ("audit", self.audit.close),
        ):
            try:
                await closer()
            except Exception as exc:  # teardown must never mask the real result
                print(yellow(f"  note: {label} teardown raised {type(exc).__name__}"))


async def build_harness(settings: Settings, provider: DetailedLLMProvider) -> Harness:
    data_dir = Path(settings.data_dir)
    await asyncio.to_thread(data_dir.mkdir, parents=True, exist_ok=True)

    registry = load_registry(settings.registry_path)
    audit = await AuditLogger.open(data_dir / AUDIT_DB_FILENAME)
    store = await EncryptedDocumentStore.open(settings)
    sessions = SessionRegistry(settings)
    vault = await SessionVault.open(data_dir / VAULT_DB_FILENAME, sessions)

    # Session keys never survive a process restart, so rows left by a previous
    # run are undecryptable garbage. Same startup hygiene the API performs.
    swept = await vault.sweep_orphans(await sessions.active_ids())
    if swept:
        kv("swept", f"{swept} orphan vault row(s) from earlier runs (undecryptable)")

    detector = Detector(registry, settings)
    restorer = Restorer(vault=vault, settings=settings, audit=audit)
    orchestrator = PipelineOrchestrator(
        store=store,
        detector=detector,
        engine=ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=settings,
            audit=audit,
        ),
        injector=ContextInjector(),
        gate=EgressGate(vault=vault, detector=detector, settings=settings, audit=audit),
        provider=provider,
        restorer=restorer,
        vault=vault,
        settings=settings,
        audit=audit,
    )
    return Harness(
        settings=settings,
        audit=audit,
        store=store,
        sessions=sessions,
        vault=vault,
        restorer=restorer,
        orchestrator=orchestrator,
        provider_name=provider.name,
    )


def load_settings(provider: Literal["mock", "anthropic"]) -> tuple[Settings, bool]:
    """Settings for this run, generating an ephemeral master key if there is none.

    A clean clone has no ``.env``; ``python demo.py`` must still work there. The
    first attempt is made *without* touching the environment so a real
    ``SCP_MASTER_KEY`` (env or ``.env``) always wins -- only a genuinely missing
    key triggers generation. Returns ``(settings, key_was_generated)``.
    """
    try:
        return Settings(llm_provider=provider), False
    except ConfigError as exc:
        if exc.detail.get("reason") != "master_key_missing":
            raise
    # 32 random bytes, base64. Lives in this process's environment only: it is
    # never written to disk and never printed.
    os.environ["SCP_MASTER_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()
    return Settings(llm_provider=provider), True


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------
def _display_path(path: Path) -> str:
    """Absolute path, shortened to a relative one when it sits under the cwd."""
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(Path.cwd()))
    except ValueError:
        return str(resolved)


def document_body(payload: str) -> str:
    """The fenced document inside the outbound payload, for line-aligned panes."""
    match = re.search(r"<DOCUMENT>\n(.*)\n</DOCUMENT>", payload, re.DOTALL)
    return match.group(1) if match else payload


def _is_obfuscated_line(line: str, surrogates: frozenset[str]) -> bool:
    if TOKEN_RE.search(line) or REDACTION_RE.search(line):
        return True
    return any(surrogate in line for surrogate in surrogates)


def pick_window(
    rows: list[tuple[str, str]], surrogates: frozenset[str], count: int
) -> tuple[int, int]:
    """Row window starting a little before the first obfuscated row.

    The interesting part of a document is where the entities are; opening the
    pane on the letterhead would waste the reviewer's screen.
    """
    for index, (_left, right) in enumerate(rows):
        if _is_obfuscated_line(right, surrogates):
            start = max(0, index - 2)
            return start, start + count
    return 0, count


def print_entity_tables(result: PipelineResult) -> None:
    by_action: Counter[str] = Counter(span.action.value for span in result.detections)
    by_type: Counter[str] = Counter(span.entity_type for span in result.detections)
    print(f"  {bold('entities')}   {len(result.detections)} spans "
          f"({len(by_type)} distinct types)")
    print("  by action  " + "  ".join(
        f"{action}={count}" for action, count in sorted(by_action.items())
    ))
    print("  by type")
    ranked = sorted(by_type.items(), key=lambda item: (-item[1], item[0]))
    bullet_list([f"{name}={count}" for name, count in ranked], indent="    ")


_STAGE_LABELS: Final = (
    ("fetch_ms", "fetch+decrypt"),
    ("detect_ms", "detect"),
    ("obfuscate_ms", "obfuscate+vault"),
    ("egress_ms", "EGRESS GATE"),
    ("llm_ms", "llm call"),
    ("restore_ms", "restore"),
)


def print_timings(result: PipelineResult) -> None:
    total = max(result.stats.get("total_ms", 0.0), 1e-9)
    print(f"  {bold('timings')}    per stage, from PipelineResult.stats")
    for key, label in _STAGE_LABELS:
        value = result.stats.get(key, 0.0)
        share = value / total
        bar = "#" * max(0, min(24, round(share * 24)))
        print(f"    {label:<16}{value:>9.1f} ms  {share * 100:>5.1f}%  {bar}")
    print(f"    {'TOTAL':<16}{total:>9.1f} ms")


@dataclass(slots=True)
class RunOutcome:
    result: PipelineResult
    doc_id: str
    wall_s: float


async def run_case(
    harness: Harness,
    checks: CheckList,
    *,
    session_id: str,
    path: Path,
    category: str,
    strategy: str,
    prompt: str,
    panes: bool,
    nonvacuity_fatal: bool,
) -> RunOutcome:
    """Upload one document, run the pipeline, print it, and assert on it."""
    content = await asyncio.to_thread(path.read_bytes)
    # Announced before the store call so an unsupported file type reports which
    # document failed, not just which suffix.
    kv("file", f"{path.name}  ({len(content):,} bytes, category={category})")
    doc_id = await harness.store.put(USER_ID, path.name, content, category)
    kv("doc_id", f"{doc_id}  (AES-256-GCM at rest, AAD-bound)")
    kv("strategy", strategy)

    started = time.perf_counter()
    result = await harness.orchestrator.run(session_id, USER_ID, doc_id, prompt, strategy)
    wall_s = time.perf_counter() - started
    kv("run_id", result.run_id)

    original_text = await harness.store.get_text(USER_ID, doc_id)
    outbound_doc = document_body(result.obfuscated_payload)
    surrogates = frozenset(s.surrogate for s in result.detections if s.surrogate)

    if panes:
        doc_rows = align_rows(original_text.splitlines(), outbound_doc.splitlines())
        start, end = pick_window(doc_rows, surrogates, EXCERPT_LINES)
        print()
        two_pane(
            "ORIGINAL DOCUMENT (at rest)",
            "OUTBOUND PAYLOAD (on the wire)",
            doc_rows[start:end],
            footer=(
                f"rows {start + 1}-{min(end, len(doc_rows))} of {len(doc_rows)} | "
                f"'<' '>' mark truncation | payload "
                f"{len(result.obfuscated_payload):,} chars incl. system prompt"
            ),
        )
        print()
        answer_rows = align_rows(
            result.raw_llm_response.splitlines(), result.restored_text.splitlines()
        )
        two_pane(
            "RAW LLM RESPONSE (surrogates)",
            "RESTORED ANSWER (to the user)",
            answer_rows[:RESPONSE_LINES],
            footer=(
                f"restored {int(result.stats.get('restored_count', 0))} surrogate occurrence(s); "
                f"vault misses: {int(result.stats.get('vault_misses', 0))}"
            ),
        )

    print()
    print_entity_tables(result)
    print()
    print_timings(result)

    # --- assertions --------------------------------------------------------
    originals = harness.vault.originals_for_session(session_id)
    print()
    print(f"  {bold('assertions')}")

    checks.record(
        f"[{strategy}] vault holds entities -- the leak scan is not vacuous",
        bool(originals) and result.stats.get("tokens_issued", 0.0) > 0,
        f"{len(originals)} originals, {int(result.stats.get('tokens_issued', 0))} tokens issued",
        fatal=nonvacuity_fatal,
    )
    payload_scan = scan_for_originals(result.obfuscated_payload, originals)
    checks.record(
        f"[{strategy}] ZERO originals in the outbound payload",
        payload_scan.leaks == 0,
        payload_scan.detail,
    )
    response_scan = scan_for_originals(result.raw_llm_response, originals)
    checks.record(
        f"[{strategy}] ZERO originals in the raw provider response",
        response_scan.leaks == 0,
        response_scan.detail,
    )
    residual = residual_tokens(result.restored_text)
    checks.record(
        f"[{strategy}] ZERO residual surrogate tokens in the restored output",
        not residual,
        f"{len(result.restored_text):,} chars scanned with surrogates.TOKEN_RE",
    )

    events = await harness.audit.query(run_id=result.run_id)
    egress_seq = [e.seq for e in events if e.event_type == EGRESS_PASS and e.seq is not None]
    llm_seq = [e.seq for e in events if e.event_type == LLM_CALL and e.seq is not None]
    checks.record(
        f"[{strategy}] EGRESS_PASS is audited before the provider call",
        bool(egress_seq) and bool(llm_seq) and min(egress_seq) < min(llm_seq),
        f"seq {egress_seq or '-'} then {llm_seq or '-'} of {len(events)} events for this run",
    )
    checks.record(
        f"[{strategy}] egress gate scanned the exact bytes that were sent",
        any(
            e.detail.get("payload_sha256") == _sha256_of(result.obfuscated_payload)
            for e in events
            if e.event_type in (EGRESS_PASS, LLM_CALL)
        ),
        "payload_sha256 in EGRESS_PASS matches the serialized payload",
    )
    return RunOutcome(result=result, doc_id=doc_id, wall_s=wall_s)


def _sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def demonstrate_fail_closed(
    harness: Harness, checks: CheckList, *, session_id: str, prompt: str
) -> None:
    """Make the egress gate refuse, and show what refusal costs.

    Runs A and B show the gate *passing*, which is the uninteresting half: a
    payload with nothing wrong in it is released by a gate that does nothing at
    all. The claim this system is built on is the other half -- that a payload
    with an original still in it is **not** released -- and that half was, until
    this section existed, asserted in a docstring and demonstrated nowhere.

    The failure is injected where it actually happens. The gate's first pass
    scans the outbound payload for every original the session's vault holds, so
    the way to stage "the detector missed one" is to put a value in the vault
    that the detector does not flag: the engine leaves it in the payload
    verbatim, exactly as it would leave a real entity it failed to recognise.
    :data:`LEAK_SENTINEL` is chosen for that -- it is checked against the shipped
    registry and detected as nothing, in any category.

    Three things are then true and all three are checked, because the first alone
    is not the property:

    * the run raises ``EGRESS_BLOCKED`` instead of returning an answer;
    * **no ``LLM_CALL`` event exists for that run**, against runs A and B which
      both have one -- the refusal happened *before* the provider, not after;
    * the error a caller receives names a reason and a count and never the value
      that would have leaked. A block that leaked the blocked value in its own
      error message would be a worse hole than the one it closed.
    """
    print(dim("  runs A and B show the gate passing. That is the easy half: a gate"))
    print(dim("  that always passes looks identical. Here it must refuse."))

    doc_id = await harness.store.put(USER_ID, "leak_probe.txt", LEAK_DOC.encode("utf-8"), "general")
    kv("file", f"leak_probe.txt  (synthetic, {len(LEAK_DOC)} bytes, category=general)")
    kv("doc_id", doc_id)
    wrapped(
        "  premise       ",
        "one value in this document is in the session vault but is not something "
        "the detector recognises, so obfuscation leaves it in the payload -- which "
        "is what a missed entity looks like from the gate's side. The value itself "
        "is not printed here, or anywhere.",
        style=dim,
    )

    # The vault entry a real detection would have written. `put` is the same call
    # the obfuscation engine makes; nothing here reaches around the vault's API.
    await harness.vault.put(
        session_id,
        TokenRecord(
            session_id=session_id,
            token_id=LEAK_TOKEN_ID,
            entity_type="ACCOUNT_REF",
            category=EntityCategory.FIN,
            surrogate=format_surrogate("FIN", "ACCOUNT_REF", LEAK_TOKEN_ID),
            created_at=time.time(),
        ),
        LEAK_SENTINEL,
    )

    blocked: EgressBlockedError | None = None
    try:
        await harness.orchestrator.run(session_id, USER_ID, doc_id, prompt, "tokenization")
    except EgressBlockedError as exc:
        blocked = exc

    print()
    checks.record(
        "EGRESS GATE BLOCKS a payload that still carries an original",
        blocked is not None,
        f"EgressBlockedError(reason={blocked.detail.get('reason')!r}, "
        f"hit_count={blocked.detail.get('hit_count')})" if blocked else
        "the run completed -- the gate released a payload containing a vault original",
    )

    # Scoped to *this* run, read out of the log rather than out of the exception:
    # the evidence is the audit trail a reviewer can query for themselves, and a
    # whole-log scan would pick up blocks from earlier demo runs sharing ./data.
    run_id = blocked.detail.get("run_id") if blocked else None
    events = (
        await harness.audit.query(run_id=run_id, limit=MAX_AUDIT_SCAN)
        if isinstance(run_id, str)
        else []
    )
    kinds = [e.event_type for e in events]
    checks.record(
        "the provider was NEVER called for the blocked run",
        EGRESS_BLOCK in kinds and LLM_CALL not in kinds,
        f"run {run_id} emitted {len(events)} event(s): "
        f"{EGRESS_BLOCK} present, {LLM_CALL} absent",
    )

    # Non-vacuity. "No LLM_CALL for that run" is also what a broken provider
    # wiring would produce, so the same session's *passing* runs have to show
    # the event this one is missing.
    passing = await harness.audit.query(
        session_id=session_id, event_type=LLM_CALL, limit=MAX_AUDIT_SCAN
    )
    checks.record(
        "control: the same session's passing runs DO reach the provider",
        bool(passing) and all(e.run_id != run_id for e in passing),
        f"{len(passing)} {LLM_CALL} event(s) for this session, none of them this run",
    )

    surfaced = repr(blocked) + str(dict(blocked.detail)) if blocked else ""
    checks.record(
        "the block itself leaks nothing -- the refused value is not in the error",
        blocked is not None and LEAK_SENTINEL not in surfaced,
        f"{len(surfaced)} chars of error detail scanned; keys "
        f"{sorted(blocked.detail) if blocked else []}",
    )
    if blocked is not None:
        print()
        wrapped("  caller receives: ", f"422 {blocked.code} {dict(blocked.detail)}", style=yellow)


@dataclass(slots=True)
class DestroyProbe:
    """The exact restoration that must succeed before destruction and fail after.

    Built from a real run rather than invented, and deliberately chosen so the
    post-destroy attempt *has* to reach the vault: a response with nothing to
    restore would "succeed" after destruction and prove nothing.
    """

    token_id: str | None
    surrogate: str | None
    text: str
    strategy: str
    surrogate_map: dict[str, str] | None
    #: The token IDs the producing run actually minted. Passed to `restore` as
    #: `issued`, exactly as `PipelineOrchestrator` does. Without it the restorer
    #: runs ungated: it queries the vault for any token-shaped run in the model's
    #: output, so a coincidence between eight hex characters in the response and a
    #: live token ID substitutes another entity's value -- the incident
    #: `restorer.py`'s module docstring records -- and every miss audits as
    #: MISS_INDETERMINATE carrying the model's own bytes in `token_id`. Harmless on
    #: the mock path, where the response is built from our own tokens; the `--real`
    #: path is where a live model can emit whatever it likes.
    minted: frozenset[str]
    source: str


def build_probe(outcomes: list[RunOutcome]) -> DestroyProbe | None:
    """Pick a run whose raw response still forces a vault lookup on restore."""
    for outcome in outcomes:
        token_ids = extract_token_ids(outcome.result.raw_llm_response)
        if token_ids:
            return DestroyProbe(
                token_id=sorted(token_ids)[0],
                surrogate=None,
                text=outcome.result.raw_llm_response,
                strategy=outcome.result.strategy,
                surrogate_map=None,
                minted=frozenset(extract_token_ids(outcome.result.obfuscated_payload)),
                source=f"{len(token_ids)} token(s) in the {outcome.result.strategy} response",
            )
    # No tokens anywhere: pseudonyms only. An empty mapped value is the
    # restorer's documented "look it up in the vault" fallback, so the lookup
    # still happens -- which is what the check is about.
    for outcome in outcomes:
        for span in outcome.result.detections:
            if span.surrogate and span.surrogate in outcome.result.raw_llm_response:
                return DestroyProbe(
                    token_id=None,
                    surrogate=span.surrogate,
                    text=outcome.result.raw_llm_response,
                    strategy=outcome.result.strategy,
                    surrogate_map={span.surrogate: ""},
                    minted=frozenset(extract_token_ids(outcome.result.obfuscated_payload)),
                    source=f"pseudonym echoed in the {outcome.result.strategy} response",
                )
    return None


async def demonstrate_destruction(
    harness: Harness,
    checks: CheckList,
    *,
    session_id: str,
    probe: DestroyProbe | None,
) -> None:
    """Restore, destroy the session, then fail to restore the same thing.

    The pre-destroy restore is the half that makes the post-destroy failure mean
    something: without it, "restoration failed" could just mean there was
    nothing to restore. Resolved values are reported as lengths, never printed
    -- outside the labelled document panes this file emits counts only.
    """
    if probe is None:
        checks.record(
            "a restorable surrogate was produced (control for the destruction check)",
            False,
            "no run produced a surrogate the restorer would look up",
        )
        return

    kv("probe", probe.source)
    before = await harness.restorer.restore(
        session_id,
        probe.text,
        strategy=probe.strategy,
        surrogates=probe.surrogate_map,
        issued=probe.minted,
    )
    if probe.token_id is not None:
        original = await harness.vault.get_by_token(session_id, probe.token_id)
        kv("vault", f"token {probe.token_id} -> resolved, {len(original)} chars (value withheld)")
    checks.record(
        "restoration WORKS before destruction (control for the next check)",
        before.restored_count > 0,
        f"{before.restored_count} occurrence(s) restored from the vault",
    )

    # The key first, then the rows -- the same order as the API's logout path.
    # Popping the key is the actual erasure: every surviving ciphertext is
    # AES-GCM under a key derived from it, so once it is gone no write that
    # slips in behind this call can derive a vault key and resurrect the session.
    existed = await harness.sessions.destroy(session_id)
    await harness.vault.destroy(session_id)
    await harness.audit.emit(
        AuditEvent(
            ts=time.time(),
            session_id=session_id,
            event_type=VAULT_DESTROY,
            detail={"existed": int(existed), "source": "demo"},
        )
    )
    kv("destroyed", "session key popped, vault rows deleted, caches dropped")
    print()

    refusals: list[str] = []
    successes: list[str] = []

    if probe.token_id is not None:
        try:
            await harness.vault.get_by_token(session_id, probe.token_id)
            successes.append("vault.get_by_token returned a value")
        except PipelineError as exc:
            refusals.append(f"vault.get_by_token -> {exc.code}")
            print(red("  vault.get_by_token refused:"))
            wrapped("    ", repr(exc), style=red)

    try:
        await harness.restorer.restore(
            session_id,
            probe.text,
            strategy=probe.strategy,
            surrogates=probe.surrogate_map,
            issued=probe.minted,
        )
        successes.append("restorer.restore returned normally")
    except PipelineError as exc:
        refusals.append(f"restorer.restore -> {exc.code}")
        print(red("  restorer.restore refused:"))
        wrapped("    ", repr(exc), style=red)

    print()
    print(dim("  those errors are the demonstration, not a crash: the session key was popped"))
    print(dim("  from memory, so any ciphertext that survives on disk is unreadable -- by us,"))
    print(dim("  by an attacker with the database file, and by anyone holding the master key."))
    print()
    checks.record(
        "restoration FAILS after destruction (irreversible across sessions)",
        not successes and bool(refusals),
        "; ".join(refusals) if refusals else f"unexpectedly succeeded: {'; '.join(successes)}",
    )


async def print_audit_tail(harness: Harness, checks: CheckList, session_id: str) -> None:
    events = await harness.audit.query(session_id=session_id)
    tail = events[-AUDIT_TAIL:]
    wrapped(
        "  ",
        f"last {len(tail)} of {len(events)} events for this session "
        f"({await harness.audit.length()} in the log overall)",
        style=dim,
    )
    print(f"  {'seq':>5}  {'time':<8}  {'event':<14}  {'entity':<14}  {'token':<9}  hash")
    print("  " + "-" * (WIDTH - 4))
    for event in tail:
        stamp = time.strftime("%H:%M:%S", time.localtime(event.ts))
        entity = (event.entity_type or "-")[:14]
        token = (event.token_id or "-")[:9]
        digest = (event.entry_hash or "")[:8]
        print(f"  {event.seq:>5}  {stamp:<8}  {event.event_type:<14}  {entity:<14}  "
              f"{token:<9}  {digest}")

    print()
    whole = await harness.audit.verify_chain()
    scoped = await harness.audit.verify_chain(session_id)
    print(f"  verify_chain()                 -> {green('True') if whole else red('False')}")
    print(f"  verify_chain(session_id=...)   -> {green('True') if scoped else red('False')}")
    checks.record(
        "audit hash chain verifies (whole log and this session's slice)",
        whole and scoped,
        f"{await harness.audit.length()} chained events recomputed",
    )


async def dump_wire(capture: WireCapture, checks: CheckList, originals: frozenset[str]) -> None:
    """Write the literal HTTP request bodies and scan them for vault originals."""
    total = sum(len(b) for b in capture.bodies)
    kv("captured", f"{len(capture.bodies)} request body/bodies, {total:,} bytes")
    worst = ScanResult(hits=0, scanned=0, skipped_short=0)
    chunks: list[str] = [
        "Literal outbound HTTP request bodies captured by demo.py --dump-wire.",
        "Headers are deliberately NOT captured: the API key lives there.",
        f"captured_at={time.strftime('%Y-%m-%dT%H:%M:%S')}  bodies={len(capture.bodies)}",
        "",
    ]
    for index, body in enumerate(capture.bodies, start=1):
        text = body.decode("utf-8", errors="replace")
        scan = scan_for_originals(text, originals)
        worst = ScanResult(
            hits=worst.hits + scan.hits,
            # Carried, not dropped. Without it `leaks` (= hits - substring_only)
            # cannot be computed across bodies, which is what made the check below
            # use the wrong field. `scanned`/`skipped_short` are deliberately NOT
            # summed: `originals` is the same frozenset for every body, so adding
            # them would report one session's values N times.
            substring_only=worst.substring_only + scan.substring_only,
            scanned=scan.scanned,
            skipped_short=scan.skipped_short,
        )
        chunks.extend([f"----- request {index} ({len(body):,} bytes) -----", text, ""])
    await asyncio.to_thread(WIRE_DUMP_PATH.write_text, "\n".join(chunks), "utf-8")
    kv("written", str(WIRE_DUMP_PATH))
    checks.record(
        "ZERO originals in the literal HTTP request body (network inspection)",
        # `.leaks`, not `.hits` -- the same field `run_case` asserts on, and the
        # difference is not cosmetic. `hits` counts every occurrence including one
        # that appears ONLY inside a longer word, which `ScanResult.detail` itself
        # explains is not a disclosure (the documented Brown/Browning coincidence).
        # Asserting `hits == 0` therefore failed `--real --dump-wire` with exit 1 on
        # something that is not a leak, and the explanation `detail` carries was
        # printed under a FAIL. This path has no test of its own, which is how the
        # two halves of the demo drifted apart.
        worst.leaks == 0 and bool(capture.bodies),
        worst.detail if capture.bodies else "no request bodies were captured",
    )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
async def verify_chain_only(settings: Settings) -> int:
    data_dir = Path(settings.data_dir)
    await asyncio.to_thread(data_dir.mkdir, parents=True, exist_ok=True)
    audit = await AuditLogger.open(data_dir / AUDIT_DB_FILENAME)
    try:
        valid = await audit.verify_chain()
        length = await audit.length()
    finally:
        await audit.close()
    print(f"verify_chain() -> {valid}   ({length} events in {data_dir / AUDIT_DB_FILENAME})")
    return EXIT_OK if valid else EXIT_ASSERTION_FAILED


async def run_demo(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    settings, generated_key = load_settings("anthropic" if args.real else "mock")

    if args.verify_chain:
        return await verify_chain_only(settings)

    # main() has already expanded and validated --file; path arithmetic only here.
    primary_path = Path(args.file) if args.file else PRIMARY_FIXTURE
    primary_category = args.category if args.file else PRIMARY_CATEGORY

    checks = CheckList()
    capture: WireCapture | None = None
    http_client: httpx.AsyncClient | None = None

    hr()
    print(bold("  SECURE CONTEXT PIPELINE -- END-TO-END DEMO"))
    print("  detect -> obfuscate -> EGRESS GATE -> LLM -> restore -> destroy")
    hr()
    kv("provider", f"{settings.llm_provider}  (model {settings.llm_model})")
    kv("strategy", f"{args.strategy} (document 1), pseudonymization (document 2)")
    kv("data dir", await asyncio.to_thread(_display_path, Path(settings.data_dir)))
    kv("thresholds", f"obfuscate>={settings.threshold_obfuscate}  "
                     f"redact>={settings.threshold_redact}")
    if generated_key:
        kv("master key", yellow("EPHEMERAL -- SCP_MASTER_KEY was unset, so a random 32-byte"))
        print(f"  {'':<14}key was generated for this run only. It is never written to")
        print(f"  {'':<14}disk or printed; documents stored now are unreadable next run.")
    else:
        kv("master key", "loaded from the environment (never printed)")

    if args.real:
        capture = WireCapture() if args.dump_wire else None
        if capture is not None:
            http_client = httpx.AsyncClient(event_hooks={"request": [capture.on_request]})
            provider: DetailedLLMProvider = AnthropicProvider(settings, http_client=http_client)
            kv("wire dump", f"httpx event hook attached -> {WIRE_DUMP_PATH.name}")
        else:
            provider = build_provider(settings)
    else:
        provider = build_provider(settings)

    section("0. warm-up")
    mark = time.perf_counter()
    await asyncio.to_thread(warm_up, settings)
    wrapped(
        "  ",
        f"spaCy + Presidio analyzer ready in {(time.perf_counter() - mark) * 1000:.0f} ms "
        f"-- once per process, off the event loop",
    )

    harness = await build_harness(settings, provider)
    session_id = ""
    try:
        section("1. session")
        # Bound to the user that every leg of this demo then claims -- the
        # orchestrator refuses a session presented with a different user_id.
        session_id, expires_at = await harness.sessions.create(USER_ID)
        kv("session_id", session_id)
        kv("bound to", f"user_id {USER_ID!r} -- this session works for no other user")
        kv("expires", f"{time.strftime('%H:%M:%S', time.localtime(expires_at))} "
                      f"(ttl {settings.session_ttl_seconds}s)")
        kv("session key", "32 random bytes, memory only -- never persisted, never printed")

        section(f"2-5. run a: {args.strategy}")
        first = await run_case(
            harness,
            checks,
            session_id=session_id,
            path=primary_path,
            category=primary_category,
            strategy=args.strategy,
            prompt=args.prompt,
            panes=True,
            # A reviewer-supplied file may legitimately contain nothing to detect;
            # that makes the leak scan vacuous but is not a pipeline failure.
            nonvacuity_fatal=args.file is None,
        )
        if args.real:
            checks.record(
                f"full pipeline under {REAL_BUDGET_S:.0f}s with the real provider",
                first.wall_s < REAL_BUDGET_S,
                f"{first.wall_s:.2f}s wall clock (llm "
                f"{first.result.stats.get('llm_ms', 0.0) / 1000:.2f}s)",
            )

        section("6. run b: pseudonymization")
        print(dim("  same session, different document and strategy: the vault is shared, so"))
        print(dim("  a value seen in both documents keeps its first mapping (determinism)."))
        second = await run_case(
            harness,
            checks,
            session_id=session_id,
            path=SECONDARY_FIXTURE,
            category=SECONDARY_CATEGORY,
            strategy="pseudonymization",
            prompt=args.prompt,
            panes=True,
            nonvacuity_fatal=True,
        )

        section("6c. fail-closed: the egress gate refuses")
        await demonstrate_fail_closed(
            harness, checks, session_id=session_id, prompt=args.prompt
        )

        originals_before_destroy = harness.vault.originals_for_session(session_id)
        if capture is not None:
            section("6b. wire dump")
            await dump_wire(capture, checks, originals_before_destroy)

        section("7. destroy the session")
        await demonstrate_destruction(
            harness,
            checks,
            session_id=session_id,
            probe=build_probe([first, second]),
        )
        checks.record(
            "vault reports zero originals for the destroyed session",
            not harness.vault.originals_for_session(session_id),
            f"{len(originals_before_destroy)} originals were held before destruction",
        )

        section("8. audit trail")
        await print_audit_tail(harness, checks, session_id)

    except PipelineError as exc:
        # A pipeline error is a demo failure, but the audit trail is still worth
        # printing -- that is where the reason will be.
        print()
        wrapped("  pipeline error: ", repr(exc), style=red)
        checks.record("pipeline completed without error", False, exc.code)
        if session_id:
            try:
                await print_audit_tail(harness, checks, session_id)
            except PipelineError:  # pragma: no cover -- audit is already broken
                pass
    finally:
        await harness.close()
        if http_client is not None:
            await http_client.aclose()

    return checks.banner(time.perf_counter() - started)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="demo.py",
        description="End-to-end demonstration and smoke test of the secure context pipeline. "
                    "Exits non-zero if any assertion fails.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(__doc__ or "").split("Usage::")[-1],
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help="use the Anthropic provider instead of the mock (needs ANTHROPIC_API_KEY) "
             "and assert the full pipeline finishes in under 15 s",
    )
    parser.add_argument(
        "--strategy",
        choices=("tokenization", "pseudonymization"),
        default="tokenization",
        help="obfuscation strategy for the first document (default: tokenization)",
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="run the pipeline on an arbitrary document (PDF/DOCX/TXT/MD) instead of "
             "fixtures/medical_note.txt",
    )
    parser.add_argument(
        "--category",
        choices=tuple(sorted(DOC_CATEGORIES)),
        default="general",
        help="doc_category for --file (default: general)",
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="the user prompt sent alongside the obfuscated document",
    )
    parser.add_argument(
        "--dump-wire",
        action="store_true",
        help=f"with --real: capture the literal outbound HTTP request body, scan it for "
             f"vault originals, and write it to {WIRE_DUMP_PATH.name}",
    )
    parser.add_argument(
        "--verify-chain",
        action="store_true",
        help="print the audit hash-chain verification result and exit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global _COLOUR_ENABLED

    args = parse_args(argv)
    _COLOUR_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    if args.dump_wire and not args.real:
        print("error: --dump-wire captures a live HTTP request, so it requires --real.",
              file=sys.stderr)
        return EXIT_USAGE
    if args.real and not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: --real needs ANTHROPIC_API_KEY in the environment.\n"
              "       export ANTHROPIC_API_KEY=sk-ant-...   (or add it to .env)\n"
              "       Without it, run `python demo.py` -- the mock provider needs no network.",
              file=sys.stderr)
        return EXIT_USAGE
    if args.file:
        path = Path(args.file).expanduser()
        if not path.is_file():
            print(f"error: --file {path} does not exist or is not a file.", file=sys.stderr)
            return EXIT_USAGE
        args.file = str(path.resolve())
    for fixture in (SECONDARY_FIXTURE,) if args.file else (PRIMARY_FIXTURE, SECONDARY_FIXTURE):
        if not fixture.is_file():
            print(f"error: fixture {fixture} is missing; run from the repository root.",
                  file=sys.stderr)
            return EXIT_USAGE

    try:
        return asyncio.run(run_demo(args))
    except ConfigError as exc:
        print(f"error: configuration problem: {exc!r}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover -- interactive only
        print("\ninterrupted", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
