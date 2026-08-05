"""Zero-PII-in-transit leakage harness (build doc section 10.5). Marker: ``leakage``.

This is the headline security artifact. The claim it underwrites is not "the
detector found everything" -- no NER model has perfect recall, and a guarantee
resting on recall is not a guarantee. The claim is an **egress property**: across
100 independent pipeline runs over freshly generated documents, in both
obfuscation strategies, no original value ever reached the outbound payload, the
audit log, or the process log, and everything the model actually referred to came
back intact.

Four assertions per run (build doc section 10.5):

1. **Outbound payload holds zero originals**, checked against the vault's own
   ``originals_for_session`` in raw, normalised *and* invisible-character-folded
   form -- the same **three** forms ``EgressGate._scan_originals`` compares, so the
   harness cannot pass on a normalisation the gate would also catch -- and with no
   minimum length, so a short value the gate skips still fails here. No span is
   exempt, including the pipeline's own output: a pseudonym that reproduces a real
   value verbatim puts that value on the wire wherever it sits. The run
   additionally asserts that no surrogate equals the value it replaces.
2. **Audit DB and captured log output hold zero originals.** The audit side is
   queried through :meth:`AuditLogger.query` and, as defence in depth, the raw
   SQLite files are scanned as bytes -- a value that never survives the query API
   but sits in a page of the DB file is still a leak. Both audit views resolve JSON
   ``\\uXXXX`` escapes, because ``canonical_json`` is ``ensure_ascii=True`` and an
   accented original is otherwise stored, and re-serialised, in a form no raw scan
   matches. The log side is every record the package emitted at ``DEBUG``,
   **including its ``extra=`` fields** -- ``caplog.text`` renders none of them, and
   this package logs almost every variable it has through ``extra``.

3. **Round-trip completeness.** For every surrogate the model actually mentioned,
   the original is back in the restored text. The expected set is derived from
   ``result.raw_llm_response``, which is the only correct formulation: the mock
   quotes a *subset* of the document's entities, so "every vaulted original
   appears in the restored text" is unsatisfiable by construction and would be a
   false failure rather than a finding.
4. **Nothing surrogate-shaped survives.** Zero ``TOKEN_RE`` matches and zero
   issued surrogates left in the restored text -- a token that reaches the user
   is a broken answer, and a surviving pseudonym is a silently wrong one.

**What this harness measures, and what it does not.** The claim is about *whole
vaulted values*, per channel, per session. Five boundaries are deliberate, and are
stated here rather than left to be discovered. Each is pinned by a test, so a change
that closes one is a red rather than a silent widening of the headline claim:

* **Partial disclosure is out of scope.** If a splice bug leaves one component of a
  multi-word original behind -- the surname of a vaulted full name -- neither this
  harness nor the gate reports it, because both ask whether the *value* occurs. A
  word-level scan is not safely assertable: fixture originals include ordinary
  clinical phrases and Faker surnames that are ordinary English words, so it would
  manufacture reds indistinguishable from the real thing. See
  :func:`test_a_partial_value_leak_is_outside_what_this_harness_claims`, which pins
  the boundary so it cannot be forgotten.
* **A value glued into a longer word is out of scope -- on the text channels.**
  ``xJohn Smithx`` carries the original byte for byte and is not reported by
  :func:`find_in_text`, because :func:`_occurs_as_a_unit` asserts a word boundary on
  each side whose adjacent needle character is alphanumeric. Removing that assertion
  is what makes ``Brown`` match inside ``Browning``; restricting the relaxation to
  multi-word originals does not help either, because ``chronic low back pains``
  contains ``chronic low back pain``.
  See :func:`test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims`.

  It bites hardest on the audit *file*, where it is a boundary of one **limb** rather
  than of the whole assertion. SQLite writes a record's column values end to end with
  no delimiter, so an original in any label column is always glued between
  alphanumerics -- ``...EGRESS_BLOCKMarguerite Vandenbergdeadbeef...`` -- and
  :func:`find_in_bytes` reports a file containing the value byte for byte as clean.
  :func:`find_in_text` over the *query* view of the same rows sees
  ``"entity_type": "Marguerite Vandenberg"``, where JSON quoting supplies the
  boundaries, and catches it; assertion 2 applies both. Loosening the byte limb so it
  could carry the case alone was tried and reverted -- ``8.2`` is an ordinary vaulted
  lab value and ``{"elapsed_ms":18.25}`` then reads as a leak. See
  :func:`test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`.
* **A combining mark spliced into a value is out of scope.** ``normalize`` is NFKC,
  which composes -- so a *decomposed* rendering of an accented original is caught,
  but a mark that was never in the vaulted value is not removable by any
  normalisation form. Folding marks out would make ``José`` and ``Jose`` the same
  value, which the gate's ``_INVISIBLE_RE`` deliberately refuses. See
  :func:`test_a_combining_mark_inside_a_value_is_outside_what_this_harness_claims`.
* **Cross-session leakage is out of scope here.** Each run scans only its own
  session's originals. Cross-session isolation is a cryptographic property, proven
  in ``test_vault.py::test_aad_binding_across_sessions`` and
  ``integration/test_pipeline.py::test_concurrent_session_isolation``, rather than a
  scan-form question.
* **Homoglyph substitution is out of scope**, for the same reason it is out of scope
  in the gate: catching Cyrillic U+043E for Latin ``o`` needs a confusables table,
  not another normalisation form.

The last three share one cause and it is worth naming: they are the shapes for which
the harness and the gate are blind **together**, because both resolve to the same
occurrence rule. Where the gate is a second opinion that failure is survivable; on
the audit database and the process log, where nothing else looks, it is not -- which
is why they are recorded here as claims the harness does not make rather than as
cases it happens not to have hit.

Then one adversarial run that removes detection from the argument entirely: a
value of a shape **no recogniser in the registry matches** is planted in the
document and injected into the vault's originals set, so the detector is provably
blind to it and the value rides through to the payload untouched. The gate must
still block, the block must be audited, and the provider must never be called.
That is the fail-closed property, proven independent of detection recall.

Run it with ``pytest -m leakage``. Roughly 40 s: the spaCy analyzer and the whole
component graph are built once for the module and every run gets a fresh session.
"""

from __future__ import annotations

import ast
import base64
import json
import logging
import re
import secrets
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fixtures import generator
from secure_context_pipeline.audit.logger import EGRESS_BLOCK, AuditLogger, canonical_json
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import normalize
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.errors import EgressBlockedError
from secure_context_pipeline.llm.base import LLMResponse
from secure_context_pipeline.llm.mock_provider import MockProvider
from secure_context_pipeline.models import (
    MAX_AUDIT_LABEL_LEN,
    MAX_DETAIL_VALUE_LEN,
    AuditEvent,
    PipelineResult,
    TokenRecord,
)
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import (
    EgressGate,
    _occurs_as_a_unit,
    _strip_invisible,
)
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.surrogates import TOKEN_RE, extract_token_ids
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

pytestmark = pytest.mark.leakage

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "entities.yaml"

#: Section 10.5 fixes the run count. If this harness gets slow, shrink the
#: documents -- never the run count.
RUNS = 100

USER_ID = "leakage-user"
PROMPT = "Summarise this record and list the key parties, dates and figures."

#: Both strategies alternate across the runs; three document kinds rotate under
#: them, so every (strategy, kind) pair is exercised many times over.
STRATEGIES = ("tokenization", "pseudonymization")
KINDS = ("medical", "legal", "financial")
DOC_CATEGORY = {"medical": "medical", "legal": "legal", "financial": "financial"}

#: Seed offset. Each run gets its own seed, so the 100 runs are 100 *different*
#: documents rather than one document scanned 100 times.
SEED_BASE = 90_000

#: A value whose shape no recogniser in ``entities.yaml`` matches -- no digits in
#: a pattern-bearing position, not a person, not a place, not a case number.
#:
#: The obvious candidate shape for this -- alphanumeric groups separated by
#: hyphens with a run of digits in the middle -- is NOT blind to the shipped
#: registry: ``CASE_ID``'s second pattern, ``\b\d{2}-[A-Z]{1,4}-\d{3,6}\b``,
#: claims that substring at score 0.70, so the engine would obfuscate the value
#: and the gate would never see it, making the adversarial case prove nothing.
#: The all-alphabetic grouping below avoids it, and
#: ``test_planted_value_is_invisible_to_the_detector`` asserts that blindness in
#: every document category rather than assuming it.
UNKNOWN_SHAPE_VALUE = "ZXQQ-KLM-RSTV-WYNP"

#: Where the planted value is put. It reads like an internal reference code,
#: which is exactly the class of value a registry-driven detector misses.
PLANT_TEMPLATE = "\n\nVendor control marker: {}\nRouting is keyed on this marker only.\n"


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def plan_run(index: int) -> tuple[int, str, str]:
    """``(seed, kind, strategy)`` for run ``index``. Pure, so IDs are stable."""
    return SEED_BASE + index, KINDS[index % len(KINDS)], STRATEGIES[index % len(STRATEGIES)]


def run_id_for(index: int) -> str:
    seed, kind, strategy = plan_run(index)
    return f"{index:03d}-{kind}-{strategy}-seed{seed}"


# ---------------------------------------------------------------------------
# Provider wrapper -- proves the call never fired
# ---------------------------------------------------------------------------


class CountingProvider:
    """``MockProvider`` plus a call counter and the exact strings it was handed.

    Two claims need a provider-side observer, and neither can be made from the
    orchestrator's own return value:

    * *the network call never happened* (the adversarial case) -- only a call
      counter at the boundary can say that;
    * *the string the gate scanned is the string that was sent*. The gate scans
      :attr:`ContextInjector.Payload.serialized`, and the provider is handed
      ``(system, user)`` separately. Those are two different expressions of the
      same bytes, and nothing in the type system keeps them equal --
      ``context_injector`` says so in as many words ("if the provider call ever
      stops sending exactly these two strings, this property must change with
      it"). Recording both halves here lets the run below check that the
      egress guarantee attaches to the real outbound payload rather than to a
      reconstruction of it.
    """

    name = "mock"

    def __init__(self) -> None:
        self._inner = MockProvider()
        self.calls = 0
        self.last_system: str | None = None
        self.last_user: str | None = None

    @property
    def last_payload(self) -> str | None:
        """The outbound payload as the provider received it, re-serialized.

        Built the way :meth:`ContextInjector.Payload.serialized` builds it, so an
        equality check against ``result.obfuscated_payload`` is meaningful.
        """
        if self.last_system is None or self.last_user is None:
            return None
        return f"{self.last_system}\n\n{self.last_user}"

    async def complete(self, system: str, user: str, *, model: str, timeout_s: float = 60.0) -> str:
        response = await self.complete_detailed(system, user, model=model, timeout_s=timeout_s)
        return response.text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        self.calls += 1
        self.last_system = system
        self.last_user = user
        return await self._inner.complete_detailed(
            system, user, model=model, timeout_s=timeout_s
        )


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Harness:
    settings: Settings
    registry: EntityRegistry
    detector: Detector
    store: EncryptedDocumentStore
    sessions: SessionRegistry
    vault: SessionVault
    audit: AuditLogger
    provider: CountingProvider
    orchestrator: PipelineOrchestrator
    audit_db: Path

    def audit_bytes(self) -> bytes:
        """The audit DB as raw bytes, including the WAL sidecar.

        Scanning the file rather than the query result is what makes "no
        originals in the audit log" a statement about the *storage*, not about
        the accessor we happen to use.
        """
        blob = b""
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.audit_db) + suffix)
            if path.is_file():
                blob += path.read_bytes()
        return blob


@dataclass(slots=True)
class Ledger:
    """Accumulates the run tally so the module can print one summary line."""

    runs: int = 0
    leaks: int = 0
    originals_vaulted: int = 0
    round_trip_checked: int = 0
    notes: list[str] = field(default_factory=list)

    def record(self, *, originals: int, restored: int) -> None:
        self.runs += 1
        self.originals_vaulted += originals
        self.round_trip_checked += restored

    def summary(self) -> str:
        return (
            f"[leakage] {self.runs}/{RUNS} runs clean, {self.leaks} leaks "
            f"({self.originals_vaulted} originals vaulted and scanned, "
            f"{self.round_trip_checked} surrogates round-tripped)"
        )


@pytest.fixture(scope="module")
def registry() -> EntityRegistry:
    return load_registry(REGISTRY_PATH)


@pytest.fixture(scope="module")
def leak_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("leakage-data"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def detector(registry: EntityRegistry, leak_settings: Settings) -> Detector:
    """Built ONCE for the module. Constructing it loads spaCy; 100 of those would
    dominate the runtime and measure nothing."""
    return Detector(registry, leak_settings)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def harness(
    registry: EntityRegistry,
    leak_settings: Settings,
    detector: Detector,
    tmp_path_factory: pytest.TempPathFactory,
) -> Any:
    """The whole component graph, built once and reused; each run gets a fresh session.

    Everything is closed in the teardown: an unclosed aiosqlite connection keeps a
    non-daemon thread alive and hangs interpreter exit.
    """
    root = tmp_path_factory.mktemp("leakage-db")
    audit_db = root / "audit.db"
    audit = await AuditLogger.open(audit_db)
    store = await EncryptedDocumentStore.open(leak_settings)
    sessions = SessionRegistry(leak_settings)
    vault = await SessionVault.open(root / "vault.db", sessions)
    provider = CountingProvider()
    orchestrator = PipelineOrchestrator(
        store=store,
        detector=detector,
        engine=ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=leak_settings,
            audit=audit,
        ),
        injector=ContextInjector(),
        gate=EgressGate(vault=vault, detector=detector, settings=leak_settings, audit=audit),
        provider=provider,
        restorer=Restorer(vault=vault, settings=leak_settings, audit=audit),
        vault=vault,
        settings=leak_settings,
        audit=audit,
    )
    try:
        yield Harness(
            settings=leak_settings,
            registry=registry,
            detector=detector,
            store=store,
            sessions=sessions,
            vault=vault,
            audit=audit,
            provider=provider,
            orchestrator=orchestrator,
            audit_db=audit_db,
        )
    finally:
        await vault.close()
        await store.close()
        await audit.close()


@pytest.fixture(scope="module")
def ledger(request: pytest.FixtureRequest) -> Iterator[Ledger]:
    """Tally across the module, printed once at teardown for the README."""
    book = Ledger()
    yield book
    line = book.summary()
    capture = request.config.pluginmanager.getplugin("capturemanager")
    if capture is not None:
        with capture.global_and_fixture_disabled():
            print("\n" + line)
    else:  # pragma: no cover -- capture plugin is always present under pytest
        print("\n" + line)


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------


def mask(value: str) -> str:
    """A failure-message-safe shape descriptor.

    Fixture data is synthetic, but the habit of never rendering an original into
    output is the whole point of the exercise, so the harness keeps it too.
    """
    return f"<{len(value)} chars starting {value[:2]!r}>"


#: The occurrence rule, **imported** from the EgressGate rather than restated here.
#:
#: This file used to carry its own copy: ``(?<!\w)needle(?!\w)``. That copy was
#: wrong, and the way it was wrong is the most instructive thing in this module.
#:
#: ``_`` is a regex ``\w``. So for a payload containing ``_John Smith_`` -- ordinary
#: markdown emphasis, which the mock provider emits and a real model emits
#: constantly -- the harness **did not match its own planted original**, and
#: assertion 1 below passed on a payload carrying that value byte for byte. The
#: same hole swallowed every value whose first or last character is punctuation:
#: ``tel(415) 555-0123`` and ``USD$1,234.56`` both contain the original verbatim
#: and both read as clean, because the rule asked whether the character before
#: ``(`` was a word character, which is not a question about word boundaries.
#:
#: It was the **third** independent copy of that rule. The gate and the engine's
#: residual sweep held the other two, and all three agreed -- so the gate did not
#: block, the sweep did not mask, and the harness did not report. A green
#: ``100/100`` was measuring three copies of one bug agreeing with each other,
#: which is strictly worse than having no harness at all: it launders the claim.
#:
#: Importing is therefore not a tidiness preference. A renamed or re-scoped helper
#: is now an ImportError instead of a silent divergence, and there is exactly one
#: definition of what "this value appears in this text" means across the gate, the
#: engine and this harness. :func:`test_the_occurrence_rule_has_no_fourth_copy`
#: below checks that single definition against an independently written reference,
#: so the shared rule is still verified rather than merely shared.
occurs_as_a_unit = _occurs_as_a_unit


def find_in_text(originals: frozenset[str], haystack: str) -> list[str]:
    """Every original occurring in ``haystack``, in all **three** forms the gate scans.

    1. **raw** -- the byte-exact value;
    2. **normalised** -- NFKC, whitespace collapsed, casefolded, so a value split
       across a line break or re-cased by a splice bug still trips;
    3. **folded** -- normalised with zero-width, soft-hyphen and bidi format
       characters removed.

    The third form is the one this function used to be missing, and the omission
    inverted the whole point of the module. The docstring here claimed these were
    "the same two forms the EgressGate scans, so the harness cannot pass on a
    normalisation the gate would also miss" -- but the gate scans *three*
    (``EgressGate._scan_originals``), and had done since the invisible-character
    bypass was closed there. So the harness was **weaker than the code it
    measures**: an original carrying one U+200B read as clean here.

    That asymmetry is not symmetric in consequence. On the outbound payload the
    gate is a second opinion, so a leak the harness missed would still be blocked.
    On the **audit database and the process log this function also scans, the
    harness is the only opinion there is** -- nothing else looks at those bytes --
    so an invisible character was a complete bypass of the "zero originals in the
    audit log" claim. Verified by sabotage: a real pipeline run with one U+200B
    spliced into a real vaulted original reported clean through the harness while
    the gate blocked it.

    No minimum length, deliberately: the gate skips originals shorter than
    :data:`~secure_context_pipeline.pipeline.egress_gate.MIN_ORIGINAL_LEN`, and
    the harness does not, so a short value the gate would wave through still fails
    here. That is the one direction in which the harness *should* be stricter than
    the gate, and it stays that way.
    """
    folded = normalize(haystack)
    stripped = _strip_invisible(folded)
    return sorted(
        o
        for o in originals
        if occurs_as_a_unit(o, haystack)
        or occurs_as_a_unit(normalize(o), folded)
        or occurs_as_a_unit(_strip_invisible(normalize(o)), stripped)
    )


#: A JSON ``\uXXXX`` escape. See :func:`_unescape_json_unicode`.
_JSON_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _unescape_json_unicode(text: str) -> str:
    """Resolve JSON ``\\uXXXX`` escapes so a non-ASCII original is visible again.

    :func:`~secure_context_pipeline.audit.logger.canonical_json` and
    :func:`json.dumps` both default to ``ensure_ascii=True``, so an audit ``detail``
    holding ``"José"`` is *stored in SQLite* -- and re-serialised by the query path
    -- as the ASCII text ``"Jos\\u00e9"``. Both of this module's audit scans were
    therefore blind to any original containing a non-ASCII character: the value is
    genuinely in the log, in a form any JSON reader decodes back to the original,
    and neither the raw byte scan nor the query-API scan could see it.

    Accented surnames are not an edge case in the documents this system exists to
    protect, so this was a live hole in the headline claim rather than a
    hypothetical. Applied as an *additional* view rather than a replacement, so the
    scan only ever widens.
    """
    return _JSON_UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


#: Attributes every :class:`logging.LogRecord` carries. Anything outside this set
#: arrived via ``extra=`` and is therefore *not* rendered into ``caplog.text``.
_STANDARD_LOGRECORD_ATTRS: frozenset[str] = (
    frozenset(vars(logging.LogRecord("n", 0, "p", 0, "m", None, None)))
    | {"message", "asctime", "taskName"}
)


def log_haystack(caplog: pytest.LogCaptureFixture) -> str:
    """Everything the package logged, **including the ``extra=`` fields**.

    ``caplog.text`` renders records through pytest's default formatter, which is
    ``"%(levelname)-8s %(name)s:%(filename)s:%(lineno)s %(message)s"``. That format
    contains no ``extra`` fields, and this package puts **almost every variable it
    logs into ``extra=``** -- ``session_id``, ``run_id``, ``entity_type``,
    ``token_id``, counts, latencies, error types. A scan of ``caplog.text`` alone
    therefore checked the *constant* half of every log line and none of the
    variable half.

    That is precisely the shape a logging leak takes. ``logger.debug("obfuscated a
    span", extra={"value": original})`` is the natural mistake, it is invisible to
    ``caplog.text``, and it is fully rendered by any production JSON formatter --
    which is what a deployment actually runs. So the harness was asserting "no
    originals in the logs" against a view of the logs that structurally could not
    contain one.

    Verified rather than assumed: ``test_the_log_scan_sees_structured_extra_fields``
    below plants a value in an ``extra`` field and fails if this function cannot
    find it.
    """
    parts: list[str] = [caplog.text]
    for record in caplog.records:
        parts.append(record.getMessage())
        parts.extend(
            f"{key}={value!r}"
            for key, value in vars(record).items()
            if key not in _STANDARD_LOGRECORD_ATTRS
        )
    return "\n".join(parts)


def find_in_bytes(originals: frozenset[str], haystack: bytes) -> list[str]:
    """Every original present in a raw byte blob (the audit DB file on disk).

    Decoded and then run through the **same** occurrence rule as
    :func:`find_in_text`, rather than a bare ``bytes.__contains__``. The naive
    version was an unanchored substring test sitting underneath the headline claim
    "the audit database contains zero originals", and it had a real false-positive
    path: three fixture originals are pure six-digit decimals (``382892``,
    ``390538``, ``364896``) and every audit row carries a 32-character hex
    ``run_id``, so a decimal original can appear *inside* a run ID by chance and be
    reported as a leak. Roughly 1e-6 per run -- but on this particular assertion a
    one-in-a-million false red is worse than the arithmetic suggests, because the
    next genuine red gets waved away as "that flaky audit check".

    **What this limb does and does not see, since it is the half that is easy to
    overrate.** SQLite writes a record's column values end to end with no delimiter,
    so an original in a label column sits in the file as
    ``...EGRESS_BLOCKMarguerite Vandenbergdeadbeef...`` -- alphanumeric on both
    edges, which is the "glued into a longer word" shape this module documents as
    out of scope. Measured, not reasoned: emitting one event with a name in
    ``entity_type`` produces exactly that layout and this function returns nothing.

    That is a boundary and not a hole, because it is not the only limb.
    :func:`find_in_text` over the **query view** of the same rows sees the identical
    value as ``"entity_type": "Marguerite Vandenberg"``, where JSON quoting supplies
    the boundaries, and the run below applies both -- so a label-column original is
    caught, by the other half of assertion 2. What this limb uniquely covers is bytes
    the query view cannot reach: freed pages, WAL remnants, superseded row images.
    :func:`test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did`
    pins the division of labour, so neither half can be quietly deleted on the
    assumption that the other one is doing the work.

    Loosening this limb to plain containment was tried and reverted: it re-opens the
    exact false-positive class above with interest. A lab value like ``8.2`` is an
    ordinary vaulted original and every audit row carries an ``elapsed_ms`` -- so
    ``{"elapsed_ms":18.25}`` reports a leak that is not there. Measured before
    shipping, not after.

    ``errors="replace"`` is what makes decoding safe here: an invalid byte becomes
    U+FFFD, which is not alphanumeric and therefore acts as a boundary, so binary
    garbage can never glue itself onto a needle and manufacture a match. Valid
    UTF-8 -- which is what SQLite actually stores text as -- decodes exactly.

    The blob is scanned in **two** views: as decoded, and with JSON ``\\uXXXX``
    escapes resolved. The ``detail`` column is written by ``canonical_json``, which
    is ``ensure_ascii=True``, so a non-ASCII original sits in the file as literal
    backslash-u text that a raw scan cannot match -- see
    :func:`_unescape_json_unicode`.
    """
    decoded = haystack.decode("utf-8", errors="replace")
    unescaped = _unescape_json_unicode(decoded)
    return sorted(
        o
        for o in originals
        if occurs_as_a_unit(o, decoded) or occurs_as_a_unit(o, unescaped)
    )


async def surrogate_map(harness: Harness, session_id: str, result: PipelineResult) -> dict[str, str]:
    """``surrogate -> original`` for everything this run issued.

    Read back out of the vault rather than carried along the run, so the map is
    the vault's own view of what it handed out.
    """
    mapping: dict[str, str] = {}
    for span in result.detections:
        if span.surrogate and span.surrogate not in mapping:
            mapping[span.surrogate] = await harness.vault.get_by_surrogate(
                session_id, span.surrogate
            )
    return mapping


_HEX = frozenset("0123456789abcdefABCDEF")


def issued_token_id(surrogate: str) -> str | None:
    """The 8-hex ID of a surrogate **we** issued, parsed without the production grammar.

    Hand-written string surgery rather than ``STRICT_TOKEN_RE`` on purpose -- see
    :func:`expected_round_trip` for why every predicate that decides *what must come
    back* is derived independently of the code that puts it back. The input is our
    own vault's key, not model output, so it needs no tolerance: strip the brackets,
    drop the optional ``|hint``, take the last underscore-separated component, and
    require exactly eight hex digits.

    Returns ``None`` for a pseudonym, which carries no ID and is matched as a
    literal instead.
    """
    if not (surrogate.startswith("[") and surrogate.endswith("]")):
        return None
    core = surrogate[1:-1].split("|", 1)[0]
    tail = core.rsplit("_", 1)[-1]
    if len(tail) == 8 and all(character in _HEX for character in tail):
        return tail.lower()
    return None


def expected_round_trip(raw_llm_response: str, mapping: dict[str, str]) -> set[str]:
    """Originals that MUST be back in the restored text.

    **This function deliberately shares no predicate with the restorer**, and that
    is the entire point of it. Leak detection and round-trip completeness pull in
    opposite directions, and this module used to run both through the same two
    production predicates:

    * ``extract_token_ids`` -- i.e. ``surrogates.TOKEN_RE``, which is also how the
      restorer decides what to replace;
    * ``_occurs_as_a_unit`` -- the egress gate's occurrence rule.

    For **leak detection** sharing is correct and is enforced by
    :func:`test_no_leak_comparison_in_this_module_bypasses_the_shared_rule`: a scan
    laxer than the gate would report clean through a leak the gate blocks.

    For **completeness** it is exactly wrong, because it makes the expectation
    agree with the thing it is checking. If ``TOKEN_RE`` cannot see a token the
    model emitted, then: ``expected`` silently omits the original, the restorer
    silently leaves the token in the answer, assertion 4's residual scan (also
    ``TOKEN_RE``) cannot see it either, all three agree, and the only visible
    effect is that ``round_trip_checked`` in the summary line gets *smaller*. A
    shrinking denominator is not a failure signal; nobody reads it as one. The
    user gets an answer with a dangling ``1a2b3c4d`` in it and the harness reports
    100/100 clean.

    So the expectation is derived from an independent reading of the model's own
    words: the 8-hex ID as a plain case-insensitive substring (:func:`_mentions`),
    and pseudonyms through :func:`_reference_occurs_as_a_unit`, the
    independently-written occurrence rule this module already keeps for
    differential testing. Both are *at least as broad* as the production grammar,
    which is the direction that makes a restorer miss a red instead of a rounding
    error.

    A bare ID substring cannot manufacture a false expectation in practice: the IDs
    are ``sha256[:8]`` and the only place they appear in a response is inside the
    token the payload carried. If one ever did collide, the resulting red is still
    an answer with an unrestored ID in it.

    The pseudonym branch stays boundary-anchored: a short Faker surname sitting
    inside a longer ordinary word is not the model *mentioning* that surrogate, and
    treating it as one puts an original into ``expected`` that the restorer was
    never asked to produce.

    Takes the response text rather than a :class:`PipelineResult` so it can be
    exercised directly with hand-built model output -- which is what
    :func:`test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`
    does.
    """
    expected: set[str] = set()
    for surrogate, original in mapping.items():
        token_id = issued_token_id(surrogate)
        if token_id is not None:
            if _mentions(token_id, raw_llm_response):
                expected.add(original)
        elif _reference_occurs_as_a_unit(surrogate, raw_llm_response):
            expected.add(original)
    return expected


def _mentions(token_id: str, raw_llm_response: str) -> bool:
    """Did the model refer to this token ID at all? Decided without ``TOKEN_RE``.

    Case-insensitive and unanchored, because the question is "did the model say
    this ID", not "did it emit a well-formed token" -- the second question is the
    restorer's, and asking the restorer's question here is what made the
    expectation collapse whenever the restorer was wrong.
    """
    return token_id.lower() in raw_llm_response.lower()


# ---------------------------------------------------------------------------
# 0. The scan can still see a leak
# ---------------------------------------------------------------------------


def test_the_leak_scan_bites() -> None:
    """The harness's own instrument, checked before it is trusted 100 times.

    ``find_in_text`` is the one place this file could quietly stop measuring
    anything, so its two failure modes are pinned directly: it must fire on a
    value that is genuinely present in any of the shapes the pipeline could leave
    it in, and it must not fire on a longer word that merely contains it -- the
    false positive that is indistinguishable from a real leak until somebody
    spends an hour on it.
    """
    planted = "Marguerite Vandenberg"
    surname = "Brown"

    # Present verbatim.
    assert find_in_text(
        frozenset({planted}), f"<DOCUMENT>\nThe client {planted} signed.\n</DOCUMENT>"
    ) == [planted]

    # Present but case-mangled and re-wrapped across a line break: the raw scan
    # misses it, the normalised scan does not. This is the shape a splice bug or
    # a detector miss actually leaves behind.
    wrapped = "<DOCUMENT>\nThe client MARGUERITE\nVANDENBERG signed.\n</DOCUMENT>"
    assert planted not in wrapped
    assert find_in_text(frozenset({planted}), wrapped) == [planted]

    # Absent: a longer word that merely contains the value is not an occurrence.
    assert not find_in_text(
        frozenset({surname}), "<DOCUMENT>\nCounsel Browning filed the motion.\n</DOCUMENT>"
    )
    assert find_in_text(
        frozenset({surname}), "<DOCUMENT>\nCounsel Brown filed the motion.\n</DOCUMENT>"
    ) == [surname]

    # Absent entirely.
    assert not find_in_text(frozenset({planted}), "<DOCUMENT>\n[PII_NAME_1a2b3c4d]\n</DOCUMENT>")

    # And the byte-level scan used on the audit database file.
    assert find_in_bytes(frozenset({planted}), b"\x00\x01" + planted.encode()) == [planted]
    assert not find_in_bytes(frozenset({planted}), b"\x00\x01nothing here")


def test_the_scan_sees_markdown_and_punctuation_wrapped_originals() -> None:
    """The regression cases the previous occurrence rule was blind to.

    Every literal below carries its original **byte for byte**, and every one of
    them read as clean under the old ``(?<!\\w)...(?!\\w)`` rule. They are pinned
    individually rather than folded into a loop because each is a distinct way of
    being wrong, and a reviewer should be able to see the shape of the miss:

    * ``_John Smith_`` -- ``_`` is a regex ``\\w``, so the left assertion failed on
      the emphasis marker. Markdown emphasis is not exotic; the mock provider emits
      it and real models emit it constantly.
    * ``tel(415) 555-0123`` and ``USD$1,234.56`` -- the needle *begins* with
      punctuation, so asking whether the preceding character is a word character
      is not a boundary question at all. It has no meaning on that side, and
      answering it anyway suppressed the match.

    A phone number and a dollar figure are exactly the values this pipeline
    exists to keep off the wire, so this was not a corner case.
    """
    name = "John Smith"
    phone = "(415) 555-0123"
    amount = "$1,234.56"

    for haystack in (
        f"_{name}_",
        f"__{name}__",
        f"**{name}**",
        f"the memo names _{name}_ as counsel",
        f"x_{name}",
    ):
        assert find_in_text(frozenset({name}), haystack) == [name], (
            f"the scan is blind to {haystack!r}, which contains the original verbatim"
        )

    assert find_in_text(frozenset({phone}), f"tel{phone}") == [phone]
    assert find_in_text(frozenset({amount}), f"USD{amount}") == [amount]

    # And the false positive the rule exists to prevent is still prevented.
    assert not find_in_text(frozenset({"Brown"}), "Counsel Browning filed the motion.")


def test_the_byte_scan_does_not_invent_leaks_inside_run_ids() -> None:
    """A six-digit original inside a 32-hex ``run_id`` is not a leak.

    Three fixture originals are pure decimals and every audit row carries a hex
    ``run_id``, so an unanchored ``bytes`` containment test has a genuine -- if
    rare -- false-positive path on the assertion behind "the audit database holds
    zero originals". Rare false reds on a headline claim are expensive out of
    proportion to their frequency: they teach the reader to disbelieve the next
    one.
    """
    original = "382892"
    run_id = b"a3f2382892c14e7b9d0e5a6182f4cc71"
    assert original.encode() in run_id, "premise: the decimal really is inside the hex ID"
    assert not find_in_bytes(frozenset({original}), b"\x02\x00run_id=" + run_id)

    # A real occurrence in the same blob is still caught.
    assert find_in_bytes(
        frozenset({original}), b"\x02\x00value=" + original.encode() + b"\x00"
    ) == [original]

    # Undecodable bytes become U+FFFD, which is a boundary rather than a letter,
    # so binary noise cannot glue itself to a needle and manufacture a match.
    assert find_in_bytes(frozenset({original}), b"\xff\xfe" + original.encode()) == [original]


def test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things() -> None:
    """Assertion 2 has two limbs and neither is redundant. Which is which, exactly.

    SQLite writes a record's column values end to end with no delimiter, so an
    original in a label column lands in the *file* as
    ``…EGRESS_BLOCKMarguerite Vandenbergdeadbeef…`` -- alphanumeric on both edges,
    which is the "glued into a longer word" shape the anchored rule deliberately does
    not match. The **byte** limb is therefore blind to it. The **query** limb sees the
    identical value as ``"entity_type": "Marguerite Vandenberg"``, where JSON quoting
    supplies the boundaries, and catches it.

    Both directions are asserted here because the tempting simplification is wrong in
    both directions. Loosening the byte limb to plain containment so it could carry
    this case alone was tried and reverted: ``8.2`` is an ordinary vaulted lab value
    and every audit row carries an ``elapsed_ms``, so ``{"elapsed_ms":18.25}`` reports
    a leak that is not there -- the same false-positive class the anchoring exists to
    prevent, on a channel where a rare false red teaches the reader to disbelieve the
    next genuine one. And deleting the byte limb because the query limb covers this
    case is equally wrong: the byte limb is the only thing that sees bytes the query
    view cannot reach -- freed pages, WAL remnants, superseded row images.

    So the division of labour is pinned, rather than each limb being assumed to be
    doing the other's job.
    """
    name = "Marguerite Vandenberg"
    glued = b"sess-a1b2run-c3d4EGRESS_BLOCK" + name.encode() + b"deadbeef{\"count\":1}"
    quoted = json.dumps([{"entity_type": name, "detail": {"count": 1}}], ensure_ascii=False)

    assert name.encode() in glued, "premise: the value really is in the file, verbatim"
    assert not find_in_bytes(frozenset({name}), glued), (
        "if this now fires the byte limb gained glued-word detection -- good, but the "
        "false-positive path below must be re-measured before it ships"
    )
    assert find_in_text(frozenset({name}), quoted) == [name], (
        "the query limb is what actually catches a label-column original; if this "
        "stops firing, assertion 2 is blind to it on both limbs"
    )

    # The false positive that reverted the obvious "just loosen the byte limb" fix.
    latency_row = b'detail{"elapsed_ms":18.25,"count":3}'
    assert b"8.2" in latency_row, "premise: an ordinary latency contains this lab value"
    assert not find_in_bytes(frozenset({"8.2"}), latency_row), (
        "a vaulted lab value of 8.2 is being reported as a leak because an audit "
        "latency happened to contain those three characters"
    )

    # ...and the hex-in-run_id false positive the anchoring was introduced for.
    assert not find_in_bytes(
        frozenset({"382892"}), b"\x02\x00run_id=a3f2382892c14e7b9d0e5a6182f4cc71"
    )
    assert find_in_bytes(frozenset({"4823910"}), b'detail{"v":"MRN 4823910"}') == ["4823910"]


def test_the_scan_sees_an_invisible_character_bypass() -> None:
    """One U+200B must not make an original invisible to this module.

    The gate folds zero-width, soft-hyphen and bidi format characters out before
    its third comparison; this module used to compare only two forms while its own
    docstring asserted it compared "the same two forms the EgressGate scans". The
    gate had three. A checker weaker than the code it checks reports clean through
    a leak the code would have blocked -- and on the audit and log channels, where
    the gate never looks, there was nothing else to catch it.

    Found by sabotage: a real pipeline run with one U+200B spliced into a real
    vaulted original read 100/100 clean here while the gate blocked it.
    """
    name = "Marguerite Vandenberg"
    for invisible in ("​", "­", "﻿", "‍", "⁠"):
        haystack = f"The client Marguerite{invisible} Vandenberg signed."
        assert name not in haystack, "premise: the raw value is genuinely not present"
        assert find_in_text(frozenset({name}), haystack) == [name], (
            f"the scan is blind to U+{ord(invisible):04X} inside the original, which "
            "renders identically to a human and to the model"
        )

    # The gate agrees, which is the property that was broken: harness and gate must
    # not disagree about whether this is an occurrence.
    zero_width = "The client Marguerite​ Vandenberg signed."
    assert _occurs_as_a_unit(
        _strip_invisible(normalize(name)), _strip_invisible(normalize(zero_width))
    ), "the gate's folded comparison must see this too, or the two have diverged again"

    # And the false positive is still prevented in the folded form.
    assert not find_in_text(frozenset({"Brown"}), "Counsel Brow​ning filed the motion.")


def test_the_audit_scan_sees_json_escaped_non_ascii() -> None:
    """An accented original in the audit log is not hidden by ``ensure_ascii``.

    ``canonical_json`` -- the function that writes the ``detail`` column, and whose
    determinism the hash chain depends on -- is ``ensure_ascii=True``, and
    ``test_audit.py::test_canonical_json_is_deterministic_and_parseable`` pins that
    behaviour deliberately. The consequence for *this* module is that ``"José"``
    reaches SQLite as the ASCII text ``"Jos\\u00e9"``, so both audit scans were
    blind to it: the value is genuinely in the log, any JSON reader decodes it back,
    and neither the byte scan nor the query-API scan could match it.

    Accented surnames are ordinary in the documents this system protects, so this
    was a live hole in "the audit database contains zero originals" rather than a
    hypothetical one.
    """
    accented = "José Muñoz"

    escaped = canonical_json({"leaked": accented})
    assert accented not in escaped, "premise: ensure_ascii really does hide it"
    assert "Jos\\u00e9" in escaped

    # Byte scan of the DB file.
    assert find_in_bytes(frozenset({accented}), escaped.encode("utf-8")) == [accented]
    # Query-path scan: the run below serialises with ensure_ascii=False for this
    # reason, but the unescaping view must catch it either way.
    assert find_in_bytes(
        frozenset({accented}), json.dumps({"detail": {"v": accented}}).encode("utf-8")
    ) == [accented]

    # Unescaping must not manufacture matches out of ordinary text.
    assert not find_in_bytes(frozenset({accented}), b'{"detail":{"v":"nothing here"}}')


def test_the_log_scan_sees_structured_extra_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A value logged through ``extra=`` must not be invisible to the log scan.

    ``caplog.text`` formats records as ``"%(levelname)s %(name)s:%(file)s:%(line)s
    %(message)s"``. No ``extra`` field appears in that format -- and this package
    routes almost every variable it logs through ``extra``: ``session_id``,
    ``run_id``, ``entity_type``, ``token_id``, counts, latencies.

    So the natural logging leak -- ``logger.debug("...", extra={"value": original})``
    -- was structurally invisible to the assertion that exists to catch it, while
    being fully rendered by the JSON formatter a production deployment runs. The
    harness was scanning the constant half of every log line.
    """
    caplog.set_level(logging.DEBUG)
    planted = "Marguerite Vandenberg"
    logging.getLogger("secure_context_pipeline.probe").info(
        "obfuscated a span", extra={"leaked_value": planted}
    )

    assert planted not in caplog.text, (
        "premise: caplog.text renders no extra fields -- if this ever fails, "
        "pytest's default log format changed and this test's premise needs revisiting"
    )
    assert find_in_text(frozenset({planted}), log_haystack(caplog)) == [planted]

    # The message body is still scanned too.
    caplog.clear()
    logging.getLogger("secure_context_pipeline.probe").info("value is %s", planted)
    assert find_in_text(frozenset({planted}), log_haystack(caplog)) == [planted]


def test_a_partial_value_leak_is_outside_what_this_harness_claims() -> None:
    """The boundary of the claim, pinned so it cannot be quietly forgotten.

    If a splice bug leaves one *component* of a multi-word original behind --
    ``Vandenberg`` from ``Marguerite Vandenberg`` -- neither this harness nor the
    egress gate reports it. Both ask whether the vaulted **value** occurs, and it
    does not. Confirmed by sabotage against a real pipeline: a partial leak of a
    real vaulted original passes the gate *and* reads clean here.

    It is pinned rather than fixed because the fix is not safely assertable. Fixture
    originals include ordinary clinical phrases (``chronic low back pain``) and
    Faker surnames that are ordinary English words (``Brown``, ``Rich``), so a
    word-level scan manufactures reds that are indistinguishable from real leaks --
    which is the exact failure mode, in the exact file, that cost this build the
    most time (see ``test_a_short_surrogate_inside_a_longer_word_has_not_survived``).

    The honest form of the guarantee is therefore "no whole vaulted value reaches
    the payload, the audit log or the process log", and that is what the README
    says. This test exists so that sentence stays true rather than becoming a
    sentence nobody re-reads.
    """
    original = "Marguerite Vandenberg"
    surname_only = "The client Vandenberg signed the release."

    assert original not in surname_only
    assert not find_in_text(frozenset({original}), surname_only), (
        "if this now fires, the harness has gained component-level detection -- "
        "good, but the README's stated boundary and this test must change with it"
    )

    # The whole value is of course still caught, so this is a boundary and not a hole
    # in the primary claim.
    assert find_in_text(
        frozenset({original}), f"The client {original} signed the release."
    ) == [original]


def test_a_value_glued_into_a_longer_word_is_outside_what_this_harness_claims() -> None:
    """The second stated boundary: adjacency to a letter on either side suppresses the match.

    ``xJohn Smithx`` carries the original **byte for byte**, and neither this
    harness nor the gate reports it -- both resolve to :func:`_occurs_as_a_unit`,
    which applies a word-boundary assertion on each side whose adjacent needle
    character is alphanumeric. Found by sabotage, not by reading: a real vaulted
    original was spliced into a real payload in this shape with the gate's pass 1
    blinded, and all six runs read clean; with the gate live the value reached the
    provider.

    It is a boundary rather than a bug because the alternative is worse in a way
    this file has already paid for. Dropping the assertion makes ``Brown`` match
    inside ``Browning`` -- a red that is indistinguishable from a real leak until
    somebody spends an hour on it, and one that appears and vanishes between runs
    because pseudonyms derive from a random per-session key. Restricting the
    relaxation to multi-word originals does not rescue it either: fixture originals
    include ordinary clinical phrases, and ``chronic low back pains`` contains
    ``chronic low back pain`` verbatim, so the plural alone would manufacture a red.

    What makes the residual risk small is that the shapes the *pipeline* can
    actually emit do not land here. Every surrogate ends in ``]`` and every
    redaction marker does too, so a splice that leaves an original adjacent to our
    own output has a non-alphanumeric character between them and is caught -- which
    :func:`test_the_scan_sees_markdown_and_punctuation_wrapped_originals` pins from
    the other direction. This test exists so the boundary is a decision on the
    record rather than a surprise in a live review.
    """
    original = "John Smith"

    for haystack in (
        f"Reference: x{original}x confirmed.",
        f"Reference: x{original} confirmed.",
        f"Reference: {original}x confirmed.",
    ):
        assert original in haystack, "premise: the original really is present verbatim"
        assert not find_in_text(frozenset({original}), haystack), (
            f"if this now fires, the occurrence rule has gained glued-word detection "
            f"for {haystack!r} -- good, but the README's stated boundary must change "
            "with it, and the Brown/Browning false positive must be re-checked"
        )

    # The false positive the rule exists to prevent, and the plural form that rules
    # out the obvious "relax it for multi-word needles" fix.
    assert not find_in_text(frozenset({"Brown"}), "Counsel Browning filed the motion.")
    assert not find_in_text(
        frozenset({"chronic low back pain"}), "notes chronic low back pains today"
    )

    # Separated by anything non-alphanumeric -- including our own output's ``]`` --
    # it is caught, which is the case the pipeline can actually produce.
    assert find_in_text(
        frozenset({original}), f"[PII_NAME_1a2b3c4d]{original} confirmed."
    ) == [original]


def test_a_combining_mark_inside_a_value_is_outside_what_this_harness_claims() -> None:
    """The third stated boundary: a combining mark spliced into a value defeats the scan.

    ``normalize`` is NFKC, which *composes* -- so a value written in decomposed form
    is caught (asserted below, because that half is a real capability and nothing
    else pins it). What NFKC cannot do is remove a mark that was never in the
    vaulted value: ``J`` + U+0301 + ``ohn Smith`` normalises to ``J́ohn Smith``,
    which is simply a different string from ``john smith``.

    This is deliberate upstream and not an oversight here. ``_INVISIBLE_RE`` in the
    egress gate folds 145 format codepoints and names its own limit in as many
    words -- *"no letter, digit, space or combining diacritic is in here, so
    ``José`` and ``Jose`` remain different values"*. Folding marks out would collapse
    two genuinely distinct originals into one and manufacture reds on any document
    carrying both spellings of a name, which is ordinary in the documents this
    system protects.

    So it belongs with homoglyph substitution rather than with the zero-width
    bypass: catching it needs a confusables/skeleton table, not another
    normalisation form. Verified by sabotage rather than reasoned about -- a real
    vaulted original was spliced into a real payload with one combining acute
    inserted, and with the gate **live** the run completed and the value reached the
    provider, so this is a property of the pipeline and not only of the instrument.
    """
    original = "John Smith"
    mark = unicodedata.lookup("COMBINING ACUTE ACCENT")
    mutated = f"Reference: {original[0]}{mark}{original[1:]} confirmed."

    assert original not in mutated, "premise: the raw value is genuinely not present"
    assert not find_in_text(frozenset({original}), mutated), (
        "if this now fires, the scan has gained combining-mark folding -- good, but "
        "the README's stated boundary must change with it, and `José` vs `Jose` must "
        "be re-checked, because that is what the fold would also collapse"
    )
    # The gate agrees. The two must not disagree about what an occurrence is, and a
    # boundary only counts as *stated* if it is the same boundary on both sides.
    assert not _occurs_as_a_unit(
        _strip_invisible(normalize(original)), _strip_invisible(normalize(mutated))
    ), "the gate now sees this and the harness does not -- the checker is weaker again"

    # The half that DOES hold: NFKC composes, so a decomposed rendering of an
    # accented original is still caught. Nothing else in this module asserted it.
    accented = "José Ruiz"
    decomposed = unicodedata.normalize("NFD", accented)
    assert accented not in f"client {decomposed} signed", "premise: NFD is a distinct string"
    assert find_in_text(frozenset({accented}), f"client {decomposed} signed") == [accented]


def test_a_short_surrogate_inside_a_longer_word_has_not_survived() -> None:
    """A Faker draw that is a substring of an ordinary word is not a live surrogate.

    The restorer replaces surrogates on word boundaries, so a checker using a bare
    ``in`` disagrees with the code it is checking. Because pseudonyms are seeded
    from a random per-session key, the resulting red appeared and disappeared
    between runs -- the worst kind of failure on the file that carries the headline
    number.
    """
    answer = "The report names Richardson and Browning as counsel of record."

    # Present only as a substring of a longer word: not a surviving surrogate.
    assert "Rich" in answer and "Brown" in answer, "premise: both are substrings"
    assert not [s for s in ("Rich", "Brown") if occurs_as_a_unit(s, answer)]

    # Genuinely present as a word: still caught.
    assert occurs_as_a_unit("Rich", "The client Rich signed the release.")


def _reference_occurs_as_a_unit(needle: str, haystack: str) -> bool:
    """An independently written statement of the occurrence rule.

    Deliberately shares no machinery with the implementation it checks: explicit
    index arithmetic and :meth:`str.isalnum` instead of regex lookarounds. The
    rule it encodes is the intended one, in words -- *the needle is present, and on
    each side where the needle's own edge character is alphanumeric, the character
    beyond it is not.*

    Two independent derivations agreeing is evidence. One derivation imported into
    four call sites is not, which is the lesson of the bug this file now documents.
    """
    if not needle:
        return False
    start = haystack.find(needle)
    while start != -1:
        end = start + len(needle)
        left_ok = not needle[0].isalnum() or start == 0 or not haystack[start - 1].isalnum()
        right_ok = (
            not needle[-1].isalnum() or end == len(haystack) or not haystack[end].isalnum()
        )
        if left_ok and right_ok:
            return True
        start = haystack.find(needle, start + 1)
    return False


#: Realistic originals, including the punctuation-edged shapes the old rule missed.
_DIFFERENTIAL_NEEDLES = (
    "John Smith",
    "Brown",
    "MRN: 4823910",
    "(415) 555-0123",
    "$1,234.56",
    "47-1234567",
    "Case No. 3:24-cv-01188",
    "ada.brown@example.com",
    "HbA1c of 8.2",
    "O'Brien",
)

#: Every wrapping that has ever mattered here: markdown, brackets, adjacency on
#: each side by a letter, a digit, an underscore and a full stop, and prose.
_DIFFERENTIAL_WRAPPERS = (
    "{}",
    " {} ",
    "_{}_",
    "__{}__",
    "**{}**",
    "`{}`",
    "({})",
    "[{}]",
    "<DOCUMENT>{}</DOCUMENT>",
    "the client {} signed the release",
    "x{}",
    "{}x",
    "x{}x",
    "_{}",
    "{}_",
    "1{}",
    "{}1",
    ".{}",
    "{}.",
    "line one\n{}\nline three",
    "{} and again {}",
    "nothing to see here",
)


def test_the_occurrence_rule_has_no_fourth_copy() -> None:
    """The shared rule, checked against an independent restatement of it.

    The gate, the engine's residual sweep and this harness now all resolve to one
    function, which removes the *divergence* risk that produced a false 100/100 --
    but sharing a definition is not the same as verifying it. If the single
    remaining copy is wrong, everything downstream is uniformly wrong and uniformly
    silent, which is precisely the failure mode that made the original bug so
    expensive to find.

    So the shared implementation is compared against
    :func:`_reference_occurs_as_a_unit` across every needle in every wrapping --
    220 pairs. A disagreement means one of the two is wrong and neither can be
    trusted until it is resolved, so the failure message names the exact pair.
    """
    disagreements: list[tuple[str, str, bool, bool]] = []
    pairs = 0
    for needle in _DIFFERENTIAL_NEEDLES:
        for wrapper in _DIFFERENTIAL_WRAPPERS:
            haystack = wrapper.replace("{}", needle)
            pairs += 1
            shared = occurs_as_a_unit(needle, haystack)
            reference = _reference_occurs_as_a_unit(needle, haystack)
            if shared != reference:
                disagreements.append((needle, haystack, shared, reference))

    assert pairs == len(_DIFFERENTIAL_NEEDLES) * len(_DIFFERENTIAL_WRAPPERS)
    assert not disagreements, (
        f"{len(disagreements)} of {pairs} needle/haystack pairs disagree between the "
        f"shared occurrence rule and the independent reference: "
        f"{[(n, h, f'shared={s}', f'ref={r}') for n, h, s, r in disagreements[:5]]}"
    )

    # The corpus has to exercise both answers, or agreement is trivial.
    positives = sum(
        _reference_occurs_as_a_unit(n, w.replace("{}", n))
        for n in _DIFFERENTIAL_NEEDLES
        for w in _DIFFERENTIAL_WRAPPERS
    )
    assert 0 < positives < pairs, (
        f"the differential corpus is degenerate: {positives}/{pairs} positive"
    )


#: A small alphabet with one character from each class the occurrence rule cares
#: about: letters, a digit, an underscore (a regex ``\w`` that is *not* alphanumeric
#: -- the exact character the original bug turned on), a space, and punctuation on
#: both sides of a needle. Deliberately tiny so generated needles actually collide
#: with generated haystacks; a wide alphabet makes every draw a trivial non-match.
_FUZZ_ALPHABET = "ab1_ .[]$-"


@given(
    needle=st.text(alphabet=_FUZZ_ALPHABET, min_size=1, max_size=6),
    haystack=st.text(alphabet=_FUZZ_ALPHABET, max_size=24),
)
@settings(max_examples=2_000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_the_shared_occurrence_rule_agrees_with_the_reference_on_generated_input(
    needle: str, haystack: str
) -> None:
    """The differential test, generalised past the 220 pairs somebody thought of.

    :func:`test_the_occurrence_rule_has_no_fourth_copy` compares the shared rule
    against :func:`_reference_occurs_as_a_unit` over a hand-written corpus. Hand-
    written corpora encode the cases their author already knew about, and every
    version of this bug so far has been a case nobody thought of -- ``_`` counting as
    a word character, a needle whose first character is punctuation, an invisible
    codepoint, a value glued between two SQLite column values. Four for four, the
    corpus was extended *after* the miss.

    So the same comparison is driven with generated input over an alphabet built from
    the character classes the rule turns on. A disagreement means one of the two is
    wrong and neither can be trusted until it is resolved; hypothesis shrinks it to a
    minimal pair, which is the part a hand-written corpus cannot do at all.

    This is the one place in the suite where the *shared* rule is checked rather than
    merely shared, so it is worth the couple of seconds it costs.
    """
    assert occurs_as_a_unit(needle, haystack) == _reference_occurs_as_a_unit(needle, haystack)


#: Membership tests this module must never contain again. Each is a bare ``in``
#: against a string the pipeline produced, and every one of them was a real defect:
#: two hid leaks by being stricter than the code, two invented leaks by being
#: looser. They are matched as source text because the property being protected is
#: "nobody writes a fifth convention", which is a fact about the file rather than
#: about any one run.
_FORBIDDEN_MEMBERSHIP_SNIPPETS = (
    "in result.restored_text",
    "in result.raw_llm_response",
    "in sent_payload",
    "in decoded",
    ".encode(\"utf-8\") in haystack",
)


def test_no_leak_comparison_in_this_module_bypasses_the_shared_rule() -> None:
    """No bare ``in`` decides whether a value **leaked**, anywhere in this file.

    Four separate call sites here have now been wrong in exactly this way, in both
    directions, and each one sat directly underneath a headline assertion:

    * the payload scan (stricter than the gate) -- missed markdown-wrapped leaks;
    * ``find_in_bytes`` (looser) -- a six-digit original inside a hex ``run_id``
      reads as a leak in the audit database;
    * the round-trip check (looser) -- an original inside a longer word reads as
      restored when it was not;
    * the surviving-surrogate check (looser) -- a short Faker draw inside an
      ordinary word reads as a surrogate that escaped restoration.

    A behavioural test catches the *instance* it was written for. This catches the
    **class**, which is the only thing that has actually worked on this bug: every
    *leak* decision in this module has to route through :data:`occurs_as_a_unit`,
    so the next person to add a scan cannot quietly invent a fifth convention that
    agrees with nothing.

    **The scope of this rule is leak detection, and that is a narrowing rather than
    a loophole.** It used to be stated as "no comparison anywhere in this module",
    which sounded stronger and was actively harmful in one place: the round-trip
    *expectation* must NOT share a predicate with the restorer, or it agrees with
    the code it is checking and shrinks silently whenever that code is wrong. The
    **It also used to scan only the first two-thirds of the file**, which is worth
    naming because it made the rule vacuous exactly where it mattered. The scanned
    region was ``source.split("_FORBIDDEN_MEMBERSHIP_SNIPPETS = (")[0]`` -- a way of
    stopping the tuple below from matching itself -- and the 100-run function is
    defined *after* that tuple. So three of the four historical bugs sat in a region
    this rule never looked at. Measured, not spotted by reading: putting
    ``[o for o in originals if o in sent_payload]`` back into the payload scan left
    this test **green**. The exclusion is now computed from the parsed module, so the
    only regions skipped are the tuple itself and this function's own body.

    The two rules pull opposite ways, and pretending they were one rule is what kept
    the expectation tied to ``TOKEN_RE``. The other direction is enforced by
    :func:`test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots`,
    which fails if the completeness path starts using the shared rule again.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source)

    # Everything except the snippet tuple and this function, which quote the
    # forbidden text by construction. Computed from the parse, so the covered region
    # cannot silently shrink again.
    skip: set[int] = set()
    for node in ast.walk(tree):
        named_tuple = (
            isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "_FORBIDDEN_MEMBERSHIP_SNIPPETS"
                for t in node.targets
            )
        )
        this_test = (
            isinstance(node, ast.FunctionDef)
            and node.name == "test_no_leak_comparison_in_this_module_bypasses_the_shared_rule"
        )
        if (named_tuple or this_test) and node.end_lineno is not None:
            skip.update(range(node.lineno, node.end_lineno + 1))
    body = "\n".join(line for n, line in enumerate(lines, start=1) if n not in skip)

    assert "async def test_no_original_ever_leaves_the_process" in body, (
        "the scanned region no longer includes the 100-run function, which is where "
        "three of the four historical bugs actually lived"
    )

    offenders = [snippet for snippet in _FORBIDDEN_MEMBERSHIP_SNIPPETS if snippet in body]
    assert not offenders, (
        "these membership tests bypass the shared occurrence rule and will disagree "
        f"with the gate, the engine and the restorer: {offenders}. Use "
        "occurs_as_a_unit(needle, haystack) instead."
    )

    # The rule really is the one thing in use: every leak-scan helper calls it.
    for helper in ("def find_in_text", "def find_in_bytes"):
        start = body.index(helper)
        end = body.index("\ndef ", start + 1)
        assert "occurs_as_a_unit(" in body[start:end], (
            f"{helper} no longer routes through the shared occurrence rule"
        )

    # Both limbs of the audit assertion must still be applied by the run. Loosening
    # the byte limb so it could carry the label-column case alone was tried and
    # reverted (see find_in_bytes); deleting either limb on the assumption that the
    # other one covers it is the same mistake in the other direction.
    run_start = source.index("async def test_no_original_ever_leaves_the_process")
    for limb in ("find_in_text(originals, audit_json)", "find_in_bytes(originals, harness.audit_bytes())"):
        assert limb in source[run_start:], (
            f"the audit assertion no longer applies {limb} -- the two limbs see "
            "different things and neither is redundant"
        )


#: Production predicates the round-trip *expectation* must never be built from.
#: Each is a predicate the restorer itself uses, so an expectation phrased in terms
#: of one cannot disagree with the restorer -- which is the only thing it is for.
_RESTORER_PREDICATES = ("extract_token_ids", "STRICT_TOKEN_RE", "TOKEN_RE", "occurs_as_a_unit")


def test_the_round_trip_expectation_does_not_share_the_restorer_s_blind_spots() -> None:
    """Completeness is checked against an *independent* reading of the model's words.

    Two halves, and the behavioural one is the point.

    **Structural.** ``expected_round_trip`` and ``issued_token_id`` must not *use*
    any predicate the restorer uses. This is the direction the sibling rule above
    deliberately does not cover. Checked over the parsed AST rather than the source
    text, so the names can still be discussed in a docstring -- which they have to
    be, since the reason they are forbidden is the whole content of this rule.

    **Behavioural.** A token shape ``TOKEN_RE`` cannot match -- here the bare 8-hex
    ID, which a model writes constantly when it paraphrases rather than quotes --
    must still land in ``expected``. Under the old derivation it did not: the
    expectation was built with ``extract_token_ids``, so a token the production
    grammar could not see was dropped from the expectation, left alone by the
    restorer, and missed by assertion 4's residual scan, all three agreeing. The
    only trace was a smaller ``round_trip_checked`` in the summary line, and a
    denominator quietly shrinking is not a signal anybody acts on.

    Asserted with the production regex on the same input, so the premise -- that
    this really is a shape ``TOKEN_RE`` misses -- is measured rather than claimed.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    checked = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in ("expected_round_trip", "issued_token_id", "_mentions"):
            continue
        checked += 1
        used = {inner.id for inner in ast.walk(node) if isinstance(inner, ast.Name)}
        used |= {inner.attr for inner in ast.walk(node) if isinstance(inner, ast.Attribute)}
        borrowed = sorted(used & set(_RESTORER_PREDICATES))
        assert not borrowed, (
            f"{node.name} is built from {borrowed}, which the restorer also uses -- so "
            "the expectation cannot disagree with the restorer and a token the "
            "production grammar misses will vanish from both at once"
        )
    assert checked == 3, (
        f"expected to check 3 completeness helpers, found {checked} -- one was "
        "renamed or removed without this rule being reconsidered"
    )

    surrogate = "[PHI_NAME_1a2b3c4d]"
    original = "Marguerite Vandenberg"
    mapping = {surrogate: original}

    quoted = f"The record names {surrogate} as the patient."
    assert expected_round_trip(quoted, mapping) == {original}

    # The shape the production grammar cannot see, which a model does emit.
    paraphrased = "The record names the patient (internal ref 1a2b3c4d) throughout."
    assert not extract_token_ids(paraphrased), (
        "premise: TOKEN_RE really is blind to a bare ID -- if it now matches, this "
        "test needs a shape that is still outside the grammar"
    )
    assert expected_round_trip(paraphrased, mapping) == {original}, (
        "the model referred to a token the restorer's grammar cannot see; if the "
        "restorer leaves it, the answer carries a dangling hex ID and this harness "
        "must report it rather than quietly expect less"
    )

    # Upper-cased, as the mock's own upper_hash mutation renders it.
    assert expected_round_trip("ref 1A2B3C4D", mapping) == {original}

    # And it does not invent expectations out of nothing.
    assert expected_round_trip("The record names nobody in particular.", mapping) == set()
    assert expected_round_trip("ref deadbeef", mapping) == set()

    # A pseudonym carries no ID, so it is matched as a literal -- and still
    # boundary-anchored, or a short Faker draw inside an ordinary word becomes an
    # expectation the restorer was never asked to satisfy.
    fake_map = {"Brown": "Vandenberg"}
    assert expected_round_trip("Counsel Brown filed the motion.", fake_map) == {"Vandenberg"}
    assert expected_round_trip("Counsel Browning filed the motion.", fake_map) == set()


# ---------------------------------------------------------------------------
# 1. The 100 runs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="module")
@pytest.mark.parametrize("index", range(RUNS), ids=run_id_for)
async def test_no_original_ever_leaves_the_process(
    harness: Harness,
    ledger: Ledger,
    caplog: pytest.LogCaptureFixture,
    index: int,
) -> None:
    seed, kind, strategy = plan_run(index)
    caplog.set_level(logging.DEBUG)

    document = generator.generate(seed, kind)
    doc_id = await harness.store.put(
        USER_ID, f"{kind}-{seed}.txt", document.encode("utf-8"), DOC_CATEGORY[kind]
    )
    session_id, _expires_at = await harness.sessions.create("test-user")
    calls_before = harness.provider.calls
    result = await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, strategy)

    # The payload this test scans has to be the payload that was actually sent.
    # `result.obfuscated_payload` is the orchestrator's own record of it; the
    # provider wrapper holds the two strings the provider was really handed. If
    # those ever diverge the whole file measures a string nobody transmitted, so
    # the identity is asserted rather than assumed, and everything below scans
    # the boundary-captured copy.
    assert harness.provider.calls == calls_before + 1, (
        f"run {index}: expected exactly one provider call, saw "
        f"{harness.provider.calls - calls_before}"
    )
    sent_payload = harness.provider.last_payload
    assert sent_payload is not None
    assert sent_payload == result.obfuscated_payload, (
        f"run {index}: the payload the gate scanned is not the payload the provider "
        f"received ({len(result.obfuscated_payload)} chars scanned, {len(sent_payload)} sent)"
    )

    originals = harness.vault.originals_for_session(session_id)
    assert originals, (
        f"run {index} vaulted nothing, so every leak scan below would be vacuous "
        f"(kind={kind}, seed={seed})"
    )
    mapping = await surrogate_map(harness, session_id, result)

    # --- 0. no surrogate stands for itself ---------------------------------
    # The pseudonymization collision guard rejects a fake that shares a word with
    # any original in the document. The degenerate failure of that guard is a
    # "surrogate" equal to the value it replaces -- the payload would then carry
    # the real value under cover of being obfuscated, and every later check in
    # this test would happily pass. Compared on normalised forms, so a
    # case-mangled or re-spaced identity is caught too.
    identity = sorted(
        s for s, original in mapping.items() if normalize(s) == normalize(original)
    )
    assert not identity, (
        f"run {index}: {len(identity)} surrogate(s) are identical to the value they "
        f"replace, so the value was never obfuscated at all: {[mask(v) for v in identity]}"
    )

    # --- 1. the outbound payload -------------------------------------------
    # Scanned on the bytes captured at the PROVIDER boundary (asserted identical
    # to the string the gate saw, above), with NO exemption for bytes the
    # pipeline wrote itself. A pseudonym that reproduces a real value verbatim
    # puts that value on the wire no matter which span it sits in, so there is
    # nothing here to excuse; the pseudonymization collision guard is what keeps
    # this clean.
    payload_leaks = find_in_text(originals, sent_payload)
    if payload_leaks:
        ledger.leaks += len(payload_leaks)
    assert not payload_leaks, (
        f"run {index} ({kind}/{strategy}, seed {seed}): {len(payload_leaks)} original(s) "
        f"present in the outbound payload: {[mask(v) for v in payload_leaks]}"
    )

    # --- 2a. the audit trail, through the query API and on disk -------------
    events = await harness.audit.query(session_id=session_id, limit=10_000)
    assert events, f"run {index} emitted no audit events"
    # ``ensure_ascii=False``: the default escapes every non-ASCII character to
    # ``\uXXXX``, which would hide an accented original from the scan below in a
    # haystack that provably contains it. See ``_unescape_json_unicode``.
    audit_json = json.dumps(
        [event.model_dump() for event in events], default=str, ensure_ascii=False
    )
    audit_leaks = find_in_text(originals, audit_json)
    audit_leaks += [
        value
        for value in find_in_bytes(originals, harness.audit_bytes())
        if value not in audit_leaks
    ]
    if audit_leaks:
        ledger.leaks += len(audit_leaks)
    assert not audit_leaks, (
        f"run {index}: {len(audit_leaks)} original(s) reached the audit log: "
        f"{[mask(v) for v in audit_leaks]}"
    )

    # --- 2b. every log line the package emitted, at DEBUG -------------------
    # ``log_haystack`` rather than ``caplog.text``: the default formatter renders
    # no ``extra=`` fields, and that is where this package puts every variable it
    # logs. Scanning ``caplog.text`` alone checked the constant half of each line.
    log_leaks = find_in_text(originals, log_haystack(caplog))
    if log_leaks:
        ledger.leaks += len(log_leaks)
    assert not log_leaks, (
        f"run {index}: {len(log_leaks)} original(s) reached the log output: "
        f"{[mask(v) for v in log_leaks]}"
    )

    # --- 3. round-trip completeness ----------------------------------------
    # Both predicates here are the INDEPENDENT ones -- see expected_round_trip.
    # Leak detection above must never be laxer than the gate; completeness must
    # never share a predicate with the restorer. Those are different rules, and
    # running both through one shared helper is what let a token TOKEN_RE could
    # not see disappear from the expectation, the answer and the residual scan at
    # the same time.
    expected = expected_round_trip(result.raw_llm_response, mapping)
    assert expected, (
        f"run {index}: the model referenced no surrogate at all, so the round-trip "
        f"assertion would be vacuous (kind={kind}, seed={seed})"
    )
    not_restored = sorted(
        o for o in expected if not _reference_occurs_as_a_unit(o, result.restored_text)
    )
    assert not not_restored, (
        f"run {index}: {len(not_restored)} of {len(expected)} referenced surrogate(s) were not "
        f"restored to their originals: {[mask(v) for v in not_restored]}"
    )

    # --- 4. nothing surrogate-shaped survives ------------------------------
    residual = [match.group(0) for match in TOKEN_RE.finditer(result.restored_text)]
    assert not residual, f"run {index}: residual token pattern(s) in the answer: {residual[:5]}"
    # Boundary-anchored, because the restorer replaces surrogates on word
    # boundaries and a checker that disagrees with the code it checks is wrong in
    # whichever direction it disagrees. A bare ``in`` here reported a short Faker
    # draw (``"Rich"``) as a surviving surrogate because it sat inside an ordinary
    # word -- and since pseudonyms derive from a random per-session key, that red
    # appeared and vanished between runs. This is Deviation 13's asymmetry pointing
    # the other way: there the checker was stricter than the code and hid leaks;
    # here it was looser and invented one.
    surviving = sorted(s for s in mapping if occurs_as_a_unit(s, result.restored_text))
    assert not surviving, (
        f"run {index}: {len(surviving)} issued surrogate(s) survived into the answer: "
        f"{surviving[:5]}"
    )

    ledger.record(originals=len(originals), restored=len(expected))


# ---------------------------------------------------------------------------
# 2. Adversarial: fail-closed independent of detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="module")
async def test_planted_value_is_invisible_to_the_detector(harness: Harness) -> None:
    """The premise of the adversarial case, asserted rather than assumed.

    If any recogniser fired on the planted value the next test would prove
    nothing -- the engine would obfuscate it and the gate would never see it.
    """
    document = "Internal Reference Sheet\n" + PLANT_TEMPLATE.format(UNKNOWN_SHAPE_VALUE)
    start = document.index(UNKNOWN_SHAPE_VALUE)
    end = start + len(UNKNOWN_SHAPE_VALUE)
    for doc_category in ("medical", "legal", "financial", "general"):
        hits = await harness.detector.detect(document, doc_category)
        overlapping = [h.entity_type for h in hits if h.start < end and h.end > start]
        assert not overlapping, (
            f"{UNKNOWN_SHAPE_VALUE!r} is recognised as {overlapping} in a {doc_category} "
            "document; pick a shape the registry genuinely does not know"
        )


@pytest.mark.asyncio(loop_scope="module")
async def test_unknown_shape_value_blocks_egress_and_the_call_never_fires(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail-closed, proven without the detector.

    A value of an unknown shape is planted in the document *and* injected into the
    vault's originals set. The detector is blind to it (asserted above), so the
    engine leaves it in place and it rides through into the payload. Pass 1 of the
    gate -- the original-value scan, which never consults the detector -- has to
    catch it. Nothing here depends on detection recall.
    """
    document = generator.generate(SEED_BASE + RUNS, "financial") + PLANT_TEMPLATE.format(
        UNKNOWN_SHAPE_VALUE
    )
    doc_id = await harness.store.put(
        USER_ID, "planted.txt", document.encode("utf-8"), "financial"
    )
    session_id, _expires_at = await harness.sessions.create("test-user")

    real_originals = harness.vault.originals_for_session

    def blinded(target_session: str) -> frozenset[str]:
        known = real_originals(target_session)
        if target_session == session_id:
            return known | {UNKNOWN_SHAPE_VALUE}
        return known

    monkeypatch.setattr(harness.vault, "originals_for_session", blinded)

    calls_before = harness.provider.calls
    with pytest.raises(EgressBlockedError) as excinfo:
        await harness.orchestrator.run(
            session_id, USER_ID, doc_id, PROMPT, "tokenization"
        )

    error = excinfo.value
    assert error.detail["reason"] == "vault_original"
    assert isinstance(error.detail["hit_count"], int) and error.detail["hit_count"] >= 1
    # The error itself must not carry the value it blocked on (section 16).
    assert UNKNOWN_SHAPE_VALUE not in str(error)
    assert UNKNOWN_SHAPE_VALUE not in repr(error)

    # The whole point: the provider was never reached.
    assert harness.provider.calls == calls_before, (
        "the provider was called on a blocked run -- the gate is not fail-closed"
    )

    blocks = await harness.audit.query(session_id=session_id, event_type=EGRESS_BLOCK)
    assert len(blocks) == 1, f"expected exactly one EGRESS_BLOCK event, got {len(blocks)}"
    assert blocks[0].detail["reason"] == "vault_original"
    assert UNKNOWN_SHAPE_VALUE not in json.dumps(blocks[0].model_dump(), default=str)


#: Every shape ``surrogates.TOKEN_RE`` accepts, with the mutation class the mock
#: uses to produce it -- or ``None`` where the mock never produces it at all.
#: ``MockProvider`` defines six mutation classes and both the round-trip test and
#: this harness were written against exactly those six, so the ``None`` rows are the
#: tolerance nothing had ever exercised: the adversary was written by the defender.
_TOKEN_SHAPES: tuple[tuple[str, str, str | None], ...] = (
    ("canonical", "[PHI_NAME_1a2b3c4d]", "verbatim"),
    ("upper_hash", "[PHI_NAME_1A2B3C4D]", "upper_hash"),
    ("bracket_dropped", "PHI_NAME_1a2b3c4d", "bracket_dropped"),
    ("brace_brackets", "{PHI_NAME_1a2b3c4d}", None),
    ("paren_brackets", "(PHI_NAME_1a2b3c4d)", None),
    ("hyphen_separators", "[PHI-NAME-1a2b3c4d]", None),
    ("hyphen_no_brackets", "PHI-NAME-1a2b3c4d", None),
    ("mismatched_brackets", "[PHI_NAME_1a2b3c4d}", None),
    ("interior_whitespace", "[ PHI_NAME_1a2b3c4d ]", None),
    ("mixed_case_hash", "[PHI_NAME_1A2b3C4d]", None),
)


@pytest.mark.asyncio(loop_scope="module")
async def test_every_token_shape_the_grammar_accepts_restores_not_just_the_six_the_mock_emits(
    harness: Harness,
) -> None:
    """The surplus tolerance, exercised -- because the adversary was written by us.

    ``MockProvider`` defines exactly six mutation classes, and the round-trip
    assertion in this module was written against exactly those six. ``TOKEN_RE``
    tolerates considerably more: ``{}`` and ``()`` brackets, ``-`` separators, a
    mismatched bracket pair, up to four whitespace characters inside the token, and
    any casing of the hash. Every one of those is something a real model does and the
    mock never does, so the 100 runs say nothing about them -- the suite was grading
    the pipeline against a mangler the pipeline's own author wrote.

    That gap is not cosmetic. A shape the grammar advertises but the restorer fumbles
    is a token that reaches the **user** un-restored, and the shape most likely to be
    fumbled is exactly the one no test ever sent. So each shape goes through the real
    :class:`Restorer` against a real vault record, with the mock removed from the
    loop entirely.

    Three things are asserted per shape, because "the original came back" is not the
    whole contract: the original is present, the count says the restorer believes it
    did the work, and nothing token-shaped survives -- a half-restored answer carrying
    both is worse than either.
    """
    session_id, _expires_at = await harness.sessions.create("test-user")
    original = "Marguerite Vandenberg"
    surrogate = "[PHI_NAME_1a2b3c4d]"
    await harness.vault.put(
        session_id,
        TokenRecord(
            session_id=session_id,
            token_id="1a2b3c4d",
            entity_type="PHI_NAME",
            category="PHI",
            surrogate=surrogate,
            created_at=1.0,
        ),
        original,
    )
    restorer = Restorer(vault=harness.vault, settings=harness.settings, audit=harness.audit)

    unexercised = [name for name, _shape, mutation in _TOKEN_SHAPES if mutation is None]
    assert len(unexercised) >= 6, (
        "this table no longer describes any shape the mock cannot produce, so it has "
        "stopped testing the surplus tolerance it exists for"
    )

    for name, shape, _mutation in _TOKEN_SHAPES:
        assert TOKEN_RE.search(shape), (
            f"premise: {name} is supposed to be inside the grammar -- if TOKEN_RE no "
            "longer accepts it, the grammar narrowed and this table must say so"
        )
        text = f"The record names {shape} as the patient of record."
        result = await restorer.restore(
            session_id,
            text,
            strategy="tokenization",
            surrogates={surrogate: original},
            issued={"1a2b3c4d"},
        )
        assert original in result.text, (
            f"{name} ({shape!r}) is accepted by TOKEN_RE and was NOT restored, so a "
            "model emitting it hands the user a raw token"
        )
        assert result.restored_count == 1, (
            f"{name}: restored_count is {result.restored_count}, so the answer is right "
            "by accident rather than by the restorer having done the substitution"
        )
        assert not TOKEN_RE.search(result.text), (
            f"{name}: something token-shaped survived into the answer alongside the "
            f"restored original: {result.text!r}"
        )


@pytest.mark.asyncio(loop_scope="module")
async def test_the_audit_scan_catches_a_label_column_original_and_says_which_limb_did(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The audit log CAN physically hold an original. This is what stops it.

    Worth stating in a test because the claim is easy to overstate in a live review
    and the overstatement is checkable in one line. The size ceilings -- 128
    characters on the label columns, 64 on a ``detail`` value -- make the log
    incapable of holding *content*, which is the bulk-exfiltration shape. They do not
    and cannot make it incapable of holding a name or an MRN: ``"Marguerite
    Vandenberg"`` is 21 characters and ``"MRN 4823910"`` is 11, so both pass the
    write-boundary guard untouched and land verbatim in the raw SQLite bytes. That is
    asserted here rather than argued, on a real ``AuditLogger`` and a real file.

    What actually holds is narrower and is *measured*: no call site in the package
    passes a value to ``emit`` -- every field is a token ID, a type name, a count, a
    latency or a digest -- and assertion 2 scans both the query view of the rows and
    the raw audit file, against every vaulted original, on all 100 runs. The half
    nothing pinned was that the scan would **catch** such a write if a call site ever
    started making one, which is the property the other 100 tests rely on and which
    would fail silently if either limb were narrowed.

    So the value is planted through the real writer and then hunted exactly the way
    the run hunts it -- and the result is attributed to a limb rather than to "the
    scan", because the two limbs do not see the same thing. The **query** limb catches
    a label-column original (JSON quoting supplies the boundaries the anchored rule
    needs); the **byte** limb does not, because SQLite stores column values with no
    delimiter between them. Left unattributed, this test would read as evidence for a
    property the byte limb does not have, and deleting the query limb would then look
    safe. See
    :func:`test_the_byte_limb_and_the_query_limb_of_the_audit_scan_see_different_things`.

    The reverse is checked too: a log full of ordinary audit traffic must not report
    a leak, or the instrument proves nothing by firing.
    """
    root = tmp_path_factory.mktemp("audit-value-probe")
    db = root / "audit.db"
    name = "Marguerite Vandenberg"
    mrn = "MRN 4823910"

    log = await AuditLogger.open(db)
    try:
        # Ordinary traffic first: the scan must be quiet on this.
        for i in range(5):
            await log.emit(
                AuditEvent(
                    ts=1_700_000_000.0 + i,
                    session_id="sess-probe",
                    run_id="run-probe",
                    event_type=EGRESS_BLOCK,
                    entity_type="PHI_NAME",
                    token_id=f"{i:08x}",
                    detail={"count": i, "elapsed_ms": 1.5},
                )
            )
        clean = frozenset({name, mrn})
        assert not find_in_bytes(clean, _audit_file_bytes(db)), (
            "the byte scan fires on a log carrying nothing but token IDs and counts"
        )

        # Now the write the ceilings do not stop. This is the overclaim, disproven.
        assert len(name) <= MAX_AUDIT_LABEL_LEN and len(mrn) <= MAX_DETAIL_VALUE_LEN
        await log.emit(
            AuditEvent(
                ts=1_700_000_100.0,
                session_id="sess-probe",
                run_id="run-probe",
                event_type=EGRESS_BLOCK,
                entity_type=name,
                token_id="deadbeef",
                detail={"v": mrn},
            )
        )
    finally:
        await log.close()

    blob = _audit_file_bytes(db)
    assert name.encode("utf-8") in blob and mrn.encode("utf-8") in blob, (
        "premise: a short original really does reach the file verbatim -- if this "
        "fails the schema gained a guard and the README's wording should say so"
    )

    # Assertion 2 exactly as the run performs it: both limbs, unioned.
    planted = frozenset({name, mrn})
    reopened = await AuditLogger.open(db)
    try:
        events = await reopened.query(limit=10_000)
        audit_json = json.dumps(
            [event.model_dump() for event in events], default=str, ensure_ascii=False
        )
    finally:
        await reopened.close()

    query_limb = find_in_text(planted, audit_json)
    byte_limb = find_in_bytes(planted, blob)
    caught = sorted(set(query_limb) | set(byte_limb))
    assert caught == sorted([mrn, name]), (
        "an original written into the audit log was not reported by assertion 2 -- "
        f"query limb saw {query_limb}, byte limb saw {byte_limb}"
    )

    # ...and which limb did the work, so the attribution cannot rot.
    assert name in query_limb and name not in byte_limb, (
        "the label-column case is the query limb's to catch; if the byte limb now "
        "catches it too, check the elapsed_ms false positive before celebrating"
    )
    assert mrn in query_limb and mrn in byte_limb, (
        "a detail value is JSON-quoted in both views, so both limbs must see it"
    )


def _audit_file_bytes(db: Path) -> bytes:
    """The audit DB plus its WAL sidecar, as raw bytes. Mirrors ``Harness.audit_bytes``."""
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(db) + suffix)
        if path.is_file():
            blob += path.read_bytes()
    return blob


# ---------------------------------------------------------------------------
# 3. Summary
# ---------------------------------------------------------------------------


def _selected_run_count(request: pytest.FixtureRequest) -> int:
    """How many of the 100 parametrized runs this pytest invocation actually selected.

    Read off ``session.items`` -- the post-filter collection -- so it reflects
    ``-k``, ``-m``, ``--deselect`` and an explicit node-id list, which is the whole
    point: the summary needs to tell "the runs were never asked for" apart from
    "the runs were asked for and did not happen". Those are different facts and
    only the second one is a finding.
    """
    return sum(
        1
        for item in request.session.items
        if item.originalname == "test_no_original_ever_leaves_the_process"  # type: ignore[attr-defined]
    )


@pytest.mark.asyncio(loop_scope="module")
async def test_leakage_summary(
    harness: Harness, ledger: Ledger, request: pytest.FixtureRequest
) -> None:
    """The line quoted in the README, backed by the tally the runs actually produced.

    **This assertion is the one that stops the README quoting a number nothing
    produced**, so it is deliberately not satisfiable by a harness that ran nothing.
    It is also the assertion most likely to be met by someone running a subset, and
    those two needs pull in opposite directions unless the test can see what was
    selected.

    So it distinguishes three cases explicitly rather than collapsing them into one
    ``ledger.runs == RUNS``:

    * **none selected** -- somebody ran ``-k`` or a node id that filtered the runs
      out entirely. There is no measurement to summarise and no finding to report;
      skip, and say so. Previously this raised ``expected 100 completed runs,
      recorded 0``, which reads exactly like the harness silently measuring nothing
      -- the most alarming failure this file can produce -- for what is in fact an
      ordinary filtered invocation.
    * **partially selected** -- ``n`` of 100 were collected. This is the dangerous
      middle, because a summary computed over a subset would still *look* like the
      headline result. The tally must match the selection exactly or this fails.
    * **fully selected** -- the ``pytest -m leakage`` case the README quotes. Full
      strength: every one of the 100 runs must have recorded, and the count is
      checked against ``RUNS`` rather than against the selection, so deselecting a
      run cannot lower the bar it is measured against.

    The check is therefore strictly stronger than the one it replaces: it now also
    catches a *partial* selection reporting a summary, which the old form did not.
    """
    selected = _selected_run_count(request)
    if selected == 0:
        pytest.skip(
            "the 100 leakage runs were filtered out of this invocation, so there is "
            "no tally to summarise. Run `pytest -m leakage` for the README number."
        )

    assert ledger.runs == selected, (
        f"{selected} leakage run(s) were selected but only {ledger.runs} recorded a "
        "tally -- a run completed without reaching ledger.record(), which means the "
        "summary is being computed over fewer runs than actually executed"
    )
    assert selected == RUNS, (
        f"only {selected} of {RUNS} leakage runs were selected, so this tally is a "
        "subset and must not be quoted as the headline result"
    )
    assert ledger.runs == RUNS, f"expected {RUNS} completed runs, recorded {ledger.runs}"
    assert ledger.leaks == 0, f"{ledger.leaks} leak(s) found across {ledger.runs} runs"
    assert await harness.audit.verify_chain() is True, "audit hash chain broken"
    print("\n" + ledger.summary())
