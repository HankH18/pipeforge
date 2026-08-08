"""Obfuscation strategies + engine (build doc section 10.3).

These tests own the graded half of the pipeline, so they assert *properties*
rather than snapshots: the token grammar, format preservation, interval survival
under the date shift, name-component linking, the collision guard, dedupe,
tier dispatch, strategy pluggability, and the two engine-level actions that must
behave identically in both modes.

Detections are constructed directly. The live detector is a separate component
with its own suite; building spans here keeps these tests deterministic, fast,
and independent of spaCy model availability.
"""

from __future__ import annotations

import json
import logging
import random
import re
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import pairwise
from typing import ClassVar

import pytest
from pydantic import ValidationError

from secure_context_pipeline import daterules
from secure_context_pipeline.api.schemas import MAX_PROMPT_CHARS, PipelineRunRequest
from secure_context_pipeline.audit.logger import OBFUSCATE, REDACT, STRIP, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import derive_token_id, normalize
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection import detector as detector_module
from secure_context_pipeline.detection.registry import GAZETTEER_DIR, EntityRegistry, EntitySpec
from secure_context_pipeline.errors import ConfigError, PipelineError, VaultMissError
from secure_context_pipeline.models import (
    Detection,
    EntityAction,
    EntityCategory,
    TokenRecord,
)
from secure_context_pipeline.obfuscation import engine as engine_module
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.obfuscation.strategies.base import (
    STRATEGIES,
    ObfuscationStrategy,
    StrategyContext,
    available_strategies,
    build_strategy,
    register_strategy,
)
from secure_context_pipeline.obfuscation.strategies.pseudonymization import (
    MAX_FAKE_ATTEMPTS,
    PseudonymizationStrategy,
    _Candidate,
    _gate_fold,
    _gate_needles,
    _structural_fake,
    parse_source_date,
)
from secure_context_pipeline.pipeline import egress_gate
from secure_context_pipeline.pipeline.orchestrator import (
    PipelineOrchestrator,
    _assert_surrogates_are_distinct,
)
from secure_context_pipeline.surrogates import (
    STRICT_TOKEN_RE,
    extract_token_ids,
    format_redaction,
)
from secure_context_pipeline.textrules import occurs_as_a_unit
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

BOTH_MODES = ("tokenization", "pseudonymization")

CATEGORY_OF: dict[str, EntityCategory] = {
    "NAME": EntityCategory.PII,
    "SSN": EntityCategory.PII,
    "EMAIL": EntityCategory.PII,
    "PHONE": EntityCategory.PII,
    "ADDRESS": EntityCategory.PII,
    "DOB": EntityCategory.PII,
    "DATE": EntityCategory.PHI,
    "MRN": EntityCategory.PHI,
    "INSURANCE_ID": EntityCategory.PHI,
    "DIAGNOSIS": EntityCategory.PHI,
    "MEDICATION": EntityCategory.PHI,
    "LAB_RESULT": EntityCategory.PHI,
    "ACCOUNT_NUMBER": EntityCategory.FIN,
    "TAX_ID": EntityCategory.FIN,
    "AMOUNT": EntityCategory.FIN,
    "CLIENT_IDENTITY": EntityCategory.LEGAL,
    "CASE_ID": EntityCategory.LEGAL,
    "SETTLEMENT_TERM": EntityCategory.LEGAL,
    "PRIVILEGED_MARKER": EntityCategory.LEGAL,
    "CASE_STRATEGY": EntityCategory.LEGAL,
}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Env:
    """Everything a test needs: real vault, real session registry, real audit log."""

    settings: Settings
    registry: EntityRegistry
    sessions: SessionRegistry
    vault: SessionVault
    audit: AuditLogger
    engine: ObfuscationEngine
    session_id: str
    session_key: bytes

    def context(self) -> StrategyContext:
        return StrategyContext(
            registry=self.registry, session_key=self.session_key, settings=self.settings
        )


@pytest.fixture
async def env(settings: Settings, registry: EntityRegistry) -> AsyncIterator[Env]:
    sessions = SessionRegistry(settings)
    vault = await SessionVault.open(settings.data_dir / "vault.db", sessions)
    audit = await AuditLogger.open(settings.data_dir / "audit.db")
    session_id, _expires = await sessions.create("test-user")
    session_key = await sessions.key(session_id)
    engine = ObfuscationEngine(
        registry=registry,
        vault=vault,
        session_registry=sessions,
        settings=settings,
        audit=audit,
    )
    try:
        yield Env(
            settings=settings,
            registry=registry,
            sessions=sessions,
            vault=vault,
            audit=audit,
            engine=engine,
            session_id=session_id,
            session_key=session_key,
        )
    finally:
        await vault.close()
        await audit.close()


@pytest.fixture
def strategy_registry_guard() -> Iterator[None]:
    """Restore :data:`STRATEGIES` so a test-registered strategy cannot leak."""
    snapshot = dict(STRATEGIES)
    yield
    STRATEGIES.clear()
    STRATEGIES.update(snapshot)


def span(
    text: str,
    value: str,
    entity_type: str,
    *,
    score: float = 0.9,
    occurrence: int = 0,
) -> Detection:
    """A ``Detection`` for the n-th occurrence of ``value`` in ``text``."""
    start = -1
    for _ in range(occurrence + 1):
        start = text.index(value, start + 1)
    return Detection(
        entity_type=entity_type,
        category=CATEGORY_OF[entity_type],
        start=start,
        end=start + len(value),
        text=value,
        score=score,
    )


def every_span(text: str, value: str, entity_type: str, *, score: float = 0.9) -> list[Detection]:
    """A ``Detection`` for every occurrence of ``value``."""
    return [
        Detection(
            entity_type=entity_type,
            category=CATEGORY_OF[entity_type],
            start=match.start(),
            end=match.end(),
            text=value,
            score=score,
        )
        for match in re.finditer(re.escape(value), text)
    ]


def surrogates_by_type(tokens: list[TokenRecord]) -> dict[str, str]:
    return {record.entity_type: record.surrogate for record in tokens}


def gazetteer_hint(filename: str, term: str) -> str:
    """Read the class column straight out of the shipped TSV."""
    for line in (GAZETTEER_DIR / filename).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "\t" not in line:
            continue
        entry, _, hint = line.partition("\t")
        if entry.strip().casefold() == term.casefold():
            return hint.strip()
    raise AssertionError(f"{term!r} missing from {filename}")


def with_spec(registry: EntityRegistry, entity_type: str, **updates: object) -> EntityRegistry:
    """A copy of the registry with one entity's spec overridden. Config-only change."""
    spec: EntitySpec = registry.spec(entity_type)
    entities = dict(registry.entities)
    entities[entity_type] = spec.model_copy(update=updates)
    return registry.model_copy(update={"entities": entities})


# ---------------------------------------------------------------------------
# 1. Tokenization format
# ---------------------------------------------------------------------------


async def test_tokenization_format_round_trips_through_the_strict_grammar(env: Env) -> None:
    text = "Patient John Smith was admitted."
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "John Smith", "NAME")], strategy="tokenization"
    )

    assert len(result.tokens) == 1
    record = result.tokens[0]
    match = STRICT_TOKEN_RE.fullmatch(record.surrogate)
    assert match is not None, record.surrogate
    assert match.group(1) == "PII"
    assert match.group(2) == "NAME"
    assert match.group(3) == record.token_id
    assert re.fullmatch(r"[0-9a-f]{8}", record.token_id)
    assert match.group(4) is None, "hints are off by default in tokenization mode"
    assert record.surrogate == f"[PII_NAME_{record.token_id}]"
    assert result.obfuscated_text == f"Patient {record.surrogate} was admitted."
    assert "John Smith" not in result.obfuscated_text
    # The vault round-trips it: the token is the only handle back to the value.
    assert await env.vault.get_by_token(env.session_id, record.token_id) == "John Smith"
    assert await env.vault.get_by_surrogate(env.session_id, record.surrogate) == "John Smith"


async def test_tokenization_ignores_tiers_entirely(env: Env) -> None:
    """Tier is a statement about the value; a token carries nothing value-derived."""
    text = "Dx diabetes mellitus; A1C 7.2 today."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "diabetes mellitus", "DIAGNOSIS"), span(text, "A1C 7.2", "LAB_RESULT")],
        strategy="tokenization",
    )
    # Named, not iterated: ``for record in result.tokens`` passes on an empty list,
    # so a bug that dropped every Tier-3 span would have satisfied the old loop.
    fakes = surrogates_by_type(result.tokens)
    assert set(fakes) == {"DIAGNOSIS", "LAB_RESULT"}
    for entity_type, surrogate in fakes.items():
        assert STRICT_TOKEN_RE.fullmatch(surrogate), (entity_type, surrogate)
        assert "|" not in surrogate, "the class hint is a pseudonymization feature"
    assert result.obfuscated_text == f"Dx {fakes['DIAGNOSIS']}; {fakes['LAB_RESULT']} today."
    assert "diabetes mellitus" not in result.obfuscated_text
    assert "7.2" not in result.obfuscated_text


# ---------------------------------------------------------------------------
# 2. Pseudonym format preservation
# ---------------------------------------------------------------------------


async def test_pseudonym_preserves_identifier_formats(env: Env) -> None:
    text = "SSN 123-45-6789, MRN: 4471902, EIN 12-3456789, member BCBS123456789."
    detections = [
        span(text, "123-45-6789", "SSN"),
        span(text, "MRN: 4471902", "MRN"),
        span(text, "12-3456789", "TAX_ID"),
        span(text, "BCBS123456789", "INSURANCE_ID"),
    ]
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="pseudonymization"
    )
    fakes = surrogates_by_type(result.tokens)

    assert re.fullmatch(r"\d{3}-\d{2}-\d{4}", fakes["SSN"])
    assert fakes["SSN"] != "123-45-6789"

    mrn = fakes["MRN"]
    assert mrn.startswith("MRN: "), "a detached label is boilerplate, not identity"
    assert sum(char.isdigit() for char in mrn) == 7
    assert mrn != "MRN: 4471902"

    assert re.fullmatch(r"\d{2}-\d{7}", fakes["TAX_ID"])
    assert fakes["TAX_ID"] != "12-3456789"

    # Letters glued to digits ARE part of the identifier, so they are replaced --
    # but the shape (4 uppercase + 9 digits) survives.
    assert re.fullmatch(r"[A-Z]{4}\d{9}", fakes["INSURANCE_ID"])
    assert fakes["INSURANCE_ID"] != "BCBS123456789"

    for original in ("123-45-6789", "4471902", "12-3456789", "BCBS123456789"):
        assert original not in result.obfuscated_text


async def test_pseudonym_format_preservation_needs_no_per_entity_table(env: Env) -> None:
    """A docket number keeps its punctuation and its detached label words."""
    text = "Filed under Case No. 1:23-cv-45678 last term."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "Case No. 1:23-cv-45678", "CASE_ID")],
        strategy="pseudonymization",
    )
    assert len(result.tokens) == 1
    fake = result.tokens[0].surrogate
    assert re.fullmatch(r"Case No\. \d:\d{2}-cv-\d{5}", fake)
    assert fake != "Case No. 1:23-cv-45678"
    # The regex allows a fake that changed only one digit, so require that every
    # identifying digit run actually moved while the scaffolding stayed put.
    assert fake.startswith("Case No. "), "a detached label word is not identity"
    assert re.findall(r"\d+", fake) != re.findall(r"\d+", "Case No. 1:23-cv-45678")
    assert "1:23-cv-45678" not in result.obfuscated_text
    assert result.obfuscated_text == f"Filed under {fake} last term."


class _LowestChoice(random.Random):
    """A ``Random`` whose ``choice`` is not random: always the pool's first member.

    ``_structural_fake`` takes its randomness as an argument, so handing it this
    removes the ambiguity that a real draw leaves behind. Every position the mask
    *replaces* becomes ``'0'`` (digits), ``'A'`` (upper) or ``'a'`` (lower), and
    every position it *copies* keeps the source character -- so the output is a
    total statement about which is which, with no coincidences to argue about.
    """

    def choice(self, seq):  # type: ignore[no-untyped-def]
        return seq[0]


def test_the_structural_mask_replaces_every_identifying_character() -> None:
    """Which characters the mask rewrites, pinned exactly rather than by shape.

    The two format tests above assert a *shape* plus "the fake is not the source",
    and a mask that rewrote only the **first** digit run satisfies both:
    ``123-45-6789`` becomes ``987-45-6789``, which still matches
    ``\\d{3}-\\d{2}-\\d{4}``, is still unequal to the source, and still carries
    eight of the eleven real characters into the payload. The egress gate cannot
    object either, because the whole original never appears -- the same shape as
    every leak this file has had to grow a test for. Measured: both that mutation
    and "leave the last character alone" pass the entire suite without this test.

    A per-character check under a real draw would be flaky (a redrawn digit
    coincides one time in ten), which is why the randomness is stubbed out
    instead of sampled.
    """
    fixed = _LowestChoice()

    # Every digit is identifying, wherever it sits.
    assert _structural_fake("123-45-6789", fixed).text == "000-00-0000"
    assert _structural_fake("12-3456789", fixed).text == "00-0000000"
    assert _structural_fake("(415) 555-0123", fixed).text == "(000) 000-0000"

    # A detached label word is scaffolding and is copied verbatim; the digits are
    # not. Both halves matter -- rejecting the label would burn the retry budget
    # on every labelled entity, keeping the digits would leak the identifier.
    assert _structural_fake("MRN: 4471902", fixed).text == "MRN: 0000000"
    assert _structural_fake("Case No. 1:23-cv-45678", fixed).text == "Case No. 0:00-cv-00000"

    # Letters GLUED to a digit are part of the identifier, and case is preserved
    # per character so the shape survives.
    assert _structural_fake("BCBS123456789", fixed).text == "AAAA000000000"
    assert _structural_fake("ab12Cd", fixed).text == "aa00Aa"

    # ...and a run with no digit anywhere near it is left completely alone.
    assert _structural_fake("Attorney Work Product", fixed).text == "Attorney Work Product"

    # The invented set names exactly the runs that were rewritten -- this is what
    # the collision guard reads, so it is pinned here rather than inferred.
    assert _structural_fake("MRN: 4471902", fixed).invented == {"0000000"}
    assert _structural_fake("Attorney Work Product", fixed).invented == frozenset()


async def test_pseudonym_email_is_never_a_deliverable_address(env: Env) -> None:
    text = "Reach him at john.smith@example.com any time."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "john.smith@example.com", "EMAIL")],
        strategy="pseudonymization",
    )
    assert len(result.tokens) == 1
    fake = result.tokens[0].surrogate
    assert "@" in fake
    assert fake.split("@")[1].startswith("example."), "RFC 2606 reserved domains only"
    assert fake != "john.smith@example.com"
    assert not STRICT_TOKEN_RE.fullmatch(fake), "EMAIL is Tier 1: a fake, not a token"
    # The fake is what actually reached the payload, and no part of the real
    # address survived -- the local half is as identifying as the whole.
    assert result.obfuscated_text == f"Reach him at {fake} any time."
    assert "john.smith" not in result.obfuscated_text
    assert await env.vault.get_by_surrogate(env.session_id, fake) == "john.smith@example.com"


# ---------------------------------------------------------------------------
# 3. Date shift
# ---------------------------------------------------------------------------


async def test_date_shift_preserves_the_interval_between_two_dates(env: Env) -> None:
    text = "Seen on 03/14/2024 and again on 04/18/2024 for follow-up."
    detections = [span(text, "03/14/2024", "DATE"), span(text, "04/18/2024", "DATE")]
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="pseudonymization", doc_category="medical"
    )

    shifted = [record.surrogate for record in result.tokens]
    assert all(re.fullmatch(r"\d{2}/\d{2}/\d{4}", value) for value in shifted), shifted
    first, second = (datetime.strptime(value, "%m/%d/%Y").date() for value in shifted)
    original_first = datetime.strptime("03/14/2024", "%m/%d/%Y").date()
    original_second = datetime.strptime("04/18/2024", "%m/%d/%Y").date()

    assert (second - first) == (original_second - original_first), "interval survives"
    assert first != original_first, "the absolute date must not survive"
    assert abs((first - original_first).days) >= 30, "shift floor from build doc section 8"
    assert (first - original_first) == (second - original_second), "one shift per session"

    # The delta is the session's one derived constant, not a per-date fudge that
    # merely happens to be self-consistent across two dates.
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    assert (first - original_first).days == strategy.shift_days

    assert result.obfuscated_text == (
        f"Seen on {shifted[0]} and again on {shifted[1]} for follow-up."
    )
    for original in ("03/14/2024", "04/18/2024"):
        assert original not in result.obfuscated_text


async def test_date_shift_re_renders_in_the_source_format(env: Env) -> None:
    text = "Admitted 2024-05-02, discharged May 9, 2024, follow-up 9 June 2024."
    detections = [
        span(text, "2024-05-02", "DATE"),
        span(text, "May 9, 2024", "DATE"),
        span(text, "9 June 2024", "DATE"),
    ]
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="pseudonymization", doc_category="medical"
    )
    rendered = [record.surrogate for record in result.tokens]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", rendered[0]), rendered[0]
    assert re.fullmatch(r"[A-Z][a-z]+ \d{1,2}, \d{4}", rendered[1]), rendered[1]
    assert re.fullmatch(r"\d{1,2} [A-Z][a-z]+ \d{4}", rendered[2]), rendered[2]

    # Shape alone is not the property. A renderer that emits the right *format*
    # around the wrong date -- an unshifted one, a doubly-shifted one, a
    # month/day transposition -- satisfies every regex above. So each surrogate is
    # compared against the date it must be, computed here from the session shift
    # and formatted with ``strftime`` rather than with the module's own tables.
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    shift = timedelta(days=strategy.shift_days)
    by_original = {
        await env.vault.get_by_surrogate(env.session_id, record.surrogate): record.surrogate
        for record in result.tokens
    }
    assert set(by_original) == {"2024-05-02", "May 9, 2024", "9 June 2024"}

    iso = datetime(2024, 5, 2).date() + shift
    assert by_original["2024-05-02"] == iso.strftime("%Y-%m-%d")
    mdy = datetime(2024, 5, 9).date() + shift
    assert by_original["May 9, 2024"] == f"{mdy.strftime('%B')} {mdy.day}, {mdy.year}"
    dmy = datetime(2024, 6, 9).date() + shift
    assert by_original["9 June 2024"] == f"{dmy.day} {dmy.strftime('%B')} {dmy.year}"

    assert result.obfuscated_text == (
        f"Admitted {by_original['2024-05-02']}, "
        f"discharged {by_original['May 9, 2024']}, "
        f"follow-up {by_original['9 June 2024']}."
    )


async def test_a_composite_date_span_keeps_its_intervals_instead_of_degrading(
    env: Env, settings: Settings, registry: EntityRegistry
) -> None:
    """The utility half of the composite-span split: intervals instead of a token.

    ``Prior ambulatory visits: {a}, {b}, and {c}.`` is ordinary clinical prose --
    ``fixtures/generator.py`` writes it into every generated progress note -- and
    spaCy returns the first two dates as a **single** ``DATE`` span (pinned in
    ``tests/test_detection.py``). That composite does not parse, asserted below, so
    Tier 2 had nothing to shift and degraded the whole span to a plain token by the
    route ``test_unparseable_date_falls_back_to_a_plain_token`` pins. Two of the
    three visit dates therefore lost every temporal relation they carried -- the one
    property Tier 2 exists to preserve -- while the third, detected separately, kept
    its shift, so one line of the document went to the provider carrying two
    incomparable time systems.

    Split, all three are Tier-2 surrogates under one session shift and every interval
    between them survives.

    The composite ``Detection`` is built by hand, as everything in this file is, and
    put through the detector's real splitter. That keeps the test off spaCy while
    still exercising the production rule; whether spaCy really produces this span is
    a *detection* claim and is asserted where detection is tested.
    """
    text = "    Prior ambulatory visits: 03/11/2024, 09/17/2024, and 10/01/2024.\n"
    composite = "03/11/2024, 09/17/2024"
    sources = ["03/11/2024", "09/17/2024", "10/01/2024"]

    assert parse_source_date(composite) is None, (
        "premise: the composite is unparseable, so an unsplit span degrades to a "
        "plain token and this test is measuring the split rather than luck"
    )

    detector = detector_module.Detector(registry, settings)
    dates = [
        *detector._split_composite_dates(text, span(text, composite, "DATE")),
        span(text, "10/01/2024", "DATE"),
    ]
    for detection in dates:
        assert text[detection.start : detection.end] == detection.text

    result = await env.engine.obfuscate(
        env.session_id, text, dates, strategy="pseudonymization", doc_category="medical"
    )

    # The utility claim, asserted before anything else so that it is what goes red:
    # an unsplit composite is unparseable, so Tier 2 has nothing to shift and emits a
    # plain token, and every interval the span carried is gone.
    assert not [r for r in result.tokens if STRICT_TOKEN_RE.fullmatch(r.surrogate)], (
        "a date span degraded to a plain token -- the interval property Tier 2 exists "
        "for is lost for every date inside it"
    )

    by_original = {
        await env.vault.get_by_surrogate(env.session_id, record.surrogate): record.surrogate
        for record in result.tokens
    }
    assert set(by_original) == set(sources)

    for original, surrogate in by_original.items():
        assert re.fullmatch(r"\d{2}/\d{2}/\d{4}", surrogate), (original, surrogate)

    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    shift = timedelta(days=strategy.shift_days)
    for original in sources:
        expected = datetime.strptime(original, "%m/%d/%Y").date() + shift
        assert by_original[original] == expected.strftime("%m/%d/%Y"), original

    # The property, stated as intervals rather than as three equalities: every gap
    # between two visit dates is the same gap after obfuscation.
    def gap(a: str, b: str) -> timedelta:
        return datetime.strptime(b, "%m/%d/%Y") - datetime.strptime(a, "%m/%d/%Y")

    for first, second in pairwise(sources):
        assert gap(by_original[first], by_original[second]) == gap(first, second)

    for original in sources:
        assert original not in result.obfuscated_text


async def test_unparseable_date_falls_back_to_a_plain_token(env: Env) -> None:
    text = "Follow-up sometime next spring, patient says."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "sometime next spring", "DOB")],
        strategy="pseudonymization",
    )
    assert len(result.tokens) == 1
    record = result.tokens[0]
    surrogate = record.surrogate
    assert STRICT_TOKEN_RE.fullmatch(surrogate), surrogate
    # Identity, not a prefix: a guessed date rendered in *some* format, or a token
    # carrying a hint, both start with "[PII_DOB_" too.
    assert surrogate == f"[PII_DOB_{record.token_id}]"
    assert result.obfuscated_text == f"Follow-up {surrogate}, patient says."
    assert "sometime next spring" not in result.obfuscated_text
    assert await env.vault.get_by_surrogate(env.session_id, surrogate) == "sometime next spring", (
        "unparseable must still mean restorable"
    )


# ---------------------------------------------------------------------------
# 4. Name component linking
# ---------------------------------------------------------------------------


async def test_name_component_linking_gives_a_consistent_fake_surname(env: Env) -> None:
    # Surname-only mention FIRST: the linking rule is stateless, so detection
    # order cannot change the mapping.
    text = "Smith arrived early. Later, John Smith signed the consent form."
    detections = [
        span(text, "Smith", "NAME", occurrence=0),
        span(text, "John Smith", "NAME"),
    ]
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="pseudonymization"
    )
    fakes = {record.token_id: record.surrogate for record in result.tokens}
    assert len(fakes) == 2, "'Smith' and 'John Smith' are distinct values, so two rows"

    # Sort out which is which by identity, not by shape: a plain-token fallback has
    # no space in it either, so "the value without a space" would silently pick up
    # a degraded surrogate and the linking assertion below would be comparing a
    # token to a name.
    by_original = {
        await env.vault.get_by_surrogate(env.session_id, surrogate): surrogate
        for surrogate in fakes.values()
    }
    assert set(by_original) == {"Smith", "John Smith"}
    standalone = by_original["Smith"]
    full = by_original["John Smith"]
    for value in (standalone, full):
        assert not STRICT_TOKEN_RE.fullmatch(value), (
            f"{value!r} degraded to a token; the linking rule was never exercised"
        )
    assert len(full.split()) == 2 and " " not in standalone

    assert full.split()[-1] == standalone, (full, standalone)
    assert full.split()[0] != standalone
    # Word-bounded, not substring -- and the difference is a real 2.7% flake, not
    # pedantry. These read `assert "John" not in result.obfuscated_text`, which asks
    # whether the four characters occur ANYWHERE. Under pseudonymization the surrogate
    # is a generated human name, and `conftest` mints a fresh random `master_key` per
    # test, so Faker eventually draws a surname that contains them: measured at 4
    # failures in 150 runs of this test alone, on `Johnson`, `Johnston` and `Johns`.
    #
    # Every one of those is a FAKE the engine invented. Reading them as a leak of the
    # original inverts what the test is for -- it fails precisely when obfuscation
    # worked and the replacement happened to be spelled inconveniently. The contract
    # is that the ORIGINAL does not survive as a value, and a value is a word.
    #
    # A plain `\b` rather than `textrules.word_bounded_pattern`: this is a test of the
    # engine's output, and borrowing the product's own boundary rule to check it would
    # make a shared bug invisible to both.
    for original in ("Smith", "John"):
        assert not re.search(rf"\b{re.escape(original)}\b", result.obfuscated_text), (
            f"the original {original!r} survived as a word: {result.obfuscated_text!r}"
        )


#: A session key where Faker's ``NAME:first:john`` draw on step 0 is literally
#: "John" -- a real word -- while ``NAME:last:smith`` on step 0 ("Briggs") is
#: clean. So "John Smith" must advance its *given* name while the surname stays
#: put, and the standalone "Smith" never retries at all. Under a whole-candidate
#: counter the two mentions settled on different surnames ("Briggs" vs "Edwards").
COMPONENT_RETRY_KEY = (83).to_bytes(32, "big")


async def test_regenerating_one_component_does_not_desync_the_others(env: Env) -> None:
    """Pinned counterpart to the sweep below: the exact asymmetry that broke linking.

    The collision is on the *given* name, so the "John Smith" mention needs a
    retry that the standalone "Smith" mention does not. A retry counter shared by
    the whole candidate re-seeded the surname too, and the same person came back
    as two different surnames. Per-component search leaves the clean component
    exactly where it was.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=COMPONENT_RETRY_KEY, settings=env.settings
        ),
    )
    strategy.reserved_originals = frozenset({normalize("Smith"), normalize("John Smith")})
    standalone_span = Detection(
        entity_type="NAME",
        category=EntityCategory.PII,
        start=0,
        end=5,
        text="Smith",
        score=0.9,
    )
    full_span = Detection(
        entity_type="NAME",
        category=EntityCategory.PII,
        start=0,
        end=10,
        text="John Smith",
        score=0.9,
    )

    standalone = await strategy.make_surrogate(
        standalone_span, "aaaaaaaa", env.vault, session_id=env.session_id
    )
    full = await strategy.make_surrogate(
        full_span, "bbbbbbbb", env.vault, session_id=env.session_id
    )

    assert " " not in standalone and len(full.split()) == 2, (standalone, full)
    assert full.split()[-1] == standalone, (
        f"the surname desynced: {standalone!r} standalone vs {full!r} in full"
    )
    # The retry happened for the right reason, and it did not ship the real word.
    assert full.split()[0] != "John"
    # Word-bounded for the same reason as the sibling assertion in
    # test_name_and_client_identity_pseudonymize_to_the_same_person: `full` is a
    # GENERATED two-part fake, so a drawn surname of "Smithson" or "Smithers" would
    # fail a substring check while being a perfectly correct obfuscation.
    assert not re.search(r"\bSmith\b", full), f"the original surname survived: {full!r}"


async def test_name_component_linking_survives_a_collision_regeneration(env: Env) -> None:
    """A retry must not re-seed the components that were already fine.

    "Smith" alone and the "Smith" inside "John Smith" are separate vault entries
    generated at separate moments. When the collision guard advanced a
    whole-candidate counter, one of them could settle at attempt 0 and the other
    at attempt 1, producing two different fake surnames for the same person --
    the spec-mandated linking rule (build doc section 10.3), silently broken on
    ~1.2% of session keys. Collisions are now resolved per component, which is a
    pure function of the component, so every mention converges on the same fake.

    Swept across session keys because the failure was key-dependent: one key
    proves nothing about a 1-in-80 event.
    """
    text = "Smith arrived early. Later, John Smith signed the consent form."
    detections = [
        span(text, "Smith", "NAME", occurrence=0),
        span(text, "John Smith", "NAME"),
    ]
    broken: list[tuple[str, str]] = []
    degraded = 0
    for _ in range(80):
        # A fresh session is a fresh random session key, which is the variable the
        # failure depended on.
        session_id, _expires = await env.sessions.create("test-user")
        result = await env.engine.obfuscate(
            session_id, text, detections, strategy="pseudonymization"
        )
        values = [record.surrogate for record in result.tokens]
        assert len(values) == 2, values
        standalone = next((v for v in values if " " not in v), None)
        full = next((v for v in values if " " in v), None)
        if standalone is None or full is None:
            degraded += 1  # guard exhausted into a plain token; leaks nothing
            continue
        if full.split()[-1] != standalone:
            broken.append((standalone, full))
    assert broken == [], f"{len(broken)}/80 session keys broke name-component linking: {broken[:4]}"
    # The `continue` above is the hole this sweep could otherwise fall through: a
    # change that degraded EVERY name to a plain token would skip every iteration
    # and report zero breakages. Measured 0/500 on random keys, so a 5% ceiling is
    # far above the real rate and far below "the guard stopped faking".
    assert degraded <= 4, f"{degraded}/80 runs never produced a fake name to compare"


async def test_name_passthrough_keeps_titles_and_replaces_only_the_name(env: Env) -> None:
    text = "Dr. Maria Garcia reviewed the chart."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "Dr. Maria Garcia", "NAME")],
        strategy="pseudonymization",
    )
    assert len(result.tokens) == 1
    fake = result.tokens[0].surrogate
    assert fake.startswith("Dr. ")
    assert "Maria" not in fake
    assert "Garcia" not in fake
    # The title is passed through, so the *rest* must be a two-part fake -- not the
    # title alone, and not the title with the real name still attached.
    assert len(fake.removeprefix("Dr. ").split()) == 2, fake
    assert result.obfuscated_text == f"{fake} reviewed the chart."
    assert "Maria Garcia" not in result.obfuscated_text


async def test_a_fake_carries_the_source_shape_it_is_standing_in_for(env: Env) -> None:
    """Casing, initials and street-vs-city: shape rules with no other test.

    Each of these is a one-line branch that the whole file survives losing --
    measured, by deleting each in turn: ``_match_case`` (an ALL-CAPS header
    becomes a mixed-case name), the trailing-dot arm (``"J. Smith"`` comes back
    as ``"S Barnes"``), and the digit tell in the place generator (a street line
    collapses to a bare city). None of them is a leak, which is exactly why they
    went unwatched -- but a surrogate that does not sit in the source's shape is
    a surrogate the model can spot, and spotting it is what invites the model to
    reason about the mask instead of the content.

    Swept across keys rather than pinned, because none of these is a coincidence
    of one draw: they are properties of the mapping.
    """
    for index in range(12):
        strategy = build_strategy(
            "pseudonymization",
            StrategyContext(
                registry=env.registry,
                session_key=(index + 1).to_bytes(32, "big"),
                settings=env.settings,
            ),
        )
        assert isinstance(strategy, PseudonymizationStrategy)
        mixed = strategy._generate("NAME", "John Smith", 0).text
        upper = strategy._generate("NAME", "JOHN SMITH", 0).text
        lower = strategy._generate("NAME", "john smith", 0).text
        initial = strategy._generate("NAME", "J. Smith", 0).text

        # Case is carried, and it is carried onto the SAME fake -- so a header in
        # caps and prose in title case stay one person, not two.
        assert upper == mixed.upper(), (upper, mixed)
        assert lower == mixed.lower(), (lower, mixed)

        # An initial stays an initial: one letter and its dot, not a whole given
        # name and not a bare letter. Its surname still links to the full form.
        given, surname = initial.split()
        assert re.fullmatch(r"[A-Z]\.", given), initial
        assert surname == mixed.split()[-1], (initial, mixed)

        # ADDRESS rides Presidio's LOCATION recognizer, so the span is a street
        # line or a city and a digit is the only reliable tell.
        street = strategy._generate("ADDRESS", "742 Evergreen Terrace", 0).text
        city = strategy._generate("ADDRESS", "Larkspur Valley", 0).text
        assert any(char.isdigit() for char in street), street
        assert not any(char.isdigit() for char in city), city


async def test_name_and_client_identity_pseudonymize_to_the_same_person(env: Env) -> None:
    """One human, two registry types (legal docs remap PERSON), one pseudonym."""
    strategy = build_strategy("pseudonymization", env.context())
    as_name = Detection(
        entity_type="NAME",
        category=EntityCategory.PII,
        start=0,
        end=10,
        text="John Smith",
        score=0.9,
    )
    as_client = Detection(
        entity_type="CLIENT_IDENTITY",
        category=EntityCategory.LEGAL,
        start=0,
        end=10,
        text="John Smith",
        score=0.9,
    )
    first = await strategy.make_surrogate(as_name, "aaaaaaaa", env.vault, session_id=env.session_id)
    second = await strategy.make_surrogate(
        as_client, "bbbbbbbb", env.vault, session_id=env.session_id
    )
    assert first == second
    # Equality on its own is satisfiable by two identical *failures* -- and a
    # degenerate generator returning "" for both would pass it. Pin that the shared
    # answer is a real two-part fake carrying neither component of the real name.
    assert not STRICT_TOKEN_RE.fullmatch(first), "both degraded to a token"
    assert len(first.split()) == 2, first
    # Word-bounded, not substring -- the identical defect this file already fixed once
    # at test_name_component_linking_gives_a_consistent_fake_surname, and a sibling I
    # failed to sweep for at the time. `assert "John" not in first` asks whether four
    # characters occur ANYWHERE, and the pseudonym is a GENERATED name: measured at
    # 4 failures in 300 fresh master keys (1.3%), every one on Faker drawing the
    # surname "Johnson" -- 'Jason Johnson', 'Patrick Johnson', 'Thomas Johnson',
    # 'Susan Johnson'. Each of those is a correct answer the test called a leak, so it
    # failed precisely when obfuscation worked.
    #
    # The contract is that the ORIGINAL does not survive as a value, and a value is a
    # word. A plain \b rather than textrules.word_bounded_pattern: borrowing the
    # product's own boundary rule to check the product's output would make a shared
    # bug invisible to both.
    for original in ("John", "Smith"):
        assert not re.search(rf"\b{re.escape(original)}\b", first), (
            f"the original {original!r} survived as a word in the pseudonym: {first!r}"
        )


# ---------------------------------------------------------------------------
# 5. Collision guard
# ---------------------------------------------------------------------------


async def test_collision_guard_regenerates_a_fake_equal_to_a_vault_original(env: Env) -> None:
    strategy = build_strategy("pseudonymization", env.context())
    detection = Detection(
        entity_type="SSN",
        category=EntityCategory.PII,
        start=0,
        end=11,
        text="123-45-6789",
        score=0.9,
    )
    first = await strategy.make_surrogate(
        detection, "aaaaaaaa", env.vault, session_id=env.session_id
    )
    assert re.fullmatch(r"\d{3}-\d{2}-\d{4}", first)

    # Plant the generated fake as a REAL value held by this session. Regenerating
    # is now mandatory: otherwise the payload would carry a string the egress
    # gate is scanning for, and restore would be ambiguous.
    await env.vault.put(
        env.session_id,
        TokenRecord(
            session_id=env.session_id,
            token_id="deadbeef",
            entity_type="OTHER_ID",
            category=EntityCategory.PII,
            surrogate="[PII_OTHER_ID_deadbeef]",
            created_at=time.time(),
        ),
        first,
    )
    assert first in env.vault.originals_for_session(env.session_id)

    second = await strategy.make_surrogate(
        detection, "bbbbbbbb", env.vault, session_id=env.session_id
    )
    assert second != first
    assert re.fullmatch(r"\d{3}-\d{2}-\d{4}", second), "format survives the retry"
    assert normalize(second) not in {
        normalize(value) for value in env.vault.originals_for_session(env.session_id)
    }


#: A session key for which Faker's ``NAME:last:williams`` draw on attempt 0 is
#: literally "Williams" -- i.e. the fake surname equals the real surname it is
#: replacing. Found by search (attempt 1 draws "King"), pinned so the regression
#: is deterministic instead of a 1-in-53 coincidence.
SURNAME_ECHO_KEY = (17).to_bytes(32, "big")


async def test_a_fake_name_never_keeps_the_real_surname_it_replaces(env: Env) -> None:
    """The inherited-word exclusion must not reach the semantic generator.

    Format preservation legitimately copies a *label* from the source ("MRN:"),
    so words the generator inherited are excused from the collision guard. Faker
    inherits nothing: every name part it emits is drawn from the same pool real
    surnames come from, so excusing "inherited" words there let
    ``"Anna Williams"`` pseudonymize to ``"<fake> Williams"`` -- the real surname,
    verbatim, on the wire, invisible to the egress gate (which matches whole
    originals) and to the leakage harness for the same reason.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(registry=env.registry, session_key=SURNAME_ECHO_KEY, settings=env.settings),
    )
    detection = Detection(
        entity_type="NAME",
        category=EntityCategory.PII,
        start=0,
        end=13,
        text="Anna Williams",
        score=0.9,
    )
    strategy.reserved_originals = frozenset({normalize(detection.text)})

    surrogate = await strategy.make_surrogate(
        detection, "aaaaaaaa", env.vault, session_id=env.session_id
    )

    assert not STRICT_TOKEN_RE.fullmatch(surrogate), (
        "the guard must regenerate, not give up on faking"
    )
    assert len(surrogate.split()) == 2, surrogate
    assert surrogate.split()[-1].casefold() != "williams", surrogate
    assert "Williams" not in surrogate
    assert "Anna" not in surrogate


async def test_the_guard_forbids_its_own_value_with_no_help_from_the_caller(
    env: Env,
) -> None:
    """The one original the vault cannot know about is the one being replaced.

    A value reaches the vault only *after* its surrogate exists, so while
    ``_fake_identifier`` runs, "John Smith" is in neither
    ``originals_for_session`` nor -- unless a caller happened to seed it --
    ``reserved_originals``. Every other person test in this file seeds it, and
    the engine seeds it too, which is precisely why none of them can see this:
    dropping the guard's own-words term leaves the whole file green while
    ``"John Smith"`` pseudonymizes to ``"John Briggs"`` (measured on this key),
    shipping the real given name inside our own surrogate. The egress gate cannot
    object, because the *whole* original never appears in the payload.

    So the premise is asserted first -- nothing seeded, vault empty, and the
    unguarded generator really does reproduce the given name -- and only then the
    outcome. Without those, a pass here would be indistinguishable from a lucky
    draw.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=COMPONENT_RETRY_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")

    assert strategy.reserved_originals == frozenset(), "the caller must give no help"
    assert env.vault.originals_for_session(session_id) == frozenset()
    unguarded = strategy._generate("NAME", "John Smith", 0).text
    assert "john" in {word.casefold() for word in unguarded.split()}, (
        f"{unguarded!r} no longer reproduces the given name on this key, so a pass "
        f"below would prove nothing"
    )

    surrogate = await strategy.make_surrogate(
        Detection(
            entity_type="NAME",
            category=EntityCategory.PII,
            start=0,
            end=10,
            text="John Smith",
            score=0.9,
        ),
        "aaaaaaaa",
        env.vault,
        session_id=session_id,
    )

    assert not STRICT_TOKEN_RE.fullmatch(surrogate), (
        "the guard must regenerate, not give up on faking"
    )
    assert len(surrogate.split()) == 2, surrogate
    assert not set(normalize(surrogate).split()) & {"john", "smith"}, surrogate


#: A session key on which the fake city for ``"Lake Larkspur"`` is
#: ``"Lake Patricia"`` -- an invented word that is a word of the value being
#: replaced. Also the key on which two surnames collide, below.
OWN_WORD_PLACE_KEY = (1).to_bytes(32, "big")


async def test_the_guard_forbids_its_own_value_on_the_non_person_paths_too(
    env: Env,
) -> None:
    """Same property as above, but reaching it through the other of two terms.

    ``own_words`` is spent twice, and the two spends protect different generators.
    Persons get it through ``forbidden``, which the per-component search consumes
    -- that is what the test above exercises. ``ADDRESS``, ``EMAIL`` and the
    structural mask ignore ``forbidden`` entirely (Faker builds the whole string
    in one call, so there is no component to advance), which leaves
    ``_invents_a_real_word``'s ``also`` argument as the only thing standing
    between a real word of the source and the payload.

    Because the two terms are independent, so are their failures: dropping only
    the ``_invents_a_real_word`` one keeps every person test green -- measured --
    while ``"Lake Larkspur"`` pseudonymizes to ``"Lake Patricia"``.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=OWN_WORD_PLACE_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")
    source = "Lake Larkspur"

    assert strategy.reserved_originals == frozenset(), "the caller must give no help"
    assert env.vault.originals_for_session(session_id) == frozenset()
    unguarded = strategy._generate("ADDRESS", source, 0)
    shared = {word for word in unguarded.invented if len(word) >= 3} & set(
        normalize(source).split()
    )
    assert shared, (
        f"{unguarded.text!r} no longer shares a word with {source!r} on this key, "
        f"so a pass below would prove nothing"
    )
    # The premise is a WORD collision, not a whole-string one -- otherwise this
    # would be re-testing the layer two tests down.
    assert normalize(unguarded.text) != normalize(source)

    surrogate = await strategy.make_surrogate(
        Detection(
            entity_type="ADDRESS",
            category=EntityCategory.PII,
            start=0,
            end=len(source),
            text=source,
            score=0.9,
        ),
        "aaaaaaaa",
        env.vault,
        session_id=session_id,
    )

    assert not STRICT_TOKEN_RE.fullmatch(surrogate), "regenerate, do not give up"
    assert not set(normalize(surrogate).split()) & set(normalize(source).split()), (
        f"{surrogate!r} kept a word of the value it replaces"
    )


#: A session key on which Faker's ``NAME:last:wilson`` and ``NAME:last:thompson``
#: draws both land on "Cummings" -- two distinct originals, one fake surname.
SURROGATE_CLASH_KEY = (1).to_bytes(32, "big")


async def test_two_originals_are_never_issued_the_same_surrogate(env: Env) -> None:
    """A shared surrogate is a silent mis-restore, not a cosmetic clash.

    ``get_by_surrogate`` maps a string to exactly one record, so two values
    issued the same fake would restore both mentions to whichever the vault
    holds -- one person's data returned under the other's name, with no error
    anywhere. Nothing else in this file makes the generator collide, so deleting
    the ``_surrogate_taken`` check leaves every other test green; the collision is
    constructed here from a pinned key instead.

    A person fake is deliberately *not* regenerable -- ``_fake_person`` ignores
    the whole-candidate counter, which is what keeps name-component linking
    stable across mentions -- so the second value spends its budget and degrades
    to a plain token. That is the documented trade: a fluency loss, never a
    duplicate.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=SURROGATE_CLASH_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")

    # Premise: unguarded, these two really do generate the same string.
    clash = strategy._generate("NAME", "Wilson", 0).text
    assert strategy._generate("NAME", "Thompson", 0).text == clash, (
        "this key no longer collides, so the guard is never asked anything"
    )

    def person(text: str) -> Detection:
        return Detection(
            entity_type="NAME",
            category=EntityCategory.PII,
            start=0,
            end=len(text),
            text=text,
            score=0.9,
        )

    first = await strategy.make_surrogate(
        person("Wilson"), "d0d0d0d0", env.vault, session_id=session_id
    )
    assert first == clash
    await env.vault.put(
        session_id,
        TokenRecord(
            session_id=session_id,
            token_id="d0d0d0d0",
            entity_type="NAME",
            category=EntityCategory.PII,
            surrogate=first,
            created_at=time.time(),
        ),
        "Wilson",
    )

    second = await strategy.make_surrogate(
        person("Thompson"), "d1d1d1d1", env.vault, session_id=session_id
    )

    assert second != first, "two entities were issued one surrogate"
    # Identity, not inequality: "not equal" is also satisfied by a second fake
    # surname, and this path cannot produce one -- the fallback is the token.
    assert second == "[PII_NAME_d1d1d1d1]"
    # ...and the first mapping is still the one the vault will resolve.
    assert await env.vault.get_by_surrogate(session_id, first) == "Wilson"


#: Pinned so the fakes below are the same strings in every run and a failure
#: message is reproducible. Nothing here needs a *colliding* key: the nesting is
#: constructed from whatever the generator produces, so these tests never wait on
#: a Faker coincidence the way ``SURROGATE_CLASH_KEY`` does.
SURROGATE_NESTING_KEY = (7).to_bytes(32, "big")

#: Two values with nothing in common -- not a component of one another, no shared
#: word. Whatever nesting the surrogates below have is therefore manufactured by
#: the generator rather than inherited from the values.
NESTING_PERSON = "Thomas Duncan"
NESTING_PLACE = "Sherryside"


async def _issue(
    env: Env,
    session_id: str,
    *,
    token_id: str,
    surrogate: str,
    original: str,
) -> None:
    """Put one ``surrogate -> original`` row in the vault, as the engine would."""
    await env.vault.put(
        session_id,
        TokenRecord(
            session_id=session_id,
            token_id=token_id,
            entity_type="NAME",
            category=EntityCategory.PII,
            surrogate=surrogate,
            created_at=time.time(),
        ),
        original,
    )


def _person(text: str) -> Detection:
    return Detection(
        entity_type="NAME",
        category=EntityCategory.PII,
        start=0,
        end=len(text),
        text=text,
        score=0.9,
    )


async def test_a_fake_nested_inside_an_issued_surrogate_is_refused(env: Env) -> None:
    """A fake that hides inside a longer one is a value the user never gets back.

    ``_surrogate_taken`` asks whether this exact string is spoken for, and that is
    blind to the case where one surrogate merely *occurs as a unit inside*
    another. The restorer compiles one longest-first alternation, so at a shared
    offset the long fake always wins and the short one never matches inside it:
    the model writes ``Marion <fake>``, the user correctly reads
    ``Thomas Duncan``, and the value behind the short fake is **silently missing
    from the answer** -- ``restored_count`` up, ``surrogate_misses`` 0,
    ``_assert_no_surrogates`` unable to fire because no fake survived.

    It is reachable from ordinary input rather than from a contrived key. Faker
    draws surnames from a pool of roughly a thousand and every name component is
    an independent draw from it, so a dozen components in one document collide at
    percent scale -- measured at 3 failures in 200 pseudonymization runs of the
    leakage harness, every one of them this shape.

    The nesting is *constructed* here rather than waited for, so the test is
    deterministic: whatever ``Sherryside`` fakes to, an unrelated person is issued
    a surrogate ending in that same word.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=SURROGATE_NESTING_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")

    lone = strategy._generate("NAME", NESTING_PLACE, 0).text
    assert lone and " " not in lone, f"{lone!r} cannot nest inside anything"

    # The counterfactual, taken first and in its own session: with nothing issued,
    # this value really does fake to `lone`. Without it a guard that degraded
    # every lone name to a token would satisfy the assertion below.
    clean_session, _clean_expires = await env.sessions.create("test-user")
    assert (
        await strategy.make_surrogate(
            _person(NESTING_PLACE), "beef0000", env.vault, session_id=clean_session
        )
        == lone
    )

    outer = f"Marion {lone}"
    await _issue(env, session_id, token_id="beef0001", surrogate=outer, original=NESTING_PERSON)

    # Premises: no other layer can account for the result below.
    assert not occurs_as_a_unit(normalize(NESTING_PLACE), normalize(NESTING_PERSON)), (
        "the originals nest, so this is the linking case and must NOT be refused"
    )
    assert normalize(lone) not in set(normalize(NESTING_PERSON).split()) | {
        normalize(NESTING_PLACE)
    }, f"{lone!r} is a word of a real original, so the word guard would reject it anyway"
    assert not await strategy._surrogate_taken(env.vault, session_id, lone), (
        "the equality check already covers this, so the nesting guard is not on trial"
    )

    surrogate = await strategy.make_surrogate(
        _person(NESTING_PLACE), "beef0002", env.vault, session_id=session_id
    )

    # Identity, not inequality: a person fake ignores the whole-candidate counter
    # (see ``_fake_person``), so the only other thing this path can produce is the
    # token -- and "not equal to `lone`" would also be satisfied by a second fake
    # surname, which would mean the linking rule had been broken instead.
    assert surrogate == "[PII_NAME_beef0002]", (
        f"{surrogate!r} nests inside {outer!r}, which stands for a different value"
    )


async def test_a_fake_that_swallows_an_issued_surrogate_is_refused(env: Env) -> None:
    """The same hazard arriving in the other order, which one direction misses.

    Here the *short* surrogate is already issued and the new candidate contains
    it. Detection order decides which of the two a run sees, and a guard written
    for one direction is correct exactly half the time -- so both are checked and
    both are pinned.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=SURROGATE_NESTING_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")

    full = strategy._generate("NAME", NESTING_PERSON, 0).text
    assert len(full.split()) == 2, f"{full!r} is not a two-part fake"
    tail = full.split()[-1]

    clean_session, _clean_expires = await env.sessions.create("test-user")
    assert (
        await strategy.make_surrogate(
            _person(NESTING_PERSON), "beef0010", env.vault, session_id=clean_session
        )
        == full
    )

    await _issue(env, session_id, token_id="beef0011", surrogate=tail, original=NESTING_PLACE)

    assert not occurs_as_a_unit(normalize(NESTING_PLACE), normalize(NESTING_PERSON))
    assert set(normalize(full).split()).isdisjoint(
        {normalize(NESTING_PLACE), *normalize(NESTING_PERSON).split()}
    ), f"{full!r} shares a word with a real original; the word guard would fire first"
    assert not await strategy._surrogate_taken(env.vault, session_id, full)

    surrogate = await strategy.make_surrogate(
        _person(NESTING_PERSON), "beef0012", env.vault, session_id=session_id
    )
    assert surrogate == "[PII_NAME_beef0012]", (
        f"{surrogate!r} swallows {tail!r}, which stands for a different value"
    )


async def test_name_component_linking_may_still_nest_its_own_surrogates(env: Env) -> None:
    """The other half of the rule, and the one that stops it eating the feature.

    Component linking issues ``Duncan`` and ``Thomas Duncan`` as separate values
    whose fakes nest by construction, and that pair is *correct*: restoring the
    long fake yields ``Thomas Duncan``, which still carries ``Duncan`` as a unit,
    so the short surrogate's original is in the answer even though its surrogate
    never matched. A guard that rejected on the surrogate nesting alone would
    degrade every linked surname to a plain token and delete the feature the
    module's whole component design exists for -- so the test is the *originals*,
    not the surrogates.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=SURROGATE_NESTING_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")

    full = await strategy.make_surrogate(
        _person(NESTING_PERSON), "beef0020", env.vault, session_id=session_id
    )
    assert not STRICT_TOKEN_RE.fullmatch(full) and len(full.split()) == 2
    await _issue(env, session_id, token_id="beef0020", surrogate=full, original=NESTING_PERSON)

    component = NESTING_PERSON.split()[-1]
    assert occurs_as_a_unit(normalize(component), normalize(NESTING_PERSON)), (
        "premise: the originals nest, which is what makes this the safe case"
    )

    standalone = await strategy.make_surrogate(
        _person(component), "beef0021", env.vault, session_id=session_id
    )

    assert not STRICT_TOKEN_RE.fullmatch(standalone), (
        f"{component!r} degraded to a token: the nesting guard swallowed component linking"
    )
    assert standalone == full.split()[-1], (
        f"{component!r} -> {standalone!r} does not match the surname inside {full!r}"
    )


#: A session key on which the two-digit mask over ``"MRN: 71"`` redraws ``71`` --
#: the generated fake is byte-identical to the value it is replacing.
SELF_EQUAL_MASK_KEY = (11).to_bytes(32, "big")


async def test_a_fake_equal_to_the_value_it_replaces_is_regenerated(env: Env) -> None:
    """The whole-string self-check is its own layer, and nothing else covers it.

    A short labelled identifier invents only a two-character word, which is below
    ``_MIN_COLLIDING_WORD``, so the word guard looks straight past it; and the
    value being replaced is not in the vault yet, so the originals-set check
    cannot see it either unless a caller seeded ``reserved_originals``. Strip the
    ``candidate == original`` test and the whole file stays green while
    ``"MRN: 71"`` is emitted as its own surrogate -- the original, verbatim, in
    the payload, with a vault row claiming it is a fake.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=SELF_EQUAL_MASK_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")
    source = "MRN: 71"

    # Premise, in three parts: the caller gives no help, the vault is empty, and
    # the generator's first draw really is the source string.
    assert strategy.reserved_originals == frozenset()
    assert env.vault.originals_for_session(session_id) == frozenset()
    unguarded = strategy._generate("MRN", source, 0)
    assert unguarded.text == source, (
        f"this key no longer redraws its own value ({unguarded.text!r}); nothing is proved"
    )
    assert all(len(word) < 3 for word in unguarded.invented), (
        "the invented word is long enough for the word guard to catch, so this "
        "would be testing that layer instead"
    )

    surrogate = await strategy.make_surrogate(
        Detection(
            entity_type="MRN",
            category=EntityCategory.PHI,
            start=0,
            end=len(source),
            text=source,
            score=0.9,
        ),
        "aaaaaaaa",
        env.vault,
        session_id=session_id,
    )

    assert surrogate != source
    assert not STRICT_TOKEN_RE.fullmatch(surrogate), "regenerate, do not give up"
    assert re.fullmatch(r"MRN: \d{2}", surrogate), surrogate


@pytest.mark.parametrize("entity_type", ["NAME", "CLIENT_IDENTITY"])
async def test_no_person_pseudonym_reproduces_a_real_name_word(env: Env, entity_type: str) -> None:
    """Swept across many session keys: zero shared words, not merely few.

    A single key proves the guard fires once; the sweep proves it is not
    probabilistic. The pre-fix rate on this sweep was ~1.9% of spans.
    """
    names = [
        "Anna Williams",
        "John Smith",
        "Maria Garcia",
        "David Nguyen",
        "Sarah Johnson",
        "Robert Wilson",
    ]
    offenders: list[tuple[str, str, list[str]]] = []
    degraded = 0
    for index in range(60):
        strategy = build_strategy(
            "pseudonymization",
            StrategyContext(
                registry=env.registry,
                session_key=(index + 1).to_bytes(32, "big"),
                settings=env.settings,
            ),
        )
        session_id, _ = await env.sessions.create("test-user")
        for name in names:
            detection = Detection(
                entity_type=entity_type,
                category=CATEGORY_OF[entity_type],
                start=0,
                end=len(name),
                text=name,
                score=0.9,
            )
            strategy.reserved_originals = frozenset({normalize(name)})
            surrogate = await strategy.make_surrogate(
                detection, "aaaaaaaa", env.vault, session_id=session_id
            )
            if STRICT_TOKEN_RE.fullmatch(surrogate):
                degraded += 1  # guard exhausted -> plain token, which leaks nothing
                continue
            shared = sorted(set(normalize(surrogate).split()) & set(normalize(name).split()))
            if shared:
                offenders.append((name, surrogate, shared))
    assert offenders == [], f"{len(offenders)}/360 pseudonyms kept a real name word"
    # Without this the sweep is satisfiable by breaking the generator outright: a
    # strategy that returned a plain token for every person would `continue` 360
    # times and report zero offenders. The keys here are fixed (1..60), so the
    # count is deterministic and the real answer is exactly zero.
    assert degraded == 0, f"{degraded}/360 spans never produced a fake to inspect"


async def test_a_faked_place_never_reproduces_a_real_word(env: Env) -> None:
    """The word guard is the *only* protection on the non-person semantic paths.

    Persons resolve a colliding component in place, so the outer guard rarely
    fires for them. ``ADDRESS`` and ``EMAIL`` have no such per-component search --
    Faker builds the whole string in one call -- so ``_invents_a_real_word`` is
    what stops a fake city from reproducing a word of a real original, and this is
    the test that isolates it.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    source = "Larkspur Valley"
    detection = Detection(
        entity_type="ADDRESS",
        category=EntityCategory.PII,
        start=0,
        end=len(source),
        text=source,
        score=0.9,
    )

    # What the generator produces with nothing forbidden.
    unguarded = strategy._generate("ADDRESS", source, 0)
    candidate_words = sorted(
        (word for word in unguarded.invented if len(word) >= 3), key=len, reverse=True
    )
    assert candidate_words, unguarded
    shared = candidate_words[0]

    # Plant that word inside a DIFFERENT real original. The fake is now not equal
    # to any original, so the whole-string check cannot fire -- only the
    # invented-word check stands between the real word and the payload.
    other_original = f"{shared} General Hospital"
    assert normalize(other_original) != normalize(unguarded.text)
    strategy.reserved_originals = frozenset({normalize(source), normalize(other_original)})

    surrogate = await strategy.make_surrogate(
        detection, "aaaaaaaa", env.vault, session_id=env.session_id
    )

    # Not "return if it degraded": an early return is a pass, so a guard that gave
    # up on every address would satisfy this test without ever running the check it
    # exists for. The session key is the fixture's, but the outcome does not depend
    # on it -- ten reseeded city draws against two forbidden originals resolve on
    # the first or second attempt (measured: 0/40 exhaustions across fixed keys).
    assert not STRICT_TOKEN_RE.fullmatch(surrogate), (
        "the guard exhausted instead of finding a clean city; nothing was verified"
    )
    assert normalize(surrogate) != normalize(unguarded.text), (
        "the colliding candidate was emitted unchanged"
    )
    assert shared not in normalize(surrogate).split(), (
        f"{surrogate!r} reproduces the real word {shared!r}"
    )


async def test_the_guard_still_excuses_words_the_mask_copied_from_the_source(
    env: Env,
) -> None:
    """The other half of the split: a format-preserving label is *not* invented.

    ``"MRN:"`` is a word of a real original (its own source), so a guard that
    checked every word would reject every candidate and degrade the whole entity
    to a plain token. The mask reports only the runs it rewrote.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)

    labelled = strategy._generate("MRN", "MRN: 4471902", 0)
    assert labelled.text.startswith("MRN: ")
    assert "mrn:" not in labelled.invented, "a copied label is not an invention"
    assert labelled.invented == {normalize(labelled.text.removeprefix("MRN: "))}

    docket = strategy._generate("CASE_ID", "Case No. 1:23-cv-45678", 0)
    assert docket.text.startswith("Case No. ")
    assert not {"case", "no."} & docket.invented

    # The semantic path inherits nothing: every name word it emits is invented.
    person = strategy._generate("NAME", "Dr. Anna Williams", 0)
    assert person.text.startswith("Dr. ")
    assert "dr." not in person.invented, "a title is copied, not drawn"
    assert person.invented == set(normalize(person.text.removeprefix("Dr. ")).split())


async def test_collision_guard_falls_back_to_a_token_rather_than_looping(env: Env) -> None:
    """Every attempt poisoned -> a plain token, never an unbounded loop."""
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    detection = Detection(
        entity_type="SSN",
        category=EntityCategory.PII,
        start=0,
        end=11,
        text="123-45-6789",
        score=0.9,
    )
    for attempt in range(MAX_FAKE_ATTEMPTS):
        poisoned = strategy._generate("SSN", detection.text, attempt).text
        await env.vault.put(
            env.session_id,
            TokenRecord(
                session_id=env.session_id,
                token_id=f"c0ffee{attempt:02d}",
                entity_type="OTHER_ID",
                category=EntityCategory.PII,
                surrogate=f"[PII_OTHER_ID_c0ffee{attempt:02d}]",
                created_at=time.time(),
            ),
            poisoned,
        )
    surrogate = await strategy.make_surrogate(
        detection, "1a2b3c4d", env.vault, session_id=env.session_id
    )
    assert surrogate == "[PII_SSN_1a2b3c4d]"


async def test_a_fake_cannot_collide_with_a_value_vaulted_later_in_the_same_run(
    env: Env,
) -> None:
    """The collision guard must be complete, not incremental.

    The vault only knows what has been written *so far*, which makes a guard built
    on it order-dependent: the first entity in the document is generated against an
    empty originals set, so its fake can land on a real value that is vaulted three
    entities later. The two are then byte-identical in the payload -- a real value
    on the wire that the gate cannot tell apart from our own output, and a restore
    that cannot say which entity a mention belongs to.

    The engine closes it by seeding the strategy with every original in the
    document *before* generating any surrogate.
    """
    # What the first entity's generator produces on attempt 0, with no guard.
    probe = build_strategy("pseudonymization", env.context())
    assert isinstance(probe, PseudonymizationStrategy)
    unguarded = probe._generate("NAME", "Anna Williams", 0).text
    assert unguarded and unguarded != "Anna Williams"

    # Plant that exact string as a REAL second name, later in the same document.
    text = f"Anna Williams briefed {unguarded} this morning."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "Anna Williams", "NAME"), span(text, unguarded, "NAME")],
        strategy="pseudonymization",
    )

    assert len(result.tokens) == 2
    originals = {"Anna Williams", unguarded}
    for original in originals:
        assert original not in result.obfuscated_text, original
    for record in result.tokens:
        assert record.surrogate not in originals, (
            f"{record.surrogate!r} is a real value from this very document"
        )
        # Dodging the collision by giving up on faking would satisfy the assertion
        # above while quietly disabling the tier. The guard must *regenerate*.
        assert not STRICT_TOKEN_RE.fullmatch(record.surrogate), record.surrogate
    # And the surrogates are distinct from each other, so the two names stay two
    # people once restored.
    assert len({record.surrogate for record in result.tokens}) == 2


async def test_whole_string_collision_is_caught_even_when_no_invented_word_is(
    env: Env,
) -> None:
    """The whole-string check is a distinct layer from the word-level one.

    The word guard ignores invented words below ``_MIN_COLLIDING_WORD``, so a
    short labelled identifier ("MRN: 12") can generate a fake whose only invented
    word is two characters long. That fake can still equal *another* entity's real
    value in full -- which is exactly the ambiguous-restore, gate-firing case the
    original-set check exists for. Removing that check leaves this uncaught.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    detection = Detection(
        entity_type="MRN",
        category=EntityCategory.PHI,
        start=0,
        end=7,
        text="MRN: 12",
        score=0.9,
    )

    first = strategy._generate("MRN", detection.text, 0)
    assert first.text.startswith("MRN: ")
    # The premise of this test is "an invention too short for the word guard to
    # look at". ``all(...)`` over an empty set is True, so an empty ``invented``
    # would satisfy it while quietly testing a different situation.
    assert first.invented, "the mask invented nothing, so the premise does not hold"
    assert all(len(word) < 3 for word in first.invented), first.invented

    # That exact string is a REAL value held by this session, under another entity.
    await env.vault.put(
        env.session_id,
        TokenRecord(
            session_id=env.session_id,
            token_id="deadbeef",
            entity_type="OTHER_ID",
            category=EntityCategory.PHI,
            surrogate="[PHI_OTHER_ID_deadbeef]",
            created_at=time.time(),
        ),
        first.text,
    )

    second = await strategy.make_surrogate(
        detection, "aaaaaaaa", env.vault, session_id=env.session_id
    )
    assert second != first.text, "a fake equal to a real original must be regenerated"
    assert normalize(second) not in {
        normalize(value) for value in env.vault.originals_for_session(env.session_id)
    }


#: The one original the vault holds in the seam test below, and the value the
#: strategy is asked to fake beside it. Both spellings of an MRN original are used
#: across the two tests, and both are real: ``MRN``'s pattern is ``\K\d{6,10}``, so
#: a pattern hit vaults the bare digits (the second test), while a span that arrives
#: with its label attached vaults the label too -- the shape ``_identifier_needles``
#: cites as the reason its digit-run limb exists.
NEEDLE_ACCOUNT = "Account No. 100200300400"
NEEDLE_MRN = "MRN: 556728"

#: A session key on which the structural mask draws ``Account No. 556728956575`` for
#: :data:`NEEDLE_ACCOUNT` on attempt 0 -- twelve freely chosen digits whose first six
#: are the digits of the vaulted ``MRN: 556728``. Found by searching 88 719 keys
#: (seven landing sites at 1e-6 each, so about one key in 140 000), and pinned for
#: the same reason :data:`SURNAME_ECHO_KEY` is: the fault was first seen as one
#: blocked run in eleven executions of the 100-run leakage suite, and a regression
#: test may not be a coincidence with a 9% hit rate.
DIGIT_RUN_COLLISION_KEY = (88719).to_bytes(32, "big")


async def test_a_fake_carrying_a_real_originals_digit_run_is_regenerated(env: Env) -> None:
    """The collision guard and the egress gate must mean the same thing by "collision".

    ``_invents_a_real_word`` tests whole-**word** membership. Pass 1 does not stop
    there: ``_identifier_needles`` scans for any contiguous run of six or more digits
    of a vaulted original, glued to anything at all. A Tier-1 fake draws its digits
    freely, so it can land on a real MRN's digit run while sharing no word with
    anything in the session -- the guard passed it, and the gate then blocked *our
    own output* with ``reason='vault_original'`` on a run in which nothing had
    leaked. Self-inflicted, and measured at one blocked run in eleven executions of
    the 100-run leakage suite.

    Every premise is asserted before the outcome, because a pass here would
    otherwise be indistinguishable from a lucky draw: the unguarded generator really
    does reproduce the run, the word-level guard really is blind to it, and the real
    gate really does refuse the payload that guard would have released.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=DIGIT_RUN_COLLISION_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    await env.vault.put(
        env.session_id,
        TokenRecord(
            session_id=env.session_id,
            token_id="deadbeef",
            entity_type="MRN",
            category=EntityCategory.PHI,
            surrogate="[PHI_MRN_deadbeef]",
            created_at=time.time(),
        ),
        NEEDLE_MRN,
    )
    originals = env.vault.originals_for_session(env.session_id)
    gate = egress_gate.EgressGate(
        vault=env.vault, detector=SilentDetector(), settings=env.settings
    )

    unguarded = strategy._generate("ACCOUNT_NUMBER", NEEDLE_ACCOUNT, 0)
    assert unguarded.text == "Account No. 556728956575", (
        f"{unguarded.text!r} is not the draw this key was pinned for, so nothing below "
        f"is testing the seam"
    )
    assert "556728" in unguarded.text, "the premise: the fake carries the real MRN's digits"
    assert not strategy._invents_a_real_word(unguarded, env.vault, env.session_id), (
        "the word-level guard must be blind to this -- that blindness IS the seam, and "
        "a test where the old guard already objected proves nothing about the new one"
    )
    leak = f"Ledger reconciliation for {unguarded.text} completed."
    assert gate._scan_originals(leak, originals, frozenset({unguarded.text})) == 1, (
        "the gate must refuse the unguarded fake, or this test is about nothing"
    )

    surrogate = await strategy.make_surrogate(
        Detection(
            entity_type="ACCOUNT_NUMBER",
            category=EntityCategory.FIN,
            start=0,
            end=len(NEEDLE_ACCOUNT),
            text=NEEDLE_ACCOUNT,
            score=0.9,
        ),
        "aaaaaaaa",
        env.vault,
        session_id=env.session_id,
    )

    assert not STRICT_TOKEN_RE.fullmatch(surrogate), (
        "the guard must regenerate; degrading to a token here would dodge the gate by "
        "switching the tier off"
    )
    assert re.fullmatch(r"Account No\. \d{12}", surrogate), (
        f"format preservation must survive the retry: {surrogate!r}"
    )
    assert "556728" not in surrogate, surrogate
    released = f"Ledger reconciliation for {surrogate} completed."
    assert gate._scan_originals(released, originals, frozenset({surrogate})) == 0, (
        "the payload the pipeline would now send is one the gate releases"
    )


#: The other half of the gate's unbounded vocabulary, and it needs its own key and
#: its own pair of values. On this key the mask draws ``Account No. 9004-4392-9552``
#: for ``Account No. 1002-0030-0400``; the vaulted MRN ``4439295`` appears **nowhere
#: in that string** -- its digits straddle two hyphens -- and shows up only in the
#: digit-only projection ``900443929552`` that ``_regrouped_identifier_needle`` is
#: compared against. The values were constructed rather than searched for (any key
#: yields such a slice; the MRN is read off the draw), which is the honest way to get
#: a deterministic instance of a 1e-7 event.
REGROUPED_COLLISION_KEY = (3).to_bytes(32, "big")
REGROUPED_ACCOUNT = "Account No. 1002-0030-0400"
REGROUPED_MRN = "4439295"


async def test_a_fake_that_regroups_a_real_originals_digits_is_regenerated(env: Env) -> None:
    """The second unbounded limb: the payload's digit stream, separators deleted.

    ``_identifier_needles`` is compared against a haystack that kept its separators,
    so it cannot see a real identifier our fake has *re-grouped* --
    ``4439295`` inside ``9004-4392-9552``. ``_regrouped_identifier_needle`` is
    compared against the digit-only projection of the whole payload and blocks
    exactly that, so a guard carrying only the first limb still hands the gate a
    payload it refuses.

    The two limbs are therefore pinned separately, and this test asserts the first
    one is blind here before asserting the guard is not.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry, session_key=REGROUPED_COLLISION_KEY, settings=env.settings
        ),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    await env.vault.put(
        env.session_id,
        TokenRecord(
            session_id=env.session_id,
            token_id="deadbeef",
            entity_type="MRN",
            category=EntityCategory.PHI,
            surrogate="[PHI_MRN_deadbeef]",
            created_at=time.time(),
        ),
        REGROUPED_MRN,
    )
    originals = env.vault.originals_for_session(env.session_id)
    gate = egress_gate.EgressGate(
        vault=env.vault, detector=SilentDetector(), settings=env.settings
    )

    unguarded = strategy._generate("ACCOUNT_NUMBER", REGROUPED_ACCOUNT, 0)
    assert unguarded.text == "Account No. 9004-4392-9552", (
        f"{unguarded.text!r} is not the draw these values were pinned for"
    )
    assert REGROUPED_MRN not in unguarded.text, (
        "the premise: the run is NOT written contiguously, so the substring limb "
        "cannot be what catches this"
    )
    needles = _gate_needles([REGROUPED_MRN])
    assert not needles.occur_in(egress_gate._skeleton(unguarded.text), ""), (
        "the substring half alone releases this candidate"
    )
    assert needles.occur_in("", egress_gate._digits_only(_gate_fold(unguarded.text))), (
        "the digit-stream half is the one that must catch it"
    )
    leak = f"Ledger reconciliation for {unguarded.text} completed."
    assert gate._scan_originals(leak, originals, frozenset({unguarded.text})) == 1, (
        "the gate must refuse the unguarded fake, or this test is about nothing"
    )

    surrogate = await strategy.make_surrogate(
        Detection(
            entity_type="ACCOUNT_NUMBER",
            category=EntityCategory.FIN,
            start=0,
            end=len(REGROUPED_ACCOUNT),
            text=REGROUPED_ACCOUNT,
            score=0.9,
        ),
        "aaaaaaaa",
        env.vault,
        session_id=env.session_id,
    )

    assert not STRICT_TOKEN_RE.fullmatch(surrogate), "the guard must regenerate, not give up"
    assert re.fullmatch(r"Account No\. \d{4}-\d{4}-\d{4}", surrogate), surrogate
    assert REGROUPED_MRN not in egress_gate._digits_only(surrogate), surrogate
    released = f"Ledger reconciliation for {surrogate} completed."
    assert gate._scan_originals(released, originals, frozenset({surrogate})) == 0


async def test_the_needle_guard_also_covers_the_value_being_replaced(env: Env) -> None:
    """The one original the vault cannot supply, in the needle vocabulary too.

    A value reaches the vault only once its surrogate exists, so while
    ``_fake_identifier`` runs the value being replaced is in ``originals_for_session``
    only if a caller happened to seed ``reserved_originals``. ``_invents_a_real_word``
    closes that gap for words with its ``also`` argument; this closes it for needles.

    Asserted at the unit rather than end to end, and the reason is worth stating
    rather than hiding: the structural mask preserves digit *count*, so a fake that
    contains its own original's six-digit run has to reproduce that run exactly, and
    every such candidate is already refused by the whole-string layer or by
    ``own_words``. The generators that are **not** length-preserving -- the address
    and e-mail paths -- are not bound by that argument, and neither is a future
    Tier-1 generator, so the term is carried rather than argued away. What is pinned
    here is that it is wired: with an empty vault, nothing else can reject this
    candidate.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")
    assert env.vault.originals_for_session(session_id) == frozenset(), (
        "the vault must be empty, or the session term could be what rejects this"
    )

    # One candidate, two calls: the only difference is whether the value being
    # replaced is allowed to contribute its needles.
    carrier = _Candidate("Ref 556728-A", frozenset({"ref", "556728-a"}))
    assert not strategy._carries_a_gate_needle(carrier, env.vault, session_id), (
        "with no originals anywhere and no own-value term there is nothing to collide with"
    )
    assert strategy._carries_a_gate_needle(
        carrier, env.vault, session_id, _gate_needles(["MRN: 556728"])
    ), "the value being replaced must contribute needles like any other original"


async def test_the_needle_index_is_incremental_without_being_stale(env: Env) -> None:
    """The needle index tracks the session in both directions.

    ``_original_needles`` is rebuilt incrementally because the originals snapshot
    changes on every issued surrogate and a full rescan per change is quadratic in
    the document (834 ms vs 986 ms on ``legal_brief_large.txt``). That optimisation
    is only sound while the set grows, and ``reserved_originals`` is re-seeded per
    call and can shrink -- so both directions are asserted here rather than argued:
    a value added later must contribute its needles, and a value that goes away must
    stop contributing them. A cache that only ever unions is red on the second half;
    a cache keyed on identity alone is red on the first.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    carrier = _Candidate("Ref 556728-A", frozenset({"ref", "556728-a"}))
    later = _Candidate("Ref 4439295-B", frozenset({"ref", "4439295-b"}))

    strategy.reserved_originals = frozenset({normalize("MRN: 556728")})
    assert strategy._carries_a_gate_needle(carrier, env.vault, env.session_id)
    assert not strategy._carries_a_gate_needle(later, env.vault, env.session_id)

    # A second document in the same session: the set grows.
    strategy.reserved_originals = frozenset(
        {normalize("MRN: 556728"), normalize("Account 4439295")}
    )
    assert strategy._carries_a_gate_needle(carrier, env.vault, env.session_id)
    assert strategy._carries_a_gate_needle(later, env.vault, env.session_id), (
        "a needle added after the index was first built must still be seen"
    )

    # A third call carrying only the second value: the set shrinks.
    strategy.reserved_originals = frozenset({normalize("Account 4439295")})
    assert strategy._carries_a_gate_needle(later, env.vault, env.session_id)
    assert not strategy._carries_a_gate_needle(carrier, env.vault, env.session_id), (
        "a needle whose original is no longer in the session must be dropped, or the "
        "guard degrades values on the strength of call history"
    )


#: Shapes the shipped registry vaults, as digit templates. Deliberately a mix of
#: what does and does not carry a needle -- bare identifier cores, labelled ones,
#: separator-grouped ones, a phone number, an amount, a short date, a docket number
#: and an alphanumeric member ID -- so the differential below is not a corpus of
#: guaranteed hits.
NEEDLE_SHAPES = (
    "DDDDDD",
    "DDDDDDD",
    "DDDDDDDDDD",
    "MRN: DDDDDDD",
    "DDD-DD-DDDD",
    "DDDD-DDDD-DDDD",
    "DDDDDDDDDDDD",
    "(DDD) DDD-DDDD",
    "$1,DDD.DD",
    "DD/DD/19DD",
    "Case No. 1:23-cv-DDDDD",
    "BCBSDDDDDDDDD",
    "DD-DDDDDDD",
    "Account No. DDDDDDDDDDDD",
)


def _draw(rng: random.Random, shape: str) -> str:
    return "".join(rng.choice("0123456789") if char == "D" else char for char in shape)


def _splice_digits(rng: random.Random, host: str, digits: str) -> str:
    """``host`` with ``digits`` written over its digit positions, shape preserved."""
    host_digits = [char for char in host if char.isdigit()]
    if len(host_digits) < len(digits):
        return host
    at = rng.randrange(0, len(host_digits) - len(digits) + 1)
    replaced = host_digits[:at] + list(digits) + host_digits[at + len(digits) :]
    stream = iter(replaced)
    return "".join(next(stream) if char.isdigit() else char for char in host)


class _EmptyVault:
    """A vault with no originals. The differential passes them in per pair."""

    def originals_for_session(self, session_id: str) -> frozenset[str]:
        return frozenset()


def test_the_collision_guard_reaches_exactly_as_far_as_pass_one_does(
    settings: Settings, registry: EntityRegistry
) -> None:
    """Differential: the tightened guard is neither weaker nor stricter than the gate.

    The guard exists to keep the gate from ever firing on our own output, so the
    property that matters is an agreement between two components -- and the agreement
    has two directions, both of which have cost this repo something:

    * **weaker** is the defect this test was written for: a fake the guard releases
      and pass 1 blocks is a self-inflicted ``EGRESS_BLOCKED``;
    * **stricter** is the cost of over-correcting: a fake the guard rejects and pass 1
      would have released spends the retry budget and eventually degrades a value to
      a plain token for nothing. Testing the run needles against the digit stream --
      the obvious single-haystack simplification -- is exactly that mistake, and this
      direction is what refuses it.

    Sharing the needle *functions* with the gate is deliberate (the producer conforms
    to the consumer's rule), so this test cannot be a check on the functions; it is a
    check on the **composition** -- both limbs wired, each to the projection the gate
    compares it against, over the fold the gate applies. A guard missing the
    regrouped limb, or folding the candidate differently, or testing a needle against
    the wrong haystack, is red here.

    The gate side is the real ``EgressGate._scan_originals``, so a pair counts as a
    hit only if the shipped gate really would block. 4 000 pairs here (117 gate hits,
    107 guard rejections, ~0.25 s), half of them with six digits of the original
    spliced into the candidate so hits are common rather than astronomically rare;
    the same generator run out to 40 000 pairs gives 1 040 gate hits and 0 in either
    failing direction.
    """
    rng = random.Random(20250805)
    gate = egress_gate.EgressGate(
        vault=_EmptyVault(), detector=SilentDetector(), settings=settings
    )
    assert registry.entities, "the registry fixture is only here to pin the shapes as real"
    gate_hits = 0
    guard_rejects = 0
    for _ in range(4000):
        original = _draw(rng, rng.choice(NEEDLE_SHAPES))
        candidate = _draw(rng, rng.choice(NEEDLE_SHAPES))
        if rng.random() < 0.5:
            digits = egress_gate._digits_only(original)
            start = rng.randrange(0, max(len(digits) - 5, 1))
            candidate = _splice_digits(rng, candidate, digits[start : start + 6])
        rejected = _gate_needles([original]).occur_in(
            egress_gate._skeleton(candidate),
            egress_gate._digits_only(_gate_fold(candidate)),
        )
        blocked = gate._scan_originals(candidate, frozenset({original})) >= 1
        gate_hits += blocked
        guard_rejects += rejected
        if rejected:
            assert blocked, (
                f"the guard is STRICTER than the gate: it would retry (and eventually "
                f"emit a plain token) for {candidate!r} against {original!r}, which the "
                f"gate releases"
            )
        if blocked and not rejected:
            # The remaining gate limbs are the bounded ones, which the word-level and
            # whole-string layers of the guard own. Anything else is the seam again.
            shared = {word for word in normalize(candidate).split() if len(word) >= 3} & {
                word for word in normalize(original).split() if len(word) >= 3
            }
            assert shared or normalize(candidate) == normalize(original), (
                f"the guard is WEAKER than the gate: it would release {candidate!r} "
                f"against {original!r}, and the gate blocks it"
            )
    assert gate_hits >= 100, (
        f"only {gate_hits} of 4000 pairs reached the gate's limbs at all, so this "
        f"differential is not exercising them"
    )
    assert guard_rejects >= 100, (
        f"the guard rejected only {guard_rejects} of 4000 pairs, so the stricter-than "
        f"direction above is close to vacuous"
    )


async def test_a_shifted_date_landing_on_another_real_date_degrades_to_a_token(
    env: Env,
) -> None:
    """Tier 2's one unresolvable case, handled rather than shipped.

    The shift is one constant per session, so a date shifted forward can land
    exactly on a *different* real date in the same document. The rendered
    surrogate is then a verbatim original -- the gate blocks it and restore cannot
    disambiguate it. Only that date degrades; every other date keeps the shared
    shift, so the intervals among them survive.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)

    source = datetime(2024, 3, 14).date()
    collides_with = source + timedelta(days=strategy.shift_days)
    source_text = source.strftime("%m/%d/%Y")
    other_text = collides_with.strftime("%m/%d/%Y")
    assert source_text != other_text

    detection = Detection(
        entity_type="DATE",
        category=EntityCategory.PHI,
        start=0,
        end=len(source_text),
        text=source_text,
        score=0.9,
    )

    # Without the other real date present, the shift renders normally.
    strategy.reserved_originals = frozenset()
    assert (
        await strategy.make_surrogate(detection, "aaaaaaaa", env.vault, session_id=env.session_id)
        == other_text
    )

    # With it present, shifting would emit a verbatim original -- so it must not.
    strategy.reserved_originals = frozenset({normalize(other_text)})
    degraded = await strategy.make_surrogate(
        detection, "aaaaaaaa", env.vault, session_id=env.session_id
    )
    assert STRICT_TOKEN_RE.fullmatch(degraded), degraded
    assert degraded == "[PHI_DATE_aaaaaaaa]"


#: A session key whose date shift is exactly ``+30`` days -- the smallest the
#: derivation can produce. A ``Month YYYY`` span parses to the first of the month,
#: so +30 out of a 31-day month lands *inside the same month* and re-renders the
#: source string byte for byte.
SELF_SHIFT_KEY = (117).to_bytes(32, "big")


async def test_a_shifted_date_that_re_renders_as_its_own_source_degrades(env: Env) -> None:
    """Tier 2's other collision: the date shifts onto **itself**.

    The test above covers a shifted date landing on a *different* real date, and
    the originals set catches that one. This one it cannot: the value being
    shifted is written to the vault only after its surrogate exists, so it is in
    the originals set only while a caller happens to seed ``reserved_originals``.
    That made the check correct by accident -- the engine does seed it, so the
    engine was safe, but the guarantee belonged to the caller rather than to this
    method. Driven directly, ``"January 2024"`` came back as ``"January 2024"``:
    the original, verbatim, recorded in the vault as its own surrogate.
    """
    strategy = build_strategy(
        "pseudonymization",
        StrategyContext(registry=env.registry, session_key=SELF_SHIFT_KEY, settings=env.settings),
    )
    assert isinstance(strategy, PseudonymizationStrategy)
    session_id, _expires = await env.sessions.create("test-user")

    # Premise, computed here rather than read out of the module: this key's shift
    # really does leave a 31-day month's first day inside that same month.
    assert strategy.shift_days == 30, "the pinned key no longer yields the +30 shift"
    landed = datetime(2024, 1, 1).date() + timedelta(days=strategy.shift_days)
    assert (landed.year, landed.month) == (2024, 1)
    assert strategy.reserved_originals == frozenset(), "the caller must give no help"
    assert env.vault.originals_for_session(session_id) == frozenset()

    def date_span(text: str) -> Detection:
        return Detection(
            entity_type="DATE",
            category=EntityCategory.PHI,
            start=0,
            end=len(text),
            text=text,
            score=0.9,
        )

    surrogate = await strategy.make_surrogate(
        date_span("January 2024"), "aaaaaaaa", env.vault, session_id=session_id
    )
    assert surrogate != "January 2024"
    assert surrogate == "[PHI_DATE_aaaaaaaa]"

    # ...and the fallback stays the exception. A month the shift really does move
    # is still shifted, so this did not simply disable Tier 2.
    assert (
        await strategy.make_surrogate(
            date_span("April 2024"), "bbbbbbbb", env.vault, session_id=session_id
        )
        == "May 2024"
    )


async def test_a_shifted_date_that_renders_another_original_degrades(env: Env) -> None:
    """Tier 2's third collision, and the only one a whole-string test cannot see.

    The two tests above ask whether the shifted date **equals** a real value. That
    is the wrong question. A shifted date is a *rendered string*, and it can carry
    a real original by **containing** it: ``April 2024`` is vaulted from one
    document, and a later document's ``17 March 2024`` shifts to ``29 April 2024``.
    ``'29 april 2024' != 'april 2024'``, so equality passes it straight through --
    and the residual sweep cannot catch it either, because the sweep runs on the
    ORIGINAL text before splicing and so never inspects a surrogate it spliced in.
    The result is a vaulted original on the wire as a word-bounded unit, which the
    egress gate blocks with ``reason='vault_original'``: the pipeline rejecting its
    own output, the exact unprocessable-document failure the sweep exists to
    prevent.

    Everything below runs through the real engine over two documents in one
    session, because that is the shape the defect has, and the leak assertion is a
    plain ``in`` on the payload -- not the boundary predicate the guard itself
    uses, which would share the guard's blind spot by construction.

    The month is computed from *this* session's shift rather than pinned, so the
    test exercises whatever shift the key produces instead of one lucky constant.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)

    source_text = "17 March 2024"
    landed = datetime(2024, 3, 17).date() + timedelta(days=strategy.shift_days)
    month_year = landed.strftime("%B %Y")

    # Premise, computed rather than asserted from the module: the shift really does
    # render a string that CONTAINS "<Month> YYYY" without being equal to it. If
    # this ever stops holding the test below would pass for the wrong reason.
    would_render = f"{landed.day} {month_year}"
    assert month_year in would_render
    assert would_render != month_year, "equality would have caught it; containment is the point"
    assert normalize(would_render) != normalize(month_year)

    first = f"Coverage began {month_year} for this member."
    await env.engine.obfuscate(
        env.session_id, first, [span(first, month_year, "DOB")], strategy="pseudonymization"
    )
    assert month_year in env.vault.originals_for_session(env.session_id), (
        "premise: the month-year really is a vaulted original of this session"
    )

    second = f"Follow-up visit on {source_text}."
    result = await env.engine.obfuscate(
        env.session_id, second, [span(second, source_text, "DOB")], strategy="pseudonymization"
    )

    assert month_year not in result.obfuscated_text, (
        "a vaulted original went out inside the shifted date"
    )
    assert len(result.tokens) == 1
    assert result.obfuscated_text == f"Follow-up visit on {result.tokens[0].surrogate}."
    assert STRICT_TOKEN_RE.fullmatch(result.tokens[0].surrogate), result.tokens[0].surrogate

    # And the degradation stays the exception rather than a disabled tier: the same
    # date in a session that never vaulted that month is still shifted, not tokenized.
    clean_id, _expires = await env.sessions.create("test-user")
    clean_strategy = build_strategy(
        "pseudonymization",
        StrategyContext(
            registry=env.registry,
            session_key=await env.sessions.key(clean_id),
            settings=env.settings,
        ),
    )
    assert isinstance(clean_strategy, PseudonymizationStrategy)
    clean_landed = datetime(2024, 3, 17).date() + timedelta(days=clean_strategy.shift_days)
    clean_result = await env.engine.obfuscate(
        clean_id, second, [span(second, source_text, "DOB")], strategy="pseudonymization"
    )
    assert clean_result.tokens[0].surrogate == f"{clean_landed.day} {clean_landed:%B %Y}"


async def test_a_shifted_date_landing_inside_a_longer_original_degrades(env: Env) -> None:
    """Tier 2's fourth collision: the containment test's **other direction**.

    The test above catches a shifted date that *swallows* a vaulted original. This
    one is the mirror -- a shifted date *swallowed by* a longer original -- and the
    guard did not test for it. It is not an exotic shape: any detector span that
    covers more than one date makes a multi-date string a vault original in its own
    right, and the shipped medical fixture produces one on every seed. spaCy returns
    ``Prior ambulatory visits: 03/11/2024, 09/17/2024, and 10/01/2024.`` as the
    single ``DATE`` span ``03/11/2024, 09/17/2024`` beside a separate ``10/01/2024``,
    so a session shift of ``-204`` days takes ``10/01/2024`` onto ``03/11/2024`` --
    a verbatim, word-bounded slice of the other original.

    Measured at roughly one full ``-m leakage`` run in a hundred before this guard,
    and silent in both directions. The payload carries a real appointment date of
    the real patient inside a string the pipeline invented, and neither the egress
    gate nor the leakage harness reports it, because both ask whether a *whole*
    vaulted value occurs. Then at restore the token pass puts
    ``03/11/2024, 09/17/2024`` back into the answer, and that value carries a **live
    surrogate** as a unit -- which ``Restorer._assert_no_surrogates`` is structurally
    unable to object to, since it excuses residue inside a value the restorer itself
    spliced (correctly: a restored original may legitimately contain another
    entity's fake) and in this case the splice happens in the *token* pass, after
    that assertion has already run. The answer then holds one date string standing
    for two different days with ``restored_count`` up, ``surrogate_misses`` 0 and
    outcome ``ok``.

    Everything is computed from *this* session's shift rather than pinned, so the
    test exercises whatever the key produces rather than one lucky constant.
    """
    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)

    landing = datetime(2024, 3, 11).date()
    source = landing - timedelta(days=strategy.shift_days)
    source_text = source.strftime("%m/%d/%Y")
    rendered = landing.strftime("%m/%d/%Y")
    # The second half of the run sits 7 days from the first, which the +/-30 shift
    # floor puts permanently out of reach of ``source`` -- so the composite can
    # never accidentally contain the very date under test whatever key this session
    # drew, and the two spans below can never overlap.
    composite = f"{rendered}, {(landing + timedelta(days=7)).strftime('%m/%d/%Y')}"

    # Premises, computed rather than pinned. This is precisely the case the
    # one-directional guard could not see: the original is far longer than the
    # rendered date, so "does an original occur inside this surrogate?" -- the test
    # that already shipped for the other three collisions -- answers no.
    assert not occurs_as_a_unit(normalize(composite), normalize(rendered)), (
        "premise: the old one-directional test passes this straight through"
    )
    assert occurs_as_a_unit(normalize(rendered), normalize(composite)), (
        "premise: the rendered date really is a word-bounded slice of the original"
    )
    assert source_text not in composite and rendered != composite

    # Control: with nothing vaulted, this date really does shift onto that slice.
    # Without it the test could pass because the shift went somewhere else entirely.
    detection = Detection(
        entity_type="DATE",
        category=EntityCategory.PHI,
        start=0,
        end=len(source_text),
        text=source_text,
        score=0.9,
    )
    strategy.reserved_originals = frozenset()
    assert (
        await strategy.make_surrogate(detection, "aaaaaaaa", env.vault, session_id=env.session_id)
        == rendered
    )

    # The real engine, over the document shape that produces it.
    unrelated = landing + timedelta(days=900)
    unrelated_text = unrelated.strftime("%m/%d/%Y")
    document = (
        f"Prior ambulatory visits: {composite}, and {source_text}.\n"
        f"Discharge planning conference scheduled for {unrelated_text}.\n"
    )
    result = await env.engine.obfuscate(
        env.session_id,
        document,
        [
            span(document, composite, "DATE"),
            span(document, source_text, "DATE"),
            span(document, unrelated_text, "DATE"),
        ],
        strategy="pseudonymization",
    )
    by_original = {
        token.surrogate: await env.vault.get_by_surrogate(env.session_id, token.surrogate)
        for token in result.tokens
    }
    surrogate_of = {original: s for s, original in by_original.items()}

    # A plain ``in``, not the boundary predicate the guard itself uses: a leak
    # assertion phrased in the guard's own terms shares its blind spot by
    # construction.
    assert rendered not in result.obfuscated_text, (
        "a slice of a vaulted original went out inside the shifted date"
    )
    assert STRICT_TOKEN_RE.fullmatch(surrogate_of[source_text]), surrogate_of[source_text]

    # Degradation is scoped to the one colliding date: every other date keeps the
    # shared shift, so the intervals among them survive -- which is the whole
    # reason Tier 2 exists.
    assert surrogate_of[unrelated_text] == (
        unrelated + timedelta(days=strategy.shift_days)
    ).strftime("%m/%d/%Y")

    # And the degraded date is still fully restorable -- it loses its temporal
    # relation, not its value.
    assert by_original[surrogate_of[source_text]] == source_text


async def test_two_dates_for_one_day_are_never_issued_the_same_surrogate(env: Env) -> None:
    """Tier 2's fourth collision: the surrogate that carries no original at all.

    The three tests above all ask "does this shifted date carry a **real value**?"
    -- equal to one, equal to its own source, containing one. There is a fourth
    question none of them reaches, because a duplicate surrogate carries no
    original: **does this string already stand for a different original?**

    Tier 2 is a many-to-one map by construction and that is the whole point of it:
    the shift preserves the day and the renderer preserves the source's format. So
    two spans naming the *same day in two formats* -- the ISO date in a header and
    the spelled-out date in the prose beneath it -- both come back through the ISO
    renderer (the second via ``_parse_fallback``, which has no format to preserve)
    and produce the byte-identical string. Two distinct vault originals then own
    one surrogate, and ``get_by_surrogate`` maps a string to exactly one record.

    Tier 1 cannot reach this state: ``_fake_identifier`` tests ``_surrogate_taken``
    and ``test_two_originals_are_never_issued_the_same_surrogate`` pins it. Tier 2
    was never asked the question, so it answered wrong -- on a two-format document,
    which is an ordinary document and not an attack.

    What made it invisible is that the *outcome* looks safe. Nothing leaks: both
    surrogates are fake dates, so the egress gate passes the payload. The
    orchestrator's step 4b (``_assert_surrogates_are_distinct``) then catches the
    duplicate and refuses the run before the provider is called -- correct, but it
    refuses with ``PipelineError(reason='surrogate_collision')``, so an ordinary
    document simply cannot be processed, and that function's docstring states the
    opposite ("reaching this is a bug upstream, not a user input: the
    pseudonymization strategy already rejects a candidate fake that any surrogate
    in the session has taken"). This test makes that sentence true of Tier 2 too.

    The decisive assertion is therefore asked of the *orchestrator's own* check
    rather than restated here, and of the vault rather than of the strategy: every
    surrogate on the wire resolves back to the original it stands for.
    """
    iso, spelled = "2024-01-05", "Friday, January 5, 2024"
    text = f"Admitted {iso}. Discharge summary dated {spelled}."
    detections = [span(text, iso, "DATE"), span(text, spelled, "DATE")]

    strategy = build_strategy("pseudonymization", env.context())
    assert isinstance(strategy, PseudonymizationStrategy)
    shifted = (datetime(2024, 1, 5).date() + timedelta(days=strategy.shift_days)).isoformat()

    # Premise, computed from the parsers rather than pinned: unguarded, these two
    # really do render one string. If a renderer ever changes so that they do not,
    # this test would pass for the wrong reason and must be re-pointed.
    for source in (iso, spelled):
        parsed = parse_source_date(source)
        assert parsed is not None, source
        rendered = parsed.render(parsed.value + timedelta(days=strategy.shift_days))
        assert rendered == shifted, f"{source!r} renders {rendered!r}, not {shifted!r}"
    assert normalize(iso) != normalize(spelled), "premise: two distinct originals"

    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="pseudonymization"
    )

    # Two distinct originals, two vault rows, and -- the property -- two surrogates.
    assert await env.vault.row_count(env.session_id) == 2
    issued = [record.surrogate for record in result.tokens]
    assert len(issued) == 2
    assert len(set(issued)) == 2, "two originals were issued one surrogate"

    # The degradation is the exception, not a disabled tier: the first mention keeps
    # the session shift and only the duplicate falls back to a token.
    assert issued[0] == shifted
    assert STRICT_TOKEN_RE.fullmatch(issued[1]), issued[1]
    assert result.obfuscated_text == f"Admitted {issued[0]}. Discharge summary dated {issued[1]}."

    # Asked of the vault, not of the engine: each surrogate on the wire resolves
    # back to the original it stands for, and to that one only.
    assert await env.vault.get_by_surrogate(env.session_id, issued[0]) == iso
    assert await env.vault.get_by_surrogate(env.session_id, issued[1]) == spelled

    # And the run the orchestrator would refuse is now a run it accepts. This is the
    # consequence the property exists for, so it is checked against the real
    # function rather than re-derived here.
    _assert_surrogates_are_distinct(result.tokens, env.session_id, "test-run")


async def test_token_id_collision_is_re_derived_and_both_values_resolve(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forced truncation collision: distinct originals still resolve independently.

    This pins the worst failure mode in the system. The restorer keys strictly on
    the 8-hex core and makes one vault call per distinct ID, so it can neither
    cause a collision nor detect one: if two entities ever shared an ID it would
    restore **both** mentions to whichever value the vault happened to hold, with
    no error anywhere -- a fluent, correct-looking answer carrying the wrong
    person's data. The engine settling the ID *before* the surrogate is rendered
    is the only thing standing in the way, so the assertions below are about
    **which value each mention resolves to**, not about two IDs being unequal.
    """
    real = derive_token_id

    def colliding(session_key: bytes, entity_type: str, value: str, *, counter: int = 0) -> str:
        return (
            "cafe0001" if counter == 0 else real(session_key, entity_type, value, counter=counter)
        )

    monkeypatch.setattr(engine_module, "derive_token_id", colliding)

    text = "SSNs 123-45-6789 and 987-65-4321 on file."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "123-45-6789", "SSN"), span(text, "987-65-4321", "SSN")],
        strategy="tokenization",
    )
    ids = [record.token_id for record in result.tokens]
    assert len(set(ids)) == 2, "the collision must be re-derived, not silently overwritten"
    assert "cafe0001" in ids
    assert await env.vault.row_count(env.session_id) == 2

    # 1. A BIJECTION, not a membership test. Asserting each resolved value merely
    #    belongs to the set of originals passes even when both IDs resolve to the
    #    same one -- which is precisely the mis-restore being guarded against.
    by_token = {
        record.token_id: await env.vault.get_by_token(env.session_id, record.token_id)
        for record in result.tokens
    }
    assert sorted(by_token.values()) == ["123-45-6789", "987-65-4321"]

    # 2. Every mention resolves to the value that stood THERE. This is the
    #    end-to-end statement: span offsets are in original space, so the surrogate
    #    spliced over a span must round-trip to that span's own text.
    for item in result.spans:
        assert item.surrogate is not None
        assert (
            await env.vault.get_by_surrogate(env.session_id, item.surrogate)
            == (text[item.start : item.end])
        )

    # 3. The text carries the RE-DERIVED id, not the one derived before the vault
    #    settled it. Reconstructed exactly rather than spot-checked, because the
    #    restorer reads the document, not our token list.
    surrogate_of = {
        await env.vault.get_by_token(env.session_id, record.token_id): record.surrogate
        for record in result.tokens
    }
    assert result.obfuscated_text == (
        f"SSNs {surrogate_of['123-45-6789']} and {surrogate_of['987-65-4321']} on file."
    )

    # 4. Walk the document the way the restorer does -- extract ids from the text,
    #    look each one up -- and confirm it rebuilds the original document.
    extracted = extract_token_ids(result.obfuscated_text)
    assert extracted == set(ids)
    rebuilt = result.obfuscated_text
    for token_id in extracted:
        rebuilt = rebuilt.replace(
            f"[PII_SSN_{token_id}]", await env.vault.get_by_token(env.session_id, token_id)
        )
    assert rebuilt == text


async def test_an_unresolvable_token_id_collision_fails_loudly(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retry is bounded, and exhausting it raises rather than issuing a duplicate.

    An unbounded loop is an outage, but silently reusing an ID is worse than
    either: it is the mis-restore above, shipped. So the last resort is a loud
    failure carrying a reason, an entity type and a count -- and no value.
    """
    monkeypatch.setattr(
        engine_module,
        "derive_token_id",
        lambda session_key, entity_type, value, *, counter=0: "cafe0001",
    )

    text = "SSNs 123-45-6789 and 987-65-4321 on file."
    with pytest.raises(PipelineError) as excinfo:
        await env.engine.obfuscate(
            env.session_id,
            text,
            [span(text, "123-45-6789", "SSN"), span(text, "987-65-4321", "SSN")],
            strategy="tokenization",
        )

    detail = excinfo.value.detail
    assert detail["reason"] == "token_collision_unresolved"
    assert detail["entity_type"] == "SSN"
    assert detail["attempts"] == engine_module.MAX_TOKEN_COLLISION_RETRIES
    # No original may ride out on the exception -- it is rendered into str(exc).
    rendered = f"{excinfo.value!r} {excinfo.value}"
    for secret in ("123-45-6789", "987-65-4321"):
        assert secret not in rendered

    # The first value was vaulted before the second collided; no duplicate id exists.
    assert await env.vault.row_count(env.session_id) == 1
    assert await env.vault.get_by_token(env.session_id, "cafe0001") == "123-45-6789"


# ---------------------------------------------------------------------------
# 6. Dedupe
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_repeated_value_is_one_vault_row_and_five_splices(env: Env, strategy: str) -> None:
    text = (
        "123-45-6789 opened the file. Confirm 123-45-6789. "
        "The form lists 123-45-6789, the ledger lists 123-45-6789, "
        "and the appendix repeats 123-45-6789."
    )
    detections = every_span(text, "123-45-6789", "SSN")
    assert len(detections) == 5

    result = await env.engine.obfuscate(env.session_id, text, detections, strategy=strategy)

    assert len(result.tokens) == 1, "one vault row per distinct value"
    assert await env.vault.row_count(env.session_id) == 1
    surrogate = result.tokens[0].surrogate
    assert result.obfuscated_text.count(surrogate) == 5, "five splices"
    assert "123-45-6789" not in result.obfuscated_text

    # spans is per-ORIGINAL-span, not per deduped entity (UI highlighting).
    assert len(result.spans) == 5
    assert {item.surrogate for item in result.spans} == {surrogate}
    assert all(item.action is EntityAction.OBFUSCATED for item in result.spans)
    assert [(item.start, item.end) for item in result.spans] == [
        (d.start, d.end) for d in detections
    ]
    assert all(text[item.start : item.end] == "123-45-6789" for item in result.spans)


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_the_sweep_chases_values_vaulted_by_an_earlier_call(env: Env, strategy: str) -> None:
    """A session outlives one document, so "masked everywhere" must too.

    ``POST /ask`` runs per ``doc_id`` against a long-lived session. A name vaulted
    from document 1 and missed by the detector in document 2 is the same residual
    the sweep exists to remove -- and the egress gate blocks the request for it
    either way, so leaving it unswept makes ordinary multi-document sessions fail.
    """
    first = "Patient John Smith was admitted."
    await env.engine.obfuscate(
        env.session_id, first, [span(first, "John Smith", "NAME")], strategy=strategy
    )
    surrogate = await env.vault.get_by_original(env.session_id, "NAME", "john smith")
    assert surrogate is not None

    # Second document, same session, detector returns NOTHING.
    second = "Follow-up for John Smith and again for JOHN SMITH next week."
    result = await env.engine.obfuscate(env.session_id, second, [], strategy=strategy)

    assert "John Smith" not in result.obfuscated_text
    assert "JOHN SMITH" not in result.obfuscated_text
    assert result.obfuscated_text.count(surrogate.surrogate) == 2
    # The value was already vaulted, so no second row.
    assert await env.vault.row_count(env.session_id) == 1
    # ...but the surrogate IS in this payload, so this payload must declare it.
    # See test_tokens_declare_every_surrogate_in_the_payload for why an undeclared
    # one is a blocked request and an unrestored fake rather than a cosmetic gap.
    assert [record.surrogate for record in result.tokens] == [surrogate.surrogate]
    assert result.tokens[0].token_id == surrogate.token_id
    assert len(result.spans) == 2
    assert all(item.action is EntityAction.OBFUSCATED for item in result.spans)
    assert all(item.surrogate == surrogate.surrogate for item in result.spans)
    assert all(second[item.start : item.end].casefold() == "john smith" for item in result.spans)


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_tokens_declare_every_surrogate_in_the_payload(env: Env, strategy: str) -> None:
    """``tokens`` is the payload's manifest, so a *swept* surrogate must be in it.

    Three consumers read ``ObfuscationResult.tokens`` as "the surrogates this
    payload contains": the orchestrator hands that set to the egress gate as *our
    own output*, it builds the pseudonym restore map from it, and it reports the
    issued token IDs from it. The cross-call sweep splices surrogates for values
    the detector never returned this call, so they have no entry in the engine's
    ``records`` -- and while they went undeclared each consumer failed differently:

    * the gate's pass 2 re-detected the undeclared fake as a real entity and
      **blocked the request** -- measured on a pseudonymized SSN, reason
      ``detector_rescan``, ``hit_count`` 1. An ordinary second document in a
      session became unprocessable.
    * the restorer never mapped it, so the model's answer kept the *fake* and the
      caller read a plausible invented value as the real one.
    * a vault miss on it was mis-classified as a model fabrication rather than a
      vault loss.

    The sweep and the manifest were added by different changes, which is exactly
    how a payload came to contain a surrogate that nothing declared.
    """
    first = "Patient John Smith, SSN 123-45-6789, was admitted."
    await env.engine.obfuscate(
        env.session_id,
        first,
        [span(first, "John Smith", "NAME"), span(first, "123-45-6789", "SSN")],
        strategy=strategy,
    )

    # Second document, same session, detector silent: both values reach the payload
    # only through the sweep.
    second = "Discharge note for John Smith; billing shows 123-45-6789."
    result = await env.engine.obfuscate(env.session_id, second, [], strategy=strategy)

    declared = {record.surrogate for record in result.tokens}
    in_payload = {item.surrogate for item in result.spans if item.surrogate is not None}
    assert in_payload, "the sweep spliced nothing, so this test verified nothing"
    assert in_payload <= declared, f"{sorted(in_payload - declared)} reached the payload undeclared"
    # ...and nothing phantom in the other direction.
    for surrogate in declared:
        assert surrogate in result.obfuscated_text, surrogate

    assert len(result.tokens) == 2
    assert await env.vault.row_count(env.session_id) == 2, "no new rows: both were vaulted"
    resolved = {
        await env.vault.get_by_surrogate(env.session_id, record.surrogate)
        for record in result.tokens
    }
    assert resolved == {"John Smith", "123-45-6789"}

    # A value that is BOTH detected here and reached by the sweep under another
    # surface form is one vault row, so it must be declared exactly once.
    #
    # This casing never reaches the dedupe, and cannot fail without it: the sweep
    # orders surfaces (-len, value), so the equal-length "JOHN SMITH" detected here
    # sorts ahead of the vaulted "John Smith" ("O" < "o") and claims BOTH mentions,
    # leaving the prior-call surface unused and the swept-record list empty. The
    # binding case is the other casing --
    # ``test_a_value_both_detected_and_swept_is_declared_once`` below.
    third = "JOHN SMITH signed; John Smith countersigned."
    mixed = await env.engine.obfuscate(
        env.session_id, third, [span(third, "JOHN SMITH", "NAME")], strategy=strategy
    )
    ids = [record.token_id for record in mixed.tokens]
    assert len(ids) == len(set(ids)), f"a surrogate was declared twice: {ids}"
    assert len(mixed.tokens) == 1
    assert "John Smith" not in mixed.obfuscated_text
    assert "JOHN SMITH" not in mixed.obfuscated_text


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_a_value_both_detected_and_swept_is_declared_once(env: Env, strategy: str) -> None:
    """One vault row is one token, even when two surface forms reach the payload.

    ``obfuscate`` appends the cross-call sweep's records to ``tokens`` and dedupes
    them on token ID, and until this test that dedupe was bound by nothing:
    dropping it -- ``tokens.extend(swept_records)`` -- left the whole suite green.
    The manifest would then carry the SAME row twice, and the orchestrator hands
    ``tokens`` on as three different things: the egress gate's set of "our own
    output", the pseudonym restore map, and the issued-token-ID report. A doubled
    row is a doubled restore-map entry and a doubled count of what this call
    issued -- a manifest that misdescribes the payload it is the manifest of.

    Reaching the duplicate takes a surface form this call detected and a DIFFERENT
    surface form the vault holds, both normalizing to one row (build doc section 8:
    NFKC, collapse whitespace, casefold), with the vaulted form the one that claims
    a residual. ``_add_prior_session_surfaces`` offers a prior original whenever it
    is not literally a key of this call's surfaces -- and ``surfaces`` is keyed by
    raw detection text -- so a case-differing header is exactly that.

    Casing direction is load-bearing here, which is why the neighbouring check in
    ``test_tokens_declare_every_surrogate_in_the_payload`` cannot fail: the sweep
    sorts ``(-len(surface), surface)``, so of two equal-length casings the one with
    the uppercase letter sorts first. Vaulting the UPPERCASE form and detecting the
    mixed-case one is what puts the prior-call surface in front, where it claims
    the residual and lands in the swept-record list.

    The residual span's score is the proof that it did: a prior-call surface enters
    the sweep at 1.0 ("a value the vault already holds", not a detector guess),
    while this call's surface carries the detector's 0.9. A residual scored 0.9
    would mean this call's own surface claimed it, the swept-record list came back
    empty, and the dedupe was never exercised at all.
    """
    first = "Header: JOHN SMITH, admitted today."
    await env.engine.obfuscate(
        env.session_id, first, [span(first, "JOHN SMITH", "NAME")], strategy=strategy
    )
    record = await env.vault.get_by_original(env.session_id, "NAME", "john smith")
    assert record is not None

    # Detected in its mixed casing, residual in a third one the detector missed.
    second = "John Smith signed the release; john smith countersigned it."
    result = await env.engine.obfuscate(
        env.session_id, second, [span(second, "John Smith", "NAME")], strategy=strategy
    )

    ids = [item.token_id for item in result.tokens]
    assert len(ids) == len(set(ids)), f"one vault row was declared twice: {ids}"
    assert ids == [record.token_id]
    assert await env.vault.row_count(env.session_id) == 1, "one value, one row"

    # The payload really does carry both surface forms masked, so the manifest is
    # describing two splices of one surrogate rather than a single one.
    assert result.obfuscated_text.count(record.surrogate) == 2
    assert "john smith" not in result.obfuscated_text.casefold()

    assert len(result.spans) == 2
    detected, residual = sorted(result.spans, key=lambda item: item.start)
    assert second[detected.start : detected.end] == "John Smith"
    assert second[residual.start : residual.end] == "john smith"
    assert detected.score == 0.9, "this call's detection, at the score it was given"
    assert residual.score == 1.0, "claimed by the vaulted surface -- the dedupe path ran"


async def test_the_sweep_never_masks_an_original_it_cannot_resolve_to_a_record(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cross-call sweep must not defeat the gate's fail-closed proof.

    The sweep reads the vault's originals set, which the leakage harness's
    adversarial case deliberately *inflates* with a value that has no vault row --
    the point being that the value rides through into the payload and pass 1 of
    the EgressGate blocks on it, with no help from the detector. An engine that
    masked anything merely named in that set would silently disarm the proof, and
    would also emit a surrogate that restores to nothing.

    So a value must be resolvable to a real record before it is swept. Unresolvable
    means untouched, which leaves the gate to do exactly its job.
    """
    planted = "ZXQQ-KLM-RSTV-WYNP"
    real_originals = env.vault.originals_for_session

    def inflated(session_id: str) -> frozenset[str]:
        known = real_originals(session_id)
        return known | {planted} if session_id == env.session_id else known

    monkeypatch.setattr(env.vault, "originals_for_session", inflated)

    text = f"Patient John Smith. Vendor control marker: {planted}"
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "John Smith", "NAME")], strategy="tokenization"
    )

    assert planted in result.obfuscated_text, "unresolvable -> untouched, so the gate blocks"
    assert "John Smith" not in result.obfuscated_text, "the real detection is still masked"
    # ``all(...)`` over an empty list is True, so name the count: exactly the one
    # real detection, and nothing invented for the planted value.
    assert len(result.spans) == 1
    assert result.spans[0].entity_type == "NAME"
    assert text[result.spans[0].start : result.spans[0].end] == "John Smith"
    assert len(result.tokens) == 1
    assert result.obfuscated_text == (
        f"Patient {result.tokens[0].surrogate}. Vendor control marker: {planted}"
    )


async def test_a_value_vaulted_after_the_sweeps_first_read_is_still_masked(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cross-call sweep re-reads the originals set; one read is a TOCTOU window.

    ``_add_prior_session_surfaces`` reads ``originals_for_session`` while the payload
    is being BUILT and the EgressGate reads the same session-wide set again at gate
    time. A session is shared -- ``POST /ask`` is per ``doc_id``, not per session --
    so a concurrent run can vault a value in between. If that value occurs in this
    run's document and this run's detector missed it, the sweep never had it as a
    surface, the value goes out in the clear, and the gate correctly refuses the
    request with ``EGRESS_BLOCKED(reason='vault_original')``.

    The block is right and must stay right: the payload really does carry, in the
    clear, a value the system now knows is sensitive. What is wrong is the engine
    being the last component to learn it. So the sweep asks again, after the scan,
    and masks whatever arrived in the meantime -- a refused request becomes an
    obfuscated one, and nothing the gate looks for is made invisible to it.

    **Modelled at the observable rather than by racing two coroutines.** What the
    engine sees of a concurrent vault is exactly this: one read that predates the
    write and a later read that does not. Hiding the value from the first read
    reproduces that in one deterministic run; racing a real second ``obfuscate``
    reproduces the same thing at whatever rate the interleave happens to land, and
    the integration suite's sixteen-way probe
    (``test_concurrent_runs_on_one_session_do_not_cross_wires``) does not reach it at
    all -- its documents are identical but for the MRN, so every run detects every
    shared value itself and never depends on another run's write. 62 runs of it,
    green, before this test was written.

    Tokenization only, because the model has to be exact: the pseudonymization
    collision guard reads ``originals_for_session`` too, so "the first read" would no
    longer be the sweep's read and the window under test would not be the one hidden.

    Also asserts the record is DECLARED. A surrogate spliced by the sweep and left
    out of ``ObfuscationResult.tokens`` is worse than the block it replaces: the
    orchestrator hands ``tokens`` to the gate as "our own output" and builds the
    restore map from it, so an undeclared one is re-detected by pass 2 and, under
    pseudonymization, read back by the caller as though the fake were the answer.
    """
    value = "Northgate Clinic"

    # The concurrent run's write. It lands, in the modelled timeline, after this
    # run's sweep has already read the set -- see ``racing`` below.
    other_document = f"Referred from {value} on Tuesday."
    await env.engine.obfuscate(
        env.session_id,
        other_document,
        [span(other_document, value, "NAME")],
        strategy="tokenization",
    )
    record = await env.vault.get_by_original(env.session_id, "NAME", normalize(value))
    assert record is not None, "premise: the concurrent run really did vault it"

    reads: list[frozenset[str]] = []
    real_originals = env.vault.originals_for_session
    stale = True

    def racing(session_id: str) -> frozenset[str]:
        """The set as this run observes it: the first read predates the write."""
        nonlocal stale
        known = real_originals(session_id)
        if stale and session_id == env.session_id:
            stale = False
            known -= {value}
        reads.append(known)
        return known

    monkeypatch.setattr(env.vault, "originals_for_session", racing)

    text = f"Patient John Smith was seen today.\nReferred by {value} for follow-up.\n"
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "John Smith", "NAME")], strategy="tokenization"
    )

    # Premise: the window really was open. The first read is this run's own value
    # and nothing else; the concurrent one is visible only afterwards.
    assert reads[0] == frozenset({"John Smith"}), reads
    assert value in real_originals(env.session_id)

    assert value not in result.obfuscated_text, (
        "the value the concurrent run vaulted went out in the clear -- the gate "
        "would refuse this request rather than release it"
    )
    assert record.surrogate in result.obfuscated_text
    assert record.token_id in {item.token_id for item in result.tokens}, (
        "a surrogate reached the payload undeclared"
    )
    assert "John Smith" not in result.obfuscated_text, "this run's own detection, still masked"

    # And the consequence, from the gate itself rather than restated here.
    gate = egress_gate.EgressGate(vault=env.vault, detector=SilentDetector(), settings=env.settings)
    originals = real_originals(env.session_id)
    assert gate._scan_originals(result.obfuscated_text, originals) == 0, "released, not refused"
    assert gate._scan_originals(text, originals) == 2, (
        "control: unswept, the gate counts both originals and blocks"
    )


async def test_a_late_arrival_is_swept_in_one_order_with_the_surfaces_before_it(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The re-read redoes the sweep; appending to it would leave a name half-masked.

    Longest-surface-first is a **total** order over the whole surface set, and it is
    load-bearing: where "Smith" and "John Smith" both match one residual, the surname
    claiming it splices five characters and leaves "John " standing. A second pass
    that only chased the surfaces that arrived late would break exactly that, because
    the long surface's match overlaps a span the short one already covered and is
    skipped -- and the result is the worst of both outcomes. The payload carries
    "John " in the clear beside a surrogate, and the EgressGate releases it: neither
    vaulted original occurs verbatim any more, so pass 1 counts zero and the refusal
    that would at least have been safe never happens.

    So the sweep is rewound to the detected spans and re-run over the union. The two
    assertions that separate the two implementations are the exact payload -- one
    surrogate covering the whole name, not a surname surrogate with a forename in
    front of it -- and the manifest, which must declare the record that actually
    reached the payload and not the one the discarded first pass used.
    """
    surname, full = "Smith", "John Smith"
    for value in (surname, full):
        seed = f"Case note for {value}, filed today."
        await env.engine.obfuscate(
            env.session_id, seed, [span(seed, value, "NAME")], strategy="tokenization"
        )
    short_record = await env.vault.get_by_original(env.session_id, "NAME", normalize(surname))
    full_record = await env.vault.get_by_original(env.session_id, "NAME", normalize(full))
    assert short_record is not None and full_record is not None
    assert short_record.token_id != full_record.token_id, "premise: two rows, two surrogates"

    stale = True
    real_originals = env.vault.originals_for_session

    def racing(session_id: str) -> frozenset[str]:
        """``John Smith`` is vaulted by a concurrent run after the first read."""
        nonlocal stale
        known = real_originals(session_id)
        if stale and session_id == env.session_id:
            stale = False
            known -= {full}
        return known

    monkeypatch.setattr(env.vault, "originals_for_session", racing)

    # No detections at all: everything here is the cross-call sweep's work, so the
    # ordering under test is not being decided by this call's detected spans.
    text = "Contact John Smith about the discharge summary."
    result = await env.engine.obfuscate(env.session_id, text, [], strategy="tokenization")

    assert result.obfuscated_text == f"Contact {full_record.surrogate} about the discharge summary."
    assert "John" not in result.obfuscated_text, (
        "the forename was left in the clear -- the surname claimed the span first"
    )
    assert {item.token_id for item in result.tokens} == {full_record.token_id}, (
        "the manifest must describe the surviving pass, not the rewound one"
    )
    assert len(result.spans) == 1
    assert text[result.spans[0].start : result.spans[0].end] == full


async def test_an_original_that_gains_a_row_between_the_two_reads_is_swept(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unresolvability is a fact about a moment, so it is not written off between reads.

    The second read only pays for what it has not already decided about, and that
    bookkeeping is where a re-read quietly becomes a single read again. Two of the
    three skips are permanent -- below the length floor, and absent from a document
    that cannot change -- but "no vault record" is not. A value reaches the originals
    set with no row whenever the redact band noted it (``note_unrestorable``), and a
    concurrent run scoring the SAME value above ``threshold_obfuscate`` then writes
    the row: same digits, different sentence, different confidence. Between the two
    reads it goes from unsweepable to sweepable, and an engine that remembered the
    first answer would leave it in the clear for the gate to refuse.

    Modelled exactly at that boundary: the value is in the set for both reads, and
    the row exists only for the second. ``test_the_sweep_never_masks_an_original_it
    _cannot_resolve_to_a_record`` above pins the other direction -- still no row at
    the last read means still untouched -- so the two together say "retry, do not
    assume", rather than "mask anything the set names".
    """
    value = "452-18-9376"
    text = f"Member SSN {value} verified against payer records."

    # In the set from the start, with no row: this is the redact band's needle.
    env.vault.note_unrestorable(env.session_id, value)
    seed = f"Claim for SSN {value} was reprocessed."

    reads = 0
    real_originals = env.vault.originals_for_session
    real_get = env.vault.get_by_original

    def counting(session_id: str) -> frozenset[str]:
        nonlocal reads
        reads += 1
        return real_originals(session_id)

    async def row_lands_between_the_reads(
        session_id: str, entity_type: str, normalized: str
    ) -> TokenRecord | None:
        """The concurrent run's ``put`` completes after this run's first read."""
        if reads < 2 and normalize(normalized) == normalize(value):
            return None
        return await real_get(session_id, entity_type, normalized)

    # The row the concurrent run writes. Created up front and hidden by the stub
    # above until the second read, because ``put`` cannot be driven from inside the
    # synchronous read the engine makes.
    await env.engine.obfuscate(
        env.session_id, seed, [span(seed, value, "SSN")], strategy="tokenization"
    )
    landed = await real_get(env.session_id, "SSN", normalize(value))
    assert landed is not None

    monkeypatch.setattr(env.vault, "originals_for_session", counting)
    monkeypatch.setattr(env.vault, "get_by_original", row_lands_between_the_reads)

    result = await env.engine.obfuscate(env.session_id, text, [], strategy="tokenization")

    assert reads >= 2, "premise: the sweep asked twice"
    assert value not in result.obfuscated_text
    assert result.obfuscated_text == (
        f"Member SSN {landed.surrogate} verified against payer records."
    )
    assert {item.token_id for item in result.tokens} == {landed.token_id}


MARKUP_WRAPPERS = [
    pytest.param("_{}_", id="markdown-underscore-emphasis"),
    pytest.param("*{}*", id="markdown-asterisk-emphasis"),
    pytest.param("**{}**", id="markdown-bold"),
    pytest.param("__{}__", id="markdown-underscore-bold"),
    pytest.param("<b>{}</b>", id="html-tag"),
    pytest.param("`{}`", id="code-span"),
]


@pytest.mark.parametrize("wrapper", MARKUP_WRAPPERS)
async def test_the_sweep_masks_a_residual_wrapped_in_markup(env: Env, wrapper: str) -> None:
    """Underscore is punctuation in prose, so it must be a boundary.

    Regex ``\\w`` counts ``_`` as a word character, so the old
    ``(?<!\\w)John Smith(?!\\w)`` refused to match ``_John Smith_`` -- ordinary
    markdown emphasis. The sweep left the original in place. The egress gate held
    the identical belief, so the two agreed and nothing contradicted either: the
    original went out byte-for-byte. This is the end-to-end leak.
    """
    text = f"Patient John Smith admitted. Signed, {wrapper.format('John Smith')}."
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "John Smith", "NAME")], strategy="tokenization"
    )

    surrogate = result.tokens[0].surrogate
    assert "John Smith" not in result.obfuscated_text, result.obfuscated_text
    assert result.obfuscated_text.count(surrogate) == 2, result.obfuscated_text
    assert len(result.spans) == 2


@pytest.mark.parametrize(
    ("value", "entity_type", "prefix", "suffix"),
    [
        pytest.param("(415) 555-0123", "PHONE", "tel", "", id="leading-paren-glued-left"),
        pytest.param("$1,234.56", "AMOUNT", "USD", "", id="leading-dollar-glued-left"),
        pytest.param("MRN: 4471902", "MRN", "#", "", id="leading-hash-glued-left"),
        pytest.param("Case No. 1:23-cv-45678", "CASE_ID", "(", ")", id="parenthesised"),
    ],
)
async def test_the_sweep_masks_a_residual_whose_own_edge_is_punctuation(
    env: Env, value: str, entity_type: str, prefix: str, suffix: str
) -> None:
    """A boundary assertion on a punctuation edge asks a meaningless question.

    "Is this one word or part of a longer one?" only means something on a side
    where the surface itself is alphanumeric. Asserting unconditionally asked
    whether the character before ``(`` in ``(415) 555-0123`` was a word
    character -- so ``tel(415) 555-0123`` went unswept while carrying the original
    verbatim. The assertions are therefore applied per side, and only where the
    surface's own edge is alphanumeric.
    """
    text = f"On file: {value}. Cross-reference {prefix}{value}{suffix} in the ledger."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, value, entity_type)],
        strategy="tokenization",
        doc_category="financial" if entity_type == "AMOUNT" else None,
    )

    assert value not in result.obfuscated_text, result.obfuscated_text
    assert len(result.spans) == 2, "the detected span plus the glued residual"


def occurs_as_a_unit_oracle(needle: str, haystack: str) -> bool:
    """Independent restatement of the occurrence rule. Shares no code with either side.

    Deliberately written with :meth:`str.find` and :meth:`str.isalnum` -- no regex,
    no lookaround, and nothing imported from ``engine`` or ``egress_gate``. The rule
    it encodes, stated from scratch: *the needle occurs as a unit when some
    occurrence of it is not glued to an alphanumeric character on a side where the
    needle's own edge is alphanumeric.* A side whose edge is punctuation asks no
    question at all, because "one word or part of a longer one?" is meaningless
    there.

    This exists because agreement is not correctness. The sweep and the gate have
    now been wrong together twice, and a differential test between two
    implementations of one idea passes happily while both are broken -- which is
    exactly how ``(?<!\\w)John Smith(?!\\w)`` survived: the sweep declined to mask
    ``_John Smith_`` and the gate declined to block it, so the two agreed and the
    original went out byte-for-byte.
    """
    if not needle:
        return False
    guard_left = needle[0].isalnum()
    guard_right = needle[-1].isalnum()
    index = haystack.find(needle)
    while index != -1:
        before = haystack[index - 1] if index else ""
        after = haystack[index + len(needle) : index + len(needle) + 1]
        blocked_left = guard_left and before.isalnum()
        blocked_right = guard_right and after.isalnum()
        if not blocked_left and not blocked_right:
            return True
        index = haystack.find(needle, index + 1)
    return False


#: Hand-decided ground truth for the cases that actually broke, plus the
#: false-positive case the rule exists to avoid. Written out as literals so that
#: even a change agreed on by the sweep, the gate *and* the oracle still fails.
OCCURRENCE_GROUND_TRUTH: list[tuple[str, str, bool]] = [
    # The markdown bypass: underscore is punctuation in prose, so it is a boundary.
    ("John Smith", "_John Smith_", True),
    ("John Smith", "__John Smith__", True),
    ("John Smith", "Patient John Smith was seen.", True),
    # The punctuation-edge bypass: the needle's own edge is not alphanumeric, so
    # there is no word boundary to assert on that side.
    ("(415) 555-0123", "tel(415) 555-0123", True),
    ("$1,234.56", "USD$1,234.56", True),
    ("Ph.D.", "Ph.D.degree", True),
    ("Case No. 1:23-cv-45678", "(Case No. 1:23-cv-45678)", True),
    # ...and the false blocks the rule exists to prevent: a real needle sitting
    # inside a longer word is NOT an occurrence.
    ("Brown", "Browning", False),
    ("Ann", "Announcement", False),
    ("Ann", "Anniston", False),
    ("123-45-6789", "9123-45-67890", False),
    # Absent entirely.
    ("John Smith", "Jane Smith was seen.", False),
]


def test_the_sweep_and_the_gate_agree_on_what_counts_as_an_occurrence() -> None:
    """Differential test **against an oracle**, not merely against each other.

    The rule has drifted twice, and both times the sweep and the gate were wrong
    *together* -- so a test that only asked "do these two agree?" was measuring two
    copies of one bug nodding at each other. Three things are checked here:

    1. hand-written ground truth, so a change all three implementations make in
       lockstep still fails;
    2. the sweep against :func:`occurs_as_a_unit_oracle`, which shares no code with
       it; and
    3. the sweep against the gate. Both now resolve to ``textrules``, so this leg
       can no longer catch a *divergence* -- there is nothing left to diverge. It
       is kept because it still catches the case that matters more: the shared
       rule being wrong, which is what every previous instance actually was.
    """
    # 1. Ground truth first: this is the part that does not care what any
    #    implementation currently believes.
    wrong: list[tuple[str, str, bool, bool, bool]] = []
    for needle, haystack, expected in OCCURRENCE_GROUND_TRUTH:
        sweep = re.search(engine_module._word_bounded(needle), haystack) is not None
        gate = egress_gate._occurs_as_a_unit(needle, haystack)
        oracle = occurs_as_a_unit_oracle(needle, haystack)
        if not (sweep == gate == oracle == expected):
            wrong.append((needle, haystack, sweep, gate, oracle))
    assert wrong == [], f"(needle, haystack, sweep, gate, oracle) disagreed with truth: {wrong}"

    # 2 + 3. Then the broad sweep over generated cases, three ways.
    needles = [
        "John Smith",
        "Brown",
        "Ann",
        "MRN: 4471902",
        "(415) 555-0123",
        "$1,234.56",
        "Ph.D.",
        "123-45-6789",
        "Case No. 1:23-cv-45678",
        "O'Brien",
    ]
    haystacks = [
        "{}",
        "_{}_",
        "*{}*",
        "__{}__",
        "a{}",
        "{}z",
        "({})",
        "[{}]",
        " {} ",
        "x{}y",
        "{}.",
        ".{}",
        "tel{}",
        "USD{}",
        "{}degree",
        "-{}-",
        "{}_",
        "_{}",
        "\n{}\n",
        "1{}",
        "{}9",
    ]
    vs_oracle: list[tuple[str, str]] = []
    vs_gate: list[tuple[str, str]] = []
    for needle in needles:
        pattern = engine_module._word_bounded(needle)
        for template in haystacks:
            haystack = template.format(needle)
            mine = re.search(pattern, haystack) is not None
            if mine != occurs_as_a_unit_oracle(needle, haystack):
                vs_oracle.append((needle, haystack))
            if mine != egress_gate._occurs_as_a_unit(needle, haystack):
                vs_gate.append((needle, haystack))
    assert vs_oracle == [], (
        f"the sweep disagrees with the independent oracle on {len(vs_oracle)} "
        f"case(s): {vs_oracle[:5]}"
    )
    assert vs_gate == [], f"sweep and gate disagree on {len(vs_gate)} case(s): {vs_gate[:5]}"


def test_the_occurrence_oracle_is_not_a_copy_of_the_rule_it_checks() -> None:
    """The oracle must be able to *fail*, or check 1 above proves nothing.

    A checker that shares its subject's bug is the whole reason this file grew an
    oracle. So the oracle gets the same treatment: fed the two rules the sweep and
    the gate have actually been wrong about, it must disagree with them -- which is
    only possible if it is genuinely independent code.
    """

    def naive_word_chars(needle: str, haystack: str) -> bool:
        """The original broken rule: ``\\w`` on both sides, unconditionally."""
        return re.search(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", haystack) is not None

    def naive_unconditional(needle: str, haystack: str) -> bool:
        """The second broken rule: right alphanumeric class, but both sides always."""
        return re.search(r"(?<![^\W_])" + re.escape(needle) + r"(?![^\W_])", haystack) is not None

    # The markdown bypass: the oracle says "occurrence", the first broken rule says no.
    assert occurs_as_a_unit_oracle("John Smith", "_John Smith_") is True
    assert naive_word_chars("John Smith", "_John Smith_") is False
    # The punctuation-edge bypass: the oracle says "occurrence", the second says no.
    assert occurs_as_a_unit_oracle("(415) 555-0123", "tel(415) 555-0123") is True
    assert naive_unconditional("(415) 555-0123", "tel(415) 555-0123") is False
    # And it still refuses the false positive both broken rules got right.
    assert occurs_as_a_unit_oracle("Brown", "Browning") is False


async def test_a_prior_value_is_not_swept_inside_a_longer_word(env: Env) -> None:
    """The cross-call sweep uses the same word-boundary rule as the gate."""
    first = "Contact Ann today."
    await env.engine.obfuscate(
        env.session_id, first, [span(first, "Ann", "NAME")], strategy="tokenization"
    )
    second = "Announcement from Anniston: Ann will attend."
    result = await env.engine.obfuscate(env.session_id, second, [], strategy="tokenization")

    assert result.obfuscated_text.startswith("Announcement from Anniston: ")
    assert "Ann will" not in result.obfuscated_text
    assert len(result.spans) == 1


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_a_prior_value_is_swept_when_only_its_case_differs(env: Env, strategy: str) -> None:
    """The cross-call *probe* must be as case-blind as the sweep it feeds.

    Reaching a value vaulted on an earlier call takes two steps, and only the
    second is covered elsewhere: a cheap "does this original occur here at all?"
    scan decides whether the value becomes a sweep surface, and the sweep then
    matches case-insensitively. Making only the probe case-sensitive leaves the
    whole file green -- the multi-document test above puts "John Smith" in the
    second document in its vaulted casing, so the probe succeeds there whatever
    rule it uses, and the ``JOHN SMITH`` variant is only ever reached *after*.

    Here the vaulted surface appears in the second document in **no** other
    casing, so a case-sensitive probe never offers it and the original rides out
    in the clear.
    """
    first = "Patient John Smith was admitted."
    await env.engine.obfuscate(
        env.session_id, first, [span(first, "John Smith", "NAME")], strategy=strategy
    )
    record = await env.vault.get_by_original(env.session_id, "NAME", "john smith")
    assert record is not None

    second = "DISCHARGE SUMMARY FOR JOHN SMITH, SIGNED TODAY."
    result = await env.engine.obfuscate(env.session_id, second, [], strategy=strategy)

    assert "JOHN SMITH" not in result.obfuscated_text
    assert result.obfuscated_text == (f"DISCHARGE SUMMARY FOR {record.surrogate}, SIGNED TODAY.")
    assert len(result.spans) == 1
    assert second[result.spans[0].start : result.spans[0].end] == "JOHN SMITH"
    assert result.spans[0].surrogate == record.surrogate
    # No second row, and the payload declares the surrogate it actually carries.
    assert await env.vault.row_count(env.session_id) == 1
    assert [item.token_id for item in result.tokens] == [record.token_id]


async def test_the_sweep_claims_a_residual_with_its_longest_surface(env: Env) -> None:
    """A full name must outrank the bare surname it contains.

    "Smith" and "John Smith" are two distinct vault rows, and both match the same
    residual mention. The shorter one claiming it would splice the *surname's*
    surrogate over five characters and leave "John " standing in the clear -- a
    partial mask that reads as protected, restores to the wrong entity, and leaves
    the full original in the vault's set for the gate to block on. Ordering the
    sweep longest-first is what makes the containing surface win.
    """
    first = "Smith arrived. Later John Smith signed."
    await env.engine.obfuscate(
        env.session_id,
        first,
        [span(first, "Smith", "NAME", occurrence=0), span(first, "John Smith", "NAME")],
        strategy="tokenization",
    )
    full = await env.vault.get_by_original(env.session_id, "NAME", "john smith")
    surname = await env.vault.get_by_original(env.session_id, "NAME", "smith")
    assert full is not None and surname is not None
    assert full.surrogate != surname.surrogate

    # Second document, same session, detector silent: every surface is a prior one.
    second = "Follow-up scheduled for John Smith next week."
    result = await env.engine.obfuscate(env.session_id, second, [], strategy="tokenization")

    assert len(result.spans) == 1, [second[i.start : i.end] for i in result.spans]
    swept = result.spans[0]
    assert second[swept.start : swept.end] == "John Smith", "the longest surface must win"
    assert swept.surrogate == full.surrogate, "and it must be the full name's own surrogate"
    assert result.obfuscated_text == f"Follow-up scheduled for {full.surrogate} next week."
    assert "John" not in result.obfuscated_text, "the shorter surface left a fragment behind"
    assert "Smith" not in result.obfuscated_text


async def test_the_sweep_prefers_length_over_alphabetical_order(env: Env) -> None:
    """The same rule, on the one pair shape that can actually tell it apart.

    The sweep's order is ``(-len(surface), surface)``, and the test above is meant
    to pin the ``-len`` half. It cannot: with "Smith" and "John Smith" the longer
    surface *also* sorts first alphabetically, so deleting ``-len`` entirely leaves
    that test -- and the whole file -- green while the sweep silently changes
    behaviour. The data happened to sort correctly under the very rule it was
    supposed to be excluding.

    A **prefix** pair inverts the two orders, and that is the ordinary shape of the
    problem: a given name is vaulted on its own and again inside the full name.
    Alphabetically "Anna" comes first; by length "Anna Wilson" does. If the short
    surface wins, the sweep splices the *given name's* surrogate over four
    characters and leaves the real surname standing in the clear -- a partial mask
    that reads as protected and restores to the wrong entity.
    """
    short, full = "Anna", "Anna Wilson"
    # Premise, stated as executable fact: this pair separates the two orderings and
    # the pair used above does not.
    assert full.startswith(short)
    assert sorted([short, full])[0] == short, "alphabetically the SHORT surface wins"
    assert sorted(["Smith", "John Smith"])[0] == "John Smith", (
        "and in the test above the LONG one does -- which is why it cannot see this"
    )

    first = f"{short} arrived. Later {full} signed."
    await env.engine.obfuscate(
        env.session_id,
        first,
        [span(first, short, "NAME", occurrence=0), span(first, full, "NAME")],
        strategy="tokenization",
    )
    full_record = await env.vault.get_by_original(env.session_id, "NAME", "anna wilson")
    given_record = await env.vault.get_by_original(env.session_id, "NAME", "anna")
    assert full_record is not None and given_record is not None
    assert full_record.surrogate != given_record.surrogate

    # Second document, same session, detector silent: every surface is a prior one.
    second = f"Follow-up scheduled for {full} next week."
    result = await env.engine.obfuscate(env.session_id, second, [], strategy="tokenization")

    assert len(result.spans) == 1, [second[i.start : i.end] for i in result.spans]
    swept = result.spans[0]
    assert second[swept.start : swept.end] == full, "the longest surface must win"
    assert swept.surrogate == full_record.surrogate
    assert result.obfuscated_text == f"Follow-up scheduled for {full_record.surrogate} next week."
    assert "Wilson" not in result.obfuscated_text, "the surname was left standing in the clear"
    assert short not in result.obfuscated_text


async def test_the_sweep_lands_in_the_same_place_however_a_surface_arrived(
    env: Env,
) -> None:
    """The sweep order is a total order on the surfaces, not on how they got there.

    Two equal-length surfaces can both match one residual region, and only one can
    claim it. They reach the sweep by two routes that order their contributions
    differently: this call's detections arrive in *offset* order, an earlier call's
    vault rows arrive in *sorted* order. Ordering by length alone is a partial
    order, so on a length tie Python's stable sort quietly falls back to whichever
    route inserted first -- and the identical document then masks a different span
    depending on which call happened to vault the value. The lexicographic
    tie-break makes the choice a function of the surfaces themselves, which is the
    only version of "masked everywhere" that means anything.
    """
    head = "Dana Cole and Cole Ross met."
    tail = "Notes mention Dana Cole Ross in the margin."

    # Route 1: both values vaulted by an EARLIER call. The sweep reads them out of
    # the vault, sorted -- so "Cole Ross" is offered first.
    prior_session, _expires = await env.sessions.create("test-user")
    await env.engine.obfuscate(
        prior_session,
        head,
        [span(head, "Dana Cole", "NAME"), span(head, "Cole Ross", "NAME")],
        strategy="tokenization",
    )
    from_prior = await env.engine.obfuscate(prior_session, tail, [], strategy="tokenization")
    prior_spans = sorted((item.start, item.end) for item in from_prior.spans)

    # Route 2: both values detected in THIS call. The sweep reads them off the
    # planned detections, in offset order -- so "Dana Cole" is offered first.
    same_session, _expires = await env.sessions.create("test-user")
    document = f"{head} {tail}"
    offset = len(head) + 1
    from_same = await env.engine.obfuscate(
        same_session,
        document,
        [span(document, "Dana Cole", "NAME"), span(document, "Cole Ross", "NAME")],
        strategy="tokenization",
    )
    same_spans = sorted(
        (item.start - offset, item.end - offset) for item in from_same.spans if item.start >= offset
    )

    assert prior_spans == same_spans, (
        f"the sweep landed on {[tail[s:e] for s, e in prior_spans]} when the surface "
        f"came from the vault, but on {[tail[s:e] for s, e in same_spans]} when it "
        f"came from this call's detections"
    )
    # Pinned, not merely consistent: a membership test would pass with both routes
    # agreeing on the wrong span. Lexicographic order settles the length tie.
    assert len(prior_spans) == 1
    start, end = prior_spans[0]
    assert tail[start:end] == "Cole Ross"


async def test_case_and_whitespace_variants_collapse_to_one_row(env: Env) -> None:
    text = "John Smith met JOHN  SMITH and john smith."
    detections = [
        span(text, "John Smith", "NAME"),
        span(text, "JOHN  SMITH", "NAME"),
        span(text, "john smith", "NAME"),
    ]
    result = await env.engine.obfuscate(env.session_id, text, detections, strategy="tokenization")
    assert len(result.tokens) == 1
    assert await env.vault.row_count(env.session_id) == 1
    surrogate = result.tokens[0].surrogate
    assert result.obfuscated_text.count(surrogate) == 3
    # A count of three is satisfiable while a variant rides through untouched
    # somewhere else in the string, so pin the whole document and every variant.
    assert result.obfuscated_text == f"{surrogate} met {surrogate} and {surrogate}."
    for variant in ("John Smith", "JOHN  SMITH", "john smith"):
        assert variant not in result.obfuscated_text
    # One row, and it round-trips to the first surface form seen.
    assert await env.vault.get_by_surrogate(env.session_id, surrogate) == "John Smith"


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_second_call_in_one_session_reuses_the_first_mapping(env: Env, strategy: str) -> None:
    text = "Contact John Smith about 123-45-6789."
    detections = [span(text, "John Smith", "NAME"), span(text, "123-45-6789", "SSN")]

    first = await env.engine.obfuscate(env.session_id, text, detections, strategy=strategy)
    second = await env.engine.obfuscate(env.session_id, text, detections, strategy=strategy)

    assert first.obfuscated_text == second.obfuscated_text
    assert surrogates_by_type(first.tokens) == surrogates_by_type(second.tokens)
    assert await env.vault.row_count(env.session_id) == 2
    # Two documents that agree with each other can agree on doing nothing, so pin
    # that both actually obfuscated, and that the token IDs -- not just the
    # surrogate strings -- are the reused ones.
    assert {record.entity_type for record in first.tokens} == {"NAME", "SSN"}
    assert [record.token_id for record in first.tokens] == [
        record.token_id for record in second.tokens
    ]
    for original in ("John Smith", "123-45-6789"):
        assert original not in second.obfuscated_text


async def test_a_value_the_session_already_mapped_is_never_re_derived(
    env: Env, caplog: pytest.LogCaptureFixture, strategy_registry_guard: None
) -> None:
    """Reuse is a *decision*, not a coincidence of the vault being idempotent.

    ``_resolve_groups`` short-circuits on a value the session already holds. Delete
    that branch and the payload does not move one byte -- ``SessionVault.put`` is
    idempotent per ``(entity_type, normalize(original))``, so the second write is a
    no-op and the read-back hands back the first record. The test above stays green,
    and so does every other assertion about output. That is precisely why this one
    exists: it asks the two questions the payload cannot answer.

    First, the operational one. Re-deriving an already-mapped value is *guaranteed*
    to look like a collision, because the value collides with **itself**: its token
    ID is taken (by its own row), every fake the guard draws is either the vaulted
    surrogate or a value already in the originals set, and the vault then reports a
    re-derivation. A repeat mention -- the most ordinary thing a document does --
    would emit a burst of collision warnings on every call, which is not a cosmetic
    complaint: it makes a *genuine* 32-bit token collision, the one failure that
    can restore two entities to one value, unfindable in the noise.

    Second, the interface one. Nothing in :class:`ObfuscationStrategy` promises that
    generating a surrogate is cheap, pure, or even repeatable, and the engine is
    what makes "one value, one mapping, forever" true regardless. Asking twice also
    burns the whole ``MAX_FAKE_ATTEMPTS`` budget to arrive back where it started.
    """
    text = "Patient John Smith, MRN 4429183, seen today."
    detections = [span(text, "John Smith", "NAME"), span(text, "4429183", "MRN")]
    first = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="pseudonymization"
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="secure_context_pipeline.obfuscation"):
        second = await env.engine.obfuscate(
            env.session_id, text, detections, strategy="pseudonymization"
        )
    complaints = [
        f"{record.name}: {record.getMessage()}"
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and record.name.startswith("secure_context_pipeline.obfuscation")
    ]

    # Control: the call really did happen and really did reuse the mapping, so an
    # empty warning list below is silence about work done, not silence about
    # nothing happening.
    assert second.obfuscated_text == first.obfuscated_text
    assert [record.token_id for record in second.tokens] == [
        record.token_id for record in first.tokens
    ]
    assert len(second.tokens) == 2
    assert await env.vault.row_count(env.session_id) == 2
    assert complaints == [], "a repeat mention was reported as a collision"

    # And the strategy itself is asked once per distinct value, not once per call.
    @register_strategy
    class CountingStrategy(ObfuscationStrategy):
        """Records every value it is asked to generate a surrogate for."""

        name = "counting-once"
        asked: ClassVar[list[str]] = []

        async def make_surrogate(
            self,
            detection: Detection,
            token_id: str,
            vault: SessionVault,
            *,
            session_id: str,
        ) -> str:
            CountingStrategy.asked.append(normalize(detection.text))
            return f"<<{token_id}>>"

    other = "Contact Ann Lee about 123-45-6789."
    spans = [span(other, "Ann Lee", "NAME"), span(other, "123-45-6789", "SSN")]
    once = await env.engine.obfuscate(env.session_id, other, spans, strategy="counting-once")
    twice = await env.engine.obfuscate(env.session_id, other, spans, strategy="counting-once")

    assert CountingStrategy.asked == ["ann lee", "123-45-6789"], CountingStrategy.asked
    assert twice.obfuscated_text == once.obfuscated_text
    assert await env.vault.row_count(env.session_id) == 4


#: A surrogate the strategy below returns but never writes to the vault. If this
#: string ever reaches a payload, that payload carries a token nothing can restore.
NEVER_VAULTED = "<<surrogate-that-was-never-vaulted>>"


async def test_the_payload_carries_the_surrogate_the_vault_actually_holds(
    env: Env, strategy_registry_guard: None
) -> None:
    """The vault -- not the strategy's return value -- decides what goes on the wire.

    ``_resolve_groups`` renders a surrogate, writes it, and then **reads the row
    back**, splicing whatever the vault says it holds. On the ordinary path the two
    are the same string and the read-back looks like ceremony, which is why
    replacing it with the record the engine just built passes every other test in
    this file. It is not ceremony: ``SessionVault.put`` is idempotent per
    ``(entity_type, normalize(original))``, so if anything else vaulted this value
    first, our write is a **no-op** and the row the session actually holds is
    someone else's. Splicing our own discarded string then puts a surrogate in the
    payload that ``get_by_surrogate`` cannot resolve -- the caller reads a fake as
    though it were the answer, and restoration silently returns nothing.

    In production the other writer is a second ``obfuscate`` coroutine on the same
    session. Racing two calls here would make the test a coin flip on scheduling,
    so the strategy below *is* the other writer: it stores the row itself, then
    returns a different string. Deterministic, same collision, same question --
    which of the two strings reached the payload.
    """

    @register_strategy
    class RaceLoserStrategy(ObfuscationStrategy):
        """Vaults the value itself before returning a surrogate it never stored."""

        name = "race-loser"
        vaulted: ClassVar[str] = ""

        async def make_surrogate(
            self,
            detection: Detection,
            token_id: str,
            vault: SessionVault,
            *,
            session_id: str,
        ) -> str:
            RaceLoserStrategy.vaulted = f"[PII_NAME_{token_id}]"
            await vault.put(
                session_id,
                TokenRecord(
                    session_id=session_id,
                    token_id=token_id,
                    entity_type=detection.entity_type,
                    category=detection.category,
                    surrogate=RaceLoserStrategy.vaulted,
                    created_at=time.time(),
                ),
                detection.text,
            )
            return NEVER_VAULTED

    text = "Patient John Smith is stable."
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "John Smith", "NAME")], strategy="race-loser"
    )

    winner = RaceLoserStrategy.vaulted
    # Premise: the two strings really are different, and exactly one row exists --
    # the engine's own put found the value already there and did nothing.
    assert winner and winner != NEVER_VAULTED
    assert await env.vault.row_count(env.session_id) == 1

    assert NEVER_VAULTED not in result.obfuscated_text, (
        "the payload carries a surrogate no vault row holds; it can never be restored"
    )
    assert result.obfuscated_text == f"Patient {winner} is stable."
    assert [record.surrogate for record in result.tokens] == [winner]
    assert [entry.surrogate for entry in result.spans] == [winner]
    # The decisive property, asked of the vault rather than of the engine: every
    # surrogate the payload declares resolves back to the original it stands for.
    for record in result.tokens:
        assert await env.vault.get_by_surrogate(env.session_id, record.surrogate) == "John Smith"
    with pytest.raises(VaultMissError):
        await env.vault.get_by_surrogate(env.session_id, NEVER_VAULTED)


# ---------------------------------------------------------------------------
# 7. Tier dispatch
# ---------------------------------------------------------------------------


async def test_tier3_diagnosis_emits_a_class_annotated_token_from_the_gazetteer(
    env: Env,
) -> None:
    text = "Assessment: diabetes mellitus, controlled on metformin."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "diabetes mellitus", "DIAGNOSIS"), span(text, "metformin", "MEDICATION")],
        strategy="pseudonymization",
    )
    fakes = surrogates_by_type(result.tokens)

    diagnosis = STRICT_TOKEN_RE.fullmatch(fakes["DIAGNOSIS"])
    assert diagnosis is not None, fakes["DIAGNOSIS"]
    assert diagnosis.group(4) == gazetteer_hint("diagnoses.txt", "diabetes mellitus")

    medication = STRICT_TOKEN_RE.fullmatch(fakes["MEDICATION"])
    assert medication is not None, fakes["MEDICATION"]
    assert medication.group(4) == gazetteer_hint("medications.txt", "metformin")

    # The hint is class-level only: the term itself never survives.
    assert "diabetes mellitus" not in result.obfuscated_text
    assert "metformin" not in result.obfuscated_text


async def test_tier3_with_hint_false_emits_a_plain_token(env: Env) -> None:
    """A config-only change -- one registry field -- turns the annotation off."""
    registry = with_spec(env.registry, "DIAGNOSIS", hint=False)
    engine = ObfuscationEngine(
        registry=registry,
        vault=env.vault,
        session_registry=env.sessions,
        settings=env.settings,
        audit=env.audit,
    )
    text = "Assessment: diabetes mellitus today."
    result = await engine.obfuscate(
        env.session_id,
        text,
        [span(text, "diabetes mellitus", "DIAGNOSIS")],
        strategy="pseudonymization",
    )
    assert len(result.tokens) == 1
    record = result.tokens[0]
    surrogate = record.surrogate
    match = STRICT_TOKEN_RE.fullmatch(surrogate)
    assert match is not None
    assert match.group(4) is None, surrogate
    assert "|" not in surrogate
    assert surrogate == f"[PHI_DIAGNOSIS_{record.token_id}]"
    # Only the hint went away: the term itself is still masked and still restorable.
    assert result.obfuscated_text == f"Assessment: {surrogate} today."
    assert await env.vault.get_by_surrogate(env.session_id, surrogate) == "diabetes mellitus"


async def test_tier4_numerics_stay_plain_tokens(env: Env) -> None:
    """No fake (corrupts magnitude), no hint (leaks magnitude)."""
    text = "Labs: A1C 7.2 today. Settlement of $250,000 offered."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [
            span(text, "A1C 7.2", "LAB_RESULT"),
            span(text, "Settlement of $250,000", "SETTLEMENT_TERM"),
        ],
        strategy="pseudonymization",
    )
    fakes = surrogates_by_type(result.tokens)
    assert set(fakes) == {"LAB_RESULT", "SETTLEMENT_TERM"}, "an empty loop proves nothing"
    for record in result.tokens:
        assert STRICT_TOKEN_RE.fullmatch(record.surrogate), record.surrogate
        assert "|" not in record.surrogate
        # A plain token embeds nothing but the category, the type and the ID -- no
        # magnitude, no digit count, no rounded stand-in.
        assert record.surrogate == (
            f"[{CATEGORY_OF[record.entity_type].value}_{record.entity_type}_{record.token_id}]"
        )
    assert "7.2" not in result.obfuscated_text
    assert "250,000" not in result.obfuscated_text
    assert result.obfuscated_text == (
        f"Labs: {fakes['LAB_RESULT']} today. {fakes['SETTLEMENT_TERM']} offered."
    )


async def test_unknown_entity_type_is_handled_opaquely(env: Env) -> None:
    """The engine never looks an entity name up in code -- an unknown one still works."""
    text = "Reference PASSPORT X1234567 attached."
    detection = Detection(
        entity_type="PASSPORT_NUMBER",
        category=EntityCategory.PII,
        start=text.index("X1234567"),
        end=text.index("X1234567") + 8,
        text="X1234567",
        score=0.9,
    )
    for strategy in BOTH_MODES:
        session_id, _ = await env.sessions.create("test-user")
        result = await env.engine.obfuscate(session_id, text, [detection], strategy=strategy)
        assert len(result.tokens) == 1, strategy
        record = result.tokens[0]
        surrogate = record.surrogate
        assert STRICT_TOKEN_RE.fullmatch(surrogate), surrogate
        # The conservative default is a *plain* token: an unknown type has no tier,
        # so it must get neither a format-preserving fake nor a class hint.
        assert surrogate == f"[PII_PASSPORT_NUMBER_{record.token_id}]", strategy
        assert "X1234567" not in result.obfuscated_text
        assert result.obfuscated_text == f"Reference PASSPORT {surrogate} attached."
        assert await env.vault.get_by_surrogate(session_id, surrogate) == "X1234567"


# ---------------------------------------------------------------------------
# 8. Pluggability
# ---------------------------------------------------------------------------


async def test_dummy_strategy_plugs_in_with_zero_engine_changes(
    env: Env, strategy_registry_guard: None
) -> None:
    """Adding a strategy is one class + one registry entry. Nothing else moves."""

    @register_strategy
    class ShoutingStrategy(ObfuscationStrategy):
        name = "shouting-dummy"
        seen: ClassVar[list[str]] = []

        async def make_surrogate(
            self,
            detection: Detection,
            token_id: str,
            vault: SessionVault,
            *,
            session_id: str,
        ) -> str:
            ShoutingStrategy.seen.append(detection.entity_type)
            return f"<<{detection.entity_type}:{token_id}>>"

    assert "shouting-dummy" in available_strategies()
    assert build_strategy("shouting-dummy", env.context()).name == "shouting-dummy"

    text = "Patient John Smith, SSN 123-45-6789."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "John Smith", "NAME"), span(text, "123-45-6789", "SSN")],
        strategy="shouting-dummy",
    )

    assert ShoutingStrategy.seen == ["NAME", "SSN"]
    assert [record.entity_type for record in result.tokens] == ["NAME", "SSN"]
    for record in result.tokens:
        assert record.surrogate == f"<<{record.entity_type}:{record.token_id}>>"
        assert record.surrogate in result.obfuscated_text
    # The engine still did its own job around the custom strategy: dedupe, vault,
    # splice and round-trip, none of which the strategy participates in.
    assert await env.vault.row_count(env.session_id) == 2
    by_type = surrogates_by_type(result.tokens)
    assert result.obfuscated_text == (f"Patient {by_type['NAME']}, SSN {by_type['SSN']}.")
    assert await env.vault.get_by_surrogate(env.session_id, by_type["NAME"]) == "John Smith"
    assert await env.vault.get_by_surrogate(env.session_id, by_type["SSN"]) == "123-45-6789"


async def test_unknown_strategy_name_fails_loudly(env: Env) -> None:
    text = "Patient John Smith."
    with pytest.raises(ConfigError) as excinfo:
        await env.engine.obfuscate(
            env.session_id, text, [span(text, "John Smith", "NAME")], strategy="nope"
        )
    # "A ConfigError was raised" is satisfied by an unrelated config failure -- a
    # broken registry load would pass it while the silent-fallback hole stayed open.
    assert excinfo.value.detail["reason"] == "unknown_strategy"
    assert excinfo.value.detail["strategy"] == "nope"
    # Failing loudly must also mean failing *closed*: nothing was vaulted, so there
    # is no half-obfuscated session left behind.
    assert await env.vault.row_count(env.session_id) == 0


async def test_per_entity_strategy_override_is_config_only(env: Env) -> None:
    """``strategy:`` on one entity re-routes only that entity."""
    registry = with_spec(env.registry, "SSN", strategy="tokenization")
    engine = ObfuscationEngine(
        registry=registry,
        vault=env.vault,
        session_registry=env.sessions,
        settings=env.settings,
        audit=env.audit,
    )
    text = "John Smith, SSN 123-45-6789."
    result = await engine.obfuscate(
        env.session_id,
        text,
        [span(text, "John Smith", "NAME"), span(text, "123-45-6789", "SSN")],
        strategy="pseudonymization",
    )
    fakes = surrogates_by_type(result.tokens)
    assert STRICT_TOKEN_RE.fullmatch(fakes["SSN"]), fakes["SSN"]
    assert not STRICT_TOKEN_RE.fullmatch(fakes["NAME"]), "NAME still pseudonymized"
    # Re-routing an entity must not stop protecting it: the surrogate shape is
    # only half the claim, and "which mode" is worthless if the value stayed put.
    ssn_record = next(item for item in result.tokens if item.entity_type == "SSN")
    assert fakes["SSN"] == f"[PII_SSN_{ssn_record.token_id}]"
    assert result.obfuscated_text == f"{fakes['NAME']}, SSN {fakes['SSN']}."
    for original in ("John Smith", "123-45-6789"):
        assert original not in result.obfuscated_text
    assert await env.vault.get_by_surrogate(env.session_id, fakes["SSN"]) == "123-45-6789"


@pytest.mark.parametrize(
    ("run_strategy", "overridden", "override"),
    [
        ("pseudonymization", "SSN", "tokenization"),
        ("tokenization", "NAME", "pseudonymization"),
    ],
)
async def test_a_per_entity_strategy_override_restores_in_both_directions(
    env: Env, run_strategy: str, overridden: str, override: str
) -> None:
    """A ``strategy:`` override must survive the *restore*, whichever way it points.

    The test above stops at ``ObfuscationEngine.obfuscate`` and exercises one
    direction: ``strategy: tokenization`` on SSN inside a pseudonymization run.
    That is the direction that could not fail. The opposite one --
    ``strategy: pseudonymization`` on NAME inside a **tokenization** run -- is the
    same registry mechanism pointed the other way, and it was silently broken,
    because restoring a pseudonym is not keyed on the run's strategy at all: it is
    keyed on the caller handing :meth:`Restorer.restore` a surrogate map.
    ``PipelineOrchestrator._surrogate_map`` used to short-circuit on the run's
    strategy string, so under tokenization it returned ``None``, the surrogate pass
    never ran, and the invented name reached the caller as the answer.

    Both rows below arrive at the **same payload shape from opposite
    configurations** -- NAME a pseudonym, SSN a hash token -- and that symmetry is
    the whole argument. One observed pair (the fakes are session-keyed, so the
    names differ per run): row 1 emitted ``Todd Santos, SSN [PII_SSN_2f04d083].``
    and row 2 emitted ``Ashley Thomas, SSN [PII_SSN_b7567176].`` -- two payloads a
    reader cannot tell apart, one of which used to restore and one of which did
    not. The run's strategy string is therefore the wrong thing to decide
    restoration by, and the *shape of what was actually emitted* is the only thing
    that cannot drift from what the payload contains.

    Nothing in the broken direction had a shape to notice it by, which is why it
    needed a test rather than a counter. A leftover ``[PII_SSN_...]`` is visibly
    wrong and trips ``_assert_no_tokens``; a leftover pseudonym is a well-formed
    human name in a sentence about a patient. Measured with the map withheld from
    the restorer, row 2 answered ``Summary: Mark Ramos, SSN 123-45-6789.`` -- the
    SSN correct, the patient a person who does not exist -- carrying
    ``restored_count=1``, ``vault_misses=0``, ``surrogate_misses=0``,
    ``surrogates_seen=0`` and ``surrogates_suspected_unrestored=0``. Every counter
    built to catch this was silent, because the pass that would have looked never
    ran.

    The map is built by the pipeline's own ``_surrogate_map`` rather than rebuilt
    here, and that is deliberate: a local copy of the rule would keep this test
    green in exactly the case it exists to catch -- the shipped orchestrator
    handing the restorer nothing.
    """
    registry = with_spec(env.registry, overridden, strategy=override)
    engine = ObfuscationEngine(
        registry=registry,
        vault=env.vault,
        session_registry=env.sessions,
        settings=env.settings,
        audit=env.audit,
    )
    text = "John Smith, SSN 123-45-6789."
    result = await engine.obfuscate(
        env.session_id,
        text,
        [span(text, "John Smith", "NAME"), span(text, "123-45-6789", "SSN")],
        strategy=run_strategy,
    )
    fakes = surrogates_by_type(result.tokens)
    # The premise, asserted rather than assumed: both rows really did land on the
    # same payload shape, or the two directions are not being compared at all.
    assert not STRICT_TOKEN_RE.fullmatch(fakes["NAME"]), fakes["NAME"]
    assert STRICT_TOKEN_RE.fullmatch(fakes["SSN"]), fakes["SSN"]
    assert result.obfuscated_text == f"{fakes['NAME']}, SSN {fakes['SSN']}."
    for original in ("John Smith", "123-45-6789"):
        assert original not in result.obfuscated_text

    # Unbound: `_surrogate_map` reads nothing off `self`, and building a real
    # PipelineOrchestrator here would drag in the store, detector, injector, gate
    # and provider for a pure function over TokenRecords.
    surrogates = PipelineOrchestrator._surrogate_map(None, result.tokens)  # type: ignore[arg-type]
    assert surrogates == {fakes["NAME"]: ""}, (
        f"{run_strategy} run: the map handed to the restorer must be the pseudonym, "
        "and only the pseudonym"
    )

    restorer = Restorer(vault=env.vault, settings=env.settings, audit=env.audit)
    restored = await restorer.restore(
        env.session_id,
        f"Summary: {result.obfuscated_text}",
        strategy=run_strategy,
        # Exactly what `PipelineOrchestrator.run` passes at step 8, so the test is
        # asking what the shipped pipeline gets back, not what the restorer can do.
        surrogates=surrogates,
        issued={record.token_id for record in result.tokens},
    )
    assert restored.text == "Summary: John Smith, SSN 123-45-6789."
    # Stated separately from the equality above because this is the half that fails
    # silently: the fake is an ordinary name, so its survival changes nothing a
    # reader could see.
    assert fakes["NAME"] not in restored.text
    assert restored.restored_count == 2
    assert restored.vault_misses == 0
    assert restored.surrogates_seen == 1
    assert restored.tokens_seen == 1
    assert restored.surrogates_suspected_unrestored == 0


# ---------------------------------------------------------------------------
# 9. action: strip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_privileged_marker_is_stripped_in_both_modes(env: Env, strategy: str) -> None:
    text = "PRIVILEGED AND CONFIDENTIAL. Memo to John Smith regarding the filing."
    detections = [
        span(text, "PRIVILEGED AND CONFIDENTIAL", "PRIVILEGED_MARKER"),
        span(text, "John Smith", "NAME"),
    ]
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy=strategy, doc_category="legal"
    )

    assert "PRIVILEGED" not in result.obfuscated_text
    assert "CONFIDENTIAL" not in result.obfuscated_text
    assert "REDACTED_PRIVILEGED_MARKER" not in result.obfuscated_text
    assert result.obfuscated_text.startswith(". Memo to ")

    # No surrogate, no vault entry -- only the NAME was stored.
    assert [record.entity_type for record in result.tokens] == ["NAME"]
    assert await env.vault.row_count(env.session_id) == 1
    assert len(result.stripped) == 1
    assert result.stripped[0].entity_type == "PRIVILEGED_MARKER"

    stripped_span = next(item for item in result.spans if item.entity_type == "PRIVILEGED_MARKER")
    assert stripped_span.action is EntityAction.STRIPPED
    assert stripped_span.surrogate is None

    events = await env.audit.query(session_id=env.session_id, event_type=STRIP)
    assert len(events) == 1
    assert events[0].entity_type == "PRIVILEGED_MARKER"
    assert events[0].token_id is None
    assert events[0].detail["span_chars"] == len("PRIVILEGED AND CONFIDENTIAL")


async def test_strip_does_not_leave_a_doubled_space(env: Env) -> None:
    text = "Memo marked attorney-client and sent on."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "attorney-client", "PRIVILEGED_MARKER")],
        strategy="tokenization",
    )
    assert result.obfuscated_text == "Memo marked and sent on."


# ---------------------------------------------------------------------------
# 10. action: redact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_case_strategy_is_force_redacted_in_both_modes(env: Env, strategy: str) -> None:
    text = "Background. Our litigation strategy is to delay until discovery closes."
    detection = span(
        text,
        "Our litigation strategy is to delay until discovery closes",
        "CASE_STRATEGY",
        score=0.99,
    )
    result = await env.engine.obfuscate(
        env.session_id, text, [detection], strategy=strategy, doc_category="legal"
    )

    assert result.obfuscated_text == f"Background. {format_redaction('CASE_STRATEGY')}."
    assert "[REDACTED_CASE_STRATEGY]" in result.obfuscated_text
    assert result.tokens == []
    assert await env.vault.row_count(env.session_id) == 0
    assert env.vault.originals_for_session(env.session_id) == frozenset()
    assert len(result.redactions) == 1
    assert result.redactions[0].entity_type == "CASE_STRATEGY"

    assert result.spans[0].action is EntityAction.REDACTED
    assert result.spans[0].surrogate is None

    events = await env.audit.query(session_id=env.session_id, event_type=REDACT)
    assert len(events) == 1
    assert events[0].entity_type == "CASE_STRATEGY"
    assert events[0].detail["reason"] == "policy_redact"
    assert events[0].token_id is None

    # A forced redaction is irreversible by construction: nothing to look up.
    with pytest.raises(VaultMissError):
        await env.vault.get_by_surrogate(env.session_id, "[REDACTED_CASE_STRATEGY]")


# ---------------------------------------------------------------------------
# 11. Threshold band
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_mid_confidence_span_is_redacted_without_a_vault_entry(
    env: Env, strategy: str
) -> None:
    assert env.settings.threshold_redact <= 0.4 < env.settings.threshold_obfuscate
    text = "Possible SSN 123-45-6789 in the scan."
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "123-45-6789", "SSN", score=0.4)], strategy=strategy
    )

    assert result.obfuscated_text == "Possible SSN [REDACTED_SSN] in the scan."
    assert result.tokens == []
    assert await env.vault.row_count(env.session_id) == 0
    assert result.redactions[0].score == pytest.approx(0.4)

    events = await env.audit.query(session_id=env.session_id, event_type=REDACT)
    assert events[0].detail["reason"] == "below_obfuscate_threshold"


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_a_redact_band_residual_is_masked_rather_than_left_for_the_gate(
    env: Env, strategy: str
) -> None:
    """The band's own needle must not be the thing that refuses the document.

    A redact-band detection gets ``[REDACTED_<TYPE>]``, no vault row, and -- since
    ``note_unrestorable`` -- a gate needle, so the EgressGate scans the outbound
    payload for a value the engine masked in exactly one place. Real documents state
    a number twice and the detector types it once: ``Member SSN 452189376 verified
    against payer records.`` is ``SSN@0.40`` on the shipped detector, while ``Ledger
    reference 452189376 appears in the reconciliation table.`` is nothing at all. The
    second mention therefore went out verbatim, pass 1 found the needle this call had
    just planted, and the request came back ``422
    EGRESS_BLOCKED(reason='vault_original')`` -- three of three ordinary financial
    shapes, measured through the real ASGI app.

    Redacting the residual is the same decision the call already made about the same
    value. The alternative on offer is not a safer masking, it is the identical
    policy plus a discarded document.

    The gate's own pass 1 supplies the verdict rather than this test restating it:
    ``_scan_originals`` is the code that used to block, run here over the real
    originals set, with the unswept text as the control so a zero cannot mean "the
    needle was never planted".
    """
    assert env.settings.threshold_redact <= 0.4 < env.settings.threshold_obfuscate
    value = "452189376"
    text = (
        f"Member SSN {value} verified against payer records.\n"
        f"Ledger reference {value} appears in the reconciliation table.\n"
    )
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, value, "SSN", score=0.4)], strategy=strategy
    )

    marker = format_redaction("SSN")
    assert value not in result.obfuscated_text, "the untyped second mention stayed in the clear"
    assert result.obfuscated_text == (
        f"Member SSN {marker} verified against payer records.\n"
        f"Ledger reference {marker} appears in the reconciliation table.\n"
    )

    # Still un-restorable and still a needle: the sweep must not have quietly turned
    # a redaction into a tokenization to get the payload clean.
    assert result.tokens == []
    assert await env.vault.row_count(env.session_id) == 0
    assert value in env.vault.originals_for_session(env.session_id)

    # Both occurrences are reported as what they are, and neither invents a surrogate
    # that nothing could restore.
    assert [item.action for item in result.spans] == [EntityAction.REDACTED] * 2
    assert [item.surrogate for item in result.spans] == [None, None]
    assert [text[item.start : item.end] for item in result.spans] == [value, value]
    assert len(result.redactions) == 2, "the stat strip must count the splice it made"
    assert {item.entity_type for item in result.redactions} == {"SSN"}

    gate = egress_gate.EgressGate(vault=env.vault, detector=SilentDetector(), settings=env.settings)
    originals = env.vault.originals_for_session(env.session_id)
    assert gate._scan_originals(result.obfuscated_text, originals) == 0, "released, not refused"
    assert gate._scan_originals(text, originals) == 1, (
        "control: unswept, the gate finds the needle this call planted and blocks"
    )


async def test_the_redact_band_sweep_leaves_policy_redactions_and_glued_runs_alone(
    env: Env,
) -> None:
    """Both boundaries of the redact-band sweep, in the one place they can be compared.

    **Policy redactions are out of scope**, for the reason ``note_unrestorable``
    gives: an ``action: redact`` span like ``CASE_STRATEGY`` is a *sentence*, not a
    value, and its phrasing legitimately recurs -- sweeping it would rewrite ordinary
    prose, and it is not a gate needle either, so there is nothing to protect. Only
    ``below_obfuscate_threshold`` redactions are swept.

    **The word-boundary rule still binds.** ``ledgerref452189376x`` is not an
    occurrence of ``452189376`` by :func:`textrules.occurs_as_a_unit`, so the sweep
    cannot reach it -- and it must not, or ``Browning`` stops containing ``Brown``.
    The gate scans digit-carrying values with no adjacency rule at all, so it blocks
    that payload: the glued shape is precisely the leak ``note_unrestorable`` was
    written to catch, and the two components disagreeing here is the safe direction.
    """
    sentence = "Our litigation strategy is to delay until discovery closes"
    text = f"Background. {sentence}. As stated: {sentence}."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, sentence, "CASE_STRATEGY", score=0.99)],
        strategy="tokenization",
        doc_category="legal",
    )
    assert result.obfuscated_text == (
        f"Background. {format_redaction('CASE_STRATEGY')}. As stated: {sentence}."
    ), "a policy redaction was swept across the document"
    assert env.vault.originals_for_session(env.session_id) == frozenset(), "not a needle either"
    assert len(result.redactions) == 1

    value = "452189376"
    glued = f"Member SSN {value} verified. Internal ledgerref{value}x follows.\n"
    swept = await env.engine.obfuscate(
        env.session_id, glued, [span(glued, value, "SSN", score=0.4)], strategy="tokenization"
    )
    assert swept.obfuscated_text == (
        f"Member SSN {format_redaction('SSN')} verified. Internal ledgerref{value}x follows.\n"
    ), "the sweep reached inside a longer alphanumeric run"

    gate = egress_gate.EgressGate(vault=env.vault, detector=SilentDetector(), settings=env.settings)
    originals = env.vault.originals_for_session(env.session_id)
    assert gate._scan_originals(swept.obfuscated_text, originals) >= 1, (
        "the glued run is the disclosure note_unrestorable exists to block"
    )


async def test_a_redaction_marker_never_claims_a_surface_the_vault_can_restore(
    env: Env,
) -> None:
    """The redact-band sweep is a floor, not an override: the row wins.

    A value can be vaulted on Monday's discharge summary at 0.90 and re-detected in
    Tuesday's referral letter at 0.40, and the band is decided per call. If the
    redact-band surface outranked the prior-call one, every residual of that value
    would be spliced with ``[REDACTED_SSN]`` -- irreversibly, for a value the vault
    holds a key for -- and the user would read a hole where the restorer could have
    put the number back. An irreversible mask on a restorable value is a lost answer,
    not a safer one, so the marker is added last and only by ``setdefault``.

    The detected mention is still redacted: that is this call's banding decision and
    it is not the sweep's to overrule. What the sweep decides is the *residual*, and
    it decides it with the surrogate.
    """
    value = "452189376"
    seed = f"Claim for SSN {value} was reprocessed."
    await env.engine.obfuscate(
        env.session_id, seed, [span(seed, value, "SSN", score=0.9)], strategy="tokenization"
    )
    record = await env.vault.get_by_original(env.session_id, "SSN", normalize(value))
    assert record is not None, "premise: the earlier call vaulted it"

    text = (
        f"Member SSN {value} verified against payer records.\n"
        f"Ledger reference {value} appears in the reconciliation table.\n"
    )
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, value, "SSN", score=0.4)], strategy="tokenization"
    )

    assert result.obfuscated_text == (
        f"Member SSN {format_redaction('SSN')} verified against payer records.\n"
        f"Ledger reference {record.surrogate} appears in the reconciliation table.\n"
    ), "the residual lost its restorable mask to the band's marker"
    assert record.token_id in {item.token_id for item in result.tokens}, (
        "a surrogate reached the payload undeclared, so nothing will restore it"
    )
    assert await env.vault.row_count(env.session_id) == 1, "one value, still one row"


async def test_below_the_redact_floor_the_span_is_left_alone(env: Env) -> None:
    text = "Maybe 123-45-6789 is a serial number."
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "123-45-6789", "SSN", score=0.1)]
    )
    assert result.obfuscated_text == text
    assert result.tokens == []
    assert result.redactions == []
    assert result.spans == []


async def test_per_entity_threshold_override_is_honoured(env: Env) -> None:
    registry = with_spec(env.registry, "SSN", threshold=0.95)
    engine = ObfuscationEngine(
        registry=registry,
        vault=env.vault,
        session_registry=env.sessions,
        settings=env.settings,
        audit=env.audit,
    )
    text = "SSN 123-45-6789 on file."
    result = await engine.obfuscate(
        env.session_id, text, [span(text, "123-45-6789", "SSN", score=0.9)]
    )
    assert result.obfuscated_text == "SSN [REDACTED_SSN] on file."
    assert result.tokens == []
    # Redaction above the redact floor is irreversible by design: no vault row.
    assert await env.vault.row_count(env.session_id) == 0
    # ... and irreversible is asserted directly rather than inferred from the
    # originals set. This assertion used to read `originals_for_session(...) ==
    # frozenset()`, and that was the *leak* written down as the contract: a
    # redact-band value got no row, so the EgressGate had no needle for it, while
    # pass 2 dropped the same value for the same numeric reason (both banded on
    # threshold_obfuscate). Both payload-side passes were therefore switched off
    # over exactly the band that produces un-vaulted values, and a real SSN reached
    # the provider byte-for-byte. The value is now handed to the gate as an
    # unrestorable needle; build doc section 9.2's "no vault entry" is what the
    # three checks below pin, and section 9.4 documents this set as the gate's.
    assert env.vault.originals_for_session(env.session_id) == frozenset({"123-45-6789"})
    assert await env.vault.get_by_original(env.session_id, "SSN", normalize("123-45-6789")) is None
    assert env.vault.surrogates_for_session(env.session_id) == {}


# ---------------------------------------------------------------------------
# 12. Splice correctness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_right_to_left_splice_survives_many_adjacent_spans(env: Env, strategy: str) -> None:
    values = [f"{index:03d}-45-6789" for index in range(101, 113)]
    text = "|".join(values) + "|tail"
    detections: list[Detection] = []
    cursor = 0
    for value in values:
        start = text.index(value, cursor)
        detections.append(
            Detection(
                entity_type="SSN",
                category=EntityCategory.PII,
                start=start,
                end=start + len(value),
                text=value,
                score=0.9,
            )
        )
        cursor = start + len(value)
    # Shuffled deliberately: the engine sorts, the caller must not have to.
    shuffled = detections[7:] + detections[:3] + detections[3:7]

    result = await env.engine.obfuscate(env.session_id, text, shuffled, strategy=strategy)

    mapping = {
        await env.vault.get_by_surrogate(env.session_id, record.surrogate): record.surrogate
        for record in result.tokens
    }
    expected = "|".join(mapping[value] for value in values) + "|tail"
    assert result.obfuscated_text == expected
    for value in values:
        assert value not in result.obfuscated_text
    assert len(result.spans) == len(values)


async def test_touching_spans_are_both_spliced(env: Env) -> None:
    """``a.end == b.start`` is adjacency, not overlap."""
    text = "123-45-6789987-65-4321 concatenated."
    detections = [
        Detection(
            entity_type="SSN",
            category=EntityCategory.PII,
            start=0,
            end=11,
            text="123-45-6789",
            score=0.9,
        ),
        Detection(
            entity_type="SSN",
            category=EntityCategory.PII,
            start=11,
            end=22,
            text="987-65-4321",
            score=0.9,
        ),
    ]
    result = await env.engine.obfuscate(env.session_id, text, detections, strategy="tokenization")
    assert len(result.tokens) == 2
    first, second = (record.surrogate for record in result.tokens)
    assert result.obfuscated_text == f"{first}{second} concatenated."
    # Position alone does not prove the mapping: two adjacent surrogates spliced in
    # the wrong order produce a document that still "looks" right against a
    # positional expectation built from the same list. Resolve each back instead.
    assert await env.vault.get_by_surrogate(env.session_id, first) == "123-45-6789"
    assert await env.vault.get_by_surrogate(env.session_id, second) == "987-65-4321"
    assert first != second


async def test_overlapping_spans_are_resolved_by_score_then_length(env: Env) -> None:
    text = "Patient John Smith was admitted."
    weak = span(text, "John Smith", "NAME", score=0.55)
    strong = Detection(
        entity_type="CLIENT_IDENTITY",
        category=EntityCategory.LEGAL,
        start=weak.start,
        end=weak.end,
        text="John Smith",
        score=0.85,
    )
    result = await env.engine.obfuscate(
        env.session_id, text, [weak, strong], strategy="tokenization", doc_category="legal"
    )
    assert [record.entity_type for record in result.tokens] == ["CLIENT_IDENTITY"]
    assert len(result.spans) == 1
    # The label is the only thing ranking decides; coverage is unconditional, so
    # the merged span still covers the name and the name still leaves the payload.
    assert (result.spans[0].start, result.spans[0].end) == (weak.start, weak.end)
    assert "John Smith" not in result.obfuscated_text
    assert result.obfuscated_text == f"Patient {result.tokens[0].surrogate} was admitted."


async def test_a_partially_overlapping_loser_is_absorbed_not_dropped(env: Env) -> None:
    """Ranking picks the label; it must not decide whether text is protected.

    Dropping the loser of an overlap is only safe when the winner *contains* it.
    On a partial overlap the loser's uncovered remainder rides out in the clear:
    ``CASE_STRATEGY``'s ``[^.\\n]{0,120}`` tail stops one character into a name, so
    it overlaps ``CLIENT_IDENTITY`` without containing it, and the payload became
    ``[REDACTED_CASE_STRATEGY]riyanka Raghunathan`` -- a name on the wire.
    """
    text = (
        "We should press the causation defence at the hearing, keep our damages "
        "expert on reserve, and avoid concession before we depose "
        "Priyanka Raghunathan, their economist."
    )
    name_start = text.index("Priyanka Raghunathan")
    strategy_span = Detection(
        entity_type="CASE_STRATEGY",
        category=EntityCategory.LEGAL,
        start=text.index("press the causation"),
        # Stops ONE character into the name -- overlapping, not containing.
        end=name_start + 1,
        text=text[text.index("press the causation") : name_start + 1],
        score=0.70,
    )
    name_span = Detection(
        entity_type="CLIENT_IDENTITY",
        category=EntityCategory.LEGAL,
        start=name_start,
        end=name_start + len("Priyanka Raghunathan"),
        text="Priyanka Raghunathan",
        score=0.85,
    )

    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [strategy_span, name_span],
        strategy="tokenization",
        doc_category="legal",
    )

    assert "Priyanka" not in result.obfuscated_text, result.obfuscated_text
    assert "Raghunathan" not in result.obfuscated_text, result.obfuscated_text
    assert "riyanka" not in result.obfuscated_text, "the uncovered remainder leaked"
    # One span covering the union of the two: the policy label wins the ranking,
    # and coverage is unconditional.
    assert len(result.spans) == 1
    covering = result.spans[0]
    assert covering.entity_type == "CASE_STRATEGY"
    # Exactly the union, not merely "at least as wide": an inequality is also
    # satisfied by a span that swallowed half the document, which would be
    # over-redaction rather than the absorption this test is about.
    assert (covering.start, covering.end) == (strategy_span.start, name_span.end)


async def test_a_clipped_fragment_does_not_steal_the_label_from_its_container(
    env: Env,
) -> None:
    """The span that *is* the union takes the label, outranked or not.

    A boundary-clipped fragment scoring higher than the identifier containing it
    would otherwise relabel the merged span -- spaCy types the bare digits of
    ``MRN: 4471902`` as a date at 0.85, above the 0.7 pattern hit on the whole
    identifier.
    """
    text = "Chart shows MRN: 4471902 on the header."
    whole_start = text.index("MRN: 4471902")
    whole = Detection(
        entity_type="MRN",
        category=EntityCategory.PHI,
        start=whole_start,
        end=whole_start + len("MRN: 4471902"),
        text="MRN: 4471902",
        score=0.70,
    )
    fragment_start = text.index("4471902")
    fragment = Detection(
        entity_type="DATE",
        category=EntityCategory.PHI,
        start=fragment_start,
        end=fragment_start + len("4471902"),
        text="4471902",
        score=0.85,
    )

    result = await env.engine.obfuscate(
        env.session_id, text, [fragment, whole], strategy="tokenization"
    )

    assert len(result.spans) == 1
    assert result.spans[0].entity_type == "MRN", "the container keeps its own label"
    assert (result.spans[0].start, result.spans[0].end) == (whole.start, whole.end)
    assert "4471902" not in result.obfuscated_text


async def test_contained_and_disjoint_spans_are_left_alone(env: Env) -> None:
    """Absorption must not fire where there is nothing to absorb.

    The label assertion below was changed from ``{"SSN", "NAME"}`` when the
    engine's private copy of the overlap resolver was deleted in favour of
    :func:`detection.detector.resolve_overlaps`. It was not loosened and it is not
    an accommodation of new behaviour -- it asserted the *opposite* of a shipped,
    documented rule, and the two implementations returned different labels for
    these exact three spans at commit ``fee5806``, before any of that change::

        PRISTINE detector: [('ACCOUNT_NUMBER', 4, 15, 0.5), ('NAME', 25, 35, 0.9)]
        PRISTINE engine  : [('SSN', 4, 15, 0.9), ('NAME', 25, 35, 0.9)]

    README Deviation #35 -- "Overlap resolution ranks pattern/gazetteer-backed
    entities above presidio-backed ones, below policy actions, above score" -- is
    the cited rule, and ``ACCOUNT_NUMBER`` is pattern-backed while ``SSN`` is
    presidio-backed (``presidio: US_SSN``, no ``patterns:`` in ``entities.yaml``).
    ``{"SSN", "NAME"}`` therefore encoded the defect as the contract. It is the
    same span geometry as
    ``test_resolve_overlaps_prefers_a_registry_pattern_over_a_general_ner_label``
    in ``tests/test_detection.py``, which asserts the opposite outcome -- the repo
    held two contradictory expectations for one input.

    What Deviation #35 promises is that *only the label* moves, so this test now
    pins coverage and reversibility explicitly rather than leaving them implied.
    """
    text = "SSN 123-45-6789 and name John Smith on file."
    ssn = span(text, "123-45-6789", "SSN")
    inner = Detection(  # fully contained by the SSN span, lower ranked
        entity_type="ACCOUNT_NUMBER",
        category=EntityCategory.FIN,
        start=ssn.start,
        end=ssn.start + 6,
        text=text[ssn.start : ssn.start + 6],
        score=0.5,
    )
    name = span(text, "John Smith", "NAME")

    result = await env.engine.obfuscate(
        env.session_id, text, [ssn, inner, name], strategy="tokenization"
    )

    assert len(result.spans) == 2, "the contained span collapses, the disjoint one survives"
    # The pattern-backed label wins over the presidio-backed one it sits inside.
    assert {item.entity_type for item in result.spans} == {"ACCOUNT_NUMBER", "NAME"}
    assert [(item.start, item.end) for item in result.spans] == [
        (ssn.start, ssn.end),
        (name.start, name.end),
    ], "a contained loser must not widen its winner"
    assert "123-45-6789" not in result.obfuscated_text
    assert "John Smith" not in result.obfuscated_text
    # "Only the label moves": the full SSN span is still masked as one unit, still
    # obfuscated rather than downgraded to an irreversible redaction, and still
    # restores to the value that stood there. Asserting the label alone would let a
    # future ranking change silently trade a token for a redaction.
    assert [item.action for item in result.spans] == [
        EntityAction.OBFUSCATED,
        EntityAction.OBFUSCATED,
    ]
    for item in result.spans:
        assert item.surrogate is not None
        assert (
            await env.vault.get_by_surrogate(env.session_id, item.surrogate)
            == (text[item.start : item.end])
        )


async def test_out_of_range_spans_are_dropped(env: Env) -> None:
    text = "Short text."
    bogus = Detection(
        entity_type="SSN",
        category=EntityCategory.PII,
        start=5,
        end=500,
        text="123-45-6789",
        score=0.9,
    )
    result = await env.engine.obfuscate(env.session_id, text, [bogus])
    assert result.obfuscated_text == text
    assert result.tokens == []


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_spans_below_the_sweep_floor_are_never_vaulted(env: Env, strategy: str) -> None:
    """The vault's originals set must stay co-extensive with what the gate enforces.

    Presidio types credentials like "MD" and "RN" as PERSON. A one- or two-character
    value carries no re-identification signal, cannot be swept without corrupting
    unrelated words, and sits below the egress gate's own ``MIN_ORIGINAL_LEN``.
    Vaulting one would put a value in the originals set the gate will never check,
    quietly turning "zero originals in transit" into "zero originals, except the
    ones too short to check".
    """
    text = "Reviewed by MD and RN on the ward."
    result = await env.engine.obfuscate(
        env.session_id,
        text,
        [span(text, "MD", "NAME"), span(text, "RN", "NAME")],
        strategy=strategy,
    )
    assert result.obfuscated_text == text
    assert result.tokens == []
    assert result.spans == []
    assert await env.vault.row_count(env.session_id) == 0
    assert env.vault.originals_for_session(env.session_id) == frozenset()
    assert engine_module.MIN_SWEEP_LEN == egress_gate.MIN_ORIGINAL_LEN, (
        "the engine's floor and the gate's floor are one policy, not two"
    )
    # Equality alone only says the two agree; raising BOTH to 10 would keep them
    # agreeing while silently dropping every name shorter than ten characters out
    # of the guarantee, and nothing above would notice. So pin the value, and pin
    # the far side of the boundary: the shortest ENFORCEABLE span really is kept.
    assert engine_module.MIN_SWEEP_LEN == 3
    shortest = "Ann"
    assert len(shortest) == engine_module.MIN_SWEEP_LEN
    at_floor = await env.engine.obfuscate(
        env.session_id,
        f"Contact {shortest} today.",
        [span(f"Contact {shortest} today.", shortest, "NAME")],
        strategy=strategy,
    )
    assert len(at_floor.tokens) == 1, "a span exactly at the floor must be protected"
    assert shortest not in at_floor.obfuscated_text
    assert await env.vault.row_count(env.session_id) == 1


class SilentDetector:
    """Minimal ``DetectorLike``. The gate's pass-1 originals scan never calls it."""

    async def detect(
        self, text: str, doc_category: str | None = None
    ) -> list[Detection]:  # pragma: no cover -- present to satisfy the protocol
        return []


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_the_sweep_floor_is_measured_after_normalization(env: Env, strategy: str) -> None:
    """The floor is a property of the *normalized* value, not of the raw span.

    The test above uses "MD", "RN" and "Ann" -- and every one of them has the same
    length raw as normalized, so none of them can tell the two apart. Measuring the
    raw span instead would reopen the very hole the floor exists to close: a
    detector that hands back ``"MD "`` with the trailing space gives a raw length of
    3, at the floor, while the value actually stored and actually compared is
    ``"md"``, below it. It would be vaulted, and the gate -- which drops an original
    on ``len(original.strip()) < MIN_ORIGINAL_LEN`` -- would never once scan for it.
    "Zero originals in transit" would quietly become "zero originals, except the
    ones too short to check", which is exactly what the floor is for.

    So rather than restate the gate's rule here, the gate's own ``_scan_originals``
    is asked directly, and asked a control question in the same breath so a zero
    cannot come from a broken probe.
    """
    text = "Reviewed by MD  on the ward."
    start = text.index("MD")
    padded = Detection(
        entity_type="NAME",
        category=EntityCategory.PII,
        start=start,
        end=start + 3,
        text=text[start : start + 3],
        score=0.9,
    )
    # Premise: raw length is exactly AT the floor; normalized length is BELOW it.
    assert padded.text == "MD "
    assert len(padded.text) == engine_module.MIN_SWEEP_LEN
    assert len(normalize(padded.text)) < engine_module.MIN_SWEEP_LEN

    # The consequence, from the gate itself: were this vaulted, no form of it would
    # ever be counted -- even in a payload that carries it verbatim.
    gate = egress_gate.EgressGate(
        vault=env.vault,
        detector=SilentDetector(),
        settings=env.settings,
    )
    carrying = f"Reviewed by {padded.text} on the ward."
    assert padded.text in carrying and normalize(padded.text) in normalize(carrying)
    assert gate._scan_originals(carrying, frozenset({padded.text})) == 0
    assert gate._scan_originals(carrying, frozenset({normalize(padded.text)})) == 0
    assert gate._scan_originals(carrying, frozenset({"Reviewed"})) == 1, (
        "control: the probe does count an original above the floor"
    )

    result = await env.engine.obfuscate(env.session_id, text, [padded], strategy=strategy)

    assert result.obfuscated_text == text
    assert result.tokens == []
    assert result.spans == []
    assert await env.vault.row_count(env.session_id) == 0
    assert env.vault.originals_for_session(env.session_id) == frozenset()


async def test_document_category_scoping_drops_out_of_scope_entities(env: Env) -> None:
    """``only_in_doc_categories`` is registry policy; the engine just asks."""
    text = "Wire of $250,000 cleared today."
    detection = span(text, "$250,000", "AMOUNT")

    scoped_out = await env.engine.obfuscate(
        env.session_id, text, [detection], doc_category="medical"
    )
    assert scoped_out.obfuscated_text == text
    assert scoped_out.tokens == []

    scoped_in = await env.engine.obfuscate(
        env.session_id, text, [detection], doc_category="financial"
    )
    assert "$250,000" not in scoped_in.obfuscated_text
    assert len(scoped_in.tokens) == 1


# ---------------------------------------------------------------------------
# Audit + leak hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_audit_records_carry_types_ids_and_counts_but_never_values(
    env: Env, strategy: str
) -> None:
    text = (
        "PRIVILEGED AND CONFIDENTIAL. John Smith, SSN 123-45-6789, again 123-45-6789. "
        "Possible MRN: 4471902 noted. Our settlement strategy is to hold firm."
    )
    detections = [
        span(text, "PRIVILEGED AND CONFIDENTIAL", "PRIVILEGED_MARKER"),
        span(text, "John Smith", "NAME"),
        *every_span(text, "123-45-6789", "SSN"),
        span(text, "MRN: 4471902", "MRN", score=0.4),
        span(text, "Our settlement strategy is to hold firm", "CASE_STRATEGY"),
    ]
    run_id = "run-0001"
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy=strategy, doc_category="legal", run_id=run_id
    )

    events = await env.audit.query(session_id=env.session_id)
    assert {event.event_type for event in events} == {OBFUSCATE, REDACT, STRIP}
    assert all(event.run_id == run_id for event in events)

    obfuscate_events = [event for event in events if event.event_type == OBFUSCATE]
    assert {event.entity_type for event in obfuscate_events} == {"NAME", "SSN"}
    assert len(obfuscate_events) == 2, "one event per distinct value, not per span"
    ssn_event = next(event for event in obfuscate_events if event.entity_type == "SSN")
    assert ssn_event.detail["occurrences"] == 2
    assert ssn_event.detail["strategy"] == strategy

    # Identity, not membership. ``token_id in {every token we issued}`` is satisfied
    # by an event stamped with the *other* entity's ID -- which is precisely the
    # mis-attribution an audit trail exists to rule out. Every event is matched to
    # the record for its own entity type.
    token_of = {record.entity_type: record.token_id for record in result.tokens}
    assert len(token_of) == len(result.tokens), "entity types are unique here"
    for event in obfuscate_events:
        assert event.token_id == token_of[event.entity_type], (
            f"{event.entity_type} was audited under another entity's token id"
        )
    name_event = next(event for event in obfuscate_events if event.entity_type == "NAME")
    assert name_event.token_id != ssn_event.token_id
    assert name_event.detail["occurrences"] == 1

    # Entity TYPES are required by the audit contract; original VALUES must be
    # absent -- including the stripped marker's own text.
    secrets = (
        "John Smith",
        "123-45-6789",
        "4471902",
        "hold firm",
        "PRIVILEGED AND CONFIDENTIAL",
    )
    serialised = json.dumps([event.model_dump() for event in events])
    for secret in secrets:
        assert secret not in serialised
    assert await env.audit.verify_chain(env.session_id)


async def test_no_audit_logger_is_a_supported_configuration(
    settings: Settings, registry: EntityRegistry
) -> None:
    sessions = SessionRegistry(settings)
    vault = await SessionVault.open(settings.data_dir / "vault.db", sessions)
    try:
        session_id, _ = await sessions.create("test-user")
        engine = ObfuscationEngine(
            registry=registry, vault=vault, session_registry=sessions, settings=settings
        )
        text = "Patient John Smith."
        result = await engine.obfuscate(session_id, text, [span(text, "John Smith", "NAME")])
        # "The name is gone" is also satisfied by an engine that dropped the span
        # on the floor when it found no audit logger, so pin the whole outcome:
        # the surrogate was issued, spliced, vaulted and is restorable.
        assert len(result.tokens) == 1
        record = result.tokens[0]
        assert result.obfuscated_text == f"Patient {record.surrogate}."
        assert "John Smith" not in result.obfuscated_text
        assert await vault.get_by_surrogate(session_id, record.surrogate) == "John Smith"
    finally:
        await vault.close()


async def test_strategy_context_never_reprs_the_session_key(env: Env) -> None:
    rendered = repr(env.context())
    assert "***" in rendered
    assert env.session_key.hex() not in rendered
    assert str(env.session_key) not in rendered


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_empty_detection_list_is_a_no_op(env: Env, strategy: str) -> None:
    text = "Nothing sensitive here at all."
    result = await env.engine.obfuscate(env.session_id, text, [], strategy=strategy)
    assert result.obfuscated_text == text
    assert result.tokens == []
    assert result.spans == []
    assert await env.vault.row_count(env.session_id) == 0


# ---------------------------------------------------------------------------
# 15. Overlap resolution: one implementation, two call sites
# ---------------------------------------------------------------------------
#
# The engine used to carry its own private ``_resolve_overlaps``, whose docstring
# said it mirrored ``detection.detector``'s "deliberately". It did not. The
# detector's ranked a fourth categorical dimension (registry pattern/gazetteer
# backing, README Deviation #35) that the engine's had no parameter for, and it
# guarded the union-covering winner on categorical class where the engine's did
# not. Measured at commit fee5806, before the copy was deleted::
#
#     detector, pattern_types={'EMAIL'} : [('EMAIL', 6, 30)]
#     engine   (no pattern_types param) : [('NAME',  6, 30)]
#
#     detector, policy_types={'CASE_STRATEGY'} : [('CASE_STRATEGY', 0, 63)]
#     engine,   policy_types={'CASE_STRATEGY'} : [('NAME',          0, 63)]
#
# Neither divergence is a leak -- the union is masked either way -- but the
# surviving label picks the entity's tier, action, threshold and strategy, so the
# same spans were obfuscated two different ways depending on which resolver ran.
# The second row is the sharper one: a policy ``action: redact`` entity keeps its
# label under the detector and loses it under the engine, so privileged prose the
# registry says must be destroyed was instead pseudonymized and vaulted.
#
# The cases below are the shared input the two used to disagree on. Expectations
# are written out literally rather than computed from either implementation: a
# differential test whose expected value is one side's output cannot fail.

#: Categorical facts these cases depend on, stated here rather than derived, and
#: pinned against the shipped registry by the guard test below.
POLICY_TYPES_IN_PLAY = frozenset({"CASE_STRATEGY"})
PATTERN_TYPES_IN_PLAY = frozenset({"CASE_STRATEGY", "EMAIL", "MRN"})

#: ``(label, text, [(entity_type, start, end, score)], [(entity_type, start, end)])``
OVERLAP_CASES: list[
    tuple[str, str, list[tuple[str, int, int, float]], list[tuple[str, int, int]]]
] = [
    (
        "pattern-backed label survives a wider general NER span",
        "Email awhitlock@mailer.example for details.",
        [("NAME", 0, 30, 0.85), ("EMAIL", 6, 30, 0.70)],
        [("EMAIL", 0, 30)],
    ),
    (
        "policy label survives a general span that swallows it",
        # Synthetic geometry on purpose: the property is about ranking, and the
        # engine's contract is to be correct for detections from ANY source, not
        # only for the disjoint spans ``Detector`` happens to hand it.
        "AAAAAAAAAABBBBBBBBBBCCCCCCCCCC",
        [("CASE_STRATEGY", 0, 20, 0.70), ("NAME", 0, 30, 0.85)],
        [("CASE_STRATEGY", 0, 30)],
    ),
    (
        "a clipped fragment does not take the label off the identifier around it",
        "Chart MRN: 4471902 filed.",
        [("DATE", 11, 18, 0.85), ("MRN", 6, 18, 0.70)],
        [("MRN", 6, 18)],
    ),
]


def overlap_case_spans(text: str, raw: list[tuple[str, int, int, float]]) -> list[Detection]:
    return [
        Detection(
            entity_type=entity_type,
            category=CATEGORY_OF[entity_type],
            start=start,
            end=end,
            text=text[start:end],
            score=score,
        )
        for entity_type, start, end, score in raw
    ]


def test_the_registry_classifications_these_cases_rest_on(registry: EntityRegistry) -> None:
    """The hard-coded categorical sets above must still describe ``entities.yaml``.

    Without this the literal expectations rot silently the day someone gives
    ``NAME`` a ``patterns:`` entry, and the differential test would then be
    asserting the wrong outcome rather than reporting a changed rule.
    """
    for name in ("NAME", "DATE"):
        spec = registry.entities[name]
        assert not (spec.patterns or spec.gazetteer), f"{name} is expected to be presidio-backed"
        assert spec.action is None
    for name in sorted(PATTERN_TYPES_IN_PLAY):
        spec = registry.entities[name]
        assert spec.patterns or spec.gazetteer, f"{name} is expected to be registry-backed"
    assert registry.entities["CASE_STRATEGY"].action is not None
    for name in sorted(PATTERN_TYPES_IN_PLAY - POLICY_TYPES_IN_PLAY):
        assert registry.entities[name].action is None


def test_overlap_resolution_is_one_implementation_not_two() -> None:
    """The engine must *call* the detector's resolver, not re-implement it.

    This is the structural half of the reconciliation. Two copies of a ranking
    rule cannot be kept in step by a docstring claiming they are -- that is
    exactly what was claimed, and exactly what failed.
    """
    assert engine_module.resolve_overlaps is detector_module.resolve_overlaps
    assert not hasattr(engine_module, "_resolve_overlaps"), (
        "the engine grew a private overlap resolver again"
    )


@pytest.mark.parametrize(
    ("label", "text", "raw", "expected"),
    OVERLAP_CASES,
    ids=[case[0] for case in OVERLAP_CASES],
)
def test_the_detector_resolver_matches_the_written_expectation(
    label: str,
    text: str,
    raw: list[tuple[str, int, int, float]],
    expected: list[tuple[str, int, int]],
) -> None:
    kept = detector_module.resolve_overlaps(
        text, overlap_case_spans(text, raw), POLICY_TYPES_IN_PLAY, PATTERN_TYPES_IN_PLAY
    )
    assert [(d.entity_type, d.start, d.end) for d in kept] == expected, label
    for detection in kept:
        assert detection.text == text[detection.start : detection.end]


@pytest.mark.parametrize(
    ("label", "text", "raw", "expected"),
    OVERLAP_CASES,
    ids=[case[0] for case in OVERLAP_CASES],
)
async def test_the_engine_de_overlaps_to_the_same_written_expectation(
    env: Env,
    label: str,
    text: str,
    raw: list[tuple[str, int, int, float]],
    expected: list[tuple[str, int, int]],
) -> None:
    """The engine's planned spans, end to end, against the same literal table.

    Deliberately *not* ``assert engine_output == detector_output``: the two share
    a function object now, so comparing them to each other would pass no matter
    what either one does. The table is the third opinion.
    """
    result = await env.engine.obfuscate(
        env.session_id, text, overlap_case_spans(text, raw), strategy="tokenization"
    )
    assert [(item.entity_type, item.start, item.end) for item in result.spans] == expected, label
    # Coverage is the invariant the label question must never disturb: every input
    # span is inside some kept span, so nothing rides out in the clear.
    for _entity_type, start, end, _score in raw:
        assert any(item.start <= start and end <= item.end for item in result.spans)


async def test_privileged_prose_swallowed_by_a_name_span_is_redacted_not_pseudonymized(
    env: Env,
) -> None:
    """The consequence of the divergence, stated as behaviour rather than labels.

    ``CASE_STRATEGY`` carries ``action: redact``: the registry's position is that
    strategy prose has no reasoning value worth a surrogate and a pseudonym of it
    would *fabricate strategy*. Under the engine's old private resolver a
    higher-scoring ``NAME`` span containing it took the label, so the same text
    was obfuscated instead -- a reversible token, a vault row, and privileged
    content preserved in the payload under a name-shaped pseudonym.
    """
    text = "AAAAAAAAAABBBBBBBBBBCCCCCCCCCC"
    spans = overlap_case_spans(text, [("CASE_STRATEGY", 0, 20, 0.70), ("NAME", 0, 30, 0.85)])

    result = await env.engine.obfuscate(env.session_id, text, spans, strategy="tokenization")

    assert result.obfuscated_text == "[REDACTED_CASE_STRATEGY]"
    assert [item.action for item in result.spans] == [EntityAction.REDACTED]
    assert result.spans[0].surrogate is None
    # Redaction is irreversible by design, so there must be no vault row and no
    # original for the egress gate to have to defend.
    assert result.tokens == []
    assert await env.vault.row_count(env.session_id) == 0
    assert env.vault.originals_for_session(env.session_id) == frozenset()


# ---------------------------------------------------------------------------
# 16. Bounded resources: guards that must have a biting test
# ---------------------------------------------------------------------------
#
# Each constant below was mutated one at a time with the whole suite run, and the
# suite stayed green -- the guard was enforced by a comment and nothing else. The
# tests here are written against hard-coded magnitudes rather than against the
# constants they guard, because a test that reads the constant moves with it.


async def test_the_token_collision_budget_survives_eight_consecutive_collisions(
    env: Env,
) -> None:
    """``MAX_TOKEN_COLLISION_RETRIES`` is load-bearing at 8.

    The engine settles the token ID *before* the strategy renders a surrogate
    around it, because the restorer keys on the 8-hex core: an ID chosen after
    the fact restores the wrong entity. That makes this budget the only thing
    between a 4-byte truncation collision and a hard failure, and
    ``test_token_id_collision_is_re_derived_...`` only ever needs one retry, so
    the constant could be cut to 1 with nothing red.

    Counters 0..7 are pre-occupied by other originals using the real derivation
    -- no stubbed ``derive_token_id`` -- so the engine must reach counter 8.
    """
    victim = "Rowan Delacroix-Sung"
    blocked = [
        derive_token_id(env.session_key, "NAME", victim, counter=counter) for counter in range(8)
    ]
    assert len(set(blocked)) == 8

    for index, token_id in enumerate(blocked):
        await env.vault.put(
            env.session_id,
            TokenRecord(
                session_id=env.session_id,
                token_id=token_id,
                entity_type="NAME",
                category=EntityCategory.PII,
                surrogate=f"[PII_NAME_{token_id}]",
                created_at=time.time(),
            ),
            f"Unrelated Holder {index:02d}",
        )

    text = f"Patient {victim} was admitted."
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, victim, "NAME")], strategy="tokenization"
    )

    assert len(result.tokens) == 1
    issued = result.tokens[0].token_id
    assert issued == derive_token_id(env.session_key, "NAME", victim, counter=8), (
        "the eighth re-derivation must still be inside the budget"
    )
    assert issued not in blocked
    # The occupied IDs are untouched and the value round-trips on its own ID.
    for index, token_id in enumerate(blocked):
        assert await env.vault.get_by_token(env.session_id, token_id) == (
            f"Unrelated Holder {index:02d}"
        )
    assert await env.vault.get_by_token(env.session_id, issued) == victim
    assert victim not in result.obfuscated_text


def test_an_oversized_prompt_is_refused_at_the_schema_boundary() -> None:
    """``MAX_PROMPT_CHARS`` must reject a megabyte prompt.

    Lives with the obfuscation tests because it is a property of the *outbound
    payload*, which this module owns: the prompt is spliced verbatim into the
    text handed to the provider and re-scanned there by the egress gate, so an
    unbounded prompt is an unbounded scan, an unbounded provider payload and an
    unbounded request body accepted before any auth-shaped check has run.

    Raising the ceiling to 10**9 left the whole suite green -- every existing
    assertion about the cap was written against ``MAX_PROMPT_CHARS`` itself, so
    it moved with the constant. The literals below do not.
    """
    with pytest.raises(ValidationError):
        PipelineRunRequest(user_id="u", doc_id="d", prompt="x" * 1_000_000)

    # ...and the fix for that must not be a cap so tight it breaks real use: a
    # long but ordinary question still has to be accepted.
    accepted = PipelineRunRequest(user_id="u", doc_id="d", prompt="x" * 2_000)
    assert len(accepted.prompt) == 2_000

    # The band the two literals above imply, stated once so the intent is legible.
    assert 2_000 <= MAX_PROMPT_CHARS < 1_000_000


async def test_one_value_gets_one_band_across_all_its_sightings(env: Env) -> None:
    """A repeated value is banded once, on its highest-scoring sighting.

    `_classify` reads one span's score, so a value the detector sees twice at
    different confidences was banded twice -- tokenized where it scored above the
    obfuscate threshold and irreversibly `[REDACTED_<TYPE>]` where it scored below,
    in the SAME payload. Live on `fixtures/medical_note.txt`. It fails safe, but it
    contradicts the engine's own rule (one vault row, one token, N splices), shows
    the model two referents for one entity, and costs a restoration.

    Reverting to per-span banding left the whole suite green, so this pins it.
    """
    text = "Call 704-555-0151 now. Contact number 704-555-0151 for the ward."
    low = span(text, "704-555-0151", "PHONE", score=0.40)
    high = span(text, "704-555-0151", "PHONE", score=0.75)
    high = high.model_copy(update={"start": text.rindex("704-555-0151")})
    high = high.model_copy(update={"end": high.start + len("704-555-0151")})

    result = await env.engine.obfuscate(env.session_id, text, [low, high])

    actions = {s.action for s in result.spans}
    assert actions == {"obfuscated"}, f"one value got two different masks: {actions}"
    assert "[REDACTED_PHONE]" not in result.obfuscated_text
    assert len(result.tokens) == 1, "one value, one vault row"


async def test_the_band_is_decided_on_the_group_score_but_the_span_keeps_its_own(
    env: Env,
) -> None:
    """Banding is policy; `SpanOut.score` is evidence. They must not be conflated.

    A first version passed a score-rewritten copy into `_classify`, and that copy
    flowed on into `_span()`, `_record()` and the audit `detail`. Every span of a
    repeated value was then stamped with the maximum confidence seen anywhere in
    the document, so the UI tooltip and the audit trail reported a measurement the
    detector never made at that offset.
    """
    text = "Call 704-555-0151 now. Contact number 704-555-0151 for the ward."
    low = span(text, "704-555-0151", "PHONE", score=0.40)
    high = span(text, "704-555-0151", "PHONE", score=0.75)
    high = high.model_copy(update={"start": text.rindex("704-555-0151")})
    high = high.model_copy(update={"end": high.start + len("704-555-0151")})

    result = await env.engine.obfuscate(env.session_id, text, [low, high])

    scores = sorted(round(s.score, 2) for s in result.spans)
    assert scores == [0.40, 0.75], (
        f"spans report {scores}; each must keep the score measured AT that span, "
        f"not the group maximum"
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2024-01-15", "2024-01-15"),
        ("01/15/2024", "2024-01-15"),
        ("Jan 15 2024", "2024-01-15"),
        ("9:15 AM", None),
        ("10:30", None),
        ("3:45 pm", None),
        ("1900", None),
    ],
)
def test_a_date_whose_components_came_from_the_anchor_is_refused(
    text: str, expected: str | None
) -> None:
    """`_parse_fallback`'s two-anchor probe, which nothing pinned.

    The `\\d+`-twice guard rejects a bare year but NOT a bare clock time: `9:15 AM`
    has two digit runs, neither a date component, so dateutil resolved the whole
    date from the anchor and the payload asserted a day the source never mentions.
    Relocating the anchor from *today* to a fixed date moved that lie rather than
    removing it, and every subsequent clock time collided on the same fabricated
    date -- three times on one page rendering three incomparable ways.

    No digit heuristic can decide this. Parsing against two anchors that share no
    field answers it exactly: a component the text supplies is identical both
    times, one taken from the default differs.
    """
    parsed = parse_source_date(text)
    assert (None if parsed is None else parsed.value.isoformat()) == expected


def test_the_two_fallback_anchors_share_no_field() -> None:
    """The probe's discriminating power rests on this, so it is asserted.

    An anchor sharing even one field with the primary would be blind to a text
    that omits exactly that field -- the component would agree between the two
    parses and read as supplied by the source.
    """
    a, b = daterules._FALLBACK_ANCHOR, daterules._FALLBACK_PROBE
    assert a.year != b.year and a.month != b.month and a.day != b.day
