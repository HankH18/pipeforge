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
import re
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import ClassVar

import pytest

from secure_context_pipeline.audit.logger import OBFUSCATE, REDACT, STRIP, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import derive_token_id, normalize
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
)
from secure_context_pipeline.pipeline import egress_gate
from secure_context_pipeline.surrogates import (
    STRICT_TOKEN_RE,
    extract_token_ids,
    format_redaction,
)
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
        env.session_id, text, [span(text, "Case No. 1:23-cv-45678", "CASE_ID")],
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


async def test_pseudonym_email_is_never_a_deliverable_address(env: Env) -> None:
    text = "Reach him at john.smith@example.com any time."
    result = await env.engine.obfuscate(
        env.session_id, text, [span(text, "john.smith@example.com", "EMAIL")],
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
    assert await env.vault.get_by_surrogate(
        env.session_id, fake
    ) == "john.smith@example.com"


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
    assert await env.vault.get_by_surrogate(
        env.session_id, surrogate
    ) == "sometime next spring", "unparseable must still mean restorable"


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
    assert "Smith" not in result.obfuscated_text
    assert "John" not in result.obfuscated_text


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
        entity_type="NAME", category=EntityCategory.PII, start=0, end=5,
        text="Smith", score=0.9,
    )
    full_span = Detection(
        entity_type="NAME", category=EntityCategory.PII, start=0, end=10,
        text="John Smith", score=0.9,
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
    assert "Smith" not in full


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
        env.session_id, text, [span(text, "Dr. Maria Garcia", "NAME")],
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


async def test_name_and_client_identity_pseudonymize_to_the_same_person(env: Env) -> None:
    """One human, two registry types (legal docs remap PERSON), one pseudonym."""
    strategy = build_strategy("pseudonymization", env.context())
    as_name = Detection(
        entity_type="NAME", category=EntityCategory.PII, start=0, end=10,
        text="John Smith", score=0.9,
    )
    as_client = Detection(
        entity_type="CLIENT_IDENTITY", category=EntityCategory.LEGAL, start=0, end=10,
        text="John Smith", score=0.9,
    )
    first = await strategy.make_surrogate(
        as_name, "aaaaaaaa", env.vault, session_id=env.session_id
    )
    second = await strategy.make_surrogate(
        as_client, "bbbbbbbb", env.vault, session_id=env.session_id
    )
    assert first == second
    # Equality on its own is satisfiable by two identical *failures* -- and a
    # degenerate generator returning "" for both would pass it. Pin that the shared
    # answer is a real two-part fake carrying neither component of the real name.
    assert not STRICT_TOKEN_RE.fullmatch(first), "both degraded to a token"
    assert len(first.split()) == 2, first
    assert "John" not in first and "Smith" not in first


# ---------------------------------------------------------------------------
# 5. Collision guard
# ---------------------------------------------------------------------------


async def test_collision_guard_regenerates_a_fake_equal_to_a_vault_original(env: Env) -> None:
    strategy = build_strategy("pseudonymization", env.context())
    detection = Detection(
        entity_type="SSN", category=EntityCategory.PII, start=0, end=11,
        text="123-45-6789", score=0.9,
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
        StrategyContext(
            registry=env.registry, session_key=SURNAME_ECHO_KEY, settings=env.settings
        ),
    )
    detection = Detection(
        entity_type="NAME", category=EntityCategory.PII, start=0, end=13,
        text="Anna Williams", score=0.9,
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


@pytest.mark.parametrize("entity_type", ["NAME", "CLIENT_IDENTITY"])
async def test_no_person_pseudonym_reproduces_a_real_name_word(
    env: Env, entity_type: str
) -> None:
    """Swept across many session keys: zero shared words, not merely few.

    A single key proves the guard fires once; the sweep proves it is not
    probabilistic. The pre-fix rate on this sweep was ~1.9% of spans.
    """
    names = [
        "Anna Williams", "John Smith", "Maria Garcia",
        "David Nguyen", "Sarah Johnson", "Robert Wilson",
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
            shared = sorted(
                set(normalize(surrogate).split()) & set(normalize(name).split())
            )
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
        entity_type="ADDRESS", category=EntityCategory.PII, start=0, end=len(source),
        text=source, score=0.9,
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
    strategy.reserved_originals = frozenset(
        {normalize(source), normalize(other_original)}
    )

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
        entity_type="SSN", category=EntityCategory.PII, start=0, end=11,
        text="123-45-6789", score=0.9,
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
        entity_type="MRN", category=EntityCategory.PHI, start=0, end=7,
        text="MRN: 12", score=0.9,
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
        entity_type="DATE", category=EntityCategory.PHI, start=0, end=len(source_text),
        text=source_text, score=0.9,
    )

    # Without the other real date present, the shift renders normally.
    strategy.reserved_originals = frozenset()
    assert await strategy.make_surrogate(
        detection, "aaaaaaaa", env.vault, session_id=env.session_id
    ) == other_text

    # With it present, shifting would emit a verbatim original -- so it must not.
    strategy.reserved_originals = frozenset({normalize(other_text)})
    degraded = await strategy.make_surrogate(
        detection, "aaaaaaaa", env.vault, session_id=env.session_id
    )
    assert STRICT_TOKEN_RE.fullmatch(degraded), degraded
    assert degraded == "[PHI_DATE_aaaaaaaa]"


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

    def colliding(
        session_key: bytes, entity_type: str, value: str, *, counter: int = 0
    ) -> str:
        return "cafe0001" if counter == 0 else real(session_key, entity_type, value, counter=counter)

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
        assert await env.vault.get_by_surrogate(env.session_id, item.surrogate) == (
            text[item.start : item.end]
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
async def test_the_sweep_chases_values_vaulted_by_an_earlier_call(
    env: Env, strategy: str
) -> None:
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
    surrogate = (await env.vault.get_by_original(env.session_id, "NAME", "john smith"))
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
    assert in_payload <= declared, (
        f"{sorted(in_payload - declared)} reached the payload undeclared"
    )
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
    third = "JOHN SMITH signed; John Smith countersigned."
    mixed = await env.engine.obfuscate(
        env.session_id, third, [span(third, "JOHN SMITH", "NAME")], strategy=strategy
    )
    ids = [record.token_id for record in mixed.tokens]
    assert len(ids) == len(set(ids)), f"a surrogate was declared twice: {ids}"
    assert len(mixed.tokens) == 1
    assert "John Smith" not in mixed.obfuscated_text
    assert "JOHN SMITH" not in mixed.obfuscated_text


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
    3. the sweep against the gate, which is the drift alarm the engine's import of
       ``_ALNUM`` cannot raise on its own (the per-side assembly is written out in
       both modules).
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
        "John Smith", "Brown", "Ann", "MRN: 4471902", "(415) 555-0123",
        "$1,234.56", "Ph.D.", "123-45-6789", "Case No. 1:23-cv-45678", "O'Brien",
    ]
    haystacks = [
        "{}", "_{}_", "*{}*", "__{}__", "a{}", "{}z", "({})", "[{}]", " {} ",
        "x{}y", "{}.", ".{}", "tel{}", "USD{}", "{}degree", "-{}-", "{}_", "_{}",
        "\n{}\n", "1{}", "{}9",
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
    assert vs_gate == [], (
        f"sweep and gate disagree on {len(vs_gate)} case(s): {vs_gate[:5]}"
    )


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
        return re.search(
            r"(?<![^\W_])" + re.escape(needle) + r"(?![^\W_])", haystack
        ) is not None

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
        (item.start - offset, item.end - offset)
        for item in from_same.spans
        if item.start >= offset
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
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="tokenization"
    )
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
async def test_second_call_in_one_session_reuses_the_first_mapping(
    env: Env, strategy: str
) -> None:
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
    assert await env.vault.get_by_surrogate(
        env.session_id, surrogate
    ) == "diabetes mellitus"


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
            f"[{CATEGORY_OF[record.entity_type].value}_{record.entity_type}_"
            f"{record.token_id}]"
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
    assert result.obfuscated_text == (
        f"Patient {by_type['NAME']}, SSN {by_type['SSN']}."
    )
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

    stripped_span = next(
        item for item in result.spans if item.entity_type == "PRIVILEGED_MARKER"
    )
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
        env.session_id, text, [span(text, "attorney-client", "PRIVILEGED_MARKER")],
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
        text, "Our litigation strategy is to delay until discovery closes", "CASE_STRATEGY",
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
    assert env.vault.originals_for_session(env.session_id) == frozenset()


# ---------------------------------------------------------------------------
# 12. Splice correctness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strategy", BOTH_MODES)
async def test_right_to_left_splice_survives_many_adjacent_spans(
    env: Env, strategy: str
) -> None:
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
            entity_type="SSN", category=EntityCategory.PII, start=0, end=11,
            text="123-45-6789", score=0.9,
        ),
        Detection(
            entity_type="SSN", category=EntityCategory.PII, start=11, end=22,
            text="987-65-4321", score=0.9,
        ),
    ]
    result = await env.engine.obfuscate(
        env.session_id, text, detections, strategy="tokenization"
    )
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
        env.session_id, text, [strategy_span, name_span],
        strategy="tokenization", doc_category="legal",
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
        entity_type="MRN", category=EntityCategory.PHI, start=whole_start,
        end=whole_start + len("MRN: 4471902"), text="MRN: 4471902", score=0.70,
    )
    fragment_start = text.index("4471902")
    fragment = Detection(
        entity_type="DATE", category=EntityCategory.PHI, start=fragment_start,
        end=fragment_start + len("4471902"), text="4471902", score=0.85,
    )

    result = await env.engine.obfuscate(
        env.session_id, text, [fragment, whole], strategy="tokenization"
    )

    assert len(result.spans) == 1
    assert result.spans[0].entity_type == "MRN", "the container keeps its own label"
    assert (result.spans[0].start, result.spans[0].end) == (whole.start, whole.end)
    assert "4471902" not in result.obfuscated_text


async def test_contained_and_disjoint_spans_are_left_alone(env: Env) -> None:
    """Absorption must not fire where there is nothing to absorb."""
    text = "SSN 123-45-6789 and name John Smith on file."
    ssn = span(text, "123-45-6789", "SSN")
    inner = Detection(  # fully contained by the SSN span, lower ranked
        entity_type="ACCOUNT_NUMBER", category=EntityCategory.FIN,
        start=ssn.start, end=ssn.start + 6, text=text[ssn.start : ssn.start + 6], score=0.5,
    )
    name = span(text, "John Smith", "NAME")

    result = await env.engine.obfuscate(
        env.session_id, text, [ssn, inner, name], strategy="tokenization"
    )

    assert len(result.spans) == 2, "the contained span collapses, the disjoint one survives"
    assert {item.entity_type for item in result.spans} == {"SSN", "NAME"}
    assert [(item.start, item.end) for item in result.spans] == [
        (ssn.start, ssn.end), (name.start, name.end)
    ], "a contained loser must not widen its winner"
    assert "123-45-6789" not in result.obfuscated_text
    assert "John Smith" not in result.obfuscated_text


async def test_out_of_range_spans_are_dropped(env: Env) -> None:
    text = "Short text."
    bogus = Detection(
        entity_type="SSN", category=EntityCategory.PII, start=5, end=500,
        text="123-45-6789", score=0.9,
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
        assert "John Smith" not in result.obfuscated_text
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
