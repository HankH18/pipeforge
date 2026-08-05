"""Extensibility acceptance (build doc section 10.4) -- the config-only proof.

The claim under test is the strong form of the challenge's extensibility
requirement: **a new entity type is added by editing configuration, and nothing
else.** Not "a new entity type is easy to add"; not "there is a plugin point".
Nothing in ``secure_context_pipeline/`` learns a new symbol, a new branch, or a
new name.

So this file does two things:

1. It writes a fixture ``entities.yaml`` -- the shipped registry, verbatim, with
   a ``PASSPORT_NUMBER`` block appended -- and runs the **entire pipeline** on a
   document containing a passport number: detected, obfuscated, egress-checked,
   restored, and audited, end to end.
2. It greps ``secure_context_pipeline/`` for the string ``PASSPORT`` and fails if
   it finds one. That grep is the actual proof. Without it, "config only" is a
   claim about how the test was written; with it, the test cannot pass if anybody
   ever satisfies it by teaching the package about passports.

A control case runs the same document against the shipped registry and asserts
the passport number is *not* detected -- so the difference between the two runs
is provably the six lines of YAML and nothing else.

    THIS FILE ADDS NOTHING TO THE PACKAGE. The only artifact it introduces is a
    YAML fragment written into ``tmp_path``. Every component below is imported
    unmodified and configured, never subclassed, patched, or extended.
"""

from __future__ import annotations

import base64
import re
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio

from fixtures import generator
from secure_context_pipeline.audit.logger import DETECT, EGRESS_PASS, OBFUSCATE, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.llm.base import build_provider
from secure_context_pipeline.models import EntityAction, EntityCategory
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "secure_context_pipeline"
SHIPPED_REGISTRY = REPO_ROOT / "entities.yaml"

USER_ID = "extensibility-user"
PROMPT = "Summarise this file and list every identifier it contains."
SEED = generator.DEFAULT_SEED

#: The registry addition, verbatim from build doc section 10.4.
PASSPORT_ENTITY_YAML = """
  PASSPORT_NUMBER:
    category: PII
    patterns: ['\\b[A-Z]{1,2}\\d{7,8}\\b']
    context: [passport]
"""

#: A synthetic identifier of the passport shape -- one letter, seven digits.
#: Deliberately one letter, not two: ``INSURANCE_ID``'s shipped pattern is
#: ``\\b[A-Z]{2,4}\\d{7,12}\\b``, so a two-letter prefix would be claimed by an
#: entity type that already exists and the control case below would be a lie.
PASSPORT_NUMBER = "L8842176"

PASSPORT_PARAGRAPH = (
    "\nTravel Documentation\n"
    f"The client's passport number on file is {PASSPORT_NUMBER}, issued abroad.\n"
    "A copy of the passport biodata page is retained with the engagement letter.\n"
)


# ---------------------------------------------------------------------------
# The one artifact this test introduces: a config file.
# ---------------------------------------------------------------------------


@pytest.fixture
def extended_registry_path(tmp_path: Path) -> Path:
    """The shipped ``entities.yaml`` with ``PASSPORT_NUMBER`` appended.

    Copied rather than hand-written so the fixture cannot drift from the real
    registry: whatever ships is what runs, plus six lines.
    """
    shipped = SHIPPED_REGISTRY.read_text(encoding="utf-8")
    path = tmp_path / "entities.yaml"
    path.write_text(shipped.rstrip("\n") + "\n" + PASSPORT_ENTITY_YAML, encoding="utf-8")
    return path


@pytest.fixture
def document() -> str:
    """A generator-produced financial disclosure with a passport paragraph added."""
    return generator.generate(SEED, "financial") + PASSPORT_PARAGRAPH


# ---------------------------------------------------------------------------
# Harness -- assembled from unmodified components
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
    restorer: Restorer
    orchestrator: PipelineOrchestrator


@pytest_asyncio.fixture
async def build_pipeline(tmp_path: Path) -> AsyncIterator[object]:
    """Factory: give it a registry path, get a fully-wired pipeline back."""
    built: list[Harness] = []
    counter = 0

    async def _build(registry_path: Path) -> Harness:
        nonlocal counter
        counter += 1
        root = tmp_path / f"pipe{counter}"
        root.mkdir(parents=True, exist_ok=True)
        settings = Settings(
            master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            data_dir=root / "data",
            registry_path=registry_path,
            llm_provider="mock",
        )
        registry = load_registry(registry_path)
        detector = Detector(registry, settings)
        audit = await AuditLogger.open(root / "audit.db")
        store = await EncryptedDocumentStore.open(settings)
        sessions = SessionRegistry(settings)
        vault = await SessionVault.open(root / "vault.db", sessions)
        restorer = Restorer(vault=vault, settings=settings, audit=audit)
        harness = Harness(
            settings=settings,
            registry=registry,
            detector=detector,
            store=store,
            sessions=sessions,
            vault=vault,
            audit=audit,
            restorer=restorer,
            orchestrator=PipelineOrchestrator(
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
                gate=EgressGate(
                    vault=vault, detector=detector, settings=settings, audit=audit
                ),
                provider=build_provider(settings),
                restorer=restorer,
                vault=vault,
                settings=settings,
                audit=audit,
            ),
        )
        built.append(harness)
        return harness

    try:
        yield _build
    finally:
        for harness in reversed(built):
            await harness.vault.close()
            await harness.store.close()
            await harness.audit.close()


# ---------------------------------------------------------------------------
# 1. The proof that the claim is about config and not about this test
# ---------------------------------------------------------------------------


def test_package_source_never_mentions_passport(extended_registry_path: Path) -> None:
    """No file under ``secure_context_pipeline/`` contains the string ``PASSPORT``.

    This is the load-bearing assertion of the whole file. Everything else here
    shows that ``PASSPORT_NUMBER`` *works*; this shows it works without the
    package knowing it exists. If someone ever makes the pipeline pass by adding a
    branch, a constant, an enum member, or a comment naming passports, this test
    goes red and the extensibility claim in the README stops being true.
    """
    needle = re.compile(r"passport", re.IGNORECASE)
    offenders: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        body = path.read_text(encoding="utf-8", errors="ignore")
        if needle.search(body):
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, (
        "the config-extensibility claim is broken: these package files mention "
        f"passports, so the entity type is not config-only any more: {offenders}"
    )

    # And the entity really is defined in config -- otherwise the grep above
    # would pass for the trivial reason that nothing defines it anywhere.
    registry = load_registry(extended_registry_path)
    spec = registry.spec("PASSPORT_NUMBER")
    assert spec.category is EntityCategory.PII
    assert spec.patterns == (r"\b[A-Z]{1,2}\d{7,8}\b",)
    assert spec.context == ("passport",)


# ---------------------------------------------------------------------------
# 2. Control: the shipped registry does not know this entity type
# ---------------------------------------------------------------------------


async def test_shipped_registry_does_not_detect_the_passport_number(
    build_pipeline: object, document: str
) -> None:
    """Before the config change, the value is invisible.

    Without this the acceptance test proves only that *something* detected the
    number, not that the YAML block is what did.
    """
    harness: Harness = await build_pipeline(SHIPPED_REGISTRY)  # type: ignore[operator]
    assert "PASSPORT_NUMBER" not in harness.registry.entities

    detections = await harness.detector.detect(document, "financial")
    assert not [d for d in detections if PASSPORT_NUMBER in d.text], (
        "the shipped registry already claims this value; the control is not a control"
    )
    assert not [d for d in detections if d.entity_type == "PASSPORT_NUMBER"]


# ---------------------------------------------------------------------------
# 3. Acceptance: detected, obfuscated, restored, audited -- via config alone
# ---------------------------------------------------------------------------


async def test_passport_number_is_detected_obfuscated_restored_and_audited(
    build_pipeline: object, extended_registry_path: Path, document: str
) -> None:
    """The section 10.4 acceptance case, run through the real pipeline."""
    harness: Harness = await build_pipeline(extended_registry_path)  # type: ignore[operator]
    doc_id = await harness.store.put(
        USER_ID, "disclosure.txt", document.encode("utf-8"), "financial"
    )
    session_id, _expires_at = await harness.sessions.create("test-user")

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    # -- detected ----------------------------------------------------------
    passport_spans = [
        span for span in result.detections if span.entity_type == "PASSPORT_NUMBER"
    ]
    assert passport_spans, "PASSPORT_NUMBER was not detected after the config change"
    assert all(span.category is EntityCategory.PII for span in passport_spans)
    assert all(span.action is EntityAction.OBFUSCATED for span in passport_spans)
    assert document[passport_spans[0].start : passport_spans[0].end] == PASSPORT_NUMBER

    # -- obfuscated --------------------------------------------------------
    surrogate = passport_spans[0].surrogate
    assert surrogate is not None
    assert surrogate.startswith("[PII_PASSPORT_NUMBER_")
    assert PASSPORT_NUMBER not in result.obfuscated_payload
    assert surrogate in result.obfuscated_payload

    # -- vaulted, and reversible only through the vault --------------------
    assert PASSPORT_NUMBER in harness.vault.originals_for_session(session_id)
    assert await harness.vault.get_by_surrogate(session_id, surrogate) == PASSPORT_NUMBER

    # -- restored ----------------------------------------------------------
    assert surrogate not in result.restored_text
    assert PASSPORT_NUMBER in result.restored_text, (
        "the passport number did not come back out of the round trip"
    )

    # -- audited -----------------------------------------------------------
    events = await harness.audit.query(session_id=session_id, limit=10_000)
    assert {DETECT, OBFUSCATE, EGRESS_PASS} <= {event.event_type for event in events}
    obfuscation_events = [
        event
        for event in events
        if event.event_type == OBFUSCATE and event.entity_type == "PASSPORT_NUMBER"
    ]
    assert obfuscation_events, "no OBFUSCATE audit event names the new entity type"
    assert all(event.run_id == result.run_id for event in obfuscation_events)
    # The audit log records the type and the token, never the value (section 16).
    assert all(
        PASSPORT_NUMBER not in str(event.detail) for event in events
    ), "an audit event carried the passport number itself"
    assert await harness.audit.verify_chain(session_id) is True


# ---------------------------------------------------------------------------
# 4. The same entity type under the other strategy
# ---------------------------------------------------------------------------


async def test_passport_number_works_under_pseudonymization_too(
    build_pipeline: object, extended_registry_path: Path, document: str
) -> None:
    """Config-only extensibility is strategy-independent: the engine never
    special-cases an entity name, so a new type gets the configured strategy for
    free.

    The restore leg is driven directly rather than through the mock: in
    pseudonymization mode the payload contains realistic fakes rather than
    tokens, so the mock falls back to echoing the document's *longest* lines and
    which entities it quotes is an artifact of line length, not of the pipeline.
    Restoring the emitted surrogate is the property that matters.
    """
    harness: Harness = await build_pipeline(extended_registry_path)  # type: ignore[operator]
    doc_id = await harness.store.put(
        USER_ID, "disclosure.txt", document.encode("utf-8"), "financial"
    )
    session_id, _expires_at = await harness.sessions.create("test-user")

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "pseudonymization"
    )

    passport_spans = [
        span for span in result.detections if span.entity_type == "PASSPORT_NUMBER"
    ]
    assert passport_spans
    surrogate = passport_spans[0].surrogate
    assert surrogate is not None
    assert surrogate != PASSPORT_NUMBER
    assert PASSPORT_NUMBER not in result.obfuscated_payload
    assert await harness.vault.get_by_surrogate(session_id, surrogate) == PASSPORT_NUMBER

    answer = f"The engagement file lists {surrogate} as the client's travel document."
    restored = await harness.restorer.restore(
        session_id,
        answer,
        strategy="pseudonymization",
        surrogates={surrogate: PASSPORT_NUMBER},
    )
    assert PASSPORT_NUMBER in restored.text
    assert surrogate not in restored.text
    assert restored.vault_misses == 0
