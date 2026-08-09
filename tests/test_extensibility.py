"""Extensibility acceptance (build doc section 10.4) -- the config-only proof.

The challenge grades two extensibility claims, and this file holds both to the
same standard: run the whole pipeline, then **grep the package** and fail if it
learned the new name.

**Axis 1 -- a new entity type is added by editing configuration, and nothing
else.** Not "easy to add"; not "there is a plugin point". Nothing in
``secure_context_pipeline/`` learns a new symbol, a new branch, or a new name.

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

**Axis 2 -- "adding a new strategy touches ZERO HARNESS CODE" (challenge page 5,
Code Quality).** Same shape, same grep: :class:`ShroudStrategy` is declared in
*this file*, registered through the documented ``@register_strategy`` seam, and
driven through :class:`PipelineOrchestrator`, and no file under
``secure_context_pipeline/`` may contain its name.

That claim was true of the engine and **false of the pipeline** until the seam
below was closed, which is why the end-to-end run is the test rather than a unit
call. Measured at ``058dd18`` with the same third strategy and nothing else
changed: ``Settings(strategy=...)`` accepted it, detection and obfuscation ran,
the egress gate passed the payload to the provider, and the request then died in
``Restorer.restore`` with ``PipelineError(reason='unknown_strategy')`` -- a
frozenset of the two shipped names. ``POST /pipeline/run`` refused the same name
even earlier, with ``literal_error`` from a closed ``Literal`` in ``api/schemas``.
So a reviewer testing the rubric item the obvious way got a failed run, after the
payload had already left the process.

    THIS FILE ADDS NOTHING TO THE PACKAGE. The only artifacts it introduces are a
    YAML fragment written into ``tmp_path`` and a strategy class defined here and
    unregistered again on teardown. Every component below is imported unmodified
    and configured, never patched or monkeyed.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import shutil
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio
from pydantic import ValidationError

from fixtures import generator
from secure_context_pipeline.api.schemas import PipelineRunRequest
from secure_context_pipeline.audit.logger import DETECT, EGRESS_PASS, OBFUSCATE, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.errors import ConfigError, PipelineError
from secure_context_pipeline.llm.base import build_provider
from secure_context_pipeline.models import Detection, EntityAction, EntityCategory
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.obfuscation.strategies.base import (
    STRATEGIES,
    ObfuscationStrategy,
    RestoreMode,
    available_strategies,
    register_strategy,
    restore_mode,
)
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


# ---------------------------------------------------------------------------
# 5. Axis 2: a third obfuscation strategy, declared here and nowhere else
# ---------------------------------------------------------------------------

#: The plug-in strategy's config name. Chosen to be a word the package has no
#: reason to contain, because
#: :func:`test_the_package_never_learns_the_third_strategys_name` greps for it --
#: "redaction" would have been the natural name and is unusable for that: the
#: package says "redact" all over (``EntityAction.REDACTED``, the registry's
#: ``action: redact``), so the grep could never distinguish a leak from a hit.
THIRD_STRATEGY = "shroud"

#: Prefix of every surrogate :class:`ShroudStrategy` emits.
SHROUD_PREFIX = "SHROUD-"


class ShroudStrategy(ObfuscationStrategy):
    """Blanket redaction: every entity, every tier, one shape -- ``SHROUD-<id>``.

    Deliberately unlike both shipped strategies, so "it worked" cannot be an
    artifact of resembling one. It is not token-shaped, so
    ``PipelineOrchestrator._surrogate_map`` classifies it as a pseudonym and the
    restorer's surrogate pass is what brings the value back; and it has no tier
    dispatch, no Faker, and no format preservation.

    **The token ID is in the surrogate even though nothing reads it back out of
    the string**, and that is a pipeline constraint rather than a preference. A
    true constant -- ``"[REDACTED]"`` for every span -- is refused upstream of the
    restorer: measured, a two-entity document dies at step 4d with
    ``PipelineError(reason='surrogate_collision', entity_type='DATE')``, because
    ``_assert_surrogates_are_distinct`` refuses two originals sharing one
    surrogate. That guard is right (one surrogate cannot restore to two values),
    so a redacting strategy has to vary its output per value, and the token ID is
    the per-value string the engine already hands it.

    Registered by the :func:`third_strategy` fixture rather than by a decorator on
    the class, so importing this module does not mutate the process-wide registry
    that every other test in the session shares.
    """

    name = THIRD_STRATEGY
    restores_via = RestoreMode.SURROGATE_LOOKUP

    async def make_surrogate(
        self,
        detection: Detection,
        token_id: str,
        vault: SessionVault,
        *,
        session_id: str,
    ) -> str:
        """One shape for everything. ``detection.text`` is never read, never logged."""
        return f"{SHROUD_PREFIX}{token_id.upper()}"


@pytest.fixture
def third_strategy() -> Iterator[str]:
    """Register :class:`ShroudStrategy`, and take it back out again afterwards.

    ``STRATEGIES`` is module state shared by the whole session, so a test that
    registers and walks away would change what ``available_strategies()`` returns
    for every test after it -- including the two controls below, whose whole job is
    to observe the *unregistered* state.
    """
    register_strategy(ShroudStrategy)
    try:
        yield THIRD_STRATEGY
    finally:
        STRATEGIES.pop(THIRD_STRATEGY, None)


def test_the_package_never_learns_the_third_strategys_name(third_strategy: str) -> None:
    """No file under ``secure_context_pipeline/`` contains ``shroud``.

    The load-bearing assertion of axis 2, exactly as the ``PASSPORT`` grep is for
    axis 1. Everything below shows the strategy *works*; this shows it works with
    zero harness code -- and it is the assertion that goes red if the next person
    makes a third strategy pass by adding a branch, a constant, or an entry in a
    list of known names.
    """
    needle = re.compile(re.escape(THIRD_STRATEGY), re.IGNORECASE)
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in sorted(PACKAGE_ROOT.rglob("*"))
        if path.is_file()
        and "__pycache__" not in path.parts
        and needle.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert not offenders, (
        "the zero-harness-code claim is broken: these package files name the "
        f"plug-in strategy, so it is not a plug-in any more: {offenders}"
    )

    # ...and it really is registered, or the grep above would pass for the trivial
    # reason that the strategy does not exist.
    assert third_strategy in available_strategies()
    assert STRATEGIES[third_strategy] is ShroudStrategy


def test_an_unregistered_strategy_name_is_refused_everywhere() -> None:
    """Control: without the registration, all three seams say no.

    Deliberately does *not* use the ``third_strategy`` fixture. Without it, the
    difference between this test and the next two is one decorator call -- which is
    what "adding a strategy is one class plus one registry entry" has to mean. It
    also pins the fail-closed direction: widening these three checks from a
    hardcoded pair to a registry lookup must not make an unknown name *acceptable*.
    """
    assert THIRD_STRATEGY not in available_strategies()
    assert restore_mode(THIRD_STRATEGY) is None

    with pytest.raises(ConfigError) as config_exc:
        Settings(
            master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            strategy=THIRD_STRATEGY,
        )
    assert config_exc.value.detail["reason"] == "unknown_strategy"

    with pytest.raises(ValidationError):
        PipelineRunRequest(
            user_id=USER_ID, doc_id="doc", prompt=PROMPT, strategy=THIRD_STRATEGY
        )


def test_the_third_strategy_is_selectable_from_config_and_from_a_request(
    third_strategy: str,
) -> None:
    """``SCP_STRATEGY`` and ``POST /pipeline/run`` both accept the registered name.

    The request half is the one that used to be false. ``config.strategy`` was
    widened to a registry-checked ``str`` in an earlier pass while
    ``api/schemas.StrategyName`` stayed ``Literal["tokenization",
    "pseudonymization"]``, so a plug-in strategy was reachable from the environment
    and not from a request -- half a seam, which is the shape this project keeps
    finding.
    """
    settings = Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        strategy=third_strategy,
    )
    assert settings.strategy == third_strategy

    request = PipelineRunRequest(
        user_id=USER_ID, doc_id="doc", prompt=PROMPT, strategy=third_strategy
    )
    assert request.strategy == third_strategy

    # Widened to "any registered name", not to "any string".
    with pytest.raises(ValidationError):
        PipelineRunRequest(
            user_id=USER_ID, doc_id="doc", prompt=PROMPT, strategy="not-a-strategy"
        )


def test_the_restorer_asks_the_registry_how_to_undo_the_output(third_strategy: str) -> None:
    """The restore seam is a *declaration* lookup, not a name match.

    :func:`restore_mode` is what replaced ``restorer._KNOWN_STRATEGIES``. This binds
    both directions: a registered strategy answers with the mode it declared, and an
    unregistered name answers ``None``, which is the signal the restorer turns into
    ``unknown_strategy``.
    """
    assert restore_mode(third_strategy) is RestoreMode.SURROGATE_LOOKUP
    assert restore_mode("tokenization") is RestoreMode.TOKEN_ID
    assert restore_mode("pseudonymization") is RestoreMode.SURROGATE_LOOKUP
    assert restore_mode("not-a-strategy") is None


def test_registering_a_strategy_without_a_restore_mode_is_refused() -> None:
    """A plug-in author cannot forget to say how their output comes apart.

    The declaration is the only thing the restorer cannot work out for itself, so
    omitting it fails the *import* -- the same treatment a missing ``name`` gets, and
    for the same reason. Defaulting instead would be silent: the wrong default means
    a surrogate that is simply never restored, which reads to the user as a
    fabricated value rather than as an error.
    """
    class NoModeStrategy(ObfuscationStrategy):
        name = "no-mode"

        async def make_surrogate(
            self,
            detection: Detection,
            token_id: str,
            vault: SessionVault,
            *,
            session_id: str,
        ) -> str:
            return self.plain_token(detection, token_id)  # pragma: no cover

    with pytest.raises(ConfigError) as exc:
        register_strategy(NoModeStrategy)
    assert exc.value.detail["reason"] == "strategy_missing_restore_mode"
    assert "no-mode" not in STRATEGIES


async def test_a_third_strategy_runs_the_whole_pipeline_with_no_harness_change(
    build_pipeline: object, document: str, third_strategy: str
) -> None:
    """The graded claim, run the way a reviewer would test it.

    One class in this file, one ``register_strategy`` call, one strategy string --
    and the request goes all the way through ``PipelineOrchestrator``: detect,
    obfuscate, inject, egress gate, provider, restore, audit. Nothing here patches,
    subclasses or configures a harness component to make room for it.

    Two assertions carry the weight. The payload must contain no original (the
    strategy is doing its job), and the run must come back with the originals
    restored and no ``SHROUD-`` surrogate left behind -- which is precisely what
    failed before the restore seam was widened, and failed *after* the payload had
    already been handed to the provider.
    """
    harness: Harness = await build_pipeline(SHIPPED_REGISTRY)  # type: ignore[operator]
    doc_id = await harness.store.put(
        USER_ID, "disclosure.txt", document.encode("utf-8"), "financial"
    )
    session_id, _expires_at = await harness.sessions.create("test-user")

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, third_strategy
    )

    # -- the strategy really drove the run --------------------------------
    assert result.strategy == third_strategy
    obfuscated = [span for span in result.detections if span.action is EntityAction.OBFUSCATED]
    assert obfuscated, "no span was obfuscated; the run proves nothing"
    assert all(
        span.surrogate is not None and span.surrogate.startswith(SHROUD_PREFIX)
        for span in obfuscated
    ), "a surrogate did not come from the plug-in strategy"

    # -- nothing leaked ----------------------------------------------------
    originals = [document[span.start : span.end] for span in obfuscated]
    leaked = [value for value in originals if value in result.obfuscated_payload]
    assert not leaked, f"{len(leaked)} original values survived into the payload"

    # -- and it came back --------------------------------------------------
    assert SHROUD_PREFIX not in result.restored_text, (
        "a plug-in surrogate survived the restore pass"
    )
    assert result.stats["restored_count"] >= 1
    assert any(value in result.restored_text for value in originals)
    assert await harness.audit.verify_chain(session_id) is True

    # -- restoring one specific surrogate, without relying on what the mock
    #    chose to echo --------------------------------------------------------
    span = obfuscated[0]
    surrogate = span.surrogate
    assert surrogate is not None
    original = document[span.start : span.end]
    assert await harness.vault.get_by_surrogate(session_id, surrogate) == original

    restored = await harness.restorer.restore(
        session_id,
        f"The record names {surrogate} as the counterparty.",
        strategy=third_strategy,
        surrogates={surrogate: original},
    )
    assert original in restored.text
    assert surrogate not in restored.text
    assert restored.vault_misses == 0


async def test_the_restorer_still_refuses_a_strategy_nobody_registered(
    build_pipeline: object,
) -> None:
    """The widening did not turn the restore gate into a rubber stamp.

    The counterpart to the test above: the same call, one letter different in the
    strategy name, still fails closed with ``unknown_strategy`` rather than being
    waved through and restoring nothing.
    """
    harness: Harness = await build_pipeline(SHIPPED_REGISTRY)  # type: ignore[operator]
    session_id, _expires_at = await harness.sessions.create("test-user")

    with pytest.raises(PipelineError) as exc:
        await harness.restorer.restore(session_id, "nothing to do", strategy="shroudd")
    assert exc.value.detail["reason"] == "unknown_strategy"


def test_a_strategy_shipped_as_its_own_file_is_discovered(tmp_path: Path) -> None:
    """A strategy in its own module must register with no edit to the base class.

    The existing third-strategy test declares its class INLINE, in a module pytest
    imports anyway -- so `@register_strategy` runs whether or not discovery works.
    It tests the decorator, not the seam, and it stayed green while the seam was
    broken: `_load_builtins` walked a hardcoded
    `_BUILTIN_MODULES = ("tokenization", "pseudonymization")`, so a strategy shipped
    as a FILE in the strategies package was never imported and `build_strategy`
    could not find it. Adding one meant editing a tuple in the base class, which is
    the "zero harness code" requirement failing in the one way its own test could
    not see.

    So this test writes a real file into a real copy of the package and asks
    `available_strategies()` -- the public discovery entry point -- whether it is
    there. It never imports the module itself, because importing it would run the
    decorator and reproduce exactly the blind spot described above.

    Run in a subprocess against a copied package rather than the live one: discovery
    caches into a module-level dict, and dropping a file into the real tree would
    leak a strategy into every later test in the session.
    """
    pkg_root = tmp_path / "secure_context_pipeline"
    shutil.copytree(Path(__file__).resolve().parents[1] / "secure_context_pipeline", pkg_root)
    (pkg_root / "obfuscation" / "strategies" / "plugin_probe.py").write_text(
        "from secure_context_pipeline.obfuscation.strategies.base import (\n"
        "    ObfuscationStrategy,\n"
        "    RestoreMode,\n"
        "    register_strategy,\n"
        ")\n"
        "\n"
        "\n"
        "@register_strategy\n"
        "class PluginProbeStrategy(ObfuscationStrategy):\n"
        "    name = 'plugin_probe'\n"
        "    restores_via = RestoreMode.TOKEN_ID\n"
        "\n"
        "    async def make_surrogate(self, detection, token_id, vault, *, session_id):\n"
        "        return '[PROBE]'\n",
        encoding="utf-8",
    )
    probe = tmp_path / "probe.py"
    probe.write_text(
        "from secure_context_pipeline.obfuscation.strategies.base import "
        "available_strategies\n"
        "print(','.join(available_strategies()))\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(probe)],
        cwd=tmp_path, capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    names = result.stdout.strip().split(",")
    assert "plugin_probe" in names, (
        "a strategy shipped as its own file was not discovered, so 'adding a new "
        f"strategy touches zero harness code' is false: {names}"
    )
    # Non-vacuity: the copy is a working package, not an empty one.
    assert {"tokenization", "pseudonymization"} <= set(names), names
