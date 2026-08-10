"""Spec-mandated end-to-end cases (build doc section 10.6).

These are the five cases the challenge names by test ID, run against the *real*
component graph -- real encrypted store, real spaCy detection, real engine, real
vault, real egress gate, real restorer, real hash-chained audit log -- with only
the LLM replaced by a deterministic local provider.

    test_happy_path_end_to_end
    test_entity_type_not_found
    test_vault_miss_on_deobfuscation
    test_expired_session
    test_concurrent_session_isolation

Plus the two properties the live review asks about directly:

* **Run correlation** -- every audit event a run emits carries that run's
  ``run_id``, which is what makes "reconstruct the whole detect -> obfuscate ->
  egress -> LLM -> restore chain for this request" a single query.
* **Destroy-then-restore** -- once the session key is popped, the same response
  that restored a moment ago cannot be restored at all. Cryptographic erasure,
  demonstrated rather than asserted about.

The spaCy analyzer is built once for the module; every test gets its own
databases, its own sessions, and its own provider, so nothing leaks between them.
"""

from __future__ import annotations

import asyncio
import base64
import re
import secrets
import textwrap
import time
import unicodedata
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from fixtures import generator
from secure_context_pipeline.audit.logger import (
    DEOBFUSCATE,
    DETECT,
    EGRESS_BLOCK,
    EGRESS_PASS,
    LLM_CALL,
    OBFUSCATE,
    VAULT_MISS,
    AuditLogger,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.aead import decrypt, doc_aad
from secure_context_pipeline.crypto.keys import build_key_provider, normalize
from secure_context_pipeline.deobfuscation.restorer import UNRESOLVED_ENTITY, Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.errors import (
    CryptoAuthError,
    EgressBlockedError,
    SessionExpiredError,
    VaultMissError,
)
from secure_context_pipeline.llm.base import LLMResponse, estimate_tokens
from secure_context_pipeline.llm.mock_provider import MockProvider
from secure_context_pipeline.models import (
    AuditEvent,
    Detection,
    EntityAction,
    EntityCategory,
)
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline import orchestrator as orchestrator_module
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate, EgressReport
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import RAW_SUFFIX, EncryptedDocumentStore
from secure_context_pipeline.surrogates import (
    HINT_RE,
    MAX_HINT_LEN,
    STRICT_TOKEN_RE,
    TOKEN_RE,
)
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "entities.yaml"

USER_ID = "integration-user"
OTHER_USER_ID = "someone-else"
PROMPT = "Summarise this record and list the parties, dates and figures involved."
SEED = generator.DEFAULT_SEED

#: A document a correctly-configured detector finds nothing in: process prose,
#: no names, no numbers, no dates, no identifiers of any kind.
NO_ENTITY_DOCUMENT = (
    "Operational Checklist\n\n"
    "The quarterly review process was completed.\n"
    "All procedures followed the standard operating guidelines.\n"
    "Recommendations will be circulated after the next scheduled meeting.\n"
    "No further action is required at this time.\n"
)

#: An 8-hex token ID the vault will never have issued for a fresh session.
UNKNOWN_TOKEN_ID = "deadbeef"


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


class CountingMockProvider:
    """The shipped mock, plus a call counter and every payload it was handed.

    ``last_user`` is what a single-run test asks about. ``users`` is the list of
    *all* of them, in call order, and it exists because a concurrent test cannot
    ask ``last_user`` anything meaningful: with two runs in flight the second
    overwrites the first, so "did this value ever cross the boundary" is a
    question only the whole list can answer. It is append-only and nothing else
    reads it, so no existing expectation moves.
    """

    name = "mock"

    def __init__(self) -> None:
        self._inner = MockProvider()
        self.calls = 0
        self.last_user: str | None = None
        self.users: list[str] = []

    async def complete(self, system: str, user: str, *, model: str, timeout_s: float = 60.0) -> str:
        return (await self.complete_detailed(system, user, model=model, timeout_s=timeout_s)).text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        self.calls += 1
        self.last_user = user
        self.users.append(user)
        return await self._inner.complete_detailed(system, user, model=model, timeout_s=timeout_s)


class ScriptedProvider:
    """Returns a fixed answer, whatever the payload.

    Used to put the pipeline in a state a well-behaved model would not produce --
    specifically, a token that was never issued.
    """

    name = "scripted"

    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls = 0
        self.last_user: str | None = None

    async def complete(self, system: str, user: str, *, model: str, timeout_s: float = 60.0) -> str:
        return (await self.complete_detailed(system, user, model=model, timeout_s=timeout_s)).text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        self.calls += 1
        self.last_user = user
        await asyncio.sleep(0)
        return LLMResponse(
            text=self.answer,
            input_tokens=estimate_tokens(system) + estimate_tokens(user),
            output_tokens=estimate_tokens(self.answer),
            model=model,
        )


class SeamedGate:
    """The real :class:`EgressGate` with one seam: a hook that runs before pass 1.

    It exists so that the window between "the engine finished building the payload"
    and "the gate reads the session's originals" can be *driven* rather than waited
    for. That window is a handful of awaits wide -- ``check()`` is the next thing the
    orchestrator does after obfuscation, and ``originals_for_session`` is read inside
    it -- so the only way another coroutine reliably lands a vault write in the middle
    of it is to put the hook exactly here. The alternative, running the scenario until
    the interleaving happens by luck, is measured elsewhere in this file at roughly
    one whole test execution in fourteen, which is not a test, it is a lottery ticket.

    **One-shot on purpose.** The hook is popped before it is awaited, so a hook that
    itself drives a complete pipeline run -- which is the realistic session-mate, and
    the only kind whose vault write goes through the code the product actually runs
    -- re-enters this gate without recursing.

    Nothing else is wrapped. The payload, the session, the surrogates and the run ID
    are handed to the real gate untouched, and the real gate's report, or its
    ``EgressBlockedError``, is what the caller sees. A test using this seam is still
    testing the shipped gate: the seam changes *when* pass 1 runs relative to another
    coroutine, never *what* it does.
    """

    def __init__(self, inner: EgressGate) -> None:
        self.inner = inner
        self.before_check: Callable[[str, str], Any] | None = None

    async def check(
        self,
        payload: str,
        session_id: str,
        *,
        surrogates: frozenset[str] = frozenset(),
        run_id: str | None = None,
    ) -> EgressReport:
        hook, self.before_check = self.before_check, None
        if hook is not None:
            await hook(payload, session_id)
        return await self.inner.check(
            payload, session_id, surrogates=surrogates, run_id=run_id
        )


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class MutableClock:
    """A hand-cranked clock, so TTL behaviour is testable without sleeping."""

    def __init__(self, start: float | None = None) -> None:
        self.now = time.time() if start is None else start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass(slots=True)
class Harness:
    settings: Settings
    registry: EntityRegistry
    detector: Detector
    store: EncryptedDocumentStore
    sessions: SessionRegistry
    vault: SessionVault
    audit: AuditLogger
    engine: ObfuscationEngine
    restorer: Restorer
    provider: Any
    #: The gate object the orchestrator was actually wired with -- the real
    #: :class:`EgressGate` unless the test asked for ``seamed_gate=True``, in which
    #: case it is the :class:`SeamedGate` wrapper around it. Exposed so a test can
    #: install a hook on the same object the pipeline calls, rather than reaching
    #: into ``orchestrator._gate``.
    gate: Any
    orchestrator: PipelineOrchestrator
    clock: MutableClock | None = None
    _closed: bool = field(default=False)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Order matters only in that all three must happen: an unclosed aiosqlite
        # connection keeps a non-daemon thread alive and hangs interpreter exit.
        await self.vault.close()
        await self.store.close()
        await self.audit.close()

    async def upload(self, text: str, doc_category: str, filename: str = "doc.txt") -> str:
        return await self.store.put(USER_ID, filename, text.encode("utf-8"), doc_category)


@pytest.fixture(scope="module")
def registry() -> EntityRegistry:
    return load_registry(REGISTRY_PATH)


@pytest.fixture(scope="module")
def module_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Settings used only to build the shared Detector (thresholds + registry)."""
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("integration-detector"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def detector(registry: EntityRegistry, module_settings: Settings) -> Detector:
    """Built ONCE: constructing a Detector loads spaCy, which is the slow part."""
    return Detector(registry, module_settings)


HarnessFactory = Callable[..., Any]


@pytest_asyncio.fixture
async def make_harness(
    registry: EntityRegistry, detector: Detector, tmp_path: Path
) -> AsyncIterator[HarnessFactory]:
    """Factory for fully-wired, mutually isolated pipelines.

    Each harness gets its own data directory, vault DB and audit DB, so a test can
    assert on absolute row counts and on "the only events in this log".
    """
    built: list[Harness] = []
    counter = 0

    async def _make(
        *,
        provider: Any | None = None,
        clock: MutableClock | None = None,
        strategy: str = "tokenization",
        seamed_gate: bool = False,
        without_ssn_backstop: bool = False,
    ) -> Harness:
        """``without_ssn_backstop`` deletes ONE registry field and rebuilds the detector.

        It is the registry that shipped before ``entities.yaml`` grew ``SSN.patterns``,
        and it exists so an integration test can still ask "does the egress gate hold
        when detection does not?" now that detection claims the same values. Detection
        is configuration and the gate is the guarantee; this flag *is* the
        configuration edit, applied deliberately, so the claim is measured rather than
        asserted. Everything else about the detector is the real thing -- a
        ``FakeDetector`` would let the test invent the premise it needs.

        It costs a second spaCy pipeline, which is why it is off by default and why
        exactly one test asks for it.
        """
        nonlocal counter
        counter += 1
        root = tmp_path / f"h{counter}"
        root.mkdir(parents=True, exist_ok=True)
        settings = Settings(
            master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            data_dir=root / "data",
            registry_path=REGISTRY_PATH,
            llm_provider="mock",
            strategy=strategy,  # type: ignore[arg-type]
        )
        in_use, detector_in_use = registry, detector
        if without_ssn_backstop:
            assert registry.entities["SSN"].patterns, (
                "entities.yaml no longer carries an SSN backstop; this flag is supposed "
                "to REMOVE one, and removing nothing makes the test that uses it pass "
                "for the wrong reason"
            )
            entities = dict(registry.entities)
            entities["SSN"] = entities["SSN"].model_copy(update={"patterns": ()})
            in_use = registry.model_copy(update={"entities": entities})
            detector_in_use = Detector(in_use, settings)

        audit = await AuditLogger.open(root / "audit.db")
        store = await EncryptedDocumentStore.open(settings)
        sessions = (
            SessionRegistry(settings)
            if clock is None
            else SessionRegistry(settings, clock=clock)
        )
        vault = await SessionVault.open(root / "vault.db", sessions)
        engine = ObfuscationEngine(
            registry=in_use,
            vault=vault,
            session_registry=sessions,
            settings=settings,
            audit=audit,
        )
        restorer = Restorer(vault=vault, settings=settings, audit=audit)
        chosen = CountingMockProvider() if provider is None else provider
        # Default OFF: every other test in this file is wired with the real gate
        # object and nothing between it and the orchestrator, so the seam cannot
        # change what any of them measure. Only the test that needs to drive the
        # build-vs-gate interleaving asks for it. See :class:`SeamedGate`.
        real_gate = EgressGate(
            vault=vault, detector=detector_in_use, settings=settings, audit=audit
        )
        gate: Any = SeamedGate(real_gate) if seamed_gate else real_gate
        harness = Harness(
            settings=settings,
            registry=in_use,
            detector=detector_in_use,
            store=store,
            sessions=sessions,
            vault=vault,
            audit=audit,
            engine=engine,
            restorer=restorer,
            provider=chosen,
            gate=gate,
            orchestrator=PipelineOrchestrator(
                store=store,
                detector=detector_in_use,
                engine=engine,
                injector=ContextInjector(),
                gate=gate,
                provider=chosen,
                restorer=restorer,
                vault=vault,
                settings=settings,
                audit=audit,
            ),
            clock=clock,
        )
        built.append(harness)
        return harness

    try:
        yield _make
    finally:
        for harness in reversed(built):
            await harness.close()


def leaked_originals(originals: frozenset[str], haystack: str) -> list[str]:
    """Originals present in ``haystack``, raw or normalised -- both forms, as the gate scans."""
    folded = normalize(haystack)
    return sorted(o for o in originals if o in haystack or normalize(o) in folded)


def document_section(payload: str) -> str:
    """Just the fenced document out of an outbound payload.

    The tokenization system prompt quotes ``[PHI_NAME_1a2b3c4d]`` as an example of
    the token contract, so "does the payload contain a token" is always true and
    says nothing. The question that matters is whether the *document* does.
    """
    opening = payload.index("<DOCUMENT>") + len("<DOCUMENT>")
    closing = payload.index("</DOCUMENT>")
    return payload[opening:closing]


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


async def test_happy_path_end_to_end(make_harness: HarnessFactory) -> None:
    """Upload -> detect -> obfuscate -> gate -> model -> restore, all of it real."""
    harness: Harness = await make_harness()
    document = generator.generate(SEED, "medical")
    doc_id = await harness.upload(document, "medical", "medical_note.txt")
    session_id, expires_at = await harness.sessions.create("test-user")
    assert expires_at > time.time()

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    # The run actually did work.
    assert result.run_id
    assert result.strategy == "tokenization"
    assert harness.provider.calls == 1
    assert result.stats["entities_detected"] > 0
    assert result.stats["tokens_issued"] > 0
    assert await harness.vault.row_count(session_id) == int(result.stats["tokens_issued"])

    # Nothing sensitive left the process.
    originals = harness.vault.originals_for_session(session_id)
    assert originals
    assert not leaked_originals(originals, result.obfuscated_payload)
    assert harness.provider.last_user is not None
    assert harness.provider.last_user in result.obfuscated_payload, (
        "the gate scanned a string the provider did not receive"
    )

    # The document really is obfuscated, not merely clean.
    assert STRICT_TOKEN_RE.search(document_section(result.obfuscated_payload)) is not None

    # The answer came back readable: originals restored, no tokens left behind.
    assert result.restored_text
    assert not TOKEN_RE.search(result.restored_text)
    assert UNRESOLVED_ENTITY not in result.restored_text
    assert result.stats["restored_count"] > 0
    assert result.stats["vault_misses"] == 0

    # Every stage is on the record, and the record is intact.
    events = await harness.audit.query(session_id=session_id, limit=1000)
    kinds = {event.event_type for event in events}
    assert {DETECT, OBFUSCATE, EGRESS_PASS, LLM_CALL, DEOBFUSCATE} <= kinds
    assert await harness.audit.verify_chain(session_id) is True

    # Storage isolation: the document is not readable as another user (section 8).
    from secure_context_pipeline.errors import StoreAuthError

    with pytest.raises(StoreAuthError):
        await harness.store.get_text(OTHER_USER_ID, doc_id)


# ---------------------------------------------------------------------------
# 2. No detectable entities
# ---------------------------------------------------------------------------


async def test_a_run_that_vaulted_values_blocks_if_pass_one_scanned_an_empty_set(
    make_harness: HarnessFactory,
) -> None:
    """The gate's most load-bearing pass is the one that fails silently.

    Pass 1 is the only pass independent of detector recall, and with an empty
    originals set it is a no-op that returns 0 rather than an error.
    ``SessionVault.originals_for_session`` returns ``frozenset()`` for an unknown or
    destroyed session -- "fails safe" for the vault's contract, and the exact opposite
    for the gate's. The resulting ``EGRESS_PASS`` carries ``originals_scanned: 0``,
    which is byte-identical in the audit trail to a document that legitimately held
    nothing sensitive.

    Before ``_verify_pass_one_had_something_to_scan``, **nothing in the system read
    that field back**: it was set, written to the audit detail, and asserted only in
    tests. This drives the fault directly -- a vault whose cache has gone away
    underneath a run that really did vault values -- and requires the run to block
    rather than to call the provider.

    The two numbers compared are differently sourced on purpose: the token count is
    the run's own manifest from the obfuscation stage, and ``originals_scanned`` comes
    back from the vault's cache through the gate. That is what makes their agreement
    evidence rather than a restatement.
    """
    harness: Harness = await make_harness()
    document = generator.generate(SEED, "medical")
    doc_id = await harness.upload(document, "medical", "medical_note.txt")
    session_id, _ = await harness.sessions.create("test-user")

    real_originals = harness.vault.originals_for_session

    def _amnesiac(sid: str) -> frozenset[str]:
        """The vault forgets, exactly as it does for a destroyed session."""
        return frozenset()

    harness.vault.originals_for_session = _amnesiac  # type: ignore[method-assign]
    try:
        with pytest.raises(EgressBlockedError) as exc:
            await harness.orchestrator.run(
                session_id, USER_ID, doc_id, PROMPT, "tokenization"
            )
    finally:
        harness.vault.originals_for_session = real_originals  # type: ignore[method-assign]

    assert exc.value.detail["reason"] == "pass_one_scanned_nothing"
    assert harness.provider.calls == 0, "the provider must not be reached"

    events = await harness.audit.query(session_id=session_id, limit=1000)
    blocks = [e for e in events if e.event_type == EGRESS_BLOCK]
    assert [e.detail["reason"] for e in blocks] == ["pass_one_scanned_nothing"]
    assert blocks[0].detail["tokens_issued"] > 0
    assert await harness.audit.verify_chain(session_id) is True


async def test_entity_type_not_found(make_harness: HarnessFactory) -> None:
    """A document with nothing sensitive in it: the pipeline succeeds and stays empty.

    Zero vault rows is the point. A pipeline that vaults *something* for every
    document is one that over-detects, and every spurious vault row is a value the
    egress gate will then block ordinary payloads on.
    """
    harness: Harness = await make_harness()
    doc_id = await harness.upload(NO_ENTITY_DOCUMENT, "general", "checklist.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")

    detections = await harness.detector.detect(NO_ENTITY_DOCUMENT, "general")
    assert detections == [], f"expected a clean document, detector found {detections}"

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    # Pipeline succeeded and the model was called -- the gate passed.
    assert harness.provider.calls == 1
    assert result.restored_text

    # Zero vault rows, in the cache and on disk.
    assert result.stats["tokens_issued"] == 0
    assert result.detections == []
    assert harness.vault.originals_for_session(session_id) == frozenset()
    assert await harness.vault.row_count(session_id) == 0

    # The document went out untouched: nothing was obfuscated, nothing redacted.
    body = document_section(result.obfuscated_payload)
    assert body.strip() == NO_ENTITY_DOCUMENT.strip()
    assert not TOKEN_RE.search(body)

    # The gate ran and passed with an empty originals set.
    passes = await harness.audit.query(session_id=session_id, event_type=EGRESS_PASS)
    assert len(passes) == 1
    assert passes[0].detail["originals_scanned"] == 0


# ---------------------------------------------------------------------------
# 3. Vault miss on de-obfuscation
# ---------------------------------------------------------------------------


async def test_vault_miss_on_deobfuscation(make_harness: HarnessFactory) -> None:
    """A token the vault never issued degrades the answer; it must not fail the request."""
    answer = (
        "Summary of the reviewed record.\n\n"
        f"- The intake note lists [PHI_NAME_{UNKNOWN_TOKEN_ID}].\n"
        f"- Correspondence references [PHI_NAME_{UNKNOWN_TOKEN_ID}] again.\n"
    )
    harness: Harness = await make_harness(provider=ScriptedProvider(answer))
    document = generator.generate(SEED, "medical")
    doc_id = await harness.upload(document, "medical", "medical_note.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    # Guard the premise: if this ID had genuinely been issued the test would be
    # asserting the opposite of what it claims.
    issued = {
        match.group(3)
        for span in result.detections
        if span.surrogate
        for match in [STRICT_TOKEN_RE.fullmatch(span.surrogate)]
        if match is not None
    }
    assert UNKNOWN_TOKEN_ID not in issued

    # Degraded, not crashed.
    assert result.restored_text.count(UNRESOLVED_ENTITY) == 2
    assert result.stats["vault_misses"] == 2
    assert result.stats["restored_count"] == 0
    assert not TOKEN_RE.search(result.restored_text)

    # And audited, once per distinct unknown token, with no value and -- on this
    # path -- no token ID either. The orchestrator supplies `issued`, so a token the
    # model invented classifies as `fabricated`, and its ID is eight characters
    # taken from the model's own bytes rather than anything this session minted.
    # `Restorer._fail` records why those must not reach `GET /audit`: a document's
    # own "PHI-" in front of a restored "MRN-40281993" makes them eight digits of a
    # patient's MRN. A LOST miss -- an ID we did mint -- still carries it, which is
    # `test_both_kinds_of_miss_are_separated_in_one_response`.
    misses = await harness.audit.query(session_id=session_id, event_type=VAULT_MISS)
    assert len(misses) == 1
    assert misses[0].token_id is None
    assert misses[0].detail["classification"] == "fabricated"
    assert UNKNOWN_TOKEN_ID not in misses[0].model_dump_json()
    assert misses[0].run_id == result.run_id
    assert misses[0].detail["reason"] == "token_not_in_vault"
    assert await harness.audit.verify_chain(session_id) is True


# ---------------------------------------------------------------------------
# 4. Expired session
# ---------------------------------------------------------------------------


async def test_expired_session(make_harness: HarnessFactory) -> None:
    """TTL elapses -> ``SessionExpiredError``, and the vault it protected is gone.

    Two halves, because they prove different things:

    * a TTL of 0 refuses the run outright -- the pipeline never reaches the
      provider with a session it cannot restore from;
    * a session that had *already vaulted* values loses access to them the instant
      its key is swept, and the rows are then destroyed. That is the erasure
      claim, and it needs a populated vault to mean anything.
    """
    clock = MutableClock()
    harness: Harness = await make_harness(clock=clock)
    document = generator.generate(SEED, "medical")
    doc_id = await harness.upload(document, "medical", "medical_note.txt")

    # -- half one: TTL of 0, expired before it is ever used ------------------
    dead_id, _expires_at = await harness.sessions.create("test-user", ttl_seconds=0)
    with pytest.raises(SessionExpiredError):
        await harness.orchestrator.run(dead_id, USER_ID, doc_id, PROMPT, "tokenization")
    assert harness.provider.calls == 0, "an expired session must not reach the provider"
    assert dead_id not in await harness.sessions.active_ids()

    # -- half two: a live session that expires with values in the vault ------
    live_id, _ = await harness.sessions.create("test-user", ttl_seconds=60)
    result = await harness.orchestrator.run(
        live_id, USER_ID, doc_id, PROMPT, "tokenization"
    )
    assert result.stats["tokens_issued"] > 0
    token_id = next(
        match.group(3)
        for span in result.detections
        if span.surrogate
        for match in [STRICT_TOKEN_RE.fullmatch(span.surrogate)]
        if match is not None
    )
    assert await harness.vault.get_by_token(live_id, token_id)
    rows_before = await harness.vault.row_count(live_id)
    assert rows_before > 0

    clock.advance(61.0)

    # The key is gone, so nothing about this session is reachable any more --
    # not through the registry, not through the vault, not through the pipeline.
    with pytest.raises(SessionExpiredError):
        await harness.sessions.key(live_id)
    with pytest.raises(SessionExpiredError):
        await harness.vault.get_by_token(live_id, token_id)
    with pytest.raises(SessionExpiredError):
        await harness.orchestrator.run(live_id, USER_ID, doc_id, PROMPT, "tokenization")
    assert live_id not in await harness.sessions.active_ids()

    # The destruction path then clears the rows the key already made undecryptable.
    #
    # This is called by hand, and the comment here used to attribute it to "the
    # sweep's destruction path" -- machinery that did not exist. `SessionRegistry`
    # dropped the expired key and nothing else: the rows and the plaintext cache
    # survived, and no API call could reclaim them, because `DELETE /sessions` gates
    # on an ownership check that raises for an expired session. Meanwhile the
    # README's traceability table cited THIS test as evidence for "purged on
    # expiry/logout". `deps.reap_expired_sessions` now runs that path for real, on
    # the request that discovers the expiry; it is covered by
    # `test_ttl_expiry_runs_the_whole_destruction_path`. The hand call stays here
    # because this test is about the *restore* behaviour after destruction, and it
    # should not silently depend on which caller did the destroying.
    await harness.vault.destroy(live_id)
    assert await harness.vault.row_count(live_id) == 0
    assert harness.vault.originals_for_session(live_id) == frozenset()
    assert live_id not in harness.vault.cached_session_ids()

    assert harness.provider.calls == 1, "only the one live run should have reached the provider"


# ---------------------------------------------------------------------------
# 5. Concurrent session isolation
# ---------------------------------------------------------------------------


def _detections_for(text: str, values: dict[str, tuple[str, EntityCategory]]) -> list[Detection]:
    """Hand-built detections for the exact planted values.

    The engine and vault are what this test is about; driving them with fixed
    spans keeps 50 interleaved operations fast and makes the comparison between
    the two sessions exact -- identical inputs, byte for byte.
    """
    out: list[Detection] = []
    for value, (entity_type, category) in values.items():
        start = text.index(value)
        out.append(
            Detection(
                entity_type=entity_type,
                category=category,
                start=start,
                end=start + len(value),
                text=value,
                score=0.95,
            )
        )
    return sorted(out, key=lambda d: d.start)


async def test_concurrent_session_isolation(make_harness: HarnessFactory) -> None:
    """Two sessions, the same values, 50 interleaved operations, zero crossover.

    Isolation here is cryptographic, not a filter: token IDs are
    ``HMAC(session_key, ...)`` and vault rows are AES-GCM bound to
    ``session_id || token_id``, so a token minted in A is not merely *refused* in
    B -- it is meaningless in B, and the row would fail authentication even if the
    ID were guessed.
    """
    harness: Harness = await make_harness()
    planted = generator.expected_entities(SEED, "medical")
    name = planted["NAME"][0]
    mrn = planted["MRN"][0]
    insurance = planted["INSURANCE_ID"][0]
    document = (
        f"Patient {name} was reviewed today.\n"
        f"Chart reference {mrn} was opened.\n"
        f"Coverage on file is {insurance}.\n"
    )
    values = {
        name: ("NAME", EntityCategory.PII),
        mrn: ("MRN", EntityCategory.PHI),
        insurance: ("INSURANCE_ID", EntityCategory.PHI),
    }
    detections = _detections_for(document, values)

    session_a, _ = await harness.sessions.create("test-user")
    session_b, _ = await harness.sessions.create("test-user")

    ops = 50
    schedule = [session_a if index % 2 == 0 else session_b for index in range(ops)]
    results = await asyncio.gather(
        *(
            harness.engine.obfuscate(
                session_id,
                document,
                detections,
                strategy="tokenization",
                doc_category="medical",
            )
            for session_id in schedule
        )
    )
    assert len(results) == ops

    def surrogates_of(session_id: str) -> set[str]:
        return {
            token.surrogate
            for session, result in zip(schedule, results, strict=True)
            if session == session_id
            for token in result.tokens
        }

    surrogates_a = surrogates_of(session_a)
    surrogates_b = surrogates_of(session_b)

    # Within a session: deterministic and deduped. 25 runs over the same three
    # values yield three surrogates and three vault rows, not seventy-five.
    assert len(surrogates_a) == len(values)
    assert len(surrogates_b) == len(values)
    assert await harness.vault.row_count(session_a) == len(values)
    assert await harness.vault.row_count(session_b) == len(values)

    # Across sessions: identical inputs, disjoint outputs.
    assert surrogates_a.isdisjoint(surrogates_b)
    tokens_a = {
        match.group(3) for s in surrogates_a for match in [STRICT_TOKEN_RE.fullmatch(s)] if match
    }
    tokens_b = {
        match.group(3) for s in surrogates_b for match in [STRICT_TOKEN_RE.fullmatch(s)] if match
    }
    assert len(tokens_a) == len(values)
    assert tokens_a.isdisjoint(tokens_b)

    # Both sessions hold the same originals -- so the disjointness above is a
    # property of the keys, not of the inputs having differed.
    assert harness.vault.originals_for_session(session_a) == harness.vault.originals_for_session(
        session_b
    )

    # No cross-session read succeeds, by token or by surrogate.
    for token_id in tokens_a:
        with pytest.raises(VaultMissError):
            await harness.vault.get_by_token(session_b, token_id)
    for surrogate in surrogates_a:
        with pytest.raises(VaultMissError):
            await harness.vault.get_by_surrogate(session_b, surrogate)
    for token_id in tokens_b:
        with pytest.raises(VaultMissError):
            await harness.vault.get_by_token(session_a, token_id)

    # And each session still reads its own.
    for token_id in tokens_a:
        assert await harness.vault.get_by_token(session_a, token_id) in values


# ---------------------------------------------------------------------------
# 6. Run correlation
# ---------------------------------------------------------------------------


async def test_every_audit_event_from_a_run_carries_the_run_id(
    make_harness: HarnessFactory,
) -> None:
    """One ID reconstructs the whole chain -- the compliance-query requirement.

    Two runs in one session, so the assertion is not trivially satisfied by there
    being only one run's worth of events in the log.
    """
    harness: Harness = await make_harness()
    document = generator.generate(SEED, "legal")
    doc_id = await harness.upload(document, "legal", "legal_memo.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")

    first = await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")
    second = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "pseudonymization"
    )
    assert first.run_id != second.run_id

    everything = await harness.audit.query(session_id=session_id, limit=10_000)
    assert everything
    assert all(event.run_id is not None for event in everything), (
        "an audit event with no run_id cannot be correlated to a request"
    )
    assert {event.run_id for event in everything} == {first.run_id, second.run_id}

    for result in (first, second):
        by_run = await harness.audit.query(run_id=result.run_id, limit=10_000)
        assert by_run
        assert {event.run_id for event in by_run} == {result.run_id}
        # The result advertises exactly the sequence numbers the log holds.
        assert sorted(result.audit_seq) == sorted(
            event.seq for event in by_run if event.seq is not None
        )
        kinds = {event.event_type for event in by_run}
        assert {DETECT, OBFUSCATE, EGRESS_PASS, LLM_CALL, DEOBFUSCATE} <= kinds

    assert await harness.audit.verify_chain(session_id) is True


# ---------------------------------------------------------------------------
# 6b. Per-user key derivation, pinned independently of AAD
# ---------------------------------------------------------------------------


async def test_per_user_document_keys_are_load_bearing_on_their_own(
    make_harness: HarnessFactory,
) -> None:
    """The document key alone must isolate users, with AAD taken out of the argument.

    Every blob is bound to its owner *twice*: the key is
    ``HKDF(master, "doc:" + user_id)`` and the AAD is ``doc:<user_id>:<doc_id>``.
    Both legs are real, and that redundancy is the problem this test exists for:
    every wrong-user test in the suite asserts the **outcome** -- ``StoreAuthError``
    coded ``NOT_FOUND`` -- and *either* leg on its own produces that outcome. A
    store that derived one shared key for every user would keep all of them green,
    because the AAD would still differ and GCM would still refuse. So would the
    "identical content, different users" test, whose ciphertexts differ on the
    random nonce regardless of the key.

    That matters because the README's storage argument does not rest on AAD. It
    rests on key derivation -- per-user isolation is claimed as a property of
    HKDF, which is the specific reason SQLCipher's one-password-per-file model was
    rejected. A claim nothing can falsify is not a claim.

    So this pins the key leg by itself: hand the *other* user's key the owner's
    exact AAD and require it to fail anyway. The positive control immediately
    below it -- the owner's key opening the same bytes with the same AAD -- is
    what makes the failure attributable to the key and to nothing else.
    """
    harness: Harness = await make_harness()
    doc_id = await harness.upload(
        "Chart note for the record.\nNo identifiers of interest.\n", "medical"
    )

    provider = build_key_provider(harness.settings)
    owner_key = provider.doc_key(USER_ID)
    other_key = provider.doc_key(OTHER_USER_ID)
    assert owner_key != other_key, "doc keys are not user-specific at all"

    blob = (Path(harness.settings.data_dir) / "documents" / f"{doc_id}{RAW_SUFFIX}").read_bytes()
    owner_aad = doc_aad(USER_ID, doc_id)

    # Positive control: the bytes really are this document, under this AAD.
    assert decrypt(owner_key, blob, owner_aad, scope="document").startswith(b"Chart note")

    # The property. Same ciphertext, same AAD, different derived key -- and the
    # only thing that can refuse it now is the key.
    with pytest.raises(CryptoAuthError):
        decrypt(other_key, blob, owner_aad, scope="document")


# ---------------------------------------------------------------------------
# 7. Destroy, then try to restore
# ---------------------------------------------------------------------------


async def test_restoration_is_impossible_after_the_session_is_destroyed(
    make_harness: HarnessFactory,
) -> None:
    """The live-demo moment: the same response, before and after destruction.

    Destroying a session pops the only copy of its key. The vault's ciphertext,
    if any survived the DELETE, is AES-GCM under a key derived from it, so the
    values are not withheld -- they are unrecoverable.
    """
    harness: Harness = await make_harness()
    document = generator.generate(SEED, "financial")
    doc_id = await harness.upload(document, "financial", "financial_disclosure.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )
    assert result.stats["restored_count"] > 0

    # Before: the same raw response restores again, identically.
    replay = await harness.restorer.restore(
        session_id, result.raw_llm_response, strategy="tokenization"
    )
    assert replay.text == result.restored_text
    assert replay.vault_misses == 0

    # Destroy.
    assert await harness.sessions.destroy(session_id) is True
    await harness.vault.destroy(session_id)

    # After: no rows, no cache, and no way back to a single value.
    assert await harness.vault.row_count(session_id) == 0
    assert harness.vault.originals_for_session(session_id) == frozenset()
    assert session_id not in harness.vault.cached_session_ids()
    with pytest.raises(SessionExpiredError):
        await harness.restorer.restore(
            session_id, result.raw_llm_response, strategy="tokenization"
        )
    with pytest.raises(SessionExpiredError):
        await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")

    # The audit trail outlives the session -- that is the point of separating them.
    assert await harness.audit.query(session_id=session_id, limit=10)
    assert await harness.audit.verify_chain(session_id) is True


# ---------------------------------------------------------------------------
# 8. The challenge's mandated entity minimum, proven end to end
# ---------------------------------------------------------------------------

#: The nine entity types the challenge names as the detector's *minimum*. The
#: shipped registry is a superset, and that superset is exactly why this list has
#: to be written down here: every other detection test derives what it expects
#: from ``entities.yaml`` itself, so deleting ``SSN`` from the registry would
#: leave the whole suite green. This is the one assertion that fails if the
#: registry stops meeting the specification.
SPEC_MANDATED_ENTITY_TYPES = (
    "NAME",
    "SSN",
    "DOB",
    "EMAIL",
    "PHONE",
    "MRN",
    "DIAGNOSIS",
    "ACCOUNT_NUMBER",
    "CASE_ID",
)

#: The four categories the challenge requires detection across.
SPEC_MANDATED_CATEGORIES = frozenset(
    {EntityCategory.PII, EntityCategory.PHI, EntityCategory.LEGAL, EntityCategory.FIN}
)


async def test_the_nine_mandated_entity_types_survive_the_whole_round_trip(
    make_harness: HarnessFactory,
) -> None:
    """Each mandated type is detected, obfuscated, kept off the wire, and reversible.

    The challenge fixes a floor of nine entity types across four categories. The
    registry ships more than that, and every other test in this suite checks the
    registry against *itself* -- ``test_fixture_table_covers_every_recognizer_backed_entity``
    compares the fixture table to ``registry.pattern_backed()``, so it tracks
    whatever the registry currently says rather than what the specification
    demands. Nothing else would notice if a required type were dropped.

    So this walks the three shipped fixture kinds and requires that each of the
    nine is, somewhere among them, carried through four distinct properties:

    * **detected** -- a span comes back carrying that ``entity_type``;
    * **obfuscated** -- the action is ``OBFUSCATED`` and a surrogate was issued,
      not merely redacted away;
    * **absent from the outbound document** -- every literal the generator
      planted for that type is gone from the fenced payload, checked against the
      generator's ledger rather than against the detector's own opinion of what
      it found;
    * **reversible** -- the vault maps the emitted surrogate back to the exact
      original.

    A type that is detected but never obfuscated, or obfuscated but not
    reversible, does not count. That is what makes this a round-trip assertion
    rather than a recall check.
    """
    harness: Harness = await make_harness()
    proven: dict[str, str] = {}
    categories_seen: set[EntityCategory] = set()

    for kind in ("medical", "legal", "financial"):
        document = generator.generate(SEED, kind)
        planted = generator.expected_entities(SEED, kind)
        doc_id = await harness.upload(document, kind, f"{kind}.txt")
        session_id, _expires_at = await harness.sessions.create("test-user")

        result = await harness.orchestrator.run(
            session_id, USER_ID, doc_id, PROMPT, "tokenization"
        )
        body = document_section(result.obfuscated_payload)
        categories_seen.update(span.category for span in result.detections)

        for entity_type in SPEC_MANDATED_ENTITY_TYPES:
            spans = [
                span
                for span in result.detections
                if span.entity_type == entity_type
                and span.action is EntityAction.OBFUSCATED
                and span.surrogate is not None
            ]
            if not spans:
                continue

            # Every literal the generator planted for this type is off the wire.
            for value in planted.get(entity_type, ()):
                assert value not in body, (
                    f"{kind}: a planted {entity_type} literal survived into the "
                    f"outbound document (<{len(value)} chars>)"
                )

            # And the surrogate that replaced it is reversible through the vault.
            surrogate = spans[0].surrogate
            assert surrogate is not None
            original = await harness.vault.get_by_surrogate(session_id, surrogate)
            assert original
            assert surrogate in body, (
                f"{kind}: {entity_type} was obfuscated but its surrogate is not in the payload"
            )
            proven.setdefault(entity_type, kind)

        await harness.vault.destroy(session_id)

    missing = [name for name in SPEC_MANDATED_ENTITY_TYPES if name not in proven]
    assert not missing, (
        "these mandated entity types never completed a round trip across the "
        f"shipped fixtures: {missing} (proven: {proven})"
    )
    assert SPEC_MANDATED_CATEGORIES <= categories_seen, (
        "detection did not span all four mandated categories; missing "
        f"{sorted(SPEC_MANDATED_CATEGORIES - categories_seen)}"
    )


# ---------------------------------------------------------------------------
# 9. The event loop is never blocked
# ---------------------------------------------------------------------------


async def test_the_pipeline_never_blocks_the_event_loop(
    make_harness: HarnessFactory,
) -> None:
    """spaCy is CPU-bound and synchronous; it must not run on the loop.

    This is a hard requirement of the build specification and a named guardrail
    ("DO NOT run spaCy/Presidio on the event loop; always ``asyncio.to_thread``"),
    and until now it was implemented but unasserted -- ``tests/test_extraction.py``
    pins the same property for text extraction, and nothing pinned it for
    *detection*, which is by far the more expensive of the two.

    Rather than spy on ``asyncio.to_thread`` -- which pins the mechanism and would
    go green if the call were moved to a process pool, or red on a harmless
    refactor -- this measures the property the requirement exists to protect: a
    concurrent coroutine keeps getting scheduled while the pipeline runs.

    The threshold is self-scaling and therefore not a tuned constant. If detection
    ran inline, the loop would stall for the whole of it, so the worst observed
    gap would be **at least** ``detect_ms``. Requiring the worst gap to come in
    under half of ``detect_ms`` makes the two outcomes categorically different
    rather than a few milliseconds apart, and it stays correct on a slow machine,
    because both sides of the comparison move together.
    """
    harness: Harness = await make_harness()
    document = generator.generate(SEED, "medical")
    doc_id = await harness.upload(document, "medical", "medical_note.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")

    gaps: list[float] = []
    stop = asyncio.Event()

    async def heartbeat() -> None:
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    beat = asyncio.create_task(heartbeat())
    try:
        result = await harness.orchestrator.run(
            session_id, USER_ID, doc_id, PROMPT, "tokenization"
        )
    finally:
        stop.set()
        await beat

    # The run has to have done real detection work, or there is nothing to block on.
    detect_ms = result.stats["detect_ms"]
    assert detect_ms > 10.0, (
        f"detection took only {detect_ms:.1f} ms; this document is too small for the "
        "measurement to distinguish a blocked loop from a free one"
    )
    assert result.stats["entities_detected"] > 0

    assert gaps, "the heartbeat never ran at all"
    worst_ms = max(gaps) * 1000.0
    assert worst_ms < detect_ms / 2.0, (
        f"the event loop stalled for {worst_ms:.1f} ms during a run whose detection "
        f"stage took {detect_ms:.1f} ms -- that is the signature of spaCy running on "
        f"the loop instead of in a worker thread ({len(gaps)} heartbeats observed)"
    )
    # NOTE on what this test can and cannot see, because an absolute ceiling was
    # tried here and removed rather than tuned.
    #
    # The bound above scales with `detect_ms`, so it can only really catch the
    # *detector* going back on the loop; a non-detector stage can stall for a long
    # time on this fixture and stay green. That is not hypothetical --
    # `ObfuscationEngine._sweep_residual` ran O(surfaces x len(text)) of synchronous
    # regex inline, and a 5 ms heartbeat measured **464 ms** of starvation during one
    # `obfuscate` on `fixtures/legal_brief_large.txt` while this test passed.
    # Offloading it brought that to ~46 ms.
    #
    # An absolute `worst_ms < 250` assertion looked like the fix and is not a sound
    # one: it still reads 257-307 ms here *after* the sweep is offloaded, because the
    # heartbeat is also contending with spaCy in its own worker thread, and spaCy
    # releases and reacquires the GIL throughout. So the number measures GIL
    # contention during a correctly-threaded stage, not inline blocking, and pinning
    # it would assert something this test cannot distinguish. Raising the constant
    # until it passed would have been worse: a green number engineered rather than
    # earned.
    #
    # What is actually needed is a per-stage measurement that attributes a stall to
    # the stage that caused it. Recorded in README section 7 as an open gap rather
    # than half-asserted here.


# ---------------------------------------------------------------------------
# 10. Egress leaks that were reachable from an ordinary uploaded document
#
# Every gate property below is also asserted as a unit in tests/test_egress_gate.py,
# against a FakeVault holding a value the test put there. That is the right shape for
# checking the rule and the wrong shape for checking the *claim*, which is about an
# attacker: each of these three values reached the provider through this pipeline,
# from a file, with real detection, real obfuscation and the real gate in the path.
# The unit tests would all have stayed green while it happened -- they did.
#
# Each test asserts the block AND that the provider was never called, because "the
# gate objected" and "nothing was sent" are different statements and only the second
# one is the guarantee.
# ---------------------------------------------------------------------------


async def _blocked_run(harness: Harness, document: str, category: str) -> EgressBlockedError:
    """Upload, run, and require the gate to refuse before the provider is reached."""
    doc_id = await harness.upload(document, category, "leak_probe.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")
    calls_before = harness.provider.calls
    with pytest.raises(EgressBlockedError) as exc:
        await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")
    assert harness.provider.calls == calls_before, "the provider was called anyway"
    return exc.value


async def test_a_vaulted_identifier_glued_into_a_word_never_reaches_the_provider(
    make_harness: HarnessFactory,
) -> None:
    """The document body is attacker-controlled, and that is the whole finding.

    ``47-1234567`` is detected as a ``TAX_ID`` from its clean mention, vaulted, and
    tokenized. The second mention is glued to word characters on both sides, so:
    the engine's residual sweep does not sweep it (word-boundary rule), the gate's
    pass 1 did not block it (the same word-boundary rule), and pass 2 does not
    re-detect it (``TAX_ID``'s pattern anchors on ``\\b``, which ``batch`` denies).
    Three independent-looking checks, one shared blind spot, and the taxpayer ID
    went to the provider byte-for-byte inside ``batch47-1234567Alpha``.

    The residual-risk note in ``egress_gate.py`` used to argue this was acceptable
    because "the shapes the pipeline can actually emit do not land here". That
    argument only ever covered *our* output; the payload also carries the uploaded
    document verbatim, and an uploader chooses what is next to what.
    """
    harness: Harness = await make_harness()
    document = (
        "TAXPAYER STATEMENT\n\n"
        "The taxpayer EIN 47-1234567 is on file.\n\n"
        "Internal routing tag: batch47-1234567Alpha must match the ledger.\n"
    )
    error = await _blocked_run(harness, document, "financial")
    assert error.detail["reason"] == "vault_original"


async def test_a_combining_mark_spliced_into_a_name_never_reaches_the_provider(
    make_harness: HarnessFactory,
) -> None:
    """Reproduced through NER rather than asserted about, which is why it is here.

    The first mention of ``Nathaniel Brightwater`` is found by spaCy and vaulted.
    The second carries one U+0301 between the two names -- a position spaCy does not
    recognise, so it is never independently detected and never vaulted -- and the
    resulting string matched none of the three forms pass 1 compared. It reads
    identically to the real name for a human and for the model.

    The mark position matters and is the reason this is an integration test: with the
    mark inside a token, NER often still finds the name and re-vaults it, so the leak
    closes itself and a unit test choosing that position proves nothing.

    **The assertion changed when NFC composition was added at ingestion, and the
    direction it changed in is the point.** It used to read::

        error = await _blocked_run(harness, document, "medical")
        assert error.detail["reason"] == "vault_original"

    -- that is, it asserted the run was *refused*. Refusal was the correct
    behaviour for a value the pipeline could not recognise, and it is not what this
    test is for. The requirement is in the test's own name: **never reaches the
    provider**. A block is one way to satisfy that; it is not the only way, and it
    is the worse way, because the document comes back unusable.

    U+0301 after ``l`` has a precomposed form (U+013A, ``ĺ``), so canonical
    composition turns the spliced string into a single token spaCy reads as a name.
    Both mentions are now detected, vaulted and obfuscated separately, and the run
    succeeds with nothing leaked -- measured: neither ``Nathaniel`` nor
    ``Brightwater`` nor even the prefix ``Nathanie`` appears anywhere in the
    outbound payload. So the guarantee holds *more* strongly than before and the
    document is processable, which is a strict improvement over a 422.

    Asserting on the payload rather than on the exception is also strictly stronger
    independently of that: ``_blocked_run`` is satisfied by a block that happened
    for some unrelated reason, and would have gone on passing if the name had begun
    leaking through a different path while some other value tripped the gate. The
    fail-closed ``vault_original`` mechanism itself is not going uncovered -- it is
    asserted in seventeen places in ``test_egress_gate.py``, and by
    ``test_an_ssn_the_detector_scores_at_zero_never_reaches_the_provider`` two tests
    below, which is the right level for it.
    """
    harness: Harness = await make_harness()
    mark = "́"
    document = (
        "REFERRAL LETTER\n\n"
        "The primary contact is Nathaniel Brightwater, the coordinator.\n\n"
        f"For continuity, direct questions to Nathaniel{mark} Brightwater at reception.\n"
    )
    assert unicodedata.normalize("NFC", document) != document, "premise: composable"

    doc_id = await harness.upload(document, "medical", "spliced.txt")
    session_id, _ = await harness.sessions.create(USER_ID)
    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    payload = result.obfuscated_payload
    # The prefix as well as the whole components: composition acts on the LAST
    # letter of "Nathaniel", so a fix that merely relocated the damage would leave
    # "Nathanie" behind, and checking only the full name would call that clean.
    for fragment in ("Nathaniel Brightwater", "Nathaniel", "Brightwater", "Nathanie"):
        assert fragment not in payload, f"{fragment!r} reached the provider"

    # Two mentions, two distinct originals, both vaulted -- the spliced spelling is
    # a different string and must not be silently folded onto the clean one.
    vaulted = harness.vault.originals_for_session(session_id)
    assert "Nathaniel Brightwater" in vaulted
    assert f"Nathanie{unicodedata.normalize('NFC', 'l' + mark)} Brightwater" in vaulted


async def test_an_ssn_the_detector_scores_at_zero_never_reaches_the_provider(
    make_harness: HarnessFactory,
) -> None:
    """The headline claim, tested where it is actually made.

    "No original entity value ever reaches the provider, enforced as an egress
    property rather than a detection property" -- but pass 1 only knows what
    detection vaulted, and pass 2 re-runs the same detector. Presidio's
    ``UsSsnRecognizer`` hard-invalidates the published example SSNs, so
    ``123-45-6789`` was never detected, never vaulted, never obfuscated, and left
    this pipeline in the clear with all passes silent. Pass 3 is the only thing in
    the process that has an opinion the detector did not supply.

    The premise is asserted from the vault rather than assumed: nothing at all is
    vaulted from this document, so a block here cannot be pass 1.

    **THE HARNESS DROPPED ONE REGISTRY FIELD AND THE ASSERTIONS DID NOT MOVE.** This
    test used to run on the shipped registry, because the shipped detector genuinely
    found nothing here. That is no longer true and it stopped being true on purpose:
    ``entities.yaml`` now carries an ``SSN.patterns`` backstop, because the *bare*
    spelling of the same nine digits -- ``Member SSN 123456789`` -- was matched by
    pass 3's delimiter-requiring pattern not at all and reached the provider verbatim.
    Detection is the repair; this test is about what holds when detection does not, so
    it now runs against the pre-repair registry via ``without_ssn_backstop`` and
    asserts exactly what it always asserted.

    ``test_an_invalidated_ssn_is_vaulted_by_the_shipped_registry`` below is the other
    half, on the shipped configuration, so neither layer can regress behind the other.
    """
    harness: Harness = await make_harness(without_ssn_backstop=True)
    document = "STATEMENT\n\nMember SSN 123-45-6789 verified against records.\n"

    doc_id = await harness.upload(document, "financial", "example_ssn.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")
    with pytest.raises(EgressBlockedError) as exc:
        await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")
    assert exc.value.detail["reason"] == "independent_pattern"
    assert exc.value.detail["entity_types"] == "SSN"
    assert harness.provider.calls == 0
    assert harness.vault.originals_for_session(session_id) == frozenset(), (
        "premise gone: the detector now vaults something from this document, so the "
        "block could be pass 1 and this test no longer isolates pass 3"
    )


@pytest.mark.parametrize(
    "ssn",
    [
        pytest.param("123456789", id="bare-canonical-example"),
        pytest.param("123-45-6789", id="canonical-example"),
        pytest.param("123 45 6789", id="canonical-example-with-spaces"),
        pytest.param("123-45.6789", id="mismatched-delimiters"),
        pytest.param("987-65-4320", id="second-published-example"),
        pytest.param("000-12-3456", id="never-issued-area-000"),
        pytest.param("666-12-3456", id="never-issued-area-666"),
    ],
)
async def test_an_invalidated_ssn_is_vaulted_by_the_shipped_registry(
    make_harness: HarnessFactory, ssn: str
) -> None:
    """The repair, end to end on the shipped configuration.

    The test above proves the gate holds with detection removed. This one proves the
    shipped pipeline does better than hold: the value is *detected*, so it is vaulted
    and obfuscated and the run completes, instead of being refused. Both outcomes keep
    the digits off the wire; only one of them leaves the document usable, and only one
    of them gives pass 1 a needle for a second, unlabelled mention of the same number
    later in the file.

    Refusing was not a neutral choice either. ``demo.py --file`` exited **1** on every
    delimited spelling in this list before the backstop existed, so a reviewer who
    typed the most common placeholder SSN into their own test document met a red
    pipeline; all seven exit 0 now.
    """
    harness: Harness = await make_harness()
    document = f"STATEMENT\n\nMember SSN {ssn} verified against records.\n"

    doc_id = await harness.upload(document, "financial", "example_ssn.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")
    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    assert harness.provider.calls == 1, "the run was refused rather than protected"
    assert ssn in harness.vault.originals_for_session(session_id), (
        "the SSN was not vaulted, so pass 1 has no needle for a second mention of it"
    )
    assert ssn not in result.obfuscated_payload
    assert "".join(ch for ch in ssn if ch.isdigit()) not in result.obfuscated_payload, (
        "the digits reached the provider in some other grouping"
    )
    assert ssn in result.restored_text, "a vaulted value must restore into the answer"


async def test_a_realistic_ssn_is_obfuscated_rather_than_blocked(
    make_harness: HarnessFactory,
) -> None:
    """The control the three tests above need: fail-closed must not mean fail-always.

    A gate that blocks everything is trivially leak-free and completely useless, so
    the same document shape with an SSN Presidio *does* recognise has to go all the
    way through: detected, vaulted, tokenized, sent, restored. Without this, every
    assertion above is satisfied by a gate that raises unconditionally.
    """
    harness: Harness = await make_harness()
    document = "STATEMENT\n\nMember SSN 512-24-8710 verified against records.\n"
    doc_id = await harness.upload(document, "financial", "real_ssn.txt")
    session_id, _expires_at = await harness.sessions.create("test-user")

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    assert harness.provider.calls == 1
    assert "512-24-8710" in harness.vault.originals_for_session(session_id)
    assert "512-24-8710" not in result.obfuscated_payload
    assert "512-24-8710" in result.restored_text


# ---------------------------------------------------------------------------
# 11. The pipeline under concurrency
#
# This ships as a uvicorn ASGI app serving concurrent requests on one event loop,
# and until this test nothing had ever run two `orchestrator.run` calls at the same
# time: every call site above is awaited serially and the 100-case leakage harness is
# sequential. That is a gap in the evidence rather than in the code, and it is the
# expensive kind: a race here is a wrong VALUE in a clinical answer, not a crash.
#
# The window is real and it is narrow. `ObfuscationEngine._resolve_groups` checks the
# vault for a value, and only if it is absent derives a token ID, renders a surrogate
# around it and writes the row -- three awaits later. Two runs that both pass the
# check before either writes are the ordinary case and are harmless (the second put
# is a no-op and the read-back returns the first record). The interesting order is
# the narrow one: run B's check happens before run A's write and B's ID derivation
# happens after it, so B sees its own ID already taken, re-derives with a counter,
# and ends up with a surrogate built around an ID whose row belongs to nobody. The
# read-back repair is what saves it, and a hand-built single-collision unit test was
# the only evidence that repair worked.
#
# Measured with the documents below, 16 runs, five rounds each way:
#
#     CONCURRENT: (collision_re_derived, read_back_mismatch) = [(3,3),(0,0),(0,0),(0,0),(0,0)]
#     SERIAL:                                                = [(0,0),(0,0),(0,0),(0,0),(0,0)]
#
# So this reaches the repair path where nothing else in the suite does, and reaches
# it in a minority of rounds -- which is why the assertions below are invariants that
# must hold in every round rather than an expectation that the warning fires.
# ---------------------------------------------------------------------------

#: Sixteen rather than four: the window above is a few awaits wide, and at low
#: concurrency the runs finish detection far enough apart that their obfuscation
#: phases never overlap at all.
CONCURRENT_RUNS = 16

#: How many of those sixteen may be refused by the build-vs-gate window before this
#: test calls it a defect rather than a narrow race. Two, and the number is measured
#: rather than chosen: the reported incidence is ONE refused run
#: (``hit_count=1``) in roughly one whole execution in fourteen, and 37 consecutive
#: executions on this machine (25 as separate pytest processes, 12 in-process)
#: produced zero. Two is twice the largest count ever observed here, and fourteen
#: surviving runs is still fourteen independent chances to observe a crossover.
#: A regression that makes the window wide -- or a gate that refuses everything --
#: lands well past this and turns the test red. See the docstring below.
MAX_TOLERATED_REFUSALS = 2


def _contended_documents(count: int) -> list[str]:
    """Identical records but for the MRN: maximum contention, detectable crossover.

    Every value except the MRN is shared, and a shared value is what creates the
    race -- identical normalised text in one session derives the identical token ID,
    so all sixteen runs go for the same vault row at once. Eight shared values rather
    than two because the window is per-value: with one shared value the runs have a
    single chance each to interleave inside it, and five rounds of sixteen runs
    produced zero. The unique MRN is what makes misattribution *detectable* --
    without it every run would restore to the same values and a thoroughly crossed
    set of rows would still look correct.
    """
    return [
        (
            f"CLINIC NOTE {index}\n\n"
            f"MRN: {4471900 + index * 7}\n"
            "DOB: 03/12/1985\n"
            "Contact phone: (415) 555-0142\n"
            "Attending physician: Dr Harriet Vance.\n"
            "Referred by Dr Marcus Ellery of Northgate Clinic.\n"
            "Coverage on file is BCBS448193027.\n"
            "Emergency contact: Priya Raghunathan.\n"
            "Billing reference EIN 47-1234567.\n"
            "Patient reviewed in clinic today and discharged in stable condition.\n"
        )
        for index in range(count)
    ]


async def test_concurrent_runs_on_one_session_do_not_cross_wires(
    make_harness: HarnessFactory,
) -> None:
    """Sixteen concurrent runs, one session: no dangling token, no loss, no crossover.

    Three failures are possible on this path and only the third is loud on its own:

    * **a dangling token** -- a surrogate spliced into a payload whose vault row the
      losing side of a race never wrote. The model quotes it back, the restorer finds
      nothing, and the caller reads ``[UNRESOLVED_ENTITY]`` where a value belongs.
    * **misattribution** -- two originals resolving through one token ID, so one
      patient's identifier is printed in another's note. Nothing in the output says
      so; under pseudonymization the wrong answer reads exactly like the right one.
    * **a dedupe failure** -- one value ending up behind two token IDs, which is the
      visible shadow of the re-derivation path the engine takes on an ID collision.

    Each is asserted directly rather than inferred from "no exception was raised".
    The token IDs are read out of the *document* section of each payload, not the
    whole payload, because the tokenization system prompt quotes a token of its own
    that belongs to no run and resolves to nothing by design.

    What this does NOT assert is that the warnings never fire: re-deriving an ID on a
    collision is the repair working, not the bug. What must hold is that the repair
    leaves no observable damage, which is what the three checks below measure.

    **How much this test is worth, measured rather than claimed.** With the read-back
    repair removed -- ``_resolve_groups`` trusting the surrogate it just rendered
    instead of the record the vault holds, which is the exact failure the repair
    exists to prevent -- this test goes red in roughly one run in seven (4 of 28
    measured), with ``VaultMissError(token_id=...)`` from check 1: a token in the
    payload that no vault row backs. Stated plainly because it is the property a
    reader needs: one green run is weak evidence and a red run is strong evidence.
    That asymmetry is inherent to racing a few-await window, not a defect in the
    probe, and it is still the only evidence in this suite that the repair works at
    all -- the alternative was a hand-built single-collision unit test that never
    ran two coroutines.

    **Why a fail-closed refusal is tolerated here, and what tolerating it costs.**
    This test used to be flaky -- roughly one execution in fourteen died on
    ``EgressBlockedError(reason='vault_original', hit_count=1)`` from a run that had
    crossed no wires at all. That block is a *second* race, on a different pair of
    reads: the engine reads ``originals_for_session`` while building the payload and
    the gate reads it again at gate time, and a session-mate that vaults a value in
    between leaves this run's already-built payload carrying, in the clear, a value
    that is now an original. Blocking is the correct answer to that payload -- it
    really does contain a vaulted value -- so the refusal is the gate working, not
    the crossover this test exists to detect. Sixteen near-identical documents are
    what make it reachable: the detector is deterministic per document but the
    documents differ by an MRN, so a value one run detects and vaults another run
    can miss, and the cross-call sweep that would have masked it reads the originals
    set a few awaits too early.

    Two shapes were available. Removing the collision from the fixture means either
    pre-vaulting the shared values -- which kills the ID-collision contention this
    test was built to reach, since a value already in the vault is never derived a
    second time -- or hand-picking values with no detection variance, which is a
    property of a spaCy release rather than of this repo. So the refusal is
    tolerated instead, and tolerated is not swallowed: every refusal must be an
    ``EgressBlockedError``, must carry ``reason='vault_original'`` and no other, must
    appear in the audit log as ``EGRESS_BLOCK`` for its own run, must have NO
    ``LLM_CALL`` for that run, and must leave ``provider.calls`` equal to the number
    of runs that completed. A refused run put nothing on the wire, and that is
    asserted rather than assumed.

    **The one assertion weakened, stated plainly.** ``asyncio.gather`` without
    ``return_exceptions`` asserted "all sixteen runs complete". It now asserts
    ``len(results) >= CONCURRENT_RUNS - MAX_TOLERATED_REFUSALS``. Would that still be
    wrong if the engine's window fix were reverted? No -- with the fix reverted the
    refusals are legitimate fail-closed refusals of genuinely dirty payloads, and a
    test of *crossover* should not be red for them. What must not happen is that the
    availability defect stops being tested at all, so it is tested where it can be
    tested honestly:
    ``test_a_session_mate_vaulting_between_the_build_and_the_gate_cannot_leak``
    drives that exact interleaving deterministically, on every execution, instead of
    once in fourteen. And the floor is a floor: a gate that refuses everything is
    trivially crossover-free and useless, which is the same control
    ``test_a_realistic_ssn_is_obfuscated_rather_than_blocked`` provides for the
    single-run path.
    """
    harness: Harness = await make_harness()
    session_id, _expires_at = await harness.sessions.create("test-user")
    documents = _contended_documents(CONCURRENT_RUNS)
    doc_ids = [
        await harness.upload(text, "medical", f"chart{index}.txt")
        for index, text in enumerate(documents)
    ]

    outcomes = await asyncio.gather(
        *(
            harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")
            for doc_id in doc_ids
        ),
        return_exceptions=True,
    )
    assert len(outcomes) == CONCURRENT_RUNS

    refusals = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
    # Paired with the index of the document that produced it, not re-enumerated: check
    # 3 below asks "is any OTHER chart's MRN in this answer", and a run's own index is
    # how it is excluded. Renumbering the survivors would compare a run against its own
    # MRN and fail a correct pipeline.
    results = [
        (index, outcome)
        for index, outcome in enumerate(outcomes)
        if not isinstance(outcome, BaseException)
    ]

    # Every refusal is a fail-CLOSED refusal of the one kind the build-vs-gate window
    # can produce. Anything else -- another reason code, another exception type, a
    # crash -- is a failure of this test, because those are not this window.
    for refusal in refusals:
        assert isinstance(refusal, EgressBlockedError), (
            f"a concurrent run died on {type(refusal).__name__}, which is not the "
            "documented fail-closed refusal this test tolerates"
        )
        assert refusal.detail["reason"] == "vault_original", (
            f"tolerated refusals are the build-vs-gate window only; got "
            f"{refusal.detail['reason']!r}"
        )
        assert int(refusal.detail["hit_count"]) >= 1, "a block with nothing behind it"

    # Fail-closed is a property of the *audit log and the provider*, not of the
    # exception: an exception raised after the payload went out would look identical
    # from here. So: the refused run is on the record as blocked, has no LLM_CALL of
    # its own, and the provider was called exactly once per run that completed.
    blocks = await harness.audit.query(session_id=session_id, event_type=EGRESS_BLOCK, limit=1000)
    calls = await harness.audit.query(session_id=session_id, event_type=LLM_CALL, limit=1000)
    blocked_runs = {event.run_id for event in blocks}
    called_runs = {event.run_id for event in calls}
    for refusal in refusals:
        run_id = refusal.detail["run_id"]
        assert run_id in blocked_runs, f"run {run_id} refused without an EGRESS_BLOCK record"
        assert run_id not in called_runs, f"run {run_id} was refused AFTER calling the provider"
    assert harness.provider.calls == len(results), (
        "the provider was called a different number of times than runs completed"
    )

    # A gate that refuses everything crosses no wires either. See the docstring:
    # this floor is what stops the tolerance above from being a way to pass.
    assert len(results) >= CONCURRENT_RUNS - MAX_TOLERATED_REFUSALS, (
        f"{len(refusals)} of {CONCURRENT_RUNS} concurrent runs were refused; the "
        "window is supposed to be narrow, and a test of crossover needs runs that ran"
    )

    mrns = [f"MRN: {4471900 + index * 7}" for index in range(CONCURRENT_RUNS)]
    resolved: dict[str, str] = {}

    for index, result in results:
        body = document_section(result.obfuscated_payload)
        token_ids = {match.group(3) for match in STRICT_TOKEN_RE.finditer(body)}
        assert token_ids, f"run {index} issued no tokens; it cannot detect anything"

        # 1. Every token in the payload resolves. A dangling one is a lost vault row.
        for token_id in token_ids:
            value = await harness.vault.get_by_token(session_id, token_id)
            previous = resolved.setdefault(token_id, value)
            assert previous == value, (
                f"token {token_id} resolved to two different originals across "
                "concurrent runs -- one entity's value would print as another's"
            )

        # 2. Nothing was lost on the way back.
        assert UNRESOLVED_ENTITY not in result.restored_text, f"run {index} lost a token"
        assert result.stats["unresolved_lost"] == 0.0
        assert result.stats["vault_misses"] == 0.0

        # 3. No other document's identifier appears in this run's answer.
        for other, mrn in enumerate(mrns):
            if other == index:
                continue
            assert mrn not in result.restored_text, (
                f"run {index} restored chart {other}'s MRN -- concurrent runs crossed"
            )

    # 4. One value, one token ID. The engine re-derives an ID on a collision; if that
    #    repair ever ran on a value that already had a row, the same original would
    #    come back under two IDs and dedupe would be silently gone.
    assert len(set(resolved.values())) == len(resolved), (
        "an original is behind more than one token ID after concurrent obfuscation"
    )

    # And the session really did hold the shared values once each, not once per run.
    originals = harness.vault.originals_for_session(session_id)
    assert "03/12/1985" in originals
    assert await harness.vault.row_count(session_id) == len(originals)


# ---------------------------------------------------------------------------
# 11b. The same window, driven instead of waited for
# ---------------------------------------------------------------------------

#: The value the race below is run on: eight digits the detector reads as an MRN when
#: they are labelled and does not see AT ALL when they are not. Measured against the
#: shipped registry and spaCy model:
#:
#:     "MRN: 55672814"                                    -> MRN@0.70
#:     "The figure 55672814 was quoted in the appendix."   -> nothing, of any type
#:
#: Eight digits rather than seven or ten because both of those are seen unlabelled --
#: as ``DATE@0.85`` -- and a value the victim run detects for itself is a value it
#: vaults and masks for itself, which never enters the window at all. That is a
#: property of a model release, not of this repo, so both halves are asserted as
#: premises inside the test: a spaCy update that changes either turns this red with a
#: named reason rather than quietly making it vacuous.
#:
#: It also carries more than ``egress_gate.MIN_IDENTIFIER_DIGITS`` (7) digits, so pass
#: 1 scans it as a bare substring rather than under the word-boundary rule -- the
#: block below is the plain whole-value needle, not an edge of the boundary limb.
RACED_VALUE = "55672814"

#: The session-mate. Labelled, so the value is detected, vaulted, and becomes a needle
#: for every subsequent gate check in the session -- including one already in flight.
RACED_MATE_DOCUMENT = (
    "CLINIC NOTE\n\n"
    f"MRN: {RACED_VALUE}\n"
    "Attending physician: Dr Harriet Vance.\n"
    "Patient reviewed in clinic today and discharged in stable condition.\n"
)

#: The victim. Same value, unlabelled, plus a name of its own so the run is a real run
#: that vaults something rather than a document the pipeline has no work to do on.
RACED_VICTIM_DOCUMENT = (
    "ADDENDUM\n\n"
    "Attending physician: Dr Marcus Ellery.\n"
    f"The figure {RACED_VALUE} was quoted verbatim in the appendix.\n"
    "No further action is required at this time.\n"
)


async def test_a_session_mate_vaulting_between_the_build_and_the_gate_cannot_leak(
    make_harness: HarnessFactory,
) -> None:
    """The build-vs-gate window, entered on purpose on every execution.

    ``ObfuscationEngine._add_prior_session_surfaces`` reads
    ``originals_for_session`` while the payload is being built, and
    ``EgressGate._run_passes`` reads it again at gate time. Between those two reads a
    session-mate can vault a value that this run's payload is carrying in the clear --
    a value this run's own detector never saw, so nothing in this run masked it and
    the cross-call sweep that would have masked it looked a few awaits too early.
    Sixteen concurrent runs above hit that window by coincidence in about one
    execution in fourteen as reported -- and in zero of the 37 consecutive executions
    measured while writing this, which is the argument for this test rather than
    against it. A race observable only by repetition is a race nobody notices
    regressing, so this test *drives* it:

    1. the victim run goes all the way to ``EgressGate.check`` normally, real store,
       real detector, real engine, real vault;
    2. :class:`SeamedGate` hands control to a hook at that exact point -- payload
       built, pass 1 not yet run;
    3. the hook runs a complete second pipeline run, the session-mate, through the
       same shipped code path, which vaults ``RACED_VALUE``;
    4. control returns and the real pass 1 reads the originals set the mate grew.

    Steps 1-4 are ordinary awaits, not sleeps, so the interleaving is the same on a
    loaded machine as on an idle one -- and the test asserts the interleaving happened
    (the value absent from the originals set at step 2, present at step 4, and
    verbatim in the payload the gate was handed) rather than assuming the seam worked.

    **The invariant that binds either way is the product's one claim**: no payload the
    provider was handed contains ``RACED_VALUE`` -- checked over *every* call, not the
    last one, because with two runs in flight ``last_user`` answers about whichever
    finished second and says nothing about the other. On top of that, exactly two
    outcomes are safe and each is asserted in full:

    * **Refused**, which is what the shipped pipeline does here, deterministically.
      ``_sweep_residual`` now reads the originals set a second time at the end of the
      pass, which shrinks this interval to the audit write, the prompt obfuscation,
      the payload assembly and the gate's own read -- and this hook fires *inside*
      ``check()``, in the part that engine docstring says cannot be closed from the
      engine at all. Refusing is then the correct answer, not a defect the test is
      indulging: the payload really does carry a vaulted value. What is asserted is
      that the refusal was fail-CLOSED and not merely raised -- ``EGRESS_BLOCK`` on
      the record for that run, no ``LLM_CALL`` for that run, and one provider call in
      total, the mate's.
    * **Completed**, which is what an engine that rebuilt against the grown originals
      set instead of dying on the block would do. Kept because it is the only other
      outcome that satisfies the guarantee, and because a test that hard-codes today's
      branch turns a legitimate improvement into a red suite. It asserts the run
      finished *correctly*: value gone from the outbound payload, the mate's own
      surrogate in its place -- one vault row, one token, no crossed wire -- and the
      value restored on the way back.

    Neither branch passes by default: a third outcome, a different reason code, a
    second vault row for one value, or a provider call carrying the value is a
    failure. The interval the engine *can* repair is the subject of the next test,
    and that one has no branches -- it requires the run to complete.
    """
    harness: Harness = await make_harness(seamed_gate=True)
    session_id, _expires_at = await harness.sessions.create("test-user")
    victim_doc = await harness.upload(RACED_VICTIM_DOCUMENT, "medical", "addendum.txt")
    mate_doc = await harness.upload(RACED_MATE_DOCUMENT, "medical", "chart.txt")

    victim_spans = await harness.detector.detect(RACED_VICTIM_DOCUMENT, "medical")
    assert not any(RACED_VALUE in span.text for span in victim_spans), (
        "premise gone: the victim's own detector now sees the raced value, so this run "
        "vaults and masks it itself and never enters the window this test exists for"
    )
    mate_spans = await harness.detector.detect(RACED_MATE_DOCUMENT, "medical")
    assert any(RACED_VALUE in span.text for span in mate_spans), (
        "premise gone: the mate no longer detects the raced value, so nothing vaults it "
        "mid-flight and the window is never opened"
    )

    seen: dict[str, Any] = {}

    async def vault_it_from_a_session_mate(payload: str, mate_session_id: str) -> None:
        """Runs with the victim's payload built and pass 1 not yet started."""
        seen["payload"] = payload
        seen["before"] = harness.vault.originals_for_session(mate_session_id)
        seen["mate"] = await harness.orchestrator.run(
            mate_session_id, USER_ID, mate_doc, PROMPT, "tokenization"
        )
        seen["after"] = harness.vault.originals_for_session(mate_session_id)

    harness.gate.before_check = vault_it_from_a_session_mate

    refusal: EgressBlockedError | None = None
    result = None
    try:
        result = await harness.orchestrator.run(
            session_id, USER_ID, victim_doc, PROMPT, "tokenization"
        )
    except EgressBlockedError as exc:
        refusal = exc

    # The interleaving is what this test is for, so it is evidence, not an assumption.
    assert seen, "the seam never fired; the victim run never reached the gate"
    assert RACED_VALUE not in seen["before"], (
        "premise gone: the value was already vaulted before the mate ran, so the "
        "engine's cross-call sweep had it and there was no window to race"
    )
    assert "after" in seen, "the session-mate's own run did not complete"
    assert RACED_VALUE in seen["after"], "the mate did not vault the raced value"
    assert RACED_VALUE in seen["payload"], (
        "premise gone: the payload handed to the gate no longer carries the raced "
        "value in the clear, so this is no longer the build-vs-gate window"
    )

    # THE GUARANTEE. Every payload the provider was handed, not just the last one:
    # with two runs in flight `last_user` answers a question about whichever finished
    # second and says nothing at all about the other.
    assert harness.provider.users, "premise: the provider was called at least once"
    for user in harness.provider.users:
        assert RACED_VALUE not in user, (
            "a value vaulted by a session-mate reached the provider in the clear"
        )

    # The mate is untouched by the run that raced it -- its own value came back.
    mate_result = seen["mate"]
    assert RACED_VALUE in mate_result.restored_text
    assert UNRESOLVED_ENTITY not in mate_result.restored_text

    # One value, one vault row, whichever branch ran: the raced value must not have
    # been vaulted a second time by the victim on its way through.
    record = await harness.vault.get_by_original(session_id, "MRN", RACED_VALUE)
    assert record is not None, "the mate's vault row for the raced value is gone"
    originals = harness.vault.originals_for_session(session_id)
    assert RACED_VALUE in originals
    assert await harness.vault.row_count(session_id) == len(originals), (
        "the raced value is behind two vault rows, or a needle has no row"
    )

    if refusal is not None:
        # --- refused: the shape the pipeline produces today, on every execution ---
        assert result is None
        assert refusal.detail["reason"] == "vault_original", (
            f"the window must refuse on pass 1's own reason code; got "
            f"{refusal.detail['reason']!r}"
        )
        assert int(refusal.detail["hit_count"]) >= 1
        run_id = refusal.detail["run_id"]
        blocks = await harness.audit.query(
            session_id=session_id, event_type=EGRESS_BLOCK, limit=1000
        )
        calls = await harness.audit.query(
            session_id=session_id, event_type=LLM_CALL, limit=1000
        )
        assert run_id in {event.run_id for event in blocks}, (
            "the run was refused with no EGRESS_BLOCK on the record"
        )
        assert run_id not in {event.run_id for event in calls}, (
            "the run was refused AFTER calling the provider -- that is not fail-closed"
        )
        assert harness.provider.calls == 1, (
            "exactly one provider call is expected -- the mate's; the refused run "
            "must not have made one"
        )
    else:
        # --- completed: the shape an engine that closes the window produces ---
        assert result is not None
        assert RACED_VALUE not in result.obfuscated_payload, (
            "the run completed with the raced value still in the outbound payload"
        )
        assert record.surrogate in document_section(result.obfuscated_payload), (
            "the raced value was masked behind something other than the mate's own "
            "surrogate -- two tokens for one value is a crossed wire waiting to happen"
        )
        assert RACED_VALUE in result.restored_text, "the raced value did not come back"
        assert UNRESOLVED_ENTITY not in result.restored_text
        assert result.stats["vault_misses"] == 0.0
        assert harness.provider.calls == 2, "one call for the mate, one for the victim"


async def test_a_value_vaulted_before_the_engines_second_look_is_masked_not_refused(
    make_harness: HarnessFactory,
) -> None:
    """The other side of the same window: the part the engine can and does repair.

    The test above lands a session-mate's vault write in the interval the engine
    cannot reach -- inside ``EgressGate.check`` itself -- and the only safe answer
    there is a refusal. This one lands it in the interval the engine *can* reach:
    after ``_sweep_residual`` first reads ``originals_for_session`` and before it
    reads it again at the end of the pass. A value that arrives in that interval must
    be swept into the payload like any other prior-session value, and the run must
    finish normally -- because "the request died" is not an acceptable answer to a
    value the system was perfectly able to mask.

    Driven with a one-shot hook on the engine's own prior-surfaces call, for the same
    reason the gate seam exists: this interval is a few awaits wide and waiting for
    another coroutine to land inside it by luck is not a test. The hook wraps the
    real method, runs a complete session-mate pipeline after the first look returns,
    and then lets the pass continue into its second look.

    **It is deliberately coupled to that seam, and that coupling is the point.** If
    the engine stops looking twice, this test does not quietly keep passing on the
    strength of some other mechanism: the value goes out unswept, the gate refuses
    the run, and the refusal is reported here as the failure it is. The narrowing is
    measured in ``ObfuscationEngine._sweep_residual``'s own docstring (58.9 ms of
    exposed interval down to 0.9 ms); what this test pins is not the number but the
    behaviour the number is about, end to end, through the real orchestrator.
    """
    harness: Harness = await make_harness()
    session_id, _expires_at = await harness.sessions.create("test-user")
    victim_doc = await harness.upload(RACED_VICTIM_DOCUMENT, "medical", "addendum.txt")
    mate_doc = await harness.upload(RACED_MATE_DOCUMENT, "medical", "chart.txt")

    seam = getattr(harness.engine, "_add_prior_session_surfaces", None)
    assert seam is not None, (
        "the engine's prior-surfaces call is gone or renamed; this test drives the "
        "interval between its two reads of the originals set and cannot find it"
    )

    seen: dict[str, Any] = {}
    fired = False

    async def run_the_mate_after_the_first_look(*args: Any, **kwargs: Any) -> Any:
        nonlocal fired
        surfaces = await seam(*args, **kwargs)
        if not fired:
            # Set before awaiting: the mate's own run re-enters this same engine.
            fired = True
            seen["before"] = harness.vault.originals_for_session(session_id)
            seen["mate"] = await harness.orchestrator.run(
                session_id, USER_ID, mate_doc, PROMPT, "tokenization"
            )
            seen["after"] = harness.vault.originals_for_session(session_id)
        return surfaces

    harness.engine._add_prior_session_surfaces = run_the_mate_after_the_first_look

    try:
        result = await harness.orchestrator.run(
            session_id, USER_ID, victim_doc, PROMPT, "tokenization"
        )
    except EgressBlockedError as exc:
        pytest.fail(
            "a value vaulted between the engine's two reads of the originals set was "
            "not swept into the payload, so the gate refused a run it should have "
            f"released: reason={exc.detail['reason']!r}. The second read is what "
            "makes this interval survivable; if it is gone, this is the regression."
        )

    # The interleaving happened where this test says it did.
    assert fired, "the engine seam never fired; the interval was never entered"
    assert RACED_VALUE not in seen["before"], (
        "premise gone: the value was vaulted before the pass started, so the FIRST "
        "read would have found it and the second read is not what saved this run"
    )
    assert RACED_VALUE in seen["after"], "the mate did not vault the raced value"

    # Swept, not leaked and not refused: masked behind the mate's own surrogate, so
    # one value is still one vault row and one token across the two runs.
    record = await harness.vault.get_by_original(session_id, "MRN", RACED_VALUE)
    assert record is not None
    assert RACED_VALUE not in result.obfuscated_payload
    assert record.surrogate in document_section(result.obfuscated_payload), (
        "the late-arriving value is not masked behind the mate's surrogate"
    )
    for user in harness.provider.users:
        assert RACED_VALUE not in user, "the raced value reached the provider in the clear"

    # And the answer is still whole: the token the sweep spliced in came back.
    assert RACED_VALUE in result.restored_text
    assert UNRESOLVED_ENTITY not in result.restored_text
    assert result.stats["unresolved_lost"] == 0.0
    assert result.stats["vault_misses"] == 0.0
    assert harness.provider.calls == 2, "one call for the mate, one for the victim"
    originals = harness.vault.originals_for_session(session_id)
    assert await harness.vault.row_count(session_id) == len(originals)


async def test_a_hard_wrapped_document_leaks_no_name_tail_to_the_provider(
    make_harness: HarnessFactory,
) -> None:
    """The shape the shipped corpus structurally cannot see.

    `fixtures/legal_brief_large.txt` is stored UNWRAPPED (mean line ~527 chars), so
    no committed fixture exercises a name straddling a line break -- while
    `extraction.py` hard-wraps every real PDF and DOCX, which is the whole subject
    of Deviation 32. A blanket "trim every NER span at its first newline" therefore
    passed the entire suite while sending verbatim surnames to the provider: the
    trim discarded the second half of `'Margaret\\n    Whitfield'`, nothing vaulted
    it, and the gate had no needle for a value nobody vaulted.

    Asserted end to end on the OUTBOUND payload, with no shared heuristic: an
    earlier version of this test re-derived the detector's field-label rule and
    disagreed with it, flagging correctly-kept wrapped surnames. The property that
    matters is not "which spans were trimmed" but "is any component of a detected
    person still readable on the wire".
    """
    harness: Harness = await make_harness()
    source = generator.generate(SEED, "legal")
    wrapped = "\n".join(textwrap.fill(p, width=62) for p in source.split("\n\n"))
    assert max(len(line) for line in wrapped.split("\n")) <= 80, "premise: it is wrapped"

    doc_id = await harness.upload(wrapped, "legal", "brief.txt")
    session_id, _ = await harness.sessions.create("test-user")
    result = await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")

    payload = harness.provider.last_user or ""
    assert payload, "premise: the provider was called"

    # The discriminating signal: a PERSON span that ENDS exactly at a line break
    # with a capitalised word on the next line. That word was part of the name and
    # was dropped from the span -- so nothing vaults it, and the gate has no needle
    # for a value nobody vaulted.
    #
    # Chosen because it is present in BOTH configurations. An earlier version
    # filtered to spans that still CONTAIN a newline, which the blanket trim removes
    # by construction -- the assertion selected exactly the spans the bug destroys
    # and so could never see it. Measured on this fixture: 0 here, 3 under the
    # blanket trim ('Michael'||Gonzalez, 'Steven'||Lopez, 'David'||Ford).
    #
    # Scoped to person entities and not to every vaulted original, because the prose
    # entities (CASE_STRATEGY, SETTLEMENT_TERM) are whole sentences and a
    # component-wise rule over those asserts the pipeline must scrub ordinary
    # English ('coordinated', 'figure').
    person_types = {"NAME", "CLIENT_IDENTITY"}
    dropped: list[tuple[str, str]] = []
    for span in result.detections:
        if span.entity_type not in person_types:
            continue
        following = re.match(r"[ \t]*\n[ \t]*([A-Z][a-z]{3,})", wrapped[span.end : span.end + 40])
        if following is not None:
            dropped.append((wrapped[span.start : span.end], following.group(1)))
    # The payload assertion runs FIRST, on the tails actually collected. Written the
    # other way round it sat below `assert dropped == []` and therefore iterated an
    # empty list on every green run -- dead code, and the same never-failing-check
    # class this test's own history is a record of. Ordering it this way means the
    # docstring's claim about the outbound payload is enforced rather than implied.
    assert payload, "premise: the provider was called"
    for _head, tail in dropped:
        assert not re.search(rf"\b{re.escape(tail)}\b", payload), (
            f"the tail {tail!r} was cut from its span AND is verbatim in the "
            f"outbound payload -- nothing vaulted it, so the gate cannot see it"
        )

    assert dropped == [], (
        f"{len(dropped)} person span(s) end at a line break with a capitalised word "
        f"immediately after: {dropped[:3]} -- the tail was cut off the span, so it "
        f"was never vaulted and the egress gate cannot see it"
    )


@pytest.mark.parametrize("width", [62, 50, 40])
async def test_a_hard_wrapped_document_is_processable_at_all(
    make_harness: HarnessFactory, width: int
) -> None:
    """A wrapped document must not be an unconditional EGRESS_BLOCKED.

    The residual sweep matched originals whitespace-EXACTLY (`re.escape`, so a
    literal space could not match a newline plus an indent) while pass 1 compares
    normalised forms, which COLLAPSE whitespace. Of the components `textrules`
    exists to keep in agreement, the sweep was the only whitespace-exact one, so a
    vaulted value recurring across a line break was left in the payload by the
    sweep and then blocked by the gate.

    Fail-closed -- nothing leaked -- but every hard-wrapped document was
    unprocessable, and Deviation 32 says every document reaching the detector has
    been through `extraction.py` and arrives hard-wrapped. `.pdf` and `.docx` are
    accepted inputs, so this was the normal case. The four committed fixtures are
    the only unwrapped documents in the repo (mean line lengths 52 / 161 / 61 /
    527 characters), which is exactly why the suite could not see it.

    It also falsified Deviation 13 in writing, which claimed the boundary rule
    "makes the gate agree with the engine's residual sweep about what counts as an
    occurrence -- previously they disagreed, which is exactly how a value could be
    swept everywhere and still be reported present".
    """
    harness: Harness = await make_harness()
    source = generator.generate(SEED, "medical")
    wrapped = "\n".join(textwrap.fill(p, width=width) for p in source.split("\n\n"))
    assert max(len(line) for line in wrapped.split("\n")) <= width + 20, "premise: wrapped"

    doc_id = await harness.upload(wrapped, "medical", "wrapped.txt")
    session_id, _ = await harness.sessions.create("test-user")

    # The assertion is simply that it completes. A block here is the defect.
    result = await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")
    assert harness.provider.calls == 1
    assert result.restored_text


async def test_a_second_run_under_a_different_strategy_restores_the_first_run_s_pseudonyms(
    make_harness: HarnessFactory,
) -> None:
    """Mixed strategies in one session must not hand the caller a fabricated name.

    ``_surrogate_map`` short-circuited on the RUN's strategy string::

        if strategy != "pseudonymization":
            return None

    but the vault's original -> record index has no strategy dimension: a run
    reuses whatever record an earlier call in the same session minted. So order a
    pseudonymization run then a tokenization run -- which the API allows, since
    ``strategy`` is a per-request field on ``POST /query``, and which a per-entity
    ``strategy:`` override in ``entities.yaml`` produces inside a single run on its
    own -- and the second run splices a *pseudonym* into the payload and then
    restores by hash only. The surrogate pass never runs.

    What makes this worse than a miss is that it is silent in every channel built
    to catch exactly this. ``restored_count`` is ``0`` and ``vault_misses`` is
    ``0``: nothing was missed, because nothing was looked for. The gate is happy --
    a pseudonym is not an original, so no pass fires. The residual assertion is
    happy. And the value that reaches the caller is a well-formed human name, so
    unlike a leftover ``[PHI_NAME_1a2b3c4d]`` there is no shape in the output that
    reads as wrong. Measured on the mutant, the answer came back naming
    "Alexander Johnson" and "Yolanda Foster" -- people who do not exist, in a
    clinical answer about someone who does.

    The map is now built from the RECORDS: any surrogate that is not a
    ``STRICT_TOKEN_RE`` match is a pseudonym and gets an entry, whatever the run
    asked for. Testing the shape of what was actually emitted is the only test
    that cannot drift from what the payload contains.
    """
    harness: Harness = await make_harness()
    text = (
        "Clinical note.\n\n"
        "Patient Marguerite Vandenberg was seen by Dr. Alan Reed today.\n"
    )
    doc_id = await harness.upload(text, "medical", "mixed.txt")
    session_id, _ = await harness.sessions.create(USER_ID)

    first = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "pseudonymization"
    )
    pseudonyms = {d.surrogate for d in first.detections if d.surrogate}
    assert pseudonyms, "premise: run 1 minted surrogates"
    assert not any(STRICT_TOKEN_RE.fullmatch(s) for s in pseudonyms), (
        "premise: run 1 minted PSEUDONYMS, not hash tokens"
    )

    second = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    # The premise of the bug: run 2 reuses run 1's records, so its payload carries
    # pseudonyms even though it asked for tokenization.
    assert "Marguerite Vandenberg" not in second.obfuscated_payload
    assert any(p in second.obfuscated_payload for p in pseudonyms), (
        "premise: the second run really did reuse the first run's pseudonyms"
    )

    # The bug: those pseudonyms survive into the answer, and the real name never
    # comes back. Both halves matter -- a fabricated name reaching the caller is
    # the harm; the missing original is how you would notice.
    leftover = sorted(p for p in pseudonyms if p in second.restored_text)
    assert leftover == [], f"fabricated names reached the caller: {leftover}"
    assert "Marguerite Vandenberg" in second.restored_text
    assert second.stats["restored_count"] > 0
    assert second.stats["vault_misses"] == 0


async def test_a_run_reports_the_surrogate_shape_it_emitted_not_the_one_it_asked_for(
    make_harness: HarnessFactory,
) -> None:
    """The other ordering: tokenize first, then ask the same session to pseudonymize.

    Reuse is the *documented* behaviour and the test above is why it has to stay --
    the vault has no strategy dimension, so a run splices whatever record an earlier
    call in the session minted, and ``_surrogate_map`` deliberately keys off the
    RECORDS so a pseudonym minted earlier still restores under a later tokenization
    run. Reverse the order and the same rule bites the caller instead of the
    restorer: every surrogate on the wire is a hash token, while
    ``PipelineResult.strategy`` -- and the banner in ``ui/app.js`` that prints it --
    says ``pseudonymization``. Measured on the shipped demo document: 52 detections,
    all 52 carrying bracketed token surrogates identical to the previous run's,
    reported as a pseudonymization run.

    Nothing in the response contradicted the label, which is what made it a
    reporting defect rather than an emission one. ``stats["pseudonyms_issued"]`` is
    the contradiction: derived from the records this run actually issued, so it
    reads 0 exactly when the payload carries no pseudonyms, whatever was requested.

    The expected value is derived HERE from the response's own surrogate strings by
    a different test than the production code uses -- "does it start with ``[``"
    rather than ``STRICT_TOKEN_RE`` -- so a stat that shared the pipeline's regex
    bug, or that was hardcoded to a constant, fails one of the two directions. Both
    directions are asserted: the reused-token run must report 0, and the fresh
    session must report more than 0 for the same document and the same request.
    """
    harness: Harness = await make_harness()
    text = (
        "Clinical note.\n\n"
        "Patient Marguerite Vandenberg was seen by Dr. Alan Reed today.\n"
    )
    doc_id = await harness.upload(text, "medical", "mixed-order.txt")
    session_id, _ = await harness.sessions.create(USER_ID)

    first = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )
    tokens = {d.surrogate for d in first.detections if d.surrogate}
    assert tokens, "premise: run 1 minted surrogates"
    assert first.stats["pseudonyms_issued"] == 0, (
        "a tokenization run issued something that is not a token"
    )

    second = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "pseudonymization"
    )

    # Premise, held by string equality rather than by shape: run 2 put run 1's own
    # tokens on the wire. This is the documented reuse, not a defect to fix here.
    reused = {d.surrogate for d in second.detections if d.surrogate}
    assert reused == tokens, "premise: run 2 reused run 1's records verbatim"
    assert second.strategy == "pseudonymization", (
        "premise: the caller asked for pseudonymization and the response echoes it"
    )

    # The fix: the run reports the shape it emitted. Zero pseudonyms, next to a
    # non-zero token count and a banner saying pseudonymization.
    assert second.stats["tokens_issued"] > 0
    assert second.stats["pseudonyms_issued"] == _unbracketed(reused)
    assert second.stats["pseudonyms_issued"] == 0

    # Same document, same request, fresh session: pseudonyms really are issued, so
    # the zero above is a property of the payload and not of the statistic.
    fresh_session, _ = await harness.sessions.create(USER_ID)
    fresh = await harness.orchestrator.run(
        fresh_session, USER_ID, doc_id, PROMPT, "pseudonymization"
    )
    minted = {d.surrogate for d in fresh.detections if d.surrogate}
    assert fresh.stats["pseudonyms_issued"] == _unbracketed(minted) > 0


def _unbracketed(surrogates: set[str]) -> int:
    """Surrogates that are not bracketed markers -- i.e. realistic fakes.

    Deliberately NOT ``STRICT_TOKEN_RE``: the production stat is derived from that
    regex, and a check sharing the machinery it checks is not evidence. Every
    marker this pipeline emits is wrapped in ``[...]`` (``surrogates.py``
    ``format_surrogate``), and no pseudonym generator produces a leading bracket,
    so the first character separates the two shapes independently.
    """
    return sum(1 for s in surrogates if not s.startswith("["))


@pytest.mark.parametrize(
    "name",
    ["René Müller", "Chloé Dubois", "Jörg Königsberg", "Åsa Lindqvist", "Iñaki Errázuriz"],
)
async def test_a_decomposed_accent_does_not_send_a_name_to_the_provider_in_the_clear(
    make_harness: HarnessFactory, name: str
) -> None:
    """The same document in NFD must not leak the name NFC protects.

    Unicode gives two spellings of an accented letter: NFC composes ``é`` into
    U+00E9, NFD decomposes it into ``e`` + U+0301. They are *canonically
    equivalent* -- the same character, by Unicode's own definition -- render
    identically, and compare unequal.

    spaCy does not merely score the decomposed spelling lower. It stops emitting
    the span. Measured on ten accented names before this fix, six vanished
    completely and one (``Élodie Chaumont``) came back as ``Chaumont`` alone, the
    given name silently dropped.

    That is not a fail-closed miss, which is what makes it the worst kind. Every
    layer downstream is keyed on the vault: pass 1 compares the payload against
    values the vault holds, and an entity never detected was never vaulted, so
    there is no needle to look for. Pass 2 is a re-scan by the same detector that
    just missed it. Pass 3 matches independent regexes -- and a person's name is
    not a regex. So all three passes agree the payload is clean, the run returns
    **200**, and the name goes to the provider verbatim. Nothing anywhere reports a
    warning, because from the pipeline's point of view nothing happened.

    A homoglyph or a zero-width space is an attack somebody has to mount. NFD is
    the *default* on macOS filesystems, and a routine output of text editors and
    PDF extractors -- Deviation 32 notes every document reaching the detector has
    been through ``extraction.py``. So this fired on honest documents, uploaded by
    honest users, with nobody attacking anything.

    The fix is canonical composition at ingestion (``extraction._normalise``, the
    one function all three file kinds funnel through) and on the prompt. NFC, not
    the NFKC used for comparison keys: NFKC would rewrite ``ﬁ`` to ``fi`` and
    ``½`` to ``1``+``\u2044``+``2``, which is right for a lookup bucket and wrong for a document
    that is about to be sliced by offset and reassembled.

    Asserted against the outbound payload, not against the detection count. "The
    detector found it" is the mechanism; "it did not reach the provider" is the
    guarantee, and only the second one is what the product claims.
    """
    harness: Harness = await make_harness()
    text = unicodedata.normalize(
        "NFD",
        "Clinical note.\n\n"
        f"Patient {name}, DOB 1974-03-02, presented today.\n"
        f"The care team discussed {name}'s medication with the family.\n",
    )
    assert text != unicodedata.normalize("NFC", text), "premise: NFD really differs"

    doc_id = await harness.upload(text, "medical", "decomposed.txt")
    session_id, _ = await harness.sessions.create(USER_ID)
    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )

    # Both spellings, because the store composes and the assertion must not be
    # satisfied merely by the composition having happened somewhere.
    payload = result.obfuscated_payload
    for form in ("NFC", "NFD"):
        spelling = unicodedata.normalize(form, name)
        assert spelling not in payload, f"{form} spelling of {name!r} reached the provider"
        for part in spelling.split():
            assert part not in payload, f"{form} component {part!r} reached the provider"

    assert name in result.restored_text, "and it must still come back"


async def test_a_prompt_pseudonym_restores_to_the_real_value(
    make_harness: HarnessFactory,
) -> None:
    """A name typed into the prompt must be masked outbound and restored inbound.

    The document half of this is covered several times over. The prompt half is
    newer -- the prompt only became a detect/obfuscate input once it was recognised
    as an egress channel in its own right -- and it is the half where a gap is
    invisible, because under pseudonymization an unrestored surrogate is a
    well-formed human name rather than a leftover ``[PII_NAME_...]``. There is
    nothing in the output for a reader to notice.

    Proved against the real vault and the real restorer, which is what makes it
    worth having next to the stub-driven check in ``test_egress_gate.py``: that one
    can only assert what the orchestrator *hands* the restorer, and the claim here
    is what comes back. It is also what keeps ``_surrogate_map``'s values honest --
    they are now the empty sentinel, so the vault lookup that produces this answer
    happens entirely inside ``_restore_surrogates``, and if that lookup regressed
    the stub test would still pass while this one would not.
    """
    harness: Harness = await make_harness()
    doc_id = await harness.upload(
        "Clinical note.\n\nThe patient was seen in clinic today.\n", "medical", "p.txt"
    )
    session_id, _ = await harness.sessions.create(USER_ID)

    name = "Bernadette Halloran"
    result = await harness.orchestrator.run(
        session_id,
        USER_ID,
        doc_id,
        f"What is the current medication plan for {name}?",
        "pseudonymization",
    )

    assert name not in result.obfuscated_payload, "the typed name reached the provider"

    # Asked of the vault, not of `result.detections`: that field is `obf.spans`,
    # the DOCUMENT's spans, so the prompt's surrogate is deliberately not in it.
    record = await harness.vault.get_by_original(session_id, "NAME", normalize(name))
    assert record is not None, "premise: the prompt's name was vaulted"
    surrogate = record.surrogate
    assert surrogate in result.obfuscated_payload, "premise: a pseudonym went out"
    assert not STRICT_TOKEN_RE.fullmatch(surrogate), "premise: a pseudonym, not a token"

    # The point: the pseudonym is gone from the answer and the real name is back.
    assert surrogate not in result.restored_text, "the invented name was left in the answer"
    assert name in result.restored_text
    assert result.stats["vault_misses"] == 0


#: The audit events a passing run writes BEFORE the provider is called, in order.
#: Measured, not asserted from the source: a tracing wrapper over ``audit.emit``
#: recorded ``DETECT, OBFUSCATE, OBFUSCATE, EGRESS_PASS, LLM_CALL, DEOBFUSCATE``,
#: and the provider call sits between ``EGRESS_PASS`` and ``LLM_CALL``.
#:
#: Three different components produce them -- the orchestrator writes ``DETECT``,
#: the engine writes ``OBFUSCATE``, the gate writes ``EGRESS_PASS`` -- which is the
#: reason the parametrisation below is worth its length: a change that makes one
#: component's audit writes non-fatal leaves the other two still refusing, so a
#: single-arm test passes while the guarantee is half gone. That is not
#: hypothetical; it is what the first version of this test did.
PRE_RELEASE_EVENTS: tuple[str, ...] = ("DETECT", "OBFUSCATE", "EGRESS_PASS")


@pytest.mark.parametrize("failing_event", PRE_RELEASE_EVENTS)
async def test_no_release_survives_an_audit_write_that_failed_before_it(
    make_harness: HarnessFactory, failing_event: str
) -> None:
    """No release without a record, pinned per component. The off-box tripwire.

    Two audit-failure escape hatches exist, both deliberate: ``EgressGate._emit_block``
    and the orchestrator's two block paths. Their comments all say "the block itself
    still stands", and that is right -- a run already being *refused* must not have its
    typed ``EgressBlockedError`` replaced by whatever the log threw.

    The complement is the guarantee, and nothing stated it before this test: on every
    path that would **release**, an audit failure propagates and the provider is never
    reached. Measured per event, by failing exactly one and watching the provider::

        DETECT       fails -> refused (RuntimeError)        provider=0
        OBFUSCATE    fails -> refused (RuntimeError)        provider=0
        EGRESS_PASS  fails -> refused (EgressBlockedError)  provider=0
        LLM_CALL     fails -> refused (RuntimeError)        provider=1   <- already sent
        DEOBFUSCATE  fails -> refused (RuntimeError)        provider=1   <- already sent

    ``EGRESS_PASS`` is the load-bearing one and the most interesting: it is the last
    write before the call, and its failure surfaces as ``EgressBlockedError`` rather
    than the raw error -- the gate refuses to release what it could not record. The
    last two are listed to be honest about the boundary: by then the bytes are gone,
    so an audit failure can only spoil the caller's response, not prevent the egress.
    Anything claiming otherwise would be a guarantee this architecture cannot make.

    **This is the test that should fail first if the audit log moves off-box** (S3
    Object Lock, a WORM store, a managed audit service -- README section 5 Q5's stated
    remedy for the tail-append residual). With a local SQLite write a failing emit is
    rare. With a network write it is routine: a timeout, a throttle, an expired
    credential, a partition. The obvious way to make a remote sink "resilient" is to
    wrap emits in the same ``except Exception`` the block paths already use, which
    would silently convert "refuses to release unaudited" into "releases whenever the
    audit service is unavailable" -- the exact window an attacker who can reach the
    sink would arrange.

    Verified to bite: wrapping ``PipelineOrchestrator._emit`` in ``try/except`` reddens
    the ``DETECT`` and ``OBFUSCATE`` arms; the ``EGRESS_PASS`` arm covers the gate,
    which that change does not touch. The full suite is otherwise green under it --
    2,071 passed -- so without this parametrisation nothing at all would notice.

    If you are here because you just made that change, the decision is whether an
    audit-sink outage should fail the request (keep this, and accept the sink is now in
    the availability path) or degrade to a durable local spool reconciled later
    (replace this with a test that the spool captured the event and that the reconciler
    cannot silently drop it). Dropping the event and releasing anyway is not on the
    table.
    """
    harness: Harness = await make_harness()
    text = "Clinical note.\n\nPatient Marcus Webb, DOB 1970-02-11, was seen today.\n"
    doc_id = await harness.upload(text, "medical", "audited.txt")

    # Control: the identical run reaches the provider on a healthy log, and writes
    # every event this test claims comes before the call. Without it, the assertion
    # below could pass because the run broke somewhere that never reached an emit.
    seen: list[str] = []
    healthy = harness.audit.emit

    async def tracing(event: AuditEvent) -> int:
        seen.append(event.event_type)
        return await healthy(event)

    harness.audit.emit = tracing  # type: ignore[method-assign]
    control_session, _ = await harness.sessions.create(USER_ID)
    control = await harness.orchestrator.run(
        control_session, USER_ID, doc_id, PROMPT, "tokenization"
    )
    assert harness.provider.calls == 1, "premise: a healthy run reaches the provider"
    assert "Marcus Webb" in control.restored_text
    # A new pre-release event added later is caught here rather than going unpinned.
    assert set(PRE_RELEASE_EVENTS) <= set(seen), (PRE_RELEASE_EVENTS, seen)
    assert seen.index("EGRESS_PASS") < seen.index("LLM_CALL"), seen

    attempts = 0

    async def sink_is_down_for_one_event(event: AuditEvent) -> int:
        nonlocal attempts
        if event.event_type == failing_event:
            attempts += 1
            raise RuntimeError(f"audit sink is down for {failing_event}")
        return await healthy(event)

    harness.audit.emit = sink_is_down_for_one_event  # type: ignore[method-assign]
    session_id, _ = await harness.sessions.create(USER_ID)
    with pytest.raises(Exception) as caught:
        await harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")

    assert attempts > 0, f"premise: the run really tried to write {failing_event}"
    assert not isinstance(caught.value, AssertionError)
    # Still one call -- the control's. The second run released nothing.
    assert harness.provider.calls == 1, (
        f"{failing_event} could not be recorded and the payload was sent anyway"
    )


# ---------------------------------------------------------------------------
# The class hint the model strands, and the strategy the log reports
# ---------------------------------------------------------------------------

#: A Tier-3 annotated token exactly as ``format_surrogate`` writes one.
#: Deliberately NOT ``STRICT_TOKEN_RE``: the production hint map is derived from that
#: pattern, and a test that shares the regex it checks proves only that the regex is
#: self-consistent. This is spelled out from the emitter's documented shape instead.
ANNOTATED_TOKEN_RE = re.compile(r"\[([A-Z]+_[A-Z0-9_]+_[0-9a-f]{8})\|([a-z0-9-]{1,24})\]")

#: A document whose Tier-3 gazetteer entities carry class hints under
#: pseudonymization -- the configuration the demo runs and the browser shows.
HINTED_DOCUMENT = (
    "Clinical note.\n\n"
    "Patient Marguerite Vandenberg reports chest pain and asthma.\n"
    "Follow-up scheduled with Dr. Alan Reed.\n"
)


class BracketStrippingProvider:
    """A model that drops BOTH brackets off the first annotated token it is shown.

    Core requirement 6's "grammatically modified form", in the one shape that strands
    the class hint: ``[PHI_DIAGNOSIS_ff7cf4b8|cardiovascular]`` comes back as
    ``PHI_DIAGNOSIS_ff7cf4b8|cardiovascular``. ``TOKEN_RE`` reads a hint only when a
    closer follows it, so the hash restores and the ``|cardiovascular`` stays welded
    to the restored original.

    The mutation is applied to a token read out of the *payload this run built*, so
    the test cannot pass by asserting about a token nobody issued.
    """

    name = "bracket-stripper"

    def __init__(self) -> None:
        self.calls = 0
        self.emitted_token: str | None = None
        self.stranded: str | None = None

    async def complete(self, system: str, user: str, *, model: str, timeout_s: float = 60.0) -> str:
        return (await self.complete_detailed(system, user, model=model, timeout_s=timeout_s)).text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        self.calls += 1
        match = ANNOTATED_TOKEN_RE.search(document_section(user))
        if match is None:
            answer = "The document carried no annotated token."
        else:
            self.emitted_token = match.group(0)
            self.stranded = f"{match.group(1)}|{match.group(2)}"
            answer = f"- The closing section mentions {self.stranded}.\n"
        await asyncio.sleep(0)
        return LLMResponse(
            text=answer,
            input_tokens=estimate_tokens(system) + estimate_tokens(user),
            output_tokens=estimate_tokens(answer),
            model=model,
        )


async def test_a_class_hint_the_model_stranded_does_not_reach_the_user(
    make_harness: HarnessFactory,
) -> None:
    """The orchestrator passes ``hints``, so the suffix goes with the token.

    Measured before the fix, through this same pipeline in pseudonymization mode:
    panel 4 read ``- The closing section mentions chest pain|cardiovascular.`` while
    the bracketed spelling of the same token restored cleanly. Not a leak -- the hint
    is a string this process minted out of a gazetteer class column -- but visible
    debris welded to a patient's diagnosis in the deliverable a reviewer reads.

    ``Restorer.restore`` has taken ``hints`` since the mop-up was made bounded, and
    its docstring names this exact string; the orchestrator passed ``surrogates`` and
    ``issued`` and not that. README Deviation 70 recorded the gap in as many words.

    The two halves are asserted separately on purpose: the value must be BACK (a fix
    that deleted the sentence would satisfy "no pipe" and destroy the answer), and
    the stranded suffix must be GONE.
    """
    provider = BracketStrippingProvider()
    harness: Harness = await make_harness(provider=provider, strategy="pseudonymization")
    doc_id = await harness.upload(HINTED_DOCUMENT, "medical", "hinted.txt")
    session_id, _ = await harness.sessions.create(USER_ID)

    result = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "pseudonymization"
    )

    assert provider.emitted_token is not None, (
        "premise: this run put an annotated Tier-3 token in the payload"
    )
    assert provider.stranded is not None
    hint = provider.emitted_token.split("|", 1)[1].rstrip("]")

    # The token itself is gone -- the ordinary guarantee, restated so a fix that
    # merely stopped restoring cannot pass.
    assert provider.stranded not in result.restored_text
    # The original is back, so nothing was deleted along with the suffix.
    originals = harness.vault.originals_for_session(session_id)
    assert any(original in result.restored_text for original in originals), (
        f"nothing was restored at all: {result.restored_text!r}"
    )
    # And the hint went with it.
    assert f"|{hint}" not in result.restored_text, (
        f"the class hint is still welded to the restored value: {result.restored_text!r}"
    )
    assert "|" not in result.restored_text, result.restored_text


async def test_the_audit_log_records_the_composition_restored_not_the_one_requested(
    make_harness: HarnessFactory,
) -> None:
    """Run 1 tokenizes, run 2 asks to pseudonymize the same session. The log follows.

    Vault reuse is the documented, required behaviour and is not what changes here:
    run 2 legitimately splices run 1's hash tokens. What changed is that every
    ``OBFUSCATE`` and ``DEOBFUSCATE`` row recorded ``strategy: pseudonymization`` --
    the REQUEST -- for a run that emitted nothing but tokens, so a compliance reader
    reconstructing what was sent got a false answer from the log while
    ``PipelineResult.emitted_strategy`` beside it was already correct.

    The expected value is taken from the response object, which a different mechanism
    produces than the rows do, and cross-checked against the run's own surrogates by
    a bracket test rather than by the production regex. A row that echoed ``strategy``
    under a second key fails the inequality; a row hardcoded to ``tokenization`` fails
    the first run's half.
    """
    harness: Harness = await make_harness()
    doc_id = await harness.upload(HINTED_DOCUMENT, "medical", "drift.txt")
    session_id, _ = await harness.sessions.create(USER_ID)

    first = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "tokenization"
    )
    second = await harness.orchestrator.run(
        session_id, USER_ID, doc_id, PROMPT, "pseudonymization"
    )

    reused = {d.surrogate for d in second.detections if d.surrogate}
    assert reused, "premise: run 2 put surrogates on the wire"
    assert _unbracketed(reused) == 0, (
        "premise: every surrogate run 2 emitted is a bracketed token, not a pseudonym"
    )
    assert second.strategy == "pseudonymization"
    assert second.emitted_strategy == "tokenization"

    for result, expected in ((first, "tokenization"), (second, "tokenization")):
        rows = [
            row
            for row in await harness.audit.query(run_id=result.run_id, limit=1000)
            if row.event_type in {OBFUSCATE, DEOBFUSCATE}
        ]
        assert rows, f"no obfuscate/deobfuscate rows for run {result.run_id}"
        for row in rows:
            assert row.detail["emitted_strategy"] == expected, (
                f"{row.event_type} row reports the wrong composition: {dict(row.detail)}"
            )
            # The request is still there. Dropping it would lose a fact, and on run 2
            # the two must be visibly different or the row says nothing new.
            assert row.detail["strategy"] == result.strategy, dict(row.detail)
        if result is second:
            assert all(row.detail["strategy"] != row.detail["emitted_strategy"] for row in rows), (
                "run 2 requested pseudonymization and emitted tokens; a row where the "
                "two agree is echoing the request under a second key"
            )


async def test_the_hint_map_the_orchestrator_builds_is_bounded_by_the_emitters_grammar(
    make_harness: HarnessFactory,
) -> None:
    """The map authorises a deletion from the user's answer, so its reach is checked.

    ``_consume_emitted_hint`` will remove ``|`` plus whatever this map names for a
    token ID. That is safe only because the map is *derived from the surrogates this
    run emitted* rather than guessed at, so the bound is asserted here against real
    records rather than trusted to the docstring:

    * every value is a substring of the surrogate it came from, after the pipe;
    * every value satisfies ``HINT_RE`` -- ``[a-z0-9-]{1,24}``, the same gate
      ``format_surrogate`` puts a hint through before it can reach a payload -- so
      the longest deletion any run can authorise is 25 characters;
    * a record with no hint, and a pseudonym record, contribute nothing at all.

    Built from a real obfuscation of a Tier-3 document, not from hand-made records:
    a bound that only holds for the records a test invented is not a bound.
    """
    harness: Harness = await make_harness(strategy="pseudonymization")
    session_id, _ = await harness.sessions.create(USER_ID)
    detections = await harness.detector.detect(HINTED_DOCUMENT, "medical")
    obf = await harness.engine.obfuscate(
        session_id, HINTED_DOCUMENT, detections, strategy="pseudonymization"
    )
    assert obf.tokens, "premise: the run vaulted something"

    hints = orchestrator_module._emitted_hint_map(obf.tokens)
    assert hints, "premise: this document produced at least one annotated Tier-3 token"

    by_id = {token.token_id: token.surrogate for token in obf.tokens}
    for token_id, hint in hints.items():
        surrogate = by_id[token_id]
        assert surrogate.endswith(f"|{hint}]"), (
            f"the map named {hint!r} for a token whose surrogate is {surrogate!r}"
        )
        assert HINT_RE.fullmatch(hint), hint
        assert len(hint) <= MAX_HINT_LEN
    assert len(f"|{max(hints.values(), key=len)}") <= MAX_HINT_LEN + 1

    # Nothing is invented for the records that carry no hint -- pseudonyms have no
    # token grammar at all, and an un-annotated token has no group to read.
    unannotated = [
        token.token_id
        for token in obf.tokens
        if "|" not in token.surrogate and token.token_id not in hints
    ]
    assert len(hints) + len(unannotated) == len({token.token_id for token in obf.tokens}), (
        "the map claimed a hint for a surrogate that does not carry one"
    )
