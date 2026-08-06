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
from secure_context_pipeline.models import Detection, EntityAction, EntityCategory
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import RAW_SUFFIX, EncryptedDocumentStore
from secure_context_pipeline.surrogates import STRICT_TOKEN_RE, TOKEN_RE
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
    """The shipped mock, plus a call counter and the payload it last saw."""

    name = "mock"

    def __init__(self) -> None:
        self._inner = MockProvider()
        self.calls = 0
        self.last_user: str | None = None

    async def complete(self, system: str, user: str, *, model: str, timeout_s: float = 60.0) -> str:
        return (await self.complete_detailed(system, user, model=model, timeout_s=timeout_s)).text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        self.calls += 1
        self.last_user = user
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
    ) -> Harness:
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
        audit = await AuditLogger.open(root / "audit.db")
        store = await EncryptedDocumentStore.open(settings)
        sessions = (
            SessionRegistry(settings)
            if clock is None
            else SessionRegistry(settings, clock=clock)
        )
        vault = await SessionVault.open(root / "vault.db", sessions)
        engine = ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=settings,
            audit=audit,
        )
        restorer = Restorer(vault=vault, settings=settings, audit=audit)
        chosen = CountingMockProvider() if provider is None else provider
        harness = Harness(
            settings=settings,
            registry=registry,
            detector=detector,
            store=store,
            sessions=sessions,
            vault=vault,
            audit=audit,
            engine=engine,
            restorer=restorer,
            provider=chosen,
            orchestrator=PipelineOrchestrator(
                store=store,
                detector=detector,
                engine=engine,
                injector=ContextInjector(),
                gate=EgressGate(
                    vault=vault, detector=detector, settings=settings, audit=audit
                ),
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
    """
    harness: Harness = await make_harness()
    mark = "́"
    document = (
        "REFERRAL LETTER\n\n"
        "The primary contact is Nathaniel Brightwater, the coordinator.\n\n"
        f"For continuity, direct questions to Nathaniel{mark} Brightwater at reception.\n"
    )
    error = await _blocked_run(harness, document, "medical")
    assert error.detail["reason"] == "vault_original"


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

    The premise is asserted from the vault rather than assumed: nothing at all was
    vaulted from this document, so a block here cannot be pass 1.
    """
    harness: Harness = await make_harness()
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
    """
    harness: Harness = await make_harness()
    session_id, _expires_at = await harness.sessions.create("test-user")
    documents = _contended_documents(CONCURRENT_RUNS)
    doc_ids = [
        await harness.upload(text, "medical", f"chart{index}.txt")
        for index, text in enumerate(documents)
    ]

    results = await asyncio.gather(
        *(
            harness.orchestrator.run(session_id, USER_ID, doc_id, PROMPT, "tokenization")
            for doc_id in doc_ids
        )
    )
    assert len(results) == CONCURRENT_RUNS

    mrns = [f"MRN: {4471900 + index * 7}" for index in range(CONCURRENT_RUNS)]
    resolved: dict[str, str] = {}

    for index, result in enumerate(results):
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
