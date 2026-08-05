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
import secrets
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
from secure_context_pipeline.errors import CryptoAuthError, SessionExpiredError, VaultMissError
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

    # And audited, once per distinct unknown token, with the token ID but no value.
    misses = await harness.audit.query(session_id=session_id, event_type=VAULT_MISS)
    assert len(misses) == 1
    assert misses[0].token_id == UNKNOWN_TOKEN_ID
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

    # The sweep's destruction path then clears the rows the key already made
    # undecryptable.
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
