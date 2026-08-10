"""The zero-PII-in-transit claim, asserted against the **bytes on the wire**.

The challenge's requirement is written about the network, not about a function call:
*"a network traffic inspection of the outbound LLM API call must show no recognizable
PII."* :mod:`tests.leakage.test_leakage_harness` captures the payload at the
``provider.complete(system, user)`` boundary -- the *arguments*, one frame above the
socket -- and ``demo.py --dump-wire`` inspects the real HTTP body but requires
``--real`` plus a live API key, so it has never run in CI. Between those two there was
no permanent test of the literal request body at all.

**What is real here and what is not, stated exactly, because a wire test that quietly
reconstructs the wire is worse than none.**

* Real: the whole pipeline -- ``EncryptedDocumentStore``, the shipped ``Detector`` over
  the shipped ``entities.yaml``, ``ObfuscationEngine`` under **both** strategies,
  ``ContextInjector``, ``EgressGate``, ``SessionVault``, ``AuditLogger``, ``Restorer``.
* Real: :class:`~secure_context_pipeline.llm.anthropic_provider.AnthropicProvider`, the
  provider that ships -- not a stub of it -- so the genuine ``anthropic`` SDK builds the
  request and performs the JSON serialization.
* Real: the documents, freshly generated per case by :mod:`fixtures.generator`.
* Mocked: the **transport only**. ``httpx.MockTransport`` is spliced in at the bottom of
  the stack, below every layer that composes the request, and it is the seam
  ``AnthropicProvider(settings, http_client=...)`` already exposes for ``--dump-wire``.
  Nothing else is replaced, and :func:`test_no_request_escapes_the_mock_transport` is
  what says so: every request the SDK makes arrives at the handler, so no socket opens.
* Fake: the API key, which is a literal in this file. The suite must never read the
  developer's real one -- ``tests/conftest.py`` pops ``ANTHROPIC_API_KEY`` from the
  environment at import time for that reason, and this module supplies its own rather
  than undoing that.

**The scan is of the captured request in three forms, and all three are asserted.** The
raw ``bytes`` exactly as ``request.content`` returns them; those bytes decoded as UTF-8;
and the body re-serialized from ``json.loads`` with ``ensure_ascii=False``. The three
disagree in ways that matter: the SDK writes the body with ``ensure_ascii=True``, so an
accented original is ``\\u00e9``-escaped in the raw bytes and a naive substring scan of
them reads clean on a payload that provably carries the value. Re-serializing is what
brings the escaped form back into the same alphabet as the needle; keeping the raw bytes
is what catches anything the JSON round-trip would smooth away.

**What the six generated cases above are evidence OF, and what they are not.** They are
evidence of the *obfuscator*: on an ordinary document the engine replaces every detected
value, so the request body is clean before the :class:`~...pipeline.egress_gate.EgressGate`
is ever consulted, and the gate's verdict is not load-bearing for any of them. That was
measured, not assumed. Forcing ``EgressGate._scan_originals`` -- the whole of pass 1 -- to
``return 0`` reddened ``tests/test_egress_gate.py`` (178 failed, 160 passed) and nine tests
in :mod:`tests.leakage.test_leakage_harness`, and left **this file entirely green**. A test
file carrying the network-inspection requirement that cannot see the last line of defence
die is a green whose name overstates its evidence, which is the exact defect class this
project spent its audit closing.

:func:`test_the_gate_bound_case_is_a_real_counterfactual` and its two siblings close it.
They run the same document **twice**, and the only difference between the two runs is
whether the gate knows the planted value:

* ``ZXQQ-KLM-RSTV-WYNP`` is a value the shipped registry genuinely does not recognise
  (:func:`tests.leakage.test_leakage_harness.test_planted_value_is_invisible_to_the_detector`
  asserts that blindness in every document category), so the engine leaves it in place and
  it rides into the payload untouched. Pass 2 re-scans with the same blind detector and
  pass 3's independent recognisers do not know the shape either -- measured, by the same
  sabotage: with pass 1 dead, nothing else blocked it.
* **Control run** -- the value is in the document and *not* in the vault. The gate has
  nothing to match, the request goes out, and the plant is on the wire **byte-for-byte**.
  That is the counterfactual made real rather than argued: obfuscation demonstrably does
  not remove this value.
* **Gate-bound run** -- byte-identical document, and the value is seeded into the vault
  through ``SessionVault.note_unrestorable``, the shipped path the engine itself uses for
  a redact-band detection that gets no token and no row. Pass 1 now has a needle, and the
  request never reaches the transport at all.

So the delta between the two runs, measured at ``request.content``, *is* the gate. Kill
pass 1 and the gate-bound run becomes the control run: a body appears on the wire carrying
a vaulted original, and both of the sibling tests go red for that reason. Proven by
re-running the same ``return 0`` sabotage after the fix -- see the commit message.

This is deliberately **not** a copy of
:func:`tests.leakage.test_leakage_harness.test_unknown_shape_value_blocks_egress_and_the_call_never_fires`.
That test asserts at the ``provider.complete(...)`` call boundary -- it counts calls that
did not happen. This one asserts at the serialized HTTP body, and adds the half the harness
has no way to state: a *positive* measurement, in bytes, of what the wire looks like when
the gate is not the thing keeping it clean.
"""

from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio

from fixtures import generator
from secure_context_pipeline.audit.logger import AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.errors import EgressBlockedError
from secure_context_pipeline.llm.anthropic_provider import AnthropicProvider
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault
from tests.leakage.test_leakage_harness import (
    DOC_CATEGORY,
    KINDS,
    PLANT_TEMPLATE,
    STRATEGIES,
    UNKNOWN_SHAPE_VALUE,
    USER_ID,
    find_in_bytes,
    find_in_text,
    mask,
)

pytestmark = pytest.mark.leakage

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "entities.yaml"

#: Not a credential. The provider refuses to construct without *some* key
#: (``ConfigError(reason="anthropic_api_key_missing")``), the SDK puts it in a header,
#: and the transport below never leaves the process. Deliberately not read from the
#: environment: ``tests/conftest.py`` pops ``ANTHROPIC_API_KEY`` so a developer's real
#: key cannot reach a test run, and a module that re-read it would undo that.
FAKE_API_KEY = "sk-ant-api03-not-a-real-key-0000000000000000"

#: One case per (kind, strategy). Six, so both obfuscation strategies are exercised over
#: every document category the challenge names -- the wire is a different serialization
#: for a pseudonym than for a token, and "we checked it on medical/tokenization" is not
#: a statement about the other five.
WIRE_CASES: tuple[tuple[str, str, int], ...] = tuple(
    (kind, strategy, 70_000 + index)
    for index, (kind, strategy) in enumerate(
        (kind, strategy) for kind in KINDS for strategy in STRATEGIES
    )
)

PROMPT = "Summarise this record and list the key parties, dates and figures."

#: The gate-bound pair. One document, one ``doc_id``, two sessions -- so the two runs
#: differ in exactly one respect and the wire can be read as a difference. ``financial``
#: and ``tokenization`` are arbitrary among the six above; the plant is invisible to the
#: detector in every category, which
#: ``test_planted_value_is_invisible_to_the_detector`` asserts rather than assumes.
GATE_CASE_KIND = "financial"
GATE_CASE_STRATEGY = "tokenization"
GATE_CASE_SEED = 70_100


def _message_json() -> dict[str, Any]:
    """A minimal Messages-API response body, as JSON on the wire.

    Deliberately carries no surrogate and no original. This module's subject is the
    **request**; a response engineered to exercise restoration would put values back
    into the process for no benefit here and is
    :mod:`tests.leakage.test_leakage_harness`'s job.
    """
    return {
        "id": "msg_wire_leak",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "content": [{"type": "text", "text": "Summary unavailable in this fixture."}],
        "usage": {"input_tokens": 11, "output_tokens": 7},
    }


class WireCapture:
    """Every outbound request body, exactly as the SDK handed it to the transport.

    ``request.content`` and nothing else. Headers are never recorded, so the API key --
    fake here, real under ``demo.py --dump-wire``, which uses the same seam -- cannot
    reach an assertion message or a captured artefact.
    """

    def __init__(self) -> None:
        self.bodies: list[bytes] = []
        self.urls: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(bytes(request.content))
        self.urls.append(str(request.url))
        return httpx.Response(200, json=_message_json())


def _body_views(body: bytes) -> tuple[str, str]:
    """``(decoded, reserialized)`` -- the two text views of one captured request.

    The SDK serializes with ``ensure_ascii=True``, so ``José`` reaches the wire as
    ``Jos\\u00e9``. A scan of the decoded bytes alone therefore reads CLEAN on a body
    that carries the value in the only spelling the wire has -- the same defect
    ``_unescape_json_unicode`` exists for on the audit channel. Re-serializing with
    ``ensure_ascii=False`` puts the needle and the haystack back in one alphabet.

    Both are returned rather than one chosen, because the round trip is lossy in the
    other direction too: it normalises key order and whitespace, and anything riding in
    the raw bytes that ``json.loads`` discards is only visible before it.
    """
    decoded = body.decode("utf-8", errors="replace")
    reserialized = json.dumps(json.loads(body), ensure_ascii=False, sort_keys=True)
    return decoded, reserialized


@pytest.fixture(scope="module")
def wire_registry() -> EntityRegistry:
    return load_registry(REGISTRY_PATH)


@pytest.fixture(scope="module")
def wire_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Settings for the only module in the suite that selects the ``anthropic`` provider.

    **Two details here are load-bearing and both were learned by getting them wrong.**

    ``ANTHROPIC_API_KEY`` rather than ``anthropic_api_key``: the field carries
    ``validation_alias=AliasChoices("ANTHROPIC_API_KEY")``, and with a validation alias
    pydantic will not populate the field from its own name. Combined with
    ``extra="ignore"`` the field-name spelling is accepted and **silently dropped** --
    no error, the key stays ``None``. This fixture was written that way, and what filled
    the field instead was ``.env``, i.e. the developer's real key. Nothing was
    transmitted (the transport below is a mock) but a live credential was being loaded
    into the process by a test that believed it was using the literal above.

    ``_env_file=None`` closes that door from this side. ``tests/conftest.py`` already
    disables ``.env`` process-wide ("Lock 2"), and this is deliberately not a second
    copy of that guarantee for its own sake -- it is what makes this fixture's behaviour
    a property of this file rather than of a conftest it never mentions. The assertion
    below is the part that actually enforces it: the key in play must be the fake one,
    so if either lock is removed this module goes red instead of quietly authenticating.
    """
    settings = Settings(
        _env_file=None,
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("wire-data"),
        registry_path=REGISTRY_PATH,
        llm_provider="anthropic",
        **{"ANTHROPIC_API_KEY": FAKE_API_KEY},
    )
    assert settings.anthropic_api_key == FAKE_API_KEY, (
        "this module is about to build a real AnthropicProvider with a key that is not "
        "the literal in this file. Either the field's validation alias changed or "
        "`.env` is being read -- in both cases a live credential is in play in a test"
    )
    return settings


@pytest.fixture(scope="module")
def wire_detector(wire_registry: EntityRegistry, wire_settings: Settings) -> Detector:
    return Detector(registry=wire_registry, settings=wire_settings)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def wire_run(
    wire_registry: EntityRegistry,
    wire_settings: Settings,
    wire_detector: Detector,
    tmp_path_factory: pytest.TempPathFactory,
) -> Any:
    """Drive all six cases once and hand every test the same captured evidence.

    Module-scoped because building the component graph and running six real pipelines
    is the expensive part, and every test below is a different question about the same
    six request bodies rather than a different run.
    """
    root = tmp_path_factory.mktemp("wire-db")
    audit = await AuditLogger.open(root / "audit.db")
    store = await EncryptedDocumentStore.open(wire_settings)
    sessions = SessionRegistry(wire_settings)
    vault = await SessionVault.open(root / "vault.db", sessions)
    capture = WireCapture()

    cases: list[dict[str, Any]] = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(capture.handler)) as http_client:
        provider = AnthropicProvider(wire_settings, http_client=http_client)
        orchestrator = PipelineOrchestrator(
            store=store,
            detector=wire_detector,
            engine=ObfuscationEngine(
                registry=wire_registry,
                vault=vault,
                session_registry=sessions,
                settings=wire_settings,
                audit=audit,
            ),
            injector=ContextInjector(),
            gate=EgressGate(
                vault=vault, detector=wire_detector, settings=wire_settings, audit=audit
            ),
            provider=provider,
            restorer=Restorer(vault=vault, settings=wire_settings, audit=audit),
            vault=vault,
            settings=wire_settings,
            audit=audit,
        )
        try:
            for kind, strategy, seed in WIRE_CASES:
                document = generator.generate(seed, kind)
                doc_id = await store.put(
                    USER_ID, f"{kind}-{seed}.txt", document.encode("utf-8"), DOC_CATEGORY[kind]
                )
                session_id, _expires = await sessions.create("wire-user")
                before = len(capture.bodies)
                await orchestrator.run(session_id, USER_ID, doc_id, PROMPT, strategy)
                cases.append(
                    {
                        "kind": kind,
                        "strategy": strategy,
                        "seed": seed,
                        "document": document,
                        "originals": vault.originals_for_session(session_id),
                        "bodies": capture.bodies[before:],
                    }
                )
        finally:
            await vault.close()
            await store.close()
            await audit.close()

    yield {"cases": cases, "capture": capture}


def test_the_wire_evidence_is_not_vacuous(wire_run: dict[str, Any]) -> None:
    """There is a request, it is not empty, and there was something to hide in it.

    Every assertion below is of the form *"the originals are not in the bytes"*, and
    that is satisfied for free by no originals, no bytes, or no request. Each of the
    three is a way this whole module could pass while measuring nothing, so each is
    ruled out here rather than assumed by the tests that depend on it.
    """
    cases = wire_run["cases"]
    assert len(cases) == len(WIRE_CASES) == 6, f"{len(cases)} cases ran, expected 6"
    assert {c["strategy"] for c in cases} == set(STRATEGIES), "a strategy was not exercised"
    assert {c["kind"] for c in cases} == set(KINDS), "a document category was not exercised"

    for case in cases:
        label = f"{case['kind']}/{case['strategy']}"
        assert case["bodies"], f"{label}: the pipeline ran and no HTTP request was made"
        assert case["originals"], (
            f"{label}: the vault holds no originals, so 'no original on the wire' is "
            "a statement about the empty set -- either detection found nothing in a "
            "generated fixture, or the session id is wrong"
        )
        for body in case["bodies"]:
            assert len(body) > 500, (
                f"{label}: a captured request body is {len(body)} bytes, which is too "
                "small to be a document -- the scan would be over the wrong string"
            )


def test_no_original_reaches_the_serialized_request_body(wire_run: dict[str, Any]) -> None:
    """**The claim.** No vaulted original appears in the literal outbound request.

    Scanned in all three forms -- raw bytes, decoded text, re-serialized JSON -- with
    the same scanners the 100-run harness uses, so a leak of a shape that harness knows
    about is a leak this one knows about too. :func:`find_in_bytes` is the byte limb and
    :func:`find_in_text` the text limb; they see different things (a value split across
    a JSON escape, versus a value word-bounded in ordinary prose) and both are applied.
    """
    findings: list[str] = []
    for case in wire_run["cases"]:
        label = f"{case['kind']}/{case['strategy']}"
        originals = case["originals"]
        for index, body in enumerate(case["bodies"]):
            decoded, reserialized = _body_views(body)
            for form, hits in (
                ("raw bytes", find_in_bytes(originals, body)),
                ("decoded", find_in_text(originals, decoded)),
                ("re-serialized", find_in_text(originals, reserialized)),
            ):
                findings.extend(
                    f"{label} request {index} [{form}]: {mask(value)}" for value in hits
                )

    assert not findings, (
        f"{len(findings)} original(s) are present in the literal bytes of an outbound "
        f"LLM request: {findings}. This is the network-inspection claim failing at the "
        "only place it is actually made -- the wire"
    )


def test_no_request_escapes_the_mock_transport(wire_run: dict[str, Any]) -> None:
    """No socket opened: every request the SDK made arrived at the handler.

    ``httpx.MockTransport`` cannot reach the network by construction, so this is not
    where the guarantee comes from -- it is where the guarantee is made *checkable*.
    The count of bodies the handler recorded must equal the number of requests the six
    runs produced, and every URL must be the API endpoint rather than something a
    redirect or a proxy setting rewrote.
    """
    capture = wire_run["capture"]
    per_case = sum(len(case["bodies"]) for case in wire_run["cases"])
    assert per_case == len(capture.bodies) >= len(WIRE_CASES), (
        f"{len(capture.bodies)} request(s) reached the transport but {per_case} were "
        "attributed to a case, so a request was made outside a run"
    )
    assert all(url.startswith("https://api.anthropic.com/v1/messages") for url in capture.urls), (
        f"a request went somewhere other than the Messages API: {capture.urls}"
    )


def test_the_request_body_is_the_obfuscated_document_not_the_original(
    wire_run: dict[str, Any],
) -> None:
    """The positive control: obfuscation demonstrably removed something from the wire.

    :func:`test_no_original_reaches_the_serialized_request_body` is a negative claim,
    and a negative claim is satisfied by an envelope that never carried the document.
    :func:`test_the_wire_evidence_is_not_vacuous` rules out an empty body by size; this
    rules out the subtler version -- a body of the right size that is not the document,
    or a document that had nothing in it to protect.

    The control is stated as a *difference* rather than as a shape: each vaulted
    original is asserted **present in the source document** (so there was something to
    find) and **absent from the request body** (so it was taken out). A pipeline that
    shipped an empty payload would fail the first half; a pipeline that shipped the raw
    document would fail the second, which is exactly what the sibling test measures.

    Deliberately not "the body matches a surrogate pattern". That would restate the
    surrogate grammar in a third place and would say nothing at all about
    pseudonymization, whose fakes look like ordinary text by design.
    """
    for case in wire_run["cases"]:
        label = f"{case['kind']}/{case['strategy']}"
        document, originals = case["document"], case["originals"]

        in_source = find_in_text(originals, document)
        assert len(in_source) >= 10, (
            f"{label}: only {len(in_source)} of {len(originals)} vaulted originals are "
            "findable in the source document, so 'they are not on the wire' is close to "
            "a statement about values that were never there"
        )

        for index, body in enumerate(case["bodies"]):
            sent = json.loads(body)
            assert sent["messages"], f"{label}: the request carries no user message"
            assert sent["messages"][0]["role"] == "user"
            assert sent.get("system"), f"{label}: the request carries no system prompt"
            text = sent["messages"][0]["content"]
            assert isinstance(text, str), f"{label}: the user message is not a string"
            assert len(text) > 200, (
                f"{label}: the user message is {len(text)} characters, not a document"
            )
            assert document not in text, (
                f"{label} request {index}: the raw source document is present verbatim "
                "in the outbound request body"
            )


# ---------------------------------------------------------------------------
# The gate binding: one document, two runs, and the wire read as the difference
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def gate_bound_run(
    wire_registry: EntityRegistry,
    wire_settings: Settings,
    wire_detector: Detector,
    tmp_path_factory: pytest.TempPathFactory,
) -> Any:
    """Run one planted document twice, differing only in what the vault knows.

    Both runs share a single ``doc_id``, so "the same document" is an identity rather
    than a claim about two ``generate`` calls agreeing. Between them the only change is
    one ``note_unrestorable`` -- the shipped, synchronous, cache-only path the engine
    uses for a redact-band detection that gets no token and no row, so the seeding is a
    real pipeline mechanism and not a test-only hole punched in the vault.

    Exceptions are *recorded* rather than allowed to propagate: which run raised, and
    with what reason code, is the measurement, and a fixture that died on it would turn
    a legible assertion failure into a collection error.
    """
    root = tmp_path_factory.mktemp("wire-gate-db")
    audit = await AuditLogger.open(root / "audit.db")
    store = await EncryptedDocumentStore.open(wire_settings)
    sessions = SessionRegistry(wire_settings)
    vault = await SessionVault.open(root / "vault.db", sessions)
    capture = WireCapture()

    document = generator.generate(GATE_CASE_SEED, GATE_CASE_KIND) + PLANT_TEMPLATE.format(
        UNKNOWN_SHAPE_VALUE
    )
    runs: dict[str, dict[str, Any]] = {}

    async with httpx.AsyncClient(transport=httpx.MockTransport(capture.handler)) as http_client:
        provider = AnthropicProvider(wire_settings, http_client=http_client)
        orchestrator = PipelineOrchestrator(
            store=store,
            detector=wire_detector,
            engine=ObfuscationEngine(
                registry=wire_registry,
                vault=vault,
                session_registry=sessions,
                settings=wire_settings,
                audit=audit,
            ),
            injector=ContextInjector(),
            gate=EgressGate(
                vault=vault, detector=wire_detector, settings=wire_settings, audit=audit
            ),
            provider=provider,
            restorer=Restorer(vault=vault, settings=wire_settings, audit=audit),
            vault=vault,
            settings=wire_settings,
            audit=audit,
        )
        try:
            doc_id = await store.put(
                USER_ID,
                f"plant-{GATE_CASE_SEED}.txt",
                document.encode("utf-8"),
                DOC_CATEGORY[GATE_CASE_KIND],
            )
            for name, seed_the_vault in (("control", False), ("gated", True)):
                session_id, _expires = await sessions.create(f"wire-{name}")
                if seed_the_vault:
                    vault.note_unrestorable(session_id, UNKNOWN_SHAPE_VALUE)
                before = len(capture.bodies)
                blocked: EgressBlockedError | None = None
                try:
                    await orchestrator.run(session_id, USER_ID, doc_id, PROMPT, GATE_CASE_STRATEGY)
                except EgressBlockedError as exc:
                    blocked = exc
                runs[name] = {
                    "session_id": session_id,
                    "bodies": capture.bodies[before:],
                    "originals": vault.originals_for_session(session_id),
                    "blocked": blocked,
                }
        finally:
            await vault.close()
            await store.close()
            await audit.close()

    yield {"document": document, "runs": runs}


def test_the_gate_bound_case_is_a_real_counterfactual(gate_bound_run: dict[str, Any]) -> None:
    """The control: with the gate uninterested, the plant is on the wire in bytes.

    Everything the two sibling tests below claim rests on this one, because "no original
    on the wire" is satisfied for free by a value that was never going to be there. The
    control run puts the *identical* document through the *identical* pipeline with only
    one thing missing -- the vault does not know the planted value -- and the request
    that results carries ``ZXQQ-KLM-RSTV-WYNP`` byte-for-byte.

    That is the measurement the six generated cases cannot make. On those, the engine
    replaced every value before the gate was consulted, so their green says nothing about
    whether the gate is alive. Here the engine demonstrably does *not* replace it: the
    registry has no recogniser for the shape, so obfuscation is not what keeps it off the
    wire in the gated run, and by elimination the gate is.

    Asserted both ways round on purpose. ``in body`` is the flat byte test, and
    :func:`find_in_bytes` is the same scanner the claim is stated in -- if the two ever
    disagree here, the scanner has a hole and every clean result in this file is worth
    less than it looks.
    """
    control = gate_bound_run["runs"]["control"]
    document = gate_bound_run["document"]
    needle = frozenset({UNKNOWN_SHAPE_VALUE})

    assert UNKNOWN_SHAPE_VALUE in document, (
        "the planted value is not in the source document, so both runs are about a value "
        "that was never in play"
    )
    assert control["blocked"] is None, (
        "the control run was blocked at the gate: "
        f"{control['blocked'].detail if control['blocked'] else None}. The control exists "
        "to show the payload carries the plant when the vault does not know it, and a "
        "blocked control means it never got to show that"
    )
    assert UNKNOWN_SHAPE_VALUE not in control["originals"], (
        "the control session's vault already holds the planted value, so the two runs no "
        "longer differ in the one respect this pair is built on"
    )
    assert control["bodies"], "the control run made no HTTP request, so there is no wire to read"

    carriers = [
        index
        for index, body in enumerate(control["bodies"])
        if UNKNOWN_SHAPE_VALUE.encode("utf-8") in body
    ]
    assert carriers, (
        f"the planted value is absent from all {len(control['bodies'])} control request "
        "body/bodies. Something other than the gate is removing it -- most likely a "
        "registry change that made the shape detectable -- and the pair below has stopped "
        "measuring the gate"
    )
    for index in carriers:
        body = control["bodies"][index]
        decoded, reserialized = _body_views(body)
        for form, hits in (
            ("raw bytes", find_in_bytes(needle, body)),
            ("decoded", find_in_text(needle, decoded)),
            ("re-serialized", find_in_text(needle, reserialized)),
        ):
            assert hits, (
                f"control request {index}: the planted value is in the raw bytes but the "
                f"[{form}] scanner does not report it. The scanner has a blind spot, and "
                "every clean result in this file was produced by that scanner"
            )


def test_the_vaulted_plant_never_reaches_the_wire(gate_bound_run: dict[str, Any]) -> None:
    """**The claim, bound to the gate.** The same document, with the vault told.

    One ``note_unrestorable`` is the whole difference from the control. The detector is
    still blind to the value, so pass 2 cannot see it; pass 3's independent recognisers
    do not know the shape either. Only pass 1 -- ``EgressGate._scan_originals``, the
    byte-exact scan of the payload against the session's originals -- can stop it.

    Scanned in the same three forms as
    :func:`test_no_original_reaches_the_serialized_request_body`, over every body the
    gated run produced. On a healthy gate that list is empty and this is a statement about
    nothing, which is why :func:`test_the_gate_is_what_kept_it_off_the_wire` asserts the
    emptiness separately and this one asserts the content. With pass 1 dead the list is
    not empty: a request appears carrying a value the vault holds, and this test reports
    it as bytes on the wire rather than as a call that should not have happened.
    """
    gated = gate_bound_run["runs"]["gated"]
    assert UNKNOWN_SHAPE_VALUE in gated["originals"], (
        "`note_unrestorable` did not put the planted value into the gated session's "
        "originals, so pass 1 was never given a needle and this test proves nothing"
    )

    findings: list[str] = []
    for index, body in enumerate(gated["bodies"]):
        decoded, reserialized = _body_views(body)
        for form, hits in (
            ("raw bytes", find_in_bytes(gated["originals"], body)),
            ("decoded", find_in_text(gated["originals"], decoded)),
            ("re-serialized", find_in_text(gated["originals"], reserialized)),
        ):
            findings.extend(f"gated request {index} [{form}]: {mask(value)}" for value in hits)

    assert not findings, (
        f"{len(findings)} vaulted original(s) are in the literal bytes of an outbound LLM "
        f"request: {findings}. The engine cannot have removed this value -- the detector "
        "does not recognise it -- so the egress gate was the only thing standing between "
        "it and the network, and it is on the network"
    )


def test_the_gate_is_what_kept_it_off_the_wire(gate_bound_run: dict[str, Any]) -> None:
    """The delta, stated at the transport: control sends, gated does not.

    Three things, and each rules out a different way the pair could look right while
    measuring nothing: the gated run raised, it raised for the **pass-1 reason** rather
    than for a detector re-hit that would have made the plant irrelevant, and no request
    reached the transport at all. The last is the network-inspection requirement in its
    strongest form -- there is no body to inspect, because there was no request.

    ``reason == "vault_original"`` is load-bearing. Blocking for ``detector_rescan`` or
    ``independent_pattern`` would mean some *other* limb caught the planted value, and
    the pair would then be evidence about that limb rather than about pass 1.
    """
    control, gated = gate_bound_run["runs"]["control"], gate_bound_run["runs"]["gated"]

    assert gated["blocked"] is not None, (
        "the gated run completed. A value the vault holds and the detector cannot see "
        f"went through the whole pipeline, and {len(gated['bodies'])} request(s) reached "
        "the transport -- pass 1 of the egress gate is not doing anything"
    )
    assert gated["blocked"].detail["reason"] == "vault_original", (
        f"the gated run was blocked for {gated['blocked'].detail['reason']!r}, not by "
        "pass 1. Some other limb is catching the plant, so this pair no longer measures "
        "the original-value scan"
    )
    assert not gated["bodies"], (
        f"{len(gated['bodies'])} request(s) reached the transport on a blocked run: the "
        "gate raised but the payload had already gone out, so the block is a report "
        "rather than a barrier"
    )
    assert control["bodies"] and not gated["bodies"], (
        f"the pair does not differ on the wire ({len(control['bodies'])} control "
        f"request(s), {len(gated['bodies'])} gated). The difference IS the measurement"
    )
