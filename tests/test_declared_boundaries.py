"""Two real disclosures the README declares rather than closes, pinned by measurement.

Both are **detection-side**: a value this pipeline never detects is never vaulted,
so it is not a value the egress gate could look for. That puts them in the same
family as the organisation-name limit already declared in the README's section 1 --
a different kind of thing from the four *scan* boundaries, which are about a vaulted
value the payload can still carry out.

Neither is fixable in code without contradicting the specification, so what this
module does is make each one a **number** rather than a sentence:

1. :func:`test_ordinary_dates_pass_through_outside_medical_documents` measures, at
   the provider boundary, how many distinct source dates reach the model in
   cleartext from each shipped fixture -- 153, 11, 4 and 0 -- and asserts the
   medical fixture's 0 in the same breath, so the day somebody widens ``DATE`` past
   ``only_in_doc_categories: [medical]`` the README's boundary text goes RED rather
   than quietly stale.
2. :func:`test_the_gate_cannot_backstop_a_name_the_detector_never_saw` pins the
   sharpest illustration in the project of a point the README otherwise makes
   abstractly: the gate is a second opinion on *obfuscation*, never on *detection*.

**The instrument is deliberately not the pipeline's own.** :data:`DATE_RE` is a
plain regex written here; nothing in this module imports ``daterules``, the
registry's ``DATE`` spec or any part of the detector's date handling to decide what
a date is. A checker that shares machinery with the checked code proves nothing, and
that lesson is the reason four other measurements on this page are re-derived rather
than trusted.

Both fixtures are run under **both** obfuscation strategies. That is the load-bearing
half of the date measurement: under pseudonymization a *detected* date is replaced by
a shifted, date-shaped fake, so a naive count of date-shaped substrings finds eight of
them in the medical payload and reads like a leak. Counting only the strings that are
**also in the source document** separates "never detected" from "detected and
shifted", and the surviving set is then byte-identical across the two strategies --
which is what "never detected" looks like and what "shifted" cannot look like.
"""

from __future__ import annotations

import base64
import re
import secrets
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from secure_context_pipeline.audit.logger import AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.llm.base import LLMResponse
from secure_context_pipeline.llm.mock_provider import MockProvider
from secure_context_pipeline.models import PipelineResult
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "entities.yaml"
FIXTURE_DIR = REPO_ROOT / "fixtures"

USER_ID = "boundary-user"
PROMPT = "Summarise this record and list the key parties, dates and figures."

STRATEGIES = ("tokenization", "pseudonymization")

#: What this module calls a date. Written here rather than imported, on purpose --
#: see the module docstring. It covers the three spellings the shipped fixtures use
#: and nothing else, which is why every assertion below also pins the count the
#: instrument finds in the *source*: a regex that silently stopped matching would
#: otherwise report a clean payload.
DATE_RE = re.compile(
    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b"
    r"|\b\d{4}-\d{2}-\d{2}\b"
    r"|\b(?:January|February|March|April|May|June|July|August|September|October"
    r"|November|December)\s+\d{1,2},\s+\d{4}\b"
)


def dates_in(text: str) -> set[str]:
    """The distinct date-shaped strings in ``text``."""
    return {match.group(0) for match in DATE_RE.finditer(text)}


class CapturingProvider:
    """The shipped mock, plus the exact bytes each call handed the provider.

    ``payloads`` is ``system + user`` -- the whole outbound body, not just the
    document half -- because the claim being measured is about what the provider
    sees, and the system prompt is part of that.
    """

    name = "mock"

    def __init__(self) -> None:
        self._inner = MockProvider()
        self.payloads: list[str] = []

    async def complete(self, system: str, user: str, *, model: str, timeout_s: float = 60.0) -> str:
        detailed = await self.complete_detailed(system, user, model=model, timeout_s=timeout_s)
        return detailed.text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        self.payloads.append(f"{system}\n{user}")
        return await self._inner.complete_detailed(system, user, model=model, timeout_s=timeout_s)


@dataclass
class Wired:
    """A complete pipeline with the real component graph and a capturing provider."""

    settings: Settings
    vault: SessionVault
    store: EncryptedDocumentStore
    audit: AuditLogger
    sessions: SessionRegistry
    provider: CapturingProvider
    orchestrator: PipelineOrchestrator

    async def close(self) -> None:
        await self.vault.close()
        await self.store.close()
        await self.audit.close()

    async def send(self, text: str, doc_category: str) -> tuple[PipelineResult, str, str]:
        """Upload ``text``, run it end to end, and return (result, payload, session_id)."""
        doc_id = await self.store.put(USER_ID, "doc.txt", text.encode("utf-8"), doc_category)
        session_id, _ = await self.sessions.create(USER_ID)
        result = await self.orchestrator.run(
            session_id, USER_ID, doc_id, PROMPT, self.settings.strategy
        )
        return result, self.provider.payloads[-1], session_id


@pytest.fixture(scope="module")
def registry() -> EntityRegistry:
    return load_registry(REGISTRY_PATH)


@pytest.fixture(scope="module")
def module_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("declared-boundaries-detector"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def detector(registry: EntityRegistry, module_settings: Settings) -> Detector:
    """Built ONCE: constructing a Detector is what loads spaCy."""
    return Detector(registry, module_settings)


WiredFactory = Callable[..., Any]


@pytest_asyncio.fixture
async def make_pipeline(
    registry: EntityRegistry, detector: Detector, tmp_path: Path
) -> AsyncIterator[WiredFactory]:
    built: list[Wired] = []
    counter = 0

    async def _make(strategy: str = "tokenization") -> Wired:
        nonlocal counter
        counter += 1
        root = tmp_path / f"p{counter}"
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
        sessions = SessionRegistry(settings)
        vault = await SessionVault.open(root / "vault.db", sessions)
        engine = ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=settings,
            audit=audit,
        )
        provider = CapturingProvider()
        wired = Wired(
            settings=settings,
            vault=vault,
            store=store,
            audit=audit,
            sessions=sessions,
            provider=provider,
            orchestrator=PipelineOrchestrator(
                store=store,
                detector=detector,
                engine=engine,
                injector=ContextInjector(),
                gate=EgressGate(
                    vault=vault, detector=detector, settings=settings, audit=audit
                ),
                provider=provider,
                restorer=Restorer(vault=vault, settings=settings, audit=audit),
                vault=vault,
                settings=settings,
                audit=audit,
            ),
        )
        built.append(wired)
        return wired

    try:
        yield _make
    finally:
        for wired in reversed(built):
            await wired.close()


# ---------------------------------------------------------------------------
# 1. Ordinary dates pass through in non-medical documents, at volume
# ---------------------------------------------------------------------------

#: fixture, doc category, dates the instrument finds in the SOURCE, dates that reach
#: the provider in cleartext. Measured on this repository at the provider boundary,
#: identical under both strategies. The medical row's 0 is the specification working:
#: build doc section 6.2 scopes ``DATE`` to ``only_in_doc_categories: [medical]``.
FIXTURE_DATE_COUNTS = [
    ("medical_note.txt", "medical", 8, 0),
    ("legal_memo.txt", "legal", 4, 4),
    ("financial_disclosure.txt", "financial", 12, 11),
    ("legal_brief_large.txt", "legal", 155, 153),
]


@pytest.mark.parametrize(
    ("fixture", "doc_category", "in_source", "in_payload"), FIXTURE_DATE_COUNTS
)
async def test_ordinary_dates_pass_through_outside_medical_documents(
    make_pipeline: WiredFactory,
    fixture: str,
    doc_category: str,
    in_source: int,
    in_payload: int,
) -> None:
    """A declared disclosure, measured: bare dates are PHI only inside a medical doc.

    Build doc section 6.2 defines ``DATE`` as
    ``{category: PHI, presidio: DATE_TIME, only_in_doc_categories: [medical]}`` and
    section 331 states the consequence in words -- "in ``medical`` docs, remaining
    dates map to ``DATE``; elsewhere bare dates pass through". So this is the
    specification being met, not a defect, and widening ``DATE`` in ``entities.yaml``
    would be inventing a requirement rather than satisfying one.

    It is pinned here because a reader of the README's boundary list would otherwise
    conclude the opposite. That list names four *scan* boundaries -- exotic splice
    shapes, a homoglyph, a short name whose separator was respelled -- and every one
    of them is a rare, adversarial single value. None of them prepares a reader for
    **153 dates in cleartext** on the largest shipped fixture, which is not exotic,
    not adversarial and not rare: it is the whole litigation chronology.

    The assertion is exact on both halves. The source count guards the instrument --
    a regex that stopped matching would report a clean payload and pass a test that
    only looked at the payload -- and the payload count is the disclosure. The medical
    row asserts the other direction with the same instrument, so this test cannot go
    green by the pipeline simply having stopped detecting anything.
    """
    source = (FIXTURE_DIR / fixture).read_text(encoding="utf-8")
    source_dates = dates_in(source)
    assert len(source_dates) == in_source, (
        f"the instrument found {len(source_dates)} dates in {fixture}, not {in_source}; "
        "either the fixture changed or DATE_RE did, and the payload count below is "
        "measuring something other than what the README says it measures"
    )

    surviving: dict[str, set[str]] = {}
    for strategy in STRATEGIES:
        pipeline: Wired = await make_pipeline(strategy)
        _, payload, _ = await pipeline.send(source, doc_category)
        # Intersected with the source on purpose: under pseudonymization a DETECTED
        # date is replaced by a shifted date-shaped fake, and counting date shapes
        # alone would score those eight fakes in the medical payload as a leak.
        surviving[strategy] = source_dates & dates_in(payload)

    for strategy, still_there in surviving.items():
        assert len(still_there) == in_payload, (
            f"{fixture} under {strategy}: {len(still_there)} of {in_source} source dates "
            f"reach the provider in cleartext, not the {in_payload} the README states. "
            "If this went DOWN, DATE was widened and the README's declared boundary is "
            "now wrong; if it went UP, a date that was being caught no longer is."
        )

    assert surviving["tokenization"] == surviving["pseudonymization"], (
        "the surviving dates differ between strategies, so at least one of them is "
        "being shifted rather than passed through, and the disclosure the README "
        "declares is not the one this test is measuring"
    )


async def test_a_bare_date_is_detected_in_a_medical_document_and_not_in_a_legal_one(
    make_pipeline: WiredFactory,
) -> None:
    """The same sentence, the same date, two doc categories -- the whole rule, isolated.

    The fixture measurement above is the volume; this is the mechanism, on one line
    of text, so a reader does not have to hold 155 dates in their head to see what
    ``only_in_doc_categories: [medical]`` does. It is also the tripwire that fires
    first: widening ``DATE`` turns this red on a two-line document, where the cause
    is unmistakable.
    """
    sentence = "The follow-up appointment was scheduled for 04/18/2024 with no changes.\n"
    date = "04/18/2024"
    assert dates_in(sentence) == {date}

    medical: Wired = await make_pipeline("tokenization")
    _, medical_payload, medical_session = await medical.send(sentence, "medical")
    assert date not in medical_payload, (
        "a bare date inside a medical document must be caught -- HIPAA treats "
        "individual-related dates as identifiers, and DATE exists for exactly this"
    )
    assert date in medical.vault.originals_for_session(medical_session), (
        "the date was masked but never vaulted, so the gate has no needle for it"
    )

    legal: Wired = await make_pipeline("tokenization")
    _, legal_payload, legal_session = await legal.send(sentence, "legal")
    assert date in legal_payload, (
        "a bare date outside a medical document now reaches the provider masked. "
        "That contradicts build doc section 6.2 and the README's declared boundary; "
        "if it is intended, both have to change with it"
    )
    assert date not in legal.vault.originals_for_session(legal_session), (
        "the date is in the vault but still on the wire, which is a gate failure "
        "rather than the declared detection boundary"
    )


# ---------------------------------------------------------------------------
# 2. The gate cannot backstop a detection miss
# ---------------------------------------------------------------------------

#: A chart header. ``{name}`` is the only thing that varies between the two runs
#: below, which is what makes the comparison a statement about the NAME rather than
#: about the frame it sits in.
CHART = "PATIENT CHART\nName: {name}   DOB: 03/12/1985\nMRN: 9224297\n"

#: spaCy's NER does not emit a PERSON for this name in the field-shaped frame above.
#: It does emit one for the same name in prose, and it does emit one for other names
#: in the same frame, so this is plain recall variance, not a rule.
MISSED_NAME = "Priyanka Raghunathan"

#: The control. Same frame, same DOB, same MRN -- detected, vaulted and masked.
FOUND_NAME = "Marguerite Vandenberg"


async def test_the_gate_cannot_backstop_a_name_the_detector_never_saw(
    make_pipeline: WiredFactory, detector: Detector
) -> None:
    """A name the detector misses reaches the provider, and no pass of the gate can help.

    This is the boundary the README states abstractly -- "the egress gate makes
    detection misses *safe*, not *invisible*" -- reproduced on the real component
    graph, because a person name is the case where "safe" runs out. The three passes
    each fail for their own reason, and none of the reasons is fixable by the gate:

    * **pass 1** scans the payload for the session's vaulted originals. A value the
      detector never saw was never vaulted, so the needle does not exist.
    * **pass 2** re-runs the *same* ``Detector`` over the payload. It is a second
      look, not a second opinion; every blind spot it had at detect time it has again.
    * **pass 3** is an independent recogniser set, and it matches **patterns**. A
      person name is not a pattern -- that is the whole reason NAME rides NER.

    The payload that comes out reads ``Name: Priyanka Raghunathan   DOB:
    [PII_DOB_...]``: the date of birth masked and the patient's own name in cleartext
    beside it. That juxtaposition is what makes this worth a named test rather than a
    sentence -- it is the shape a reviewer will point at, and the answer is that the
    gate was never the control that could catch it.

    Pinned rather than fixed because the fix is a better NER model (the README's
    section 7 names scispaCy as the highest-value next change), not a code change
    here. Adding an entity type or widening a pattern to cover one name is a product
    decision nobody has made, and it would not generalise to the next name anyway.

    **If this test goes red, that is good news and this file is wrong**: detection
    recall improved, and the README's declaration must be re-measured rather than
    the assertion relaxed.
    """
    document = CHART.format(name=MISSED_NAME)
    assert MISSED_NAME in document

    # Premise, on the real detector: the miss is in DETECTION, upstream of everything
    # the gate does. Asserted before the run so a failure here is not mistaken for a
    # gate failure below.
    hits = await detector.detect(document, "medical")
    assert [d.entity_type for d in hits if d.entity_type == "NAME"] == [], (
        f"the detector now finds a NAME in {document!r}; recall improved, so the "
        "README's declaration of this disclosure must be re-measured"
    )
    assert "MRN" in {d.entity_type for d in hits}, (
        "premise: the document must carry at least one detected entity, or the run "
        "proves nothing about the gate -- an empty vault is a different failure"
    )

    pipeline: Wired = await make_pipeline("tokenization")
    result, payload, session_id = await pipeline.send(document, "medical")

    # The vault never held it, which is the root cause and the reason no pass helps.
    originals = pipeline.vault.originals_for_session(session_id)
    assert originals, "premise: the session vaulted something, so pass 1 had work to do"
    assert MISSED_NAME not in originals, (
        "the name IS vaulted, so this is no longer a detection miss and the gate's "
        "failure to catch it would be a real defect rather than a declared boundary"
    )

    # And the gate released the run: three passes, no block, name on the wire.
    assert MISSED_NAME in payload, (
        "the undetected name did not reach the provider -- something other than "
        "detection is now removing it, and this test no longer measures what it claims"
    )
    assert "03/12/1985" not in payload, (
        "premise: the DOB beside the name IS masked. Without this the document is "
        "simply not being processed, and the name's survival says nothing"
    )
    assert result.stats["entities_detected"] > 0

    # The control: the identical frame with a name the detector does find. This is
    # what rules out "field-shaped documents are not obfuscated at all".
    control_document = CHART.format(name=FOUND_NAME)
    control: Wired = await make_pipeline("tokenization")
    _, control_payload, control_session = await control.send(control_document, "medical")
    assert FOUND_NAME not in control_payload, (
        "the control name is also on the wire, so the miss is not specific to the "
        "name and the README's framing of it as NER recall variance is wrong"
    )
    assert FOUND_NAME in control.vault.originals_for_session(control_session)

    # And the same missed name in ordinary prose IS found, which is the other half of
    # "recall variance": it is the field-shaped frame, not the string, that loses it.
    prose = f"{MISSED_NAME} was admitted overnight and remains stable.\n"
    prose_hits = await detector.detect(prose, "medical")
    assert MISSED_NAME in [d.text for d in prose_hits if d.entity_type == "NAME"], (
        "the name is missed in prose too, so it is not the frame; the README's "
        "explanation of this disclosure needs to change"
    )
