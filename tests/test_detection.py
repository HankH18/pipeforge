"""Detection tests (build doc section 10.2).

Presidio's NER is probabilistic, so assertions here are on entity **type** and
**offsets**, never on an exact float score. The one score assertion that exists
(the threshold-policy test) asserts a *band*, not a value.

No fixture in this file is real personal data: names, numbers and identifiers are
made up, and the SSNs are chosen to be non-placeholder shapes so Presidio's own
sample-value invalidation does not silently swallow them.
"""

from __future__ import annotations

import logging
import logging.config
import re
import time
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from typing import NamedTuple

import pytest

from secure_context_pipeline.audit.logger import AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.detection.detector import (
    CHUNK_OVERLAP_CHARS,
    PRESIDIO_LOGGER_NAME,
    DetectionInvariantError,
    Detector,
    _resolve_overlaps,
    _verify_offsets,
    chunk_text,
    get_analyzer,
    reset_analyzer_cache,
    warm_up,
)
from secure_context_pipeline.detection.recognizers import (
    GAZETTEER_SCORE,
    PATTERN_SCORE,
    class_hint_for,
    gazetteer_terms,
    load_gazetteer,
)
from secure_context_pipeline.detection.registry import (
    GAZETTEER_DIR,
    EntityRegistry,
    EntitySpec,
    load_registry,
)
from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.models import Detection
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault


def uncovered(text: str, detections: list[Detection], fragment: str) -> str:
    """The part of ``fragment`` that no detection covers -- i.e. what leaves in the clear.

    The detector's contract is not "label every entity" but "leave no detected
    original in the outbound text", so coverage, not entity type, is what the
    leak-shaped tests below assert on.
    """
    covered = bytearray(len(text))
    for detection in detections:
        for index in range(detection.start, detection.end):
            covered[index] = 1
    at = text.index(fragment)
    return "".join(text[i] for i in range(at, at + len(fragment)) if not covered[i])


@pytest.fixture
def detector(registry: EntityRegistry, settings: Settings) -> Detector:
    """Cheap to build -- the expensive AnalyzerEngine is a process-wide singleton."""
    return Detector(registry, settings)


def types_of(detections: list[Detection]) -> set[str]:
    return {d.entity_type for d in detections}


def spans_of(detections: list[Detection], entity_type: str) -> list[tuple[int, int]]:
    return [(d.start, d.end) for d in detections if d.entity_type == entity_type]


# ---------------------------------------------------------------------------
# 1. Per-entity coverage: every pattern- and gazetteer-backed registry entity
# ---------------------------------------------------------------------------
# (entity_type, doc_category, positive fixture, near-miss negative)
ENTITY_FIXTURES: list[tuple[str, str | None, str, str]] = [
    (
        # EMAIL is the one entity backed by both a built-in and a pattern. The
        # positive is deliberately an internal corporate domain: that is the case
        # Presidio's Public-Suffix-List validation drops, so the row fails if the
        # backstop pattern is removed. The near-miss has no dotted domain, which is
        # what carries the pattern's specificity.
        "EMAIL",
        None,
        "Reply to o.adeyemi@patientportal.internal for the chart.",
        "The service account is svc@localhost and has no mailbox.",
    ),
    (
        "MRN",
        "medical",
        "Chart note: MRN: 4471902 filed today.",
        "The medical record number is missing from this chart.",
    ),
    (
        "INSURANCE_ID",
        "medical",
        "Insurance member ID BCBS123456789 on file.",
        "Insurance member ID BCBS12345 on file.",
    ),
    (
        "LAB_RESULT",
        "medical",
        "Lab result: A1C 8.2 percent.",
        "Lab result pending for the metabolic panel.",
    ),
    (
        "DIAGNOSIS",
        "medical",
        "Assessment: patient presents with type 2 diabetes.",
        "Family history of diabetes was discussed at length.",
    ),
    (
        "MEDICATION",
        "medical",
        "Prescribed metformin 500 mg twice daily.",
        "Prescribed metforminol 500 mg twice daily.",
    ),
    (
        "ACCOUNT_NUMBER",
        "financial",
        "Bank account: 100200300400 debited today.",
        "Bank account balance is running low.",
    ),
    (
        "TAX_ID",
        "financial",
        "The taxpayer EIN 47-1234567 is on file.",
        "The taxpayer EIN 47-12345 is on file.",
    ),
    (
        "AMOUNT",
        "financial",
        "The payment of $4,250.00 cleared.",
        "The payment cleared without incident.",
    ),
    (
        "CASE_ID",
        "legal",
        "Case No. 1:23-cv-04567 was filed in March.",
        "The case was filed last week in court.",
    ),
    (
        "SETTLEMENT_TERM",
        "legal",
        "The settlement demand is $250,000 total.",
        "The settlement conference is scheduled.",
    ),
    (
        "PRIVILEGED_MARKER",
        "legal",
        "ATTORNEY-CLIENT PRIVILEGED AND CONFIDENTIAL - do not forward.",
        "Please keep this memo internal to the team.",
    ),
    (
        "CASE_STRATEGY",
        "legal",
        "Our litigation strategy is to delay the deposition.",
        "The litigation calendar is full this quarter.",
    ),
]


def test_fixture_table_covers_every_recognizer_backed_entity(registry: EntityRegistry) -> None:
    """A new pattern/gazetteer entity in entities.yaml must arrive with fixtures."""
    covered = {entity_type for entity_type, _, _, _ in ENTITY_FIXTURES}
    expected = set(registry.pattern_backed()) | set(registry.gazetteer_backed())
    assert covered == expected


@pytest.mark.parametrize(
    ("entity_type", "doc_category", "positive", "negative"),
    ENTITY_FIXTURES,
    ids=[row[0] for row in ENTITY_FIXTURES],
)
async def test_entity_positive_and_near_miss(
    detector: Detector,
    entity_type: str,
    doc_category: str | None,
    positive: str,
    negative: str,
) -> None:
    hits = await detector.detect(positive, doc_category)
    assert entity_type in types_of(hits), f"{entity_type} not detected in its positive fixture"

    misses = await detector.detect(negative, doc_category)
    assert entity_type not in types_of(misses), f"{entity_type} fired on its near-miss fixture"


# ---------------------------------------------------------------------------
# 1b. Recall on the spellings real documents actually use
# ---------------------------------------------------------------------------
# One fixture per entity proves the pattern compiles, not that it covers the field.
# Each row below is a spelling the build doc's own regexes miss, and a missed
# identifier is the one failure mode obfuscation cannot recover from -- it goes to
# the provider verbatim. Rows are grouped with the near-miss negatives that keep the
# widened patterns honest.
SPELLING_VARIANTS: list[tuple[str, str | None, str, str]] = [
    # (entity_type, doc_category, document, the substring that must be covered)
    ("MRN", "medical", "Patient chart MRN-4471902 reviewed by records.", "4471902"),
    ("MRN", "medical", "Medical Record Number: 4471902 was pulled from the chart.", "4471902"),
    ("MRN", "medical", "Chart MR# 4471902 reviewed at intake.", "4471902"),
    ("MRN", "medical", "chart note mrn 4471902 filed by the desk.", "4471902"),
    ("ACCOUNT_NUMBER", "financial", "Deposit to Account: 100200300400 cleared.", "100200300400"),
    ("ACCOUNT_NUMBER", "financial", "Bank Account No. 100200300400 was debited.", "100200300400"),
    ("ACCOUNT_NUMBER", "financial", "Account Number: 100200300400 on file.", "100200300400"),
    ("ACCOUNT_NUMBER", "financial", "Wire to Acct. 100200300400 at the bank.", "100200300400"),
    ("CASE_ID", "legal", "The court docket 1:23-cv-04567 lists the hearing.", "1:23-cv-04567"),
    ("CASE_ID", "legal", "Case No. 1:23-CV-04567 was filed in March.", "1:23-CV-04567"),
    ("CASE_ID", "legal", "See Docket No 2:19-cr-00881 for the indictment.", "2:19-cr-00881"),
    ("DOB", "medical", "Patient D.O.B. 03/12/1985 confirmed at intake.", "03/12/1985"),
    ("DOB", "legal", "Client D.O.B. 03/12/1985 per the retainer file.", "03/12/1985"),
    ("DOB", "medical", "Date of Birth: 03/12/1985 per the intake form.", "03/12/1985"),
    # "birthdate" is a separate context word rather than a spelling "birth" covers:
    # ``_has_context`` matches on word boundaries, and \bbirth\b does not match
    # inside "birthdate". The corpus row that uses it sits within 60 characters of
    # an earlier "D.O.B.", so the leading window claimed it from the neighbour and
    # deleting "birthdate" from the registry changed nothing. This row is isolated.
    ("DOB", None, "Applicant three: birthdate 17-Feb-1995 recorded.", "17-Feb-1995"),
]

# Prose that must stay clean: the widened patterns above all anchor on a long digit
# run, and these confirm the anchor is what carries the specificity.
VARIANT_NEGATIVES: list[tuple[str | None, str]] = [
    ("medical", "The medical record number is missing from this chart."),
    ("medical", "Dr. Mrachek reviewed 1234567 samples in the study cohort."),
    ("medical", "The mrna vaccine schedule was discussed with the patient."),
    ("financial", "Bank account balance is running low this quarter."),
    ("financial", "The accountant filed 12345678 forms electronically."),
    ("legal", "The meeting ran 1:30-2:00 and covered scheduling."),
    ("legal", "Sections 1:23 through 4:56 of the treatise were cited."),
    ("legal", "Exhibit 12-3 to 45-678 were entered into evidence."),
]


@pytest.mark.parametrize(
    ("entity_type", "doc_category", "text", "value"),
    SPELLING_VARIANTS,
    ids=[f"{row[0]}-{index}" for index, row in enumerate(SPELLING_VARIANTS)],
)
async def test_realistic_spelling_variants_are_detected(
    detector: Detector, entity_type: str, doc_category: str | None, text: str, value: str
) -> None:
    hits = await detector.detect(text, doc_category)
    assert entity_type in types_of(hits), f"{entity_type} missed in {text!r}"
    assert uncovered(text, hits, value) == "", f"{value!r} partly left in the clear"


@pytest.mark.parametrize(
    ("doc_category", "text"),
    VARIANT_NEGATIVES,
    ids=[f"neg-{index}" for index in range(len(VARIANT_NEGATIVES))],
)
async def test_widened_patterns_stay_off_clean_prose(
    detector: Detector, doc_category: str | None, text: str
) -> None:
    found = types_of(await detector.detect(text, doc_category))
    assert not found & {"MRN", "ACCOUNT_NUMBER", "CASE_ID", "DOB"}, f"false positive in {text!r}"


# Presidio's EmailRecognizer runs every candidate through `tldextract`, which
# resolves the domain against the Public Suffix List and drops anything it cannot
# resolve -- silently, at score zero. Enterprise documents are full of exactly
# those addresses. EMAIL is a build-doc-mandated entity, so a whole class of it
# going undetected is the most expensive single gap the corpus turned up.
EMAIL_DOMAINS_OFF_THE_PUBLIC_SUFFIX_LIST = [
    "j.okafor@northwind.internal",
    "oncall@ops.northwind.local",
    "d.iyer@northwind.corp",
    "svc-account@cluster.lan",
    "records@hospital.intranet",
]


@pytest.mark.parametrize("address", EMAIL_DOMAINS_OFF_THE_PUBLIC_SUFFIX_LIST)
async def test_internal_domain_email_is_detected(detector: Detector, address: str) -> None:
    text = f"Please copy {address} on the reply."
    hits = await detector.detect(text)
    assert "EMAIL" in types_of(hits), f"{address} was not detected at all"
    assert uncovered(text, hits, address) == "", f"{address} partly left in the clear"


@pytest.mark.parametrize(
    "text",
    [
        "The service account is svc@localhost and has no mailbox.",
        "Ping @records before the audit closes.",
        "Rates run 12@4 per unit for the quarter.",
        "Use the operator a@b for the reduction step.",
    ],
)
async def test_email_backstop_needs_a_dotted_domain(detector: Detector, text: str) -> None:
    """The dotted domain is what carries the pattern's specificity, not the ``@``."""
    assert "EMAIL" not in types_of(await detector.detect(text)), f"false positive in {text!r}"


# ---------------------------------------------------------------------------
# 1b-ii. `context:` has to be able to fire
# ---------------------------------------------------------------------------
async def test_context_words_boost_a_pattern_hit(detector: Detector, settings: Settings) -> None:
    """The mechanism itself: the same identifier scores higher with its context words.

    Worth pinning because the obvious reading of Presidio's API is wrong in a way
    that would make the whole ``context:`` column decorative. Custom recognizers
    are passed to ``analyze()`` as *ad-hoc* recognizers, and it is easy to assume
    ad-hoc recognizers bypass the context enhancer. They do not --
    ``AnalyzerEngine`` folds them into the same recognizer list it hands the
    enhancer -- and the difference is large: 0.70 bare against 1.00 with context,
    which is what lets a hand-written pattern outrank spaCy's flat 0.85.
    """
    bare = await detector.detect("Reference: MRN 4471902 appears below.", "medical")
    with_context = await detector.detect("Medical record chart: MRN 4471902.", "medical")

    bare_score = next(d.score for d in bare if d.entity_type == "MRN")
    boosted_score = next(d.score for d in with_context if d.entity_type == "MRN")
    assert boosted_score > bare_score
    assert bare_score >= settings.threshold_obfuscate, "a bare pattern hit must still obfuscate"


def test_every_context_word_can_boost_a_real_match(registry: EntityRegistry) -> None:
    """No configured context word may be one the enhancer can never match.

    ``LemmaContextAwareEnhancer`` runs ``configured_word in surrounding_word`` --
    a substring test, in that direction -- so an inflected word never fires: the
    lemma of "filed" is "file", and "filed" is not a substring of "file". Five
    words shipped in the build doc's own registry were inert this way, which cost
    the boost that keeps a ``CASE_ID`` pattern hit ahead of spaCy's DATE_TIME
    guess on the same span.

    The list searched is ``nlp_artifacts.keywords``, **not** ``.lemmas``:
    ``_extract_surrounding_words`` walks the preceding lemmas but keeps one only
    when it also appears in ``keywords``, which is the lemma list with spaCy's
    stop words removed. Asserting against ``.lemmas`` is the same shape of mistake
    as the one this test exists to catch -- a checker that models the mechanism
    one filter short of what the mechanism does. It passed "take", whose lemma is
    itself and which is nonetheless unreachable because spaCy classes it as a stop
    word, so ``MEDICATION`` shipped a context word that could never fire.

    Both lists come from the real analyzer's NLP engine, so this also fails if a
    model upgrade changes how a word is lemmatised or which words are stop words
    -- precisely when a context list silently stops working.
    """
    nlp_engine = get_analyzer().nlp_engine
    inert: list[str] = []
    for name, spec in registry.entities.items():
        # Only recognizer-level context reaches the enhancer. A `presidio:`-only
        # entity's context list is consumed by the detector's own word matcher,
        # which is a word-boundary regex over raw text and has no such filters.
        if not (spec.patterns or spec.gazetteer):
            continue
        for word in spec.context:
            artifacts = nlp_engine.process_text(word, "en")
            if not any(word.lower() in keyword.lower() for keyword in artifacts.keywords):
                inert.append(
                    f"{name}: {word!r} lemmatises to {artifacts.lemmas} and survives "
                    f"the stop-word filter as {artifacts.keywords}"
                )
    assert inert == [], "\n".join(["context words the enhancer can never match:", *inert])


# A `presidio:`-only entity's context list has exactly one consumer: the tie-break
# in ``_resolve_builtin`` between the registry entities claiming the same built-in.
# If only one entity claims that built-in and the entity does not set
# ``requires_context``, the tie-break has nothing to decide and the words are
# decorative -- present, plausible, and unable to change any outcome. ADDRESS is
# exactly that today and is spec-mandated, so it is held as a named exemption
# rather than deleted or silently tolerated.
CONTEXT_WITHOUT_A_CONSUMER = frozenset({"ADDRESS"})


def test_context_lists_have_a_live_consumer(registry: EntityRegistry) -> None:
    """A ``context:`` list some code path can never read is dead config that reads as coverage.

    Two consumers exist and they are not interchangeable. A ``patterns:`` or
    ``gazetteer:`` entity's list is attached to the recognizer and reaches
    Presidio's enhancer (substring match against stop-word-filtered lemmas). A
    ``presidio:``-only entity's list reaches only ``Detector._has_context``, a
    word-boundary regex over raw text used to pick between rival claimants -- so
    with one claimant and no ``requires_context`` it decides nothing at all.

    The exemption set is what stops this being a test that always passes: adding a
    second ``LOCATION`` claimant makes ADDRESS's list live and fails here, forcing
    the entry and its comment in ``entities.yaml`` to be revisited together.
    """
    aliases = registry.presidio_aliases()
    decorative: list[str] = []
    for name, spec in registry.entities.items():
        if not spec.context or spec.patterns or spec.gazetteer:
            continue
        claimants = aliases.get(spec.presidio or "", ())
        if len(claimants) == 1 and not spec.requires_context:
            decorative.append(f"{name}: sole claimant of {spec.presidio}, not requires_context")

    named = {line.split(":")[0] for line in decorative}
    assert named == CONTEXT_WITHOUT_A_CONSUMER, "\n".join(
        ["context lists whose only consumer cannot read them:", *decorative]
    )


async def test_a_trailing_context_word_still_claims_the_hit(detector: Detector) -> None:
    """``CONTEXT_WINDOW_AFTER`` is asymmetric on purpose; prove the trailing half works.

    Labels usually precede their value ("DOB: 1985-03-12") and the 60-character
    leading window carries almost every case, which is exactly why the 30-character
    trailing window can rot unnoticed: drop it to zero and every other test in this
    file still passes. The parenthetical-label form below is the shape it exists
    for, and without the trailing window ``DOB`` (which is ``requires_context``)
    finds no birth word, falls through to ``DATE``, and outside a medical document
    the date is dropped entirely -- an identifier in the clear.
    """
    text = "The value 03/12/1985 (date of birth) is on file."
    assert "DOB" in types_of(await detector.detect(text, None))
    assert uncovered(text, await detector.detect(text, None), "03/12/1985") == ""


async def test_settlement_term_matches_the_amount_before_the_word(detector: Detector) -> None:
    """SETTLEMENT_TERM's second pattern reads ``$X ... settlement``, not ``settle ... $X``.

    Both orders occur in practice and the registry ships a pattern for each, but
    every settlement fixture and every corpus row happens to use the forward order,
    so deleting the reverse pattern outright left the whole suite green. A pattern
    no test can distinguish from its own absence is not covered by anything.
    """
    text = "The $250,000 settlement was approved by the client this morning."
    hits = await detector.detect(text, "legal")
    assert "SETTLEMENT_TERM" in types_of(hits), "the reverse-order pattern did not fire"
    assert uncovered(text, hits, "$250,000") == ""


# ---------------------------------------------------------------------------
# 1c. Measured recall -- the number a reviewer will ask for
# ---------------------------------------------------------------------------
# The fixtures above prove each recognizer fires *somewhere*. They do not answer
# "what fraction of the sensitive values in a realistic document does this system
# find, and what does that recall cost in precision?" -- which is the binding
# question, and nothing downstream answers it for us. The egress gate is not the
# safety net for a *detector* miss: its first pass scans the outbound payload for
# values already in the vault, and its second pass re-runs this same detector, so a
# value this file never finds is invisible to both. The gate covers splice bugs and
# un-obfuscated echoes of things detection did find. Recall here is therefore the
# whole of the recall story. This section is the measurement, and it is a test
# rather than a report so the number cannot go stale.
#
# METHODOLOGY -- stated so the figure is checkable rather than asserted.
#
# Corpus. Two disjoint sets, all synthetic, no real personal data (section 16).
#   * RECALL_CORPUS: 42 documents / 1,672 words of ordinary domain prose -- notes,
#     discharge summaries, privileged memos, briefs, statements, wire
#     instructions, HR mail, support tickets -- spanning all four document
#     categories plus untagged. Every sensitive value is annotated inline as
#     `<<TYPE|value>>`; the markers are stripped before detection, so the
#     detector sees ordinary text and the annotation yields exact ground-truth
#     offsets. Annotations mark the *value*, not its label: "MRN: 4471902"
#     annotates only the digits, because "MRN:" is not sensitive.
#     Includes deliberately adversarial forms -- hard-wrapped strategy prose,
#     table layouts, OCR-style column spacing, internal-domain e-mail, five
#     spellings of a date of birth, identifiers written into running prose.
#   * CLEAN_CORPUS: 18 documents / 797 words of the same registers containing *no*
#     sensitive values at all -- policies, boilerplate, runbooks, minutes. Ground
#     truth is that a compliant detector returns nothing, so every returned span is
#     a false positive and the rate needs no adjudication.
#
# Precision is reported alongside recall, from two angles, because recall bought by
# widening a pattern until it fires on ordinary prose is not recall:
# test_clean_documents_produce_no_detections is the zero-tolerance measure, and
# test_over_detection_on_realistic_prose_stays_bounded caps the spans returned
# inside the annotated corpus that overlap nothing annotated.
#
# Counting rule. An annotated value counts as **covered** when some returned
# detection's span contains it end to end, whatever that detection is labelled.
# Coverage is the number that matters for the security claim: a covered value is
# obfuscated or redacted and does not reach the provider. A partially overlapping
# detection does *not* count -- the uncovered remainder is exactly the leak shape
# `uncovered()` exists to catch. A value counts as **typed** when a covering
# detection also carries the expected label or an accepted alias (LABEL_ALIASES:
# NAME/CLIENT_IDENTITY are the same PERSON hit under two document policies, as
# are DOB/DATE and AMOUNT/SETTLEMENT_TERM). Typed recall is a utility measure --
# the label picks the pseudonymization tier -- not a security one.
#
# What the numbers are NOT. This is a constructed corpus written by the same
# author as the patterns, so it measures whether the detector handles the shapes
# we know about. It is not a random sample of production documents and no
# recall figure from it transfers to one. Its value is as a regression floor and
# as an honest inventory of the residual misses, which
# test_residual_recall_misses_are_the_known_ones enumerates by name.
#
# Where the fixes came from also decides how far these numbers generalise. Most
# were driven by a property rather than by a corpus row -- Presidio's Public
# Suffix List validation, a tail quantifier that stops at a newline, a greedy
# quantifier that swallows the next analyte, context words the lemma enhancer can
# never match -- and each is guarded by its own test above, independently of this
# corpus. The gazetteer is the exception and the most corpus-fitted change: the
# diagnosis list roughly doubled, of which the corpus itself demanded three terms.
#
# Reproduce with:  pytest tests/test_detection.py -k recall -s

# (doc_id, doc_category, annotated text)
RECALL_CORPUS: list[tuple[str, str | None, str]] = [
# ---------------------------------------------------------------- medical
("med_progress_note", "medical", """
Hospitalist Progress Note

Patient: <<NAME|Marcus Delgado>>   DOB: <<DOB|04/18/1962>>   MRN: <<MRN|4471902>>
Insurance: <<INSURANCE_ID|BCBS7741029>>

Mr. <<NAME|Delgado>> is a 62-year-old man admitted overnight with worsening
<<DIAGNOSIS|shortness of breath>>. He has a known history of <<DIAGNOSIS|congestive heart failure>>
and <<DIAGNOSIS|type 2 diabetes>>. Home medications include <<MEDICATION|metformin>> 1000 mg twice
daily and <<MEDICATION|lisinopril>> 20 mg daily.

Labs this morning: <<LAB_RESULT|creatinine of 1.8>>, <<LAB_RESULT|HbA1c 8.2>>.
Reachable at <<PHONE|(415) 555-0182>> or <<EMAIL|m.delgado@example.com>>.
"""),
("med_discharge", "medical", """
DISCHARGE SUMMARY

Name: <<NAME|Priya Ramanathan>>
Date of birth: <<DOB|1985-03-12>>
Medical Record Number: Medical Record Number: <<MRN|3390188>>
Admission date <<DATE|2024-02-04>>, discharge date <<DATE|2024-02-09>>.

Ms. <<NAME|Ramanathan>> was admitted for <<DIAGNOSIS|pneumonia>> complicated by
<<DIAGNOSIS|sepsis>>. She was treated with intravenous <<MEDICATION|ceftriaxone>> and
transitioned to oral <<MEDICATION|amoxicillin>> on day three. Discharge <<LAB_RESULT|WBC 9.1>>.

Follow-up has been arranged with her primary care physician Dr. <<NAME|Alan Whitfield>>.
Questions may be directed to <<PHONE|206-555-0147>>.
"""),
("med_referral_letter", "medical", """
Dear Dr. <<NAME|Chen>>,

Thank you for seeing <<NAME|Robert Ellison>> in your clinic. His medical record number is
MRN-<<MRN|8820314>> and he was born on <<DOB|22 November 1957>>. He presents with
poorly controlled <<DIAGNOSIS|hypertension>> despite <<MEDICATION|amlodipine>> 10 mg daily.

His social security number on file is <<SSN|412-88-7391>>. Please reach my office at
<<PHONE|+1 617-555-0113>>; my direct email is <<EMAIL|s.okafor@clinicmail.example>>.

Sincerely,
Dr. <<NAME|Samuel Okafor>>
"""),
("med_nursing_note", "medical", """
Nursing shift note. <<DATE|03/14/2024>> 22:15.

Patient <<NAME|Yolanda Briggs>> (mrn <<MRN|6612045>>) rested comfortably. She reports her
<<DIAGNOSIS|migraine>> has improved after <<MEDICATION|sumatriptan>> 50 mg. Blood glucose stable.
Daughter <<NAME|Tanya Briggs>> called from <<PHONE|(312) 555-0198>> asking about visiting hours.
Patient's d.o.b. is <<DOB|09/30/1948>>.
"""),
("med_telephone_encounter", "medical", """
Telephone encounter documented by triage.

Caller: <<NAME|Ethan Kowalski>>, DOB <<DOB|7/2/1990>>, chart MR # <<MRN|2201883>>.
He states his <<DIAGNOSIS|asthma>> is flaring and his rescue inhaler is empty. Current
prescriptions: <<MEDICATION|albuterol>>, <<MEDICATION|fluticasone>>. Callback number
<<PHONE|503-555-0166>>. He also asked whether his insurance ID <<INSURANCE_ID|UHC44120933>>
is still active.
"""),
("med_op_report", "medical", """
Operative report.

Surgeon: Dr. <<NAME|Helen Vasquez>>. Patient: <<NAME|Grant Sobieski>>, MRN MRN: <<MRN|7719204>>,
date of surgery <<DATE|11/02/2023>>. Preoperative diagnosis <<DIAGNOSIS|appendicitis>>.
Postoperative course uncomplicated. Discharged on <<MEDICATION|ibuprofen>> as needed.
Patient date of birth <<DOB|1979-06-21>>.
"""),
("med_lab_followup", "medical", """
Lab follow-up letter.

<<NAME|Denise Achebe>> — record Medical Record No. <<MRN|4408812>> — your recent results are back.
Your <<LAB_RESULT|LDL is 162>> and your <<LAB_RESULT|A1C came back at 7.4>>, which is consistent
with <<DIAGNOSIS|type 2 diabetes>>. We would like to start <<MEDICATION|metformin>>.
Please call <<PHONE|(602) 555-0121>> or write to <<EMAIL|labs@northside.example.org>>.
Born on <<DOB|March 3, 1971>>.
"""),
("med_psych_intake", "medical", """
Behavioral health intake.

Client <<NAME|Aaron Whitlock>>, born <<DOB|12/08/1994>>, MRN MRN#<<MRN|5590231>>.
Reports symptoms consistent with <<DIAGNOSIS|major depressive disorder>> and
<<DIAGNOSIS|generalized anxiety disorder>>. Trialed <<MEDICATION|sertraline>> 50 mg without
benefit; now on <<MEDICATION|bupropion>>. Emergency contact <<NAME|Maria Whitlock>>,
<<PHONE|(719) 555-0104>>. Email <<EMAIL|awhitlock@mailer.example>>.
"""),
("med_peds_note", "medical", """
Pediatric well-child visit on <<DATE|05/19/2024>>.

Patient <<NAME|Sofia Marchetti>>, date of birth <<DOB|05/19/2019>>, MRN mrn: <<MRN|1120994>>.
Mother <<NAME|Elena Marchetti>> reports intermittent <<DIAGNOSIS|eczema>>. Continue
<<MEDICATION|hydrocortisone>> cream. Immunizations up to date. Contact <<PHONE|847-555-0173>>.
"""),
("med_oncology", "medical", """
Oncology consult note.

<<NAME|Harold Nkemdirim>>, MRN MRN <<MRN|9908123>>, DOB <<DOB|02/14/1955>>, referred for newly
diagnosed <<DIAGNOSIS|breast cancer>>. He is also managed for <<DIAGNOSIS|hypothyroidism>>
on <<MEDICATION|levothyroxine>>. Baseline <<LAB_RESULT|creatinine 0.9>>. SSN on the intake form
was recorded as <<SSN|287-44-9012>>. Insurance <<INSURANCE_ID|AET1029384756>>.
"""),
# ---------------------------------------------------------------- legal
("legal_memo", "legal", """
<<PRIVILEGED_MARKER|PRIVILEGED AND CONFIDENTIAL>> — <<PRIVILEGED_MARKER|ATTORNEY-CLIENT>> COMMUNICATION

To: File
Re: <<CLIENT_IDENTITY|Angela Rosenthal>> v. Meridian Logistics, Case No. <<CASE_ID|1:23-cv-04567>>

<<CASE_STRATEGY|Our litigation strategy remains to press the causation defence through expert discovery>>.
<<CASE_STRATEGY|We should to depose their economist before the mediation window closes>>.

Opposing counsel is <<CLIENT_IDENTITY|Dev Ramaswamy>> of Halloran & Pike, reachable at
<<EMAIL|dramaswamy@halloranpike.example>>. Our client's date of birth is <<DOB|08/09/1978>>
and her direct line is <<PHONE|(646) 555-0129>>.
"""),
("legal_brief", "legal", """
Plaintiff's opposition brief, filed in <<CASE_ID|1:23-cv-04567>>.

The related matter, <<CASE_ID|22-CV-01188>>, was consolidated below.
<<CLIENT_IDENTITY|Angela Rosenthal>> testified that she signed the release on
March 4, 2022. <<CASE_STRATEGY|We recommend to move for partial summary judgment on the
release issue>>.

This document is <<PRIVILEGED_MARKER|work product>> and is not subject to disclosure.
"""),
("legal_engagement", "legal", """
Engagement letter.

Dear Mr. <<CLIENT_IDENTITY|Okonkwo>>,

This letter confirms our representation of you in Docket No. <<CASE_ID|3:24-cv-00912>>.
Our records show your date of birth as born <<DOB|15 January 1969>> and your taxpayer
identification number as <<TAX_ID|84-1129055>>. Retainer funds should be wired to
account number <<ACCOUNT_NUMBER|4400291837>>.

Please confirm receipt by email to <<EMAIL|billing@vantagelaw.example>> or by phone at
<<PHONE|(213) 555-0155>>.

Very truly yours,
<<CLIENT_IDENTITY|Naomi Vantage>>
"""),
("legal_deposition_summary", "legal", """
Attorney <<PRIVILEGED_MARKER|work product>>.

Deposition summary — <<CLIENT_IDENTITY|Terrence Vaughn>>, taken 09/12/2023.

The witness conceded knowledge of the inspection report. <<CASE_STRATEGY|Our trial posture should
therefore shift toward contributory negligence rather than notice>>. Related docket
<<CASE_ID|2:22-cv-03310>>. <<CASE_STRATEGY|We intend to serve a supplemental expert disclosure before
the cutoff>>.

<<SETTLEMENT_TERM|settlement demand of $1,250,000>> remains outstanding.
"""),
("legal_settlement_letter", "legal", """
<<PRIVILEGED_MARKER|Privileged & Confidential>>

Re: <<CLIENT_IDENTITY|Bianca Ferreira>>, Case No. <<CASE_ID|4:21-cv-00877>>

Counsel,

Our client will consider a <<SETTLEMENT_TERM|settlement in the amount of $475,000>>, inclusive of
fees. <<CASE_STRATEGY|We are prepared to proceed to trial if that figure is not met>>.
Ms. <<CLIENT_IDENTITY|Ferreira>> may be reached through this office at <<PHONE|305-555-0188>>.
"""),
("legal_client_intake", "legal", """
New client intake form.

Client name: <<CLIENT_IDENTITY|Gregory Halstead>>
Date of birth: <<DOB|11/27/1980>>
SSN: <<SSN|501-22-8834>>
Email: <<EMAIL|g.halstead@personalmail.example>>
Phone: <<PHONE|(770) 555-0192>>
Matter: <<CASE_ID|1:24-cv-02201>>

Retainer received; deposit to acct <<ACCOUNT_NUMBER|883012994571>>.
"""),
("legal_discovery_email", "legal", """
From: <<CLIENT_IDENTITY|Isabel Contreras>> <<<EMAIL|icontreras@vantagelaw.example>>>
Subject: discovery status, Docket No. <<CASE_ID|5:23-cv-07781>>

<<PRIVILEGED_MARKER|attorney client>> communication — do not forward.

<<CASE_STRATEGY|We plan to withhold the internal audit memo under the work-product doctrine>>.
The consolidated action <<CASE_ID|21-CIV-04490>> is on the same schedule.
"""),
# ---------------------------------------------------------------- financial
("fin_disclosure", "financial", """
Financial disclosure statement.

Name: <<NAME|Rachel Osei>>
Social Security Number: <<SSN|332-11-7845>>
Date of birth: <<DOB|06/04/1983>>
Address: <<ADDRESS|Cleveland>>, Ohio

Primary checking Account No. <<ACCOUNT_NUMBER|100029384756>> held at Fifth Third.
Employer identification number <<TAX_ID|34-9182736>>.
Transactions: deposit of <<AMOUNT|$12,400.00>> and a withdrawal of <<AMOUNT|$3,275.50>>.
Contact <<EMAIL|rosei@example.net>> or <<PHONE|216-555-0139>>.
"""),
("fin_wire_instructions", "financial", """
Wire instructions.

Beneficiary: <<NAME|Thomas Iverson>>
Beneficiary account: Acct. <<ACCOUNT_NUMBER|5540229183>>
Bank routing details on file.
Payment amount <<AMOUNT|$88,000>>.
Taxpayer ID <<TAX_ID|12-3456789>>.
Questions to <<EMAIL|treasury@bridgeport.example>> or <<PHONE|(917) 555-0107>>.
"""),
("fin_loan_application", "financial", """
Consumer loan application.

Applicant <<NAME|Camila Restrepo>>, born <<DOB|1991-09-17>>, SSN <<SSN|647-30-2219>>.
Existing balance on account #<<ACCOUNT_NUMBER|77012938465>> is <<AMOUNT|$4,912.33>>.
Requested loan amount <<AMOUNT|$25,000>>. Home address is in <<ADDRESS|Denver>>.
Best contact: <<PHONE|720-555-0116>>, <<EMAIL|c.restrepo@mailbox.example>>.
"""),
("fin_kyc_review", "financial", """
KYC periodic review.

Customer <<NAME|Abdul Rahman Siddiqui>> (DOB <<DOB|03/22/1975>>) maintains
a/c <<ACCOUNT_NUMBER|9910238475612>>. Source of funds documented. Tax identification number
<<TAX_ID|91-2837465>>. A transaction of <<AMOUNT|$150,000>> on the account was reviewed and cleared.
Registered email <<EMAIL|ar.siddiqui@corpmail.example>>.
"""),
("fin_statement", "financial", """
Monthly statement summary.

Account holder <<NAME|Lucia Bertrand>>. Account Number: <<ACCOUNT_NUMBER|3300192847>>.
Opening balance <<AMOUNT|$18,220.14>>. Total deposits <<AMOUNT|$6,400.00>>. Total withdrawals
<<AMOUNT|$2,118.76>>. Closing balance <<AMOUNT|$22,501.38>>.
For disputes call <<PHONE|(888) 555-0164>> or email <<EMAIL|disputes@bankcorp.example>>.
"""),
("fin_fraud_report", "financial", """
Suspected fraud report.

Reporting customer: <<NAME|Devon Pritchard>>, SSN <<SSN|713-55-0290>>, DOB <<DOB|10/05/1966>>.
Unauthorized payment of <<AMOUNT|$2,340.00>> posted to acct: <<ACCOUNT_NUMBER|4400882913>>.
Customer lives in <<ADDRESS|Sacramento>>. Callback <<PHONE|916-555-0122>>.
"""),
# ---------------------------------------------------------------- general
("gen_hr_email", None, """
From: <<NAME|Karen Iwuchukwu>> <<<EMAIL|k.iwuchukwu@company.example>>>
Subject: onboarding paperwork

Hi team — our new analyst <<NAME|Peter Nakagawa>> starts Monday. His personal email is
<<EMAIL|pnakagawa@personal.example>> and his mobile is <<PHONE|(408) 555-0198>>. Payroll needs his
social security number, which he provided as <<SSN|559-44-1023>>. He was born
on <<DOB|14 July 1996>>.
"""),
("gen_support_ticket", None, """
Support ticket #44210.

Reporter <<NAME|Alice Bergström>> writes: "I cannot log in." Account email is
<<EMAIL|alice.bergstrom@customer.example>>; phone on file is <<PHONE|+1 (206) 555-0143>>.
Verified identity using the last four of her SSN, full value <<SSN|602-19-4471>>, and her
date of birth <<DOB|1988-12-01>>.
"""),
("gen_insurance_letter", None, """
Dear Mr. <<NAME|Hollingsworth>>,

We have received your claim. Your policy member ID is <<INSURANCE_ID|CIG9081726354>> and the claim
was filed under <<CASE_ID|24-ARB-00912>>. Please confirm your birth date, which we show as
<<DOB|02/29/1988>>.

Reply to <<EMAIL|claims@assurity.example>> or call <<PHONE|1-800-555-0177>>.
"""),
("gen_background_check", None, """
Background check request.

Subject: <<NAME|Malik Johnson>>
SSN: <<SSN|188-33-9021>>
DOB: <<DOB|07/19/1992>>
Last known residence: street address in <<ADDRESS|Baltimore>>
Contact phone <<PHONE|410-555-0159>>, email <<EMAIL|mjohnson@webmail.example>>.
Prior civil matter: <<CASE_ID|1:19-cv-00443>>.
"""),
("gen_school_record", None, """
Student services memo.

<<NAME|Hannah Lindqvist>>, born birth date <<DOB|04/02/2006>>, requires accommodations.
Guardian <<NAME|Erik Lindqvist>> can be reached at <<PHONE|(651) 555-0134>> or
<<EMAIL|erik.lindqvist@family.example>>. The guardian's SSN <<SSN|423-70-1188>> is on the FAFSA.
"""),
("adv_wrapped_strategy", "legal", """
<<PRIVILEGED_MARKER|Privileged and Confidential>>

Re: <<CLIENT_IDENTITY|Nadia Petrova>>, Case No. <<CASE_ID|1:24-cv-08812>>

<<CASE_STRATEGY|Our settlement posture is to hold at four hundred thousand until after the
Daubert ruling, then reassess based on how the court treats their causation expert>>.

<<CASE_STRATEGY|We are prepared to concede the notice issue if it buys us a favourable
scheduling order on the remaining claims>>.
"""),
("adv_table_layout", "medical", """
Patient summary table

Field                  Value
Name                   <<NAME|Oluwaseun Adeyemi>>
Date of Birth          <<DOB|1968-11-04>>
MRN                    <<MRN|5512078>>
Insurance              <<INSURANCE_ID|HUM998877665>>
Primary diagnosis      <<DIAGNOSIS|atrial fibrillation>>
Secondary diagnosis    <<DIAGNOSIS|chronic kidney disease>>
Current medication     <<MEDICATION|warfarin>>
Telephone              <<PHONE|(504) 555-0126>>
Email                  <<EMAIL|o.adeyemi@patientportal.internal>>
"""),
("adv_internal_domains", None, """
Directory extract for the migration.

Primary contact <<NAME|Ingrid Solberg>> at <<EMAIL|i.solberg@northwind.internal>>.
Backup contact <<NAME|Devendra Iyer>> at <<EMAIL|d.iyer@northwind.corp>>.
On-call pager routes to <<EMAIL|oncall@ops.northwind.local>> and the escalation line is
<<PHONE|(425) 555-0111>>.
"""),
("adv_ocr_spacing", "medical", """
Scanned chart page, OCR output.

PATIENT   <<NAME|Bernard Kowalczyk>>
D.O.B.    <<DOB|02/17/1951>>
MRN       <<MRN|7740219>>

Assessment: worsening <<DIAGNOSIS|copd>> with superimposed <<DIAGNOSIS|bronchitis>>.
Plan: continue <<MEDICATION|tiotropium>>, add <<MEDICATION|prednisone>> taper.
Lab: <<LAB_RESULT|eGFR 48>>. Contact daughter at <<PHONE|814-555-0170>>.
"""),
("adv_prose_ids", "legal", """
The dispute arises out of the consolidated proceeding filed in <<CASE_ID|3:21-cv-00994>>,
which the parties have referred to throughout as the Harborline matter. Counsel for
<<CLIENT_IDENTITY|Vincent Aldridge>> entered an appearance shortly after the transfer order.
A parallel arbitration, <<CASE_ID|21-AAA-00317>>, remains stayed.
"""),
("adv_narrative_med", "medical", """
The patient, <<NAME|Farida Haddad>>, is a pleasant woman born <<DOB|3 August 1977>> who was last
seen in clinic six weeks ago. Her chart, medical record number <<MRN|6690135>>, documents a long
history of <<DIAGNOSIS|rheumatoid arthritis>> managed with <<MEDICATION|methotrexate>>. She now
reports new <<DIAGNOSIS|shortness of breath>> on exertion. We checked labs and her
<<LAB_RESULT|creatinine was 1.1>>, unchanged. She can be reached at <<PHONE|(913) 555-0148>>.
"""),
("adv_multi_mention", "medical", """
Consult note.

<<NAME|Gustavo Marroquin>> was seen today. Mr. <<NAME|Marroquin>> reports adherence to therapy.
Since <<NAME|Gustavo Marroquin>> was last admitted, his <<DIAGNOSIS|congestive heart failure>>
has been stable. MRN <<MRN|4419023>>, DOB <<DOB|12/25/1959>>.
"""),
("adv_financial_prose", "financial", """
The customer, <<NAME|Wendy Castellanos>>, called to dispute a charge. She confirmed her account,
ending in the digits we hold on file as <<ACCOUNT_NUMBER|account no. 6602119384>>, and verified
her identity with her social security number <<SSN|305-77-1194>> and her date of birth,
<<DOB|1 May 1984>>. The disputed transaction was for <<AMOUNT|$1,899.99>>. Her employer's tax
identification number, <<TAX_ID|45-6677889>>, was also on the file.
"""),
("adv_uppercase_ids", "legal", """
CAPTION: <<CLIENT_IDENTITY|Marcus Thorne>> v. Delta Freight
DOCKET: <<CASE_ID|2:23-CV-05510>>
RELATED: <<CASE_ID|20-CIV-00881>>

<<PRIVILEGED_MARKER|ATTORNEY WORK PRODUCT>> — internal only.
"""),
("adv_dob_formats", None, """
Verification worksheet.

Applicant one: <<NAME|Georgina Ashworth>>, born <<DOB|Jan 9, 1973>>.
Applicant two: <<NAME|Hiroshi Tanaka>>, D.O.B. <<DOB|1980/04/23>>.
Applicant three: <<NAME|Nkechi Obi>>, birthdate <<DOB|17-Feb-1995>>.
All three provided a phone number: <<PHONE|(559) 555-0181>>.
"""),
("adv_email_variants", None, """
Contact sheet.

<<EMAIL|first.last@acme-holdings.com>>, <<EMAIL|j_smith+billing@sub.domain.co.uk>>,
<<EMAIL|helpdesk@it.university.edu>>, <<EMAIL|noreply@service.example.internal>>,
<<EMAIL|Q.Zhao@lab.research.local>>.
Escalation to <<NAME|Priya Venkatesan>> on <<PHONE|+1 (781) 555-0190>>.
"""),
("adv_legal_paraphrase", "legal", """
<<PRIVILEGED_MARKER|Privileged & Confidential>>

Memorandum regarding <<CASE_ID|1:22-cv-06623>>.

<<CASE_STRATEGY|Our negotiation approach should be to open low and signal flexibility only after
their expert report lands>>. Client <<CLIENT_IDENTITY|Sandra Beauchamp>> has authorised a
<<SETTLEMENT_TERM|settlement range up to $900,000>>.
"""),
("adv_mixed_category", "financial", """
Account maintenance request.

Customer <<NAME|Elias Mwangi>>, SSN <<SSN|221-09-4478>>, DOB <<DOB|08/31/1970>>.
Close <<ACCOUNT_NUMBER|acct # 8801293746>> and transfer the balance of <<AMOUNT|$47,300.12>> to
the new account. Mailing address is in <<ADDRESS|Portland>>. Confirmation to
<<EMAIL|e.mwangi@banking.internal>> and <<PHONE|503-555-0136>>.
"""),
("adv_dense_clinical", "medical", """
Problem list and reconciliation for <<NAME|Josefina Alvarez>>, MRN <<MRN|3301827>>, DOB
<<DOB|06/11/1946>>.

Problems: <<DIAGNOSIS|hypertension>>, <<DIAGNOSIS|osteoarthritis>>, <<DIAGNOSIS|hyperlipidemia>>,
<<DIAGNOSIS|gerd>>, <<DIAGNOSIS|anemia>>.
Medications: <<MEDICATION|lisinopril>>, <<MEDICATION|atorvastatin>>, <<MEDICATION|omeprazole>>,
<<MEDICATION|acetaminophen>>, <<MEDICATION|ferrous sulfate>>.
Recent labs: <<LAB_RESULT|HDL 38>>, <<LAB_RESULT|LDL 141>>.
"""),
]

# Same registers, zero sensitive values: ground truth is "return nothing".
CLEAN_CORPUS: list[tuple[str, str | None, str]] = [
("clean_med_policy", "medical", """
Infection control policy update. All clinical staff must perform hand hygiene before and after
every patient encounter. Alcohol-based rub is preferred unless hands are visibly soiled, in which
case soap and water are required. Isolation carts should be restocked each shift. Questions about
this policy go to the unit educator during regular rounds.
"""),
("clean_med_quality", "medical", """
Quality committee minutes. The committee reviewed readmission trends over the last twelve hours of
reporting and agreed the sample was too small to act on. A revised dashboard will be circulated
before the next meeting. Staffing ratios were discussed briefly. No action items were assigned.
"""),
("clean_legal_policy", "legal", """
Firm document retention policy. Matter files are retained for seven years after closure. Physical
storage requests must be submitted through the records team. Electronic files are backed up nightly
and replicated offsite. Departing personnel must return all firm property before their final day.
"""),
("clean_legal_cle", "legal", """
Continuing legal education announcement. This session covers recent developments in appellate
procedure, including changes to briefing schedules and word limits. Attendance qualifies for one
credit hour. Registration closes at the end of the month.
"""),
("clean_fin_policy", "financial", """
Expense reimbursement policy. Receipts must be submitted within thirty days of the expense being
incurred. Meals during travel are reimbursed at the standard per diem rate. Personal expenses are
never reimbursable. Approvals route to the department manager and then to finance.
"""),
("clean_fin_notice", "financial", """
Service notice. Online banking will be unavailable during a scheduled maintenance window this
weekend. Card transactions and cash withdrawals are unaffected. We apologise for the inconvenience
and appreciate your patience while we complete the upgrade.
"""),
("clean_gen_readme", None, """
Deployment runbook. Build the container, run the migration step, then restart the workers one at a
time. Confirm the health endpoint returns success before moving to the next worker. Roll back by
redeploying the previous tag. Alerting is configured to page on sustained error rates.
"""),
("clean_gen_newsletter", None, """
Company newsletter. The engineering team shipped a redesigned onboarding flow this quarter and
reduced median setup time considerably. Support volume dropped as a result. Next quarter the focus
moves to reliability work and paying down accumulated technical debt.
"""),
("clean_med_consent", "medical", """
General consent for treatment. By signing this form the person named on the accompanying cover
sheet consents to routine examination and to treatment considered necessary by the attending
clinician. Consent may be withdrawn at any time. Separate consent is required for procedures
involving sedation.
"""),
("clean_legal_engagement_terms", "legal", """
Standard terms of engagement. Fees are billed monthly in arrears. Disbursements are charged at
cost. Either party may terminate the engagement on written notice. Any dispute about a bill is
handled first through the firm's internal review process before any external process is started.
"""),
("clean_fin_disclosure_boiler", "financial", """
Important information about this document. Past performance is not a reliable indicator of future
results. The value of an investment may fall as well as rise. This material is provided for
information only and does not constitute advice. Please read the full terms before deciding.
"""),
("clean_gen_meeting", None, """
Weekly sync notes. We agreed to move the review meeting later in the week so that more of the team
can attend. The recruiting update was deferred. Everyone should update the shared tracker before
Friday so the summary is accurate.
"""),
("clean_med_handoff", "medical", """
Shift handoff checklist. Confirm that every infusion pump has been checked against the order set and
that alarm limits are set for the unit standard. Escalate any device fault to biomedical engineering
rather than silencing it. Restock the code cart and sign the log. Report equipment shortages to the
charge nurse before the end of the shift so the next team is not left short.
"""),
("clean_med_education", "medical", """
Patient education handout on managing a long-term condition. Take your medicines at the same time
each day. Keep a written record of how you feel so you can discuss it at your next visit. Regular
walking helps most people. Call the clinic if symptoms get worse rather than waiting for the next
appointment.
"""),
("clean_legal_discovery_protocol", "legal", """
Electronic discovery protocol. The parties will exchange documents in a searchable format with load
files. Metadata fields agreed between the parties will be produced where available. Privileged
material will be logged rather than produced. Disputes about scope will be raised with the court
only after a meet and confer.
"""),
("clean_legal_ethics", "legal", """
Conflicts checking procedure. Every prospective engagement is run through the conflicts system
before any substantive discussion. Where a conflict appears, the matter is referred for review. No
work may be opened until clearance is recorded. Waivers require written consent and partner
approval.
"""),
("clean_fin_controls", "financial", """
Internal controls summary. Segregation of duties applies to all payment initiation and approval.
Reconciliations are performed monthly and reviewed independently. Exceptions are tracked to closure.
Access rights are recertified twice a year and removed promptly when someone changes role.
"""),
("clean_gen_incident", None, """
Incident review. The outage began when a configuration change was rolled out without the usual
staged deployment. The change was reverted and service recovered. Follow-up work covers making the
staged rollout mandatory and improving the alert that should have caught this sooner.
"""),
]

_ANNOTATION = re.compile(r"<<([A-Z_]+)\|(.*?)>>", re.DOTALL)


def parse_annotated(annotated: str) -> tuple[str, list[tuple[str, int, int, str]]]:
    """Strip ``<<TYPE|value>>`` markers, returning the plain text and ground truth.

    Ground truth is ``(entity_type, start, end, value)`` with offsets into the
    *stripped* text -- the text the detector is actually handed.
    """
    plain: list[str] = []
    truth: list[tuple[str, int, int, str]] = []
    read_at = 0
    write_at = 0
    for marker in _ANNOTATION.finditer(annotated):
        plain.append(annotated[read_at : marker.start()])
        write_at += marker.start() - read_at
        value = marker.group(2)
        truth.append((marker.group(1), write_at, write_at + len(value), value))
        plain.append(value)
        write_at += len(value)
        read_at = marker.end()
    plain.append(annotated[read_at:])
    return "".join(plain), truth


# Two registry entities can claim the same underlying recognizer hit; which one
# wins is a document-category policy, not a detection difference, so either label
# counts as correctly typed.
LABEL_ALIASES: dict[str, frozenset[str]] = {
    "NAME": frozenset({"NAME", "CLIENT_IDENTITY"}),
    "CLIENT_IDENTITY": frozenset({"CLIENT_IDENTITY", "NAME"}),
    "DOB": frozenset({"DOB", "DATE"}),
    "DATE": frozenset({"DATE", "DOB"}),
    "AMOUNT": frozenset({"AMOUNT", "SETTLEMENT_TERM"}),
    "SETTLEMENT_TERM": frozenset({"SETTLEMENT_TERM", "AMOUNT"}),
}

# Measured floors, not aspirations: each is the coverage this detector achieves on
# the corpus today. A drop below one of these is a real regression in what reaches
# the provider, not a flaky threshold -- spaCy is deterministic for a fixed model,
# so the same corpus gives the same numbers on every run. The two entities below
# 1.0 are bounded by spaCy's PERSON recall, which no registry edit can raise; the
# residual misses are enumerated in test_residual_recall_misses_are_the_known_ones.
COVERAGE_FLOORS: dict[str, float] = {
    "ACCOUNT_NUMBER": 1.0,
    "ADDRESS": 1.0,
    "AMOUNT": 1.0,
    "CASE_ID": 1.0,
    "CASE_STRATEGY": 1.0,
    "CLIENT_IDENTITY": 0.85,
    "DATE": 1.0,
    "DIAGNOSIS": 1.0,
    "DOB": 1.0,
    "EMAIL": 1.0,
    "INSURANCE_ID": 1.0,
    "LAB_RESULT": 1.0,
    "MEDICATION": 1.0,
    "MRN": 1.0,
    "NAME": 0.97,
    "PHONE": 1.0,
    "PRIVILEGED_MARKER": 1.0,
    "SETTLEMENT_TERM": 1.0,
    "SSN": 1.0,
    "TAX_ID": 1.0,
}

OVERALL_COVERAGE_FLOOR = 0.98
OVERALL_TYPED_FLOOR = 0.98


class Residual(NamedTuple):
    """One annotated value the detector did not fully and correctly claim.

    ``covered`` distinguishes the two shortfalls, which are not equally serious.
    ``covered=False`` means the value went out in the clear -- a leak. ``True``
    with a non-matching label means the value *was* masked but under the wrong
    entity type, so only the pseudonymization tier is wrong.
    """

    doc_id: str
    entity_type: str
    value: str
    covered: bool
    labels: tuple[str, ...]

    def describe(self) -> str:
        if not self.covered:
            return f"{self.doc_id}: {self.entity_type} {self.value!r} not covered"
        return (
            f"{self.doc_id}: {self.entity_type} {self.value!r} labelled {list(self.labels)}"
        )


async def measure_coverage(
    detector: Detector,
    corpus: list[tuple[str, str | None, str]],
    in_scope: Callable[[str, str | None], bool] | None = None,
) -> tuple[dict[str, list[int]], list[Residual], list[int]]:
    """``{entity_type: [covered, typed, total]}``, one ``Residual`` per shortfall, and
    the same ``[covered, typed, total]`` restricted to values ``in_scope`` accepts.

    One counting rule, applied to both the tuned corpus and the held-out one, so
    the two figures are comparable rather than merely adjacent. A separate
    implementation per corpus would be the same shape of mistake as a checker that
    shares a bug with the thing it checks: the comparison that carries the whole
    argument would rest on two rules nothing forces to agree.

    The scoped subtotal is accumulated in this loop rather than reconstructed
    afterwards from the residual list. Reconstruction has to key on something, and
    every available key -- ``(doc_id, entity_type, value)`` included -- repeats:
    ``ho_immunization`` annotates the same name and the same chart number on two
    consecutive rows. Both are missed today, so a set-based reconstruction would
    agree with this one and be wrong the moment one of them started matching.
    """
    tally: dict[str, list[int]] = {}
    residual: list[Residual] = []
    scoped = [0, 0, 0]
    for doc_id, doc_category, annotated in corpus:
        text, truth = parse_annotated(annotated)
        found = await detector.detect(text, doc_category)
        for entity_type, start, end, value in truth:
            row = tally.setdefault(entity_type, [0, 0, 0])
            row[2] += 1
            counted = in_scope is not None and in_scope(entity_type, doc_category)
            if counted:
                scoped[2] += 1
            covering = [d for d in found if d.start <= start and end <= d.end]
            if not covering:
                residual.append(Residual(doc_id, entity_type, value, False, ()))
                continue
            row[0] += 1
            if counted:
                scoped[0] += 1
            accepted = LABEL_ALIASES.get(entity_type, frozenset({entity_type}))
            if any(d.entity_type in accepted for d in covering):
                row[1] += 1
                if counted:
                    scoped[1] += 1
            else:
                labels = tuple(sorted({d.entity_type for d in covering}))
                residual.append(Residual(doc_id, entity_type, value, True, labels))
    return tally, residual, scoped


async def measure_recall(detector: Detector) -> tuple[dict[str, list[int]], list[str]]:
    """``{entity_type: [covered, typed, total]}`` plus a line per residual miss."""
    tally, residual, _scoped = await measure_coverage(detector, RECALL_CORPUS)
    return tally, [item.describe() for item in residual]


def format_recall_table(tally: dict[str, list[int]]) -> str:
    lines = [f"{'ENTITY':<20}{'N':>5}{'COVERED':>9}{'TYPED':>8}"]
    for entity_type in sorted(tally):
        covered, typed, total = tally[entity_type]
        lines.append(
            f"{entity_type:<20}{total:>5}{covered / total:>8.0%}{typed / total:>8.0%}"
        )
    total = sum(row[2] for row in tally.values())
    covered = sum(row[0] for row in tally.values())
    typed = sum(row[1] for row in tally.values())
    lines.append(f"{'TOTAL':<20}{total:>5}{covered / total:>8.0%}{typed / total:>8.0%}")
    return "\n".join(lines)


async def test_recall_per_entity_meets_its_measured_floor(detector: Detector) -> None:
    """The headline number, per entity type, with the table printed under ``-s``."""
    tally, misses = await measure_recall(detector)
    print("\n" + format_recall_table(tally))
    print("\n".join(["", "residual misses:", *misses]))

    assert set(tally) == set(COVERAGE_FLOORS), "corpus and floor table disagree"
    for entity_type, (covered, _typed, total) in sorted(tally.items()):
        assert covered / total >= COVERAGE_FLOORS[entity_type], (
            f"{entity_type} coverage fell to {covered}/{total}"
        )

    total = sum(row[2] for row in tally.values())
    assert sum(row[0] for row in tally.values()) / total >= OVERALL_COVERAGE_FLOOR
    assert sum(row[1] for row in tally.values()) / total >= OVERALL_TYPED_FLOOR


async def test_every_spec_mandated_entity_is_found_in_realistic_prose(
    detector: Detector,
) -> None:
    """Build doc section 2's mandated minimum set, measured on prose rather than fixtures.

    The hard requirement names nine types. Each must be found in ordinary
    documents, not only in a string written to satisfy its own regex, so this
    asserts coverage of every annotated instance of the nine across the whole
    corpus -- 218 values as written, of which one escapes (see NAME's floor).
    """
    mandated = {
        "NAME",
        "SSN",
        "DOB",
        "EMAIL",
        "PHONE",
        "MRN",
        "DIAGNOSIS",
        "ACCOUNT_NUMBER",
        "CASE_ID",
    }
    tally, _misses = await measure_recall(detector)
    assert mandated <= set(tally), "the corpus does not exercise every mandated type"
    for entity_type in sorted(mandated):
        covered, _typed, total = tally[entity_type]
        assert total >= 5, f"{entity_type} needs more than {total} corpus instances"
        # NAME rides spaCy's PERSON recall and carries the one documented residual.
        floor = COVERAGE_FLOORS[entity_type]
        assert covered / total >= floor, f"{entity_type} coverage {covered}/{total}"


async def test_residual_recall_misses_are_the_known_ones(detector: Detector) -> None:
    """Pin the residual misses so a new one cannot hide inside an aggregate floor.

    All three are spaCy ``PERSON`` failures on the full name, which is the one
    detection weakness no registry edit can close -- the README says so, and this
    test is what keeps that claim true. "Contreras" *is* detected in the third
    case, so only the forename escapes; the surname is still masked.
    """
    _tally, misses = await measure_recall(detector)
    assert len(misses) == 3, "\n".join(["unexpected residual misses:", *misses])
    assert all("CLIENT_IDENTITY" in miss or "NAME" in miss for miss in misses), misses


async def test_clean_documents_produce_no_detections(detector: Detector) -> None:
    """False-positive rate, measured where ground truth needs no adjudication.

    Every span returned here is a false positive by construction. Reporting a
    recall figure without this number would be reporting half a result: recall
    bought by loosening a pattern until it fires on ordinary prose is not recall.
    """
    spurious: list[str] = []
    words = 0
    for doc_id, doc_category, text in CLEAN_CORPUS:
        words += len(text.split())
        for found in await detector.detect(text, doc_category):
            spurious.append(f"{doc_id}: {found.entity_type} {found.text!r}")
    print(f"\nclean corpus: {len(CLEAN_CORPUS)} documents, {words} words")
    assert spurious == [], "\n".join(["false positives on entity-free prose:", *spurious])


# Spans returned inside the *annotated* corpus that overlap no annotated value.
# Unlike the clean corpus these are not all errors -- "Ohio" next to a street
# address is a defensible LOCATION -- so the assertion is a cap, not zero. It is
# the precision guard for the recall work: a pattern widened until it fires on
# neighbouring prose shows up here rather than silently.
MAX_UNANNOTATED_SPANS = 6


async def test_over_detection_on_realistic_prose_stays_bounded(detector: Detector) -> None:
    extra: list[str] = []
    for doc_id, doc_category, annotated in RECALL_CORPUS:
        text, truth = parse_annotated(annotated)
        for found in await detector.detect(text, doc_category):
            if not any(found.start < end and start < found.end for _t, start, end, _v in truth):
                extra.append(f"{doc_id}: {found.entity_type} {found.text!r}")
    print("\n".join(["", "unannotated spans:", *extra]))
    assert len(extra) <= MAX_UNANNOTATED_SPANS, "\n".join(["over-detection grew:", *extra])


# ---------------------------------------------------------------------------
# 1d. Held-out recall -- the same measurement on shapes nothing was tuned against
# ---------------------------------------------------------------------------
# RECALL_CORPUS above was written by the same process that tuned the patterns, so
# its 99% measures how well the detector handles the shapes we already knew about.
# That number is not wrong, but on its own it is not evidence about an unseen
# document, and it is the first thing a reviewer should distrust.
#
# HELD_OUT_CORPUS is the control. 53 documents in registers that appear nowhere
# above -- radiology dictation, surgical pathology, pharmacy prior-auth, EOB,
# clinical-trial adverse event, immunization export, physical therapy, telehealth
# transcript, patient-portal message, hospice plan, dental recall, EMS run sheet,
# arbitration award, subpoena, court transcript, docketing notice, retainer
# invoice, cease-and-desist, will, closing statement, parenting plan, expert
# invoice, commercial invoice, collections notice, mortgage payoff and servicing
# transfer, brokerage confirmation, payroll register and adjustment, tax notice
# and transmittal, card dispute, adjuster file note, dunning statement, chat log,
# voicemail transcription, CSV and JSON exports, CV, visa letter, university
# record, HR investigation, Slack thread, conference registration, veterinary
# summary, alumni note, IT escalation, survey free text, incident narrative --
# and in spellings the fixtures above never use: dotted and international phone
# numbers, space-separated SSNs, "Patient ID" and "Chart No." for a chart number,
# space-grouped account digits, day-month-year and two-digit-year dates, names
# with particles, hyphens and non-Latin transliteration, plus-addressed e-mail.
#
# The corpus was written before it was measured and NOTHING was changed in
# response to the result. That is the whole point: tuning the registry until this
# number rises would recreate exactly the bias it exists to detect, and would
# leave the project with two home-turf corpora and no control. If a future change
# closes one of the documented gaps below, it must be driven by the property (a
# pattern that is wrong about the world), not by a row in this table.
#
# MEASURED, on the shipped registry:
#
#     RECALL_CORPUS (tuned)      99.1% covered 99.1% typed over 320 values
#     HELD_OUT_CORPUS (unseen)   88.5% covered 87.4% typed over 366 values
#     ... of which in-policy      91.3% covered 90.1% typed over 355 values
#
# An eleven-point drop on unseen shapes is the honest figure and the one the
# README's caveat is about. The residual is not spread evenly -- it concentrates
# in four places, all of them already-known properties rather than surprises, and
# HELD_OUT_MISS_SHAPES below names each one.
#
# "In-policy" excludes annotated values whose entity type is not `allowed_in`
# that document's category -- an AMOUNT in a legal invoice, a service DATE in a
# financial statement. Those are values the detector was never asked to look for,
# because `only_in_doc_categories` scopes AMOUNT to financial documents and DATE
# to medical ones. They are counted in the headline number anyway (a value in the
# clear is in the clear, whatever the reason) and reported separately so the two
# causes are not confused.
#
# Reproduce with:  pytest tests/test_detection.py -k held_out -s

HELD_OUT_CORPUS: list[tuple[str, str | None, str]] = [
# ---------------------------------------------------------------- medical
("ho_radiology", "medical", """
RADIOLOGY REPORT — CT ABDOMEN/PELVIS WITH CONTRAST

Patient ID <<MRN|8814027>>        Accession 2024-CT-88140
Patient: <<NAME|Halvard Nystrom>>
Birth date <<DOB|21-Aug-1958>>
Ordering clinician: Dr. <<NAME|Priti Raval>>

FINDINGS: There is a 3.1 cm hypodense lesion in segment VI of the liver.
No free fluid. Known <<DIAGNOSIS|cirrhosis>> is again noted with a nodular contour.

IMPRESSION: Indeterminate hepatic lesion; recommend MRI. Renal function adequate,
<<LAB_RESULT|creatinine 1.0>>. Results phoned to the ordering clinician at
<<PHONE|312.555.0164>>.
"""),
("ho_pathology", "medical", """
SURGICAL PATHOLOGY REPORT

Chart No. <<MRN|2207731>>. Specimen received from <<NAME|Ingeborg Vasquez-Lund>>,
date of birth <<DOB|9 Feb 1949>>.

Microscopic description: sections show invasive ductal carcinoma, grade 2.
Final diagnosis: <<DIAGNOSIS|breast cancer>>, ER positive.

The patient also carries a diagnosis of <<DIAGNOSIS|osteoporosis>> and takes
<<MEDICATION|alendronate>> weekly. Please direct queries to the laboratory,
<<EMAIL|histology@path.regionalhealth.internal>>, or <<PHONE|+44 20 7946 0958>>.
"""),
("ho_pharmacy_pa", "medical", """
PHARMACY PRIOR AUTHORIZATION REQUEST — FAX COVER

Member <<NAME|Terrance O'Loughlin>>          Member ID <<INSURANCE_ID|AETNA4412093>>
DOB <<DOB|03-07-1972>>                        Chart <<MRN|9014482>>

Requested drug: <<MEDICATION|insulin glargine>>. Prior therapy with
<<MEDICATION|metformin>> and <<MEDICATION|glipizide>> was inadequate; most recent
<<LAB_RESULT|HbA1c of 9.6>> supports escalation. Indication is
<<DIAGNOSIS|type 2 diabetes>>.

Prescriber fax <<PHONE|(415) 555-0193>>; prescriber e-mail
<<EMAIL|rx.desk@clinic-network.corp>>.
"""),
("ho_eob", "medical", """
EXPLANATION OF BENEFITS — THIS IS NOT A BILL

Subscriber: <<NAME|Rosalind Achterberg>>
Policy member number <<INSURANCE_ID|UHG88213047>>
Service date <<DATE|02-14-2024>>

Charge submitted <<AMOUNT|$1,842.00>>. Plan allowance $912.30. You may owe $184.20.
Claim questions: <<PHONE|1 (800) 555-0122>>, or write to
<<EMAIL|member.services@payerco.example>>.
"""),
("ho_trial_ae", "medical", """
CLINICAL TRIAL — SERIOUS ADVERSE EVENT NARRATIVE

Subject initials H.T.  Subject record <<MRN|4402198>>.
Subject full name on the consent form: <<NAME|Hiroko Takahashi>>. Born
<<DOB|1966-11-30>>.

On study day 42 the subject was hospitalised with <<DIAGNOSIS|pulmonary embolism>>.
Study drug was withheld. Concomitant medication at the time included
<<MEDICATION|apixaban>> and <<MEDICATION|prednisone>>. Baseline
<<LAB_RESULT|WBC of 12.4>> on admission.

Investigator contact <<PHONE|617-555-0128>> / <<EMAIL|pi.office@trialsite.local>>.
"""),
("ho_pt_progress", "medical", """
PHYSICAL THERAPY PROGRESS NOTE

Pt: <<NAME|Anneliese van der Berg>> | mrn# <<MRN|7712340>> | dob <<DOB|12/4/1981>>

Subjective: reports improved tolerance. History of <<DIAGNOSIS|rheumatoid arthritis>>.
Objective: knee flexion 118 degrees. Continues <<MEDICATION|naproxen>> as needed.
Plan: two visits weekly for four weeks.

Home number on file: <<PHONE|206 555 0175>>.
"""),
("ho_immunization", "medical", """
IMMUNIZATION RECORD EXPORT

name,dob,mrn,vaccine,date
<<NAME|Chidi Okonjo>>,<<DOB|07/23/2011>>,<<MRN|3318802>>,MMR,<<DATE|09/15/2016>>
<<NAME|Chidi Okonjo>>,<<DOB|07/23/2011>>,<<MRN|3318802>>,Tdap,<<DATE|09/15/2022>>

Guardian e-mail: <<EMAIL|okonjo.family+records@mailhost.example>>
Guardian phone: <<PHONE|(773) 555-0119>>
"""),
("ho_pt_visit", "medical", """
Physical therapy -- visit 4 of 12

Client <<NAME|Dorothy Vaneck>> arrived on time and reports her
<<DIAGNOSIS|chronic low back pain>> is now 4/10, down from 7/10 at evaluation. She
continues <<MEDICATION|meloxicam>> 15 mg each morning and denies new numbness.

Objective: lumbar flexion improved to within functional limits. No red flags today.
Plan: continue twice weekly for four more weeks, then reassess.

Billing reference: chart <<MRN|5518044>>. Insurance on file is member
<<INSURANCE_ID|AET88120334>>. Patient was born <<DOB|09.14.1958>>.
"""),
("ho_prior_auth_appeal", "medical", """
Re: Adverse determination -- request for reconsideration

To whom it may concern,

I am writing on behalf of my patient, <<NAME|Angela Whitmore>>, whose date of birth is
<<DOB|1966-11-30>>, to appeal the denial issued against member ID
<<INSURANCE_ID|CIG4471290>>. Her <<DIAGNOSIS|rheumatoid arthritis>> has failed two prior
agents, and continued <<MEDICATION|methotrexate>> monotherapy is inadequate.

Her most recent renal function, <<LAB_RESULT|creatinine 0.8>>, does not contraindicate
escalation, and her chart number is <<MRN|4419307>>.

I can be reached directly at <<EMAIL|k.morrisey@grovehealth.example>> should you require
additional records before the appeal deadline.
"""),
("ho_ems_run", "medical", """
EMS RUN SHEET -- UNIT 12

DISP 0347. ARR 0356. PT: <<NAME|Rudolph Steinmetz>>, M, DOB <<DOB|3/9/62>>.
HX: <<DIAGNOSIS|copd>>, <<DIAGNOSIS|atrial fibrillation>>.
MEDS: <<MEDICATION|tiotropium>>, <<MEDICATION|apixaban>>.
CC: increasing <<DIAGNOSIS|shortness of breath>> since the evening meal.
TX: oxygen via non-rebreather, <<MEDICATION|albuterol>> nebuliser en route.
Receiving facility chart MRN <<MRN|7702914>>. Spouse notified at <<PHONE|619-555-0128>>.
"""),
("ho_telehealth_chat", "medical", """
Telehealth session transcript

[10:02] Clinician: Good morning, am I speaking with <<NAME|Beatrice Solano>>?
[10:02] Patient: Yes, that's me.
[10:03] Clinician: Thanks. Can you confirm your date of birth for me?
[10:03] Patient: Sure, it's <<DOB|July 4, 1988>>.
[10:04] Clinician: Perfect. Does the portal show your record as <<MRN|4419305>>?
[10:04] Patient: It does.
[10:05] Clinician: You mentioned the <<DIAGNOSIS|migraine>> is back. Are you still taking
        the <<MEDICATION|sumatriptan>> we prescribed?
[10:05] Patient: Yes, but it isn't helping much this week.
[10:07] Clinician: Understood. Is <<PHONE|(801) 555-0169>> still the best number for you?
[10:07] Patient: That's right.
"""),
("ho_portal_message", "medical", """
Secure message -- from your care team

Hello <<NAME|Terrence Boudreaux>>,

Your recent bloodwork is back. Your <<LAB_RESULT|LDL was 148>> and your
<<LAB_RESULT|A1C is 6.1>>, which puts you in the range we call
<<DIAGNOSIS|prediabetes>>. We would like you to start <<MEDICATION|metformin>> at a low
dose and recheck in three months.

If anything looks wrong on your chart -- it should list record <<MRN|3308871>> and a
birth date of <<DOB|02-28-1974>> -- please tell the front desk when you next visit.

Reply here or write to <<EMAIL|carecoordination@stmarks.internal>>.
"""),
("ho_hospice_plan", "medical", """
Hospice plan of care -- interdisciplinary team review

* Patient: <<NAME|Grace Okorie>>, record <<MRN|6612977>>
* Born <<DOB|12 March 1939>>
* Primary terminal diagnosis: <<DIAGNOSIS|end-stage renal disease>>
* Secondary conditions: <<DIAGNOSIS|dementia>>, <<DIAGNOSIS|anemia>>
* Comfort medications: <<MEDICATION|morphine>> concentrate, <<MEDICATION|lorazepam>>
* Primary caregiver: her daughter, <<NAME|Charlotte Okorie>>, cell <<PHONE|443-555-0192>>
* Caregiver email for the visit calendar: <<EMAIL|c.okorie@familymail.example>>
"""),
("ho_dental_note", "medical", """
Dental chart entry.

Patient <<NAME|Steven Halvorsen>> presented for recall prophylaxis. Health history was
updated; he reports <<DIAGNOSIS|type 2 diabetes>> controlled on <<MEDICATION|metformin>>
and also takes <<MEDICATION|lisinopril>> daily. Blood pressure taken in the chair.

Radiographs: four bitewings. No new caries. Periodontal charting stable.
Chart number <<MRN|2214880>>. Patient's mobile is <<PHONE|(505) 555-0175>>.
"""),
# ------------------------------------------------------------------ legal
("ho_arbitration_award", "legal", """
FINAL AWARD OF THE ARBITRATOR

In the matter of <<CLIENT_IDENTITY|Rowan Delacroix-Meyer>> and Sundial Freight LLC,
AAA case <<CASE_ID|23-AAA-00641>>, consolidated with <<CASE_ID|3:22-cv-01145>>.

Having considered the evidence, the arbitrator awards claimant
<<SETTLEMENT_TERM|damages in the sum of $612,500>>, payable within thirty days.

<<PRIVILEGED_MARKER|Attorney Work Product>> — the panel's deliberation notes are
not part of this award.
"""),
("ho_subpoena", "legal", """
SUBPOENA DUCES TECUM

To: Custodian of Records
Re: <<CLIENT_IDENTITY|Beatriz Sanabria>>, born <<DOB|30 June 1988>>, social security
number <<SSN|418 22 9037>>.

You are commanded to produce all documents in <<CASE_ID|1:25-cv-00318>> concerning
the above individual on or before <<DATE|03/28/2025>>.

Service copy to <<EMAIL|records@courtservices.example>> and by telephone
confirmation to <<PHONE|202-555-0146>>.
"""),
("ho_transcript", "legal", """
EXCERPT OF PROCEEDINGS — VOLUME II

THE COURT: We are on the record in <<CASE_ID|2:24-cv-09931>>.
MR. ABERNATHY: Appearing for the plaintiff, your honour.
THE COURT: And your client is present?
MR. ABERNATHY: <<CLIENT_IDENTITY|Yusuf Abdi-Rahman>> is seated at counsel table.
THE COURT: Very well. <<CASE_STRATEGY|We intend to move to bifurcate liability
from damages before the pretrial conference>>, counsel indicated in the joint report.
"""),
("ho_retainer_invoice", "legal", """
STATEMENT OF ACCOUNT — LEGAL SERVICES

Bill to: <<CLIENT_IDENTITY|Margarethe Solheim>>
Matter: <<CASE_ID|4:23-cv-00219>>
Invoice 2024-1187

Professional fees this period <<AMOUNT|$18,750.00>>. Trust balance applied
<<AMOUNT|$5,000.00>>. Remit to our operating account, a/c
<<ACCOUNT_NUMBER|7710294883>>, or contact accounts at
<<EMAIL|billing@solheimlaw.internal>>.

Taxpayer identification number for our firm is <<TAX_ID|27-4419283>>.
"""),
("ho_cease_desist", "legal", """
<<PRIVILEGED_MARKER|PRIVILEGED & CONFIDENTIAL>>

Dear Sir or Madam,

This firm represents <<CLIENT_IDENTITY|Sunniva Bjørnstad>>. Your continued use of the
mark is actionable. <<CASE_STRATEGY|We are inclined to seek preliminary injunctive
relief in the Northern District if we do not receive written assurances by the end
of the month>>.

Related proceeding: <<CASE_ID|24-CIV-00771>>. Please respond to
<<EMAIL|litigation@brandcounsel.example>> or <<PHONE|(628) 555-0187>>.
"""),
("ho_docketing_notice", "legal", """
DOCKETING NOTICE

The clerk has assigned <<CASE_ID|5:25-cr-00042>> to Judge Alvarez.
Counsel of record for the defendant is <<CLIENT_IDENTITY|Nnamdi Eze>>, whose date of
birth appears in the sealed exhibit as <<DOB|1990/02/09>>.
A settlement conference is set. <<SETTLEMENT_TERM|A settlement of $75,000 was
discussed off the record>>.
"""),
("ho_will", "legal", """
LAST WILL AND TESTAMENT

I, <<CLIENT_IDENTITY|Cornelius Ashby>>, being of sound mind, do hereby revoke all former
wills heretofore made by me.

FIRST: I direct that my just debts and funeral expenses be paid.

SECOND: I give and bequeath the residue of my estate to my niece,
<<CLIENT_IDENTITY|Prudence Ashby>>, presently residing in <<ADDRESS|Charleston>>.

THIRD: I nominate as executor the attorney whose office maintains the file bearing
number <<CASE_ID|2:24-pr-00318>>, and whose taxpayer identification number is
<<TAX_ID|58-2210947>>.

Executed this day in the presence of the witnesses named below.
Witness contact: <<PHONE|(843) 555-0181>>.
"""),
("ho_closing_statement", "legal", """
SETTLEMENT STATEMENT -- REAL PROPERTY CLOSING

Buyer: <<CLIENT_IDENTITY|Margaret Lindholm>>
Seller: <<CLIENT_IDENTITY|Hollis Trueblood>>
Companion litigation matter <<CASE_ID|3:24-cv-01177>>

Purchase price and adjustments were reconciled against the escrow
account no. <<ACCOUNT_NUMBER|6640118293>>. Seller proceeds were wired the same afternoon
and the file has been closed.

Buyer's counsel may be reached at <<EMAIL|mlindholm@harborcounsel.example>> or on
<<PHONE|(360) 555-0154>>. The buyer's date of birth, taken for title purposes, is
<<DOB|1979/05/02>>.
"""),
("ho_parenting_plan", "legal", """
PARENTING PLAN AND PARENTING TIME SCHEDULE

The parties, <<CLIENT_IDENTITY|Delphine Marchetti>> and <<CLIENT_IDENTITY|Stefan Reyes>>,
agree as follows.

1. The children shall reside primarily with the mother in <<ADDRESS|Missoula>>.
2. Exchanges occur at the midpoint of the drive. Each parent shall keep a working
   telephone number on file; the father's is <<PHONE|406-555-0136>>.
3. Neither parent shall disparage the other in the presence of the children.

Case number <<CASE_ID|4:23-dr-00250>>. The mediator's email is
<<EMAIL|mediation@bitterrootadr.example>>.
"""),
("ho_expert_invoice", "legal", """
INVOICE FOR EXPERT SERVICES

Bill to: counsel of record, matter <<CASE_ID|5:22-cv-04471>>.
Expert: <<CLIENT_IDENTITY|Raymond Ballinger>>
Federal employer identification number <<TAX_ID|77-3049182>>

Services rendered: record review, 6.5 hours; deposition preparation, 3.0 hours.

Remit by ACH to account number <<ACCOUNT_NUMBER|1102938475>>. Questions to
<<EMAIL|billing@ballingerconsulting.example>> or <<PHONE|(650) 555-0119>>.
"""),
# -------------------------------------------------------------- financial
("ho_invoice", "financial", """
COMMERCIAL INVOICE 88-2044

Bill to: <<NAME|Ferdinand Oyelaran>>
Remit payment to account no <<ACCOUNT_NUMBER|4471029384>> at Meridian Bank.
Supplier EIN: <<TAX_ID|81-2947160>>

Subtotal <<AMOUNT|$34,200.00>>. Freight <<AMOUNT|$1,150.00>>. Total due
<<AMOUNT|$35,350.00>> net 30.

Accounts payable questions: <<EMAIL|ap@oyelaran-imports.corp>>,
<<PHONE|+1-312-555-0138>>.
"""),
("ho_collections", "financial", """
NOTICE OF DELINQUENCY

<<NAME|Consuelo Ibarra-Nunez>>
Account number <<ACCOUNT_NUMBER|9902831746>>

Your balance of <<AMOUNT|$2,884.19>> is now 90 days past due. A payment of
<<AMOUNT|$500.00>> today will stop further collection activity. We hold your
social security number as <<SSN|530 41 8827>> and your date of birth as
<<DOB|18-Mar-1979>> for identification purposes.

Call <<PHONE|888.555.0154>> or e-mail <<EMAIL|collections@recoverypartners.example>>.
"""),
("ho_mortgage_payoff", "financial", """
MORTGAGE PAYOFF STATEMENT

Borrower: <<NAME|Bartholomew Achterberg>>
Loan/acct # <<ACCOUNT_NUMBER|30012948756>>
Property address in <<ADDRESS|Tulsa>>, Oklahoma

Principal balance <<AMOUNT|$214,880.42>>. Per diem interest $23.14. Good through
<<DATE|06/30/2025>>. Wire instructions will be released only after telephone
verification at <<PHONE|(918) 555-0102>>.

Borrower taxpayer id <<TAX_ID|44-8827193>>.
"""),
("ho_brokerage_confirm", "financial", """
TRADE CONFIRMATION

Registered owner <<NAME|Xiulan Zhao>>
Brokerage a/c <<ACCOUNT_NUMBER|660112938475>>

Bought 400 shares at a principal amount of <<AMOUNT|$18,004.00>>; commission
<<AMOUNT|$4.95>>. Settlement date <<DATE|05/22/2025>>.

Statements are delivered to <<EMAIL|x.zhao@investormail.local>>. Service line
<<PHONE|(646) 555-0173>>.
"""),
("ho_payroll_register", "financial", """
PAYROLL REGISTER — PERIOD ENDING <<DATE|03/15/2025>>

Employee                 SSN               Net pay      Direct deposit
<<NAME|Aurelio Santangelo>>      <<SSN|602 33 1194>>       <<AMOUNT|$3,412.77>>    acct <<ACCOUNT_NUMBER|551029384712>>
<<NAME|Dilnoza Yusupova>>        <<SSN|714 08 2265>>       <<AMOUNT|$2,988.10>>    acct <<ACCOUNT_NUMBER|551029477310>>

Employer identification number <<TAX_ID|59-1102847>>. Payroll questions to
<<EMAIL|payroll@company-hq.internal>>.
"""),
("ho_tax_notice", "financial", """
NOTICE OF PROPOSED ASSESSMENT

Taxpayer: <<NAME|Grigore Enescu>>
Taxpayer identification number <<TAX_ID|72-3391085>>
Tax period ending <<DATE|12/31/2023>>

Our records show an underpayment of <<AMOUNT|$7,412.00>> plus interest. Payment may
be made from your bank account <<ACCOUNT_NUMBER|880194728310>>.

If you disagree, write to <<EMAIL|appeals@revenueoffice.example>> or telephone
<<PHONE|1-877-555-0161>>.
"""),
("ho_card_dispute", "financial", """
CARDHOLDER DISPUTE FORM

Cardholder <<NAME|Marguerite N'Diaye>>, date of birth <<DOB|4 Oct 1993>>, resides in
<<ADDRESS|Providence>>, Rhode Island.

Disputed transaction of <<AMOUNT|$1,204.55>> posted to account
<<ACCOUNT_NUMBER|4400 8829 1374>> on <<DATE|01/09/2025>>. Cardholder states the
transaction was not authorised.

Callback <<PHONE|401-555-0130>>; e-mail <<EMAIL|m.ndiaye@personalbox.example>>.
"""),
("ho_collections_letter", "financial", """
NOTICE OF DELINQUENCY

Dear <<NAME|Marisol Cabrera>>,

Our records show the balance on Account Number: <<ACCOUNT_NUMBER|9930118274>> remains
unpaid. The amount now due is <<AMOUNT|$3,412.09>>, which includes late fees assessed
against the account since the last payment was received.

We hold your social security number as <<SSN|318-46-2207>> and your date of birth as
<<DOB|10/22/1981>> for identification purposes only.

To arrange payment, call <<PHONE|(844) 555-0193>> or write to
<<EMAIL|resolutions@pinnaclerecovery.example>>.
"""),
("ho_tax_cover", "financial", """
Transmittal letter -- individual return

Enclosed please find the completed return for <<NAME|Ingrid Haugland>>, prepared from the
documents you provided. Your taxpayer identification number as shown on the return is
<<TAX_ID|26-4471902>> and your date of birth is <<DOB|Feb 11, 1969>>.

The refund of <<AMOUNT|$2,206.44>> will be deposited directly to the checking
a/c <<ACCOUNT_NUMBER|8801927364>> you designated on the signature page.

Please sign where indicated and return by email to <<EMAIL|returns@meridiantax.example>>.
Our office line is <<PHONE|(612) 555-0102>>.
"""),
("ho_mortgage_servicing", "financial", """
IMPORTANT NOTICE ABOUT YOUR LOAN

The servicing of your mortgage is transferring to a new servicer.

Borrower of record: <<NAME|Charlotte Fitzgerald>>
Loan account: <<ACCOUNT_NUMBER|acct # 44029183756>>
Current escrow balance: <<AMOUNT|$4,118.62>>

Nothing else about your loan changes. Your payment, currently <<AMOUNT|$1,942.18>> each
month, stays exactly the same, and no action is required from you.

Questions? Call <<PHONE|1-877-555-0112>> or email <<EMAIL|transfers@atlasloan.internal>>.
"""),
("ho_adjuster_note", "financial", """
Claim file note -- adjuster entry.

Insured <<NAME|Bartholomew Reed>>. DOB <<DOB|05/07/1977>>. SSN on file
<<SSN|466-92-1130>>. Spoke with insured regarding the loss and confirmed policy member
<<INSURANCE_ID|GEI7719042>>.

Estimate written for <<AMOUNT|$8,940.55>>. Payment to be issued to the mortgagee and the
insured jointly, deposited to account no. <<ACCOUNT_NUMBER|2200194837>>.

Insured cell <<PHONE|(210) 555-0187>>. Email on file <<EMAIL|b.reed@webmail.example>>.
"""),
("ho_payroll_dispute", "financial", """
Payroll adjustment request

Employee: <<NAME|Susan Torkelsen>>
Employee SSN: <<SSN|529-07-3341>>
Direct deposit account <<ACCOUNT_NUMBER|3391028475>>

The employee reports that the deduction of <<AMOUNT|$412.77>> taken from the last cycle
was applied in error. Payroll confirms the transaction was a duplicate withdrawal and has
been reversed.

Corrected net pay of <<AMOUNT|$2,884.31>> will be released on the next cycle.
Employee contact: <<PHONE|503-555-0141>>, <<EMAIL|s.torkelsen@company.internal>>.
Employer identification number <<TAX_ID|93-1102847>>.
"""),
("ho_dunning_invoice", "financial", """
STATEMENT OF ACCOUNT -- 60 DAYS PAST DUE

Customer <<NAME|Prosper Adeyinka>> owes a balance of <<AMOUNT|$27,510.00>> against
account no <<ACCOUNT_NUMBER|770291384562>>.

Invoice 8841 was issued against a deposit of <<AMOUNT|$9,170.00>>, of which nothing has
been received. A payment plan is available on request.

Our tax identification number for your records is <<TAX_ID|41-9928374>>.
Accounts receivable: <<EMAIL|ar@northgateindustrial.example>>, <<PHONE|(414) 555-0125>>.
"""),
# ---------------------------------------------------------------- general
("ho_chat_log", None, """
#support-escalations

09:14  <<NAME|Priyanka Raghunathan>>: customer can't log in, verified last 4 of ssn
09:15  <<NAME|Tomas Bergqvist>>: what's the full number, i'll check the record
09:15  <<NAME|Priyanka Raghunathan>>: <<SSN|385-22-9014>>, dob <<DOB|11/06/1987>>
09:16  <<NAME|Tomas Bergqvist>>: found them, mail is <<EMAIL|k.svensson@clientdomain.lan>>
09:17  <<NAME|Priyanka Raghunathan>>: phone on file <<PHONE|(415) 555-0109>>, calling now
"""),
("ho_voicemail_ext", None, """
VOICEMAIL TRANSCRIPTION — EXTENSION 4402

"Hi, this is <<NAME|Eamonn Fitzgerald>> returning your call. You can reach me back on
<<PHONE|503 555 0141>> any time today. My date of birth is <<DOB|Feb 3, 1975>> if you
need to verify, and my e-mail is <<EMAIL|e.fitzgerald@homedomain.internal>>.
Thanks, bye."
"""),
("ho_csv_export", None, """
customer_id,full_name,email,phone,ssn,dob
44120,<<NAME|Solveig Haraldsen>>,<<EMAIL|s.haraldsen@nordicmail.example>>,<<PHONE|+47 21 08 44 12>>,<<SSN|221-55-0084>>,<<DOB|1994-07-19>>
44121,<<NAME|Rajesh Ramachandran>>,<<EMAIL|r.ramachandran@corp.intranet>>,<<PHONE|(972) 555-0166>>,<<SSN|609-14-3372>>,<<DOB|1982-01-05>>
"""),
("ho_json_payload", None, """
{
  "applicant": {
    "name": "<<NAME|Zainab Al-Mansouri>>",
    "email": "<<EMAIL|z.almansouri@applicants.internal>>",
    "phone": "<<PHONE|+971 4 555 0177>>",
    "ssn": "<<SSN|477-90-2216>>",
    "date_of_birth": "<<DOB|1996-05-28>>"
  },
  "reference_case": "<<CASE_ID|1:24-cv-03310>>"
}
"""),
("ho_cv", None, """
CURRICULUM VITAE

<<NAME|Oluwadamilare Adebayo-Fischer>>
<<EMAIL|o.adebayo@jobseeker.example>> · <<PHONE|(212) 555-0184>> · <<ADDRESS|Newark>>, New Jersey

PROFILE
Fifteen years in supply-chain analytics. Authorised to work without sponsorship.

PERSONAL
Date of birth: <<DOB|29 September 1979>>. Reference number for the background check
was <<CASE_ID|1:22-cv-00551>>.
"""),
("ho_visa_letter", None, """
LETTER OF EMPLOYMENT VERIFICATION FOR VISA PURPOSES

To whom it may concern,

This letter confirms that <<NAME|Nguyen Thi Minh Chau>>, born <<DOB|14/08/1990>>, is
employed by this company. Her annual salary is <<AMOUNT|$96,000>>.

Her social security number on our records is <<SSN|315-77-2048>> and she can be
contacted at <<EMAIL|minh.chau@employer.corp>> or <<PHONE|+84 28 3555 0128>>.

Human resources: <<PHONE|(206) 555-0117>>.
"""),
("ho_university_record", None, """
OFFICE OF THE REGISTRAR — ENROLMENT VERIFICATION

Student: <<NAME|Cathal Ó Briain>>
Student e-mail <<EMAIL|c.obriain@students.university.edu>>
Date of birth: <<DOB|22-11-2003>>

The above named is enrolled full time for the current term. The student's social
security number, <<SSN|498-31-7720>>, is retained on the financial-aid file, and a
guardian may be reached at <<PHONE|614.555.0198>>.
"""),
("ho_hr_investigation", None, """
CONFIDENTIAL HR INVESTIGATION MEMORANDUM

Complainant: <<NAME|Ravindra Balasubramanian>>
Respondent: <<NAME|Britt-Marie Lindgren>>

The complainant reported the incident on <<DATE|10/02/2024>>. The complainant's
personal contact details are <<EMAIL|r.bala@personal.lan>> and
<<PHONE|(650) 555-0111>>. Occupational health noted a pre-existing diagnosis of
<<DIAGNOSIS|migraine>> which the complainant says was aggravated.

No further identifying information is recorded in this memorandum.
"""),
("ho_slack_thread", None, """
#ops-escalations

<<NAME|Tobias Wrenfield>>  9:14 AM
anyone around? customer says they cannot log in at all

<<NAME|Patricia Ranganathan>>  9:15 AM
what is their account email

<<NAME|Tobias Wrenfield>>  9:15 AM
<<EMAIL|p.hollander@vertexbuild.internal>> -- they also left a callback number of
<<PHONE|(971) 555-0166>>

<<NAME|Patricia Ranganathan>>  9:17 AM
found them, the legacy record id is <<MRN|4471023>> which is odd for this tenant

<<NAME|Tobias Wrenfield>>  9:18 AM
ok escalating now
"""),
("ho_conference_reg", None, """
Registration confirmation -- Annual Symposium

Attendee: <<NAME|Laura Bertolucci>>
Email used for registration: <<EMAIL|l.bertolucci@institute.example>>
Mobile for on-site alerts: <<PHONE|+39 06 5555 0170>>

Your registration has been received and a receipt has been sent to the address above.

If your badge shows the wrong name, please reply before the cutoff date. Accessibility
requests may mention a relevant condition; this attendee disclosed
<<DIAGNOSIS|multiple sclerosis>> and asked for seating near an exit.
"""),
("ho_vet_record", None, """
Veterinary visit summary

Owner: <<NAME|Fiona Shaughnessy>>
Owner phone: <<PHONE|(617) 555-0189>>
Owner email: <<EMAIL|fiona.shaughnessy@petmail.example>>

Patient "Biscuit", a nine-year-old retriever, presented for lethargy. The owner mentioned
that she herself manages <<DIAGNOSIS|hypothyroidism>> and wondered whether the dog could
have the same condition.

Bloodwork was sent to the outside laboratory. The balance was settled on the card held
against account <<ACCOUNT_NUMBER|5580291837>>.
"""),
("ho_alumni_note", None, """
Class notes

<<NAME|Gwendolyn Pryce>> writes in from abroad to say she has finally retired after
thirty years in the same practice. She would love to hear from classmates and can be
reached at <<EMAIL|gwen.pryce@alumnimail.example>>.

Meanwhile <<NAME|Howard Park>>, born <<DOB|November 2, 1961>>, has taken up long distance
cycling and reports covering three thousand miles this year. His new number is
<<PHONE|(608) 555-0198>>.
"""),
("ho_it_escalation", None, """
Priority 1 escalation -- identity verification service

Impact: password resets are failing for a subset of tenants.

Reported by <<NAME|Aurelio Santangelo>> (<<EMAIL|a.santangelo@corp.internal>>), on call
at <<PHONE|(415) 555-0177>>.

During triage an engineer pasted a production record into the ticket, which included a
customer social security number, <<SSN|657-21-9948>>, and that customer's date of birth
<<DOB|1990-04-15>>. The ticket has since been restricted.

Vendor case reference <<CASE_ID|24-SUP-00931>>.
"""),
("ho_survey_freetext", None, """
Patient experience survey -- free text responses

"The nurse who saw me, <<NAME|Kenneth Osei>>, was excellent. I have
<<DIAGNOSIS|generalized anxiety disorder>> and he was patient with me throughout."

"Nobody told me my <<LAB_RESULT|eGFR 52>> result for two weeks. Please telephone me on
<<PHONE|(704) 555-0132>> next time instead of writing."

"Billing sent my statement to the wrong address. My email is
<<EMAIL|d.osullivan@homemail.example>> and it has been for years."
"""),
("ho_incident_narrative", None, """
INCIDENT NARRATIVE

On the date in question the reporting party, <<NAME|Katherine Volkonsky>>, stated that
she returned home and discovered the rear door had been forced. She provided a date of
birth of <<DOB|24-Sep-1986>> and a contact number of <<PHONE|(619) 555-0150>>.

Taken from the residence were documents including a card statement bearing
account <<ACCOUNT_NUMBER|acct. 6690118273>> and a tax notice showing employer
identification number <<TAX_ID|82-1937465>>.

The reporting party's email for follow up is <<EMAIL|k.volkonsky@mailbox.example>>.
A related civil matter, <<CASE_ID|3:25-cv-00218>>, is already on file.
"""),
("ho_voicemail_callback", None, """
Voicemail transcription (automated, low confidence)

"Hi, um, this is <<NAME|Rosalind Kavanagh>> calling back about the paperwork. Uh, you
asked for my social, it is <<SSN|205-63-8814>>, and I was born <<DOB|8/16/1993>>. You can
get me at <<PHONE|(937) 555-0158>> most days, or on my email which is
<<EMAIL|r.kavanagh@personalmail.example>>. Thanks, bye."
"""),
]

# Held-out entity-free prose in the same new registers: ground truth is "return nothing".
HELD_OUT_CLEAN_CORPUS: list[tuple[str, str | None, str]] = [
("hoc_rad_protocol", "medical", """
Contrast protocol standard. Screening for renal impairment is performed before every
contrast-enhanced study. Where screening is not possible the study proceeds without
contrast unless the clinical question requires otherwise. Scanner calibration is
verified at the start of each working day.
"""),
("hoc_lab_qc", "medical", """
Laboratory quality control summary. Control material is run at the start of every
shift and after any instrument maintenance. Out-of-range controls require repeat
testing before patient samples are released. Reagent lots are recorded in the
instrument log rather than on paper.
"""),
("hoc_pt_gym", "medical", """
Gym safety notice for the therapy suite. Wipe down equipment between users. Report any
frayed resistance band to the lead therapist so that it can be replaced. Do not leave
weights on the floor between sessions. The emergency pull cord is tested weekly.
"""),
("hoc_bereavement", "medical", """
Bereavement support is offered to families for thirteen months following a death. Groups
meet twice monthly and are open to anyone who has been served by the agency. Attendance is
voluntary and there is no charge. Individual counselling can be arranged where a group is
not the right fit.
"""),
("hoc_arb_rules", "legal", """
Arbitration rules, article twelve. The tribunal shall determine the procedure subject
to the parties agreeing otherwise in writing. Hearings are private unless the parties
agree to admit observers. The tribunal may proceed in the absence of a party that
fails to appear without showing sufficient cause.
"""),
("hoc_court_notice", "legal", """
General notice to the bar. Filings submitted after four in the afternoon are entered
on the following business day. Paper courtesy copies are no longer accepted for
routine motions. Counsel should consult the standing orders before noticing any
hearing.
"""),
("hoc_third_party_requests", "legal", """
Guidance for responding to third party requests. Route every request to the records team
on the day it arrives. Do not produce anything before the response date has been
calendared and the scope confirmed. Where a request appears overbroad, prepare objections
rather than producing first and objecting later.
"""),
("hoc_closing_checklist", "legal", """
Pre closing checklist. Confirm the title commitment has been updated. Confirm the payoff
figures are current through the anticipated funding date. Confirm the wire instructions
were verified by telephone using a number obtained independently rather than one supplied
in an email.
"""),
("hoc_ap_policy", "financial", """
Accounts payable policy. Invoices are matched against a purchase order and a receipt
before payment is scheduled. Payment runs occur twice a month. Any invoice without a
matching purchase order is returned to the requesting department rather than held.
"""),
("hoc_aml_training", "financial", """
Anti-money-laundering refresher training. All staff complete the module annually.
Escalation is through the nominated officer and not through line management. Records
of training completion are retained for the period required by the regulator.
"""),
("hoc_escrow_policy", "financial", """
Escrow analysis is performed annually. Where a shortage is identified it may be spread
over the following twelve months or paid as a lump sum at the borrower's election. A
surplus above the threshold is refunded. Analyses are mailed at least thirty days before
the new payment takes effect.
"""),
("hoc_collections_standards", "financial", """
Collection call standards. Calls may not be placed before eight in the morning or after
nine at night in the consumer's own time zone. A consumer who states in writing that they
refuse to pay must not be contacted further except as the statute permits. Every call is
recorded and reviewed on a sample basis.
"""),
("hoc_it_runbook", None, """
Certificate rotation runbook. Generate the new key material, stage it alongside the
existing certificate, then cut over during the maintenance window. Verify the chain
from an external network before removing the old certificate. Roll back by restoring
the previous bundle.
"""),
("hoc_office_notice", None, """
Building notice. The lifts in the south tower will be out of service while the
controllers are replaced. Please use the stairs or the north tower lifts. Deliveries
should be routed to the loading bay entrance for the duration of the works.
"""),
("hoc_voicemail_greeting", None, """
"You have reached our main line. Our offices are open on weekdays. Please listen carefully
as our options have changed. To repeat this message, remain on the line. Otherwise, leave
a message after the tone and someone will return your call on the next business day."
"""),
("hoc_slack_standup", None, """
standup thread -- yesterday: finished the migration dry run and wrote up the rollback
steps. today: pairing on the flaky integration test, then reviewing the deploy checklist.
blockers: none, though the staging environment was slow again this morning.
"""),
("hoc_conference_cfp", None, """
Call for proposals. Submissions should describe work that has not been presented
elsewhere. Sessions run forty minutes including questions. Reviewers score on relevance,
originality and clarity. Notification is sent to every submitter whether or not the
proposal is accepted.
"""),
]

# Measured on the held-out corpus, not on the tuned one, and not adjusted afterwards.
# Where a floor sits far below 1.0 the gap is real and named in HELD_OUT_MISS_SHAPES;
# lowering a floor here without moving the corresponding entry there is how a
# regression would get through.
HELD_OUT_COVERAGE_FLOORS: dict[str, float] = {
    "ACCOUNT_NUMBER": 0.94,
    "ADDRESS": 1.0,
    "AMOUNT": 0.84,
    "CASE_ID": 1.0,
    "CASE_STRATEGY": 1.0,
    "CLIENT_IDENTITY": 0.92,
    "DATE": 0.30,
    "DIAGNOSIS": 1.0,
    "DOB": 0.87,
    "EMAIL": 1.0,
    "INSURANCE_ID": 0.80,
    "LAB_RESULT": 1.0,
    "MEDICATION": 1.0,
    "MRN": 0.26,
    "NAME": 0.81,
    "PHONE": 1.0,
    "PRIVILEGED_MARKER": 1.0,
    "SETTLEMENT_TERM": 0.0,
    "SSN": 1.0,
    "TAX_ID": 1.0,
}

# Measured: 324/366 covered, 320/366 typed; in-policy 324/355.
HELD_OUT_COVERAGE_FLOOR = 0.88
HELD_OUT_TYPED_FLOOR = 0.87
HELD_OUT_IN_POLICY_COVERAGE_FLOOR = 0.91

# entity type -> (how many of its held-out values fall short, and why).
#
# This is the inventory the aggregate floors would otherwise hide. Each ceiling is
# the count measured today and the assertion is ``<=``, so closing a gap passes while
# a NEW kind of shortfall -- an entity type absent from this table, or an existing one
# getting worse -- fails. An aggregate floor alone cannot do that: MRN could fall to
# zero and NAME rise to compensate without the headline number moving at all.
HELD_OUT_MISS_SHAPES: dict[str, tuple[int, str]] = {
    "MRN": (
        13,
        "the field label is not literally 'MRN', 'medical record number' or 'MR #' "
        "-- 'Patient ID 8814027', 'Chart No. 2207731', 'chart number is 4419307', "
        "'record 6612977'. entities.yaml documents this gap in the comment above MRN; "
        "the held-out corpus is what puts a number on it, and the number is bad: 4/15 "
        "covered, 2/15 typed. Eleven of the thirteen shortfalls go to the provider in "
        "the clear -- 'the legacy record id is 4471023' among them. The other two are "
        "masked only incidentally, both by a DATE detection over the bare digit run "
        "('Chart No. 2207731', 'Billing reference: chart 5518044'), which is luck "
        "rather than design and gives the value the wrong pseudonymization tier. See "
        "HELD_OUT_INCIDENTAL_MASKS: those two are the only MRN masks of that kind and "
        "no PERSON/NAME detection covers any held-out MRN.",
    ),
    "NAME": (
        12,
        "spaCy's PERSON recall, which no registry edit can raise: hyphenated and "
        "multi-particle names ('Oluwadamilare Adebayo-Fischer', 'Ingeborg "
        "Vasquez-Lund'), and names in a CSV or column-aligned row with no sentence "
        "around them ('Chidi Okonjo' twice, 'Solveig Haraldsen', 'Rajesh "
        "Ramachandran', 'Dilnoza Yusupova'). Structure alone does not predict the "
        "miss, so 'no grammatical context' is not the whole story: the JSON payload's "
        "quoted 'Zainab Al-Mansouri' IS detected, while 'Customer Prosper Adeyinka "
        "owes a balance' sits in an ordinary sentence and is not. One of the twelve, "
        "'Priyanka Raghunathan' in the chat log, is masked incidentally by a DOB span "
        "that swallowed the '09:15' timestamp ahead of it -- masked, wrongly tiered.",
    ),
    "DATE": (
        7,
        "out of policy rather than missed: DATE is scoped to medical documents by "
        "only_in_doc_categories, so a settlement date on a brokerage confirmation or a "
        "tax period on an assessment notice is never looked for. Section 9.2 makes "
        "that choice deliberately -- HIPAA treats individual-related dates as "
        "identifiers, ordinary business dates are not -- and the held-out corpus "
        "annotates them anyway so the cost of the choice stays visible.",
    ),
    "DOB": (
        5,
        "three are an ISO date in a structured column, where the only birth context is "
        "a header several fields away and outside the 60-character leading window; one "
        "is '4 Oct 1993', where Presidio returns 'Oct 1993' and leaves the day "
        "uncovered. The fifth, '09.14.1958', is not a miss at all -- a dot-separated "
        "date is claimed by PHONE, so it is masked under the wrong type rather than "
        "left in the clear (HELD_OUT_INCIDENTAL_MASKS).",
    ),
    "AMOUNT": (
        4,
        "out of policy: AMOUNT is scoped to financial documents, so a fee line on a "
        "legal retainer invoice and a salary in a visa letter are not looked for.",
    ),
    "SETTLEMENT_TERM": (
        2,
        "both patterns need a literal 'settle...' inside the bounded gap. An award of "
        "'damages in the sum of $612,500' has none, and AMOUNT is out of scope in a "
        "legal document, so that figure goes to the provider in the clear -- a plain "
        "gap rather than a known limit, as is ACCOUNT_NUMBER's below. The second "
        "shortfall is not of that kind: 'A settlement of $75,000 was\\ndiscussed off "
        "the record' does match, but the span returned is 'settlement of $75,000', so "
        "the money is masked and only the surrounding words are uncovered.",
    ),
    "INSURANCE_ID": (
        1,
        "'AETNA4412093' has a five-letter payer prefix and the pattern allows "
        "[A-Z]{2,4}. Widening to {2,5} would also match any five-letter word followed "
        "by seven digits, so this is a real trade rather than an oversight -- but it "
        "is a trade nothing in the tuned corpus exposed.",
    ),
    "CLIENT_IDENTITY": (
        1,
        "spaCy PERSON again: only the surname of 'Margarethe Solheim' is returned, so "
        "the forename is left uncovered. The surname is still masked.",
    ),
    "ACCOUNT_NUMBER": (
        1,
        "'4400 8829 1374' is space-grouped, and the pattern's specificity comes from "
        "an unbroken 8-17 digit run. Card-style grouping is common; this is a real gap.",
    ),
}

# Every held-out value that IS masked, but by a detection carrying the wrong label:
# (entity_type, doc_id, value, labels that cover it). These are the shortfalls that
# leak nothing and mis-tier everything, and the ones the notes above are most likely
# to describe from memory.
#
# It is a table rather than a sentence because a sentence is exactly how this went
# wrong. The MRN note used to read "three of the shortfalls are masked anyway because
# spaCy happens to type a bare digit run as DATE_TIME or PERSON". Measured, it is two,
# both DATE, and no PERSON/NAME detection covers any held-out MRN at all -- the whole
# "or PERSON" branch describes something that never happens. Nothing in the file
# asserted any of it, so the number and the mechanism could both be wrong while the
# suite stayed green: the same shared silence as a docstring nobody can falsify.
#
# Asserted with ``==`` on purpose. ``<=`` on the count would have let the old sentence
# through (2 <= 3), and a subset check on the labels would have let "or PERSON"
# through as well. A documented mask that stops happening is a stale note, which is
# the defect being fixed here, so it has to fail too.
HELD_OUT_INCIDENTAL_MASKS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    # A dot-separated birth date reads as a phone number: PHONE '09.14.1958' @ 0.40.
    ("DOB", "ho_pt_visit", "09.14.1958", ("PHONE",)),
    # Bare 7-digit chart numbers, claimed by DATE @ 0.85. Never by PERSON.
    ("MRN", "ho_pathology", "2207731", ("DATE",)),
    ("MRN", "ho_pt_visit", "5518044", ("DATE",)),
    # DOB's span here is '09:15  Priyanka Raghunathan' -- a chat timestamp that ran on
    # into the speaker's name, so the name is masked as a birth date.
    ("NAME", "ho_chat_log", "Priyanka Raghunathan", ("DOB",)),
)


async def measure_held_out(
    detector: Detector, registry: EntityRegistry
) -> tuple[dict[str, list[int]], list[Residual], list[int]]:
    """Held-out tally and residual, plus the subtotal for values policy asks for.

    "In policy" means the annotated entity type is ``allowed_in`` that document's
    category. Everything else was never looked for, so counting it as a detection
    failure blames the detector for a deliberate scoping decision -- and dropping it
    silently would hide a value that really is in the clear. Both numbers are
    reported and the headline one is the conservative one.
    """
    return await measure_coverage(
        detector,
        HELD_OUT_CORPUS,
        in_scope=lambda entity_type, doc_category: registry.spec(entity_type).allowed_in(
            doc_category
        ),
    )


async def test_held_out_recall_meets_its_measured_floor(
    detector: Detector, registry: EntityRegistry
) -> None:
    """The number a reviewer should actually ask for: recall on unseen shapes.

    RECALL_CORPUS reports 99%, and that figure is honest about what it measures --
    the shapes this detector was built to handle. It is not evidence about a
    document nobody has seen, and quoting it as though it were is the most
    misleading thing this project could do.

    Measured here, on 53 documents in registers that appear nowhere above:
    88.5% covered and 87.4% typed, against 99%/99% on home turf. Restricted to the
    values the registry's document-category scoping actually asks for, 91.3%/90.1%.

    The eleven-point drop is the result, not a defect to be tuned away. Editing
    patterns until this table improves would destroy the only control the project
    has and leave two home-turf corpora behind it. Every gap it exposes is a
    property of a pattern or of spaCy rather than a corpus artefact, and each is
    named in HELD_OUT_MISS_SHAPES.
    """
    tally, residual, in_policy = await measure_held_out(detector, registry)
    covered_in_policy, typed_in_policy, total_in_policy = in_policy
    print("\nHELD-OUT (shapes nothing was tuned against)")
    print(format_recall_table(tally))
    print(
        f"{'IN-POLICY ONLY':<20}{total_in_policy:>5}"
        f"{covered_in_policy / total_in_policy:>8.0%}"
        f"{typed_in_policy / total_in_policy:>8.0%}"
    )
    print("\n".join(["", "held-out residual:", *(item.describe() for item in residual)]))

    assert set(tally) == set(HELD_OUT_COVERAGE_FLOORS), "corpus and floor table disagree"
    for entity_type, (covered, _typed, total) in sorted(tally.items()):
        assert covered / total >= HELD_OUT_COVERAGE_FLOORS[entity_type], (
            f"{entity_type} held-out coverage fell to {covered}/{total}"
        )

    total = sum(row[2] for row in tally.values())
    assert sum(row[0] for row in tally.values()) / total >= HELD_OUT_COVERAGE_FLOOR
    assert sum(row[1] for row in tally.values()) / total >= HELD_OUT_TYPED_FLOOR
    assert covered_in_policy / total_in_policy >= HELD_OUT_IN_POLICY_COVERAGE_FLOOR


async def test_held_out_residual_stays_inside_the_documented_shapes(
    detector: Detector, registry: EntityRegistry
) -> None:
    """Every held-out shortfall must be a failure that has already been named.

    An aggregate floor cannot see a change of shape: MRN could collapse while NAME
    improved and 88% would not move. This asserts the per-type inventory instead,
    with ``<=`` so that closing a gap passes and opening a new one -- an entity type
    that is not in the table at all, or one that gets worse -- fails.
    """
    _tally, residual, _in_policy = await measure_held_out(detector, registry)
    counts: dict[str, int] = {}
    for item in residual:
        counts[item.entity_type] = counts.get(item.entity_type, 0) + 1

    undocumented = sorted(set(counts) - set(HELD_OUT_MISS_SHAPES))
    assert undocumented == [], "\n".join(
        [
            f"held-out shortfalls in entity types with no documented cause: {undocumented}",
            *(item.describe() for item in residual if item.entity_type in undocumented),
        ]
    )
    for entity_type, count in sorted(counts.items()):
        ceiling, why = HELD_OUT_MISS_SHAPES[entity_type]
        assert count <= ceiling, f"{entity_type} shortfalls grew to {count} (was {ceiling}): {why}"


async def test_held_out_incidental_masks_are_exactly_the_documented_ones(
    detector: Detector, registry: EntityRegistry
) -> None:
    """The notes above say which shortfalls are masked by the wrong recognizer. Check it.

    The ceilings test one above counts shortfalls and cannot tell the two kinds
    apart: a value in the clear and a value masked under the wrong entity type both
    add one. The difference is the whole severity question -- ``Residual.covered``
    exists to record it -- and it is the part the prose kept getting wrong, because
    prose was all it was. The MRN note claimed three such masks "DATE_TIME or
    PERSON"; there are two, both DATE, and nothing in this corpus has ever produced
    a PERSON detection over an MRN.

    So the claim is a table now, and this is what makes it cost something to be
    wrong about. Equality in both directions: an undocumented new mask fails
    (something started masking that the notes do not explain), and a documented mask
    that stops happening fails too (the note has gone stale). The second half is not
    a test punishing an improvement -- it is the assertion that would have caught the
    sentence this replaces, and closing a gap here means editing HELD_OUT_MISS_SHAPES
    and this table in the same commit, which is the point. Re-measure and rewrite;
    never relax this to ``<=`` or to a subset check.

    Measurement comes from ``measure_held_out``, the same pass the ceilings and the
    printed table use, so the notes describe the run a reviewer sees rather than a
    second opinion computed alongside it.
    """
    _tally, residual, _in_policy = await measure_held_out(detector, registry)
    measured = tuple(
        sorted(
            (item.entity_type, item.doc_id, item.value, item.labels)
            for item in residual
            if item.covered
        )
    )
    assert measured == HELD_OUT_INCIDENTAL_MASKS, (
        "HELD_OUT_INCIDENTAL_MASKS no longer matches what the detector does.\n"
        f"measured: {measured}\ndocumented: {HELD_OUT_INCIDENTAL_MASKS}\n"
        "Re-measure and update the table AND the prose in HELD_OUT_MISS_SHAPES that "
        "describes it. Do not weaken this assertion."
    )

    mrn_labels = sorted(
        {
            label
            for entity_type, _doc, _value, labels in measured
            if entity_type == "MRN"
            for label in labels
        }
    )
    assert "PERSON" not in mrn_labels and "NAME" not in mrn_labels, (
        f"an MRN is now masked by a person detection: {mrn_labels}. The MRN note says "
        "this has never happened; if it now does, the note is wrong."
    )


async def test_held_out_clean_documents_produce_no_detections(detector: Detector) -> None:
    """Precision on unseen prose, where ground truth needs no adjudication.

    The recall drop above would be worthless as a finding if the detector had
    quietly become trigger-happy on unfamiliar registers -- a pattern that fires on
    everything scores well on coverage. It has not: zero spans over 17 entity-free
    documents in the same new registers.
    """
    spurious: list[str] = []
    words = 0
    for doc_id, doc_category, text in HELD_OUT_CLEAN_CORPUS:
        words += len(text.split())
        for found in await detector.detect(text, doc_category):
            spurious.append(f"{doc_id}: {found.entity_type} {found.text!r}")
    print(f"\nheld-out clean corpus: {len(HELD_OUT_CLEAN_CORPUS)} documents, {words} words")
    assert spurious == [], "\n".join(["false positives on unseen entity-free prose:", *spurious])


# DIAGNOSIS and MEDICATION are exempt from the disjointness rule below: both are
# matched from a closed, curated gazetteer of real clinical vocabulary, so the two
# corpora necessarily draw on the same few hundred terms. Requiring disjoint drug
# names would only push the held-out corpus towards rarer drugs, which measures the
# gazetteer's length rather than the detector's behaviour on unfamiliar shapes.
SHARED_VOCABULARY_TYPES = frozenset({"DIAGNOSIS", "MEDICATION"})


def test_held_out_corpus_shares_no_identifier_with_the_tuned_corpus() -> None:
    """"Held out" has to be structurally true, not merely intended.

    The comparison the section above rests on is worth nothing if the two corpora
    overlap, and overlap is exactly what happens when a later author "refreshes" the
    held-out set by copying rows across, or reuses a memorable identifier from
    upstairs. One value had in fact been carried over -- an AAA docket number -- and
    this assertion is what found it.
    """

    def annotated_values(corpus: list[tuple[str, str | None, str]]) -> set[tuple[str, str]]:
        return {
            (entity_type, value)
            for _doc_id, _category, annotated in corpus
            for entity_type, _start, _end, value in parse_annotated(annotated)[1]
            if entity_type not in SHARED_VOCABULARY_TYPES
        }

    shared = sorted(annotated_values(RECALL_CORPUS) & annotated_values(HELD_OUT_CORPUS))
    assert shared == [], f"the held-out corpus reuses tuned-corpus values: {shared}"

    tuned_ids = {doc_id for doc_id, _c, _a in RECALL_CORPUS} | {
        doc_id for doc_id, _c, _t in CLEAN_CORPUS
    }
    held_ids = {doc_id for doc_id, _c, _a in HELD_OUT_CORPUS} | {
        doc_id for doc_id, _c, _t in HELD_OUT_CLEAN_CORPUS
    }
    assert not tuned_ids & held_ids, "a document id appears in both corpora"
    assert len(held_ids) == len(HELD_OUT_CORPUS) + len(HELD_OUT_CLEAN_CORPUS), (
        "duplicate document id inside the held-out corpus"
    )


def test_held_out_corpus_exercises_every_spec_mandated_entity() -> None:
    """The unseen-shape figure has to cover the nine types section 2 mandates.

    A held-out corpus that happened to omit MRN would report a much better number
    while saying nothing at all about the type that turns out to fail hardest.
    """
    mandated = {
        "NAME",
        "SSN",
        "DOB",
        "EMAIL",
        "PHONE",
        "MRN",
        "DIAGNOSIS",
        "ACCOUNT_NUMBER",
        "CASE_ID",
    }
    counts: dict[str, int] = {}
    for _doc_id, _category, annotated in HELD_OUT_CORPUS:
        for entity_type, _start, _end, _value in parse_annotated(annotated)[1]:
            counts[entity_type] = counts.get(entity_type, 0) + 1
    thin = sorted(entity_type for entity_type in mandated if counts.get(entity_type, 0) < 5)
    assert thin == [], f"the held-out corpus needs at least 5 instances of each of {thin}"


# ---------------------------------------------------------------------------
# 2. Threshold policy
# ---------------------------------------------------------------------------
async def test_mid_confidence_span_is_returned_inside_the_redact_band(
    detector: Detector, settings: Settings
) -> None:
    """A bare 9-digit SSN with context is weak evidence: returned, but redact-band.

    The engine turns exactly this band into ``[REDACTED_SSN]`` with no vault entry,
    so the detector's job is to hand the score over rather than round it away.
    """
    hits = await detector.detect("Her SSN is 412337891 per the intake form.")
    ssn = [d for d in hits if d.entity_type == "SSN"]
    assert len(ssn) == 1
    assert settings.threshold_redact <= ssn[0].score < settings.threshold_obfuscate


def test_per_entity_threshold_override_moves_the_detector_floor(
    tmp_path: Path, settings: Settings
) -> None:
    """``threshold:`` is a documented registry field that no shipped entity sets.

    Nothing else in the suite exercises it, so replacing ``_floor_for``'s
    ``min(redact_floor, override)`` with the bare redact floor left every test
    green -- a documented extensibility knob with no behavioural proof, which is
    the same shape as config that does nothing at all. Asserted at the floor
    function rather than end to end because the interesting case is an override
    *below* the redact floor, and no fixture can be relied on to produce a
    detector score down there on demand.

    The semantics, from ``_floor_for``: an override below the redact floor lowers
    it, because the registry author asked for that entity at a lower confidence;
    an override above it does not raise it, because the band between redact and
    obfuscate is the engine's to turn into ``[REDACTED_<TYPE>]``.
    """
    path = tmp_path / "entities.yaml"
    path.write_text(
        "categories: [PII]\n"
        "entities:\n"
        "  LOW: {category: PII, patterns: ['\\bAAA\\d{4}\\b'], threshold: 0.1}\n"
        "  HIGH: {category: PII, patterns: ['\\bBBB\\d{4}\\b'], threshold: 0.9}\n"
        "  PLAIN: {category: PII, patterns: ['\\bCCC\\d{4}\\b']}\n",
        encoding="utf-8",
    )
    floors = Detector(load_registry(path), settings)._floor_for
    assert floors("LOW") == pytest.approx(0.1), "an override below the floor must lower it"
    assert floors("HIGH") == pytest.approx(settings.threshold_redact), "the floor is a floor"
    assert floors("PLAIN") == pytest.approx(settings.threshold_redact)
    assert settings.threshold_redact > 0.1, "fixture assumes the override sits below the floor"


async def test_below_floor_span_is_dropped(detector: Detector) -> None:
    """The same digits with no supporting context fall under the redact floor."""
    hits = await detector.detect("The ledger reference 412337891 was archived.")
    assert "SSN" not in types_of(hits)


async def test_every_returned_detection_clears_the_redact_floor(
    detector: Detector, settings: Settings
) -> None:
    text = (
        "Her SSN is 412-33-7891 and her email is jane.roe@example.com.\n\n"
        "Chart note: MRN: 4471902 filed today."
    )
    for detection in await detector.detect(text, "medical"):
        assert detection.score >= settings.threshold_redact


async def test_redact_band_reaches_the_obfuscated_text_end_to_end(
    detector: Detector, registry: EntityRegistry, settings: Settings
) -> None:
    """A real document, a real detector score, a real ``[REDACTED_SSN]``, no vault row.

    Section 9.2's three bands are only worth anything if they are observable from
    end to end. The engine's own band tests construct the ``Detection`` and set
    ``score=0.4`` by hand, which proves the engine's arithmetic but assumes the
    thing actually in question -- that a document exists whose *detector-assigned*
    score lands between the two thresholds. This starts from text.

    The document carries a strong SSN and a weak one. Both are the same entity
    type, so the split cannot come from configuration: the formatted
    ``412-33-7891`` scores above the obfuscate threshold and is tokenized and
    vaulted, while the bare nine-digit run scores inside the redact band and
    becomes an irreversible ``[REDACTED_SSN]`` with nothing written to the vault.
    Exactly one vault row for two SSN-shaped values is what "graceful degradation"
    means in practice, and it is the property the README's irreversibility note
    depends on.
    """
    text = (
        "Her SSN is 412-33-7891 on the signed form.\n\n"
        "A second SSN is 412337891 per the unverified intake sheet."
    )
    detections = await detector.detect(text)
    scores = {d.text: d.score for d in detections if d.entity_type == "SSN"}
    assert scores["412-33-7891"] >= settings.threshold_obfuscate
    assert settings.threshold_redact <= scores["412337891"] < settings.threshold_obfuscate

    sessions = SessionRegistry(settings)
    vault = await SessionVault.open(settings.data_dir / "vault.db", sessions)
    audit = await AuditLogger.open(settings.data_dir / "audit.db")
    try:
        session_id, _expires = await sessions.create("threshold-band-user")
        engine = ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=settings,
            audit=audit,
        )
        result = await engine.obfuscate(session_id, text, detections)

        assert "[REDACTED_SSN]" in result.obfuscated_text
        assert "412337891" not in result.obfuscated_text, "redact band left the value in the clear"
        assert "412-33-7891" not in result.obfuscated_text, "obfuscate band left the value"
        # One vault row: the obfuscated value. The redacted one is unrecoverable.
        assert await vault.row_count(session_id) == 1
        assert [token.entity_type for token in result.tokens] == ["SSN"]
        assert [r.entity_type for r in result.redactions] == ["SSN"]
    finally:
        await vault.close()
        await audit.close()


# ---------------------------------------------------------------------------
# 3. Chunking keeps absolute offsets
# ---------------------------------------------------------------------------
FILLER_PARAGRAPH = (
    "Operational notes continue with routine scheduling details and no identifiers "
    "of any kind in this paragraph whatsoever. " * 8
).strip()


def _long_document() -> str:
    """A document whose last paragraph starts well past the 8,000-char chunk limit."""
    body = "\n\n".join(FILLER_PARAGRAPH for _ in range(12))
    return body + "\n\nChart note: MRN: 4471902 was filed by the records desk."


def test_chunking_reconstructs_the_document_exactly(settings: Settings) -> None:
    text = _long_document()
    chunks = chunk_text(text, settings.chunk_max_chars)
    assert len(chunks) > 1
    assert all(len(body) <= settings.chunk_max_chars for _, body in chunks)
    assert "".join(body for _, body in chunks) == text
    for offset, body in chunks:
        assert text[offset : offset + len(body)] == body


@pytest.mark.parametrize(
    ("label", "unit"),
    [
        ("crlf", "Chart note. MRN: 4471902 filed.\r\n\r\nPrescribed metformin 500 mg.\r\n"),
        ("utf8", "Zoë Bäcker 😀 seen today. Ω-lab drawn.\n\n"),
        ("no-boundary", "x" * 97 + ". "),
        ("blank-only", "\n \n\t\n"),
        ("newlines-only", "\n" * 13),
        ("tabs", "a\tb\t\tc.\n\n"),
    ],
)
@pytest.mark.parametrize("max_chars", [1, 2, 3, 7, 50, 8000])
@pytest.mark.parametrize("repeats", [1, 5, 40])
def test_chunking_is_lossless_under_adversarial_encodings(
    label: str, unit: str, max_chars: int, repeats: int
) -> None:
    """CRLF, astral-plane characters and degenerate whitespace must not move offsets.

    ``chunk_text`` output is the basis of every absolute offset, so its two
    invariants -- exact reconstruction and ``text[offset:offset+len] == chunk`` --
    are asserted directly rather than inferred from a detection landing in the right
    place. CRLF matters in particular: ``\\r\\n\\r\\n`` is not a paragraph break to
    the splitter, so a CRLF document takes the oversized-paragraph fallback path.
    """
    text = unit * repeats
    chunks = chunk_text(text, max_chars)
    assert "".join(body for _, body in chunks) == text
    for offset, body in chunks:
        assert text[offset : offset + len(body)] == body
        assert len(body) <= max_chars


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("utf8", "Zoë Bäcker 😀 seen today. Chart note: MRN: 4471902 filed.\n\n"
                 "Prescribed metformin 500 mg. Her SSN is 412-33-7891."),
        ("crlf", "Patient JANE DOE\r\n\r\nChart note: MRN: 4471902 filed.\r\n\r\n"
                 "Prescribed metformin 500 mg.\r\n"),
        ("astral-heavy", "😀" * 50 + "\r\nMRN: 4471902\r\n" + "Ω" * 50 + " metformin 500 mg"),
    ],
)
async def test_offsets_survive_multibyte_and_crlf_documents(
    detector: Detector, label: str, text: str
) -> None:
    hits = await detector.detect(text, "medical")
    assert hits, "fixture should detect something"
    for detection in hits:
        assert text[detection.start : detection.end] == detection.text
    assert uncovered(text, hits, "4471902") == ""


def test_chunking_splits_a_single_oversized_paragraph(settings: Settings) -> None:
    """No blank lines at all: the sentence/newline fallback has to carry it."""
    text = "This sentence has no paragraph breaks anywhere. " * 400
    chunks = chunk_text(text, settings.chunk_max_chars)
    assert len(chunks) > 1
    assert all(len(body) <= settings.chunk_max_chars for _, body in chunks)
    assert "".join(body for _, body in chunks) == text


# A run with no sentence end and no blank line, so chunk_text has no soft boundary
# to cut on and must hard-cut at exactly ``max_chars`` -- straight through whatever
# sits there.
_UNBROKEN_FILLER = "the patient was seen and evaluated in clinic, "
_STRADDLE_LIMIT = 400
_STRADDLE_ENTITY = "MRN: 4471902"


def _straddling_document(chars_before_the_cut: int) -> tuple[str, int]:
    """A document whose hard chunk cut falls *inside* ``MRN: 4471902``.

    The filler is trimmed to end on a space so the label keeps its leading word
    boundary; truncating mid-word would make the fixture fail for a reason that has
    nothing to do with chunking.
    """
    prefix_len = _STRADDLE_LIMIT - chars_before_the_cut
    repeats = prefix_len // len(_UNBROKEN_FILLER) + 1
    filler = (_UNBROKEN_FILLER * repeats)[: prefix_len - 1] + " "
    return filler + _STRADDLE_ENTITY + " was filed by the records desk", prefix_len


@pytest.mark.parametrize("chars_before_the_cut", [1, 4, 6, 9, 11])
async def test_entity_straddling_a_chunk_boundary_is_detected_whole(
    settings: Settings, registry: EntityRegistry, chars_before_the_cut: int
) -> None:
    """A chunk cut through an entity used to truncate it or lose it entirely.

    Chunks are analysed independently, so the cut split ``MRN: 4471902`` in two:
    with 6 characters left before the boundary the pattern matched the truncated
    ``MRN: 447190`` and the trailing ``2`` went out in the clear, and with fewer
    digits left it matched nothing at all and the whole identifier did.
    """
    text, entity_at = _straddling_document(chars_before_the_cut)
    scoped = settings.model_copy(update={"chunk_max_chars": _STRADDLE_LIMIT})
    cuts = [offset for offset, _ in chunk_text(text, _STRADDLE_LIMIT)]
    assert entity_at < _STRADDLE_LIMIT < entity_at + len(_STRADDLE_ENTITY)
    assert _STRADDLE_LIMIT in cuts, "fixture must actually straddle a chunk boundary"

    hits = await Detector(registry, scoped).detect(text, "medical")

    mrn = [d for d in hits if d.entity_type == "MRN"]
    assert len(mrn) == 1, "the straddling entity was lost or duplicated"
    assert (mrn[0].start, mrn[0].end) == (entity_at, entity_at + len(_STRADDLE_ENTITY))
    assert mrn[0].text == _STRADDLE_ENTITY
    assert uncovered(text, hits, _STRADDLE_ENTITY) == ""


# A literal prefix like "medical record number" or "our negotiation strategy" sits
# in front of the bounded part of a pattern and contributes to the matched span
# without appearing in any quantifier. 64 characters is comfortably above the
# longest such prefix in the registry.
LITERAL_PREFIX_ALLOWANCE = 64


def test_chunk_overlap_exceeds_the_longest_registry_span(registry: EntityRegistry) -> None:
    """The overlap window only works if it is wider than anything that can match.

    A straddling entity is matched whole only if some chunk's analysis window
    contains all of it, so ``CHUNK_OVERLAP_CHARS`` has to exceed the longest span
    the registry can produce. This pins that relationship so a future
    ``{0,400}`` tail fails here rather than silently reintroducing boundary
    truncation.

    The bound summed per pattern, not maximised: a pattern with two quantifiers
    can produce a span as long as both together. The previous form took a plain
    ``max`` and reassigned it inside the loop, so it reported whichever pattern
    happened to be declared last rather than the widest one -- it passed for the
    same reason a broken clock does.
    """
    import re as _re

    widest = 0
    for spec in registry.entities.values():
        for pattern in spec.patterns:
            bounds = [int(bound) for bound in _re.findall(r"\{\d+,(\d+)\}", pattern)]
            widest = max(widest, sum(bounds) + LITERAL_PREFIX_ALLOWANCE)
    assert 0 < widest < CHUNK_OVERLAP_CHARS, f"widest registry span {widest} needs a wider overlap"


# The overlap widens each chunk's analysis window, so the analyser sees more than the
# document. ``detect`` caps it at one chunk -- ``min(CHUNK_OVERLAP_CHARS,
# chunk_max_chars)`` -- which bounds that at twice the document however small the
# chunk size is configured. Measured with the cap in place: 2.05x. With it removed
# and ``chunk_max_chars`` at 64: 8.86x. 3.0 separates the two with room on each side.
ANALYSIS_BUDGET_RATIO = 3.0


async def test_the_analysis_window_never_scans_the_document_more_than_twice_over(
    registry: EntityRegistry, settings: Settings
) -> None:
    """``chunk_max_chars`` below ``CHUNK_OVERLAP_CHARS`` must not multiply the work.

    Every chunk is analysed over a window running ``overlap`` characters into the
    next one, so the total text handed to spaCy is the document plus one overlap per
    chunk. With a small ``chunk_max_chars`` there are many chunks, and without the
    cap each still drags a full 512-character tail: at 64 the analyser processes the
    document nearly nine times over, which is a self-inflicted denial of service on
    the one code path that is CPU-bound and configurable.

    Nothing tested this. ``chunk_max_chars`` is 8,000 by default and the cap only
    binds below 512, so deleting ``min(...)`` left all 277 tests green -- the fix was
    real, load-bearing under a supported configuration, and completely unproven.
    Asserted as a ratio to the document length rather than as a time, so it measures
    the work done rather than how busy the machine is.
    """
    text = ("Operational notes continue with routine scheduling details. " * 60) + (
        "Chart note: MRN: 4471902 filed by the records desk."
    )
    scoped = settings.model_copy(update={"chunk_max_chars": 64})
    assert scoped.chunk_max_chars < CHUNK_OVERLAP_CHARS, "fixture must make the cap bind"
    detector = Detector(registry, scoped)

    analysed: list[int] = []
    unpatched = detector._analyze_sync

    def spy(body: str, entities: tuple[str, ...]) -> list[object]:
        analysed.append(len(body))
        return unpatched(body, entities)

    detector._analyze_sync = spy  # type: ignore[method-assign]
    hits = await detector.detect(text, "medical")

    assert "MRN" in types_of(hits), "the fixture must still detect across the tiny chunks"
    assert sum(analysed) <= ANALYSIS_BUDGET_RATIO * len(text), (
        f"analysed {sum(analysed)} characters of a {len(text)}-character document "
        f"({sum(analysed) / len(text):.2f}x) across {len(analysed)} chunks"
    )


async def test_entity_past_a_paragraph_boundary_keeps_absolute_offsets(
    detector: Detector, settings: Settings
) -> None:
    text = _long_document()
    mrn_at = text.index("MRN")
    assert mrn_at > settings.chunk_max_chars, "fixture must place the entity in a later chunk"

    hits = await detector.detect(text, "medical")
    mrn = [d for d in hits if d.entity_type == "MRN"]
    assert len(mrn) == 1
    assert mrn[0].start == mrn_at
    for detection in hits:
        assert text[detection.start : detection.end] == detection.text


# ---------------------------------------------------------------------------
# 4. only_in_doc_categories
# ---------------------------------------------------------------------------
async def test_amount_fires_only_in_financial_documents(detector: Detector) -> None:
    text = "The payment of $4,250.00 cleared."
    assert "AMOUNT" in types_of(await detector.detect(text, "financial"))
    assert "AMOUNT" not in types_of(await detector.detect(text, "general"))
    assert "AMOUNT" not in types_of(await detector.detect(text, None))


async def test_case_strategy_fires_only_in_legal_documents(detector: Detector) -> None:
    text = "Our litigation strategy is to delay the deposition."
    assert "CASE_STRATEGY" in types_of(await detector.detect(text, "legal"))
    assert "CASE_STRATEGY" not in types_of(await detector.detect(text, "general"))
    assert "CASE_STRATEGY" not in types_of(await detector.detect(text, "medical"))


# ---------------------------------------------------------------------------
# 5. DOB vs DATE (build doc section 9.2)
# ---------------------------------------------------------------------------
async def test_date_with_birth_context_is_dob_in_a_medical_document(
    detector: Detector,
) -> None:
    hits = await detector.detect("Patient DOB: 1985-03-12 confirmed at intake.", "medical")
    assert "DOB" in types_of(hits)
    assert "DATE" not in types_of(hits)


async def test_date_with_birth_context_is_dob_in_a_general_document(
    detector: Detector,
) -> None:
    hits = await detector.detect("She was born on March 12, 1985 in Ohio.", "general")
    assert "DOB" in types_of(hits)


async def test_bare_date_in_a_medical_document_is_date(detector: Detector) -> None:
    hits = await detector.detect("The follow-up visit is on 2024-05-06.", "medical")
    assert "DATE" in types_of(hits)
    assert "DOB" not in types_of(hits)


async def test_bare_date_in_a_general_document_is_dropped(detector: Detector) -> None:
    hits = await detector.detect("The follow-up visit is on 2024-05-06.", "general")
    assert "DATE" not in types_of(hits)
    assert "DOB" not in types_of(hits)


# ---------------------------------------------------------------------------
# 6. PERSON remapping
# ---------------------------------------------------------------------------
async def test_person_is_client_identity_in_a_legal_document(detector: Detector) -> None:
    hits = await detector.detect("Jane Doe signed the retainer agreement today.", "legal")
    assert "CLIENT_IDENTITY" in types_of(hits)
    assert "NAME" not in types_of(hits)


@pytest.mark.parametrize("doc_category", [None, "general", "medical", "financial"])
async def test_person_is_name_outside_a_legal_document(
    detector: Detector, doc_category: str | None
) -> None:
    hits = await detector.detect("Jane Doe signed the retainer agreement today.", doc_category)
    assert "NAME" in types_of(hits)
    assert "CLIENT_IDENTITY" not in types_of(hits)


@pytest.mark.parametrize("order", [("ALPHA_NAME", "BETA_NAME"), ("BETA_NAME", "ALPHA_NAME")])
async def test_tied_claimants_resolve_in_registry_declaration_order(
    tmp_path: Path, settings: Settings, order: tuple[str, str]
) -> None:
    """Two entities claiming one built-in with nothing to separate them must not coin-flip.

    ``_resolve_builtin`` scores claimants on context and document scoping and
    breaks the remaining tie on declaration order. The shipped registry never
    reaches that tie -- ``DOB``/``DATE`` and ``NAME``/``CLIENT_IDENTITY`` are
    always separated by one of the two scores -- so it is reachable only once
    someone adds a second claimant by config, which is exactly what section 10.4
    invites, and a label that depended on dict iteration order would make the
    pseudonymization tier non-deterministic across runs.

    Parametrized on both declaration orders so the assertion cannot be satisfied
    by alphabetical order or by whichever name happens to hash first.

    What this test does **not** establish is that ``_declaration_order`` is the
    mechanism producing the answer. It is not: ``presidio_aliases`` already returns
    claimants in declaration order and the comparison is a strict ``<``, so the
    first claimant iterated wins any tie whether or not the key mentions
    declaration order at all. Replacing that key with a constant leaves this test
    green -- measured, not supposed. The test below removes that agreement and is
    the one that makes the key load-bearing.
    """
    first, second = order
    path = tmp_path / "entities.yaml"
    path.write_text(
        "categories: [PII]\nentities:\n"
        f"  {first}: {{category: PII, presidio: PERSON}}\n"
        f"  {second}: {{category: PII, presidio: PERSON}}\n",
        encoding="utf-8",
    )
    hits = await Detector(load_registry(path), settings).detect("Jane Doe signed today.")
    assert types_of(hits) == {first}, f"{second} took a hit declared second"


@pytest.mark.parametrize("order", [("ALPHA_NAME", "BETA_NAME"), ("BETA_NAME", "ALPHA_NAME")])
async def test_declaration_order_wins_even_when_claimants_arrive_reversed(
    tmp_path: Path, settings: Settings, order: tuple[str, str]
) -> None:
    """The tie-break must come from the registry, not from iteration order.

    Two independent things currently give the same answer, and the test above
    cannot tell them apart: ``_resolve_builtin``'s ``(-score, declaration_order)``
    key, and the plain fact that ``presidio_aliases`` hands back claimants in the
    order the YAML declared them. So the explicit key looked proven and was not --
    swapping ``self._declaration_order[name]`` for the constant ``0`` leaves every
    other test in this file passing.

    That is the "correct only by accident" shape: the guard is real, the agreement
    that hides its absence is incidental, and the day something reorders that
    tuple -- a registry accessor that sorts, a refactor that routes through a set,
    a caller that builds aliases itself -- the label silently starts depending on
    whatever order fell out. Reversing the alias tuple here removes the accidental
    agreement, so declaration order is the only thing left that can produce the
    answer, and the constant tie-break fails.
    """
    first, second = order
    path = tmp_path / "entities.yaml"
    path.write_text(
        "categories: [PII]\nentities:\n"
        f"  {first}: {{category: PII, presidio: PERSON}}\n"
        f"  {second}: {{category: PII, presidio: PERSON}}\n",
        encoding="utf-8",
    )
    detector = Detector(load_registry(path), settings)
    assert detector._aliases["PERSON"] == (first, second), (
        "fixture assumes aliases start in declaration order"
    )
    detector._aliases = {
        builtin: tuple(reversed(claimants))
        for builtin, claimants in detector._aliases.items()
    }

    hits = await detector.detect("Jane Doe signed today.")
    assert types_of(hits) == {first}, (
        f"{second} took the hit: the winner followed claimant order, not declaration order"
    )


# ---------------------------------------------------------------------------
# 7. Detector detects strip/redact entities; the engine acts on them later
# ---------------------------------------------------------------------------
# Every document reaching this pipeline has been through the text extractor, and
# PDF, DOCX and TXT all arrive hard-wrapped. The build doc's '[^.\n]{0,120}' tail
# ends a span at the first newline, so on a wrapped document a `redact` entity
# covered only the first line of its own sentence and shipped the rest.
HARD_WRAPPED_STRATEGY = (
    "Memorandum.\n\n"
    "We should to depose their economist before the mediation window\n"
    "closes and then revisit the causation defence with our expert.\n\n"
    "Unrelated scheduling follows."
)


async def test_case_strategy_covers_a_hard_wrapped_sentence(detector: Detector) -> None:
    hits = await detector.detect(HARD_WRAPPED_STRATEGY, "legal")
    tail = "closes and then revisit the causation defence with our expert"
    assert uncovered(HARD_WRAPPED_STRATEGY, hits, tail) == "", (
        "the second line of a wrapped strategy sentence went out in the clear"
    )


async def test_case_strategy_stops_at_a_blank_line(detector: Detector) -> None:
    """Tolerating a soft wrap must not let the redaction run into the next paragraph."""
    hits = await detector.detect(HARD_WRAPPED_STRATEGY, "legal")
    strategy = [d for d in hits if d.entity_type == "CASE_STRATEGY"]
    assert len(strategy) == 1
    assert "Unrelated scheduling follows." not in strategy[0].text


async def test_lab_result_keeps_two_analytes_apart(detector: Detector) -> None:
    """A greedy tail merged both analytes into one span and dropped the second value."""
    text = "Your LDL is 162 and your A1C came back at 7.4 today."
    hits = await detector.detect(text, "medical")
    assert len(spans_of(hits, "LAB_RESULT")) == 2
    assert uncovered(text, hits, "7.4") == ""


async def test_privileged_marker_and_case_strategy_are_detected(
    detector: Detector, registry: EntityRegistry
) -> None:
    text = (
        "ATTORNEY-CLIENT PRIVILEGED AND CONFIDENTIAL\n\n"
        "Our negotiation posture is to hold firm until the mediation date."
    )
    hits = await detector.detect(text, "legal")
    found = types_of(hits)
    assert "PRIVILEGED_MARKER" in found
    assert "CASE_STRATEGY" in found
    # The registry still carries the engine-level policy for both.
    assert registry.action_of("PRIVILEGED_MARKER") is not None
    assert registry.action_of("CASE_STRATEGY") is not None


# ---------------------------------------------------------------------------
# 8. Sorted, strictly non-overlapping output
# ---------------------------------------------------------------------------
async def test_output_is_sorted_and_non_overlapping(detector: Detector) -> None:
    """SETTLEMENT_TERM and AMOUNT both claim the dollar figure; one span survives."""
    text = "The settlement payment of $50,000.00 was wired on 2024-05-06 by Jane Doe."
    hits = await detector.detect(text, "financial")

    assert hits == sorted(hits, key=lambda d: d.start)
    for earlier, later in pairwise(hits):
        assert earlier.end <= later.start, "overlapping spans escaped resolution"

    assert "SETTLEMENT_TERM" in types_of(hits)
    assert "AMOUNT" not in types_of(hits), "the shorter overlapping claim should lose"

    # Control: AMOUNT does fire in the same document category without the rival span.
    control = await detector.detect("The wire of $50,000.00 was posted.", "financial")
    assert "AMOUNT" in types_of(control)


async def test_repeated_markers_produce_disjoint_spans(detector: Detector) -> None:
    text = "ATTORNEY-CLIENT PRIVILEGED AND CONFIDENTIAL - work product enclosed."
    hits = await detector.detect(text, "legal")
    markers = spans_of(hits, "PRIVILEGED_MARKER")
    assert len(markers) >= 2
    for (_, first_end), (second_start, _) in pairwise(markers):
        assert first_end <= second_start


# ---------------------------------------------------------------------------
# 8b. Overlap resolution must never leave detected text uncovered
# ---------------------------------------------------------------------------
# Ranking decides which label survives an overlap. It must not decide whether the
# text is protected: a winner that only *partially* overlaps the loser used to drop
# the loser outright, and the loser's uncovered remainder went to the provider in
# the clear.
LEAKY_STRATEGY_DOC = (
    "We should to press the causation defence at the hearing, keep our damages "
    "expert on reserve, and avoid concession before we depose Priyanka "
    "Raghunathan, their economist."
)


async def test_case_strategy_truncation_does_not_leak_the_client_name(
    detector: Detector,
) -> None:
    """CASE_STRATEGY's bounded tail stops one character into the client's name.

    It therefore overlaps CLIENT_IDENTITY without containing it. Dropping the name
    on the strength of the strategy span's rank shipped
    ``[REDACTED_CASE_STRATEGY]riyanka Raghunathan`` to the provider.
    """
    hits = await detector.detect(LEAKY_STRATEGY_DOC, "legal")
    assert uncovered(LEAKY_STRATEGY_DOC, hits, "Priyanka Raghunathan") == ""


async def test_no_detected_span_is_left_partially_uncovered(detector: Detector) -> None:
    """The kept set must cover every span the analyzer proposed, not just the winners."""
    docs = [
        (LEAKY_STRATEGY_DOC, "legal"),
        ("Our settlement posture is to open low and hold until we depose "
         "their damages expert Bartholomew Fitzgerald-Hume at the hearing.", "legal"),
        ("The settlement payment of $50,000.00 was wired on 2024-05-06 by Jane Doe.",
         "financial"),
    ]
    for text, category in docs:
        hits = await detector.detect(text, category)
        for earlier, later in pairwise(hits):
            assert earlier.end <= later.start
        for detection in hits:
            assert text[detection.start : detection.end] == detection.text


def test_resolve_overlaps_absorbs_a_partially_overlapping_loser() -> None:
    """Unit-level: the loser widens the winner instead of vanishing.

    ``winner`` outranks ``loser`` on score but stops 4 characters into it. Before the
    fix ``loser`` was dropped and ``BBBB`` survived in the clear.
    """
    text = "AAAAAAAAAABBBBBBBBBB"
    winner = Detection(
        entity_type="CASE_STRATEGY", category="LEGAL", start=0, end=14, text=text[0:14], score=0.7
    )
    loser = Detection(
        entity_type="CLIENT_IDENTITY", category="LEGAL", start=10, end=20, text=text[10:20],
        score=0.85,
    )
    kept = _resolve_overlaps(text, [winner, loser], frozenset({"CASE_STRATEGY"}))

    assert len(kept) == 1
    assert (kept[0].start, kept[0].end) == (0, 20), "the union must be covered"
    assert kept[0].text == text
    # The policy label wins the ranking, exactly as before.
    assert kept[0].entity_type == "CASE_STRATEGY"
    assert uncovered(text, kept, "BBBBBBBBBB") == ""


def test_resolve_overlaps_gives_the_label_to_the_span_that_covers_the_union() -> None:
    """A higher-scoring *fragment* must not take the label off the entity around it.

    Chunk-boundary windows produce exactly this: spaCy reads the bare digits of a
    clipped ``MRN: 4471902`` as DATE_TIME at 0.85, which outranks the 0.7 pattern hit
    on the whole identifier. Merging on rank alone would label the identifier DATE.
    """
    text = "Chart MRN: 4471902 filed."
    fragment = Detection(
        entity_type="DATE", category="PHI", start=11, end=18, text=text[11:18], score=0.85
    )
    whole = Detection(
        entity_type="MRN", category="PHI", start=6, end=18, text=text[6:18], score=0.7
    )
    kept = _resolve_overlaps(text, [fragment, whole])

    assert len(kept) == 1
    assert kept[0].entity_type == "MRN"
    assert (kept[0].start, kept[0].end) == (6, 18)
    assert kept[0].text == "MRN: 4471902"


def test_resolve_overlaps_prefers_a_registry_pattern_over_a_general_ner_label() -> None:
    """A hand-written pattern keeps its label against a lower-specificity guess.

    Presidio scores every spaCy ``PERSON``/``DATE_TIME`` hit a flat 0.85 and a
    registry pattern 0.70, so on score alone the general-purpose guess always wins
    the label. It also frequently covers the *wider* span -- spaCy reads "Email
    awhitlock@..." as one PERSON -- which defeats the union-covering rule too.
    Neither is a leak, since the union is masked either way, but the label chooses
    the pseudonymization tier, so the outcome here decides whether an e-mail
    address is replaced by a fake person's name.
    """
    text = "Email awhitlock@mailer.example for details."
    general = Detection(
        entity_type="NAME", category="PII", start=0, end=30, text=text[0:30], score=0.85
    )
    specific = Detection(
        entity_type="EMAIL", category="PII", start=6, end=30, text=text[6:30], score=0.70
    )
    kept = _resolve_overlaps(text, [general, specific], frozenset(), frozenset({"EMAIL"}))

    assert len(kept) == 1
    assert kept[0].entity_type == "EMAIL"
    # Still the union: specificity decides the label, never the coverage.
    assert (kept[0].start, kept[0].end) == (0, 30)
    assert uncovered(text, kept, "awhitlock@mailer.example") == ""


def test_policy_action_still_outranks_a_registry_pattern() -> None:
    """The two categorical dimensions are ordered, and policy comes first."""
    text = "We should to wire $50,000 to settle the claim by Friday."
    strategy = Detection(
        entity_type="CASE_STRATEGY", category="LEGAL", start=0, end=25, text=text[0:25], score=0.70
    )
    amount = Detection(
        entity_type="AMOUNT", category="FIN", start=18, end=25, text=text[18:25], score=0.70
    )
    kept = _resolve_overlaps(
        text,
        [strategy, amount],
        frozenset({"CASE_STRATEGY"}),
        frozenset({"CASE_STRATEGY", "AMOUNT"}),
    )

    assert [d.entity_type for d in kept] == ["CASE_STRATEGY"]


def test_resolve_overlaps_leaves_contained_and_disjoint_spans_alone() -> None:
    """Absorption must not fire when the winner already contains the loser."""
    text = "The settlement demand of $250,000 was rejected."
    outer = Detection(
        entity_type="SETTLEMENT_TERM", category="LEGAL", start=4, end=33, text=text[4:33], score=0.7
    )
    inner = Detection(
        entity_type="AMOUNT", category="FIN", start=25, end=33, text=text[25:33], score=0.7
    )
    apart = Detection(
        entity_type="NAME", category="PII", start=37, end=45, text=text[37:45], score=0.85
    )
    kept = _resolve_overlaps(text, [outer, inner, apart])

    assert [(d.entity_type, d.start, d.end) for d in kept] == [
        ("SETTLEMENT_TERM", 4, 33),
        ("NAME", 37, 45),
    ]
    assert all(text[d.start : d.end] == d.text for d in kept)


# ---------------------------------------------------------------------------
# 9. Gazetteer class hints (Tier-3 annotated tokens)
# ---------------------------------------------------------------------------
def test_class_hint_for_known_medication(registry: EntityRegistry) -> None:
    assert class_hint_for(registry, "MEDICATION", "metformin") == "oral-antidiabetic"
    assert class_hint_for(registry, "MEDICATION", "Metformin") == "oral-antidiabetic"


def test_class_hint_for_known_diagnosis(registry: EntityRegistry) -> None:
    assert class_hint_for(registry, "DIAGNOSIS", "Type 2 Diabetes") == "endocrine-metabolic"
    assert class_hint_for(registry, "DIAGNOSIS", "  type   2\tdiabetes ") == "endocrine-metabolic"


def test_class_hint_for_unknown_term_and_non_gazetteer_entity(registry: EntityRegistry) -> None:
    assert class_hint_for(registry, "MEDICATION", "metforminol") is None
    assert class_hint_for(registry, "DIAGNOSIS", "seasonal wanderlust") is None
    assert class_hint_for(registry, "NAME", "metformin") is None
    assert class_hint_for(registry, "MRN", "metformin") is None


def test_every_recognizer_pattern_is_compiled_before_any_request(
    registry: EntityRegistry,
) -> None:
    """``_precompile`` has to actually compile, not merely be called.

    ``PatternRecognizer`` compiles a ``Pattern`` lazily inside ``analyze()`` and
    caches the result on the shared object, and chunks are analysed from four
    worker threads -- so the compile has to happen at construction or four threads
    race to write the same attribute mid-request. Removing ``_precompile``
    entirely leaves every other test green, because lazy compilation still
    produces the right answer; only the race disappears. Asserting on the
    ``compiled_regex`` attribute is what makes the call load-bearing.
    """
    from secure_context_pipeline.detection.recognizers import build_recognizers

    recognizers = build_recognizers(registry)
    assert recognizers, "the registry should produce recognizers"
    uncompiled = [
        f"{recognizer.name}/{pattern.name}"
        for recognizer in recognizers
        for pattern in recognizer.patterns
        if getattr(pattern, "compiled_regex", None) is None
    ]
    assert uncompiled == [], f"patterns left to compile mid-request: {uncompiled}"


async def test_a_bare_gazetteer_hit_is_still_strong_enough_to_tokenize(
    detector: Detector, settings: Settings
) -> None:
    """``GAZETTEER_SCORE`` decides tokenize-vs-redact, and nothing pinned its value.

    The pattern side of this has a guard --
    ``test_context_words_boost_a_pattern_hit`` ends by asserting a bare pattern hit
    still clears ``threshold_obfuscate`` -- and the gazetteer side, which starts
    from a *different* constant, had none. That asymmetry is the whole bug: the two
    constants were silently assumed to move together and only one of them was
    watched.

    What the missing half costs, measured: dropping ``GAZETTEER_SCORE`` from 0.80 to
    0.45 leaves all 285 tests green, and 0.45 lands between ``threshold_redact``
    (0.30) and ``threshold_obfuscate`` (0.50). Every diagnosis and medication
    mentioned without a nearby context word would stop being a reversible Tier-3
    token and become an irreversible ``[REDACTED_DIAGNOSIS]`` with no vault row --
    the class-annotated token that section 9.3 exists for, gone, with nothing red.

    The fixture deliberately carries no DIAGNOSIS context word ("diagnosis", "dx",
    "condition", "present"), so the score observed here is the bare constant rather
    than a context-enhanced 1.00 that would pass whatever the constant became.
    """
    hits = await detector.detect("The problem list records pneumonia.", "medical")
    diagnosis = [d for d in hits if d.entity_type == "DIAGNOSIS"]
    assert len(diagnosis) == 1, "fixture should produce exactly one gazetteer hit"
    assert diagnosis[0].score == pytest.approx(GAZETTEER_SCORE), (
        "fixture picked up a context boost, so it no longer measures the bare score"
    )
    assert diagnosis[0].score >= settings.threshold_obfuscate, (
        "a curated-term hit must be tokenized, not silently downgraded to a redaction"
    )

    # An exact match against a curated clinical list is stronger evidence than a
    # shape-based regex, and score is what breaks the tie once the two categorical
    # dimensions in _resolve_overlaps agree -- which they do for any two custom
    # recognizers. Asserted as a relationship rather than behaviourally because no
    # document in either corpus overlaps a gazetteer hit with a pattern hit, so
    # there is nothing honest to measure it on; the ordering is a design invariant
    # and this is what stops the two constants drifting past each other unnoticed.
    assert GAZETTEER_SCORE > PATTERN_SCORE


def test_gazetteers_are_parsed_once_and_skip_comments() -> None:
    first = load_gazetteer("medications.txt")
    assert first is load_gazetteer("medications.txt"), "gazetteer cache missed"
    assert not any(term.startswith("#") for term in first)
    assert all(term == term.casefold() for term in first)
    # Longest first, so multi-word terms win the alternation.
    lengths = [len(term) for term in gazetteer_terms("diagnoses.txt")]
    assert lengths == sorted(lengths, reverse=True)


# Build doc section 9.2 sets the coverage target: ~150 medications, ~100 diagnoses.
GAZETTEER_FLOORS = {"medications.txt": 150, "diagnoses.txt": 100}


@pytest.mark.parametrize("filename", sorted(GAZETTEER_FLOORS))
def test_every_gazetteer_line_survives_parsing(filename: str) -> None:
    """The parsed table must account for every content line in the file.

    This replaces an assertion on an exact term count. The count was incidental --
    it had to be edited whenever anyone added a drug, which is the friction that
    eventually gets "fixed" by loosening the assertion into a meaningless floor.
    Tying the table back to the file catches strictly more: a term silently dropped
    for a missing tab, a duplicate key shadowing an earlier entry, a parser that
    starts eating content lines. The build doc's coverage target is asserted
    separately as a floor, which is the only thing the number was ever standing in
    for.
    """
    raw = (GAZETTEER_DIR / filename).read_text(encoding="utf-8")
    content_lines = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    table = load_gazetteer(filename)

    assert len(table) >= GAZETTEER_FLOORS[filename], "coverage fell below the build doc target"
    assert len(table) == len(content_lines), "a content line did not become a table entry"
    assert len({line.split("\t")[0] for line in content_lines}) == len(content_lines), (
        "duplicate term -- the later entry silently shadows the earlier one"
    )
    for line in content_lines:
        term, tab, hint = line.partition("\t")
        assert tab, f"{term!r} has no class-hint column"
        assert term == term.casefold(), f"{term!r} is not stored casefolded"
        assert hint and hint == hint.strip(), f"{term!r} has a blank or padded class hint"
        # The hint is emitted verbatim inside a Tier-3 token, so it has to stay
        # short and stay inside the surrogate grammar's annotation alphabet.
        assert len(hint) <= 24, f"{term!r} class hint is too long for a token annotation"
        assert re.fullmatch(r"[a-z0-9-]+", hint), f"{term!r} class hint is not [a-z0-9-]"


# ---------------------------------------------------------------------------
# 9b. Registry robustness -- a bad config must fail at load, not at request time
# ---------------------------------------------------------------------------
def test_duplicate_entity_name_is_rejected_at_load(tmp_path: Path) -> None:
    """YAML's last-one-wins rule silently discards the first of two ``MRN:`` entries.

    The file then loads clean, the suite stays green, and detection runs with only
    one of the two pattern sets -- a config error that surfaces as a missed entity
    in production rather than an error at startup.
    """
    path = tmp_path / "entities.yaml"
    path.write_text(
        "categories: [PII]\n"
        "entities:\n"
        "  X: {category: PII, patterns: ['\\bAAA\\d{4}\\b']}\n"
        "  X: {category: PII, patterns: ['\\bZZZ\\d{4}\\b']}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as raised:
        load_registry(path)
    assert raised.value.detail["reason"] == "registry_duplicate_key"


@pytest.mark.parametrize(
    ("reason", "body"),
    [
        ("registry_entity_invalid", "categories: [PII]\nentities:\n  X: {category: PII, patterns: ['(unclosed']}\n"),
        ("registry_unknown_category", "categories: [PII, NOPE]\nentities:\n  X: {category: PII, patterns: ['a']}\n"),
        ("registry_category_not_declared", "categories: [PII]\nentities:\n  X: {category: PHI, patterns: ['a']}\n"),
        ("registry_gazetteer_missing", "categories: [PHI]\nentities:\n  X: {category: PHI, gazetteer: nope.txt}\n"),
        ("registry_entity_has_no_recognizer", "categories: [PII]\nentities:\n  X: {category: PII, context: [a]}\n"),
        ("registry_no_entities", "categories: [PII]\nentities: {}\n"),
        ("registry_not_a_mapping", "- a\n- b\n"),
        ("registry_yaml_invalid", "categories: [PII\nentities:\n"),
    ],
    ids=lambda value: value if value.startswith("registry_") else "",
)
def test_malformed_registry_fails_loudly_at_load(tmp_path: Path, reason: str, body: str) -> None:
    path = tmp_path / "entities.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError) as raised:
        load_registry(path)
    assert raised.value.detail["reason"] == reason


# A registry regex runs against attacker-supplied document text, so a pattern that
# backtracks super-linearly is a denial-of-service primitive. Two shapes cause it
# here and both were live:
#
#   * two whitespace-matching quantifiers separated by an optional group, which can
#     split one run of blanks between them in n ways. ACCOUNT_NUMBER and CASE_ID were
#     both written that way (CASE_ID verbatim from the build doc) and measured *8x*
#     per doubling -- cubic, not quadratic: 2.2 s on 1,000 blanks, 141 s on 4,000.
#   * a start anchor that admits positions inside the run it is scanning. EMAIL's
#     backstop used '\b', which fires at every letter/dot transition, so a long
#     dotted local part restarted the scan ~n/2 times: 4x per doubling, 301 ms on
#     16,000 characters.
#
# Each attack is a *builder* rather than a fixed string so the growth assertion below
# has two sizes to compare. Every shape the fixed-string form covered is preserved.
REDOS_ATTACKS: list[tuple[str, Callable[[int], str]]] = [
    ("account-blanks", lambda n: "account" + " " * n),
    ("account-blanks-tail", lambda n: "account" + " " * n + "x"),
    ("account-no-blanks", lambda n: "Account No." + " " * n),
    ("acct-separators", lambda n: "acct." + " :#" * (n // 3)),
    ("a/c-blanks", lambda n: "a/c" + " " * n),
    ("caseno-blanks", lambda n: "Case No." + " " * n),
    ("caseno-blanks-partial", lambda n: "Case No." + " " * n + "1:23-cv-"),
    ("docket-tabs", lambda n: "docket no" + "\t" * n),
    ("mrn-blanks", lambda n: "MRN" + " " * n),
    ("mrn-separators", lambda n: "mrn" + ".-" * (n // 2)),
    ("mrn-words-blanks", lambda n: "Medical Record Number" + " " * n),
    ("settlement-filler", lambda n: "settlement " + "x" * n),
    ("dollar-groups", lambda n: "$" + "1," * (n // 2)),
    ("dollar-groups-settlement", lambda n: "$" + "1," * (n // 2) + " settlement"),
    ("strategy-filler", lambda n: "our litigation strategy " + "y" * n),
    ("we-should-repeat", lambda n: "we should to " * (n // 13)),
    ("a1c-filler", lambda n: "A1C " + "z" * n),
    ("letters-then-digits", lambda n: "X" * (n // 2) + "1" * (n // 2)),
    ("privileged-blanks", lambda n: "privileged " + " " * n + "and confidential"),
    ("attorney-hyphens", lambda n: "attorney" + "-" * n + "client"),
    ("blanks-only", lambda n: " " * n),
    ("newlines-only", lambda n: "\n" * n),
    # EMAIL's backstop: a long run of local-part characters that never reaches an
    # "@", and a dotted-domain group that repeats. The first of these is what
    # caught the '\b' anchor -- see the note in entities.yaml.
    ("email-dotted-local", lambda n: "a." * (n // 2)),
    ("email-long-local", lambda n: "a" * n + "@"),
    ("email-hyphen-domain", lambda n: "user@" + "a-" * (n // 2)),
    ("email-dotted-domain", lambda n: "user@" + "a." * (n // 2)),
    # The newline-tolerant sentence tails: the two branches are disjoint on their
    # first character, so the alternation cannot split a run between them, and the
    # negative lookahead is re-evaluated at most once per consumed newline.
    ("we-should-newlines", lambda n: "we should to " + "\n" * n),
    ("strategy-soft-wraps", lambda n: "our trial strategy " + "\n \n" * (n // 3)),
    ("a1c-newlines", lambda n: "A1C" + "\n" * n),
    ("settlement-newlines-dollar", lambda n: "settlement " + "\n" * n + "$1"),
]

# Doubling the input doubles a linear scan. Measured on the shipped registry the
# worst honest ratio is 2.05 and the super-linear forms score 4.0 and 8.1, so 3.0
# separates them with room on both sides.
REDOS_SMALL_CHARS = 4000
REDOS_LARGE_CHARS = 8000
REDOS_GROWTH_CAP = 3.0
# Absorbs the regime where a pattern fails so fast that the measurement is mostly
# call overhead (~5 us) and the *ratio* is meaningless. Far below any cost that
# could matter: a pattern hidden by this slack is 0.5 ms on 8,000 characters.
REDOS_FLOOR_MS = 0.5
# Kept from the previous form of this test so a pattern that is merely expensive --
# linear with a huge constant, which the growth ratio would pass -- still fails.
REDOS_BUDGET_MS = 250.0
REDOS_SAMPLES = 3


def _best_search_ms(compiled: re.Pattern[str], text: str) -> float:
    """Fastest of ``REDOS_SAMPLES`` runs, in milliseconds.

    The minimum, not the mean or a single sample. Scheduler preemption, GC and a
    loaded machine can only ever *add* time to a measurement, so the minimum is the
    closest estimate of the pattern's true cost and the only one that does not turn
    this into a test of how busy the CPU is. The previous form took one sample and
    compared it to an absolute budget, which failed once under concurrent load with
    nothing wrong with the code -- and a security test that cries wolf during a
    review is worse than no test at all.
    """
    samples = []
    for _ in range(REDOS_SAMPLES):
        started = time.perf_counter()
        compiled.search(text)
        samples.append((time.perf_counter() - started) * 1000.0)
    return min(samples)


@pytest.mark.parametrize(
    ("label", "build"), REDOS_ATTACKS, ids=[label for label, _ in REDOS_ATTACKS]
)
def test_no_registry_pattern_backtracks_super_linearly(
    registry: EntityRegistry, label: str, build: Callable[[int], str]
) -> None:
    """Every pattern must stay linear on adversarial input.

    Asserted as *growth* rather than as an absolute stopwatch reading, because
    super-linear is a statement about growth and because an absolute reading is a
    statement about the machine. Doubling the input doubles a linear scan; the
    forms this guards against went to 4x and 8x. That makes the assertion both
    stricter than a fixed budget -- it catches a quadratic pattern that happens to
    stay under 250 ms at this length, which the fixed budget could not, and did not:
    EMAIL's backstop measured 74 ms here and 4x per doubling -- and immune to load,
    since both sides of the ratio are measured on the same machine moments apart.

    The absolute budget is kept as a second, independent assertion so a pattern that
    is linear but ruinously expensive per character still fails.
    """
    from secure_context_pipeline.detection.recognizers import PATTERN_FLAGS

    small_text = build(REDOS_SMALL_CHARS)
    large_text = build(REDOS_LARGE_CHARS)
    for name, spec in registry.entities.items():
        for index, pattern in enumerate(spec.patterns):
            compiled = re.compile(pattern, PATTERN_FLAGS)
            small_ms = _best_search_ms(compiled, small_text)
            large_ms = _best_search_ms(compiled, large_text)
            assert large_ms <= REDOS_GROWTH_CAP * small_ms + REDOS_FLOOR_MS, (
                f"{name}[{index}] on {label}: {small_ms:.3f} ms at {REDOS_SMALL_CHARS} chars "
                f"-> {large_ms:.3f} ms at {REDOS_LARGE_CHARS} "
                f"({large_ms / max(small_ms, 1e-9):.1f}x per doubling; linear is 2x)"
            )
            assert large_ms < REDOS_BUDGET_MS, (
                f"{name}[{index}] on {label} took {large_ms:.0f} ms at {REDOS_LARGE_CHARS} chars"
            )


@pytest.mark.parametrize(
    "entity_name",
    [
        "2FA_CODE",  # leading digit
        "MedicalId",  # camel case
        "medical_id",  # lower case
        "TWO-FA",  # hyphen
        "MEDICAL ID",  # space
        "_LEADING",  # leading underscore
        "PII_ÜBER",  # non-ASCII
    ],
)
def test_entity_name_outside_the_surrogate_grammar_fails_at_load(
    tmp_path: Path, entity_name: str
) -> None:
    """A name that cannot round-trip must be refused when the config is loaded.

    ``format_surrogate`` emits ``[{category}_{entity_type}_{token_id}]`` and
    ``TOKEN_RE`` only matches ``[A-Z][A-Z0-9_]*``. A config-only addition like
    ``2FA_CODE`` therefore produces ``[PII_2FA_CODE_deadbeef]``, which the restorer
    cannot match and which never reaches the egress gate's skip-list -- so the value
    is obfuscated, shipped, and then silently never restored. Failing at startup is
    what makes the config-only extensibility claim safe to make.
    """
    path = tmp_path / "entities.yaml"
    path.write_text(
        f"categories: [PII]\nentities:\n  {entity_name!r}: "
        "{category: PII, patterns: ['\\bAAA\\d{4}\\b']}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as raised:
        load_registry(path)
    assert raised.value.detail["reason"] == "entity_type_not_in_surrogate_grammar"


def test_a_valid_config_only_entity_name_still_loads(tmp_path: Path) -> None:
    """The guard must not narrow what section 10.4 promises is addable by config."""
    path = tmp_path / "entities.yaml"
    path.write_text(
        "categories: [PII]\n"
        "entities:\n"
        "  PASSPORT_NUMBER: {category: PII, patterns: ['\\b[A-Z]{1,2}\\d{7,8}\\b'], "
        "context: [passport]}\n"
        "  MFA_CODE_2: {category: PII, patterns: ['\\b\\d{6}\\b']}\n",
        encoding="utf-8",
    )
    loaded = load_registry(path)
    assert set(loaded.entities) == {"PASSPORT_NUMBER", "MFA_CODE_2"}


def test_every_shipped_entity_name_is_expressible_as_a_surrogate(
    registry: EntityRegistry,
) -> None:
    """All 20 shipped types round-trip, so the new guard changes nothing today."""
    from secure_context_pipeline.surrogates import ENTITY_TYPE_RE

    assert len(registry.entities) >= 20
    for name in registry.entities:
        assert ENTITY_TYPE_RE.match(name), f"{name} cannot be expressed as a surrogate"


def test_no_entity_name_is_hardcoded_in_detection_code(registry: EntityRegistry) -> None:
    """Section 10.4's claim, checked against the code rather than asserted in prose.

    "Add an entity type via config only" is false the moment ``detection/`` branches
    on a name. Docstrings and comments naming ``MRN`` or ``CASE_STRATEGY`` are fine
    and there are many -- most of the reasoning in this package is about specific
    entities -- so both are stripped before the search. A plain grep over these
    files reports dozens of hits and every one of them is prose.
    """
    import ast
    import re as _re

    names = {name for name in registry.entities}
    names |= {spec.presidio for spec in registry.entities.values() if spec.presidio}
    names |= {
        category
        for spec in registry.entities.values()
        for category in spec.only_in_doc_categories
    }
    assert len(names) > 20, "the registry should supply a meaningful set of names"

    package = Path(__file__).resolve().parent.parent / "secure_context_pipeline" / "detection"
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                first = node.body[0] if node.body else None
                if (
                    isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)
                ):
                    node.body.pop(0)
        code = ast.unparse(tree)  # comments are dropped by the parser
        found = sorted(name for name in names if _re.search(rf"\b{_re.escape(name)}\b", code))
        assert not found, f"{path.name} hardcodes registry names in executable code: {found}"


# Build doc section 6.2's field list, verbatim. A field the specification defines
# and the code silently ignores is a compliance gap that no other test would show:
# the registry would accept it, the loader would validate it, and nothing would
# happen.
SPEC_REGISTRY_FIELDS = frozenset(
    {
        "presidio",
        "patterns",
        "gazetteer",
        "context",
        "only_in_doc_categories",
        "threshold",
        "strategy",
        "tier",
        "hint",
        "action",
    }
)


def test_every_documented_registry_field_is_read_somewhere() -> None:
    """Each ``EntitySpec`` field must be read by real code, not just declared.

    Scanning for attribute access rather than for the bare word: "patterns" and
    "context" are ordinary English and appear all over the package in prose, so a
    grep would pass on a field nothing consumes.

    Reachability is transitive by one hop, because some fields are deliberately
    read only through a registry accessor -- nothing outside ``registry.py``
    touches ``spec.threshold``; the detector and the engine both go through
    ``threshold_for``. Excluding ``registry.py`` outright would report that field
    as dead, and requiring direct access would push callers into reaching past the
    accessor. So a field counts as reached when something outside ``registry.py``
    reads it directly, or when it is read inside a registry method that something
    outside calls.
    """
    import ast

    declared = set(EntitySpec.model_fields) - {"name", "category"}
    assert SPEC_REGISTRY_FIELDS <= declared, "a documented field is missing from the model"

    package = Path(__file__).resolve().parent.parent / "secure_context_pipeline"
    registry_source = package / "detection" / "registry.py"

    # Registry accessor -> the spec fields its body reads.
    accessor_fields: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(registry_source.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef):
            accessor_fields[node.name] = {
                inner.attr
                for inner in ast.walk(node)
                if isinstance(inner, ast.Attribute) and inner.attr in declared
            }

    read: set[str] = set()
    for path in sorted(package.rglob("*.py")):
        if path == registry_source:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute):
                read.add(node.attr)

    for accessor, fields in accessor_fields.items():
        if accessor in read:
            read |= fields

    ignored = sorted(declared - read)
    assert ignored == [], f"registry fields no code outside registry.py can reach: {ignored}"


def test_registry_errors_never_carry_document_content(tmp_path: Path) -> None:
    """Config errors name the entity, never a pattern or a matched value."""
    path = tmp_path / "entities.yaml"
    path.write_text(
        "categories: [PII]\nentities:\n  SECRET_SHAPE: {category: PII, patterns: ['(unclosed']}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as raised:
        load_registry(path)
    assert "unclosed" not in str(raised.value)


# ---------------------------------------------------------------------------
# 10. Analyzer singleton
# ---------------------------------------------------------------------------
async def test_detectors_share_one_analyzer_engine(
    registry: EntityRegistry, settings: Settings
) -> None:
    warm_up(settings)
    first = Detector(registry, settings)
    second = Detector(registry, settings)
    assert first.analyzer is second.analyzer
    assert first.analyzer is get_analyzer(settings.spacy_model)

    await first.detect("Jane Doe called today.")
    await second.detect("John Roe called today.")
    assert first.analyzer is second.analyzer


# ---------------------------------------------------------------------------
# Misc guarantees
# ---------------------------------------------------------------------------
async def test_empty_and_blank_documents_return_nothing(detector: Detector) -> None:
    assert await detector.detect("") == []
    assert await detector.detect("   \n\n \t ") == []


async def test_debug_logging_never_carries_document_content(
    detector: Detector, caplog: pytest.LogCaptureFixture
) -> None:
    """Zero PII in logs holds on the debug path too (build doc section 16).

    Presidio's own DEBUG stream prints the lemmas around every hit, which is
    document content; the detector pins that logger at INFO on import.
    """
    text = (
        "Chart note: MRN: 9987651 for Jane Doe.\n\n"
        "Prescribed metformin 500 mg; assessment type 2 diabetes."
    )
    with caplog.at_level(logging.DEBUG):
        hits = await detector.detect(text, "medical")

    assert hits, "fixture should produce detections to log about"
    emitted = "\n".join(record.getMessage() for record in caplog.records)
    for secret in ("9987651", "Jane Doe", "metformin", "type 2 diabetes"):
        assert secret not in emitted, "document content reached a log record"


@pytest.mark.parametrize("attack", ["set_level", "dict_config", "notset_inherits_root"])
async def test_presidio_debug_stream_stays_muted_when_a_caller_re_enables_it(
    detector: Detector, attack: str
) -> None:
    """The mute must survive a host application turning debug logging on.

    Presidio's DEBUG path logs document content, and on this registry it is live
    rather than hypothetical: ``AnalyzerEngine`` folds ad-hoc recognizers into the
    same list it hands the lemma context enhancer, so every ``patterns:``/
    ``gazetteer:`` entity carrying ``context:`` drives ``"Context list is: %s"`` --
    lemmas lifted straight out of the document -- on every match.
    ``test_context_words_boost_a_pattern_hit`` measures the same path from the
    other side, where the boost it produces is visible in the score.

    The synthetic record below is emitted anyway so the assertion does not depend
    on which of Presidio's own call sites happen to fire for this fixture: a DEBUG
    record carrying content, logged on Presidio's logger, must not reach a handler
    no matter how the caller has configured that logger. Pinning the level alone
    fails all three attacks below.
    """
    presidio_logger = logging.getLogger(PRESIDIO_LOGGER_NAME)
    records: list[str] = []
    sink = logging.StreamHandler()
    sink.emit = lambda record: records.append(record.getMessage())  # type: ignore[method-assign]
    sink.setLevel(logging.DEBUG)
    original_level = presidio_logger.level
    root = logging.getLogger()
    original_root_level = root.level

    presidio_logger.addHandler(sink)
    try:
        if attack == "set_level":
            presidio_logger.setLevel(logging.DEBUG)
        elif attack == "dict_config":
            logging.config.dictConfig(
                {
                    "version": 1,
                    "disable_existing_loggers": False,
                    "loggers": {PRESIDIO_LOGGER_NAME: {"level": "DEBUG"}},
                }
            )
        else:
            presidio_logger.setLevel(logging.NOTSET)
            root.setLevel(logging.DEBUG)

        # What Presidio's own enhancer does: log a lemma window from the document.
        presidio_logger.debug("Context list is: %s", "chart mrn 9987651 jane doe metformin")
        hits = await detector.detect(
            "Chart note: MRN: 9987651 for Jane Doe.\n\n"
            "Prescribed metformin 500 mg; assessment type 2 diabetes.",
            "medical",
        )
    finally:
        presidio_logger.removeHandler(sink)
        presidio_logger.setLevel(original_level)
        root.setLevel(original_root_level)

    assert hits, "fixture should produce detections to log about"
    emitted = "\n".join(records)
    assert not any(
        record.startswith("Context list is") for record in records
    ), f"a DEBUG record survived the {attack} attack"
    for secret in ("9987651", "Jane Doe", "metformin", "type 2 diabetes"):
        assert secret not in emitted, "document content reached Presidio's debug stream"


# ---------------------------------------------------------------------------
# The two load-bearing invariants must hold under `python -O`
# ---------------------------------------------------------------------------
def test_offset_drift_raises_a_structured_error_without_the_span() -> None:
    """A detection whose offsets stop addressing its own text must fail loudly.

    The engine vaults ``detection.text`` while splicing ``text[start:end]``; if those
    diverge the vault holds a value that never appeared in the document and
    de-obfuscation restores the wrong string. The error carries offsets and lengths
    only -- the span itself is an original value.
    """
    text = "Chart note: MRN: 4471902 filed today."
    drifted = Detection(
        entity_type="MRN", category="PHI", start=0, end=12, text="MRN: 4471902", score=0.9
    )
    with pytest.raises(DetectionInvariantError) as raised:
        _verify_offsets(text, [drifted])

    assert raised.value.detail["reason"] == "offset_drift"
    assert raised.value.detail["entity_type"] == "MRN"
    assert raised.value.detail["start"] == 0
    assert "4471902" not in str(raised.value)
    assert "Chart note" not in str(raised.value)


def test_offset_verification_accepts_a_consistent_detection() -> None:
    text = "Chart note: MRN: 4471902 filed today."
    good = Detection(
        entity_type="MRN", category="PHI", start=12, end=24, text=text[12:24], score=0.9
    )
    _verify_offsets(text, [good])  # must not raise


def test_chunking_invariant_raises_when_a_chunk_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Losing text during chunking shifts every absolute offset after it."""
    import secure_context_pipeline.detection.detector as detector_module

    original = detector_module._split_oversized

    def lossy(offset: int, body: str, max_chars: int) -> list[tuple[int, str]]:
        return original(offset, body, max_chars)[:-1]

    monkeypatch.setattr(detector_module, "_split_oversized", lossy)
    with pytest.raises(DetectionInvariantError) as raised:
        chunk_text("This sentence has no paragraph breaks anywhere. " * 400, 8000)
    assert raised.value.detail["reason"] == "chunking_lost_text"


def test_both_invariants_still_fire_with_assertions_disabled() -> None:
    """``python -O`` strips ``assert``; these checks must not be assert statements.

    Run in a subprocess with -O rather than inspecting the source, so the test
    measures the built behaviour instead of trusting that it was written correctly.
    """
    import subprocess
    import sys

    program = (
        "from secure_context_pipeline.detection.detector import ("
        "    DetectionInvariantError, _verify_offsets, chunk_text)\n"
        "from secure_context_pipeline.models import Detection\n"
        "import secure_context_pipeline.detection.detector as m\n"
        "assert False, 'assertions are still enabled -- the -O flag did not take'\n"
        "drifted = Detection(entity_type='MRN', category='PHI', start=0, end=12,"
        "                    text='MRN: 4471902', score=0.9)\n"
        "try:\n"
        "    _verify_offsets('Chart note: MRN: 4471902 filed.', [drifted])\n"
        "except DetectionInvariantError:\n"
        "    print('offset_drift_raised')\n"
        "original = m._split_oversized\n"
        "m._split_oversized = lambda o, b, mx: original(o, b, mx)[:-1]\n"
        "try:\n"
        "    chunk_text('This sentence has no paragraph breaks anywhere. ' * 400, 8000)\n"
        "except DetectionInvariantError:\n"
        "    print('chunking_raised')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-O", "-c", program],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr
    assert "offset_drift_raised" in completed.stdout
    assert "chunking_raised" in completed.stdout


def test_detection_repr_never_leaks_the_original_value() -> None:
    detection = Detection(
        entity_type="MRN", category="PHI", start=0, end=12, text="MRN: 4471902", score=0.9
    )
    assert "4471902" not in repr(detection)
    assert "4471902" not in str(detection)


# Placed last on purpose: it evicts the singleton and the next caller reloads spaCy.
async def test_zz_reset_analyzer_cache_forces_a_rebuild(settings: Settings) -> None:
    before = get_analyzer(settings.spacy_model)
    reset_analyzer_cache()
    after = get_analyzer(settings.spacy_model)
    assert before is not after
    assert after is get_analyzer(settings.spacy_model)
