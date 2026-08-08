"""Registry lookups, recognizer construction, and the loader's remaining error paths.

``tests/test_detection.py`` proves the *shipped* registry detects the right things.
This file proves the layer underneath it: that each registry field shape
(``presidio:`` / ``patterns:`` / ``gazetteer:``) produces the recognizer it is
supposed to and no other, that every lookup helper answers correctly on a miss as
well as a hit, and that the gazetteer parser keeps exactly the lines it should.

Sections 1-6 are asserted against a small synthetic registry written here, so the
expected values are literals rather than something re-derived from the code under
test, and nothing in them reads ``entities.yaml``.

Section 7 is the deliberate exception, and the reason is the point of it: three of
the *shipped* patterns carry hand-written guards whose failure mode is a value
reaching the provider, not a wrong lookup. A guard asserted against a synthetic copy
of the pattern would be a guard nothing binds to ``entities.yaml`` -- the copy stays
green while the shipped regex is edited underneath it. So section 7 loads the real
registry and runs the real ``build_pattern_recognizer`` over it.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest
import regex

from secure_context_pipeline.detection import recognizers as recognizers_module
from secure_context_pipeline.detection import registry as registry_module
from secure_context_pipeline.detection.recognizers import (
    PATTERN_FLAGS,
    build_gazetteer_recognizer,
    build_pattern_recognizer,
    build_recognizers,
    class_hint_for,
    gazetteer_terms,
    load_gazetteer,
)
from secure_context_pipeline.detection.registry import (
    EntityRegistry,
    RegistryAction,
    load_registry,
)
from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.models import EntityCategory

# A TSV exercising every branch of the gazetteer parser: a comment, a blank line,
# a normal term, a term with no class column, a term needing whitespace and case
# normalisation, a term whose class column is nothing but trailing blanks, and a
# malformed line carrying a second tab.
GAZETTEER_FILE = (
    "# synthetic clinical vocabulary -- not a real drug list\n"
    "\n"
    "metformin\toral-antidiabetic\n"
    "aspirin\n"
    "  Type  2   Diabetes \tendocrine\n"
    "GLIPIZIDE\t   \n"
    "insulin\tinjectable\n"
    "warfarin\t  anticoagulant\n"
    "lisinopril\tace-inhibitor\textra\n"
)

# The table the file above must parse to, written out by hand.
GAZETTEER_TABLE = {
    "metformin": "oral-antidiabetic",
    "aspirin": "",
    "type 2 diabetes": "endocrine",
    "glipizide": "",
    "insulin": "injectable",
    "warfarin": "anticoagulant",
    "lisinopril": "ace-inhibitor\textra",
}

# Five entities covering all three field shapes plus the both-fields case:
#   ALPHA_ID      patterns only, given as scalars (the str -> 1-tuple coercion)
#   BUILTIN_NAME  presidio only, with an action override
#   ALIAS_NAME    presidio only, claiming the SAME built-in as BUILTIN_NAME
#   MEDICATION    gazetteer only, restricted to one doc category
#   CASE_TAG      patterns AND gazetteer, restricted to two doc categories
REGISTRY_FILE = """\
categories: [PII, PHI, LEGAL]
entities:
  ALPHA_ID:
    category: PII
    patterns: '[A-Z]{2}\\d{4}'
    context: badge
    threshold: 0.55
    tier: 4
  BUILTIN_NAME:
    category: PII
    presidio: PERSON
    action: redact
  ALIAS_NAME:
    category: PII
    presidio: PERSON
  MEDICATION:
    category: PHI
    gazetteer: terms.txt
    only_in_doc_categories: [medical]
    tier: 3
  CASE_TAG:
    category: LEGAL
    patterns: ['CV-\\d{3}']
    gazetteer: terms.txt
    only_in_doc_categories: [legal, financial]
    action: strip
"""


class FakeClock:
    """Injectable clock so TTL behaviour is testable without sleeping."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def gazetteer_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect both modules' ``GAZETTEER_DIR`` at a scratch directory.

    ``recognizers`` imported the constant by value, so both bindings have to move
    or the loader and the recognizer builder disagree about where terms live. The
    parse cache is swapped for an empty one so these files never pollute -- or get
    served from -- the process-wide cache of the shipped gazetteers.
    """
    directory = tmp_path / "gazetteers"
    directory.mkdir()
    (directory / "terms.txt").write_text(GAZETTEER_FILE, encoding="utf-8")
    (directory / "empty.txt").write_text("# every line is a comment\n\n", encoding="utf-8")
    (directory / "adir.txt").mkdir()
    monkeypatch.setattr(recognizers_module, "GAZETTEER_DIR", directory)
    monkeypatch.setattr(registry_module, "GAZETTEER_DIR", directory)
    monkeypatch.setattr(recognizers_module, "_GAZETTEER_CACHE", {})
    return directory


@pytest.fixture
def synthetic(gazetteer_dir: Path, tmp_path: Path) -> EntityRegistry:
    """The five-entity registry above, loaded through the real loader."""
    path = tmp_path / "synthetic.yaml"
    path.write_text(REGISTRY_FILE, encoding="utf-8")
    return load_registry(path)


# ---------------------------------------------------------------------------
# 1. gazetteer parsing
# ---------------------------------------------------------------------------


def test_gazetteer_parsing_keeps_exactly_the_content_lines(gazetteer_dir: Path) -> None:
    """Comments and blanks are dropped, terms are casefolded and whitespace-collapsed,
    and a missing class column yields an empty hint rather than a dropped term."""
    assert load_gazetteer("terms.txt") == GAZETTEER_TABLE
    # Second call is served from the cache -- the same object, not an equal one.
    assert load_gazetteer("terms.txt") is load_gazetteer("terms.txt")


def test_gazetteer_terms_are_longest_first_then_alphabetical(gazetteer_dir: Path) -> None:
    """Presidio's deny-list alternation is leftmost-first, so a shorter term listed
    ahead of a longer one that starts at the same offset would clip the match.
    Equal-length terms are ordered by name so the alternation is reproducible."""
    assert gazetteer_terms("terms.txt") == [
        "type 2 diabetes",
        "lisinopril",
        "glipizide",
        "metformin",
        "warfarin",
        "aspirin",
        "insulin",
    ]


@pytest.mark.parametrize("filename", ["absent.txt", "adir.txt"])
def test_an_unreadable_gazetteer_fails_as_a_config_error(
    gazetteer_dir: Path, filename: str
) -> None:
    """A missing file and a directory in its place must both surface as ``ConfigError``.

    The bare ``OSError`` would escape a startup path that only catches pipeline
    errors, so the container would die with a traceback instead of a config reason.
    """
    with pytest.raises(ConfigError) as raised:
        load_gazetteer(filename)
    assert raised.value.detail["reason"] == "gazetteer_unreadable"
    assert raised.value.detail["gazetteer"] == filename


# ---------------------------------------------------------------------------
# 2. one registry field shape -> one recognizer shape
# ---------------------------------------------------------------------------


def test_each_registry_field_shape_builds_the_recognizers_it_declares(
    synthetic: EntityRegistry,
) -> None:
    """``presidio:`` builds nothing (the detector remaps built-ins instead), each
    ``patterns:`` and each ``gazetteer:`` builds one recognizer named for the
    *registry* entity, and an entity carrying both fields builds both."""
    built = [(r.name, tuple(r.supported_entities)) for r in build_recognizers(synthetic)]
    assert built == [
        ("ALPHA_IDPatternRecognizer", ("ALPHA_ID",)),
        ("MEDICATIONGazetteerRecognizer", ("MEDICATION",)),
        ("CASE_TAGPatternRecognizer", ("CASE_TAG",)),
        ("CASE_TAGGazetteerRecognizer", ("CASE_TAG",)),
    ]


def test_a_pattern_recognizer_is_case_sensitive_and_carries_its_context(
    synthetic: EntityRegistry,
) -> None:
    """``[A-Z]{2}`` must mean uppercase. Presidio's default global flags include
    IGNORECASE, which would turn every shape-based registry regex into a
    case-blind one and make ``[A-Z]{2,4}\\d{7,12}`` match any four letters."""
    recognizer = build_pattern_recognizer(synthetic.spec("ALPHA_ID"))
    assert recognizer.context == ["badge"]

    hits = recognizer.analyze(text="badge AB1234", entities=["ALPHA_ID"])
    assert [(h.entity_type, h.start, h.end) for h in hits] == [("ALPHA_ID", 6, 12)]
    assert recognizer.analyze(text="badge ab1234", entities=["ALPHA_ID"]) == []


def test_a_gazetteer_recognizer_is_case_insensitive_and_word_bounded(
    synthetic: EntityRegistry,
) -> None:
    """Clinical vocabulary is written every which way, so a gazetteer must match
    case-insensitively -- but only on whole words, or ``premetforminx`` becomes a
    medication. A gazetteer hit also has to outscore a shape-based regex hit,
    which is the whole reason a curated list is worth keeping."""
    recognizer = build_gazetteer_recognizer(synthetic.spec("MEDICATION"))

    hits = recognizer.analyze(text="Metformin 500 mg", entities=["MEDICATION"])
    assert [(h.entity_type, h.start, h.end) for h in hits] == [("MEDICATION", 0, 9)]
    assert recognizer.analyze(text="TYPE 2 DIABETES", entities=["MEDICATION"])
    assert recognizer.analyze(text="premetforminx", entities=["MEDICATION"]) == []

    pattern_hit = build_pattern_recognizer(synthetic.spec("ALPHA_ID")).analyze(
        text="AB1234", entities=["ALPHA_ID"]
    )
    assert hits[0].score > pattern_hit[0].score


def test_building_a_recognizer_from_the_wrong_field_shape_is_a_config_error(
    synthetic: EntityRegistry,
) -> None:
    """Both builders refuse a spec that lacks their field instead of constructing a
    recognizer with an empty pattern list, which Presidio accepts and which would
    silently match nothing."""
    presidio_only = synthetic.spec("BUILTIN_NAME")

    with pytest.raises(ConfigError) as no_patterns:
        build_pattern_recognizer(presidio_only)
    assert no_patterns.value.detail["reason"] == "entity_has_no_patterns"
    assert no_patterns.value.detail["entity_type"] == "BUILTIN_NAME"

    with pytest.raises(ConfigError) as no_gazetteer:
        build_gazetteer_recognizer(presidio_only)
    assert no_gazetteer.value.detail["reason"] == "entity_has_no_gazetteer"


def test_a_gazetteer_of_only_comments_is_rejected_rather_than_built(
    gazetteer_dir: Path, tmp_path: Path
) -> None:
    """An existing-but-contentless term file passes the loader's is_file() check, so
    the emptiness has to be caught here. A deny-list of zero terms builds fine and
    detects nothing -- an entity silently switched off."""
    path = tmp_path / "empty-gazetteer.yaml"
    path.write_text(
        "categories: [PHI]\nentities:\n  MEDICATION: {category: PHI, gazetteer: empty.txt}\n",
        encoding="utf-8",
    )
    spec = load_registry(path).spec("MEDICATION")

    with pytest.raises(ConfigError) as raised:
        build_gazetteer_recognizer(spec)
    assert raised.value.detail["reason"] == "gazetteer_empty"


# ---------------------------------------------------------------------------
# 3. class hints for Tier-3 annotated tokens
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entity_type", "matched_text", "expected"),
    [
        ("MEDICATION", "metformin", "oral-antidiabetic"),
        # The engine passes the ORIGINAL span, so case and spacing vary.
        ("MEDICATION", "  METFORMIN ", "oral-antidiabetic"),
        ("MEDICATION", "Type  2  Diabetes", "endocrine"),
        # Present in the file but with no class column -- an empty hint is not a hint.
        ("MEDICATION", "aspirin", None),
        ("MEDICATION", "glipizide", None),
        ("MEDICATION", "nosuchdrug", None),
        # Not gazetteer-backed, so there is no class column to read.
        ("ALPHA_ID", "metformin", None),
        ("BUILTIN_NAME", "metformin", None),
        # Unknown entity type: None, not a raise -- the engine calls this per span.
        ("NOT_AN_ENTITY", "metformin", None),
    ],
)
def test_class_hint_for_on_hit_and_miss(
    synthetic: EntityRegistry, entity_type: str, matched_text: str, expected: str | None
) -> None:
    """The hint is emitted verbatim inside ``[PHI_MEDICATION_2f4a|oral-antidiabetic]``,
    so an empty class column must become ``None`` rather than an empty annotation."""
    assert class_hint_for(synthetic, entity_type, matched_text) == expected


# ---------------------------------------------------------------------------
# 4. registry lookups, on a hit and on a miss
# ---------------------------------------------------------------------------


def test_spec_raises_on_an_unknown_type_and_get_returns_none(
    synthetic: EntityRegistry,
) -> None:
    """The two accessors differ only in how they answer a miss, and callers depend on
    that: ``spec`` is for code that cannot proceed, ``get`` for code with a default."""
    assert synthetic.spec("ALPHA_ID").category is EntityCategory.PII
    assert synthetic.get("ALPHA_ID") is synthetic.spec("ALPHA_ID")

    assert synthetic.get("NOT_AN_ENTITY") is None
    with pytest.raises(ConfigError) as raised:
        synthetic.spec("NOT_AN_ENTITY")
    assert raised.value.detail["reason"] == "unknown_entity_type"
    assert raised.value.detail["entity_type"] == "NOT_AN_ENTITY"


def test_a_long_unknown_entity_type_is_truncated_out_of_the_error(
    synthetic: EntityRegistry,
) -> None:
    """``entity_type`` is attacker-influencable, and ``PipelineError`` refuses any
    detail value over 64 chars -- so an unclamped name would raise ValueError from
    inside the error constructor instead of the ConfigError the caller handles."""
    with pytest.raises(ConfigError) as raised:
        synthetic.spec("Z" * 200)
    assert raised.value.detail["entity_type"] == "Z" * 64


def test_category_and_tier_lookups_answer_from_the_spec(synthetic: EntityRegistry) -> None:
    """Tier drives which pseudonymization strategy runs, and an entity that declares
    no tier must land on the identifier tier rather than on 0 or None."""
    assert synthetic.category_of("MEDICATION") is EntityCategory.PHI
    assert synthetic.category_of("CASE_TAG") is EntityCategory.LEGAL
    assert synthetic.tier_of("ALPHA_ID") == 4
    assert synthetic.tier_of("MEDICATION") == 3
    assert synthetic.tier_of("BUILTIN_NAME") == 1

    for lookup in (synthetic.category_of, synthetic.tier_of):
        with pytest.raises(ConfigError):
            lookup("NOT_AN_ENTITY")


def test_action_of_returns_the_override_or_none(synthetic: EntityRegistry) -> None:
    """``action:`` is an engine-level policy override for a whole entity type; an
    entity without one must not be reported as redact-or-strip by default."""
    assert synthetic.action_of("BUILTIN_NAME") is RegistryAction.REDACT
    assert synthetic.action_of("CASE_TAG") is RegistryAction.STRIP
    assert synthetic.action_of("ALPHA_ID") is None
    # A miss is None, not a raise -- the engine asks this for every detected span.
    assert synthetic.action_of("NOT_AN_ENTITY") is None


def test_threshold_for_prefers_the_registry_over_the_caller_default(
    synthetic: EntityRegistry,
) -> None:
    """A per-entity ``threshold:`` exists precisely to override the global one, and an
    entity that declares none -- or is not in the registry at all -- must fall back."""
    assert synthetic.threshold_for("ALPHA_ID", 0.9) == 0.55
    assert synthetic.threshold_for("ALPHA_ID", 0.1) == 0.55
    assert synthetic.threshold_for("MEDICATION", 0.42) == 0.42
    assert synthetic.threshold_for("NOT_AN_ENTITY", 0.42) == 0.42


def test_grouped_views_partition_the_registry_by_field(synthetic: EntityRegistry) -> None:
    """An entity declaring both ``patterns:`` and ``gazetteer:`` belongs to both views,
    and two entities claiming one Presidio built-in must both survive the alias map --
    a dict keyed the other way round would drop one of them."""
    assert set(synthetic.presidio_backed()) == {"BUILTIN_NAME", "ALIAS_NAME"}
    assert set(synthetic.pattern_backed()) == {"ALPHA_ID", "CASE_TAG"}
    assert set(synthetic.gazetteer_backed()) == {"MEDICATION", "CASE_TAG"}
    assert synthetic.presidio_aliases() == {"PERSON": ("BUILTIN_NAME", "ALIAS_NAME")}


@pytest.mark.parametrize(
    ("doc_category", "expected"),
    [
        # An unclassified document gets only the unrestricted entities. This is the
        # row that matters: a restricted entity must NOT leak into "we don't know".
        (None, ("ALPHA_ID", "BUILTIN_NAME", "ALIAS_NAME")),
        ("general", ("ALPHA_ID", "BUILTIN_NAME", "ALIAS_NAME")),
        ("medical", ("ALPHA_ID", "BUILTIN_NAME", "ALIAS_NAME", "MEDICATION")),
        ("legal", ("ALPHA_ID", "BUILTIN_NAME", "ALIAS_NAME", "CASE_TAG")),
        ("financial", ("ALPHA_ID", "BUILTIN_NAME", "ALIAS_NAME", "CASE_TAG")),
    ],
)
def test_types_for_doc_restricts_by_declared_doc_category(
    synthetic: EntityRegistry, doc_category: str | None, expected: tuple[str, ...]
) -> None:
    """``only_in_doc_categories`` is enforced by narrowing the entity set handed to
    the analyzer, so an over-broad answer here silently detects an entity where the
    config said it must not, and an under-broad one switches it off everywhere."""
    assert set(synthetic.types_for_doc(doc_category)) == set(expected)
    assert all(synthetic.spec(name).allowed_in(doc_category) for name in expected)
    for name in set(synthetic.entities) - set(expected):
        assert synthetic.spec(name).allowed_in(doc_category) is False


# ---------------------------------------------------------------------------
# 5. loader paths not exercised by test_detection's malformed-registry table
# ---------------------------------------------------------------------------


def test_a_missing_registry_file_is_a_config_error(tmp_path: Path) -> None:
    """Startup must report a reason, not raise FileNotFoundError from a read."""
    with pytest.raises(ConfigError) as raised:
        load_registry(tmp_path / "does-not-exist.yaml")
    assert raised.value.detail["reason"] == "registry_not_found"
    assert raised.value.detail["path"] == "does-not-exist.yaml"


def test_the_default_registry_path_is_entities_yaml_in_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``load_registry()`` with no argument must read ``./entities.yaml`` and nothing
    else -- not a copy packaged inside the installed wheel, which would let the
    container boot on a stale registry while an operator edited the file they
    mounted. Run from a directory without one, it has to fail loudly instead."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    with pytest.raises(ConfigError) as raised:
        load_registry()
    assert raised.value.detail["reason"] == "registry_not_found"
    assert raised.value.detail["path"] == "entities.yaml"

    (workdir / "entities.yaml").write_text(
        "categories: [FIN]\nentities:\n  ONLY_HERE: {category: FIN, patterns: ['x']}\n",
        encoding="utf-8",
    )
    assert set(load_registry().entities) == {"ONLY_HERE"}


@pytest.mark.parametrize("body", ["MRN", "[a, b]", "null"])
def test_an_entity_whose_body_is_not_a_mapping_is_rejected(tmp_path: Path, body: str) -> None:
    """A half-finished edit -- ``MRN: PHI`` instead of ``MRN: {category: PHI}`` --
    must not reach the pydantic constructor as ``**a_string``."""
    path = tmp_path / "entities.yaml"
    path.write_text(f"categories: [PHI]\nentities:\n  MRN: {body}\n", encoding="utf-8")
    with pytest.raises(ConfigError) as raised:
        load_registry(path)
    assert raised.value.detail["reason"] == "registry_entity_not_a_mapping"
    assert raised.value.detail["entity_type"] == "MRN"


def test_scalar_list_fields_are_accepted_as_a_single_value(synthetic: EntityRegistry) -> None:
    """``patterns: 'x'`` and ``context: badge`` are the natural way to write a
    one-element list in YAML. Without the coercion pydantic would take the string as
    an iterable of characters, so ``'[A-Z]{2}\\d{4}'`` would become twelve
    single-character patterns -- each of which compiles, so nothing would raise."""
    assert synthetic.spec("ALPHA_ID").patterns == ("[A-Z]{2}\\d{4}",)
    assert synthetic.spec("ALPHA_ID").context == ("badge",)
    # The list form is unchanged by the same code path.
    assert synthetic.spec("CASE_TAG").patterns == ("CV-\\d{3}",)
    assert synthetic.spec("CASE_TAG").only_in_doc_categories == ("legal", "financial")


def test_an_omitted_categories_block_admits_every_category(tmp_path: Path) -> None:
    """``categories:`` is optional, and when it is absent no entity may be rejected
    for declaring a category that was never listed."""
    path = tmp_path / "entities.yaml"
    path.write_text(
        "entities:\n"
        "  A_TYPE: {category: PII, patterns: ['a']}\n"
        "  B_TYPE: {category: FIN, patterns: ['b']}\n",
        encoding="utf-8",
    )
    loaded = load_registry(path)
    assert set(loaded.categories) == set(EntityCategory)
    assert loaded.category_of("B_TYPE") is EntityCategory.FIN


# ---------------------------------------------------------------------------
# 6. session registry: expires_at has the same contract as key()
# ---------------------------------------------------------------------------


def test_a_gazetteer_row_with_no_term_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hint with no term must not become a detection term.

    `load_gazetteer` guards on an empty term, and that guard was unreachable: it
    partitioned the STRIPPED line, and `.strip()` eats the leading tab that makes a
    term empty. So `"\\toral-antidiabetic"` -- what a mis-edited TSV row looks like --
    promoted the HINT into the term position and silently registered
    `oral-antidiabetic` as a MEDICATION the detector matches on.

    Latent on the shipped files (both have zero leading-tab rows) but the same
    fail-open-on-a-config-typo class as the `only_in_doc_categories` defect, and a
    gazetteer is exactly the kind of file that gets hand-edited.
    """
    monkeypatch.setattr(recognizers_module, "GAZETTEER_DIR", tmp_path)
    recognizers_module._GAZETTEER_CACHE.clear()
    (tmp_path / "bad.txt").write_text(
        "metformin\toral-antidiabetic\n\tinsulin-analogue\ninsulin\tinjectable\n",
        encoding="utf-8",
    )

    table = recognizers_module.load_gazetteer("bad.txt")

    assert "insulin-analogue" not in table, "a hint with no term became a detection term"
    assert table["metformin"] == "oral-antidiabetic"
    assert table["insulin"] == "injectable"
    recognizers_module._GAZETTEER_CACHE.clear()


# ---------------------------------------------------------------------------
# 7. the shipped patterns' hand-written guards
# ---------------------------------------------------------------------------
# These run against the real `entities.yaml` (the session-scoped `registry` fixture)
# through the real recognizer builder, so they see the same regex and the same
# `PATTERN_FLAGS` the detector does. Everything above this line uses the synthetic
# registry instead; see the module docstring for why these three do not.


def _shipped_spans(registry: EntityRegistry, entity_type: str, text: str) -> list[str]:
    """Substrings the shipped pattern for `entity_type` claims in `text`."""
    recognizer = build_pattern_recognizer(registry.spec(entity_type))
    hits = recognizer.analyze(text=text, entities=[entity_type])
    return [text[hit.start : hit.end] for hit in sorted(hits, key=lambda hit: hit.start)]


def test_the_shipped_insurance_id_pattern_reaches_five_and_six_letter_payers(
    registry: EntityRegistry,
) -> None:
    """A member ID this pattern misses is never vaulted, and no egress pass sees it.

    The build doc's prefix bound is `[A-Z]{2,4}`, which knows BCBS and UHC and misses
    every payer whose scheme prints five or six letters. Measured on the sentence
    below before the widening: ONE detection of three, `BCBS123456789`, with
    `AETNA1234567` and `HUMANA12345678` travelling to the provider byte for byte.
    That is the identifier-position failure class entities.yaml states above MRN --
    the egress gate's first pass scans for *vaulted* originals and its second re-runs
    this same pattern, so a value nothing anchors on is invisible to both. On the
    held-out corpus the same widening took INSURANCE_ID coverage 4/5 -> 5/5.

    The second half is what keeps the widening from being a licence: two more letters
    must not loosen what makes the pattern specific. The letters stay UPPER case and
    must abut the digit run with no separator, so a spaced or title-cased payer name
    is still not a match -- which is why those two are asserted here rather than
    left to the clean-corpus false-positive count in test_detection.py.
    """
    text = "Member ID AETNA1234567 and policy HUMANA12345678 and BCBS123456789 on file."
    assert _shipped_spans(registry, "INSURANCE_ID", text) == [
        "AETNA1234567",
        "HUMANA12345678",
        "BCBS123456789",
    ]

    assert _shipped_spans(registry, "INSURANCE_ID", "Member ID AETNA 4412093 on file.") == []
    assert _shipped_spans(registry, "INSURANCE_ID", "Member ID Aetna4412093 on file.") == []


def test_the_shipped_lab_result_pattern_stops_at_the_next_fields_label(
    registry: EntityRegistry,
) -> None:
    """LAB_RESULT may cross a hard wrap into a VALUE, never into a LABEL.

    The line-break trim in detector.py is scoped to `presidio:`-backed entities on the
    stated ground that a pattern-backed sentence tail is *required* to span a hard
    wrap. That holds for CASE_STRATEGY and SETTLEMENT_TERM, which need the wrap to
    reach the end of a sentence. LAB_RESULT is a field-VALUE pattern and needs it only
    to reach the next column of one wrapped row, so it was exempt from the trim
    without ever needing the exemption, and it collected all three harms the trim's
    own comment enumerates: `'Recent labs: LDL\\nDOB: 1974-03-02'` matched the single
    span `'LDL\\nDOB: 1974'`, which collapses two lines and destroys the DOB label,
    vaults a composite that is not a value (so the bare date is never an original and
    the gate has no needle for it), and audits a PII date as PHI LAB_RESULT.

    Not covered by `test_detection.py::test_no_detection_spans_a_line_break`: that one
    filters to `ner_backed`, which is precisely the set LAB_RESULT is not in.

    Both directions are asserted. Refusing the label is worth nothing if the guard
    also refuses the wrapped table row the newline branch exists for -- that would
    trade a composite span for an undetected lab value, which is the worse of the two.
    """
    for text in (
        "Recent labs: LDL\nDOB: 1974-03-02\n",
        "    Recent labs: HbA1c\n    DOB: 04/13/1956\n",
    ):
        spans = _shipped_spans(registry, "LAB_RESULT", text)
        assert spans == [], f"a lab span ran into the next field's label: {spans}"

    assert _shipped_spans(registry, "LAB_RESULT", "Row: HbA1c\n    7.4 percent\n") == [
        "HbA1c\n    7.4"
    ]


def test_the_shipped_lab_result_pattern_crosses_a_non_sentence_period(
    registry: EntityRegistry,
) -> None:
    """A period inside a lab line is punctuation, not the end of the tail.

    The doc's tail class `[^.\\n]` cannot cross any `.`, so two ordinary
    extracted-chart layouts returned ZERO detections and their values went to the
    provider un-vaulted: a parenthetical abbreviation, `'LDL cholesterol (calc.) 162'`,
    and the dot leaders of a fixed-width table, `'WBC ..... 12.3'`.

    The widening is bounded by the two SHAPES those layouts are made of -- a `.`
    abutting a closer or another `.`, and the last `.` of a leader run, identified by
    the `.` before it -- and not by a blanket "crossable unless a letter follows".
    That blanket form was what shipped first and it is what
    `test_the_shipped_lab_result_pattern_stays_inside_one_sentence` below exists to
    keep out. The last assertion here is the constraint at its mildest: an ordinary
    sentence boundary must still stop the tail, or LAB_RESULT starts vaulting the
    next sentence's numbers as a lab value.
    """
    assert _shipped_spans(registry, "LAB_RESULT", "Lab report: LDL cholesterol (calc.) 162.") == [
        "LDL cholesterol (calc.) 162"
    ]
    assert _shipped_spans(registry, "LAB_RESULT", "Lab report: WBC ..... 12.3 today.") == [
        "WBC ..... 12.3"
    ]
    assert _shipped_spans(registry, "LAB_RESULT", "Panel: eGFR ........ 58 mL/min today.") == [
        "eGFR ........ 58"
    ]

    assert _shipped_spans(registry, "LAB_RESULT", "LDL was normal. Patient is 62 today.") == []


# The sentence openings a period-crossing tail can reach that a LETTER test does
# not stop. Each is an ordinary clinical or administrative sentence, and each was
# measured swallowed by the blanket form of the period branch; the second element
# is what LAB_RESULT vaulted -- text that is not a lab value, which the restorer
# then splices back as though it were one.
SENTENCE_AFTER_A_LAB_LINE = [
    ("Her LDL was normal. 3 refills were sent to the pharmacy.", "LDL was normal. 3"),
    ("The WBC came back fine. 2024 follow-up is already booked.", "WBC came back fine. 2024"),
    ("His A1C is at goal. (See note 4 for the plan.)", "A1C is at goal. (See note 4"),
    ("Creatinine stable. -- 12 month recheck.", "Creatinine stable. -- 12"),
    ("eGFR unremarkable. 62-year-old male, no complaints.", "eGFR unremarkable. 62"),
]


@pytest.mark.parametrize(
    ("text", "over_captured"),
    SENTENCE_AFTER_A_LAB_LINE,
    ids=[case[0][:44] for case in SENTENCE_AFTER_A_LAB_LINE],
)
def test_the_shipped_lab_result_pattern_stays_inside_one_sentence(
    registry: EntityRegistry, text: str, over_captured: str
) -> None:
    """A LAB_RESULT span may never reach past the full stop that ends its sentence.

    Over-capture here is not a leak -- the span is vaulted, so nothing extra travels
    to the provider. It is a CORRECTNESS defect, and a quiet one: the vaulted
    original is a sentence fragment rather than a value, so the token the model is
    given stands for "LDL was normal. 3" and the restorer splices that whole
    fragment back wherever the model put the token. The answer the user reads is
    then wrong in a way no audit row records, because every count is clean.

    The rule that let it in was "a `.` is crossable unless a letter follows it",
    which is a description of a sentence boundary seen from the wrong side: English
    sentences open on digits, dashes and brackets too. `over_captured` is the exact
    span measured under that rule, asserted as a value the pattern must NOT return,
    so this cannot be satisfied by a pattern that merely stops somewhere else.

    The `\\d` in each case is deliberate. The tail is lazy and stops at the first
    digit after the analyte, so a next sentence with no number in it would pass
    trivially -- these are the ones that actually reach.
    """
    spans = _shipped_spans(registry, "LAB_RESULT", text)

    assert over_captured not in spans, f"a lab span ran into the next sentence: {spans}"
    for span in spans:
        assert not _crosses_a_full_stop(span), f"span crosses a sentence boundary: {span!r}"


def _crosses_a_full_stop(span: str) -> bool:
    """Does `span` contain a `.` that ends a sentence rather than punctuating a value?

    A sentence-ending `.` is one with no `.` abutting it on either side, no closer
    immediately after, and digits on neither side -- i.e. neither of the two shapes
    the pattern's period branch is allowed to cross, and not the decimal point of
    the value the span ends on. Written from that DEFINITION rather than by reusing
    the registry's regex, so the checker and the checked share no expression and a
    pattern edit cannot make the check agree with it.
    """
    for index, char in enumerate(span):
        if char != ".":
            continue
        before = span[index - 1] if index else ""
        after = span[index + 1 :][:1]
        if before == "." or after in {".", ")", "]", "}"}:
            continue
        if before.isdigit() and after.isdigit():
            continue
        return True
    return False


# The dot-run attacks the shipped ReDoS harness does not carry.
#
# `test_detection.py::test_no_registry_pattern_backtracks_super_linearly` runs every
# registry pattern against a table of attack payloads, and LAB_RESULT's rows there
# are `a1c-filler` ("A1C " + "z" * n) and `a1c-newlines` -- neither of which is made
# of DOTS. That matters because the period branch is the one part of the pattern
# whose alternatives can both consume a '.', and an ambiguous pair of them is
# catastrophic rather than merely slow: the first draft of the branch,
# `\.(?=[.)\]}])|(?<=\.)\.` with no `(?!...)` on the second alternative, took
# 57 SECONDS on `"A1C " + "." * 250` under `regex` with PATTERN_FLAGS -- against
# 0.03 ms for the shipped form -- and every row of the shipped harness stayed green
# through it, because none of them feeds the pattern a dot run.
#
# So the guard lives here, next to the branch it guards. A fixed-width table of dot
# leaders is not an attack shape a reviewer has to imagine; it is the layout the
# branch was ADDED for, which is what makes the omission worth closing.
LAB_DOT_RUN_ATTACKS = [
    ("solid-dots", lambda n: "A1C " + "." * n),
    ("dot-space", lambda n: "A1C " + ". " * (n // 2)),
    ("dot-newline", lambda n: "A1C " + ".\n" * (n // 2)),
    # A dot run that never reaches a digit, so the match must FAIL after walking it
    # -- failure is where a backtracking pattern spends its time.
    ("dots-no-value", lambda n: "A1C " + "." * n + " end"),
]

DOT_RUN_SMALL_CHARS = 4_000
DOT_RUN_LARGE_CHARS = 16_000
# 4x the length, so linear is 4x. 12x leaves room for cache and constant-factor
# effects while still failing anything quadratic (which is 16x) by a wide margin.
DOT_RUN_GROWTH_CAP = 12.0
DOT_RUN_FLOOR_MS = 0.5
# The failure this exists for measured ~22 000 ms at 4 000 characters, so any bound
# in this range catches it; 250 ms matches the shipped harness's own budget.
DOT_RUN_BUDGET_MS = 250.0
DOT_RUN_SAMPLES = 3


def _best_search_ms(compiled: object, text: str) -> float:
    """Fastest of `DOT_RUN_SAMPLES` runs, in milliseconds.

    The minimum rather than the mean, for the reason the shipped harness gives:
    preemption and GC can only ADD time, so the minimum is the closest estimate of
    the pattern's own cost and the only one that does not make this a test of how
    busy the machine is.
    """
    samples = []
    for _ in range(DOT_RUN_SAMPLES):
        started = time.perf_counter()
        compiled.search(text)  # type: ignore[attr-defined]
        samples.append((time.perf_counter() - started) * 1000.0)
    return min(samples)


@pytest.mark.parametrize(
    ("label", "build"), LAB_DOT_RUN_ATTACKS, ids=[case[0] for case in LAB_DOT_RUN_ATTACKS]
)
def test_the_shipped_lab_result_pattern_is_linear_on_dot_runs(
    registry: EntityRegistry, label: str, build: Callable[[int], str]
) -> None:
    """LAB_RESULT's period branch must stay linear on the runs it is allowed to cross.

    Compiled the way the detector compiles it -- `regex` with `PATTERN_FLAGS` -- so
    this measures the engine that actually runs in the pipeline and not `re`.
    """
    (pattern,) = registry.spec("LAB_RESULT").patterns
    compiled = regex.compile(pattern, PATTERN_FLAGS)

    small_ms = _best_search_ms(compiled, build(DOT_RUN_SMALL_CHARS))
    large_ms = _best_search_ms(compiled, build(DOT_RUN_LARGE_CHARS))

    assert large_ms < DOT_RUN_BUDGET_MS, (
        f"LAB_RESULT on {label} took {large_ms:.0f} ms at {DOT_RUN_LARGE_CHARS} chars"
    )
    assert large_ms <= DOT_RUN_GROWTH_CAP * small_ms + DOT_RUN_FLOOR_MS, (
        f"LAB_RESULT on {label}: {small_ms:.3f} ms at {DOT_RUN_SMALL_CHARS} chars -> "
        f"{large_ms:.3f} ms at {DOT_RUN_LARGE_CHARS} "
        f"({large_ms / max(small_ms, 1e-9):.1f}x for 4x the length; linear is 4x)"
    )
