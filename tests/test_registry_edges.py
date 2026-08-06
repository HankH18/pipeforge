"""Registry lookups, recognizer construction, and the loader's remaining error paths.

``tests/test_detection.py`` proves the *shipped* registry detects the right things.
This file proves the layer underneath it: that each registry field shape
(``presidio:`` / ``patterns:`` / ``gazetteer:``) produces the recognizer it is
supposed to and no other, that every lookup helper answers correctly on a miss as
well as a hit, and that the gazetteer parser keeps exactly the lines it should.

Everything is asserted against a small synthetic registry written here, so the
expected values are literals rather than something re-derived from the code under
test. No assertion here reads ``entities.yaml``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_context_pipeline.detection import recognizers as recognizers_module
from secure_context_pipeline.detection import registry as registry_module
from secure_context_pipeline.detection.recognizers import (
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




def test_a_gazetteer_row_with_no_term_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
