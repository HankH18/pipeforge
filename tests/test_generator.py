"""Tests for :mod:`fixtures.generator` -- the synthetic corpus everything else trusts.

The generator is ground truth for the leakage harness and the integration suite:
``expected_entities`` is what those tests assert *absence* and *restoration* over.
If a planted literal never reaches the rendered document, or the mapping drifts
from the text, every downstream assertion phrased over it becomes vacuous while
staying green. So the properties pinned here are the ones the rest of the suite
silently depends on: determinism, mapping/text agreement, the size and
entity-count claims the README makes of the large brief, and the build doc
section 16 rule that no value in this repo can belong to a living person.

Nothing here imports the generator's private helpers to build an expected value.
Ranges, domains and counts are restated independently, and the fixture files and
README table are read as data.
"""

from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from faker import Faker

from fixtures import generator
from secure_context_pipeline.detection.registry import GAZETTEER_DIR, EntityRegistry

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "fixtures"
README = REPO_ROOT / "README.md"

SEED = generator.DEFAULT_SEED

#: Enough seeds to make a per-seed accident implausible, cheap enough to run every
#: time -- a full four-document build is a few milliseconds.
SEEDS = (1, 2, 3, 7, 19, 104)

# -- independently restated claims -------------------------------------------
# Section 11 of the build doc / README fixtures section. These are deliberately
# literals rather than imports of the generator's own constants: a test that reads
# its bound from the code under test cannot fail when that bound moves.

#: "~12,000 words", checked with a ten percent margin either side.
BRIEF_TARGET_WORDS = 12_000
BRIEF_WORD_MARGIN = 0.10

#: "200+ distinct entities".
BRIEF_MIN_DISTINCT = 200

#: RFC 2606 reserved second-level domains.
RESERVED_EMAIL_DOMAINS = frozenset({"example.com", "example.org", "example.net"})

SSN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
PHONE_RE = re.compile(r"\(?\b(\d{3})\)?[ -](\d{3})-(\d{4})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

#: Entity types that only one builder is supposed to plant. Wiring the wrong
#: builder to a kind keeps every other property in this file green.
SIGNATURE_TYPES = {
    "medical": frozenset({"MRN", "DIAGNOSIS", "MEDICATION", "LAB_RESULT", "INSURANCE_ID"}),
    "financial": frozenset({"SSN", "TAX_ID", "ACCOUNT_NUMBER", "AMOUNT"}),
    "legal": frozenset({"CASE_ID", "CASE_STRATEGY", "SETTLEMENT_TERM", "PRIVILEGED_MARKER"}),
    "legal_brief_large": frozenset({"CASE_ID", "CASE_STRATEGY", "SETTLEMENT_TERM"}),
}


#: The last word of an organisation name, as English writes one. Restated from the
#: register rather than read off the generator's pools: a list imported from the code
#: under test would shrink in step with a pool that lost an entry.
ORG_SUFFIXES = frozenset(
    {
        "Alliance",
        "Center",
        "Corp",
        "Escrow",
        "Group",
        "Health",
        "Holdings",
        "Hospital",
        "Inc",
        "LLC",
        "LLP",
        "Partners",
        "Plan",
        "Savings",
        "Securities",
        "Services",
        "Supply",
        "System",
        "Systems",
        "Trust",
        "Utilities",
    }
)

#: A run of title-case words (``&`` and the two bare-capital company forms included).
ORG_PHRASE_RE = re.compile(r"\b(?:[A-Z][a-z]+|LLC|LLP|&)(?:\s(?:[A-Z][a-z]+|LLC|LLP|&))+")

#: The fewest organisation names each document is known to name, so an empty scan
#: cannot pass for a clean one.
ORG_FLOORS = {"medical": 2, "legal": 3, "financial": 4, "legal_brief_large": 15}


def organisation_phrases(text: str) -> set[str]:
    """Every title-case phrase in ``text`` that ends on a company-name suffix.

    Structural, not a list of the names the generator happens to ship: a new
    carrier, hospital or corporate party added to a pool is caught by the same rule
    that catches the ones here today. The phrase ends at the LAST suffix word in the
    run, so "Cascade Meridian Health Plan" is one name and not two.
    """
    found: set[str] = set()
    for match in ORG_PHRASE_RE.finditer(text):
        words = match.group(0).split()
        tail = max((i for i, word in enumerate(words) if word in ORG_SUFFIXES), default=0)
        if tail:
            found.add(" ".join(words[: tail + 1]))
    return found


def all_planted(mapping: dict[str, list[str]]) -> set[str]:
    """Every distinct literal in an ``expected_entities`` mapping, type ignored."""
    return {value for values in mapping.values() for value in values}


def gazetteer_terms(filename: str) -> set[str]:
    """The term column of a shipped gazetteer, parsed here rather than imported."""
    terms: set[str] = set()
    for raw in (GAZETTEER_DIR / filename).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            terms.add(line.split("\t")[0].strip())
    return terms


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", generator.KINDS)
def test_same_seed_gives_a_byte_identical_document(kind: str) -> None:
    """The whole corpus contract rests on this: one seed, one document, every time.

    The committed fixtures, the leakage ground truth and the benchmark input are
    three separate calls that have to agree.
    """
    first = generator.generate(SEED, kind)
    second = generator.generate(SEED, kind)
    assert first == second
    assert generator.expected_entities(SEED, kind) == generator.expected_entities(SEED, kind)


@pytest.mark.parametrize("kind", generator.KINDS)
def test_different_seeds_give_different_documents(kind: str) -> None:
    """Seeds must actually vary the corpus -- a generator that ignores its seed
    would make the 100-run leakage harness one run repeated a hundred times."""
    rendered = {seed: generator.generate(seed, kind) for seed in SEEDS}
    assert len(set(rendered.values())) == len(SEEDS)


def test_generation_ignores_global_random_state() -> None:
    """Documents must not move when unrelated code seeds ``random`` or ``Faker``.

    Both are process-global; a single ``random.randrange`` in place of the
    per-document RNG would make the fixtures depend on whatever ran before them.
    """
    saved = random.getstate()
    try:
        random.seed(1)
        Faker.seed(1)
        before = generator.generate_all(SEED)

        random.seed(99)
        Faker.seed(4242)
        for _ in range(500):
            random.random()
        Faker("en_US").name()
        after = generator.generate_all(SEED)
    finally:
        # Both seeds are process-global; leave them as they were found.
        random.setstate(saved)
        Faker.seed(None)

    assert before == after


@pytest.mark.parametrize("hash_seed", ["0", "1", "12345"])
def test_documents_do_not_depend_on_the_interpreter_hash_seed(hash_seed: str) -> None:
    """Rendered in a fresh process under a different ``PYTHONHASHSEED``, the
    documents must be unchanged -- iterating a set anywhere on the build path
    would make the committed fixtures unreproducible on someone else's machine."""
    script = (
        "import sys\n"
        "from fixtures import generator\n"
        f"sys.stdout.write(repr(generator.generate_all({SEED})))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONHASHSEED": hash_seed},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == repr(generator.generate_all(SEED))


# ---------------------------------------------------------------------------
# the advertised surface
# ---------------------------------------------------------------------------


def test_generate_all_covers_exactly_the_advertised_kinds() -> None:
    """``KINDS``, ``FILENAMES`` and ``generate_all`` have to name the same set, and
    each entry must be the document ``generate`` returns for that kind."""
    assert set(generator.FILENAMES) == set(generator.KINDS)
    produced = generator.generate_all(SEED)
    assert set(produced) == set(generator.KINDS)
    for kind, text in produced.items():
        assert text == generator.generate(SEED, kind)
        assert text.strip()


@pytest.mark.parametrize("kind", generator.KINDS)
def test_each_kind_plants_its_own_entity_types(kind: str) -> None:
    """Each kind must carry the entity types that make it that kind of document.

    Cross-wiring a builder to the wrong kind leaves every other property in this
    file green -- the corpus would simply stop covering medical or financial data.
    """
    planted = set(generator.expected_entities(SEED, kind))
    assert SIGNATURE_TYPES[kind] <= planted


def test_medical_and_financial_signatures_do_not_appear_in_the_legal_documents() -> None:
    """Kind separation stated as exclusions, so a builder swap cannot hide."""
    for kind in ("legal", "legal_brief_large"):
        planted = set(generator.expected_entities(SEED, kind))
        assert not planted & {"SSN", "MRN", "DIAGNOSIS", "LAB_RESULT", "TAX_ID"}
    assert "CASE_ID" not in generator.expected_entities(SEED, "medical")
    assert "CASE_ID" not in generator.expected_entities(SEED, "financial")


@pytest.mark.parametrize("call", [generator.generate, generator.expected_entities])
def test_an_unknown_kind_is_rejected_by_name(call: object) -> None:
    """A typo'd kind must fail loudly at the call, not return an empty document."""
    with pytest.raises(ValueError) as excinfo:
        call(SEED, "medial")  # type: ignore[operator]
    assert "medial" in str(excinfo.value)


# ---------------------------------------------------------------------------
# the planted-entity mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("kind", generator.KINDS)
def test_every_planted_literal_appears_in_the_document(seed: int, kind: str) -> None:
    """The ground-truth contract. A literal in the mapping that is not in the text
    turns the leakage harness's "must be absent from the payload" assertion into a
    tautology: absent from the payload because it was never in the input."""
    document = generator.generate(seed, kind)
    planted = generator.expected_entities(seed, kind)
    assert planted
    missing = [
        (entity_type, value)
        for entity_type, values in planted.items()
        for value in values
        if value not in document
    ]
    assert missing == []


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("kind", generator.KINDS)
def test_every_organisation_the_document_names_is_in_the_ledger(seed: int, kind: str) -> None:
    """The other half of the ground-truth contract, and the half that was missing.

    ``test_every_planted_literal_appears_in_the_document`` checks the mapping against
    the text. Nothing checked the text against the mapping, so a value the generator
    wrote into a document and never handed to ``led.plant`` was invisible: not in the
    expected set, therefore not something any downstream test could fail on. The
    carrier and the hospital in the medical note were exactly that, and the carrier
    name reached the provider verbatim -- twice, in both strategies -- with the
    leakage harness reporting 100/100 clean the whole time.

    Phrased over the class rather than over the two literals that were found, because
    the defect is the class: this scans the rendered document for anything shaped like
    an organisation name and requires each one to be in the ledger. Case-folded on
    both sides -- the medical header and the brief's caption upper-case the name they
    render, and every needle scan in this repo folds case, so one ledger entry covers
    both spellings.
    """
    document = generator.generate(seed, kind)
    found = organisation_phrases(document)
    assert len(found) >= ORG_FLOORS[kind], (
        f"{kind}/{seed}: the scan found {len(found)} organisation-shaped phrases, "
        f"fewer than the {ORG_FLOORS[kind]} this document is known to name -- the "
        "scan has stopped seeing them, so its silence means nothing"
    )
    planted = {value.upper() for value in generator.expected_entities(seed, kind).get("ORG", [])}
    unplanted = sorted(name for name in found if name.upper() not in planted)
    assert unplanted == [], (
        f"{kind}/{seed}: organisation name(s) written into the document but never "
        f"planted, so no test can fail on them: {unplanted}"
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_the_medical_note_s_carrier_and_hospital_are_planted(seed: int) -> None:
    """The reported instance, pinned by position rather than by literal.

    Both names are read back out of the document -- the facility off the header line,
    the carrier off the insurance line -- so this stays true for every seed and fails
    if either stops being planted, whichever names the pools happen to hold.
    """
    document = generator.generate(seed, "medical")
    orgs = generator.expected_entities(seed, "medical").get("ORG", [])
    planted = {value.upper() for value in orgs}

    facility = document.splitlines()[0].strip()
    carrier = re.search(r"^\s*Insurance: (.+?), member ID ", document, re.MULTILINE)
    assert carrier is not None, "the insurance line has been reworded; re-derive it here"

    assert facility.upper() in planted, facility
    assert carrier.group(1).upper() in planted, carrier.group(1)


@pytest.mark.parametrize("kind", generator.KINDS)
def test_planted_values_are_non_empty_and_deduplicated(kind: str) -> None:
    """One literal, one entry: a repeated value would double-count the corpus and
    inflate the brief's distinct-entity total."""
    for entity_type, values in generator.expected_entities(SEED, kind).items():
        assert values, entity_type
        assert len(values) == len(set(values)), entity_type
        for value in values:
            assert value == value.strip()
            assert value


def test_non_restorable_types_are_exactly_the_types_the_registry_removes(
    registry: EntityRegistry,
) -> None:
    """``NON_RESTORABLE_ENTITY_TYPES`` must be derivable from ``entities.yaml``.

    It is documentation of registry policy: a type carries an ``action`` (strip or
    redact) so its span is removed rather than tokenised. If the two ever disagree,
    a round-trip assertion is skipped for a type that does restore, or run for one
    that cannot.
    """
    planted_types = {
        entity_type
        for seed in SEEDS
        for kind in generator.KINDS
        for entity_type in generator.expected_entities(seed, kind)
    }
    removed = {t for t in planted_types if registry.action_of(t) is not None}
    assert set(generator.NON_RESTORABLE_ENTITY_TYPES) == removed
    assert generator.NON_RESTORABLE_ENTITY_TYPES <= planted_types


@pytest.mark.parametrize("kind", ["legal", "legal_brief_large"])
def test_non_restorable_types_are_really_planted_in_the_legal_documents(kind: str) -> None:
    """The exclusion must not be vacuous: the two types it names have to be present
    in the documents, and present in the text, or "never on the wire" proves
    nothing."""
    document = generator.generate(SEED, kind)
    planted = generator.expected_entities(SEED, kind)
    for entity_type in generator.NON_RESTORABLE_ENTITY_TYPES:
        assert planted.get(entity_type), entity_type
        for value in planted[entity_type]:
            assert value in document


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("kind", generator.KINDS)
def test_people_have_distinct_full_names_and_distinct_surnames(kind: str, seed: int) -> None:
    """Two people sharing a surname make an absence assertion ambiguous: obfuscating
    one occurrence hides the leak of the other.

    Checked across seeds because a single seed can miss a collision by luck -- the
    brief casts forty people out of a few hundred Faker surnames.
    """
    planted = generator.expected_entities(seed, kind)
    full_names = [
        value
        for entity_type in ("NAME", "CLIENT_IDENTITY")
        for value in planted.get(entity_type, [])
        if " " in value
    ]
    assert len(full_names) >= 3
    assert len(set(full_names)) == len(full_names)
    surnames = [name.split()[-1] for name in full_names]
    assert len(set(surnames)) == len(surnames)


def test_clinical_terms_come_from_the_shipped_gazetteers() -> None:
    """Every planted medication and diagnosis must be a term the detector's
    gazetteer actually carries; planting one it does not know is an undetectable
    entity and a silent hole in the medical fixture."""
    medications = gazetteer_terms("medications.txt")
    diagnoses = gazetteer_terms("diagnoses.txt")
    assert medications and diagnoses

    # Forty seeds: three medications and two diagnoses are drawn per note, so this
    # exhausts both pools and no single off-gazetteer term can hide behind the draw.
    seen_meds: set[str] = set()
    seen_dx: set[str] = set()
    for seed in range(1, 41):
        planted = generator.expected_entities(seed, "medical")
        seen_meds |= set(planted["MEDICATION"])
        seen_dx |= set(planted["DIAGNOSIS"])
    assert seen_meds <= medications, sorted(seen_meds - medications)
    assert seen_dx <= diagnoses, sorted(seen_dx - diagnoses)
    assert len(seen_meds) >= 12
    assert len(seen_dx) >= 10


# ---------------------------------------------------------------------------
# the large brief's advertised size
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_the_large_brief_meets_the_documented_size_and_entity_claims(seed: int) -> None:
    """README section 9: "~12,000 words, 200+ distinct entities".

    Measured here against independently written bounds rather than the generator's
    own guard constants, so weakening that guard shows up as a failure instead of
    as a quietly smaller corpus.
    """
    document = generator.generate(seed, "legal_brief_large")
    words = len(document.split())
    low = int(BRIEF_TARGET_WORDS * (1 - BRIEF_WORD_MARGIN))
    high = int(BRIEF_TARGET_WORDS * (1 + BRIEF_WORD_MARGIN))
    assert low <= words <= high, f"seed {seed}: {words} words"

    distinct = all_planted(generator.expected_entities(seed, "legal_brief_large"))
    assert len(distinct) >= BRIEF_MIN_DISTINCT, f"seed {seed}: {len(distinct)} distinct"
    assert all(value in document for value in distinct)


def test_the_large_brief_dwarfs_the_short_fixtures() -> None:
    """The brief exists to be the long-document case; if it ever collapsed to the
    size of a memo the chunking and benchmark paths would stop being exercised."""
    brief = len(generator.generate(SEED, "legal_brief_large").split())
    for kind in ("medical", "legal", "financial"):
        assert brief > 10 * len(generator.generate(SEED, kind).split())


# ---------------------------------------------------------------------------
# build doc section 16 -- no real personal data
# ---------------------------------------------------------------------------


def every_document() -> list[str]:
    return [generator.generate(seed, kind) for seed in SEEDS for kind in generator.KINDS]


def test_every_ssn_is_in_a_never_issued_range() -> None:
    """SSNs must be incapable of belonging to a person: area 900-999 (never issued),
    group 01-49 (outside every ITIN range), non-zero serial."""
    found = [match for document in every_document() for match in SSN_RE.finditer(document)]
    assert len(found) >= 2 * len(SEEDS)
    for match in found:
        area, group, serial = (int(part) for part in match.groups())
        assert 900 <= area <= 999, match.group(0)
        assert 1 <= group <= 49, match.group(0)
        assert serial != 0, match.group(0)


def test_every_phone_number_is_in_the_reserved_fictional_block() -> None:
    """NANP reserves 555-0100 through 555-0199 for fictional use; anything outside
    it could ring a real handset."""
    found = [match for document in every_document() for match in PHONE_RE.finditer(document)]
    assert len(found) >= 4 * len(SEEDS)
    for match in found:
        _area, exchange, line = match.groups()
        assert exchange == "555", match.group(0)
        assert 100 <= int(line) <= 199, match.group(0)


def test_every_email_address_uses_an_rfc_2606_reserved_domain() -> None:
    """Reserved domains cannot be registered, so a generated address can never
    deliver to a real mailbox."""
    found = {
        match.group(0) for document in every_document() for match in EMAIL_RE.finditer(document)
    }
    assert len(found) >= 4 * len(SEEDS)
    for address in found:
        assert address.rsplit("@", 1)[1] in RESERVED_EMAIL_DOMAINS, address


# ---------------------------------------------------------------------------
# writing the corpus out
# ---------------------------------------------------------------------------


def test_write_all_writes_every_kind_under_its_own_filename(tmp_path: Path) -> None:
    """``write_all`` has to create the directory and put each kind in the file the
    rest of the repo looks it up by -- a crossed mapping ships a legal memo as the
    medical note and nothing downstream would notice."""
    out_dir = tmp_path / "nested" / "fixtures"
    generator.write_all(SEED, out_dir)

    written = sorted(path.name for path in out_dir.iterdir())
    assert written == sorted(generator.FILENAMES.values())
    for kind, filename in generator.FILENAMES.items():
        assert (out_dir / filename).read_text(encoding="utf-8") == generator.generate(SEED, kind)


def test_write_all_is_idempotent(tmp_path: Path) -> None:
    """Re-running the generator over an existing corpus must overwrite, not append
    or fail -- ``python -m fixtures.generator`` is the documented regenerate step."""
    generator.write_all(SEED, tmp_path)
    first = {name: (tmp_path / name).read_bytes() for name in generator.FILENAMES.values()}
    generator.write_all(SEED, tmp_path)
    second = {name: (tmp_path / name).read_bytes() for name in generator.FILENAMES.values()}
    assert first == second


def test_the_documented_regenerate_command_rewrites_the_corpus(tmp_path: Path) -> None:
    """``python -m fixtures.generator`` is the regenerate step the README names, and
    the source of the counts it publishes.

    Run against a copy of the package so a drifted generator cannot rewrite the
    committed corpus as a side effect of testing it.
    """
    package = tmp_path / "fixtures"
    package.mkdir()
    for name in ("__init__.py", "generator.py"):
        shutil.copy(FIXTURE_DIR / name, package / name)

    result = subprocess.run(
        [sys.executable, "-m", "fixtures.generator"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True,
        text=True,
        check=True,
    )

    # ``-m`` puts the working directory first on ``sys.path``, so the copy is what
    # ran; if that ever stopped being true these files would not exist.
    for kind, filename in generator.FILENAMES.items():
        written = (package / filename).read_text(encoding="utf-8")
        assert written == generator.generate(generator.DEFAULT_SEED, kind), filename
        line = next(row for row in result.stdout.splitlines() if row.startswith(filename))
        assert f" {len(written.split())} words" in line, line


@pytest.mark.parametrize("kind", generator.KINDS)
def test_the_committed_fixtures_are_what_the_generator_emits(kind: str) -> None:
    """The README invites a reviewer to regenerate and diff. If a committed fixture
    has drifted from the generator, ``expected_entities`` is ground truth for a
    document that is no longer on disk."""
    committed = (FIXTURE_DIR / generator.FILENAMES[kind]).read_text(encoding="utf-8")
    assert committed == generator.generate(generator.DEFAULT_SEED, kind)


def test_the_readme_fixture_table_matches_what_the_generator_produces() -> None:
    """The README publishes word, distinct-value and entity-type counts per fixture.
    They are measurements, and a stale table is a false claim in the deliverable."""
    readme = README.read_text(encoding="utf-8")
    header = "| Fixture | Words | Distinct planted values | Entity types |"
    assert header in readme, "the README fixtures table has moved or been renamed"
    table = readme.split(header, 1)[1].split("\n\n", 1)[0]

    for kind, filename in generator.FILENAMES.items():
        row = re.search(
            rf"^\|\s*`{re.escape(filename)}`\s*\|(.+)\|\s*$",
            table,
            re.MULTILINE,
        )
        assert row is not None, filename
        cells = [cell.replace("*", "").replace(",", "").strip() for cell in row.group(1).split("|")]
        claimed_words, claimed_distinct, claimed_types = (int(cell) for cell in cells[:3])

        document = generator.generate(generator.DEFAULT_SEED, kind)
        planted = generator.expected_entities(generator.DEFAULT_SEED, kind)
        assert claimed_words == len(document.split()), filename
        assert claimed_distinct == len(all_planted(planted)), filename
        assert claimed_types == len(planted), filename
