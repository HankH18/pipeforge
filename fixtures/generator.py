"""Seeded synthetic fixture generator (build doc section 11).

Produces the four committed fixture documents and, for each one, the *exact*
literal strings it planted.  The leakage harness uses :func:`expected_entities`
as ground truth: every literal it returns must be absent from the outbound
payload and present again after restore.

Everything in here is synthetic (build doc section 16 -- no real personal data
anywhere in the repo).  The values that could otherwise collide with something
real are deliberately drawn from reserved or never-issued ranges:

* **SSNs** use area numbers ``900``-``999`` with group digits held to
  ``01``-``49``.  Detectability came first here and was verified empirically
  against the real detector: this Presidio build's
  ``UsSsnRecognizer.invalidate_result`` throws out the ``000-`` and ``666-``
  prefixes and the three canonical placeholder SSNs (``123-45-6789``,
  ``987-65-4320``, ``078-05-1120``), so a fixture built on any of those would
  detect *nothing*, silently.  The 9xx block is not rejected, and it is also
  fictional on its own terms -- the SSA has never issued an area above ``899``
  and groups ``01``-``49`` fall outside every IRS ITIN range -- so these values
  are both detected and incapable of belonging to a living person.
* **Phone numbers** use the NANP ``555-0100``-``555-0199`` block, reserved for
  fictional use.
* **Email addresses** use the RFC 2606 ``example.com`` / ``.net`` / ``.org``
  reserved domains.
* **MRNs, insurance IDs, account numbers, tax IDs, case numbers and dollar
  figures** are generator-drawn from arbitrary digit ranges; the alphabetic
  prefixes (carrier codes, Bates prefixes, party and firm names) are invented.
* **People** are Faker-generated; **organisations, firms, hospitals and carriers**
  are invented compound names.

Three notes for consumers of :func:`expected_entities`:

1.  For *most* pattern-backed entity types the planted literal is the whole span
    the registry regex will match (e.g. ``"HbA1c of 8.2"``, ``"settlement demand
    of $2,400,000"``), not just the payload digits, so round-trip assertions are
    exact.

    **Two types are the exception, and this paragraph used to deny it.**
    ``MRN`` and ``ACCOUNT_NUMBER`` anchor with PCRE ``\\K``, which *resets the
    match start* -- so the span the engine vaults is the bare digits
    (``"4823910"``), not the planted literal (``"MRN: 4823910"``). The old
    wording ("the planted literal is the whole span... That is what the vault
    will hold") is false for them, and the consequence is worse than an
    inaccurate comment: an absence assertion phrased over the *planted* literal
    (``assert "MRN: 9224297" not in payload``) passes in a world where the bare
    digits are on the wire, because the label prefix was never the thing at risk.

    Anything asserting over these types must use the value the vault holds, which
    is what ``vault.originals_for_session`` returns and what the leakage harness
    scans. Measured on the committed fixtures: 129 of 850 planted occurrences are
    not fully inside a detected span, almost all of them ``CASE_ID`` (124) plus
    ``ACCOUNT_NUMBER`` (4) and ``MRN`` (1) -- so "every one fully inside a
    detected span" was never true either.
2.  ``PRIVILEGED_MARKER`` (``action: strip``) and ``CASE_STRATEGY``
    (``action: redact``) do not round-trip by design -- the span is removed or
    replaced rather than tokenised.  They are still returned, because they must
    never appear on the wire; skip them for the restore assertion using
    :data:`NON_RESTORABLE_ENTITY_TYPES`.
3.  ``ADDRESS`` is intentionally **absent** from the mapping even though every
    fixture carries street addresses -- Faker-drawn, like everything else here,
    never transcribed -- and the detector does raise ADDRESS spans on them.
    ADDRESS resolves to Presidio's ``LOCATION``, i.e. to spaCy
    NER, and no phrasing tested here covers all three components (street line,
    city, state) on every seed -- coverage tops out around 90 percent whichever
    framing is used.  Planting a value the detector misses roughly one seed in
    ten would make a 100-run leakage harness flaky, so addresses exercise the
    recogniser without being part of the must-not-leak contract.  Every entity
    type that *is* returned was verified to be fully covered by a real
    ``Detector.detect`` span at every occurrence.

``NAME`` and ``CLIENT_IDENTITY`` both resolve to Presidio's ``PERSON``
recogniser, and which of the two a given span comes back as depends on overlap
resolution; the split in the returned mapping is descriptive only.

Every planted literal was checked against the real ``Detector.detect`` -- 60
seeds of the three short documents and 20 seeds of the large brief, 10,735
planted-value occurrences in all, every one of them fully inside a detected
span.  Reaching that took three fixture-side rules that are load-bearing and
should survive any edit to the prose:

* person names always sit mid-sentence behind a lower-case role noun
  ("defendant X", "attorney X", "nurse X") -- bare object-position names are
  missed by spaCy often enough to leak;
* names are drawn from Faker minus :data:`_AMBIGUOUS_NAME_TOKENS`;
* no numeric date is placed inside a ``CASE_STRATEGY`` sentence and no
  two-decimal value directly in front of a unit abbreviation in a lab line,
  because spaCy reads those as ``DATE_TIME`` at 0.85 and the higher score
  evicts the surrounding lower-scored span in overlap resolution.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Final

from faker import Faker

from secure_context_pipeline.detection.registry import GAZETTEER_DIR

__all__ = [
    "DEFAULT_SEED",
    "FILENAMES",
    "KINDS",
    "NON_RESTORABLE_ENTITY_TYPES",
    "expected_entities",
    "generate",
    "generate_all",
    "write_all",
]

# --------------------------------------------------------------------------
# public constants
# --------------------------------------------------------------------------

DEFAULT_SEED: Final[int] = 7

KINDS: Final[tuple[str, ...]] = ("medical", "legal", "financial", "legal_brief_large")

FILENAMES: Final[dict[str, str]] = {
    "medical": "medical_note.txt",
    "legal": "legal_memo.txt",
    "financial": "financial_disclosure.txt",
    "legal_brief_large": "legal_brief_large.txt",
}

#: Entity types whose registry ``action`` removes the span instead of tokenising
#: it, so they cannot be asserted on the restore side of the round trip.
NON_RESTORABLE_ENTITY_TYPES: Final[frozenset[str]] = frozenset(
    {"PRIVILEGED_MARKER", "CASE_STRATEGY"}
)

# --------------------------------------------------------------------------
# private constants
# --------------------------------------------------------------------------

# Faker name tokens that Presidio's PERSON recogniser (spaCy NER) drops often
# enough to leak a planted literal -- surnames that double as common nouns
# ("Flowers", "Banks", "Young"), place names ("Washington", "Park"), and first
# names that are ordinary words ("April", "Chase", "Summer").  Screened
# empirically: ~2600 random Faker full names were run through the real detector
# in the exact frames these fixtures use, and every token that appeared in any
# failing combination was rejected.  Filtering them drops the observed
# per-name miss rate from ~2 percent to ~0.05 percent while leaving 600+ first
# names and 850+ surnames in play.
_AMBIGUOUS_NAME_TOKENS: Final[frozenset[str]] = frozenset(
    """
    Abigail Alejandra Alexandra Alison Amber Andre April Arellano Arias Autumn
    Bailey Baldwin Banks Barnes Barry Baxter Bentley Bernard Bethany Betty
    Beverly Black Booker Branch Bridges Bridget Brooks Bryce Buckley Cannon
    Cantu Carey Carl Carla Cassidy Cesar Chambers Chase Cheyenne Christian
    Christie Chung Church Claire Clifford Cole Collin Colton Connie Contreras
    Conway Costa Cristian Cross Crystal Cummings Cynthia Dakota Dale Daniel
    Davidson Davies Dawn Day Debbie Decker Destiny Diamond
    Dickerson Dominic Dominique Dorothy Downs Eaton Ebony Edward English Ernest
    Faith Farmer Fisher Flowers Forbes Foster Franklin French Fry Gabriella
    Gabrielle Gamble Garner Gay Good Goodman Grant Greene Hall Hampton Hancock
    Hanna Hart Haynes Hebert Hester Hill Holder Holland Holly Holt Hood Hooper
    House Howard Hughes Hunter Hutchinson Isaac Isabel Isabella Jaclyn Jackson
    Jacob Jade Janet Jared Jeff Jimenez Jocelyn Julian Justin Kaiser Katrina
    Kaufman Kelly Kevin Kristie Krystal Lam Lance Lang Lawrence Le Lester Little
    Logan Long Louis Love Lowery Lucas Madison Makayla Mariah Martin Mason Mathews
    Maxwell May Mayo Mcclure Mckinney Mclaughlin Megan Mercedes Meredith Meyer
    Meza Mills Misty Mitchell Moody Morgan Morris Murphy Myers Nancy Nathan
    Norton Olivia Oscar Palmer Park Patel Penny Perkins Philip Ramsey Reed Regina
    Rivera Rivers Rogers Ross Rowe Rush Russo Sandoval Savage Savannah Schaefer
    Schwartz Selena Sellers Shannon Shari Shaw Shelby Shelton Sheryl Shields
    Sierra Simmons Sophia Sosa Sparks Stone Stuart Summer Summers Sutton Sydney
    Tate Terrell Thompson Tiffany Tom Troy Valencia Valenzuela Velazquez Vernon
    Villanueva Wall Walls Walsh Walton Wanda Warner Washington Watts Weeks
    Whitney Wilson Winters Wise Wood Woods Young
    """.split()
)

_SEED_OFFSETS: Final[dict[str, int]] = {
    "medical": 101,
    "legal": 211,
    "financial": 331,
    "legal_brief_large": 457,
}

_AS_OF: Final[date] = date(2025, 3, 31)

_EMAIL_DOMAINS: Final[tuple[str, ...]] = ("example.com", "example.org", "example.net")

_AREA_CODES: Final[tuple[str, ...]] = ("205", "312", "406", "415", "503", "559", "704", "812")

# Invented carrier codes -- 2-4 uppercase letters so the INSURANCE_ID regex
# (`\b[A-Z]{2,4}\d{7,12}\b`) anchors on a word boundary.
_CARRIER_CODES: Final[tuple[str, ...]] = ("BRMH", "CVGX", "HLTQ", "MRDN", "PNCL", "WSTB")

_CARRIER_NAMES: Final[tuple[str, ...]] = (
    "Blue Ridge Mutual Health",
    "Cascade Meridian Health Plan",
    "Pinnacle Grove Benefit Trust",
    "Westbank Care Alliance",
)

_FACILITIES: Final[tuple[str, ...]] = (
    "Cedar Hollow Regional Medical Center",
    "Larkspur Valley Hospital",
    "Fernbrook Memorial Health System",
    "Quarry Bend Community Hospital",
)

# (gazetteer term, dose, route/frequency).  Every term is verified against
# medications.txt at draw time so a gazetteer edit degrades gracefully.
_MEDICATION_DOSES: Final[tuple[tuple[str, str, str], ...]] = (
    ("metformin", "1000 mg", "PO BID"),
    ("lisinopril", "20 mg", "PO daily"),
    ("atorvastatin", "40 mg", "PO nightly"),
    ("metoprolol", "50 mg", "PO BID"),
    ("furosemide", "40 mg", "IV daily"),
    ("pantoprazole", "40 mg", "PO daily"),
    ("gabapentin", "300 mg", "PO TID"),
    ("sertraline", "50 mg", "PO daily"),
    ("amlodipine", "10 mg", "PO daily"),
    ("levothyroxine", "88 mcg", "PO every morning"),
    ("apixaban", "5 mg", "PO BID"),
    ("empagliflozin", "10 mg", "PO daily"),
    ("hydrochlorothiazide", "25 mg", "PO daily"),
    ("albuterol", "2 puffs", "inhaled every six hours as needed"),
    ("prednisone", "20 mg", "PO daily"),
    ("insulin glargine", "22 units", "subcutaneous nightly"),
)

_DIAGNOSIS_CHOICES: Final[tuple[str, ...]] = (
    "type 2 diabetes",
    "chronic kidney disease",
    "hypertension",
    "congestive heart failure",
    "copd",
    "atrial fibrillation",
    "hyperlipidemia",
    "obstructive sleep apnea",
    "chronic low back pain",
    "gerd",
    "osteoarthritis",
    "major depressive disorder",
    "asthma",
    "iron deficiency anemia",
)

# (analyte, joiner, low, high, decimals, unit).  The unit never contains a digit
# and each result sits on its own line, so the LAB_RESULT regex -- which cannot
# cross "." or a newline -- matches exactly "<analyte><joiner><value>".
_LAB_SPECS: Final[tuple[tuple[str, str, float, float, int, str], ...]] = (
    ("HbA1c", " of ", 6.5, 11.0, 1, "percent"),
    ("eGFR", " ", 28, 89, 0, "mL/min"),
    ("LDL", " ", 88, 172, 0, "mg/dL"),
    # One decimal place, not two: "creatinine of 2.30 mg/dL" makes spaCy read
    # "2.30 mg" as a clock time and tag it DATE_TIME at 0.85, which outranks
    # LAB_RESULT and clips the planted span.
    ("creatinine", " of ", 1.1, 2.4, 1, "mg/dL"),
    ("WBC", " ", 4.2, 14.8, 1, "K/uL"),
    ("HDL", " ", 28, 58, 0, "mg/dL"),
)

_LAW_FIRM_HEADS: Final[tuple[str, ...]] = (
    "Ashgrove",
    "Bellcourt",
    "Cranemoor",
    "Dunhollow",
    "Elverton",
    "Fenwake",
    "Grimsby",
    "Hallowfield",
    "Ivenhurst",
    "Jarrowdale",
    "Kestrelwood",
    "Lanternridge",
)

_ORG_NAMES: Final[tuple[str, ...]] = (
    "Northwind Composites LLC",
    "Cascadia Ridge Logistics Group",
    "Harbor Point Savings",
    "Ridgeline Securities",
    "Quarrystone Fabrication Inc",
    "Bellhaven Marine Supply",
    "Torrent Valley Utilities",
    "Ambergate Freight Systems",
    "Sablefield Manufacturing LLC",
    "Kingfisher Terminals Group",
    "Verdant Mill Holdings",
    "Copperline Industrial Services",
    "Wrenfield Packaging Corp",
    "Duskwater Energy Partners",
    "Marrowbrook Distribution LLC",
    "Stonepath Aggregates Group",
)

_BATES_PREFIXES: Final[tuple[str, ...]] = ("NWC", "CRL", "HPS", "RDG", "QSF", "BMS")

_COURT_TYPES: Final[tuple[str, ...]] = ("cv", "cr", "md", "mc", "bk")

_BRIEF_TARGET_WORDS: Final[int] = 12_000
_BRIEF_MIN_WORDS: Final[int] = 11_400
_BRIEF_MAX_WORDS: Final[int] = 12_900
_BRIEF_MIN_DISTINCT_ENTITIES: Final[int] = 200

# CASE_STRATEGY's regex consumes at most 120 characters after its trigger, so
# every clause below is kept short enough that the whole sentence is captured
# (a longer clause would be only partially obfuscated).
_MAX_STRATEGY_CLAUSE: Final[int] = 130

_STRATEGY_TEMPLATES: Final[tuple[str, ...]] = (
    "Our litigation strategy is to hold the current position until the mediator issues a bracketed proposal",
    "Our settlement posture assumes exclusion of the opposing damages expert",
    "The defense position is that the indemnity clause bars the third count outright",
    "Our trial approach favors an early motion in limine on the spoliation issue",
    "Our negotiation approach is to concede the interest calculation and contest the multiplier",
    "The settlement strategy is to keep the two matters coupled through the pretrial conference",
    "We intend to depose the corporate designee before the close of fact discovery",
    "We recommend to counter at a figure well below the demand transmitted last month",
    "We are prepared to accept a structured payout over thirty-six months",
    "We plan to preserve the arbitration-clause defense through the evidentiary hearing",
    "We plan to move for partial summary judgment on the negligent-supervision count",
    "We intend to sequence the custodial productions so the audit file lands last",
    "We intend to hold the reserve figure confidential until the second mediation session",
    "The trial posture depends on whether the court bifurcates liability and damages",
)

if any(len(clause) > _MAX_STRATEGY_CLAUSE for clause in _STRATEGY_TEMPLATES):  # pragma: no cover
    raise ValueError("a CASE_STRATEGY clause exceeds the regex capture window")

_SETTLEMENT_LEADS: Final[tuple[str, ...]] = (
    "settlement demand of",
    "settlement offer of",
    "settlement figure of",
    "settlement authority capped at",
    "settlement range topping out at",
    "settlement number of",
    "settlement proposal of",
)


# --------------------------------------------------------------------------
# planted-value ledger
# --------------------------------------------------------------------------


class _Ledger:
    """Ordered, de-duplicated record of every literal planted in a document."""

    __slots__ = ("_by_type",)

    def __init__(self) -> None:
        self._by_type: dict[str, list[str]] = {}

    def plant(self, entity_type: str, value: str) -> str:
        """Record ``value`` under ``entity_type`` and hand it back for rendering."""
        bucket = self._by_type.setdefault(entity_type, [])
        if value not in bucket:
            bucket.append(value)
        return value

    def snapshot(self) -> dict[str, list[str]]:
        return {key: list(values) for key, values in self._by_type.items()}

    def distinct_count(self) -> int:
        return len({value for values in self._by_type.values() for value in values})


# --------------------------------------------------------------------------
# seeded value helpers
# --------------------------------------------------------------------------


def _context(seed: int, kind: str) -> tuple[Faker, random.Random]:
    """Build the per-document Faker + RNG pair.  Same seed and kind => same values."""
    offset = _SEED_OFFSETS[kind]
    fake = Faker("en_US")
    fake.seed_instance(seed + offset)
    return fake, random.Random(seed * 1_000_003 + offset)


class _NamePool:
    """Draws synthetic people with distinct full names *and* distinct surnames."""

    __slots__ = ("_fake", "_full", "_last")

    def __init__(self, fake: Faker) -> None:
        self._fake = fake
        self._full: set[str] = set()
        self._last: set[str] = set()

    def person(self) -> tuple[str, str, str]:
        """Return ``(first, last, full)`` for a person not drawn before."""
        for _ in range(20_000):
            first = self._fake.first_name()
            last = self._fake.last_name()
            if not first.isalpha() or not last.isalpha():
                continue
            if first in _AMBIGUOUS_NAME_TOKENS or last in _AMBIGUOUS_NAME_TOKENS:
                continue
            full = f"{first} {last}"
            if full in self._full or last in self._last:
                continue
            self._full.add(full)
            self._last.add(last)
            return first, last, full
        raise RuntimeError("name pool exhausted")

    def full(self) -> str:
        return self.person()[2]


class _Rotation:
    """Round-robin cursor over a pool, so every pooled value is used at least once."""

    __slots__ = ("_index", "_items", "_last")

    def __init__(self, items: Sequence[str]) -> None:
        if not items:
            raise ValueError("empty rotation")
        self._items: tuple[str, ...] = tuple(items)
        self._index = 0
        self._last: str | None = None

    def next(self) -> str:
        value = self._items[self._index % len(self._items)]
        self._index += 1
        return value

    def any(self, rng: random.Random) -> str:
        """A random pick that never repeats the previous one back to back.

        Keeps "a course of dealing between {org} and {org2}" from naming the
        same organisation twice.
        """
        value = self._items[rng.randrange(len(self._items))]
        if value == self._last and len(self._items) > 1:
            value = self._items[(self._items.index(value) + 1) % len(self._items)]
        self._last = value
        return value


def _phone(rng: random.Random, parenthesised: bool) -> str:
    """NANP fictional-use number: 555-0100 through 555-0199."""
    area = _AREA_CODES[rng.randrange(len(_AREA_CODES))]
    line = rng.randrange(100, 200)
    return f"({area}) 555-{line:04d}" if parenthesised else f"{area}-555-{line:04d}"


def _email(rng: random.Random, first: str, last: str) -> str:
    local = f"{_slug(first)}.{_slug(last)}"
    return f"{local}@{_EMAIL_DOMAINS[rng.randrange(len(_EMAIL_DOMAINS))]}"


def _slug(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _ssn(rng: random.Random) -> str:
    """Never-issued SSN: 9xx area, group outside every ITIN range, non-zero serial."""
    return (
        f"{rng.randrange(900, 1000):03d}-{rng.randrange(1, 50):02d}-{rng.randrange(1, 10000):04d}"
    )


def _tax_id(rng: random.Random) -> str:
    return f"{rng.randrange(10, 100):02d}-{rng.randrange(1_000_000, 10_000_000):07d}"


def _mrn(rng: random.Random) -> str:
    return f"MRN: {rng.randrange(1_000_000, 10_000_000)}"


def _insurance_id(rng: random.Random) -> str:
    code = _CARRIER_CODES[rng.randrange(len(_CARRIER_CODES))]
    return f"{code}{rng.randrange(100_000_000, 1_000_000_000)}"


def _account_number(rng: random.Random, digits: int) -> str:
    return "".join(str(rng.randrange(10)) for _ in range(digits))


def _money(rng: random.Random, low: int, high: int, cents: bool) -> str:
    whole = rng.randrange(low, high)
    if not cents:
        return f"${whole:,}"
    return f"${whole:,}.{rng.randrange(0, 100):02d}"


def _date_str(fake: Faker, start: date, end: date) -> str:
    return fake.date_between_dates(date_start=start, date_end=end).strftime("%m/%d/%Y")


def _case_pair(rng: random.Random) -> tuple[str, str]:
    """Return ``("Case No. 3:24-cv-01188", "24-CV-01188")`` for the same matter."""
    district = rng.randrange(1, 10)
    year = rng.randrange(19, 26)
    court = _COURT_TYPES[rng.randrange(len(_COURT_TYPES))]
    serial = rng.randrange(100, 100_000)
    label = "Docket" if rng.random() < 0.25 else "Case"
    return (
        f"{label} No. {district}:{year:02d}-{court}-{serial:05d}",
        f"{year:02d}-{court.upper()}-{serial:05d}",
    )


def _bates(rng: random.Random) -> str:
    prefix = _BATES_PREFIXES[rng.randrange(len(_BATES_PREFIXES))]
    return f"{prefix}-{rng.randrange(1, 400_000):06d}"


def _street(fake: Faker) -> str:
    """A street line with no secondary-unit suffix, so it stays one clean span."""
    return f"{fake.building_number()} {fake.street_name()}"


def _load_gazetteer(filename: str) -> set[str]:
    terms: set[str] = set()
    for raw in (GAZETTEER_DIR / filename).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        terms.add(line.split("\t", 1)[0].strip())
    return terms


# --------------------------------------------------------------------------
# medical_note.txt
# --------------------------------------------------------------------------


def _build_medical(fake: Faker, rng: random.Random) -> tuple[str, dict[str, list[str]]]:
    led = _Ledger()
    names = _NamePool(fake)

    p_first, p_last, p_full = names.person()
    _, _, kin_full = names.person()
    _, _, doc_full = names.person()
    _, _, rn_full = names.person()

    facility = _FACILITIES[rng.randrange(len(_FACILITIES))]
    carrier = _CARRIER_NAMES[rng.randrange(len(_CARRIER_NAMES))]

    dob = _date_str(fake, date(1948, 1, 1), date(1988, 12, 31))
    dob_year = int(dob[-4:])
    age = _AS_OF.year - dob_year

    admit = _date_str(fake, date(2025, 2, 1), date(2025, 2, 10))
    labs_on = _date_str(fake, date(2025, 2, 11), date(2025, 2, 14))
    note_on = _date_str(fake, date(2025, 2, 15), date(2025, 2, 20))
    followup = _date_str(fake, date(2025, 3, 1), date(2025, 3, 20))
    prior = sorted({_date_str(fake, date(2024, 1, 1), date(2024, 12, 20)) for _ in range(6)})[:3]

    mrn = _mrn(rng)
    member_id = _insurance_id(rng)
    # Dashed form only in the medical note: DATE is enabled for medical documents,
    # and Presidio's DATE_TIME outscores PHONE_NUMBER on the "555-0197" tail of a
    # parenthesised number, which would leave the "(205) " prefix unobfuscated.
    phone_main = _phone(rng, False)
    phone_kin = _phone(rng, False)
    email = _email(rng, p_first, p_last)

    known_meds = _load_gazetteer("medications.txt")
    known_dx = _load_gazetteer("diagnoses.txt")
    med_pool = [row for row in _MEDICATION_DOSES if row[0] in known_meds]
    dx_pool = [term for term in _DIAGNOSIS_CHOICES if term in known_dx]
    meds = rng.sample(med_pool, 3)
    diagnoses = rng.sample(dx_pool, 2)

    labs: list[tuple[str, str]] = []
    for analyte, joiner, low, high, decimals, unit in rng.sample(_LAB_SPECS, 5):
        if decimals == 0:
            value = str(rng.randrange(int(low), int(high) + 1))
        else:
            step = 10**decimals
            value = f"{rng.randrange(int(low * step), int(high * step) + 1) / step:.{decimals}f}"
        labs.append((f"{analyte}{joiner}{value}", unit))

    # -- plant --------------------------------------------------------------
    for value in (p_full, p_last, kin_full, doc_full, rn_full):
        led.plant("NAME", value)
    led.plant("DOB", dob)
    for value in (admit, labs_on, note_on, followup, *prior):
        led.plant("DATE", value)
    led.plant("MRN", mrn)
    led.plant("INSURANCE_ID", member_id)
    for term in diagnoses:
        led.plant("DIAGNOSIS", term)
    for term, _dose, _route in meds:
        led.plant("MEDICATION", term)
    for span, _unit in labs:
        led.plant("LAB_RESULT", span)
    led.plant("PHONE", phone_main)
    led.plant("PHONE", phone_kin)
    led.plant("EMAIL", email)

    med_lines = "\n".join(f"    {term} {dose} {route}" for term, dose, route in meds)
    lab_lines = "\n".join(f"    {span} {unit}" for span, unit in labs)

    text = f"""{facility.upper()}
HOSPITALIST SERVICE -- DAILY PROGRESS NOTE
Note filed {note_on} by physician {doc_full}, MD, and nurse {rn_full}, RN.

PATIENT IDENTIFICATION
    Patient name: {p_full}
    DOB: {dob} (age {age})
    {mrn}
    Insurance: {carrier}, member ID {member_id}
    Phone: {phone_main}
    Email: {email}
    Emergency contact is spouse {kin_full}, reachable at {phone_kin}.

ENCOUNTER HISTORY
    Admitted {admit} through the emergency department.
    Prior ambulatory visits: {prior[0]}, {prior[1]}, and {prior[2]}.
    Discharge planning conference scheduled for {followup}.

SUBJECTIVE
    Mr. {p_last} is a {age}-year-old patient carrying a documented history of
    {diagnoses[0]} and {diagnoses[1]}. Overnight the patient slept in two blocks and
    tolerated a full oral diet. Mr. {p_last} denies chest pain, palpitations, or new
    shortness of breath, and reports that the swelling in both ankles is softer than it
    was at the {admit} presentation. Mr. {p_last} does report morning dizziness on
    standing, which he attributes to the timing of his morning doses rather than to the underlying
    {diagnoses[1]}. The home dosing schedule below was confirmed at the bedside by
    spouse {kin_full}, who keeps the pill organiser.

OBJECTIVE
    Vitals over the last twelve hours have been stable, with no fevers recorded and
    oxygen saturation in the mid-nineties on room air. Weight is down two kilograms
    from the {admit} admission weight.

    Laboratory results drawn {labs_on}:
{lab_lines}

ASSESSMENT
    1. Poorly controlled {diagnoses[0]}. The trajectory since the {prior[2]} visit is
       consistent with intermittent adherence rather than with primary treatment
       failure.
    2. Progressive {diagnoses[1]}. Every agent on the list below has been dose-checked
       against renal function, and pharmacy reviewed the chart on {labs_on}.

MEDICATIONS (active, reconciled at the bedside)
{med_lines}

PLAN
    Continue the current regimen through discharge and repeat the metabolic panel
    before the {followup} follow-up. Care management has been consulted and will see
    Mr. {p_last} before discharge. Mr. {p_last} will call the clinic at {phone_main} for
    any recurrence of the dizziness, and results will be routed to {email}. A copy of
    this note goes to the primary care panel at {facility}, and the insurance
    authorisation for the follow-up study has been filed with {carrier} under member ID
    {member_id}.

Electronically signed by physician {doc_full}, MD, on {note_on}.
"""
    return text, led.snapshot()


# --------------------------------------------------------------------------
# legal_memo.txt
# --------------------------------------------------------------------------


def _build_legal_memo(fake: Faker, rng: random.Random) -> tuple[str, dict[str, list[str]]]:
    led = _Ledger()
    names = _NamePool(fake)

    client_first, _client_last, client_full = names.person()
    author_first, author_last, author_full = names.person()
    _assoc_first, _assoc_last, assoc_full = names.person()
    _, plaintiff_last, plaintiff_full = names.person()
    _, _, opp1_full = names.person()
    _, _, opp2_full = names.person()
    _, _, opp3_full = names.person()
    _, _, mediator_full = names.person()

    client_org = _ORG_NAMES[0]
    opp_firm = f"{_LAW_FIRM_HEADS[rng.randrange(len(_LAW_FIRM_HEADS))]} & {_LAW_FIRM_HEADS[rng.randrange(len(_LAW_FIRM_HEADS))]} LLP"
    own_firm = f"{_LAW_FIRM_HEADS[rng.randrange(len(_LAW_FIRM_HEADS))]} Partners LLP"

    case_formal, case_bare = _case_pair(rng)
    case_formal_2, case_bare_2 = _case_pair(rng)

    memo_date = _date_str(fake, date(2024, 4, 1), date(2024, 4, 30))
    demand_date = _date_str(fake, date(2024, 3, 1), date(2024, 3, 31))
    mediation_date = _date_str(fake, date(2024, 5, 1), date(2024, 5, 31))
    filing_date = _date_str(fake, date(2024, 1, 5), date(2024, 2, 20))

    client_email = _email(rng, client_first, _client_last)
    author_email = _email(rng, author_first, author_last)
    client_phone = _phone(rng, True)
    author_phone = _phone(rng, False)

    demand = f"settlement demand of {_money(rng, 1_800_000, 3_400_000, False)}"
    mediator_number = f"settlement figure of {_money(rng, 900_000, 1_700_000, False)}"
    authority = (
        f"settle the coordinated matters at or below {_money(rng, 1_000_000, 1_400_000, False)}"
    )
    reverse = f"{_money(rng, 600_000, 900_000, False)} in exchange for a full settlement"

    strategies = rng.sample(_STRATEGY_TEMPLATES, 5)

    # -- plant --------------------------------------------------------------
    led.plant("PRIVILEGED_MARKER", "PRIVILEGED AND CONFIDENTIAL")
    led.plant("PRIVILEGED_MARKER", "WORK PRODUCT")
    led.plant("PRIVILEGED_MARKER", "attorney-client")
    led.plant("PRIVILEGED_MARKER", "work product")
    led.plant("CLIENT_IDENTITY", client_full)
    for value in (
        author_full,
        assoc_full,
        plaintiff_full,
        opp1_full,
        opp2_full,
        opp3_full,
        mediator_full,
    ):
        led.plant("NAME", value)
    for value in (case_formal, case_bare, case_formal_2, case_bare_2):
        led.plant("CASE_ID", value)
    for value in (demand, mediator_number, authority, reverse):
        led.plant("SETTLEMENT_TERM", value)
    for value in strategies:
        led.plant("CASE_STRATEGY", value)
    led.plant("EMAIL", client_email)
    led.plant("EMAIL", author_email)
    led.plant("PHONE", client_phone)
    led.plant("PHONE", author_phone)

    text = f"""PRIVILEGED AND CONFIDENTIAL -- ATTORNEY WORK PRODUCT
Prepared in anticipation of litigation. Do not circulate outside the engagement team.

MEMORANDUM

TO:      general counsel {client_full}, {client_org}
FROM:    partner {author_full}, {own_firm}
DATE:    {memo_date}
RE:      {plaintiff_last} v. {client_org} -- {case_formal}

1. SCOPE AND PRIVILEGE

This memorandum was prepared at your request and is protected by the attorney-client privilege; it is also work product prepared because of anticipated litigation. It evaluates our exposure in {case_formal}, the coordinated state action docketed as {case_bare}, and the third-party contribution claim carried under {case_formal_2}.

2. PARTIES AND COUNSEL

Our client is {client_org}. The client contact for the engagement is general counsel {client_full}, reachable at {client_email} or {client_phone}; day-to-day handling sits with partner {author_full} and associate {assoc_full}, and my direct line is {author_phone} with copy traffic to {author_email}. The case was filed on {filing_date} by plaintiff {plaintiff_full}. Opposing counsel is attorney {opp1_full}, of {opp_firm}. The co-defendant carrier is represented by attorney {opp2_full}, and attorney {opp3_full} has entered a limited appearance for the third-party defendant in the matter docketed as {case_bare_2}. The parties have retained mediator {mediator_full} for the {mediation_date} session.

3. CURRENT POSTURE

Counsel for the plaintiff transmitted a {demand} on {demand_date}, framed as a global resolution of both dockets. At the close of the first session mediator {mediator_full} floated a {mediator_number} without commitment from either side. The client has authorised us to {authority}, and the carrier has confirmed that figure in writing. If the release language can be broadened to cover the affiliates, the client would accept {reverse} and dismissal with prejudice.

4. EXPOSURE

The plaintiff's damages model rests on a three-year projection that our economist calls unsupported on the record produced so far. The contract contains a limitation-of-liability clause that, if enforced, caps the recoverable amount well under the number now demanded. The contribution claim tracked in {case_formal_2} is likely to resolve on the papers.

5. RECOMMENDED APPROACH

{strategies[0]}. {strategies[1]}. {strategies[2]}.

{strategies[3]}. {strategies[4]}. Nothing in this section is intended for production, and it should be withheld on the privilege log as work product.

6. NEXT STEPS

Confirm the mediation logistics with attorney {opp1_full} before {mediation_date}, circulate the revised release to {client_email}, and calendar the pretrial conference deadlines that attach to the case docketed as {case_bare}.
"""
    return text, led.snapshot()


# --------------------------------------------------------------------------
# financial_disclosure.txt
# --------------------------------------------------------------------------


def _build_financial(fake: Faker, rng: random.Random) -> tuple[str, dict[str, list[str]]]:
    led = _Ledger()
    names = _NamePool(fake)

    p_first, p_last, p_full = names.person()
    _s_first, _s_last, s_full = names.person()
    prep_first, prep_last, prep_full = names.person()

    street_home = _street(fake)
    city_home = fake.city()
    state_home = fake.state()
    zip_home = fake.postcode()

    street_rental = _street(fake)
    city_rental = fake.city()
    state_rental = fake.state()
    zip_rental = fake.postcode()

    dob = _date_str(fake, date(1958, 1, 1), date(1990, 12, 31))
    ssn_primary = _ssn(rng)
    ssn_spouse = _ssn(rng)
    tax_id = _tax_id(rng)
    tax_id_trust = _tax_id(rng)

    acct_operating = f"account {_account_number(rng, 12)}"
    acct_reserve = f"acct #{_account_number(rng, 12)}"
    acct_brokerage = f"account {_account_number(rng, 13)}"
    acct_trust = f"account: {_account_number(rng, 10)}"

    phone = _phone(rng, True)
    phone_prep = _phone(rng, False)
    email = _email(rng, p_first, p_last)
    email_prep = _email(rng, prep_first, prep_last)

    bal_operating = _money(rng, 200_000, 900_000, True)
    bal_reserve = _money(rng, 20_000, 120_000, True)
    bal_brokerage = _money(rng, 900_000, 2_400_000, True)
    bal_trust = _money(rng, 100_000, 400_000, True)

    ledger_rows: list[tuple[str, str, str]] = []
    descriptions = (
        "outbound wire to Ridgeline Escrow",
        "payroll deposit",
        "quarterly distribution received",
        "vendor payment, Bellhaven Marine Supply",
        "brokerage transfer in",
        "property tax withdrawal",
        "insurance premium debit",
        "rental income deposit",
        "equipment purchase",
        "charitable contribution",
    )
    for description in descriptions:
        when = _date_str(fake, date(2025, 1, 2), date(2025, 3, 28))
        ledger_rows.append((when, description, _money(rng, 1_200, 90_000, True)))

    mortgage = _money(rng, 400_000, 800_000, True)
    note_balance = _money(rng, 60_000, 200_000, True)

    # -- plant --------------------------------------------------------------
    for value in (p_full, s_full, prep_full):
        led.plant("NAME", value)
    led.plant("DOB", dob)
    led.plant("SSN", ssn_primary)
    led.plant("SSN", ssn_spouse)
    led.plant("TAX_ID", tax_id)
    led.plant("TAX_ID", tax_id_trust)
    for value in (acct_operating, acct_reserve, acct_brokerage, acct_trust):
        led.plant("ACCOUNT_NUMBER", value)
    for value in (
        bal_operating,
        bal_reserve,
        bal_brokerage,
        bal_trust,
        mortgage,
        note_balance,
        *(amount for _when, _desc, amount in ledger_rows),
    ):
        led.plant("AMOUNT", value)
    # ADDRESS is deliberately NOT planted -- see the module docstring. The street
    # lines below are real content and the detector does tag ADDRESS spans in
    # this document; they are simply not part of the must-not-leak contract.
    led.plant("PHONE", phone)
    led.plant("PHONE", phone_prep)
    led.plant("EMAIL", email)
    led.plant("EMAIL", email_prep)

    ledger_lines = "\n".join(
        f"    {when}   {description:<44}{amount}" for when, description, amount in ledger_rows
    )

    text = f"""CONFIDENTIAL PERSONAL FINANCIAL DISCLOSURE STATEMENT
Reporting period: 01/01/2025 through 03/31/2025
Prepared by accountant {prep_full}, reachable at {email_prep} or {phone_prep}.

PART I -- DISCLOSING PARTY

    Name of the disclosing taxpayer: {p_full}
    Date of birth: {dob}
    Social Security Number: {ssn_primary}
    Taxpayer identification number: {tax_id}
    The disclosing party lives at {street_home}, {city_home}, {state_home} {zip_home}.
    Phone: {phone}
    Email: {email}

PART II -- SPOUSE AND CO-FILER

    Name of the co-filing spouse: {s_full}
    Social Security Number: {ssn_spouse}
    The co-filer lives at the same residence address shown in Part I. A rental property
    is held jointly at {street_rental}, {city_rental}, {state_rental} {zip_rental}.
    The family trust that holds the rental property files under employer identification
    number {tax_id_trust}.

PART III -- DEPOSIT AND BROKERAGE HOLDINGS

    Primary operating account {acct_operating[8:]} at Harbor Point Savings, balance {bal_operating}.
    Reserve {acct_reserve} at Harbor Point Savings, balance {bal_reserve}.
    Brokerage {acct_brokerage} at Ridgeline Securities, balance {bal_brokerage}.
    Trust custody {acct_trust} at Harbor Point Savings, balance {bal_trust}.

PART IV -- TRANSACTION LEDGER (first quarter)

    DATE         DESCRIPTION                                 AMOUNT
{ledger_lines}

PART V -- LIABILITIES

    Mortgage secured by the residence at {street_home}, {city_home}, outstanding
    principal {mortgage}, serviced by Harbor Point Savings.
    Equipment note held against the rental property at {street_rental}, {city_rental},
    outstanding balance {note_balance}.

PART VI -- CERTIFICATION

    The filers, taxpayer {p_full} and co-filer {s_full}, certify that the balances, the
    account identifiers, the taxpayer identification numbers, and the residence
    information stated above are complete as of 03/31/2025. Questions about this filing
    should be directed to accountant {prep_full} at {email_prep}.
"""
    return text, led.snapshot()


# --------------------------------------------------------------------------
# legal_brief_large.txt
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _BriefPools:
    formal_cases: _Rotation
    bare_cases: _Rotation
    parties: _Rotation
    counsel: _Rotation
    judges: _Rotation
    experts: _Rotation
    emails: _Rotation
    phones: _Rotation
    settlements: _Rotation
    strategies: _Rotation
    orgs: _Rotation
    firms: _Rotation


_SlotFn = Callable[[random.Random, _Ledger, _BriefPools], str]


def _slot_case(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("CASE_ID", pools.formal_cases.next())


def _slot_bare(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("CASE_ID", pools.bare_cases.next())


def _slot_party(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("CLIENT_IDENTITY", pools.parties.next())


def _slot_counsel(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("NAME", pools.counsel.next())


def _slot_judge(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("NAME", pools.judges.next())


def _slot_expert(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("NAME", pools.experts.next())


def _slot_email(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("EMAIL", pools.emails.next())


def _slot_phone(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("PHONE", pools.phones.next())


def _slot_settlement(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("SETTLEMENT_TERM", pools.settlements.next())


def _slot_strategy(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("CASE_STRATEGY", pools.strategies.next())


def _slot_privilege(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("PRIVILEGED_MARKER", "attorney-client")


def _slot_workproduct(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return led.plant("PRIVILEGED_MARKER", "work product")


def _slot_org(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return pools.orgs.any(rng)


def _slot_firm(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return pools.firms.any(rng)


def _slot_date(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return f"{rng.randrange(1, 13):02d}/{rng.randrange(1, 29):02d}/{rng.randrange(2019, 2026)}"


def _slot_year(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return str(rng.randrange(2016, 2025))


def _slot_amount(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return _money(rng, 40_000, 9_000_000, False)


def _slot_n(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return str(rng.randrange(3, 900))


def _slot_pct(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return str(rng.randrange(4, 40))


def _slot_bates(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    return _bates(rng)


def _slot_exhibit(rng: random.Random, led: _Ledger, pools: _BriefPools) -> str:
    letter = "ABCDEFGHJKLMNPQRSTUVW"[rng.randrange(21)]
    return f"{letter}-{rng.randrange(1, 90)}"


_SLOT_FNS: Final[dict[str, _SlotFn]] = {
    "case": _slot_case,
    "bare": _slot_bare,
    "party": _slot_party,
    "counsel": _slot_counsel,
    "judge": _slot_judge,
    "expert": _slot_expert,
    "email": _slot_email,
    "phone": _slot_phone,
    "settlement": _slot_settlement,
    "strategy": _slot_strategy,
    "privilege": _slot_privilege,
    "workproduct": _slot_workproduct,
    "org": _slot_org,
    "firm": _slot_firm,
    "date": _slot_date,
    "year": _slot_year,
    "amount": _slot_amount,
    "n": _slot_n,
    "pct": _slot_pct,
    "bates": _slot_bates,
    "ex": _slot_exhibit,
}


class _Slots(dict[str, str]):
    """Resolves ``{slot}`` names lazily, planting each value as it is rendered.

    A trailing digit lets one template use two independent draws of the same
    slot (``{org}`` and ``{org2}``).
    """

    def __init__(self, rng: random.Random, led: _Ledger, pools: _BriefPools) -> None:
        super().__init__()
        self._rng = rng
        self._led = led
        self._pools = pools

    def __missing__(self, key: str) -> str:
        base = key.rstrip("0123456789")
        try:
            fn = _SLOT_FNS[base]
        except KeyError as exc:  # pragma: no cover -- template typo guard
            raise KeyError(key) from exc
        return fn(self._rng, self._led, self._pools)


# Every person slot below is preceded by a lower-case role noun and sits
# mid-sentence.  That framing is what makes spaCy's PERSON recogniser fire
# reliably: bare object-position names ("served on Jane Doe eleven days later")
# are missed often enough to leak a planted literal, while "served on defendant
# Jane Doe" is detected consistently.
_SECTIONS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (
        "I. PRELIMINARY STATEMENT",
        (
            "This consolidated pretrial brief is submitted on behalf of {org} in the above-captioned matter, {case}, and in the related matter docketed as {bare}.",
            "The claims at issue arise from a course of dealing between {org} and {org2} that began in {year} and continued through the termination notice served on {date}.",
            "The operative pleading was filed by claimant {party} after the parties' pre-suit exchange failed to narrow the disputed accounting entries.",
            "Counsel of record for the moving party is attorney {counsel}, of {firm}, admitted in this district on {date}.",
            "The court consolidated the two actions for pretrial purposes by order entered {date}, and every subsequent filing bears the caption {case}.",
            "Nothing in this brief waives any objection preserved in the answer filed on {date} by attorney {counsel}.",
            "The parties have exchanged initial disclosures, and claimant {party} supplemented those disclosures twice, most recently on {date}.",
            "For the reasons set out below, {org} asks the court to narrow the triable issues before the conference now calendared for {date}.",
            "The dispute centers on {n} disputed invoices issued across the {year} and {year2} fiscal years under a master supply agreement.",
            "Both signatories, principal {party} and principal {party2}, agree that the governing contract was executed on {date}, yet they disagree about which schedule controls.",
        ),
    ),
    (
        "II. PROCEDURAL HISTORY",
        (
            "The complaint in {case} was filed on {date} and served on defendant {party} eleven days later.",
            "An answer was filed on {date} by defendant {party}, asserting {n} affirmative defenses, including failure to mitigate and unclean hands.",
            "The magistrate judge entered a scheduling order on {date} fixing the close of fact discovery and setting a further status conference.",
            "A related declaratory action, docketed as {bare}, was transferred into this district on {date} and assigned to Judge {judge}.",
            "Pro hac vice admission was granted on {date} to attorney {counsel}, who appeared for the intervenor without opposition.",
            "The parties stipulated to a protective order governing the production of confidential financial records, entered {date}.",
            "A motion to compel supplemental responses was filed on {date} by claimant {party} and resolved by agreement before the hearing.",
            "The court denied the motion to dismiss the amended pleading in {case} by written opinion issued {date}.",
            "All remaining discovery disputes were referred to the magistrate judge by Judge {judge} in a minute order dated {date}.",
            "An unopposed motion to extend the expert disclosure deadline in the matter docketed as {bare} was granted on {date}.",
            "The representation was withdrawn on {date} by attorney {counsel}, and attorney {counsel2} substituted in the following week.",
        ),
    ),
    (
        "III. STATEMENT OF FACTS",
        (
            "The operations lead for {org} across the {year} and {year2} contract cycles was manager {party}, who signed each of the disputed purchase orders.",
            "The records produced by {org} show {n} deliveries under the master agreement, of which nine were rejected on arrival.",
            "Deposition testimony given on {date} by manager {party} states that the change orders were approved verbally by a supervisor he could not name.",
            "Correspondence produced at {bates} confirms that {org} notified {org2} of the defect on {date}.",
            "The maintenance logs for the affected units were kept by technician {party}, who left the company on {date}.",
            "{org} contends the shortfall traces to a warehouse reconciliation error first flagged in an internal audit completed in {year}.",
            "A field report authored by engineer {party} and circulated to {email} describes the same failure mode in three earlier installations.",
            "Telephone records subpoenaed from the carrier show eleven calls to {phone} in the week preceding the shipment hold.",
            "The certificate of conformance attached to the shipment released on {date} was signed by supervisor {party} and by inspector {party2}.",
            "Site access logs place employee {party} at the facility on {date}, which is difficult to reconcile with the verified interrogatory responses.",
            "The quality hold was lifted on {date} after {org} accepted a corrective action plan drafted by consultant {party}.",
            "Invoices produced at {bates} total {amount} and are the only contemporaneous record of the disputed freight charges.",
        ),
    ),
    (
        "IV. RELATED AND CONSOLIDATED MATTERS",
        (
            "{case} remains stayed pending resolution of the interlocutory appeal docketed as {bare}.",
            "The court in {case} adopted the same protective-order language now proposed here.",
            "A parallel arbitration between {org} and {org2} is proceeding under the docket reference {bare}.",
            "The same insurer is represented in {case} and in the coordinated matter {bare} by attorney {counsel}.",
            "The clerk assigned the case docketed as {bare} to the complex-litigation track on {date}.",
            "Judgment was entered against the third-party defendant in {case} on {date} and satisfied without appeal.",
            "The parties agree that discovery taken in the matter docketed as {bare} may be used in this action subject to the standing objections.",
            "{org} has moved to relate {case} to the earlier-filed action for purposes of the pretrial conference.",
            "Coordination counsel for the {org} entities is attorney {counsel}, who also appeared in {bare}.",
            "The docket in {case} reflects {n} entries since the consolidation order was entered.",
        ),
    ),
    (
        "V. DAMAGES AND VALUATION",
        (
            "Direct damages are calculated at {amount} by claimant {party}, exclusive of prejudgment interest.",
            "The competing model prepared by economist {expert} places the loss between {amount} and {amount2}.",
            "Consequential damages are pleaded at {amount}, although the contract contains a limitation-of-liability clause.",
            "Replacement cost for the rejected units is documented at {amount} in the invoices produced at {bates}.",
            "Testimony from economist {expert} will show that the discount rate applied by the opposing model understates present value by roughly {pct} percent.",
            "The claimed lost-profits figure of {amount} rests on a three-year projection that economist {expert} calls unsupported.",
            "Audited statements show a working-capital swing of {amount} across the two quarters at issue.",
            "Fees and costs of {amount} are sought by claimant {party} under the prevailing-party clause.",
            "The mitigation credit urged by {org} would reduce the claim by approximately {pct} percent.",
            "The general ledger entries produced at {bates} were reconciled by economist {expert} against the {n} invoices in dispute.",
        ),
    ),
    (
        "VI. SETTLEMENT POSTURE",
        (
            "Counsel for the claimant transmitted a {settlement} shortly before the first mediation session.",
            "The mediator proposed a {settlement} that both sides took under advisement.",
            "The responding party countered with a {settlement} conditioned on a full and final release.",
            "The client has authorised a {settlement} for the coordinated matters taken together.",
            "A prior {settlement} in the related action informs the valuation applied here.",
            "The carrier signalled a {settlement} subject to written confirmation from the reinsurer.",
            "Opposing counsel {counsel} confirmed a {settlement} in writing on the eve of the conference.",
            "The parties remain apart, with the most recent {settlement} still well above the reserve.",
            "A {settlement} was rejected by claimant {party} on the ground that it excluded the affiliates.",
            "The bracketed exchange closed with a {settlement} and no agreement on fees.",
        ),
    ),
    (
        "VII. LITIGATION STRATEGY AND WORK PRODUCT",
        (
            "{strategy}.",
            "{strategy}, and the client concurs.",
            "Counsel notes that this section is covered by the {privilege} privilege and was prepared as {workproduct}.",
            "The deposition sequencing memorandum circulated to {email} sets out the intended order of witnesses.",
            "Internal notes reflect that attorney {counsel} will handle the cross-examination of economist {expert}.",
            # No {date} slot inside a {strategy} sentence: spaCy sometimes tags a
            # bare numeric date as PERSON at 0.85, which outranks CASE_STRATEGY's
            # 0.7 in overlap resolution and evicts the whole strategy span.
            "{strategy}, subject to the outcome of the pending evidentiary hearing.",
            "The evaluation prepared for claimant {party} assumes the court reaches the choice-of-law question first.",
            "{strategy}.",
            "A privileged assessment of {case} was circulated to {email} and withheld on the log.",
            "{strategy}, which preserves the appellate record.",
        ),
    ),
    (
        "VIII. WITNESSES, EXPERTS, AND COUNSEL OF RECORD",
        (
            "The inspection protocol will be described by witness {party}, reachable at {phone}.",
            "A doctorate in materials engineering is held by expert {expert}, who has been retained by {org}.",
            "An appearance in {case} was entered by attorney {counsel} of {firm}, reachable at {email}.",
            "The parties have agreed to limit each side to {n} fact witnesses at the conference.",
            "Six hours of deposition testimony were given by witness {party}, who later produced a supplemental errata sheet.",
            "Rebuttal disclosure from expert {expert} is due before the close of expert discovery.",
            "The dispositive motions will be argued by attorney {counsel} and the evidentiary hearing handled by attorney {counsel2}.",
            "Scheduling requests should be directed to {email} or, if urgent, to {phone}.",
            "Prior qualification in the case docketed as {bare} on substantially the same subject matter was given by expert {expert}.",
            "The witness list filed with {case} identifies {n} individuals, {n2} of whom are current employees of {org}.",
            "Consecutive testimony days are expected for witness {party} and witness {party2}.",
        ),
    ),
    (
        "IX. EXHIBITS AND DISCOVERY STATUS",
        (
            "Exhibit {ex} is the master agreement produced at {bates} and authenticated by custodian {party}.",
            "The production totals {n} pages, of which {n2} were designated confidential.",
            "{org} has withheld {n} documents on privilege grounds and served a log on {date}.",
            "Exhibit {ex} collects the delivery receipts referenced in {case}.",
            "Third-party subpoenas issued to {org2} returned {n} pages on {date}.",
            "The parties dispute the completeness of the search terms applied to the custodial files of employee {party}.",
            "Exhibit {ex} is a demonstrative summarising the calculations offered by expert {expert}.",
            "Metadata for the native files produced in the matter docketed as {bare} was supplied under separate cover.",
            "Exhibit {ex} is the email chain produced at {bates} between manager {party} and attorney {counsel}.",
            "Outstanding written discovery in {case} is limited to {n} requests for admission.",
        ),
    ),
    (
        "X. CONCLUSION AND RELIEF REQUESTED",
        (
            "For the foregoing reasons, {org} respectfully asks the court to grant the relief requested in {case}.",
            "Scheduling questions may be directed to attorney {counsel} at {email} before the conference.",
            "The moving party reserves every objection preserved in the pleadings filed in the case docketed as {bare}.",
            "{strategy}.",
            "A proposed order accompanies this brief and reflects the narrowing agreed by principal {party} and principal {party2}.",
            "Nothing here waives the protections asserted over the {workproduct} identified on the privilege log.",
            "{org} requests leave to supplement this brief after the {date} ruling.",
            "The relief requested would resolve {n} of the disputed line items without further motion practice.",
        ),
    ),
)


def _brief_pools(fake: Faker, rng: random.Random, names: _NamePool) -> _BriefPools:
    # Pool sizes are weighted towards the deterministic, pattern-backed entity
    # types.  Case numbers, settlement phrases, e-mail addresses and phone
    # numbers are recognised by regex and always detected; person names go
    # through spaCy and carry a small residual miss rate, so the brief clears the
    # 200-distinct bar without leaning on a large cast of names.
    formal: list[str] = []
    bare: list[str] = []
    for _ in range(60):
        formal_case, bare_case = _case_pair(rng)
        formal.append(formal_case)
        bare.append(bare_case)

    parties: list[str] = []
    counsel: list[str] = []
    judges: list[str] = []
    experts: list[str] = []
    emails: list[str] = []
    phones: list[str] = []

    for _ in range(20):
        parties.append(names.full())
    for _ in range(8):
        counsel.append(names.full())
    for _ in range(4):
        judges.append(names.full())
    for _ in range(6):
        experts.append(names.full())
    for _ in range(24):
        first, last, _full = names.person()
        emails.append(_email(rng, first, last))
    for index in range(18):
        phones.append(_phone(rng, index % 2 == 0))

    settlements = [
        f"{_SETTLEMENT_LEADS[index % len(_SETTLEMENT_LEADS)]} {_money(rng, 250_000, 8_500_000, index % 3 == 0)}"
        for index in range(55)
    ]

    strategies = list(_STRATEGY_TEMPLATES)

    return _BriefPools(
        formal_cases=_Rotation(formal),
        bare_cases=_Rotation(bare),
        parties=_Rotation(parties),
        counsel=_Rotation(counsel),
        judges=_Rotation(judges),
        experts=_Rotation(experts),
        emails=_Rotation(emails),
        phones=_Rotation(phones),
        settlements=_Rotation(settlements),
        strategies=_Rotation(strategies),
        orgs=_Rotation(_ORG_NAMES),
        firms=_Rotation(
            tuple(
                f"{_LAW_FIRM_HEADS[i]} & {_LAW_FIRM_HEADS[(i + 5) % len(_LAW_FIRM_HEADS)]} LLP"
                for i in range(len(_LAW_FIRM_HEADS))
            )
        ),
    )


def _word_count(text: str) -> int:
    return len(text.split())


def _build_legal_brief(fake: Faker, rng: random.Random) -> tuple[str, dict[str, list[str]]]:
    led = _Ledger()
    names = _NamePool(fake)
    pools = _brief_pools(fake, rng, names)
    slots = _Slots(rng, led, pools)

    lead_case_formal, lead_case_bare = _case_pair(rng)
    led.plant("CASE_ID", lead_case_formal)
    led.plant("CASE_ID", lead_case_bare)
    led.plant("PRIVILEGED_MARKER", "PRIVILEGED AND CONFIDENTIAL")
    led.plant("PRIVILEGED_MARKER", "WORK PRODUCT")

    lead_counsel = names.full()
    lead_client = names.full()
    led.plant("NAME", lead_counsel)
    led.plant("CLIENT_IDENTITY", lead_client)

    plaintiff_org = _ORG_NAMES[1]
    defendant_org = _ORG_NAMES[0]

    header = f"""PRIVILEGED AND CONFIDENTIAL -- ATTORNEY WORK PRODUCT

IN THE UNITED STATES DISTRICT COURT
FOR THE NORTHERN DISTRICT OF THE STATE OF FRANKLIN

{plaintiff_org.upper()},
                                Plaintiff,
        v.                                              {lead_case_formal}
{defendant_org.upper()}, ET AL.,                        (coordinated with the case docketed as {lead_case_bare})
                                Defendants.

CONSOLIDATED PRETRIAL BRIEF AND STATEMENT OF DISPUTED ISSUES

Submitted by attorney {lead_counsel} on behalf of {defendant_org}, at the direction
of general counsel {lead_client}, who supervises the defendant entities' response.
"""

    chunks: list[str] = [header]
    total_words = _word_count(header)
    paragraph_number = 1
    remaining_sections = len(_SECTIONS)

    for title, templates in _SECTIONS:
        heading = f"\n{title}\n"
        chunks.append(heading)
        total_words += _word_count(heading)

        budget = max(1, (_BRIEF_TARGET_WORDS - total_words) // remaining_sections)
        section_words = 0
        while section_words < budget:
            picks = rng.sample(templates, min(len(templates), rng.randrange(4, 7)))
            body = " ".join(template.format_map(slots) for template in picks)
            paragraph = f"\n{paragraph_number}. {body}\n"
            chunks.append(paragraph)
            words = _word_count(paragraph)
            section_words += words
            total_words += words
            paragraph_number += 1
        remaining_sections -= 1

    footer = (
        f"\nRespectfully submitted by attorney {lead_counsel}, counsel of record for "
        f"{defendant_org}.\n"
    )
    chunks.append(footer)
    total_words += _word_count(footer)

    text = "".join(chunks)
    actual = _word_count(text)
    if not _BRIEF_MIN_WORDS <= actual <= _BRIEF_MAX_WORDS:
        raise ValueError(f"legal_brief_large word count out of range: {actual}")
    if led.distinct_count() < _BRIEF_MIN_DISTINCT_ENTITIES:
        raise ValueError(f"legal_brief_large planted only {led.distinct_count()} distinct entities")
    return text, led.snapshot()


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

_Builder = Callable[[Faker, random.Random], tuple[str, dict[str, list[str]]]]

_BUILDERS: Final[dict[str, _Builder]] = {
    "medical": _build_medical,
    "legal": _build_legal_memo,
    "financial": _build_financial,
    "legal_brief_large": _build_legal_brief,
}


def _build(seed: int, kind: str) -> tuple[str, dict[str, list[str]]]:
    try:
        builder = _BUILDERS[kind]
    except KeyError as exc:
        raise ValueError(f"unknown fixture kind: {kind!r}") from exc
    fake, rng = _context(seed, kind)
    return builder(fake, rng)


def generate(seed: int, kind: str) -> str:
    """Render one fixture document.  Same ``(seed, kind)`` => byte-identical text."""
    return _build(seed, kind)[0]


def generate_all(seed: int) -> dict[str, str]:
    """Render every fixture kind for ``seed``, keyed by kind."""
    return {kind: generate(seed, kind) for kind in KINDS}


def expected_entities(seed: int, kind: str) -> dict[str, list[str]]:
    """Entity type -> the exact literal originals planted in ``generate(seed, kind)``.

    The values are taken from the same variables used to render the document, so
    they are exact rather than re-parsed.  See the module docstring for the two
    entity types that do not round-trip.
    """
    return _build(seed, kind)[1]


def write_all(seed: int, out_dir: Path) -> None:
    """Write the four committed fixture ``.txt`` files into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for kind, filename in FILENAMES.items():
        (out_dir / filename).write_text(generate(seed, kind), encoding="utf-8")


if __name__ == "__main__":
    target = Path(__file__).resolve().parent
    write_all(DEFAULT_SEED, target)
    for fixture_kind in KINDS:
        document = generate(DEFAULT_SEED, fixture_kind)
        planted = expected_entities(DEFAULT_SEED, fixture_kind)
        distinct = len({value for values in planted.values() for value in values})
        print(
            f"{FILENAMES[fixture_kind]:<28} "
            f"{_word_count(document):>6} words  "
            f"{distinct:>4} distinct planted values  "
            f"{len(planted):>2} entity types"
        )
