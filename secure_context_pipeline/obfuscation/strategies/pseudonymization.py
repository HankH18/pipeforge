"""Pseudonymization: the three-tier policy (build doc section 9.3).

Every entity is answered with one question -- *does the model need to reason
about this value's content, about its temporal relations, or about neither?* --
and the answer picks the surrogate. The tier lives in ``entities.yaml``
(``tier:``), so the assignment is configuration, not code.

===== ==================================== =================================================
Tier  Entities (shipped registry)           Surrogate
===== ==================================== =================================================
1     NAME, CLIENT_IDENTITY, SSN, MRN,      Realistic, **format-preserving** fake.
      INSURANCE_ID, ACCOUNT_NUMBER,         Reasoning-inert: the model uses these
      TAX_ID, CASE_ID, ADDRESS, EMAIL,      referentially and never reasons about their
      PHONE                                 content, so a plausible fake buys fluency at
                                            zero utility cost.
2     DOB, DATE                             One per-session date shift. Intervals (the
                                            reasoning-relevant part) survive; absolute
                                            dates (the identifying part) do not.
3     DIAGNOSIS, MEDICATION                 Class-annotated token
                                            ``[PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]``.
                                            The class is what the model reasons over; the
                                            exact term is what identifies the patient.
4     LAB_RESULT, SETTLEMENT_TERM, AMOUNT   Plain token. Any fake corrupts reasoning about
                                            magnitude and any magnitude hint leaks the
                                            value, so: referential integrity only.
===== ==================================== =================================================

Entities the registry does not know fall to a plain token -- the conservative
default for a shape we cannot reason about.

Format preservation without an entity lookup table
--------------------------------------------------
Identifiers are faked by a **structural mask** over the source string: digits
become digits, and an alphabetic run becomes random letters of the same case
*only when it is glued to a digit*; separators, punctuation and detached label
words are preserved verbatim. That single rule yields ``NNN-NN-NNNN`` for an
SSN, ``NN-NNNNNNN`` for a TAX_ID, an identical digit count for an MRN, and
``Case No. 4:81-cv-30215`` for a docket number -- with no per-entity format
table, so a Tier-1 entity added to ``entities.yaml`` tomorrow is format-preserved
on day one. Only three shapes get semantic generators instead (persons, email
addresses, places), because those read as gibberish under a structural mask.

Name component linking, statelessly
-----------------------------------
"John Smith" appearing later as "Smith" must map to the *same* fake surname.
The build doc suggests a stateful check -- before generating, test whether the
new span is a token-subset of an already-mapped name in this session. This
module does it differently: each **component** is seeded independently, from
``derive_faker_seed(session_key, "NAME:last:smith")`` (or ``NAME:first:...``), so
"Smith" produces the same fake surname whether it is generated alone or as part
of "John Smith".

That is a deliberate deviation, for three reasons: it needs no cross-call state,
so two coroutines obfuscating concurrently cannot disagree; it survives
out-of-order detection, where the surname-only mention is processed first; and it
cannot drift, because the mapping is a pure function of (session key, role,
component) rather than of history. The seed label omits the entity type on
purpose, so a person detected as ``NAME`` in one document and ``CLIENT_IDENTITY``
in another pseudonymizes identically within the session.

Known limits, stated rather than hidden: a lone component is treated as a
surname (which is the common case in these documents -- "Dr. Patel said..."
after a full-name introduction), so a standalone *first*-name mention does not
link back to its full-name form; and an initial ("J.") does not link to the given
name it abbreviates.

Collision guard
---------------
A fake that happens to equal a real value elsewhere in the session would make the
egress gate fire on a value we invented, and would make restore ambiguous. Every
Tier-1 fake is therefore checked against the session's vault originals, against
the value it is replacing, and against the surrogates already issued this
session; a hit re-seeds with an attempt counter and tries again, bounded by
:data:`MAX_FAKE_ATTEMPTS`, then falls back to a plain token. Never an unbounded
loop -- a fallback token is a fluency loss, a hung request is an outage.

Whole-string equality is not enough, because a fake that merely *contains* a real
value still puts that value verbatim on the wire. The guard therefore works at
word granularity -- and to do that it needs to know which words the generator
actually **invented** as opposed to which it **copied from the source by
construction**. Every generator reports that itself, in :class:`_Candidate`:

* The structural mask copies every character it did not replace, so a word with
  no replaced character is a byte-identical copy of the source's word -- the
  ``"MRN:"`` in ``"MRN: 5551234"`` or the ``"Case No."`` in a docket number. Those
  are labels, not identifiers, and rejecting them would burn the whole retry
  budget on every labelled entity.
* The semantic generators copy only name titles (``"Dr."``) and the punctuation
  between words. **Every name part they emit is invented**, including the
  surname, and Faker draws surnames from the same pool real ones come from. So a
  fake surname that equals the real surname it replaces is rejected -- it is the
  single most identifying word in the span, and excusing it as "inherited from
  the source" would put the real surname on the wire inside our own surrogate.
  Measured at ~1.9% of person spans before the split existed.

Whole-string equality is not enough on the **surrogate** side either, and that
half is about restoration rather than leakage. Two surrogates where one occurs as
a unit inside the other are restored longest-first, so the short one never
matches inside the long one. When the originals nest the same way that is
name-component linking working as designed (``Hammond`` beside ``Chelsea
Hammond``); when two *unrelated* entities happen to draw the same fake surname it
is a value that never reaches the user, with ``restored_count`` up,
``surrogate_misses`` at 0 and nothing anywhere saying so. Faker's surname pool is
about a thousand deep, so a dozen name components in one document makes that a
percent-scale event rather than a curiosity -- measured at 3 failures in 200
pseudonymization runs of the leakage harness. The guard is
:meth:`PseudonymizationStrategy._nests_with_an_issued_surrogate`, and it is the
surrogate/original *pairing* rather than the surrogate set that tells the two
cases apart.

**Tier 2 never regenerates on collision; it degrades.** The date shift is a
bijection, so varying it per date to dodge a collision would break the interval
property that is the entire reason the tier exists. It still has to be guarded,
because a shifted date is a *rendered string* and can carry a real original --
by equalling one, by containing one (``29 April 2024`` contains the separately
vaulted ``April 2024``), or by *being contained in* one, which is the direction
the guard missed: a detector span covering two dates at once vaults
``03/11/2024, 09/17/2024`` as a single original, and a neighbouring date shifted
onto ``03/11/2024`` is then a verbatim slice of it. All three put a real value on
the wire inside a string we invented, and the third is the one nothing else can
catch: the first two leave a *whole* vaulted original in the payload, which the
egress gate blocks, whereas a slice is what both the gate and the leakage harness
document themselves as blind to. It must also not *duplicate* a surrogate the
session already issued: Tier 2 is many-to-one by construction, so ``2024-01-05``
and ``Friday, January 5, 2024`` shift to the same day and render to the same
string, and two originals sharing one surrogate is the one collision restoration
cannot undo. The single colliding date therefore degrades to a plain token and
loses only its own temporal relation; every other date in the document keeps the
shared shift. See :meth:`PseudonymizationStrategy._shift_date`.

Nothing in this module logs, raises, or reprs an original value.
"""

from __future__ import annotations

import logging
import re
import string
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING

from dateutil import parser as dateutil_parser
from faker import Faker

from secure_context_pipeline.crypto.keys import (
    derive_date_shift_days,
    derive_faker_seed,
    normalize,
)
from secure_context_pipeline.errors import VaultMissError
from secure_context_pipeline.models import Detection
from secure_context_pipeline.obfuscation.strategies.base import (
    ObfuscationStrategy,
    StrategyContext,
    register_strategy,
)
from secure_context_pipeline.textrules import occurs_as_a_unit as _occurs_as_a_unit

if TYPE_CHECKING:  # pragma: no cover -- import cycle avoidance / typing only
    from random import Random

    from secure_context_pipeline.vault.session_vault import SessionVault

logger = logging.getLogger(__name__)

__all__ = [
    "FAKER_LOCALE",
    "MAX_FAKE_ATTEMPTS",
    "TIER_CONTENT",
    "TIER_IDENTIFIER",
    "TIER_NUMERIC",
    "TIER_TEMPORAL",
    "PseudonymizationStrategy",
]

#: Tier numbers, matching ``tier:`` in ``entities.yaml`` (build doc section 9.3).
TIER_IDENTIFIER = 1
TIER_TEMPORAL = 2
TIER_CONTENT = 3
TIER_NUMERIC = 4

#: Tier used for an entity the registry does not define: plain token, no fake.
TIER_UNKNOWN = TIER_NUMERIC

#: Bounded because an unbounded regeneration loop is an outage. Ten attempts
#: against a session holding a few thousand values is already absurd headroom.
MAX_FAKE_ATTEMPTS = 10

#: Shortest word the collision guard will reject a fake for sharing with a real
#: original. Mirrors the egress gate's ``MIN_ORIGINAL_LEN``: below this a word
#: carries no re-identification signal and the gate does not scan for it either,
#: so rejecting on it would burn the retry budget on particles like "de" or "van".
_MIN_COLLIDING_WORD = 3

#: Fixtures and documents are US-shaped; the locale only affects fake *style*.
FAKER_LOCALE = "en_US"

#: The only entity names this module knows. Everything else -- including a
#: Tier-1 entity added by config tomorrow -- goes through the structural mask,
#: which preserves the shape of whatever it is handed.
_PERSON_ENTITIES = frozenset({"NAME", "CLIENT_IDENTITY"})
_EMAIL_ENTITIES = frozenset({"EMAIL"})
_PLACE_ENTITIES = frozenset({"ADDRESS"})

_DIGITS = string.digits
_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase

#: A name word: letters, optionally hyphenated/apostrophised, optional trailing
#: dot so initials ("J.") round-trip.
_NAME_WORD_RE = re.compile(r"[^\W\d_]+(?:['\u2019\-][^\W\d_]+)*\.?")

#: One whitespace-delimited run. Used to map the structural mask's replaced-character
#: bitmap onto whole words.
_RUN_RE = re.compile(r"\S+")

#: Titles and suffixes are boilerplate, not identity: preserved verbatim so
#: "Dr. Smith" stays "Dr. <fake>" rather than becoming a two-part fake name.
_NAME_PASSTHROUGH = frozenset(
    {"dr", "mr", "mrs", "ms", "miss", "prof", "rev", "hon", "jr", "sr", "ii", "iii", "md", "phd",
     "esq"}
)


# ---------------------------------------------------------------------------
# A generated candidate + the words its generator invented
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Candidate:
    """A generated surrogate plus the normalised words the generator invented.

    ``invented`` is exactly the set the collision guard must check. Everything
    else in ``text`` was copied from the source by construction -- a
    format-preserving label, a name title, the punctuation between words -- and
    could not have been coincidentally drawn from the pool real values come from.

    Splitting the two is what lets the guard stay maximally strict about the
    words that *are* generated (a fake surname must never equal the real one)
    without rejecting the scaffolding that format preservation exists to keep.
    """

    text: str
    invented: frozenset[str]


def _words_of(value: str) -> frozenset[str]:
    """Normalised whitespace-delimited words of ``value``.

    Normalising *before* splitting matters: NFKC turns a no-break space into an
    ordinary one, so a run that looked like one word can normalise into two.
    """
    return frozenset(normalize(value).split())


# ---------------------------------------------------------------------------
# Structural (format-preserving) mask
# ---------------------------------------------------------------------------


def _structural_fake(text: str, rng: Random) -> _Candidate:
    """Replace the identifying characters of ``text``, preserving its shape.

    Digits are always replaced. An alphabetic run is replaced only when it
    touches a digit -- letters glued to digits are part of the identifier
    (``BCBS123456789``), letters separated from them are a label
    (``MRN: 1234567``, ``Case No. 1:23-cv-45678``). Everything else -- spaces,
    hyphens, slashes, colons -- is preserved, which is what makes the output
    match the source's format regex.

    Substitution is strictly in place, so the output has the source's length and
    the source's whitespace. That is what makes the ``replaced`` bitmap usable to
    name the invented words: a word holding no replaced character is a verbatim
    copy of the source's word at the same offsets.
    """
    chars = list(text)
    out = list(text)
    replaced = [False] * len(chars)
    length = len(chars)
    index = 0
    while index < length:
        char = chars[index]
        if char.isdigit():
            out[index] = rng.choice(_DIGITS)
            replaced[index] = True
            index += 1
            continue
        if char.isalpha():
            end = index
            while end < length and chars[end].isalpha():
                end += 1
            glued = (index > 0 and chars[index - 1].isdigit()) or (
                end < length and chars[end].isdigit()
            )
            if glued:
                for position in range(index, end):
                    out[position] = (
                        rng.choice(_UPPER) if chars[position].isupper() else rng.choice(_LOWER)
                    )
                    replaced[position] = True
            index = end
            continue
        index += 1
    generated = "".join(out)
    invented: set[str] = set()
    for run in _RUN_RE.finditer(generated):
        if any(replaced[run.start() : run.end()]):
            invented |= _words_of(run.group())
    return _Candidate(generated, frozenset(invented))


def _match_case(source: str, generated: str) -> str:
    """Carry the source's ALL-CAPS / all-lower styling onto a generated word."""
    if source.isupper():
        return generated.upper()
    if source.islower():
        return generated.lower()
    return generated


# ---------------------------------------------------------------------------
# Tier 2 -- date parsing that remembers the source format
# ---------------------------------------------------------------------------

_MONTHS_FULL = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)

_MONTH_INDEX: dict[str, int] = {}
for _position, _month in enumerate(_MONTHS_FULL, start=1):
    _MONTH_INDEX[_month.lower()] = _position
    _MONTH_INDEX[_month[:3].lower()] = _position
_MONTH_INDEX["sept"] = 9

_ISO_RE = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})$")
_NUMERIC_RE = re.compile(r"^(\d{1,2})([/.\-])(\d{1,2})\2(\d{2}|\d{4})$")
_MDY_RE = re.compile(
    r"^([A-Za-z]{3,9})(\.?)\s+(\d{1,2})(?:st|nd|rd|th)?\s*(,?)\s+(\d{4})$", re.IGNORECASE
)
_DMY_RE = re.compile(
    r"^(\d{1,2})(?:st|nd|rd|th)?\s+([A-Za-z]{3,9})(\.?),?\s+(\d{4})$", re.IGNORECASE
)
_MY_RE = re.compile(r"^([A-Za-z]{3,9})(\.?)\s+(\d{4})$", re.IGNORECASE)
_ORDINAL_RE = re.compile(r"\d{1,2}(st|nd|rd|th)\b", re.IGNORECASE)
_DIGIT_RUN_RE = re.compile(r"\d+")

#: Anchors the dateutil fallback so a missing component is never filled from
#: "today" -- a shifted today is a wrong date that looks right.
_FALLBACK_ANCHOR = datetime(2000, 1, 1)


@dataclass(frozen=True, slots=True)
class _SourceDate:
    """A parsed date plus a renderer that reproduces the source's formatting."""

    value: date
    render: Callable[[date], str]


def _ordinal_suffix(day: int) -> str:
    if 11 <= day % 100 <= 13:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")


def _month_word(target_month: int, source_word: str, dotted: str) -> str:
    """Render ``target_month`` in the source's style (full/abbreviated, case, dot)."""
    source_index = _MONTH_INDEX[source_word.lower()]
    abbreviated = len(source_word.rstrip(".")) < len(_MONTHS_FULL[source_index - 1])
    rendered = _MONTHS_FULL[target_month - 1]
    if abbreviated:
        rendered = rendered[:3]
    return _match_case(source_word, rendered) + dotted


def _safe_date(year: int, month: int, day: int) -> date | None:
    try:
        return date(year, month, day)
    except ValueError:
        return None


def _expand_year(raw: str) -> int:
    """Two-digit years use the POSIX pivot: 00-68 -> 2000s, 69-99 -> 1900s."""
    if len(raw) == 4:
        return int(raw)
    value = int(raw)
    return 2000 + value if value < 69 else 1900 + value


def _parse_iso(text: str) -> _SourceDate | None:
    match = _ISO_RE.match(text)
    if match is None:
        return None
    year, month, day = match.group(1), match.group(2), match.group(3)
    value = _safe_date(int(year), int(month), int(day))
    if value is None:
        return None
    month_width, day_width = len(month), len(day)

    def render(shifted: date) -> str:
        return (
            f"{shifted.year:04d}-{shifted.month:0{month_width}d}-{shifted.day:0{day_width}d}"
        )

    return _SourceDate(value, render)


def _parse_numeric(text: str) -> _SourceDate | None:
    match = _NUMERIC_RE.match(text)
    if match is None:
        return None
    first, separator, second, year_raw = match.groups()
    # US convention (M/D/Y) unless the leading field cannot be a month.
    month_first = not (int(first) > 12 and int(second) <= 12)
    month, day = (int(first), int(second)) if month_first else (int(second), int(first))
    value = _safe_date(_expand_year(year_raw), month, day)
    if value is None:
        return None
    first_width, second_width, year_width = len(first), len(second), len(year_raw)

    def render(shifted: date) -> str:
        lead = shifted.month if month_first else shifted.day
        follow = shifted.day if month_first else shifted.month
        year = f"{shifted.year % 100:02d}" if year_width == 2 else f"{shifted.year:04d}"
        return f"{lead:0{first_width}d}{separator}{follow:0{second_width}d}{separator}{year}"

    return _SourceDate(value, render)


def _parse_month_day_year(text: str) -> _SourceDate | None:
    match = _MDY_RE.match(text)
    if match is None:
        return None
    word, dotted, day_raw, comma, year_raw = match.groups()
    month = _MONTH_INDEX.get(word.lower())
    if month is None:
        return None
    value = _safe_date(int(year_raw), month, int(day_raw))
    if value is None:
        return None
    ordinal = bool(_ORDINAL_RE.search(text))

    def render(shifted: date) -> str:
        day = f"{shifted.day}{_ordinal_suffix(shifted.day) if ordinal else ''}"
        return f"{_month_word(shifted.month, word, dotted)} {day}{comma} {shifted.year:04d}"

    return _SourceDate(value, render)


def _parse_day_month_year(text: str) -> _SourceDate | None:
    match = _DMY_RE.match(text)
    if match is None:
        return None
    day_raw, word, dotted, year_raw = match.groups()
    month = _MONTH_INDEX.get(word.lower())
    if month is None:
        return None
    value = _safe_date(int(year_raw), month, int(day_raw))
    if value is None:
        return None
    ordinal = bool(_ORDINAL_RE.search(text))

    def render(shifted: date) -> str:
        day = f"{shifted.day}{_ordinal_suffix(shifted.day) if ordinal else ''}"
        return f"{day} {_month_word(shifted.month, word, dotted)} {shifted.year:04d}"

    return _SourceDate(value, render)


def _parse_month_year(text: str) -> _SourceDate | None:
    match = _MY_RE.match(text)
    if match is None:
        return None
    word, dotted, year_raw = match.groups()
    month = _MONTH_INDEX.get(word.lower())
    if month is None:
        return None
    value = _safe_date(int(year_raw), month, 1)
    if value is None:
        return None

    def render(shifted: date) -> str:
        return f"{_month_word(shifted.month, word, dotted)} {shifted.year:04d}"

    return _SourceDate(value, render)


def _parse_fallback(text: str) -> _SourceDate | None:
    """``dateutil`` for anything the format table missed; renders ISO.

    Guarded by "at least two digit runs" so a bare year ("2024") is *not*
    silently promoted to 1 January and shifted into a plausible-looking lie.
    """
    if len(_DIGIT_RUN_RE.findall(text)) < 2:
        return None
    try:
        parsed = dateutil_parser.parse(text, default=_FALLBACK_ANCHOR, fuzzy=False)
    except (ValueError, OverflowError, TypeError):
        return None
    return _SourceDate(parsed.date(), lambda shifted: shifted.isoformat())


_DATE_PARSERS: tuple[Callable[[str], _SourceDate | None], ...] = (
    _parse_iso,
    _parse_numeric,
    _parse_month_day_year,
    _parse_day_month_year,
    _parse_month_year,
    _parse_fallback,
)


def parse_source_date(text: str) -> _SourceDate | None:
    """First parser that recognises ``text``, or ``None`` if none does."""
    for parser in _DATE_PARSERS:
        parsed = parser(text)
        if parsed is not None:
            return parsed
    return None


# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------


@register_strategy
class PseudonymizationStrategy(ObfuscationStrategy):
    """Tier-dispatching pseudonymizer. See the module docstring for the policy."""

    name = "pseudonymization"

    def __init__(self, ctx: StrategyContext) -> None:
        super().__init__(ctx)
        # One Faker instance, re-seeded before every single generation. That is
        # what makes output a pure function of (session key, entity type, value)
        # instead of a function of how many values came before it.
        self._faker = Faker(FAKER_LOCALE)
        self._shift_days = derive_date_shift_days(self.session_key)
        self._originals_source: frozenset[str] | None = None
        self._originals_normalized: frozenset[str] = frozenset()
        self._union_cache: frozenset[str] = frozenset()
        self._union_key: tuple[int, int] | None = None
        self._words_source: frozenset[str] | None = None
        self._words_cache: frozenset[str] = frozenset()

    @property
    def shift_days(self) -> int:
        """The session's date shift, in days. Identical for every Tier-2 entity."""
        return self._shift_days

    def tier_of(self, entity_type: str) -> int:
        """Registry tier, or the conservative default for an unknown entity type."""
        spec = self.registry.get(entity_type)
        return spec.tier if spec is not None else TIER_UNKNOWN

    async def make_surrogate(
        self,
        detection: Detection,
        token_id: str,
        vault: SessionVault,
        *,
        session_id: str,
    ) -> str:
        tier = self.tier_of(detection.entity_type)
        if tier == TIER_IDENTIFIER:
            return await self._fake_identifier(detection, token_id, vault, session_id)
        if tier == TIER_TEMPORAL:
            return await self._shift_date(detection, token_id, vault, session_id)
        if tier == TIER_CONTENT:
            return self.plain_token(detection, token_id, self.hint_for(detection))
        return self.plain_token(detection, token_id)

    # -- Tier 1 ------------------------------------------------------------

    async def _fake_identifier(
        self,
        detection: Detection,
        token_id: str,
        vault: SessionVault,
        session_id: str,
    ) -> str:
        """A realistic fake, guarded against colliding with anything real."""
        original = normalize(detection.text)
        # The value being replaced right now is the one original the vault cannot
        # know about yet: it is written only once its surrogate exists, i.e. after
        # this method returns. ``reserved_originals`` normally covers it, but that
        # is seeded by the caller -- so a guard that relied on it would be correct
        # only while the engine happens to wire it, and silently blind anywhere
        # else. Forbid its own words directly instead: without this, "John Smith"
        # can be faked as "John Martin", shipping a real given name inside our own
        # surrogate, and the egress gate cannot object because the *whole* original
        # never appears.
        own_words = frozenset(
            word for word in _words_of(detection.text) if len(word) >= _MIN_COLLIDING_WORD
        )
        forbidden = self._original_words(vault, session_id) | own_words
        for attempt in range(MAX_FAKE_ATTEMPTS):
            candidate = self._generate(
                detection.entity_type, detection.text, attempt, forbidden
            )
            if not candidate.text.strip():
                break
            if normalize(candidate.text) == original:
                continue
            if normalize(candidate.text) in self._normalized_originals(vault, session_id):
                continue
            # Whole-string equality is not enough. Faker draws surnames from the same
            # space real ones come from, so it can hand back "Rachel Medina" while
            # "Medina" is genuinely another entity's original -- putting a real
            # surname verbatim on the wire inside our own surrogate. Reject on any
            # INVENTED word that is a real word, in either direction.
            if self._invents_a_real_word(candidate, vault, session_id, own_words):
                continue
            if await self._surrogate_taken(vault, session_id, candidate.text):
                continue
            if self._nests_with_an_issued_surrogate(
                candidate.text, detection.text, vault, session_id
            ):
                continue
            if attempt:
                logger.info(
                    "pseudonym regenerated after collision",
                    extra={"entity_type": detection.entity_type, "attempts": attempt + 1},
                )
            return candidate.text
        # Counts and IDs only -- never the value we failed to fake.
        logger.warning(
            "pseudonym collision guard exhausted; emitting a plain token",
            extra={
                "entity_type": detection.entity_type,
                "token_id": token_id,
                "attempts": MAX_FAKE_ATTEMPTS,
            },
        )
        return self.plain_token(detection, token_id)

    def _generate(
        self,
        entity_type: str,
        text: str,
        attempt: int,
        forbidden: frozenset[str] = frozenset(),
    ) -> _Candidate:
        """Dispatch to a semantic generator, or fall back to the structural mask.

        Every branch reports which words it invented, because that -- not the
        entity type and not the source string -- is what the collision guard has
        to police. See :class:`_Candidate`.

        ``forbidden`` is the session's original-word set, handed to the person
        generator so it can resolve a colliding component *in place* rather than
        forcing a whole-candidate retry. See :meth:`_fake_name_word`.
        """
        if entity_type in _PERSON_ENTITIES:
            return self._fake_person(text, forbidden)
        if entity_type in _EMAIL_ENTITIES:
            return self._fake_email(text, attempt)
        if entity_type in _PLACE_ENTITIES:
            return self._fake_place(text, attempt)
        return self._fake_structural(entity_type, text, attempt)

    def _seed(self, label: str, attempt: int) -> int:
        """Deterministic Faker seed. ``attempt`` only participates on a retry."""
        return derive_faker_seed(self.session_key, label if not attempt else f"{label}:{attempt}")

    def _fake_structural(self, entity_type: str, text: str, attempt: int) -> _Candidate:
        self._faker.seed_instance(self._seed(f"{entity_type}:{normalize(text)}", attempt))
        # The mask names its own invented words -- only the runs it actually
        # rewrote. A detached label is copied through and stays excused.
        return _structural_fake(text, self._faker.random)

    def _fake_email(self, text: str, attempt: int) -> _Candidate:
        self._faker.seed_instance(self._seed(f"EMAIL:{normalize(text)}", attempt))
        # ``ascii_safe_email`` only ever emits RFC 2606 reserved domains, so a
        # fake address can never be a real deliverable mailbox. Nothing of the
        # source survives, so every word of the result is invented.
        generated = str(self._faker.ascii_safe_email())
        return _Candidate(generated, _words_of(generated))

    def _fake_place(self, text: str, attempt: int) -> _Candidate:
        self._faker.seed_instance(self._seed(f"ADDRESS:{normalize(text)}", attempt))
        # ADDRESS rides Presidio's LOCATION recognizer, so the span is as often a
        # city as a street line; a digit is the reliable tell. Faker builds the
        # whole string, so -- as for email -- every word of it is invented.
        if any(char.isdigit() for char in text):
            generated = str(self._faker.street_address())
        else:
            generated = str(self._faker.city())
        return _Candidate(generated, _words_of(generated))

    def _fake_person(self, text: str, forbidden: frozenset[str]) -> _Candidate:
        """Component-wise fake name -- the linking rule (see module docstring).

        Titles and the punctuation between words are copied from the source;
        every *name* word is drawn from Faker and is therefore invented, surname
        included. Reporting the surname as invented is what stops a fake from
        keeping the real surname it was supposed to replace.

        Note what this does **not** take: the whole-candidate ``attempt``. A retry
        that re-seeded every component would break the linking rule, because
        "Smith" alone and the "Smith" inside "John Smith" are separate vault
        entries generated at separate times and would land on different retry
        counts. Collisions are resolved per component instead
        (:meth:`_fake_name_word`), which is a pure function of the component, so
        every mention of it converges on the same fake.
        """
        words = list(_NAME_WORD_RE.finditer(text))
        core = [word for word in words if not _is_passthrough(word.group())]
        if not core:
            return _Candidate("", frozenset())
        last = core[-1]
        pieces: list[str] = []
        invented: set[str] = set()
        cursor = 0
        for word in words:
            pieces.append(text[cursor : word.start()])
            token = word.group()
            if _is_passthrough(token):
                pieces.append(token)
            else:
                role = "last" if word is last else "first"
                generated = self._fake_name_word(token, role, forbidden)
                pieces.append(generated)
                invented |= _words_of(generated)
            cursor = word.end()
        pieces.append(text[cursor:])
        return _Candidate("".join(pieces), frozenset(invented))

    def _fake_name_word(self, word: str, role: str, forbidden: frozenset[str]) -> str:
        """One fake name component, advanced past any real word it lands on.

        The search index belongs to the **component**, not to the candidate. That
        is what keeps the linking rule true under a collision: "Smith" standing
        alone and "Smith" inside "John Smith" are distinct vault entries generated
        at different moments, so if a rejection bumped a shared counter they would
        settle on different surnames and the same person would read as two people.
        Here both run the identical pure search over
        ``(session_key, role, component, forbidden)`` and land on the same word.

        ``forbidden`` is stable for the whole ``obfuscate`` call: the engine seeds
        ``reserved_originals`` with every original in the document up front, and
        the vault only ever gains originals that were already in that set -- so
        the search cannot give two answers within one document.
        """
        trailing_dot = word.endswith(".")
        core = word.rstrip(".")
        # The seed label omits the entity type on purpose: NAME and
        # CLIENT_IDENTITY are the same person and must pseudonymize identically.
        label = f"NAME:{role}:{normalize(core)}"
        generated = ""
        for step in range(MAX_FAKE_ATTEMPTS):
            self._faker.seed_instance(self._seed(label, step))
            generated = str(
                self._faker.last_name() if role == "last" else self._faker.first_name()
            )
            folded = normalize(generated)
            if len(folded) < _MIN_COLLIDING_WORD or folded not in forbidden:
                break
        if len(core) == 1:
            return generated[:1].upper() + ("." if trailing_dot else "")
        return _match_case(core, generated) + ("." if trailing_dot else "")

    # -- collision guard ---------------------------------------------------

    def _normalized_originals(self, vault: SessionVault, session_id: str) -> frozenset[str]:
        """Normalised view of the session's vault originals, memoised per snapshot.

        ``originals_for_session`` returns a memoised frozenset that the vault
        replaces on every write, so identity comparison is a correct and O(1)
        cache key.
        """
        current = vault.originals_for_session(session_id)
        if current is not self._originals_source:
            self._originals_source = current
            self._originals_normalized = frozenset(normalize(value) for value in current)
        # Union with the whole document's originals, not just those already vaulted --
        # otherwise the guard is order-dependent and a fake can collide with a value
        # vaulted later in the same run. See ObfuscationStrategy.reserved_originals.
        # Cached on the identity of both inputs so the union (and the word index
        # derived from it) is rebuilt only when one of them actually changes.
        key = (id(self._originals_normalized), id(self.reserved_originals))
        if key != self._union_key:
            self._union_key = key
            self._union_cache = self._originals_normalized | self.reserved_originals
        return self._union_cache

    def _invents_a_real_word(
        self,
        candidate: _Candidate,
        vault: SessionVault,
        session_id: str,
        also: frozenset[str] = frozenset(),
    ) -> bool:
        """Whether the generator invented a word that is also a real original's word.

        A fake that merely *contains* a real value still puts that value verbatim in
        the outbound payload, so the egress gate is right to treat it as a leak --
        hence word granularity rather than whole-string equality.

        Only :attr:`_Candidate.invented` is checked, and that distinction is the
        whole point. The words a generator *copied* from the source are structural
        scaffolding -- the ``"MRN:"`` in ``"MRN: 5551234"``, the ``"Dr."`` in
        ``"Dr. Alvarez"`` -- and rejecting them would exhaust the retry budget on
        every labelled entity for no security gain. The words a generator *drew*
        are a different thing entirely: Faker draws surnames from the same pool
        real surnames come from, so ``"anna williams"`` can generate
        ``"madison williams"``, and treating that surname as "inherited from the
        source" would ship the real one. It is invented, so it is checked, so it
        is rejected and regenerated.

        Words below ``_MIN_COLLIDING_WORD`` are ignored: they carry no
        re-identification signal and sit under the egress gate's own scan floor,
        so rejecting on them would only burn retries on particles like "de" or
        "van".

        ``also`` carries words the vault cannot supply -- in practice the words of
        the very value being replaced, which is not written until its surrogate
        exists. See :meth:`_fake_identifier`.
        """
        original_words = self._original_words(vault, session_id) | also
        if not original_words:
            return False
        return any(
            word in original_words
            for word in candidate.invented
            if len(word) >= _MIN_COLLIDING_WORD
        )

    def _original_words(self, vault: SessionVault, session_id: str) -> frozenset[str]:
        """Every word appearing in any original for this session, normalised."""
        source = self._normalized_originals(vault, session_id)
        if source is not self._words_source:
            self._words_source = source
            self._words_cache = frozenset(
                word
                for value in source
                for word in value.split()
                if len(word) >= _MIN_COLLIDING_WORD
            )
        return self._words_cache

    @staticmethod
    async def _surrogate_taken(vault: SessionVault, session_id: str, candidate: str) -> bool:
        """Whether this exact surrogate has already been issued in the session."""
        try:
            await vault.get_by_surrogate(session_id, candidate)
        except VaultMissError:
            return False
        return True

    def _nests_with_an_issued_surrogate(
        self, candidate: str, original: str, vault: SessionVault, session_id: str
    ) -> bool:
        """Whether ``candidate`` would make an issued surrogate un-restorable, or vice versa.

        **Whole-string equality is not enough here either, and for a second reason.**
        :meth:`_surrogate_taken` asks whether this exact string is already spoken
        for; that catches two originals sharing one surrogate. It cannot see the
        case where one surrogate merely *contains* another as a unit, and that case
        is equally unrestorable: the restorer compiles one longest-first alternation
        (``deobfuscation.restorer._compile_surrogate_pattern``), so the long fake
        always wins at a shared offset and the short one never matches inside it.

        Whether that is a bug or the design depends entirely on the **originals**,
        which is why this needs the pairing rather than the surrogate set:

        * ``Hammond -> Brightwater`` beside ``Chelsea Hammond -> Nathaniel
          Brightwater`` is name-component linking doing its job. The fakes nest and
          so do the values: restoring the long fake yields ``Chelsea Hammond``,
          which still carries ``Hammond`` as a unit, so the short surrogate's
          original is in the answer even though its surrogate never matched. This
          must be allowed -- rejecting it degrades every linked surname to a plain
          token and deletes the feature.
        * ``Sherryside -> White`` beside ``Thomas Duncan -> Daniel White`` is two
          **unrelated** entities whose fakes collided: Faker draws surnames from a
          pool of roughly a thousand, and ``NAME:last:duncan`` and
          ``NAME:last:sherryside`` are independent draws from it, so a birthday
          collision at a dozen name components per document is a percent-scale
          event rather than a curiosity. Here the model writes ``Daniel White``,
          the restorer correctly yields ``Thomas Duncan``, and ``Sherryside`` is
          **silently absent from the user's answer** -- ``restored_count`` up,
          ``surrogate_misses`` 0, ``_assert_no_surrogates`` unable to fire because
          no fake survived. Measured at 3 failures in 200 pseudonymization runs of
          the leakage harness before this guard existed.

        So the test is *nesting on the surrogate side without the matching nesting
        on the original side*, in either direction. The exact-equality case is left
        to :meth:`_surrogate_taken`: two originals sharing one surrogate is a
        different defect with a different remedy, and the orchestrator's step 4b
        refuses the run over it.

        Surrogates are compared **raw** because that is what the restorer matches
        (its alternation is case-sensitive by design); originals are compared
        **normalised**, so a value that differs only in case or spacing from the one
        it nests in still counts as mirrored and is not degraded for nothing.

        A rejected candidate takes the ordinary path: regenerate for the shapes that
        vary with ``attempt``, and a plain token for persons, which deliberately do
        not (see :meth:`_fake_person`). That is the right trade -- a token is a
        fluency loss and fully restorable, whereas the fake it replaces is a value
        the user would never have seen.

        Cost: one pass over the session's issued surrogates per Tier-1 candidate,
        rejected by the C-level substring pre-filter inside ``_occurs_as_a_unit`` on
        all but a handful. Same shape, and the same answer at scale, as the pass
        :meth:`_shift_date` makes over the originals.

        **Called from Tier 1 only, and that scope is argued rather than assumed.**
        A Tier-1 candidate is checked against *every* issued surrogate, dates
        included, so the only pair this cannot see is a Tier-2 candidate nesting
        with something already issued. A shifted date can only nest as a unit inside
        another shifted date rendered in the same format, and the shift is one
        constant per session -- so the two originals differ by exactly the same
        offset and nest on the original side too, which is the mirrored case this
        guard permits. Tier 2 therefore has nothing to reject; it keeps the
        equality check (:meth:`_surrogate_taken`) that it does need.
        """
        issued = vault.surrogates_for_session(session_id)
        if not issued:
            return False
        folded = normalize(original)
        for surrogate, other in issued.items():
            if surrogate == candidate:
                continue  # _surrogate_taken's question, not this one
            if _occurs_as_a_unit(candidate, surrogate):
                if not _occurs_as_a_unit(folded, normalize(other)):
                    return True
            elif _occurs_as_a_unit(surrogate, candidate) and not _occurs_as_a_unit(
                normalize(other), folded
            ):
                return True
        return False

    # -- Tier 2 ------------------------------------------------------------

    async def _shift_date(
        self, detection: Detection, token_id: str, vault: SessionVault, session_id: str
    ) -> str:
        """Shift by the session delta and re-render in the source's format.

        The shift is **not** regenerated on collision: it is one constant per
        session, and varying it per date would destroy the interval preservation
        this tier exists for. Anything unparseable degrades to a plain token rather
        than to a guessed date.

        There is, however, one case the constant shift cannot resolve. Because the
        delta is constant, a date shifted forward can land exactly on a *different*
        real date in the same document -- ``12/08/2024 + 283d == 09/17/2025``, where
        ``09/17/2025`` is itself a visit date. The rendered surrogate is then a
        verbatim original, which the egress gate correctly blocks on and the
        restorer cannot disambiguate. Observed on ~1 in 100 harness runs.

        That single date degrades to a plain token. Every other date in the document
        keeps the shared shift, so all intervals among them survive; only the
        colliding date loses its temporal relation, and it stays fully restorable.
        Blocking the whole request instead would be a strictly worse trade.

        The date can also collide with **itself**, and that case needs its own test
        rather than the originals-set one. A ``Month YYYY`` span parses to the first
        of the month, so a ``+30`` shift out of a 31-day month re-renders the *same*
        month and year: ``January 2024`` shifts to ``January 2024``, byte for byte.
        The originals set cannot be relied on to notice, because the value being
        replaced is written to the vault only once its surrogate exists -- it is in
        ``reserved_originals`` only while the engine happens to seed it, which is a
        caller's habit rather than this method's guarantee. So the source string is
        compared directly, exactly as :meth:`_fake_identifier` forbids its own
        words directly.

        The collision that matters is **containment, not equality**, and a
        whole-string test cannot see it. A shifted date does not have to *equal*
        another original to carry it: it can *render* one. ``April 2024`` is vaulted
        from one document; a later document's ``17 March 2024`` shifts to
        ``29 April 2024``, and the payload now holds ``April 2024`` verbatim, as a
        word-bounded unit. ``'29 april 2024' != 'april 2024'``, so equality passes it,
        and the engine's residual sweep cannot catch it either -- the sweep runs on
        the ORIGINAL text before splicing, so it never inspects a surrogate it
        spliced in. The egress gate then blocks our own output with
        ``reason='vault_original'`` and the document becomes unprocessable, which is
        exactly the failure the sweep exists to prevent. This is the same
        word-versus-whole-string reasoning :meth:`_fake_identifier` applies through
        :meth:`_invents_a_real_word`; Tier 2 needs it too.

        **Containment is tested in BOTH directions, and for a while it was not.**
        The paragraph above is about a rendered date that *swallows* an original.
        The mirror case -- a rendered date that is itself *swallowed by* a longer
        original -- is just as real and was measured at roughly one full leakage-harness
        run in a hundred. It needs no exotic input, only a detector span that covers
        more than one date: the fixture line ``Prior ambulatory visits: 03/11/2024,
        09/17/2024, and 10/01/2024.`` comes back as the single ``DATE`` span
        ``03/11/2024, 09/17/2024`` beside a separate ``10/01/2024``, so
        ``03/11/2024, 09/17/2024`` is one vault original in its own right. A session
        shift of ``-204`` days then takes ``10/01/2024`` to ``03/11/2024`` -- a
        verbatim, word-bounded slice of that original -- and the one-directional test
        waved it through, because ``'03/11/2024, 09/17/2024'`` does not occur inside
        ``'03/11/2024'``.

        Both halves of the damage are silent, which is what makes this worth a guard
        rather than a note:

        * the outbound payload carries ``03/11/2024``, a real appointment date of the
          real patient, inside a string *we invented*. Neither the egress gate nor the
          leakage harness reports it, because both ask whether a **whole** vaulted
          value occurs and this is a slice of one -- so the pipeline manufactures
          exactly the partial disclosure both scanners document themselves as blind
          to;
        * at restore, the token pass puts ``03/11/2024, 09/17/2024`` back into the
          answer, and that value carries a **live surrogate** as a unit.
          :meth:`~secure_context_pipeline.deobfuscation.restorer.Restorer._assert_no_surrogates`
          is structurally unable to object -- it excuses residue lying inside a value
          the restorer itself spliced, correctly, since a restored original may
          legitimately contain another entity's fake, and in this case the splice is
          made by the *token* pass, which runs after that assertion entirely. The
          answer then holds one date string standing for two different days with
          ``restored_count`` up, ``surrogate_misses`` 0 and outcome ``ok``.

        So the test is symmetric: reject if the rendered date occurs as a unit in any
        original, or any original occurs as a unit in it.

        What this cannot close, stated rather than implied: the guard is evaluated
        when the surrogate is minted, against the originals known then. A *later*
        call in the same session that vaults a new original containing an
        already-issued date surrogate reaches the same state, and no per-candidate
        test can see a value that does not exist yet. Within one ``obfuscate`` call
        there is no such window -- ``reserved_originals`` carries the whole
        document's originals before the first surrogate is rendered.

        The containment test calls the one shared rule,
        :func:`~secure_context_pipeline.textrules.occurs_as_a_unit`,
        rather than re-deriving a boundary rule here. Re-deriving it is how five
        separate copies of ``(?<!\\w)...(?!\\w)`` came to share one blind spot; a
        guard whose job is "do not emit what the gate will block" should be asking
        the gate's question, not a lookalike. Whole-string equality against the
        originals set is subsumed by it -- a needle equal to the haystack occurs in
        it as a unit -- so it is not also tested separately.

        Cost: one pass over the session's originals per Tier-2 span, rejected by the
        C-level substring pre-filter inside ``_occurs_as_a_unit`` on all but a
        handful. The haystack is a date, so it is tens of characters rather than a
        payload; this is the same shape as the gate's own pass 1 and inherits the
        same answer at scale (an incremental Aho-Corasick automaton, README Q1).

        **A shifted date must also not duplicate a surrogate the session already
        issued**, and that is a wholly separate collision from the two above. Those
        ask "does this surrogate carry a real value?"; this one asks "does this
        surrogate already stand for a *different* original?". Nothing about the
        originals set can answer it, because a duplicate carries no original at all.

        It is reachable from ordinary input, which is what makes it worth a guard
        rather than an assumption. Tier 2 is a *many-to-one* map by construction:
        the shift preserves the date and the renderer preserves the source's
        format, so two spans denoting the same day in two formats -- ``2024-01-05``
        in a header and ``Friday, January 5, 2024`` in the prose beneath it -- both
        render through the ISO renderer (the second via :func:`_parse_fallback`)
        and produce the byte-identical string. Two distinct vault originals then
        own one surrogate. Tier 1 cannot reach this state because
        :meth:`_fake_identifier` already tests :meth:`_surrogate_taken`; Tier 2 was
        simply never asked the question.

        The consequence was not a leak and not a silent mis-restore -- the
        orchestrator's step 4b
        (``_assert_surrogates_are_distinct``) catches the duplicate and refuses the
        run before the provider is called, which is the right backstop. But it
        refuses it with ``PipelineError(reason='surrogate_collision')``, so a
        perfectly ordinary two-format document became unprocessable, and that
        function's own docstring asserts the opposite -- "reaching this is a bug
        upstream, not a user input: the pseudonymization strategy already rejects a
        candidate fake that any surrogate in the session has taken". That sentence
        is true of Tier 1 only. Making it true of Tier 2 as well is this check.

        The colliding date degrades to a plain token, exactly as it does for the
        two collisions above: it keeps referential integrity and loses only its own
        temporal relation, while every other date in the document keeps the shared
        shift. Regenerating is not an option here for the same reason it is not
        above -- the shift is one constant per session and varying it is what the
        tier exists not to do.
        """
        raw = detection.text
        stripped = raw.strip()
        lead = raw[: len(raw) - len(raw.lstrip())]
        trail = raw[len(raw.rstrip()) :]
        parsed = parse_source_date(stripped)
        if parsed is None:
            logger.info(
                "date span unparseable; emitting a plain token",
                extra={"entity_type": detection.entity_type, "token_id": token_id},
            )
            return self.plain_token(detection, token_id)

        shifted = f"{lead}{parsed.render(parsed.value + timedelta(days=self._shift_days))}{trail}"
        rendered = normalize(shifted)
        originals = self._normalized_originals(vault, session_id)
        # Both directions. A rendered date that swallows an original and one that is
        # swallowed by a longer original are the same defect -- a real vaulted value
        # travelling verbatim inside a surrogate we invented -- and only the first
        # was tested. See this method's docstring for the measured second case.
        if rendered == normalize(raw) or any(
            _occurs_as_a_unit(value, rendered) or _occurs_as_a_unit(rendered, value)
            for value in originals
        ):
            logger.info(
                "shifted date collides with an original; emitting a plain token",
                extra={"entity_type": detection.entity_type, "token_id": token_id},
            )
            return self.plain_token(detection, token_id)
        # Exact string, not the normalised one: the vault indexes a surrogate by the
        # bytes it stores, so that is the only comparison that predicts what
        # ``get_by_surrogate`` -- and the orchestrator's step-4b duplicate check --
        # will actually see.
        if await self._surrogate_taken(vault, session_id, shifted):
            logger.info(
                "shifted date duplicates a surrogate already issued; emitting a plain token",
                extra={"entity_type": detection.entity_type, "token_id": token_id},
            )
            return self.plain_token(detection, token_id)
        return shifted


def _is_passthrough(word: str) -> bool:
    return word.rstrip(".").casefold() in _NAME_PASSTHROUGH
