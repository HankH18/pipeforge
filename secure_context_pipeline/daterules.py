"""Date parsing that remembers the source format, plus the composite-span split.

**Why this is a leaf module rather than part of the Tier-2 strategy.** The format
table below was written for one consumer -- ``PseudonymizationStrategy._shift_date``,
which has to re-render a shifted date in the spelling the document used. It now has a
second, one layer *below* it: the detector, which needs to know whether a span it is
about to hand downstream is one date or several. ``obfuscation.engine`` imports
``detection.detector`` (for :func:`~secure_context_pipeline.detection.detector.resolve_overlaps`),
so detection cannot import back into obfuscation without a cycle, and the alternative
-- a second, narrower "does this look like a date" test living in the detector -- is
exactly the two-copies-of-one-decision shape that
:mod:`secure_context_pipeline.textrules` exists to record the cost of. So the table
moved down here, where both layers can depend on it *downward*, and
:mod:`~secure_context_pipeline.obfuscation.strategies.pseudonymization` re-exports
:func:`parse_source_date` under the name its callers already used.

Nothing here logs, raises or reprs a value: a date span is an original.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime

from dateutil import parser as dateutil_parser

from secure_context_pipeline.textrules import delimited_parts, match_case

__all__ = [
    "SourceDate",
    "parse_source_date",
    "split_composite_date",
]

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

#: The second anchor :func:`_parse_fallback` parses against. Shares **no field** with
#: :data:`_FALLBACK_ANCHOR` -- different year, month and day -- so any component the
#: text does not supply differs between the two parses and is detectable as invented.
#: A probe sharing even one field would be blind to a text that omits exactly that
#: field.
_FALLBACK_PROBE = datetime(1997, 6, 24)


@dataclass(frozen=True, slots=True)
class SourceDate:
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
    return match_case(source_word, rendered) + dotted


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


def _parse_iso(text: str) -> SourceDate | None:
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

    return SourceDate(value, render)


def _parse_numeric(text: str) -> SourceDate | None:
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

    return SourceDate(value, render)


def _parse_month_day_year(text: str) -> SourceDate | None:
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

    return SourceDate(value, render)


def _parse_day_month_year(text: str) -> SourceDate | None:
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

    return SourceDate(value, render)


def _parse_month_year(text: str) -> SourceDate | None:
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

    return SourceDate(value, render)


def _parse_fallback(text: str) -> SourceDate | None:
    """``dateutil`` for anything the format table missed; renders ISO.

    Guarded twice, and the second guard is the one that works.

    The digit-run count rejects a bare year ("2024") so it is not silently promoted
    to 1 January and shifted into a plausible-looking lie. It does **not** reject a
    bare clock time: ``9:15 AM`` has two digit runs, neither of which is a date
    component, and ``dateutil`` resolved the whole date from the anchor. The payload
    then asserted ``2000-03-14`` for a span whose text says nothing about any day --
    which is exactly the failure this module's own comment says it exists to prevent
    ("a shifted today is a wrong date that looks right"). Relocating the anchor from
    *today* to a fixed date moved that lie; it did not remove it. Worse, every
    subsequent clock time in the document resolves to the same fabricated date and
    collides in the vault, so three times on one page render three incomparable ways.

    So the real question is asked directly: **did any date component come from the
    text, or all of them from the default?** Parsing twice against two anchors that
    share no field answers it exactly -- a component the text supplies is identical
    both times, and one taken from the default differs. No heuristic about digits can
    decide this, which is why the first guard could not.
    """
    if len(_DIGIT_RUN_RE.findall(text)) < 2:
        return None
    try:
        parsed = dateutil_parser.parse(text, default=_FALLBACK_ANCHOR, fuzzy=False)
        probe = dateutil_parser.parse(text, default=_FALLBACK_PROBE, fuzzy=False)
    except (ValueError, OverflowError, TypeError):
        return None
    if parsed.date() != probe.date():
        # At least one of (year, month, day) was invented by the anchor. A date this
        # pipeline made up is not a date it may shift and present as the source's.
        return None
    return SourceDate(parsed.date(), lambda shifted: shifted.isoformat())


_DATE_PARSERS: tuple[Callable[[str], SourceDate | None], ...] = (
    _parse_iso,
    _parse_numeric,
    _parse_month_day_year,
    _parse_day_month_year,
    _parse_month_year,
    _parse_fallback,
)


def parse_source_date(text: str) -> SourceDate | None:
    """First parser that recognises ``text``, or ``None`` if none does."""
    for parser in _DATE_PARSERS:
        parsed = parser(text)
        if parsed is not None:
            return parsed
    return None


#: Shortest constituent worth parsing at all. A one- or two-character run cannot be a
#: date in any spelling this table knows, and refusing it before ``dateutil`` sees it
#: keeps the fallback from being asked a question it might answer creatively.
_MIN_CONSTITUENT_LEN = 3


def split_composite_date(text: str) -> tuple[tuple[int, int], ...]:
    """``(start, end)`` bounds of the dates in ``text`` when it is a *list* of dates.

    Returns ``()`` -- meaning "leave this span exactly as it is" -- unless all of the
    following hold:

    * ``text`` does **not** parse as a single date. A span the format table already
      understands is not a composite whatever punctuation it contains, and this
      function must not change what happens to it;
    * it splits on :data:`~secure_context_pipeline.textrules.DELIMITER_RE` into **two
      or more** non-trivial constituents;
    * **every** one of those constituents parses.

    The last condition is the load-bearing one and it is all-or-nothing on purpose. A
    *partial* split is worse than no split: it would vault some constituents and leave
    the rest sitting in a rump span, and a rump span is a value the pipeline has
    decided is not an entity. So one unparseable piece refuses the whole thing, which
    is also what keeps this function away from spans it has no business touching --
    ``Prior visits: 03/11/2024, 09/17/2024`` fails on ``Prior visits: 03/11/2024``,
    and a ``DATE_TIME`` span that overlap resolution widened to swallow a name fails on
    the piece carrying the name.

    **This is a security fix and a utility fix, and the second one is not a
    consolation.** Security: spaCy returns ``03/11/2024, 09/17/2024`` as a single
    ``DATE`` span, so that whole composite string becomes one vault original, and both
    leak scanners ask whether a *whole* vaulted value occurs. A different date in the
    same document, shifted by the session delta, can then render as a verbatim
    word-bounded *slice* of that original -- a real patient date on the wire inside a
    string the pipeline invented, with both scanners correctly reporting clean by their
    own definitions. Utility: the composite also fails
    :func:`parse_source_date`, so Tier 2 degrades it to a plain token and silently
    loses the interval property that is the entire reason Tier 2 exists. Split, each
    constituent gets the session's shift, and the intervals between the dates in the
    list survive into the payload exactly as the intervals between every other pair of
    dates in the document do.

    Offsets are into ``text`` and are trimmed of surrounding whitespace, so
    ``text[start:end]`` is the constituent byte for byte. The caller translates them
    into the document and re-derives each detection's text by *slicing the document*
    rather than by trusting that arithmetic -- see
    :meth:`~secure_context_pipeline.detection.detector.Detector._split_composite_dates`,
    which raises rather than emitting a detection whose offsets and text disagree.
    """
    stripped = text.strip()
    if not stripped or parse_source_date(stripped) is not None:
        return ()

    parts = delimited_parts(text)
    if len(parts) < 2:
        return ()
    for start, end in parts:
        constituent = text[start:end]
        if len(constituent) < _MIN_CONSTITUENT_LEN:
            return ()
        if parse_source_date(constituent) is None:
            return ()
    return parts
