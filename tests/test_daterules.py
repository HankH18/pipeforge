"""Tests for :mod:`secure_context_pipeline.daterules` -- the format-preserving parser.

The module exists so a Tier-2 shifted date can be written back in the spelling the
document used, so the tests that matter are the **rendering** ones: a parser that reads
``Sept. 5, 2024`` and hands back ``2024-10-15`` has lost the thing this module is for.
Every rendering expectation below is a literal string written out here, never a value
computed by calling the renderer under test.

The refusal half is equally load-bearing. An impossible date that parses anyway becomes
a fabricated day the pipeline presents as the source's -- which is the failure the
module's own docstring says it exists to prevent.

``tests/test_obfuscation.py`` already pins the two-anchor probe inside ``_parse_fallback``
(clock times, bare years) and ``tests/test_detection.py`` pins the all-or-nothing rule in
:func:`split_composite_date`; neither is repeated here.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from secure_context_pipeline.daterules import parse_source_date, split_composite_date


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("2024-01-15", "2024-01-15", id="iso"),
        pytest.param("2024-1-5", "2024-01-05", id="iso-unpadded"),
        pytest.param("03/11/2024", "2024-03-11", id="numeric-slash"),
        pytest.param("03.11.2024", "2024-03-11", id="numeric-dot"),
        pytest.param("03-11-2024", "2024-03-11", id="numeric-dash"),
        pytest.param("3/11/2024", "2024-03-11", id="numeric-unpadded"),
        pytest.param("01/15/24", "2024-01-15", id="numeric-two-digit-year"),
        # The leading field cannot be a month, so this one is day-first.
        pytest.param("25/12/2024", "2024-12-25", id="numeric-day-first"),
        pytest.param("January 5, 2024", "2024-01-05", id="month-day-year"),
        pytest.param("Jan 5, 2024", "2024-01-05", id="month-day-year-abbreviated"),
        pytest.param("Sept. 5, 2024", "2024-09-05", id="month-day-year-sept-dotted"),
        pytest.param("January 5 2024", "2024-01-05", id="month-day-year-no-comma"),
        pytest.param("January 1st, 2024", "2024-01-01", id="month-day-year-ordinal"),
        pytest.param("5 June 2024", "2024-06-05", id="day-month-year"),
        pytest.param("5th June 2024", "2024-06-05", id="day-month-year-ordinal"),
        pytest.param("5 Jun. 2024", "2024-06-05", id="day-month-year-abbreviated"),
        # No day in the text at all: the month's first is the documented choice.
        pytest.param("January 2024", "2024-01-01", id="month-year"),
        pytest.param("May 2024", "2024-05-01", id="month-year-may"),
        # Nothing in the format table matches; dateutil supplies every component.
        pytest.param("Friday, January 5, 2024", "2024-01-05", id="fallback"),
    ],
)
def test_each_format_branch_reads_the_day_the_source_names(text: str, expected: str) -> None:
    """One row per branch of the format table, asserted on the calendar day parsed.

    The day-first row is the one that is easy to get wrong in both directions: US
    ordering is assumed unless the leading field cannot be a month, so ``25/12/2024``
    is 25 December and ``03/11/2024`` is 11 March, not the other way round.
    """
    parsed = parse_source_date(text)
    assert parsed is not None, f"{text!r} is a date and did not parse"
    assert parsed.value.isoformat() == expected


@pytest.mark.parametrize(
    ("text", "why"),
    [
        pytest.param("02/30/2024", "February has no 30th, in any year", id="numeric-day-30-feb"),
        pytest.param("13/13/2024", "neither field can be a month", id="numeric-13-13"),
        pytest.param("00/11/2024", "month zero", id="numeric-month-zero"),
        pytest.param("03/00/2024", "day zero", id="numeric-day-zero"),
        pytest.param("2024-02-30", "ISO shape, impossible day", id="iso-impossible-day"),
        pytest.param("2024-13-01", "ISO shape, impossible month", id="iso-impossible-month"),
        pytest.param("0000-01-01", "year zero is not a date Python can build", id="iso-year-zero"),
        pytest.param("February 30, 2024", "spelled out, impossible day", id="mdy-impossible-day"),
        pytest.param("30 February 2024", "day-first, impossible day", id="dmy-impossible-day"),
        pytest.param("Foobar 5, 2024", "matches the shape, is not a month", id="mdy-not-a-month"),
        pytest.param("5 Foobar 2024", "matches the shape, is not a month", id="dmy-not-a-month"),
        pytest.param("Foobar 2024", "matches the shape, is not a month", id="my-not-a-month"),
        pytest.param("January 0000", "month-year with year zero", id="my-year-zero"),
        pytest.param("March", "a bare month names no day", id="bare-month"),
        pytest.param("not a date at all", "prose", id="prose"),
    ],
)
def test_text_that_is_not_a_real_date_does_not_parse(text: str, why: str) -> None:
    """Impossible and half-formed dates are refused rather than repaired.

    Each of these matches one of the format regexes on shape alone, so the refusal has
    to come from the calendar check behind it. A date that parses here is a day the
    pipeline invented, and Tier 2 would shift it and present it as the source's.
    """
    assert parse_source_date(text) is None, why


@pytest.mark.parametrize(
    ("source", "shift_days", "expected"),
    [
        pytest.param("2024-01-15", 40, "2024-02-24", id="iso"),
        pytest.param("2024-01-15", -45, "2023-12-01", id="iso-backwards-over-new-year"),
        # Zero padding is a property of the source, not of the renderer.
        pytest.param("2024-1-5", 40, "2024-2-14", id="iso-unpadded-stays-unpadded"),
        pytest.param("03/11/2024", 40, "04/20/2024", id="numeric-slash"),
        pytest.param("03.11.2024", 40, "04.20.2024", id="numeric-dot"),
        pytest.param("03-11-2024", 40, "04-20-2024", id="numeric-dash"),
        pytest.param("3/11/2024", 40, "4/20/2024", id="numeric-unpadded-first-field"),
        pytest.param("01/15/24", 40, "02/24/24", id="numeric-two-digit-year"),
        pytest.param("01/15/24", -20, "12/26/23", id="numeric-two-digit-year-backwards"),
        pytest.param("25/12/2024", 40, "03/02/2025", id="numeric-day-first-stays-day-first"),
        pytest.param("January 5, 2024", 40, "February 14, 2024", id="mdy-full-month"),
        pytest.param("Jan 5, 2024", 40, "Feb 14, 2024", id="mdy-abbreviated-stays-abbreviated"),
        pytest.param("Sep 5, 2024", 40, "Oct 15, 2024", id="mdy-abbreviated-across-months"),
        pytest.param("Sept. 5, 2024", 40, "Oct. 15, 2024", id="mdy-dot-is-kept"),
        pytest.param("JAN 5, 2024", 40, "FEB 14, 2024", id="mdy-all-caps"),
        pytest.param("jan. 5, 2024", 40, "feb. 14, 2024", id="mdy-all-lower-dotted"),
        pytest.param("January 5 2024", 40, "February 14 2024", id="mdy-absent-comma-stays-absent"),
        pytest.param("January 1st, 2024", 40, "February 10th, 2024", id="mdy-ordinal"),
        # "May" is both the full name and its own abbreviation, so it is read as full
        # and the shifted month is spelled out.
        pytest.param("May 5, 2024", 40, "June 14, 2024", id="mdy-may-renders-full"),
        pytest.param("5 June 2024", 40, "15 July 2024", id="dmy-full-month"),
        pytest.param("5 Jun. 2024", 40, "15 Jul. 2024", id="dmy-abbreviated-dotted"),
        pytest.param("5th June 2024", 40, "15th July 2024", id="dmy-ordinal"),
        # The source named no day, so neither does the render -- even though the shift
        # moved one.
        pytest.param("January 2024", 40, "February 2024", id="month-year-drops-the-day"),
        pytest.param("January 2024", 5, "January 2024", id="month-year-shift-within-month"),
        # Nothing was preserved because nothing was recognised: the fallback renders ISO.
        pytest.param("Friday, January 5, 2024", 40, "2024-02-14", id="fallback-renders-iso"),
    ],
)
def test_a_shifted_date_is_re_rendered_in_the_source_format(
    source: str, shift_days: int, expected: str
) -> None:
    """The point of the module: the shifted day comes back in the source's spelling.

    Separator, field widths, field order, month abbreviation, the trailing dot, the
    comma, letter case and the ordinal suffix are all carried from the source rather
    than chosen by the renderer. A document that wrote ``03.11.2024`` and gets back
    ``2024-04-20`` has been reformatted by the pipeline, which is a fidelity loss the
    reader can see.
    """
    parsed = parse_source_date(source)
    assert parsed is not None, f"premise: {source!r} parses"
    assert parsed.render(parsed.value + timedelta(days=shift_days)) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param("2024-01-15", "2024-01-15", id="iso"),
        pytest.param("2024-1-5", "2024-1-5", id="iso-unpadded"),
        pytest.param("03.11.2024", "03.11.2024", id="numeric-dot"),
        pytest.param("01/15/24", "01/15/24", id="numeric-two-digit-year"),
        pytest.param("25/12/2024", "25/12/2024", id="numeric-day-first"),
        pytest.param("January 1st, 2024", "January 1st, 2024", id="mdy-ordinal"),
        pytest.param("jan. 5, 2024", "jan. 5, 2024", id="mdy-lower-dotted"),
        pytest.param("5th June 2024", "5th June 2024", id="dmy-ordinal"),
        pytest.param("MAY 2024", "MAY 2024", id="month-year-caps"),
        # The two shapes that do NOT round-trip, recorded rather than asserted away.
        # "Sept" is four letters and every abbreviation this table renders is three.
        pytest.param("Sept. 5, 2024", "Sep. 5, 2024", id="sept-is-normalised-to-sep"),
        pytest.param("SEPT 5, 2024", "SEP 5, 2024", id="sept-caps-is-normalised-to-sep"),
        # The fallback recognised no format, so it has none to reproduce.
        pytest.param("Friday, January 5, 2024", "2024-01-05", id="fallback-renders-iso"),
    ],
)
def test_a_zero_shift_reproduces_the_source(source: str, expected: str) -> None:
    """Rendering the day that was parsed returns the source text, with two exceptions.

    This is format preservation stated as an identity, which is a stronger claim than
    any single shifted example: it fails if the renderer normalises anything at all.
    The two rows that are not identities are the whole of the divergence, and both are
    named -- if a third appears, this test says so.
    """
    parsed = parse_source_date(source)
    assert parsed is not None, f"premise: {source!r} parses"
    assert parsed.render(parsed.value) == expected


@pytest.mark.parametrize(
    ("day", "suffix"),
    [
        (1, "st"),
        (2, "nd"),
        (3, "rd"),
        (4, "th"),
        (10, "th"),
        (11, "th"),
        (12, "th"),
        (13, "th"),
        (21, "st"),
        (22, "nd"),
        (23, "rd"),
        (30, "th"),
        (31, "st"),
    ],
)
def test_the_ordinal_suffix_follows_the_shifted_day(day: int, suffix: str) -> None:
    """The suffix is recomputed for the day the shift landed on, not copied.

    11th, 12th and 13th are the rows that matter: a suffix table keyed on the last
    digit alone renders them ``11st``, ``12nd``, ``13rd``, which reads as a typo in an
    otherwise clean document.
    """
    parsed = parse_source_date("January 1st, 2024")
    assert parsed is not None, "premise"
    assert parsed.render(date(2024, 1, day)) == f"January {day}{suffix}, 2024"


def test_no_ordinal_is_invented_for_a_source_that_used_none() -> None:
    """The suffix is a source property; a plain source stays plain after the shift."""
    parsed = parse_source_date("January 1, 2024")
    assert parsed is not None, "premise"
    assert parsed.render(date(2024, 1, 21)) == "January 21, 2024"


@pytest.mark.parametrize(
    ("source", "expected_year"),
    [
        pytest.param("01/15/00", 2000, id="00-lower-bound"),
        pytest.param("01/15/68", 2068, id="68-last-of-the-2000s"),
        pytest.param("01/15/69", 1969, id="69-first-of-the-1900s"),
        pytest.param("01/15/99", 1999, id="99-upper-bound"),
    ],
)
def test_two_digit_years_use_the_posix_pivot_at_its_boundaries(
    source: str, expected_year: int
) -> None:
    """00-68 is 2000s and 69-99 is 1900s, checked on both sides of the pivot.

    Only the two rows either side of 68/69 can tell one pivot year from another, and a
    wrong pivot puts a date a century away from the one the document meant -- which
    survives the shift and reads as a plausible date throughout.
    """
    parsed = parse_source_date(source)
    assert parsed is not None, "premise"
    assert parsed.value.year == expected_year


def test_a_two_digit_year_stays_two_digits_across_a_century() -> None:
    """The source wrote two digits, so the shifted date does too.

    ``12/31/99`` shifted a single day is a year, a century and a millennium later, and
    the render must still be ``01/01/00`` -- widening it to ``2000`` would put a shape
    in the document the document never used.
    """
    parsed = parse_source_date("12/31/99")
    assert parsed is not None, "premise"
    assert parsed.value == date(1999, 12, 31)
    assert parsed.render(parsed.value + timedelta(days=1)) == "01/01/00"


def test_a_composite_offset_indexes_the_untrimmed_span() -> None:
    """Offsets address the string as given, so slicing it yields each date exactly.

    The caller translates these into document offsets, so an offset measured against a
    trimmed copy would mis-splice every span that arrives with surrounding whitespace.
    """
    text = "  03/11/2024 , 09/17/2024  "
    parts = split_composite_date(text)
    assert [text[start:end] for start, end in parts] == ["03/11/2024", "09/17/2024"]


@pytest.mark.parametrize(
    ("text", "why"),
    [
        pytest.param("03/11/2024, 12, 09/17/2024", "a two-character constituent", id="short-piece"),
        pytest.param(
            "03/11/2024, 1, 09/17/2024", "a one-character constituent", id="shorter-piece"
        ),
        pytest.param("   ", "whitespace only", id="blank"),
    ],
)
def test_a_span_with_a_trivial_constituent_is_left_whole(text: str, why: str) -> None:
    """A run too short to be a date in any spelling refuses the whole split.

    All-or-nothing is the rule: a partial split vaults some constituents and leaves the
    rest in a rump span the pipeline has already decided is not an entity. The blank row
    covers the other early return -- a span with nothing in it is not a list of dates.
    """
    assert split_composite_date(text) == (), why
