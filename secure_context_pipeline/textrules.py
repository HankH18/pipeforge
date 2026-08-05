"""Surface-text rules, defined once, in a leaf module below everything.

The rule this module was built for is the word-boundary one. Four components need to
answer one question -- *does this value occur here as a unit, or is it part of a
longer word?* -- and they must answer it identically:

* the egress gate's pass 1, deciding whether a vaulted original is in the payload;
* the obfuscation engine's residual sweep, deciding whether to replace a surface;
* the restorer's surrogate matcher, deciding where a pseudonym ends;
* the leakage harness, deciding whether a planted value leaked.

**Why this module exists.** The rule was previously written out independently in each
of them as ``(?<!\\w)...(?!\\w)``. Because regex ``\\w`` counts ``_`` as a word
character, all four refused to match ``_John Smith_`` -- ordinary markdown emphasis --
and the value went to the provider byte-for-byte while the harness reported
``100/100 clean``. Three components agreeing with each other proved nothing, because
they shared the mistake. The same blind spot covered every value whose first or last
character is punctuation: ``(415) 555-0123``, ``$1,234.56``, ``Ph.D.``.

The first repair pointed the consumers at the gate's copy. That fixed divergence but
left two problems, and this module is the second repair:

1. **It inverted the dependency graph.** ``obfuscation`` and ``deobfuscation`` are
   lower layers than ``pipeline``, which imports both -- so the gate could not import
   them back without a cycle, and the arrows pointed the wrong way.
2. **It only shared the alphabet, not the rule.** The engine and the restorer imported
   ``_ALNUM`` and then *reassembled the guards by hand*, so a rename raised
   ``ImportError`` (as intended) but an edit to the rule still had to be made in three
   places and nothing would have caught missing one. Sharing a constant is not sharing
   a decision.

Everything here is public and this module imports nothing from the package, so every
consumer depends *downward* on one definition. A fifth convention cannot appear
without deleting an import.

**What this rule is not.** It is the right test for a *name* and the wrong one for an
*identifier*. The false-positive argument it exists to prevent is a word-list argument:
``Browning`` is a real word containing the real surname ``Brown``, so matching ``Brown``
inside it would be a false leak report. But ``batch47-1234567Alpha`` is not a real
anything containing a taxpayer ID. The gate scans digit-carrying values with no
adjacency requirement at all (``_identifier_needles``) for exactly that reason, and the
two deliberately disagree -- the gate blocks a shape the sweep leaves behind, which is
the safe direction to differ in.

**Two smaller rules live here for the same reason**, and neither is a boundary
question:

* :func:`delimited_parts` -- where an ordinary English list separates one value from
  the next. Detection uses it to split a composite ``DATE`` span into the dates it is
  actually made of; the egress gate's pass 1 uses it to derive a needle per
  constituent of a composite vaulted original. The two apply *different* rules to
  decide which constituents qualify and share nothing else, which is exactly why the
  split itself has to be shared: "the gate scans for the pieces detection would have
  split out" is a claim about one delimiter grammar, and it is only true while there
  is one.
* :func:`match_case` -- carrying a source word's ALL-CAPS/all-lower styling onto a
  generated one. The Tier-1 name generator and the Tier-2 date renderer both need it,
  and since the date format table moved into
  :mod:`secure_context_pipeline.daterules` they no longer share a module to keep it
  in.
"""

from __future__ import annotations

import re

__all__ = [
    "ALNUM",
    "ALNUM_RE",
    "DELIMITER_RE",
    "LEFT_GUARD",
    "RIGHT_GUARD",
    "boundary_guards",
    "delimited_parts",
    "guards_left",
    "guards_right",
    "match_case",
    "occurs_as_a_unit",
    "word_bounded_pattern",
]

#: A word character for boundary purposes, **excluding underscore**. Regex ``\w``
#: counts ``_`` as a word character, which hands markdown a free bypass: the emphasis
#: form ``_John Smith_`` puts the original on the wire byte-for-byte while
#: ``(?<!\w)John Smith(?!\w)`` refuses to match it. Underscore is punctuation in prose,
#: so it is a boundary here.
ALNUM = r"[^\W_]"
ALNUM_RE = re.compile(ALNUM)

#: The two assertions, as constants rather than as f-strings at each call site. The
#: restorer needs them separately -- it groups surrogates by whether the left guard
#: applies so one assertion can front a whole alternation -- which is why this module
#: exposes the predicates and the assembled pattern rather than the pattern alone.
LEFT_GUARD = f"(?<!{ALNUM})"
RIGHT_GUARD = f"(?!{ALNUM})"


def guards_left(value: str) -> bool:
    """Whether a left boundary assertion is meaningful for ``value``.

    Only when the value's own first character is alphanumeric. A boundary assertion
    answers "is this one word, or part of a longer one?", which is meaningless on a
    side where the value itself begins with punctuation. Asserting unconditionally
    asked whether the character before ``(`` in ``(415) 555-0123`` was a word
    character -- so ``tel(415) 555-0123`` passed every check while carrying the
    original verbatim.
    """
    return bool(value) and ALNUM_RE.match(value[0]) is not None


def guards_right(value: str) -> bool:
    """Whether a right boundary assertion is meaningful for ``value``.

    The mirror of :func:`guards_left`; see it for why this is per-side rather than
    unconditional. ``USD$1,234.56`` and ``Ph.D.degree`` are the values this decides.
    """
    return bool(value) and ALNUM_RE.match(value[-1]) is not None


def boundary_guards(value: str) -> tuple[str, str]:
    """The ``(left, right)`` assertions for ``value``, each empty where meaningless.

    This is the single decision the four consumers must agree on. Everything else in
    this module is built from it.
    """
    return (
        LEFT_GUARD if guards_left(value) else "",
        RIGHT_GUARD if guards_right(value) else "",
    )


def word_bounded_pattern(value: str) -> str:
    """``value`` as a literal pattern that cannot match inside a longer word.

    An empty value gets a pattern that never matches rather than one that matches
    everywhere -- the difference between a no-op and a catastrophe, since callers
    substitute on what this matches.
    """
    if not value:
        return r"(?!)"
    left, right = boundary_guards(value)
    return left + re.escape(value) + right


def occurs_as_a_unit(needle: str, haystack: str) -> bool:
    """Whether ``needle`` appears in ``haystack`` as a unit rather than inside a word.

    Raw substring matching produces false blocks that look exactly like leaks: the
    surname ``Brown`` is a real original, a generated fake surname ``Browning``
    contains it, and a naive ``"brown" in payload`` reports a leak that is not one.
    The 100-run harness surfaced this and it cost real time to tell apart from the
    genuine substring leak it resembles.

    Because every match requires the literal needle to be present, ``needle in
    haystack`` is an **exact** pre-filter rather than an approximation. It is roughly
    40x faster than the regex on the overwhelmingly common miss, which is what keeps a
    large per-session originals set off the critical path (20k originals against a
    54 KB payload: ~31 s before, ~1 s after).
    """
    if not needle or needle not in haystack:
        return False
    left, right = boundary_guards(needle)
    if not left and not right:
        return True
    return re.search(left + re.escape(needle) + right, haystack) is not None


#: The delimiters an ordinary English list puts between one value and the next: a
#: comma, a semicolon, an ampersand, or the word "and".
#:
#: **Whitespace is deliberately not one of them.** A space is what separates the
#: *components* of a single value -- ``John Smith``, ``Park Avenue``, ``chronic low
#: back pain`` -- so admitting it would turn a rule about composite values into a rule
#: about partial ones. Those are different problems with very different costs: a
#: composite constituent is a whole value that a joining word happened to glue to
#: another whole value, while ``Smith`` out of ``John Smith`` needs per-entity policy
#: and is what makes a fail-closed gate deny ordinary prose.
#:
#: No quantifier here is unbounded and none can backtrack: the alternation is four
#: literals matched left to right, so ``finditer`` is linear in the input. An earlier
#: draft absorbed the surrounding whitespace (``\s*(?:,|;|&|\band\b)\s*``), which is
#: quadratic on a long whitespace run -- the same shape as the ``TOKEN_RE`` denial of
#: service recorded in :mod:`secure_context_pipeline.surrogates`, reachable from an
#: ordinary document upload. The whitespace is trimmed off the parts instead.
DELIMITER_RE = re.compile(r",|;|&|\band\b", re.IGNORECASE)


def delimited_parts(value: str) -> tuple[tuple[int, int], ...]:
    """``(start, end)`` bounds of ``value``'s :data:`DELIMITER_RE`-separated parts.

    Bounds rather than substrings, because the offsets are the part that is easy to
    get wrong and both callers need them. The detector emits one detection per
    constituent and those offsets have to address the *document*, so a caller that
    received strings would have to re-find them -- and re-finding is how an off-by-one
    becomes a mis-spliced value rather than a failed test. ``value[start:end]`` is the
    constituent exactly, with surrounding whitespace already trimmed.

    Empty and whitespace-only runs are dropped. They occur for real rather than
    theoretically: ``"a, b, and c"`` puts a bare space between the second comma and
    the ``and``, and a trailing comma leaves an empty tail. Neither carries anything,
    and counting them as constituents would make every ordinary three-item list fail a
    caller's "every part must qualify" rule.

    A value with no delimiter in it comes back as a 1-tuple covering the whole
    (trimmed) value, not as ``()``. Deciding that one part is not a composite belongs
    to the caller -- both of this function's callers require at least two -- and
    folding that decision in here would hide it in a helper.
    """
    bounds: list[tuple[int, int]] = []
    cursor = 0
    for match in DELIMITER_RE.finditer(value):
        bounds.append((cursor, match.start()))
        cursor = match.end()
    bounds.append((cursor, len(value)))

    parts: list[tuple[int, int]] = []
    for start, end in bounds:
        piece = value[start:end]
        trimmed = piece.strip()
        if not trimmed:
            continue
        lead = len(piece) - len(piece.lstrip())
        parts.append((start + lead, start + lead + len(trimmed)))
    return tuple(parts)


def match_case(source: str, generated: str) -> str:
    """Carry the source's ALL-CAPS / all-lower styling onto a generated word.

    Mixed case is left alone: a source that is neither uniformly upper nor uniformly
    lower carries no styling decision worth copying, and guessing one (title case,
    say) would rewrite ``McDonald`` and ``d'Arcy`` into something the source never
    said.
    """
    if source.isupper():
        return generated.upper()
    if source.islower():
        return generated.lower()
    return generated
