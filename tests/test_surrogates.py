"""The surrogate/token grammar -- the one module three components must agree on.

``secure_context_pipeline/surrogates.py`` had no test file of its own, and it is
the seam where the *emitter* (the tokenization strategy), the *matcher* (the
restorer) and the *skip-list* (the egress gate) meet. A disagreement between them
is not a cosmetic bug: a token the emitter can produce and the matcher cannot read
back is unrestorable **and** absent from the gate's protected spans, which is both
halves of what this module exists to prevent.

So these tests are written as **properties over the validator/matcher pair**, not
as a list of shapes. Listing shapes is how the hole got there: every shape anyone
thought to write down passed, while ``ENTITY_TYPE_RE``'s ``$`` quietly accepted a
trailing newline and ``format_surrogate("PII", "NAME\\n", ...)`` emitted
``[PII_NAME\\n_deadbeef]``, which nothing in the codebase can match. A property
that quantifies over inputs finds that; a table of examples never will.

Hypothesis carries the quantification. Where a property is cheap to state
exhaustively (every category, every codepoint class at every position) it is done
exhaustively instead, because an exhaustive check is a stronger statement than a
sampled one.
"""

from __future__ import annotations

import re
import string
import unicodedata

import pytest
from hypothesis import assume, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.surrogates import (
    CATEGORIES,
    ENTITY_TYPE_RE,
    HINT_RE,
    MAX_ENTITY_TYPE_LEN,
    MAX_HINT_LEN,
    REDACTION_RE,
    STRICT_TOKEN_RE,
    TOKEN_RE,
    extract_token_ids,
    format_redaction,
    format_surrogate,
    validate_entity_type,
)

# A token ID is `hexdigest()[:8]`: lowercase, exactly eight.
TOKEN_ID = "1a2b3c4d"

#: Text that is *around* a token in a real response. Hypothesis draws from the
#: whole unicode range, but these are the shapes that actually broke things.
NASTY_TEXT = st.text(
    alphabet=st.sampled_from(list(" \t\n\r|[](){}_-.,:;'\"*`abcXYZ019é́")),
    max_size=24,
)

entity_types = st.text(
    alphabet=st.sampled_from(string.ascii_uppercase + string.digits + "_"),
    min_size=1,
    max_size=MAX_ENTITY_TYPE_LEN,
)
hints = st.text(alphabet=st.sampled_from(string.ascii_lowercase + string.digits + "-"), max_size=32)
token_ids = st.text(alphabet=st.sampled_from(string.hexdigits), min_size=1, max_size=12)
categories = st.sampled_from(CATEGORIES)


# --------------------------------------------------------------------------
# THE property: whatever the validators accept, the matchers must read back.
#
# This is the invariant the module docstring claims and the one that was false.
# It is stated once, over generated input, rather than re-derived per call site.
# --------------------------------------------------------------------------


@given(category=categories, entity_type=entity_types, token_id=st.just(TOKEN_ID), hint=hints)
@hypothesis_settings(max_examples=400)
def test_anything_format_surrogate_emits_is_matchable_by_every_matcher(
    category: str, entity_type: str, token_id: str, hint: str
) -> None:
    """Emit -> match, for every input the validators let through.

    Three matchers, because three components read this string back and a token
    that satisfies only some of them is the exact failure mode: ``STRICT_TOKEN_RE``
    is the gate's skip-list and the emitter's self-check, ``TOKEN_RE`` is the
    restorer, and ``extract_token_ids`` is what keys the vault lookup.
    """
    try:
        surrogate = format_surrogate(category, entity_type, token_id, hint or None)
    except ConfigError:
        # Rejected at the door is the other acceptable outcome -- what must never
        # happen is "accepted and then unmatchable".
        return

    assert STRICT_TOKEN_RE.fullmatch(surrogate), surrogate
    match = TOKEN_RE.search(surrogate)
    assert match is not None, surrogate
    assert match.group(0) == surrogate, (match.group(0), surrogate)
    assert match.group(3).lower() == token_id.lower()
    assert extract_token_ids(surrogate) == {token_id.lower()}


@given(entity_type=entity_types)
@hypothesis_settings(max_examples=200)
def test_anything_format_redaction_emits_is_matchable_by_the_gates_pattern(
    entity_type: str,
) -> None:
    """The redaction marker has the same emitter/matcher contract.

    The egress gate protects a redaction span by :data:`REDACTION_RE` alone. A
    marker that regex cannot read back is a span the gate re-scans as ordinary
    document text -- and the marker is what is left where a value was removed.
    """
    try:
        marker = format_redaction(entity_type)
    except ConfigError:
        return

    assert REDACTION_RE.fullmatch(marker), marker
    assert REDACTION_RE.search(marker) is not None


@given(entity_type=st.text(max_size=8), token_id=token_ids, hint=st.text(max_size=8))
@hypothesis_settings(max_examples=400)
def test_the_emitter_never_returns_an_unmatchable_string_for_any_input(
    entity_type: str, token_id: str, hint: str
) -> None:
    """Unrestricted alphabet, including whitespace and control characters.

    The strategy above draws from the grammar's own alphabet, which is the input
    a well-behaved registry produces. This one draws from anything at all, which
    is what a hand-edited ``entities.yaml`` or a gazetteer class column produces.
    Either the call raises or the result is matchable; there is no third outcome.
    """
    try:
        surrogate = format_surrogate("PHI", entity_type, token_id, hint or None)
    except ConfigError:
        return
    assert STRICT_TOKEN_RE.fullmatch(surrogate), repr(surrogate)


# --------------------------------------------------------------------------
# The specific hole: `$` matches before a trailing newline.
# --------------------------------------------------------------------------

#: Trailers that must never ride along on an entity type. Written as escapes, never
#: as literals, so no invisible character appears in this source file -- the same
#: rule ``restorer._RSQUO`` follows.
#:
#: ``\n`` is the one that actually defeated ``$``; the rest are here because a
#: reader should be able to see the boundary being asserted rather than infer it,
#: and because ``\Z`` is the only anchor that rejects the whole set uniformly.
TRAILING = [
    "\n",  # THE bug: `re` lets `$` match immediately before a trailing newline
    "\r\n",
    "\n\n",
    "\r",
    "\x0b",  # VERTICAL TAB
    "\x0c",  # FORM FEED
    "\x85",  # NEXT LINE
    "\u2028",  # LINE SEPARATOR
    " ",
    "\t",
]


@pytest.mark.parametrize("trailer", TRAILING, ids=[repr(t) for t in TRAILING])
def test_a_trailing_control_character_is_rejected_not_smuggled_through(trailer: str) -> None:
    """``ENTITY_TYPE_RE`` anchors with ``\\A``/``\\Z``, so ``.match`` cannot be fooled.

    With ``^...$`` and ``.match``, ``"NAME\\n"`` validated and ``format_surrogate``
    returned ``'[PII_NAME\\n_deadbeef]'`` -- a string NEITHER ``TOKEN_RE`` nor
    ``STRICT_TOKEN_RE`` matches. Unrestorable, and invisible to the egress gate's
    skip-list: both halves of the outcome the validator exists to prevent, from an
    input a YAML editor produces by pressing return.

    Asserted through all three doors -- the regex, the validator, and the emitter --
    because the regex is exported and a caller reaching for ``.match`` on a
    ``$``-anchored pattern is how this happened.
    """
    dirty = "NAME" + trailer

    assert ENTITY_TYPE_RE.match(dirty) is None
    assert ENTITY_TYPE_RE.fullmatch(dirty) is None
    with pytest.raises(ConfigError) as excinfo:
        validate_entity_type(dirty)
    assert excinfo.value.detail["reason"] == "entity_type_not_in_surrogate_grammar"
    with pytest.raises(ConfigError):
        format_surrogate("PII", dirty, TOKEN_ID)
    with pytest.raises(ConfigError):
        format_redaction(dirty)


@pytest.mark.parametrize("trailer", TRAILING, ids=[repr(t) for t in TRAILING])
def test_a_trailing_control_character_in_a_hint_degrades_to_a_plain_token(
    trailer: str,
) -> None:
    """A hint is dropped rather than rejected -- but it must be dropped, not emitted.

    Hints come from the gazetteer's class column, so a trailing newline is as
    reachable here as in the entity key. ``HINT_RE``'s ``$`` accepted it and
    produced ``[PII_NAME_1a2b3c4d|oral\\n]``, unmatchable by every matcher.
    """
    assert HINT_RE.match("oral" + trailer) is None

    surrogate = format_surrogate("PII", "NAME", TOKEN_ID, "oral" + trailer)

    assert surrogate == f"[PII_NAME_{TOKEN_ID}]"
    assert STRICT_TOKEN_RE.fullmatch(surrogate)


@pytest.mark.parametrize("trailer", TRAILING, ids=[repr(t) for t in TRAILING])
def test_a_trailing_control_character_in_a_token_id_is_rejected(trailer: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        format_surrogate("PII", "NAME", TOKEN_ID[:-1] + trailer)
    assert excinfo.value.detail["reason"] == "malformed_token_id"


def test_the_validator_anchors_the_match_itself_not_only_its_pattern() -> None:
    """Two independent layers, pinned independently: ``\\A``/``\\Z`` AND ``fullmatch``.

    With the pattern anchored, ``.match`` and ``.fullmatch`` behave identically, so
    the second layer is invisible unless the first is removed -- which is exactly
    the condition it exists for. ``ENTITY_TYPE_RE`` is exported and someone will
    eventually edit it; an unanchored pattern plus ``.match`` accepts ``"NAME\\n"``
    on its prefix, and the whole defect returns.

    The substitution here is unanchored on purpose. If ``validate_entity_type``
    reverts to ``.match`` this returns normally instead of raising.
    """
    import secure_context_pipeline.surrogates as module

    original = module.ENTITY_TYPE_RE
    try:
        module.ENTITY_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")  # no \A, no \Z
        assert module.ENTITY_TYPE_RE.match("NAME\n") is not None, "premise: .match accepts it"
        with pytest.raises(ConfigError) as excinfo:
            validate_entity_type("NAME\n")
        assert excinfo.value.detail["reason"] == "entity_type_not_in_surrogate_grammar"
    finally:
        module.ENTITY_TYPE_RE = original


def test_the_emitter_checks_its_own_output_not_just_its_inputs() -> None:
    """The backstop is a claim about the STRING, and it must be load-bearing.

    Anchoring the validators fixes the instance. This fixes the class: sabotage the
    validator and the emitter still refuses to hand back a token nothing can read.
    Without ``_emitted``, monkeypatching ``ENTITY_TYPE_RE`` here returns
    ``'[PII_NAME\\n_1a2b3c4d]'`` and the run continues.
    """
    import secure_context_pipeline.surrogates as module

    original = module.ENTITY_TYPE_RE
    try:
        module.ENTITY_TYPE_RE = re.compile(r".*", re.DOTALL)  # a validator that validates nothing
        with pytest.raises(ConfigError) as excinfo:
            format_surrogate("PII", "NAME\n", TOKEN_ID)
        assert excinfo.value.detail["reason"] == "emitted_token_is_unmatchable"

        with pytest.raises(ConfigError) as redaction:
            format_redaction("NAME\n")
        assert redaction.value.detail["reason"] == "emitted_redaction_is_unmatchable"
    finally:
        module.ENTITY_TYPE_RE = original

    # And the guard is not permanently on: the real validator still works.
    assert format_surrogate("PII", "NAME", TOKEN_ID) == f"[PII_NAME_{TOKEN_ID}]"


# --------------------------------------------------------------------------
# TOKEN_RE's match EXTENT -- the bytes the restorer deletes from the answer.
# --------------------------------------------------------------------------


@given(prose=NASTY_TEXT)
@hypothesis_settings(max_examples=500)
def test_the_hint_group_never_claims_the_models_prose(prose: str) -> None:
    """A hint is only a hint when a closing bracket follows it.

    The restorer replaces the WHOLE match span, so every character ``TOKEN_RE``
    over-claims is a character deleted from the user's answer -- silently, with
    ``restored_count`` correct and ``vault_misses`` 0. The optional group
    ``(?:\\s{0,4}\\|\\s{0,4}([a-z0-9-]{1,24}))?`` claimed a pipe and the next
    lowercase word of the model's own prose, so ``[PHI_NAME_1a2b3c4d| was
    reviewed`` restored with ``was`` gone.

    Stated as a property: whatever follows the pipe, if it is not terminated by a
    closer then no hint was consumed, and the match stops at the hash.
    """
    token = f"[PHI_NAME_{TOKEN_ID}|{prose}"
    match = TOKEN_RE.search(token)
    assert match is not None

    if match.group(4) is not None:
        # A hint was taken -- then a closer must genuinely be there.
        assert re.match(r"\s{0,4}[\]\})]", token[match.end(4) :]), token
    else:
        assert match.group(0) == f"[PHI_NAME_{TOKEN_ID}", (match.group(0), token)


#: Pipe-adjacent shapes a model emits constantly. Every one of them used to lose a
#: word; the markdown row lost a whole table cell and shifted the rest one column
#: left, so a "Note" value rendered under the "Status" header.
PIPE_SHAPES = [
    (f"[PHI_NAME_{TOKEN_ID}| and call the doctor about it]", f"[PHI_NAME_{TOKEN_ID}"),
    (f"[PHI_NAME_{TOKEN_ID}| was reviewed by Dr. Lee.", f"[PHI_NAME_{TOKEN_ID}"),
    (f"| PII_NAME_{TOKEN_ID} | active | reviewed |", f" PII_NAME_{TOKEN_ID} "),
    (f"PHI_NAME_{TOKEN_ID} | stable, discharged.", f"PHI_NAME_{TOKEN_ID} "),
    (f"[PHI_NAME_{TOKEN_ID}|note (about the case) here]", f"[PHI_NAME_{TOKEN_ID}"),
    # ...and the shapes a real hint still has to claim in full.
    (
        f"[PHI_MEDICATION_{TOKEN_ID}|oral-antidiabetic]",
        f"[PHI_MEDICATION_{TOKEN_ID}|oral-antidiabetic]",
    ),
    (
        f"[PHI_MEDICATION_{TOKEN_ID} | oral-antidiabetic]",
        f"[PHI_MEDICATION_{TOKEN_ID} | oral-antidiabetic]",
    ),
    (f"{{PHI_MEDICATION_{TOKEN_ID}|oral}}", f"{{PHI_MEDICATION_{TOKEN_ID}|oral}}"),
    (f"PHI_MEDICATION_{TOKEN_ID}|oral]", f"PHI_MEDICATION_{TOKEN_ID}|oral]"),
]


@pytest.mark.parametrize(
    ("text", "expected"), PIPE_SHAPES, ids=[case[0][:44] for case in PIPE_SHAPES]
)
def test_the_match_extent_is_exactly_the_token(text: str, expected: str) -> None:
    match = TOKEN_RE.search(text)
    assert match is not None
    assert match.group(0) == expected


def test_narrowing_the_hint_group_did_not_narrow_what_matches_at_all() -> None:
    """Existence must be untouched -- only extent. This is the safety of the change.

    ``mock_provider._is_token_free`` and several gate-adjacent checks ask
    ``TOKEN_RE.search(x) is None``. Making a token match *less text* is safe there;
    making one stop matching would silently reclassify a line as token-free. The
    hint group is optional, so a failed hint alternative always falls back to the
    empty one -- asserted here rather than reasoned about.
    """
    for suffix in ("", "|hint", "|hint]", "| prose here", "|MANGLED-HINT]", " | x |", "|"):
        for wrapper in ("[{}", "{}]", "[{}]", "{}", "{{{}}}", "({})"):
            text = wrapper.format(f"PHI_NAME_{TOKEN_ID}{suffix}")
            match = TOKEN_RE.search(text)
            assert match is not None, text
            assert match.group(3).lower() == TOKEN_ID
            assert extract_token_ids(text) == {TOKEN_ID}


# --------------------------------------------------------------------------
# Case and separator tolerance -- core requirement 6's "grammatically modified
# forms". Tolerance belongs to TOKEN_RE ONLY: every case below is also asserted
# against STRICT_TOKEN_RE, because that is the pattern the egress gate builds its
# skip-list from and anything it starts matching is outbound payload the gate
# stops re-scanning.
# --------------------------------------------------------------------------

#: Re-casings and separator whitespace a model produces, with the reason each one
#: is not exotic. Every one of these was a NO MATCH before, i.e. a token left in
#: the answer the user reads.
CASE_AND_SPACING_FORMS = [
    (f"[phi_name_{TOKEN_ID}]", "the model lower-cased the whole token"),
    (f"[Phi_Name_{TOKEN_ID}]", "title case, as in a heading"),
    (f"[PHI_NAME_{TOKEN_ID.upper()}]", "upper-cased hash -- the one case already tolerated"),
    (f"[phi_name_{TOKEN_ID.upper()}]", "both halves re-cased"),
    (f"[pHi-NaMe-{TOKEN_ID}]", "re-cased and hyphen-separated at once"),
    (f"[PHI_NAME_\n{TOKEN_ID}]", "line wrapped after the second separator"),
    (f"[PHI_NAME\n_{TOKEN_ID}]", "line wrapped before the second separator"),
    (f"[PHI\n_NAME_{TOKEN_ID}]", "line wrapped at the first separator"),
    (f"[PHI_ NAME_{TOKEN_ID}]", "a space after the first separator"),
    (f"[PHI _NAME_ {TOKEN_ID}]", "spaces on both sides of both separators"),
]


@pytest.mark.parametrize(
    ("text", "why"), CASE_AND_SPACING_FORMS, ids=[case[1] for case in CASE_AND_SPACING_FORMS]
)
def test_a_recased_or_rewrapped_token_is_matchable_and_keys_the_same_vault_row(
    text: str, why: str
) -> None:
    """A token we cannot match is a token that reaches the user (requirement 6).

    Measured before the fix, with everything else about the token intact::

        [PHI_NAME_1a2b3c4d]   -> match      [phi_name_1a2b3c4d]   -> NO match
        [PHI_NAME_1A2B3C4D]   -> match      [Phi_Name_1a2b3c4d]   -> NO match
                                            [PHI_NAME_\\n1a2b3c4d] -> NO match

    The hash was the only case-tolerant field and the two ``[_-]`` separators were
    the only places the bounded whitespace class was not allowed.

    The vault key is asserted too, not just the match: tolerating a shape whose
    group 3 came out differently would substitute the wrong entity, which is worse
    than not matching at all.
    """
    match = TOKEN_RE.search(text)
    assert match is not None, f"{why}: {text!r} does not match"
    assert match.group(0) == text, "the whole token must be claimed, not a prefix"
    assert match.group(3).lower() == TOKEN_ID
    assert extract_token_ids(text) == {TOKEN_ID}


@pytest.mark.parametrize(
    ("text", "why"), CASE_AND_SPACING_FORMS, ids=[case[1] for case in CASE_AND_SPACING_FORMS]
)
def test_the_strict_grammar_refuses_every_shape_the_tolerant_one_gained(
    text: str, why: str
) -> None:
    """STRICT_TOKEN_RE must stay exactly as narrow as ``format_surrogate``.

    ``egress_gate._own_token_mask`` builds the detector skip-list from
    ``STRICT_TOKEN_RE`` spans, so a shape added there is a span of *outbound
    payload* the gate stops re-scanning. None of the strings above is one this
    pipeline can emit -- so on that path they are uploaded-document text, and
    document text must be scanned. The emitter is asserted alongside the matcher
    because "we never emit this" is the whole justification.
    """
    assert STRICT_TOKEN_RE.fullmatch(text) is None, why
    assert STRICT_TOKEN_RE.search(text) is None, why
    assert format_surrogate("PHI", "NAME", TOKEN_ID) != text


def test_case_tolerance_stops_at_the_hint_because_the_emitter_stops_there() -> None:
    """An upper-case hint is not a shape ``format_surrogate`` can write.

    This is why the pattern is not simply compiled with ``re.IGNORECASE``: that
    flag is pattern-wide and would fold the hint group's ``[a-z0-9-]`` too. The
    module's rule is that the matcher must never out-run the emitter, and a hint
    the matcher absorbs is a hint the restorer *deletes* from the answer.
    ``[PHI_MEDICATION_2f4a1b3c|MANGLED-HINT]`` is still cleaned up, but downstream
    in ``restorer._consume_unclosed_tail`` under its five bounds -- not here.
    """
    assert HINT_RE.fullmatch("ORAL-ANTIDIABETIC") is None
    match = TOKEN_RE.search(f"[PHI_MEDICATION_{TOKEN_ID}|ORAL-ANTIDIABETIC]")
    assert match is not None
    assert match.group(4) is None, "an upper-case hint must not be absorbed"
    assert match.group(0) == f"[PHI_MEDICATION_{TOKEN_ID}"
    # The lower-case one still is -- otherwise this test would pass on a matcher
    # that had simply stopped reading hints.
    annotated = TOKEN_RE.search(f"[PHI_MEDICATION_{TOKEN_ID}|oral-antidiabetic]")
    assert annotated is not None
    assert annotated.group(4) == "oral-antidiabetic"


#: Codepoints Python's ``re.IGNORECASE`` folds onto ASCII letters. Both are legal
#: in an identifier-shaped run and both are confusable with the ASCII letter they
#: fold to, which is what makes them a bad thing to widen an audit label with.
#:
#: Built with ``chr`` rather than written literally, the same convention
#: ``restorer._RSQUO`` follows: a character confusable with ASCII must not appear
#: as itself in this source file (RUF001), least of all in the test that exists
#: because it is confusable.
UNICODE_CASE_CONFUSABLES = [chr(0x212A), chr(0x017F)]  # KELVIN SIGN, LATIN SMALL LONG S


@pytest.mark.parametrize("char", UNICODE_CASE_CONFUSABLES)
def test_case_tolerance_is_ascii_only_and_admits_no_unicode_lookalike(char: str) -> None:
    """``(?i)`` would have let U+212A into the entity type; the explicit classes do not.

    Python's ``IGNORECASE`` is Unicode case folding, so ``[A-Z]`` under it matches
    KELVIN SIGN and LATIN SMALL LETTER LONG S. The restorer copies group 2 into an
    audit row's ``entity_type``, so folding would have put a character that reads
    as ``K`` -- and is not ``K`` -- into a compliance column, for a tolerance no
    re-casing model needs. Asserted against the real folding behaviour rather than
    assumed, so the premise cannot rot.
    """
    assert re.fullmatch("[A-Z]", char, re.IGNORECASE), "premise: this really is folded by (?i)"
    assert TOKEN_RE.search(f"[PHI_NAM{char}_{TOKEN_ID}]") is None
    assert TOKEN_RE.search(f"[P{char}I_NAME_{TOKEN_ID}]") is None
    # ...and an entity type carrying one is refused at the door, as it always was.
    with pytest.raises(ConfigError):
        validate_entity_type(f"NAM{char}")


def test_widening_the_grammar_did_not_widen_the_match_extent() -> None:
    """The restorer deletes the whole match, so extent is the blast radius.

    Case tolerance and separator whitespace both live strictly *inside* the token,
    between the opening bracket and the hash, so neither can reach further into the
    model's prose than the old pattern did. Pinned on the two shapes where an
    over-reach would be invisible: a markdown table row and a sentence.
    """
    row = f"| pii_name_{TOKEN_ID} | active | reviewed |"
    match = TOKEN_RE.search(row)
    assert match is not None
    assert match.group(0) == f" pii_name_{TOKEN_ID} ", match.group(0)

    prose = f"phi-name-{TOKEN_ID} was reviewed by Dr. Lee."
    match = TOKEN_RE.search(prose)
    assert match is not None
    assert match.group(0) == f"phi-name-{TOKEN_ID} ", match.group(0)


# --------------------------------------------------------------------------
# Bounds -- every quantifier here is a security property (module docstring).
# --------------------------------------------------------------------------


def test_every_quantifier_in_the_shipped_patterns_is_bounded() -> None:
    """No ``*``, ``+`` or open ``{n,}`` outside a character class, in any pattern.

    A payload of 128 000 spaces took 94 seconds in one ``TOKEN_RE.search`` before
    the bounds went in, and the pattern runs on the raw LLM response. This asserts
    the property structurally rather than trusting that nobody re-adds a ``\\s*``.
    """
    # `{m,n}` and `{n}` are fine; `{n,}` is not. `?` is bounded by definition.
    unbounded = re.compile(r"(?<!\\)[*+]|\{\d+,\}")
    for pattern in (TOKEN_RE, STRICT_TOKEN_RE, ENTITY_TYPE_RE, HINT_RE, REDACTION_RE):
        # Strip character classes: `[^\s]*` inside a class body is a literal.
        source = re.sub(r"\[(?:\\.|[^\]\\])*\]", "C", pattern.pattern)
        assert unbounded.search(source) is None, (pattern.pattern, source)


@pytest.mark.parametrize("size", [1_000, 32_000])
def test_the_matcher_does_not_blow_up_on_a_long_whitespace_run(size: int) -> None:
    """The DoS regression, kept as a test rather than as a comment.

    Quadratic backtracking here is reachable from an ordinary document upload, so
    the bound is checked by timing the shape that triggered it.
    """
    import time

    haystack = " " * size + f"[PHI_NAME_{TOKEN_ID}]"
    started = time.perf_counter()
    assert TOKEN_RE.search(haystack) is not None
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    assert elapsed_ms < 200.0, f"{elapsed_ms:.0f} ms over {size:,} spaces"


@pytest.mark.parametrize("size", [1_000, 32_000, 128_000])
def test_the_new_separator_whitespace_is_bounded_like_every_other_run(size: int) -> None:
    """The separators gained a ``\\s{0,4}`` on each side; that is two more entry points.

    Same denial of service, one field to the right: the run that cost 94 seconds
    sat in front of the category, and whitespace was not permitted at the
    separators at all until re-wrapped tokens had to restore. Timed at the size
    that produced the original 94 s, which the structural bounds test cannot
    observe -- it reads the pattern, not the clock. Measured after the change:
    23 ms for a 128 000-character run inside the token, 23 ms in front of it.
    """
    import time

    inside = f"[PHI_{' ' * size}NAME_{TOKEN_ID}]"
    started = time.perf_counter()
    TOKEN_RE.search(inside)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    assert elapsed_ms < 200.0, f"{elapsed_ms:.0f} ms over {size:,} spaces at a separator"

    # The run is past the four-character bound, so the token does NOT match -- the
    # cost of the bound, stated exactly, the same way the restorer's tests state it.
    if size > 4:
        assert TOKEN_RE.search(inside) is None


def test_the_hint_bound_matches_what_the_emitter_can_produce() -> None:
    """Matcher tolerance must never exceed emitter capability.

    An unbounded hint alphabet covers an SSN, an EIN and a phone number, so
    ``[PHI_NAME_deadbeef|123-45-6789]`` matched as one token -- and while the gate
    still skipped detector hits inside a ``TOKEN_RE`` span, that skipped the SSN.
    """
    longest = "a" * MAX_HINT_LEN
    assert HINT_RE.fullmatch(longest)
    assert HINT_RE.fullmatch(longest + "a") is None

    emitted = format_surrogate("PHI", "NAME", TOKEN_ID, longest)
    assert emitted == f"[PHI_NAME_{TOKEN_ID}|{longest}]"
    match = TOKEN_RE.search(f"[PHI_NAME_{TOKEN_ID}|{longest}a]")
    assert match is not None
    # One character past the bound: the matcher stops, it does not stretch.
    assert match.group(4) is None


def test_the_entity_type_bound_matches_what_the_emitter_can_produce() -> None:
    widest = "A" + "B" * (MAX_ENTITY_TYPE_LEN - 1)
    assert validate_entity_type(widest) == widest
    with pytest.raises(ConfigError):
        validate_entity_type(widest + "C")

    surrogate = format_surrogate("LEGAL", widest, TOKEN_ID)
    assert STRICT_TOKEN_RE.fullmatch(surrogate)
    assert TOKEN_RE.search(surrogate)


# --------------------------------------------------------------------------
# Categories and the rest of the surface
# --------------------------------------------------------------------------


@pytest.mark.parametrize("category", CATEGORIES)
def test_every_declared_category_round_trips(category: str) -> None:
    """``CATEGORIES`` is interpolated into two patterns; all four must survive both."""
    surrogate = format_surrogate(category, "NAME", TOKEN_ID)
    match = TOKEN_RE.search(surrogate)
    assert match is not None
    assert match.group(1) == category
    assert STRICT_TOKEN_RE.fullmatch(surrogate)


@given(category=st.text(max_size=6))
@hypothesis_settings(max_examples=200)
def test_an_undeclared_category_is_rejected(category: str) -> None:
    assume(category not in CATEGORIES)
    with pytest.raises(ConfigError) as excinfo:
        format_surrogate(category, "NAME", TOKEN_ID)
    assert excinfo.value.detail["reason"] == "unknown_surrogate_category"


@given(token_id=token_ids)
@hypothesis_settings(max_examples=200)
def test_only_a_lowercase_eight_hex_id_is_emittable(token_id: str) -> None:
    """The restorer keys on this alone, and the gate's span ends at it."""
    expected = len(token_id) == 8 and token_id == token_id.lower()
    try:
        format_surrogate("PII", "NAME", token_id)
        emitted = True
    except ConfigError:
        emitted = False
    assert emitted == expected, token_id


@given(text=NASTY_TEXT, token_id=st.just(TOKEN_ID))
@hypothesis_settings(max_examples=300)
def test_extract_token_ids_agrees_with_the_matcher_on_any_text(text: str, token_id: str) -> None:
    """``extract_token_ids`` is the vault's key source; it must not drift from ``TOKEN_RE``."""
    haystack = f"{text}[PHI_NAME_{token_id}]{text}"
    assert extract_token_ids(haystack) == {
        match.group(3).lower() for match in TOKEN_RE.finditer(haystack)
    }
    assert token_id in extract_token_ids(haystack)


def test_an_uppercase_hash_extracts_lowercased() -> None:
    """Models upper-case hashes; the vault key must not follow them."""
    assert extract_token_ids(f"[PHI_NAME_{TOKEN_ID.upper()}]") == {TOKEN_ID}


def test_a_decomposed_entity_type_is_not_silently_normalised() -> None:
    """NFD text is not ASCII uppercase, so it is rejected rather than mangled.

    Worth pinning because a "helpful" normalisation here would change the string
    the vault is keyed on relative to the string the gate protects.
    """
    decomposed = unicodedata.normalize("NFD", "NAMÉ")
    assert decomposed != "NAME"
    with pytest.raises(ConfigError):
        validate_entity_type(decomposed)
