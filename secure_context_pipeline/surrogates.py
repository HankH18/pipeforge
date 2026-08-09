"""The surrogate/token grammar -- one authoritative definition.

Three components need to agree on exactly what a token looks like: the
tokenization strategy that *emits* them, the restorer that *matches* them back,
and the egress gate that *skips* them during its detector re-scan. Defining the
grammar in one place is what keeps those three from drifting apart.

Canonical emitted form (build doc section 9.3)::

    [PHI_NAME_1a2b3c4d]                       plain
    [PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]   Tier-3, class-annotated

``TOKEN_RE`` is deliberately *tolerant* (build doc section 9.7): an LLM will mangle
tokens, and a token we fail to match is a token that reaches the user un-restored.
It accepts wrong or missing brackets, stray whitespace **anywhere inside the
token**, and any casing of the category, the entity type and the hash.
Restore keys on the 8-hex hash alone, so a dropped or corrupted hint still restores.

**Tolerance is one-way: ``TOKEN_RE`` is tolerant, ``STRICT_TOKEN_RE`` is not.**
The two were both once case-sensitive outside the hash, and the cost was measured
directly::

    [PHI_NAME_1a2b3c4d] -> match      [phi_name_1a2b3c4d] -> NO match
    [PHI_NAME_1A2B3C4D] -> match      [Phi_Name_1a2b3c4d] -> NO match
    [PHI_NAME_1a2b3c4d] -> match      [PHI_NAME_\n1a2b3c4d] -> NO match

Lower-casing a token, title-casing it, or wrapping a line at one of its two
separators are all "paraphrased or grammatically modified forms" in the sense of
core requirement 6, and each of those three left the token in the answer the user
reads -- the outcome the rubric names separately as "no tokens leak to the user".
``TOKEN_RE`` now accepts all of them (:func:`_any_case`, :data:`_SEPARATOR`).

``STRICT_TOKEN_RE`` stays exactly as narrow as :func:`format_surrogate`, and
widening it in sympathy would be a *security* change rather than a tolerance one:
the egress gate builds its detector skip-list from ``STRICT_TOKEN_RE`` spans
(``egress_gate._own_token_mask``), so every shape added to it is a span of outbound
payload the gate stops re-scanning. ``phi_name_1a2b3c4d`` is not a string this
pipeline can emit, so it is document text, and document text must be scanned.
The same asymmetry is why the hint group is *not* case-folded: an upper-case hint
is not a shape :func:`format_surrogate` can write either.

**Every quantifier here is bounded, and that is a security property, not style.**
``TOKEN_RE`` runs on fully untrusted text -- the raw LLM response, in
:mod:`~secure_context_pipeline.deobfuscation.restorer` -- and its *match extent*
decides which characters the restorer deletes from the user's answer. Three
things follow, and each one was a real defect:

* An unbounded ``\\s*``/``[A-Z0-9_]*`` gives quadratic backtracking. A payload of
  128 000 spaces took **94 seconds** in one ``TOKEN_RE.search`` before these bounds
  were added -- a denial of service reachable from an ordinary document upload.
* An unbounded hint group was a *confidentiality* hole while the egress gate still
  skipped detector hits inside a ``TOKEN_RE`` span: the hint alphabet
  ``[a-z0-9-]`` covers an SSN (``123-45-6789``), an EIN, and a phone number, so
  ``[PHI_NAME_deadbeef|123-45-6789]`` matched as one token and the gate skipped the
  SSN inside it. The gate now builds its skip-list from :data:`STRICT_TOKEN_RE` and
  stops at ``end(3)`` -- the hash -- so no hint is protected there any more; the
  bound stays because a matcher must never out-run what :func:`format_surrogate`
  can emit.
* **A hint is only recognised when a closing bracket follows it.** Without that
  guard the group ``(?:\\s{0,4}\\|\\s{0,4}([a-z0-9-]{1,24}))?`` absorbed a pipe and
  the next lowercase word of the model's *own prose* into the match, and the
  restorer replaces the whole match span -- so ``[PHI_NAME_1a2b3c4d| was reviewed``
  restored with ``was`` deleted, and an ordinary markdown row
  ``| PII_NAME_3328d30c | active | reviewed |`` lost its ``active`` cell and shifted
  every later cell one column left. The user cannot see a word that is not there.
  A hint the model mangled past recognition is handled downstream by
  ``restorer._consume_unclosed_tail``, under the same four guards; the matcher must
  never be *more* permissive than the mop-up that cleans up after it.

**The validators are anchored with ``\\A``/``\\Z``, never ``^``/``$``.** ``$``
matches before a trailing newline, so ``ENTITY_TYPE_RE.match("NAME\\n")`` succeeded
and :func:`format_surrogate` emitted ``[PII_NAME\\n_deadbeef]`` -- a string neither
:data:`TOKEN_RE` nor :data:`STRICT_TOKEN_RE` matches, i.e. unrestorable *and*
absent from the gate's skip-list, the exact outcome these validators exist to
prevent. ``load_registry`` accepts an ``entities.yaml`` whose entity key carries a
trailing newline, so this was reachable from config alone. Both formatters now also
check their own output against the matcher that has to read it back
(:func:`_emitted`), because an anchor is a claim about a regex and the backstop is
a claim about the string.
"""

from __future__ import annotations

import re

from secure_context_pipeline.errors import ConfigError

__all__ = [
    "CATEGORIES",
    "ENTITY_TYPE_RE",
    "HINT_RE",
    "MAX_ENTITY_TYPE_LEN",
    "MAX_HINT_LEN",
    "REDACTION_RE",
    "STRICT_TOKEN_RE",
    "TOKEN_RE",
    "extract_token_ids",
    "format_redaction",
    "format_surrogate",
    "validate_entity_type",
]

CATEGORIES = ("PII", "PHI", "LEGAL", "FIN")

MAX_ENTITY_TYPE_LEN = 64
MAX_HINT_LEN = 24
# Stray whitespace an LLM might insert inside a token. Bounded so the leading
# `\s{0,N}` cannot be walked O(n) times from every offset of a whitespace run.
_MAX_TOKEN_WS = 4

_CATEGORY_ALT = "|".join(CATEGORIES)
_TYPE_BODY = f"[A-Z][A-Z0-9_]{{0,{MAX_ENTITY_TYPE_LEN - 1}}}"
_WS = f"\\s{{0,{_MAX_TOKEN_WS}}}"

#: The grammar an ``entity_type`` must satisfy to be *expressible* as a surrogate.
#: Entity types are opaque config strings (build doc section 6.2), so a registry
#: entry like ``2FA_CODE`` or ``MedicalId`` would otherwise emit a token that
#: :data:`TOKEN_RE` cannot match -- unrestorable *and* invisible to the egress
#: gate's skip-list. Fail loudly instead.
#:
#: Anchored ``\A``/``\Z`` rather than ``^``/``$`` so that a trailing newline is
#: rejected however the caller invokes it -- ``.match``, ``.search`` or
#: ``.fullmatch``. See the module docstring.
ENTITY_TYPE_RE = re.compile(rf"\A{_TYPE_BODY}\Z")

#: The closers a hint must be followed by to be read as a hint at all. Written as
#: its own constant because the *whole* discriminator between "an annotated token"
#: and "a pipe in the model's prose" is whether one of these characters comes next.
_CLOSER_CLASS = r"[\]\}\)]"


def _any_case(literal: str) -> str:
    """``PHI`` -> ``[Pp][Hh][Ii]``: a literal the *matcher* reads in any casing.

    Written out per character rather than by compiling :data:`TOKEN_RE` with
    ``re.IGNORECASE``, and the difference is not stylistic:

    * ``re.IGNORECASE`` is pattern-wide, so it would also fold the hint group's
      ``[a-z0-9-]`` -- and the module docstring's rule is that the matcher must
      never out-run what :func:`format_surrogate` can emit. ``HINT_RE`` is
      lowercase-only, so an upper-case hint is not a shape we can have written.
    * Python's ``IGNORECASE`` is *Unicode* case folding, so ``[A-Z]`` would begin
      matching U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S. Those
      characters would then travel into the entity-type label the restorer copies
      into an audit row, which is a confusable-lookalike in a compliance column
      for no tolerance gained -- a model that re-cases a token types ASCII.

    A scoped ``(?i:...)`` group fixes the first problem and not the second.
    """
    return "".join(f"[{char.upper()}{char.lower()}]" for char in literal)


#: The category and entity-type literals as the *matcher* accepts them: ASCII, in
#: any casing. ``[phi_name_1a2b3c4d]`` and ``[Phi_Name_1a2b3c4d]`` did not match at
#: all before this, so a model that lower-cased or title-cased a token -- an
#: ordinary "grammatically modified form" (core requirement 6) -- left the token
#: un-restored and visible to the user. Only the 8-hex hash was case-tolerant.
_CATEGORY_ALT_ANY_CASE = "|".join(_any_case(category) for category in CATEGORIES)
_TYPE_BODY_ANY_CASE = f"[A-Za-z][A-Za-z0-9_]{{0,{MAX_ENTITY_TYPE_LEN - 1}}}"

#: ``_`` or ``-``, with the same bounded whitespace class allowed on either side.
#: The class was already permitted after the opening bracket, around the pipe and
#: before the closer, but not here -- so a token a model wrapped across a line at a
#: separator (``[PHI_NAME_\n1a2b3c4d]``) did not match and reached the user whole.
#: Bounded for the reason every quantifier in this module is bounded; see the
#: module docstring.
_SEPARATOR = f"{_WS}[_\\-]{_WS}"

# Tolerant matcher -- see module docstring. Groups: (category, entity_type, hash, hint)
#
# The hint group ends in `(?={_CLOSER_CLASS})`: a lookahead, so the closer stays
# available to the trailing optional-closer term and the match extent is unchanged
# for every well-formed token. Making the hint conditional this way is what stops
# the group from eating the model's prose (module docstring, third bullet) while
# leaving match *existence* untouched -- the group is optional, so nothing that
# matched before stops matching; only over-long matches get shorter.
#
# Groups 1 and 2 are case-*tolerant*, which makes them case-*unreliable*: a caller
# that copies either into a label must upper-case it, or one entity produces two
# spellings of the same audit row depending on how the model typed it. See
# `restorer._restore_tokens`, the only caller that does.
TOKEN_RE = re.compile(
    rf"[\[\{{\(]?{_WS}({_CATEGORY_ALT_ANY_CASE}){_SEPARATOR}({_TYPE_BODY_ANY_CASE})"
    rf"{_SEPARATOR}([0-9a-fA-F]{{8}})"
    rf"(?:{_WS}\|{_WS}([a-z0-9\-]{{1,{MAX_HINT_LEN}}}){_WS}(?={_CLOSER_CLASS}))?"
    rf"{_WS}{_CLOSER_CLASS}?"
)

# Exactly what we emit -- used to assert our own output shape, never to match LLM text.
STRICT_TOKEN_RE = re.compile(
    rf"\[({_CATEGORY_ALT})_({_TYPE_BODY})_([0-9a-f]{{8}})"
    rf"(?:\|([a-z0-9\-]{{1,{MAX_HINT_LEN}}}))?\]"
)

HINT_RE = re.compile(rf"\A[a-z0-9\-]{{1,{MAX_HINT_LEN}}}\Z")

REDACTION_RE = re.compile(rf"\[REDACTED_({_TYPE_BODY})\]")

# `derive_token_id` returns `hexdigest()[:8]` -- always lowercase, always 8 chars.
_TOKEN_ID_RE = re.compile(r"\A[0-9a-f]{8}\Z")


def _emitted(marker: str, matcher: re.Pattern[str], reason: str) -> str:
    """Return ``marker`` once the matcher that must read it back accepts it whole.

    The validators above are claims about a *regex*; this is a claim about the
    *string*, checked on the one path that puts markers into a document. They are
    not the same claim, and the gap between them was a live hole: ``$`` matches
    before a trailing newline, so every validator passed while the emitted marker
    was unmatchable by :data:`TOKEN_RE` -- and therefore unrestorable, and absent
    from the egress gate's skip-list. Anchoring the validators closed that
    instance; this closes the *class*, because any future field, separator or
    anchor mistake shows up here as a loud ``ConfigError`` at emit time rather than
    as a token the user can never get back.

    ``fullmatch``, not ``match``: a marker with anything appended is exactly the
    failure being guarded against.
    """
    if matcher.fullmatch(marker) is None:  # pragma: no cover - emitter invariant
        raise ConfigError(reason=reason, length=len(marker))
    return marker


def validate_entity_type(entity_type: str) -> str:
    """Return ``entity_type`` if it is expressible in the surrogate grammar.

    Raises :class:`ConfigError` otherwise. Call this when *loading* the registry to
    fail at startup rather than mid-run; the formatters below call it as a
    backstop so a bad type can never silently produce an unmatchable token.

    ``fullmatch`` rather than ``match``, and belt-and-braces with the ``\\A``/``\\Z``
    anchors: ``ENTITY_TYPE_RE`` is exported, and a caller reaching for ``.match``
    on a ``^...$`` pattern is precisely how ``"NAME\\n"`` was accepted.
    """
    if not ENTITY_TYPE_RE.fullmatch(entity_type):
        raise ConfigError(
            reason="entity_type_not_in_surrogate_grammar",
            entity_type=entity_type[:MAX_ENTITY_TYPE_LEN],
        )
    return entity_type


def format_surrogate(
    category: str,
    entity_type: str,
    token_id: str,
    hint: str | None = None,
) -> str:
    """Build the canonical surrogate string.

    ``category``, ``entity_type`` and ``token_id`` are all validated, because every
    one of them sits *inside* the token: a stray ``]``, ``|`` or lowercase letter in
    any of them yields a string :data:`TOKEN_RE` cannot match, which means the token
    is never restored **and** never lands in the egress gate's skip-list.

    ``hint`` is the one field that is dropped rather than rejected -- it is
    advisory-only metadata from the gazetteer class column, so a malformed one
    degrades to a plain token instead of failing the run.
    """
    if category not in CATEGORIES:
        raise ConfigError(reason="unknown_surrogate_category", category=category[:32])
    validate_entity_type(entity_type)
    if not _TOKEN_ID_RE.fullmatch(token_id):
        raise ConfigError(reason="malformed_token_id", length=len(token_id))
    core = f"{category}_{entity_type}_{token_id}"
    if hint and HINT_RE.fullmatch(hint):
        return _emitted(f"[{core}|{hint}]", STRICT_TOKEN_RE, "emitted_token_is_unmatchable")
    return _emitted(f"[{core}]", STRICT_TOKEN_RE, "emitted_token_is_unmatchable")


def format_redaction(entity_type: str) -> str:
    """``[REDACTED_<TYPE>]`` -- irreversible by design, no vault entry.

    Held to the same emitter/matcher backstop as :func:`format_surrogate`: the
    egress gate protects a redaction marker by :data:`REDACTION_RE`, so a marker
    that regex cannot read back is a span the gate will re-scan as ordinary
    document text.
    """
    validate_entity_type(entity_type)
    return _emitted(
        f"[REDACTED_{entity_type}]", REDACTION_RE, "emitted_redaction_is_unmatchable"
    )


def extract_token_ids(text: str) -> set[str]:
    """Lowercased 8-hex token IDs present in ``text``. Restore keys on these alone."""
    return {m.group(3).lower() for m in TOKEN_RE.finditer(text)}
