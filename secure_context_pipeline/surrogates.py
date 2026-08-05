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
It accepts wrong or missing brackets, stray whitespace, and a case-mangled hash.
Restore keys on the 8-hex hash alone, so a dropped or corrupted hint still restores.

**Every quantifier here is bounded, and that is a security property, not style.**
``TOKEN_RE`` runs on two pieces of fully untrusted text -- the outbound payload
(derived from an uploaded document) and the raw LLM response -- and in the egress
gate it decides which spans are *skipped* by the detector re-scan
(``EgressGate._protected_spans``). Two things follow:

* An unbounded ``\\s*``/``[A-Z0-9_]*`` gives quadratic backtracking. A payload of
  128 000 spaces took **94 seconds** in one ``TOKEN_RE.search`` before these bounds
  were added -- a denial of service on the security centerpiece, reachable from an
  ordinary document upload.
* An unbounded hint group is a *confidentiality* hole, not just a slow one. The
  hint alphabet ``[a-z0-9-]`` covers an SSN (``123-45-6789``), an EIN, and a phone
  number, so ``[PHI_NAME_deadbeef|123-45-6789]`` matched as one token and the gate
  skipped the SSN inside it. The bound is now exactly :data:`HINT_RE`'s, so the
  matcher's tolerance can never exceed what :func:`format_surrogate` can emit.
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
ENTITY_TYPE_RE = re.compile(f"^{_TYPE_BODY}$")

# Tolerant matcher -- see module docstring. Groups: (category, entity_type, hash, hint)
TOKEN_RE = re.compile(
    rf"[\[\{{\(]?{_WS}({_CATEGORY_ALT})[_\-]({_TYPE_BODY})[_\-]([0-9a-fA-F]{{8}})"
    rf"(?:{_WS}\|{_WS}([a-z0-9\-]{{1,{MAX_HINT_LEN}}}))?{_WS}[\]\}}\)]?"
)

# Exactly what we emit -- used to assert our own output shape, never to match LLM text.
STRICT_TOKEN_RE = re.compile(
    rf"\[({_CATEGORY_ALT})_({_TYPE_BODY})_([0-9a-f]{{8}})"
    rf"(?:\|([a-z0-9\-]{{1,{MAX_HINT_LEN}}}))?\]"
)

HINT_RE = re.compile(rf"^[a-z0-9\-]{{1,{MAX_HINT_LEN}}}$")

REDACTION_RE = re.compile(rf"\[REDACTED_({_TYPE_BODY})\]")

# `derive_token_id` returns `hexdigest()[:8]` -- always lowercase, always 8 chars.
_TOKEN_ID_RE = re.compile(r"^[0-9a-f]{8}$")


def validate_entity_type(entity_type: str) -> str:
    """Return ``entity_type`` if it is expressible in the surrogate grammar.

    Raises :class:`ConfigError` otherwise. Call this when *loading* the registry to
    fail at startup rather than mid-run; the formatters below call it as a
    backstop so a bad type can never silently produce an unmatchable token.
    """
    if not ENTITY_TYPE_RE.match(entity_type):
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
    if not _TOKEN_ID_RE.match(token_id):
        raise ConfigError(reason="malformed_token_id", length=len(token_id))
    core = f"{category}_{entity_type}_{token_id}"
    if hint and HINT_RE.match(hint):
        return f"[{core}|{hint}]"
    return f"[{core}]"


def format_redaction(entity_type: str) -> str:
    """``[REDACTED_<TYPE>]`` -- irreversible by design, no vault entry."""
    validate_entity_type(entity_type)
    return f"[REDACTED_{entity_type}]"


def extract_token_ids(text: str) -> set[str]:
    """Lowercased 8-hex token IDs present in ``text``. Restore keys on these alone."""
    return {m.group(3).lower() for m in TOKEN_RE.finditer(text)}
