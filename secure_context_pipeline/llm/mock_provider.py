"""Deterministic, network-free provider -- what every test and CI run uses.

Build doc sections 9.6 and 10.7.  This is not a stub: it is the adversary the
de-obfuscation restorer is graded against.  A real model does *not* echo
placeholders back character-for-character however firmly the token contract
(section 9.5.2) asks it to -- it bolds them, makes them possessive, upper-cases
the hash, drops a bracket, forgets an annotation suffix, and slips in a bare
co-reference.  So the mock does all of those, deliberately and reproducibly, and
the restorer has to survive every one.

Every response is built from two blocks, and **both always run** -- there is no
mode switch, because a real pseudonymization payload is not one shape or the
other, it is both at once:

*Tokens.*  Each distinct ``[PHI_NAME_1a2b3c4d]``-shaped surrogate in the payload
is echoed back exactly once, under a mutation class assigned round-robin so a
payload with enough tokens exercises the whole catalogue.

*Token-free excerpts.*  The most salient lines that carry no token are quoted
back verbatim.  Under pseudonymization those lines are where the Tier-1 realistic
fakes live, and quoting them is the **only** thing that gives the restorer's
surrogate pass any anchor to work from.

Running both unconditionally is a deliberate fix, not a convenience.  Branching on
"are there any tokens?" looks right and is not: a realistic pseudonymization
payload carries Tier-1 fakes *and* Tier-3 class-annotated tokens (build doc
section 9.3), so it took the token branch, the fakes were never echoed, and the
restorer's surrogate pass received zero anchors in every end-to-end run.  The
whole pseudonymization half of de-obfuscation was reachable only from unit tests
with hand-written surrogate maps.  Now one mock response exercises both passes.

Fully deterministic: no randomness, no clock, no I/O.  The same payload always
produces the same bytes.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Final

from secure_context_pipeline.config import Settings
from secure_context_pipeline.llm.base import LLMResponse, estimate_tokens, register_provider
from secure_context_pipeline.surrogates import TOKEN_RE

__all__ = [
    "COREFERENCE_SENTENCE",
    "DOC_MUTATION_CLASSES",
    "EXCERPT_HEADER",
    "MAX_ECHO_LINES",
    "MUTATION_BOLD",
    "MUTATION_BRACKET_DROPPED",
    "MUTATION_CLASSES",
    "MUTATION_HINT_STRIPPED",
    "MUTATION_POSSESSIVE",
    "MUTATION_UPPER_HASH",
    "MUTATION_VERBATIM",
    "SURROGATE_TOKEN_RE",
    "MockProvider",
    "build_response",
    "find_tokens",
    "plan_mutations",
    "render_mutation",
]

logger = logging.getLogger(__name__)

#: The surrogate shape the obfuscation engine emits: ``[CATEGORY_TYPE_hash]``
#: with an optional ``|hint`` suffix.  Real tokens carry an 8-hex-char truncated
#: HMAC (locked decision #3); 4 is accepted too so the shortened annotated example
#: the build doc uses in the token contract (``[PHI_MEDICATION_2f4a|
#: oral-antidiabetic]``) is recognised rather than silently ignored.
#:
#: That tolerance is *wider than the restorer's* on purpose, and the asymmetry is
#: the safe direction: ``surrogates.TOKEN_RE`` requires ``{8}``, so a 4-hex
#: look-alike is unmatchable there -- and unissuable, since ``format_surrogate``
#: rejects any token ID that is not 8 lowercase hex.  Recognising it here only
#: means the mock will not quote the doc's illustration back as if it were prose;
#: it must never be read as a promise that such a token restores.  Pinned by
#: ``test_the_build_docs_shortened_example_hash_cannot_be_issued``.
SURROGATE_TOKEN_RE: Final = re.compile(
    r"\[(?P<category>PII|PHI|LEGAL|FIN)_(?P<type>[A-Z][A-Z0-9_]*)_"
    r"(?P<hash>[0-9a-fA-F]{4,8})(?:\|(?P<hint>[a-z0-9\-]+))?\]"
)

MUTATION_POSSESSIVE: Final = "possessive"
MUTATION_BOLD: Final = "bold"
MUTATION_UPPER_HASH: Final = "upper_hash"
MUTATION_BRACKET_DROPPED: Final = "bracket_dropped"
MUTATION_HINT_STRIPPED: Final = "hint_stripped"
MUTATION_VERBATIM: Final = "verbatim"

#: The five grammatical mutations named in build doc section 9.6 / 10.7.
DOC_MUTATION_CLASSES: Final[tuple[str, ...]] = (
    MUTATION_POSSESSIVE,
    MUTATION_BOLD,
    MUTATION_UPPER_HASH,
    MUTATION_BRACKET_DROPPED,
    MUTATION_HINT_STRIPPED,
)

#: Everything the mock can emit.  ``verbatim`` is the un-mutated control: a real
#: model gets some tokens right, and the restorer must handle those too.
MUTATION_CLASSES: Final[tuple[str, ...]] = (*DOC_MUTATION_CLASSES, MUTATION_VERBATIM)

#: The one deliberate co-reference.  Build doc section 9.7 / README Q2: under
#: tokenization the referent was never exposed, so this is left un-restored on
#: purpose and the demo shows the honest limitation rather than hiding it.
#:
#: **Category-neutral wording, deliberately.**  This was "The patient's condition
#: remains stable." -- a clinical sentence appended to *every* answer, including
#: the ones the reviewer reads for ``fixtures/legal_memo.txt``,
#: ``fixtures/legal_brief_large.txt`` and ``fixtures/financial_disclosure.txt``.
#: Three of the four shipped fixtures are not medical records, so the closing line
#: of the restored answer described a docket filing and a brokerage statement as a
#: patient chart.  The *property* being demonstrated is what matters and it is
#: unchanged: this is a bare definite description standing in for an entity the
#: model was never shown, carrying no surrogate, so the restorer has nothing to
#: resolve and leaves it alone.  "The individual named above" is that same
#: un-restorable co-reference in prose that is true of any document category.
COREFERENCE_SENTENCE: Final = "The individual named above remains the subject of this record."

#: How many token-free input lines are quoted back verbatim.
MAX_ECHO_LINES: Final = 6

#: Introduces the quoted block, so a reader of the demo output can see which part
#: of the answer is the model's prose and which part is quoted source.
EXCERPT_HEADER: Final = "Key excerpts from the source material:"

_HEADER: Final = "Summary of the reviewed record."

#: The carrier prose each echoed token is wrapped in.  **Category-neutral, and
#: that is a correctness property of the demo rather than a style preference.**
#: These read "The intake note lists {}.", "The assessment section retains {}."
#: and "The discharge summary mentions {}." -- clinical sentences emitted for
#: every document, because the provider is handed a payload and never a
#: ``doc_category``.  Three of the four shipped fixtures are not clinical
#: (``legal_memo.txt``, ``legal_brief_large.txt``, ``financial_disclosure.txt``),
#: so the UI's panel 3 (raw model answer) and panel 4 (restored answer) -- the two
#: panels a reviewer reads as the product's output -- described a docket filing as
#: a patient chart in three runs out of four.
#:
#: Widening the provider interface to carry the category was the alternative and is
#: the wrong trade: :class:`~secure_context_pipeline.llm.base.LLMProvider` is copied
#: verbatim from build doc section 9.6 and nothing may be added to it, and a mock
#: that branches on the document class would also stop being one fixed adversary
#: for the restorer.  Wording that is true of a chart, a memo and a disclosure
#: alike costs nothing and is correct for all of them.  The mutation catalogue --
#: the thing the restorer is actually graded against -- is untouched by this.
_SENTENCE_TEMPLATES: Final[tuple[str, ...]] = (
    "The record lists {}.",
    "Correspondence in the file references {}.",
    "The summary section retains {}.",
    "Supporting documents cite {}.",
    "The closing section mentions {}.",
)

_POSSESSIVE_TEMPLATES: Final[tuple[str, ...]] = (
    "{} record was reviewed in preparing this summary.",
    "{} file remains open pending follow-up.",
)


# ---------------------------------------------------------------------------
# Token discovery and mutation
# ---------------------------------------------------------------------------


def find_tokens(text: str) -> tuple[str, ...]:
    """Every distinct surrogate token in ``text``, in order of first appearance."""
    seen: dict[str, None] = {}
    for match in SURROGATE_TOKEN_RE.finditer(text):
        seen.setdefault(match.group(0), None)
    return tuple(seen)


def _has_hint(token: str) -> bool:
    match = SURROGATE_TOKEN_RE.fullmatch(token)
    return match is not None and match.group("hint") is not None


def plan_mutations(payload: str) -> tuple[tuple[str, str], ...]:
    """Assign a mutation class to every token in ``payload``.

    Pure and deterministic, and exported so tests can assert catalogue coverage
    against :data:`MUTATION_CLASSES` without re-deriving the mock's internals.

    ``hint_stripped`` needs an annotated token, so the first one found is
    reserved for it; the rest cycle through the remaining classes in
    :data:`MUTATION_CLASSES` order.
    """
    tokens = find_tokens(payload)
    if not tokens:
        return ()

    assigned: dict[int, str] = {}
    annotated = next((i for i, token in enumerate(tokens) if _has_hint(token)), None)
    if annotated is not None:
        assigned[annotated] = MUTATION_HINT_STRIPPED

    cycle = tuple(name for name in MUTATION_CLASSES if name != MUTATION_HINT_STRIPPED)
    step = 0
    for index in range(len(tokens)):
        if index in assigned:
            continue
        assigned[index] = cycle[step % len(cycle)]
        step += 1

    return tuple((token, assigned[index]) for index, token in enumerate(tokens))


def _rewrite_group(token: str, group: str, replacement: str) -> str:
    match = SURROGATE_TOKEN_RE.fullmatch(token)
    if match is None or match.group(group) is None:
        return token
    start, end = match.span(group)
    return token[:start] + replacement + token[end:]


def render_mutation(token: str, mutation: str) -> str:
    """Render ``token`` under one mutation class.

    Every form here is something the restorer's ``TOKEN_RE`` (build doc 9.7) is
    specified to tolerate: optional brackets, case-insensitive hash, optional and
    ignorable hint suffix, adjacent markdown, trailing possessive.
    """
    if mutation == MUTATION_VERBATIM:
        return token
    if mutation == MUTATION_POSSESSIVE:
        return f"{token}'s"
    if mutation == MUTATION_BOLD:
        return f"**{token}**"
    if mutation == MUTATION_UPPER_HASH:
        match = SURROGATE_TOKEN_RE.fullmatch(token)
        if match is None:
            return token
        return _rewrite_group(token, "hash", match.group("hash").upper())
    if mutation == MUTATION_BRACKET_DROPPED:
        # Both brackets, matching the mangled form the build doc's robustness
        # matrix names: `PHI_NAME_1a2b3c4d`.
        if token.startswith("[") and token.endswith("]"):
            return token[1:-1]
        return token
    if mutation == MUTATION_HINT_STRIPPED:
        match = SURROGATE_TOKEN_RE.fullmatch(token)
        if match is None or match.group("hint") is None:
            return token
        start, end = match.span("hint")
        # start - 1 is the '|' separator, which goes with the hint.
        return token[: start - 1] + token[end:]
    return token


# ---------------------------------------------------------------------------
# Response construction
# ---------------------------------------------------------------------------


def _is_token_free(line: str) -> bool:
    """Whether ``line`` carries nothing the restorer would treat as a token.

    Both grammars are consulted, and the union is the point.  This module's
    :data:`SURROGATE_TOKEN_RE` recognises the canonical emitted shape (plus the
    build doc's shortened 4-hex illustration);
    :data:`~secure_context_pipeline.surrogates.TOKEN_RE` is the tolerant grammar
    the restorer actually matches with.  "Token-free" has to mean free of
    *either*, or a line the restorer would rewrite could still be quoted verbatim.
    """
    return SURROGATE_TOKEN_RE.search(line) is None and TOKEN_RE.search(line) is None


def _salient_lines(payload: str) -> tuple[str, ...]:
    """The token-free lines a summariser would most plausibly quote back.

    Lines carrying a token are excluded, and that exclusion is load-bearing:
    tokens are already echoed exactly once each under an assigned mutation, and
    quoting a token line verbatim would slip an *un-mutated* second copy into the
    answer -- silently weakening the mutation coverage the restorer is graded
    against, since a verbatim token restores whether or not the mangled forms do.

    Longest first (that is where names, addresses and account numbers live),
    tie-broken by position so the result is stable, then re-ordered back into
    document order for readability.  Lines already containing the co-reference
    sentence are skipped so the mock keeps emitting it exactly once.
    """
    candidates = [
        (index, stripped)
        for index, line in enumerate(payload.splitlines())
        if (stripped := line.strip())
        and COREFERENCE_SENTENCE not in line
        and _is_token_free(line)
    ]
    ranked = sorted(candidates, key=lambda item: (-len(item[1]), item[0]))
    chosen = sorted(ranked[:MAX_ECHO_LINES], key=lambda item: item[0])
    return tuple(line for _, line in chosen)


def build_response(user_payload: str) -> str:
    """The mock's whole answer for ``user_payload``. Pure and deterministic.

    Both blocks run unconditionally -- see the module docstring for why branching
    on "does this payload contain tokens?" left the restorer's surrogate pass
    without a single end-to-end anchor.
    """
    lines: list[str] = [_HEADER, ""]

    for index, (token, mutation) in enumerate(plan_mutations(user_payload)):
        rendered = render_mutation(token, mutation)
        if mutation == MUTATION_POSSESSIVE:
            template = _POSSESSIVE_TEMPLATES[index % len(_POSSESSIVE_TEMPLATES)]
        else:
            template = _SENTENCE_TEMPLATES[index % len(_SENTENCE_TEMPLATES)]
        lines.append(f"- {template.format(rendered)}")

    # Quoted verbatim: under pseudonymization these lines carry the Tier-1 fakes,
    # and the restorer's surrogate pass has nothing to anchor on without them.
    # Safe to echo by construction -- every one of them is a slice of a payload
    # the EgressGate already certified free of originals.
    excerpts = _salient_lines(user_payload)
    if excerpts:
        lines.append("")
        lines.append(EXCERPT_HEADER)
        lines.extend(f"- {line}" for line in excerpts)

    lines.extend(["", COREFERENCE_SENTENCE])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


@register_provider("mock")
class MockProvider:
    """Deterministic provider. No network, no randomness, no clock."""

    name: str = "mock"

    def __init__(self, settings: Settings | None = None) -> None:
        # ``settings`` is accepted so the class satisfies the registry's factory
        # signature; the mock has nothing to configure.
        self._settings = settings

    async def complete(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> str:
        response = await self.complete_detailed(
            system, user, model=model, timeout_s=timeout_s
        )
        return response.text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        await asyncio.sleep(0)  # a real yield point, so callers exercise the await path
        text = build_response(user)
        response = LLMResponse(
            text=text,
            input_tokens=estimate_tokens(system) + estimate_tokens(user),
            output_tokens=estimate_tokens(text),
            model=model,
        )
        logger.info(
            "LLM_CALL provider=%s model=%s input_tokens=%d output_tokens=%d tokens_echoed=%d",
            self.name,
            model,
            response.input_tokens,
            response.output_tokens,
            len(find_tokens(user)),
        )
        return response
