"""De-obfuscation -- turning the model's answer back into the user's answer.

Build doc section 9.7. This is the last stage of the pipeline and the only one
that puts original values back into a string, so two properties are load-bearing:

**Tolerance.** The LLM rewrote our tokens. It bolded them, uppercased the hash,
dropped a bracket, made one possessive, stripped or mangled a class hint. A token
we fail to match is a token that reaches the user un-restored, so matching is done
with :data:`~secure_context_pipeline.surrogates.TOKEN_RE` -- the single tolerant
grammar shared with the emitting strategy and the egress gate -- and lookup keys
on the lowercased 8-hex hash *alone*. Hints are decoration; they never participate
in a lookup, which is exactly why a dropped or mangled hint still restores.

Pseudonyms have no embedded key, so their matcher needs the same tolerance from a
different direction: a fake is an ordinary word and the only question is whether
an occurrence is *this* word rather than part of a longer one. That question is
answered by :mod:`secure_context_pipeline.textrules`, the one place the rule lives
-- see :func:`_compile_surrogate_pattern`, which also explains why a home-grown
``\\b`` here left ``_Maria Torres_`` un-restored and silent.

**Fail-loud on residue.** After restoration this module re-scans its own output
and raises :class:`~secure_context_pipeline.errors.PipelineError` if any token
grammar or any known surrogate survived. A leaked token is a bug that must never
reach a user silently. ``[UNRESOLVED_ENTITY]`` is the one legitimate residue: it
carries no category prefix and no 8-hex tail, so the token grammar cannot match
it (checked at import, below).

``issued`` is load-bearing, not decoration
------------------------------------------
The token grammar is a *shape*, not a secret, and the model's answer is derived
from a document we do not control. So a token-shaped run in the response is not
evidence that this run minted it: ``Reference: FIN-ACCOUNT-40281993`` in an
uploaded file is undetected, un-obfuscated, quoted back by the model verbatim --
and matches ``CATEGORY[_-]TYPE[_-]8hex`` exactly. Resolving it against the vault
had two outcomes, both silent and both wrong: the user's own reference code came
back as ``[UNRESOLVED_ENTITY]`` with the audit blaming the model for text the model
faithfully copied, and -- when those eight hex digits happened to equal a live
token ID -- *another document's original* was spliced into an unrelated sentence
with ``restored_count`` up, ``vault_misses`` at zero and outcome ``ok``.

So ``issued`` now gates the substitution rather than merely labelling the miss:

* an ID this run minted resolves exactly as before;
* an ID it did not, written in a **bracketed** form, is the model inventing a
  placeholder -- it degrades to ``[UNRESOLVED_ENTITY]`` and audits as
  :data:`MISS_FABRICATED`, and the vault is never asked;
* an ID it did not, written **without brackets**, is indistinguishable from
  ordinary document text and is left byte-for-byte alone. It is counted
  (``foreign_tokens``) and logged, never rewritten. Deleting a user's own
  reference code is a data-integrity failure they cannot see; a token-shaped
  string surviving verbatim is text they can read.

Omitting ``issued`` keeps the old, ungated behaviour, and honestly: every miss is
:data:`MISS_INDETERMINATE` and every token-shaped residue is fatal, because
without the set there is no way to tell ours from theirs.

Nothing this module wrote is ever re-read
-----------------------------------------
Under pseudonymization the surrogate pass runs first and splices **original
values** into the string. The token pass used to scan that result, including the
text the surrogate pass had just written, so the pipeline could manufacture a
token out of its own output: an EHR line ``Record locator: PHI-MRN-48273910``
leaves ``PHI-`` in the payload as prose, the surrogate pass restores
``MRN-48273910`` behind it, and ``PHI-MRN-48273910`` is a valid token match that
the model never wrote. The token pass is therefore handed the spans the surrogate
pass wrote and skips any match overlapping one -- overlap, not containment,
because the manufactured match straddles the seam by construction.

Two kinds of vault miss, and they are not the same incident
-----------------------------------------------------------
``[UNRESOLVED_ENTITY]`` is what the *user* sees for either, and deliberately so:
the answer degrades, it never fails, and the placeholder says nothing about the
entity behind it. But "the model invented a token we never issued" and "we issued
this token and the vault cannot give it back" are a routine model artefact and a
data-integrity incident respectively, and an operator who cannot tell them apart
cannot act on either. Pass ``issued`` -- the token IDs this run actually minted --
and every ``VAULT_MISS`` audit row carries a ``classification`` of
:data:`MISS_FABRICATED` or :data:`MISS_LOST`, the lost ones are logged at ERROR
rather than WARNING, and :class:`RestoreResult` splits them into ``fabricated``
and ``lost``. Omit it and the classification is honestly
:data:`MISS_INDETERMINATE` rather than a guess.

Untrusted input
---------------
The model response is untrusted text. Everything here is a string operation over
it: scan, slice, concatenate. Nothing is evaluated, no control flow branches on
its *content* (only on whether our own regexes matched), and no instruction
inside it is ever followed. Originals never enter a log line, an audit detail, or
an exception message -- token IDs, entity-type labels, and counts only.

Co-reference is deliberately not solved
---------------------------------------
"The patient's condition remains stable." passes through untouched, and that is
designed behaviour, not an omission (locked decision #8, sections 13.4 Q2 and 16).
Under tokenization the model paraphrased a *token*: the underlying value was never
exposed to it, so the sentence is already both safe and readable and there is
nothing to restore. Linking "the patient" back to ``[PHI_NAME_...]`` for display
enrichment is a UX feature, not a security control, and a co-reference resolver
here would add a large surface for *wrong* re-identification -- attributing the
wrong name to a pronoun is worse than leaving the pronoun alone.
"""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from collections.abc import Collection, Iterable, Mapping
from typing import NamedTuple, NoReturn, Protocol

from pydantic import BaseModel, ConfigDict

from secure_context_pipeline.audit.logger import DEOBFUSCATE, VAULT_MISS, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import PipelineError, VaultMissError
from secure_context_pipeline.models import MASK, AuditEvent
from secure_context_pipeline.surrogates import TOKEN_RE
from secure_context_pipeline.textrules import (
    LEFT_GUARD,
    RIGHT_GUARD,
    escape_ws_flexible,
    guards_left,
    guards_right,
)

logger = logging.getLogger(__name__)

__all__ = [
    "MISS_FABRICATED",
    "MISS_INDETERMINATE",
    "MISS_LOST",
    "PSEUDONYMIZATION",
    "TOKENIZATION",
    "UNRESOLVED_ENTITY",
    "RestoreResult",
    "Restorer",
    "SupportsVaultLookup",
]

#: What we splice in when a token ID is not in the vault -- the one residue the
#: post-restore assertion tolerates.
UNRESOLVED_ENTITY = "[UNRESOLVED_ENTITY]"

#: The model referred to a token this run never minted. Expected model behaviour
#: at some rate: nothing was lost, the answer merely names an entity that does not
#: exist. Logged at WARNING.
MISS_FABRICATED = "fabricated"

#: This run minted the token and the vault cannot return it. That is an integrity
#: incident -- a destroyed session, an evicted row, a cross-session lookup -- and a
#: value the user was entitled to see is gone. Logged at ERROR.
MISS_LOST = "vault_lost"

#: No ``issued`` set was supplied, so the two above cannot be told apart. Recorded
#: as its own value rather than defaulted to either: a guess in an audit row is
#: worse than an honest "not determined".
MISS_INDETERMINATE = "indeterminate"

TOKENIZATION = "tokenization"
PSEUDONYMIZATION = "pseudonymization"
_KNOWN_STRATEGIES = frozenset({TOKENIZATION, PSEUDONYMIZATION})

# Import-time invariant: the placeholder must not itself look like a token, or
# every restore with a vault miss would trip its own assertion.
if TOKEN_RE.search(UNRESOLVED_ENTITY):  # pragma: no cover - grammar invariant
    raise PipelineError(reason="unresolved_placeholder_matches_token_grammar")

# Markdown the model wraps tokens in. Longest first: '**' must be tried before
# '`' and '__' so a bold marker is never read as two separate delimiters.
_MARKDOWN_DELIMS: tuple[str, ...] = ("**", "__", "`")

#: U+2019 RIGHT SINGLE QUOTATION MARK, built with ``chr`` so that no character
#: confusable with ASCII ``'`` appears literally in this source file.
_RSQUO = chr(0x2019)

# A possessive sitting *outside* the bracket: "[PHI_NAME_1a2b3c4d]'s" must come
# back as "John Smith's". Models emit the typographic apostrophe freely, so both
# forms are recognised.
_POSSESSIVES: tuple[str, ...] = ("'s", _RSQUO + "s")

#: The suffixes a *surrogate* match may carry, longest first so ``'s`` is peeled
#: before the bare apostrophe. Wider than :data:`_POSSESSIVES` because a plural
#: possessive ("the Torres' file") is ordinary prose around a name.
_POSSESSIVE_SUFFIXES: tuple[str, ...] = ("'s", _RSQUO + "s", "'", _RSQUO)

#: Opener -> the closer that balances it. A tail is only swallowed when it ends
#: with the bracket that *matches* the one the token opened with, so a stray
#: ``)`` inside the model's prose cannot terminate a ``[``-opened token.
_BRACKET_PAIRS: dict[str, str] = {"[": "]", "{": "}", "(": ")"}
_CLOSERS = "".join(_BRACKET_PAIRS.values())

# A bracketed token whose hint the model mangled ("|MANGLED-HINT" -- the hint
# grammar is lowercase-only) leaves its closing bracket outside TOKEN_RE's match.
# This mops up that tail so the user never sees "Metformin|MANGLED-HINT]".
#
# The character class is what keeps the mop-up from eating prose. An emitted hint
# is ``HINT_RE`` -- ``[a-z0-9-]{1,24}``, never whitespace -- so a *mangled* hint is
# still a single unbroken run. Allowing spaces here would let
# ``[PHI_NAME_1a2b3c4d| and call the doctor about it]`` delete the model's own
# sentence, which is a far worse outcome than leaving a visible remnant.
_HINT_TAIL_RE = re.compile(r"[^\s\]\}\)]{0,48}")

#: One run of whitespace. Compiled once: it is used per surrogate per call, both
#: to build the matcher and to key the issued map back from a flexed match.
_WS_RUN_RE = re.compile(r"\s+")

#: Longest label copied out of untrusted text into an audit row. The type label
#: is grammar-constrained to ``[A-Z][A-Z0-9_]*`` and so can never be an entity
#: value; the cap is belt-and-braces against a pathological response.
_MAX_LABEL_LEN = 48


class SupportsVaultLookup(Protocol):
    """The slice of the session vault this module depends on (build doc section 9.4).

    Structural, not nominal, so the restorer can be exercised against a fake
    without importing the vault. The real ``SessionVault`` also exposes
    ``originals_for_session`` -- that one belongs to the EgressGate, not here.
    """

    async def get_by_token(self, session_id: str, token_id: str) -> str:
        """Original for a token ID, or raise :class:`VaultMissError`."""
        ...

    async def get_by_surrogate(self, session_id: str, surrogate: str) -> str:
        """Original for a surrogate string, or raise :class:`VaultMissError`."""
        ...


class RestoreResult(BaseModel):
    """Outcome of one restore pass.

    ``text`` holds ORIGINAL VALUES -- it is the user-facing answer. It is masked
    in ``__repr__``/``__str__`` so an accidental ``f"{result}"`` in a log line
    cannot leak it, the same convention ``Detection`` and ``TokenRecord`` follow
    in :mod:`secure_context_pipeline.models`.

    ``vault_misses`` counts *occurrences* replaced with ``[UNRESOLVED_ENTITY]``;
    ``unresolved`` lists the *distinct* token IDs behind them. A surrogate that
    could not be resolved counts toward ``vault_misses`` but never appears in
    ``unresolved``, which is token IDs only -- never an original, never a fake.

    ``fabricated`` and ``lost`` partition ``unresolved`` when the caller passed
    ``issued`` to :meth:`Restorer.restore`: IDs the run never minted versus IDs it
    did. Without ``issued`` both are empty while ``unresolved`` is not, and that
    combination *is* the :data:`MISS_INDETERMINATE` signal -- it is not a claim
    that nothing was fabricated and nothing was lost.

    Three counters exist so that a *degraded* answer is distinguishable from a
    correct one by the caller rather than only by reading this module:

    ``foreign_tokens``
        Token-shaped runs still in ``text`` whose ID this run never issued. Left
        verbatim on purpose (see the module docstring); non-zero means the answer
        contains something that looks like a token and is not one.
    ``restored_collisions``
        Token matches skipped because they overlapped a value the surrogate pass
        had just restored -- i.e. text this module wrote, not text the model did.
    ``surrogates_suspected_unrestored``
        Case- and whitespace-variant fakes that survived in the model's own prose.
        The matcher is deliberately case-sensitive (see
        :func:`_compile_surrogate_pattern`), so a shouted or re-wrapped pseudonym
        reaches the user *as the fake* with ``restored_count`` at zero and nothing
        else to distinguish it from a correct answer. This is the missing signal,
        and it is an upper bound, not a defect count: a fake drawn from ordinary
        English (``Long``, ``Brown``, ``May``) matches its lowercase common-word
        twin and is counted here. Non-zero means "look", never "fail".
    """

    model_config = ConfigDict(frozen=True)

    text: str
    strategy: str
    restored_count: int = 0
    vault_misses: int = 0
    unresolved: tuple[str, ...] = ()
    fabricated: tuple[str, ...] = ()
    lost: tuple[str, ...] = ()
    surrogate_misses: int = 0
    tokens_seen: int = 0
    surrogates_seen: int = 0
    surrogates_issued: int = 0
    surrogates_suspected_unrestored: int = 0
    foreign_tokens: int = 0
    restored_collisions: int = 0
    elapsed_ms: float = 0.0

    def __repr__(self) -> str:
        return (
            f"RestoreResult(text={MASK!r}, strategy={self.strategy!r}, "
            f"restored_count={self.restored_count}, vault_misses={self.vault_misses}, "
            f"unresolved={self.unresolved!r}, fabricated={self.fabricated!r}, "
            f"lost={self.lost!r}, surrogate_misses={self.surrogate_misses}, "
            f"tokens_seen={self.tokens_seen}, "
            f"surrogates_seen={self.surrogates_seen}, "
            f"surrogates_issued={self.surrogates_issued}, "
            f"surrogates_suspected_unrestored={self.surrogates_suspected_unrestored}, "
            f"foreign_tokens={self.foreign_tokens}, "
            f"restored_collisions={self.restored_collisions}, "
            f"elapsed_ms={self.elapsed_ms:.3f})"
        )

    __str__ = __repr__


class _TokenPass(NamedTuple):
    text: str
    restored: int
    missed: int
    unresolved: tuple[str, ...]
    #: Disjoint subsets of ``unresolved``; both empty when the caller supplied no
    #: ``issued`` set, which is :data:`MISS_INDETERMINATE`.
    fabricated: tuple[str, ...]
    lost: tuple[str, ...]
    seen: int
    #: Matches deliberately left verbatim: not issued by this run and not
    #: bracketed, so indistinguishable from the uploaded document's own text.
    foreign: int = 0
    #: Matches deliberately left verbatim because they overlapped a span the
    #: surrogate pass wrote -- text this module produced, not text the model did.
    collisions: int = 0
    #: ``protected``, re-expressed in the coordinates of ``text``. This pass never
    #: rewrites a protected span, so its bytes survive intact and only its offsets
    #: move; :meth:`Restorer._assert_no_tokens` needs them in output coordinates.
    protected: tuple[tuple[int, int], ...] = ()


class _SurrogatePass(NamedTuple):
    text: str
    restored: int
    missed: int
    seen: int
    #: Half-open ``(start, end)`` spans of ``text`` that this pass wrote, in
    #: ascending order. The residue assertion needs them -- see
    #: :meth:`Restorer._assert_no_surrogates`.
    spliced: tuple[tuple[int, int], ...]


class Restorer:
    """Re-identifies an LLM response inside one session.

    ::

        restorer = Restorer(vault=vault, settings=settings, audit=audit)
        result = await restorer.restore(session_id, response, strategy="tokenization")

    Stateless between calls and safe to share across sessions: every lookup is
    scoped by the ``session_id`` argument, and the per-call resolution cache
    lives on the stack, never on the instance -- a cache that outlived a call
    would be a cross-session leak waiting to happen.
    """

    def __init__(
        self,
        *,
        vault: SupportsVaultLookup,
        settings: Settings,
        audit: AuditLogger | None = None,
    ) -> None:
        self._vault = vault
        self._settings = settings
        self._audit = audit

    def __repr__(self) -> str:
        return (
            f"Restorer(default_strategy={self._settings.strategy!r}, "
            f"audit={self._audit is not None})"
        )

    # -- public API --------------------------------------------------------

    async def restore(
        self,
        session_id: str,
        text: str,
        *,
        strategy: str,
        surrogates: Mapping[str, str] | None = None,
        issued: Collection[str] | None = None,
        run_id: str | None = None,
    ) -> RestoreResult:
        """Restore ``text`` for ``session_id`` and verify that nothing leaked.

        ``surrogates`` maps surrogate -> original and is supplied by the caller
        from the obfuscation result; a surrogate present as a key but without a
        usable original falls back to ``vault.get_by_surrogate``. The surrogate
        pass runs whenever that map is non-empty, and the token pass *always*
        runs -- pseudonymization still emits tokens for the tiers configured that
        way (build doc section 9.3), so one response can carry both shapes.

        ``issued`` is the set of token IDs this run minted (case-insensitive). It
        classifies every vault miss, and it *gates* substitution: an ID this run
        did not mint is never resolved against the vault, and an unbracketed one is
        left byte-for-byte alone rather than rewritten. See the module docstring
        for why that is a correctness property and not a tolerance regression.
        Omitting it is supported and honest: every miss is then recorded
        :data:`MISS_INDETERMINATE` and every token-shaped residue is fatal, because
        without the set our tokens and the document's own text are the same shape.

        Raises :class:`PipelineError` if a token this run issued, or a known
        surrogate, survives the pass. Returns normally with ``[UNRESOLVED_ENTITY]``
        spliced in when a token ID is simply absent from the vault: an unknown
        token degrades the answer, it never fails the request.
        """
        started = time.perf_counter()
        if strategy not in _KNOWN_STRATEGIES:
            raise PipelineError(reason="unknown_strategy", strategy=str(strategy)[:32])

        supplied: dict[str, str] = {key: value for key, value in (surrogates or {}).items() if key}
        pattern = _compile_surrogate_pattern(supplied) if supplied else None
        minted = None if issued is None else {token_id.lower() for token_id in issued}

        working = text
        surrogate_pass = _SurrogatePass(working, 0, 0, 0, ())
        suspected = 0
        if pattern is not None:
            surrogate_pass = await self._restore_surrogates(
                session_id, working, pattern=pattern, supplied=supplied, run_id=run_id
            )
            working = surrogate_pass.text
            # Checked here, before token restoration, and against the spans this
            # pass wrote -- see _assert_no_surrogates for why that ordering is
            # the correct scope for the question "did a fake survive?".
            await self._assert_no_surrogates(
                session_id,
                working,
                pattern=pattern,
                spliced=surrogate_pass.spliced,
                strategy=strategy,
                run_id=run_id,
            )
            suspected = _count_surrogate_near_misses(
                working, supplied, spliced=surrogate_pass.spliced
            )

        token_pass = await self._restore_tokens(
            session_id,
            working,
            minted=minted,
            protected=surrogate_pass.spliced,
            run_id=run_id,
        )
        working = token_pass.text
        foreign = await self._assert_no_tokens(
            session_id,
            working,
            minted=minted,
            protected=token_pass.protected,
            strategy=strategy,
            run_id=run_id,
        )

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        result = RestoreResult(
            text=working,
            strategy=strategy,
            restored_count=token_pass.restored + surrogate_pass.restored,
            vault_misses=token_pass.missed + surrogate_pass.missed,
            unresolved=token_pass.unresolved,
            fabricated=token_pass.fabricated,
            lost=token_pass.lost,
            surrogate_misses=surrogate_pass.missed,
            tokens_seen=token_pass.seen,
            surrogates_seen=surrogate_pass.seen,
            surrogates_issued=len(supplied),
            surrogates_suspected_unrestored=suspected,
            foreign_tokens=foreign,
            restored_collisions=token_pass.collisions,
            elapsed_ms=elapsed_ms,
        )
        await self._emit(
            session_id,
            run_id=run_id,
            event_type=DEOBFUSCATE,
            detail={
                "strategy": strategy,
                "tokens_seen": result.tokens_seen,
                "surrogates_seen": result.surrogates_seen,
                "restored": result.restored_count,
                "vault_misses": result.vault_misses,
                "unresolved_ids": len(result.unresolved),
                # The classification breakdown, so a compliance query can answer
                # "did we lose anything?" without re-reading every VAULT_MISS row.
                "unresolved_fabricated": len(result.fabricated),
                "unresolved_lost": len(result.lost),
                "surrogate_misses": result.surrogate_misses,
                # Three ways an answer can be degraded without a single miss being
                # recorded. Before these, an all-caps pseudonym reached the user as
                # the fake with `outcome: ok, restored: 0, vault_misses: 0` and
                # nothing anywhere said so.
                "surrogates_issued": result.surrogates_issued,
                "surrogates_suspected_unrestored": result.surrogates_suspected_unrestored,
                "foreign_tokens": result.foreign_tokens,
                "restored_collisions": result.restored_collisions,
                "elapsed_ms": round(elapsed_ms, 3),
                "outcome": "ok",
            },
        )
        # Counts only -- never the text, never a value.
        logger.info(
            "response restored",
            extra={
                "session_id": session_id,
                "run_id": run_id,
                "strategy": strategy,
                "restored_count": result.restored_count,
                "vault_misses": result.vault_misses,
                "elapsed_ms": round(elapsed_ms, 3),
            },
        )
        return result

    # -- tokenization ------------------------------------------------------

    async def _restore_tokens(
        self,
        session_id: str,
        text: str,
        *,
        minted: set[str] | None,
        protected: tuple[tuple[int, int], ...],
        run_id: str | None,
    ) -> _TokenPass:
        """Resolve every *claimable* token, then rebuild in one left-to-right pass.

        Equivalent to replacing right-to-left, and safer: the output is assembled
        from slices of the *original* string, so an earlier splice can never
        shift a later match's offsets.

        Two filters decide what is claimable at all, and both exist because a
        ``TOKEN_RE`` match is not proof that this pipeline put those bytes there:

        ``protected``
            Half-open spans the surrogate pass wrote -- original values. A match
            *overlapping* one was manufactured out of our own output and is left
            alone. Overlap rather than containment: the manufactured match
            straddles the seam (``PHI-`` from the model, ``MRN-48273910`` from us).

        ``minted``
            The lowercased ``issued`` set, or ``None``. An ID outside it is never
            sent to the vault. Bracketed, it degrades to ``[UNRESOLVED_ENTITY]``
            (the model invented a placeholder); unbracketed, it is left verbatim,
            because that is what an uploaded document's own reference code looks
            like and destroying it is worse than showing it.
        """
        matches = list(TOKEN_RE.finditer(text))
        if not matches:
            # `protected` is handed straight back rather than dropped: no splice
            # happened, so no offset moved, and the assertion downstream must not
            # depend on this branch having been taken.
            return _TokenPass(text, 0, 0, (), (), (), 0, 0, 0, protected)

        # Widen once, up front: the claim decision is about the span that would
        # actually disappear, not about the bare regex match.
        spans = [_span_and_suffix(text, match) for match in matches]
        claimable: list[bool] = []
        collisions = 0
        foreign = 0
        for match, (span_start, span_end, _suffix) in zip(matches, spans, strict=True):
            if _overlaps(span_start, span_end, protected):
                collisions += 1
                claimable.append(False)
            elif (
                minted is not None
                and match.group(3).lower() not in minted
                and not _is_bracketed(match.group(0))
            ):
                foreign += 1
                claimable.append(False)
            else:
                claimable.append(True)

        # Resolve each distinct claimable token ID once. This cache is per call by
        # design: one that outlived the call would outlive its session scope.
        order: list[str] = []
        labels: dict[str, str] = {}
        for match, claimed in zip(matches, claimable, strict=True):
            if not claimed:
                continue
            token_id = match.group(3).lower()
            if token_id not in labels:
                labels[token_id] = f"{match.group(1)}_{match.group(2)}"[:_MAX_LABEL_LEN]
                order.append(token_id)

        resolved: dict[str, str] = {}
        unresolved: list[str] = []
        fabricated: list[str] = []
        lost: list[str] = []
        for token_id in order:
            try:
                if minted is not None and token_id not in minted:
                    # Not ours. The vault is never asked -- asking is how a
                    # coincidence became a substitution -- and the miss is a
                    # statement of fact rather than a lookup result.
                    raise VaultMissError(session_id=session_id, token_id=token_id)
                resolved[token_id] = await self._vault.get_by_token(session_id, token_id)
            except VaultMissError:
                # Spec-required path: an unknown token degrades, never crashes.
                unresolved.append(token_id)
                if minted is None:
                    classification = MISS_INDETERMINATE
                elif token_id in minted:
                    classification = MISS_LOST
                    lost.append(token_id)
                else:
                    classification = MISS_FABRICATED
                    fabricated.append(token_id)
                # `token_id` is recorded only when the ID is one we MINTED.
                #
                # The two fields are not the same risk, and treating them as one was
                # the first version of this fix. `entity_type` is `TOKEN_RE`'s groups
                # 1 and 2, which the grammar constrains to a category literal and
                # `[A-Z][A-Z0-9_]*` -- a type label, not a value -- and it is clamped
                # to `_MAX_LABEL_LEN` by the deliberate defence
                # `test_the_entity_type_label_copied_from_untrusted_text_is_bounded`
                # exists to check. `token_id` is group 3, eight characters of
                # unconstrained hex taken straight from the model's bytes, and it is
                # the one that carries a value.
                #
                # The trigger is not adversarial. An ordinary document reference the
                # model echoes, `(PHI-MRN-40281993)`, is a `TOKEN_RE` match whose
                # group 3 is eight digits of a real MRN -- and it landed in the
                # `token_id` column, in the hash chain, and in `GET /audit`. That is
                # the outcome build doc section 16 forbids unconditionally. For a
                # FABRICATED miss the ID is by definition not ours -- `minted` was
                # supplied and this ID is not in it -- so the classification is the
                # diagnosis and the ID adds nothing a reader can act on.
                #
                # INDETERMINATE deliberately keeps it, and the line is drawn there
                # rather than at "anything we cannot prove is ours" because of where
                # each case can occur. The orchestrator always supplies `issued`
                # (see `orchestrator.py`), so the shipped pipeline can only ever
                # produce LOST or FABRICATED, and the demonstrated leak is
                # FABRICATED. INDETERMINATE means a library caller opted out of
                # classification entirely, and on that path the ID is the only
                # signal the row has at all.
                ours = classification != MISS_FABRICATED
                await self._emit(
                    session_id,
                    run_id=run_id,
                    event_type=VAULT_MISS,
                    entity_type=labels[token_id],
                    token_id=token_id if ours else None,
                    detail={
                        "stage": "deobfuscate",
                        # Kept stable: it names the *observation*. `classification`
                        # names the diagnosis, which is the part that needs a
                        # human.
                        "reason": "token_not_in_vault",
                        "classification": classification,
                    },
                )
                # A lost token is a value the user was entitled to and cannot be
                # given; a fabricated one costs nothing. Same placeholder to the
                # user, different severity to whoever reads the logs.
                logger.log(
                    logging.ERROR if classification == MISS_LOST else logging.WARNING,
                    "vault miss during restore",
                    extra={
                        "session_id": session_id,
                        "run_id": run_id,
                        # Same rule as the audit row above: the process log is a
                        # channel too, and section 16 carves out no exception for it.
                        "token_id": token_id if ours else None,
                        "entity_type": labels[token_id],
                        "classification": classification,
                    },
                )

        parts: list[str] = []
        cursor = 0
        restored = 0
        missed = 0
        # (input_start, input_end, replacement_length) per committed splice, in
        # ascending order -- everything needed to move a protected span's offsets.
        edits: list[tuple[int, int, int]] = []
        for match, claimed, (span_start, span_end, possessive) in zip(
            matches, claimable, spans, strict=True
        ):
            # Not claimed -> not touched, and the cursor does not move: the bytes
            # are emitted by the next lead slice exactly as the model wrote them.
            if not claimed or span_end <= cursor:  # swallowed by the previous splice
                continue
            parts.append(text[cursor : max(span_start, cursor)])
            value = resolved.get(match.group(3).lower())
            if value is None:
                piece = UNRESOLVED_ENTITY + possessive
                missed += 1
            else:
                piece = value + possessive
                restored += 1
            parts.append(piece)
            edits.append((max(span_start, cursor), span_end, len(piece)))
            cursor = span_end
        parts.append(text[cursor:])
        return _TokenPass(
            "".join(parts),
            restored,
            missed,
            tuple(unresolved),
            tuple(fabricated),
            tuple(lost),
            len(matches),
            foreign,
            collisions,
            _shift_spans(protected, edits),
        )

    # -- pseudonymization --------------------------------------------------

    async def _restore_surrogates(
        self,
        session_id: str,
        text: str,
        *,
        pattern: re.Pattern[str],
        supplied: Mapping[str, str],
        run_id: str | None,
    ) -> _SurrogatePass:
        """Replace surrogates longest-first, carrying any possessive suffix through."""
        matches = list(pattern.finditer(text))
        if not matches:
            return _SurrogatePass(text, 0, 0, 0, ())

        # The surrogate/possessive split is computed once per match and reused by
        # both loops below, so the two can never disagree about where the
        # surrogate ended.
        canonical = _canonical_by_shape(supplied)
        split = [
            _split_surrogate_match(match.group(0), supplied, canonical) for match in matches
        ]

        resolved: dict[str, str] = {}
        missing: set[str] = set()
        for surrogate, _possessive in split:
            if surrogate in resolved or surrogate in missing:
                continue
            original = supplied.get(surrogate)
            if original:
                resolved[surrogate] = original
                continue
            try:
                resolved[surrogate] = await self._vault.get_by_surrogate(session_id, surrogate)
            except VaultMissError:
                missing.add(surrogate)
                # There is no token ID for a surrogate-only miss, and the
                # surrogate itself never enters the audit row.
                #
                # Unlike a token miss this one needs no `issued` set to classify.
                # The alternation is compiled from `supplied`, i.e. from what this
                # run handed out, so a surrogate can only be matched here if the
                # run issued it: the model cannot fabricate its way into this
                # branch, and a miss is always the vault failing to return
                # something we minted.
                await self._emit(
                    session_id,
                    run_id=run_id,
                    event_type=VAULT_MISS,
                    detail={
                        "stage": "deobfuscate",
                        "reason": "surrogate_not_in_vault",
                        "classification": MISS_LOST,
                    },
                )
                logger.error(
                    "vault miss during restore",
                    extra={
                        "session_id": session_id,
                        "run_id": run_id,
                        "token_id": None,
                        "classification": MISS_LOST,
                    },
                )

        parts: list[str] = []
        spliced: list[tuple[int, int]] = []
        cursor = 0
        written = 0
        restored = 0
        missed = 0
        for match, (surrogate, possessive) in zip(matches, split, strict=True):
            lead = text[cursor : match.start()]
            parts.append(lead)
            written += len(lead)

            value = resolved.get(surrogate)
            if value is None:
                piece = UNRESOLVED_ENTITY + possessive
                missed += 1
            else:
                piece = value + possessive
                restored += 1
            parts.append(piece)
            spliced.append((written, written + len(piece)))
            written += len(piece)
            cursor = match.end()
        parts.append(text[cursor:])
        return _SurrogatePass("".join(parts), restored, missed, len(matches), tuple(spliced))

    # -- post-restore assertions ------------------------------------------

    async def _assert_no_tokens(
        self,
        session_id: str,
        text: str,
        *,
        minted: set[str] | None,
        protected: tuple[tuple[int, int], ...],
        strategy: str,
        run_id: str | None,
    ) -> int:
        """In-code guarantee: no token **this run issued** reaches the user.

        Scanned with the same matcher used to restore, so detection and
        verification cannot drift apart. Nothing is excluded by *position* -- not
        even text that came out of the vault -- but the scan is scoped by
        ``minted``, and that scoping is a correction, not a relaxation.

        The previous wording of this docstring claimed "the token grammar is a
        synthetic high-entropy shape (``CATEGORY_TYPE_8hex``) that a real entity
        value cannot accidentally take". That is false, and cheaply so::

            TOKEN_RE.search("FIN_ACCOUNT_12345678")   # matches

        Any category literal in the document's own prose in front of an eight-hex
        run does it -- an account reference, an EHR record locator ``PHI-MRN-
        48273910``, a docket number. Treating those as leaks failed correct runs
        *after* the provider had already been called and billed, and (before
        :meth:`_fail` stopped copying bytes) wrote eight characters of the
        patient's own MRN into the 500 body and into ``GET /audit``.

        So the question the assertion actually asks is the one that matters: did a
        token **we minted** survive un-restored? Those are the only strings with a
        vault row behind them and therefore the only ones whose survival is a
        failure of this stage. Token-shaped residue we did not mint is counted and
        logged, and the count is returned so it reaches the caller and the audit
        row rather than dying here. With no ``issued`` set the old, stricter rule
        stands unchanged -- ours and theirs are indistinguishable without it, so
        every occurrence is fatal.

        ``protected`` excuses a residue lying **wholly inside** a value the
        surrogate pass restored -- the same scope and the same reason as
        :meth:`_assert_no_surrogates`: those bytes are the answer, not residue.
        Note the deliberate asymmetry with :meth:`_restore_tokens`, which excludes
        on *overlap*. Rewriting is the destructive act, so the pass is generous
        about what it refuses to touch; excusing is the permissive one, so the
        assertion is strict about what it lets go. A residue merely *touching* a
        restored value is still reported.

        ``[UNRESOLVED_ENTITY]`` is inert against the grammar (checked at import),
        so a legitimate vault miss does not trip this.
        """
        # Containment is tested on the *core* -- ``start(1)`` (category) through
        # ``end(3)`` (hash) -- not on the whole match. Both brackets and both
        # whitespace runs are optional and greedy, so a match around a restored
        # value routinely reaches one character past it on each side; testing the
        # raw span would excuse nothing and the exclusion would be dead code. The
        # core is the part that identifies a token, and it is still the model's
        # prose that has to supply anything outside a restored value for a
        # straddling residue (``PHI-`` + ``MRN-48273910``) to stay reported.
        residues = [
            match
            for match in TOKEN_RE.finditer(text)
            if not any(
                start <= match.start(1) and match.end(3) <= end for start, end in protected
            )
        ]
        if not residues:
            return 0
        if minted is None:
            await self._fail(
                session_id,
                run_id=run_id,
                strategy=strategy,
                reason="residual_token_after_restore",
                count=len(residues),
            )
        ours = [match for match in residues if match.group(3).lower() in minted]
        if ours:
            await self._fail(
                session_id,
                run_id=run_id,
                strategy=strategy,
                reason="residual_token_after_restore",
                count=len(ours),
            )
        foreign = len(residues) - len(ours)
        if foreign:
            # Not fatal and not silent. Counts and a shape, never the bytes: the
            # residue is by definition text we could not account for.
            logger.warning(
                "token-shaped text this run never issued survived restoration",
                extra={
                    "session_id": session_id,
                    "run_id": run_id,
                    "strategy": strategy,
                    "foreign_tokens": foreign,
                },
            )
        return foreign

    async def _assert_no_surrogates(
        self,
        session_id: str,
        text: str,
        *,
        pattern: re.Pattern[str],
        spliced: tuple[tuple[int, int], ...],
        strategy: str,
        run_id: str | None,
    ) -> None:
        """Assert no known surrogate survived in text the *model* wrote.

        Matches falling wholly inside a span this pass spliced in are skipped,
        and that exclusion is the whole subtlety. Surrogates are realistic fakes
        drawn from the same name space as the originals, so a restored original
        ("Maria Torres") can legitimately contain another entity's fake
        ("Torres") as a word. Flagging that would fail a run that was in fact
        perfectly restored. What the assertion is actually asking is narrower and
        correct: did any fake survive in the model's own prose? The token
        assertion needs no such exclusion (see :meth:`_assert_no_tokens`).

        Both lists are in ascending order, so one linear walk covers them.
        """
        index = 0
        for match in pattern.finditer(text):
            while index < len(spliced) and spliced[index][1] <= match.start():
                index += 1
            if index < len(spliced):
                start, end = spliced[index]
                if start <= match.start() and match.end() <= end:
                    continue
            await self._fail(
                session_id,
                run_id=run_id,
                strategy=strategy,
                reason="residual_surrogate_after_restore",
                count=len(pattern.findall(text)),
            )

    async def _fail(
        self,
        session_id: str,
        *,
        run_id: str | None,
        strategy: str,
        reason: str,
        count: int,
    ) -> NoReturn:
        """Audit the violation, then raise. A count and a reason -- nothing else.

        This used to copy ``residue.group(3)`` into ``detail['sample_token_id']``
        and into the exception, under a docstring claiming it "never carries the
        offending text". It did. When the residue was manufactured out of a value
        the restorer had just put back -- the document's own ``PHI-`` in front of a
        restored ``MRN-40281993`` -- those eight characters were eight digits of a
        patient's MRN, and they travelled into the HTTP 500 body and into
        ``GET /audit``, whose schema documents itself as safe to hand a compliance
        reader. Build doc section 16 forbids embedding an original entity value in
        any exception or log, including debug paths.

        The residue is, by construction, text this stage could not account for.
        That is exactly the text no sampling rule can promise is safe, so nothing
        is sampled. If a sample is ever wanted for triage, hash it with a salt --
        do not carry the bytes.
        """
        detail: dict[str, int | float | str] = {
            "strategy": strategy,
            "outcome": "assertion_failed",
            "reason": reason,
            "residual": count,
        }
        await self._emit(session_id, run_id=run_id, event_type=DEOBFUSCATE, detail=detail)
        logger.error(
            "post-restore assertion failed",
            extra={
                "session_id": session_id,
                "run_id": run_id,
                "reason": reason,
                "residual": count,
            },
        )
        raise PipelineError(
            reason=reason,
            session_id=session_id[:_MAX_LABEL_LEN],
            run_id=None if run_id is None else run_id[:_MAX_LABEL_LEN],
            strategy=strategy,
            residual=count,
        )

    # -- audit -------------------------------------------------------------

    async def _emit(
        self,
        session_id: str,
        *,
        run_id: str | None,
        event_type: str,
        detail: Mapping[str, int | float | str],
        entity_type: str | None = None,
        token_id: str | None = None,
    ) -> None:
        if self._audit is None:
            return
        await self._audit.emit(
            AuditEvent(
                ts=time.time(),
                session_id=session_id,
                run_id=run_id,
                event_type=event_type,
                entity_type=entity_type,
                token_id=token_id,
                detail=dict(detail),
            )
        )


# --------------------------------------------------------------------------
# Matching helpers -- pure string/regex work over untrusted text.
# --------------------------------------------------------------------------


def _span_and_suffix(text: str, match: re.Match[str]) -> tuple[int, int, str]:
    """Widen a token match to the span that should disappear, plus its possessive.

    Returns ``(start, end, possessive)`` where ``text[start:end]`` is everything
    to replace -- the token, the markdown hugging it, a mangled hint tail -- and
    ``possessive`` is the suffix to re-append to the restored value.

    Markdown is stripped only where it is *mirrored* -- and in both directions.
    ``**[TOKEN]**`` collapses cleanly, but a lone ``[TOKEN]**`` keeps its ``**``
    (that one closes emphasis opened earlier in the sentence) and, symmetrically,
    a lone ``**[TOKEN]`` keeps its ``**`` (that one opens emphasis closed later:
    ``**[TOKEN] is stable**``). Eating either half would leave the user an
    unbalanced delimiter -- exactly the orphan the stripping exists to prevent --
    so the leftward walk is only a *proposal*, committed one delimiter at a time
    against what is actually mirrored on the right.
    """
    matched = match.group(0)
    end = _consume_unclosed_tail(text, match)

    # Both brackets in TOKEN_RE are optional and both are hugged by a greedy
    # ``\s*``, so an *unbracketed* token absorbs the spaces on either side of it
    # ("lists PHI_NAME_1a2b3c4d today"). Hand that whitespace back, or the
    # restored words run together with their neighbours.
    start = match.start() + (len(matched) - len(matched.lstrip()))
    if end == match.end():
        end -= len(matched) - len(matched.rstrip())

    # Proposal only: innermost delimiter first, nothing committed yet.
    opened: list[str] = []
    probe = start
    while True:
        for delim in _MARKDOWN_DELIMS:
            left = probe - len(delim)
            if left >= 0 and text[left:probe] == delim:
                opened.append(delim)
                probe = left
                break
        else:
            break

    possessive = ""
    for suffix in _POSSESSIVES:
        if text.startswith(suffix, end):
            possessive = suffix
            end += len(suffix)
            break

    mirrored = 0
    for delim in opened:  # innermost first, mirroring the leftward walk
        if not text.startswith(delim, end):
            break
        end += len(delim)
        mirrored += 1
    # Commit exactly as much of the leftward walk as the right side confirmed.
    start -= sum(len(delim) for delim in opened[:mirrored])

    if not possessive:  # "**[TOKEN]**'s" -- possessive outside the emphasis
        for suffix in _POSSESSIVES:
            if text.startswith(suffix, end):
                possessive = suffix
                end += len(suffix)
                break

    return start, end, possessive


def _consume_unclosed_tail(text: str, match: re.Match[str]) -> int:
    """Swallow a mangled class hint that TOKEN_RE could not absorb.

    ``[PHI_MEDICATION_2f4a1b3c|MANGLED-HINT]`` matches only up to the hash -- the
    hint grammar is lowercase-only -- which would strand ``|MANGLED-HINT]`` in
    the output. This extends the span to the closing bracket, but only when the
    token opened with a bracket, did not close, and a hint separator is actually
    involved.

    Four things bound what may be swallowed, and each one is load-bearing because
    everything past the match is the *model's own prose*:

    * it must be a single unbroken run -- no whitespace (see :data:`_HINT_TAIL_RE`);
    * it must be length-capped;
    * it must end with the bracket that *balances* the one the token opened with,
      so a ``)`` inside a parenthetical cannot terminate a ``[``-opened token; and
    * it must contain no second token, so a run-on like
      ``[PHI_NAME_aaaaaaaa|PHI_NAME_bbbbbbbb]`` can never eat its neighbour.

    Fail the tail rather than over-consume: a visible ``|MANGLED HINT]`` remnant
    is cosmetic, whereas deleting a clause the model wrote silently changes the
    answer the user reads.
    """
    end = match.end()
    matched = match.group(0)
    if not matched or matched[-1] in _CLOSERS:
        return end
    closer = _BRACKET_PAIRS.get(matched[0])
    if closer is None:
        return end

    if "|" not in matched:
        probe = end
        limit = min(len(text), end + 4)
        while probe < limit and text[probe].isspace():
            probe += 1
        if probe >= len(text) or text[probe] != "|":
            return end

    tail = _HINT_TAIL_RE.match(text, end)
    if tail is None:
        return end
    stop = tail.end()
    if not text.startswith(closer, stop) or TOKEN_RE.search(text[end:stop]):
        return end
    return stop + len(closer)


def _overlaps(start: int, end: int, spans: tuple[tuple[int, int], ...]) -> bool:
    """Does ``[start, end)`` share any character with a half-open span in ``spans``?

    ``spans`` is ascending and non-overlapping (the surrogate pass builds it that
    way), but the scan is a plain walk rather than a bisection: the list is one
    entry per restored value in a single response, and a linear pass that is
    obviously correct beats a binary search that is nearly so.

    *Overlap*, not containment. The case this exists for straddles the boundary by
    construction: ``PHI-`` is the model's text and ``MRN-48273910`` is ours, and a
    containment test would wave the manufactured token straight through.
    """
    return any(start < span_end and span_start < end for span_start, span_end in spans)


def _shift_spans(
    spans: tuple[tuple[int, int], ...], edits: list[tuple[int, int, int]]
) -> tuple[tuple[int, int], ...]:
    """Move ``spans`` from input coordinates into the rebuilt string's coordinates.

    ``edits`` are the ``(start, end, replacement_length)`` splices the token pass
    committed, ascending and non-overlapping. A protected span never intersects an
    edit -- that is what ``protected`` means -- so its own bytes are untouched and
    only the drift accumulated by earlier edits applies. Both lists are ascending,
    so one merge walk does it.
    """
    if not spans or not edits:
        return spans
    shifted: list[tuple[int, int]] = []
    index = 0
    delta = 0
    for start, end in spans:
        while index < len(edits) and edits[index][1] <= start:
            edit_start, edit_end, length = edits[index]
            delta += length - (edit_end - edit_start)
            index += 1
        shifted.append((start + delta, end + delta))
    return tuple(shifted)


def _is_bracketed(matched: str) -> bool:
    """Did this token match carry a bracket on either side?

    The discriminator between "the model invented a placeholder" and "the document
    contained a reference code". Either side is enough: a dropped bracket is a
    mutation class the mock models and the build doc lists (section 9.6), so
    demanding both would push half of the model's own placeholders into the
    left-alone branch. Both absent means nothing in the string says *we* wrote it.
    """
    stripped = matched.strip()
    return bool(stripped) and (stripped[0] in _BRACKET_PAIRS or stripped[-1] in _CLOSERS)


def _collapse_ws(text: str) -> str:
    """Whitespace-insensitive key for a surrogate. See :func:`_canonical_by_shape`."""
    return _WS_RUN_RE.sub(" ", text)


def _canonical_by_shape(surrogates: Iterable[str]) -> dict[str, str]:
    """Whitespace-collapsed form -> the surrogate that was actually issued.

    :func:`_compile_surrogate_pattern` matches a multi-word fake across any
    whitespace run, so the matched text may not be a key of the caller's map:
    ``Sherri\\nLopez`` has to resolve as ``Sherri Lopez``. Without this the lookup
    misses, the value degrades to ``[UNRESOLVED_ENTITY]`` and a ``VAULT_MISS``
    audits as :data:`MISS_LOST` -- an integrity incident reported for a line break.

    A shape claimed by two different surrogates is dropped rather than resolved
    arbitrarily: guessing between two entities is the one outcome worse than not
    matching, and the exact-match path still handles both.
    """
    claims: dict[str, set[str]] = {}
    for surrogate in surrogates:
        claims.setdefault(_collapse_ws(surrogate), set()).add(surrogate)
    return {shape: next(iter(owners)) for shape, owners in claims.items() if len(owners) == 1}


def _count_surrogate_near_misses(
    text: str, surrogates: Iterable[str], *, spliced: tuple[tuple[int, int], ...]
) -> int:
    """Fakes that *nearly* matched, in the model's own prose. A signal, not a gate.

    :func:`_compile_surrogate_pattern` is case-sensitive on purpose and that
    decision is right (folding case splices a real original next to a sentence
    about the common word ``long``). The cost is that an upper-cased heading, a
    lower-cased mention or a pluralised surname reaches the user **as the fake**,
    with ``restored_count`` 0, ``vault_misses`` 0, ``surrogates_seen`` 0 and
    outcome ``ok``. Nothing in the answer or the audit row distinguished that from
    a document that simply had no pseudonyms in it.

    This scans once more, case-insensitively and NFKC-folded, and *counts*. It
    never resolves and never rewrites, so the reason for case-sensitivity is
    untouched -- a count cannot splice a name into a sentence. Spans the surrogate
    pass wrote are excluded for the same reason
    :meth:`Restorer._assert_no_surrogates` excludes them: a restored original
    legitimately contains other entities' fakes.

    Deliberately an upper bound. ``Long`` counts its lowercase common-word twin,
    and that over-count is preferable to a signal that goes quiet exactly when the
    fake is an ordinary word -- the case where a reader most needs to look.
    """
    # NFKC catches the equal-length compatibility forms (fullwidth Latin, ligature
    # digraphs). Anything that changes the length has moved the spliced offsets,
    # and a near-miss count is not worth mis-scoping the exclusion for, so that
    # case scans the original text instead of guessing at a mapping.
    folded = unicodedata.normalize("NFKC", text)
    if len(folded) != len(text):
        folded = text
    pattern = _compile_surrogate_pattern(surrogates, fold=True)
    if pattern is None:
        return 0
    return sum(
        1
        for match in pattern.finditer(folded)
        if not any(
            start <= match.start() and match.end() <= end for start, end in spliced
        )
    )


def _compile_surrogate_pattern(
    surrogates: Iterable[str], *, fold: bool = False
) -> re.Pattern[str] | None:
    """One alternation, longest alternative first, boundary-guarded per side.

    Longest-first is the whole game. Python tries alternatives in written order
    at each position, so listing ``Torres-Blake`` before ``Torres`` is what stops
    the shorter fake from biting a chunk out of the longer one and leaving a
    half-restored hybrid. A longer alternative that fails its own boundary guard
    still backtracks into the shorter ones, so ordering and guarding compose.

    **The guards are the gate's rule, imported rather than re-derived.**
    :data:`~secure_context_pipeline.pipeline.egress_gate._ALNUM` is
    ``[^\\W_]``, not ``\\w``, and applies **per side, only where the surrogate's
    own edge is alphanumeric** -- the same rule as
    ``egress_gate._occurs_as_a_unit`` and the engine's residual sweep. Both
    halves were bugs here:

    * ``\\w`` counts ``_`` as a word character, so ``(?<!\\w)`` refused to match
      ``_Maria Torres_`` -- ordinary markdown italics, and exactly what a model
      emits when it emphasises a name. The pseudonym was never restored, and
      because :meth:`Restorer._assert_no_surrogates` re-scans with *this same
      pattern*, the guard was blind in precisely the same way and could not fire.
      The fake shipped to the user silently. Importing the constant is what stops
      a fifth copy of this rule from drifting: a rename becomes an ImportError.
    * An unconditional left assertion asks a meaningless question of a surrogate
      that *starts* with punctuation: ``(?<!\\w)`` before the ``(`` of
      ``(415) 555-0123`` failed inside ``tel(415) 555-0123``, so that pseudonym
      went un-restored too.

    The right-hand assertion is written *per alternative and behind the
    possessive suffix*, because the boundary question belongs to the effective
    right edge: after ``'s`` that edge is ``s`` (alphanumeric, so guard it),
    after a bare ``'`` it is punctuation (so do not), and with no suffix it is
    the surrogate's own last character. Hence three ordered branches per
    surrogate rather than one assertion at the end of the alternation.

    The *left* assertion is instead hoisted, with the surrogates partitioned into
    a guarded group and an unguarded one, and that is a measured decision rather
    than a stylistic one. CPython's ``re`` derives a first-character prefilter
    from the start of a top-level alternation; a lookbehind written in front of
    every branch destroys it. Written per branch, a 300-surrogate pattern took
    **683 ms** over 160 KB where the hoisted form takes **17 ms** -- a 40x
    regression on a stage the build doc budgets at 500 ms.

    Partitioning is safe, and provably so rather than by inspection: two
    surrogates can only compete at the same offset if they share a first
    character, and a shared first character puts them in the same group. So no
    partition can reorder two candidates that were ever in contention, and
    longest-first still decides between them.

    **Internal whitespace is compiled as ``\\s+``, not as a literal space**, and
    that is the difference between a correct answer and a person who does not
    exist. Pseudonymization links name components, so one patient owns both
    ``Sherri Lopez`` and ``Lopez``. Longest-first protects the pair only while the
    model reproduces the long fake byte-for-byte; the moment it hard-wraps the
    line, re-flows a paragraph, double-spaces or drops the name into a table cell,
    the long alternative stops matching and the *surname* alternative wins alone.
    The output is the fake given name welded to the **real** surname --
    ``Sherri\\nTorres`` -- and every counter says the run went well:
    ``restored_count`` goes *up*, ``surrogate_misses`` stays 0, and
    :meth:`Restorer._assert_no_surrogates` cannot fire because ``Sherri`` on its
    own is not an issued fake. ``\\s+`` keeps the long alternative matching, which
    is the only place this can be fixed: once the pass has run, the hybrid is
    indistinguishable from a correctly restored two-word original.
    :func:`_canonical_by_shape` maps the flexed match back to the issued key.

    ``fold=True`` compiles the same alternation case-insensitively. That form is
    used **only** by :func:`_count_surrogate_near_misses` to count; nothing is
    ever resolved through it, because the reason case-sensitivity exists is that
    folding it turns ``long`` into a splice site.
    """
    ordered = sorted({s for s in surrogates if s}, key=lambda s: (-len(s), s))
    if not ordered:
        return None
    # The typographic apostrophe is interpolated from _RSQUO for the same reason
    # the constant exists: no confusable character literal in this source file.
    apostrophe = f"['{_RSQUO}]"
    guarded: list[str] = []
    unguarded: list[str] = []
    for surrogate in ordered:
        # The right-hand assertion is decided by the shared rule, then woven into a
        # possessive-aware alternation that is this module's own concern: a surrogate
        # may be followed by "'s", by a bare apostrophe, or by nothing.
        bare = RIGHT_GUARD if guards_right(surrogate) else ""
        suffix = f"(?:{apostrophe}s{RIGHT_GUARD}|{apostrophe}|{bare})"
        branch = f"{_escape_ws_flexible(surrogate)}{suffix}"
        # Grouped by whether the LEFT guard applies so one assertion can front the
        # whole alternation, which is why this uses the predicate rather than
        # `word_bounded_pattern`: the guards are needed apart, not assembled.
        if guards_left(surrogate):
            guarded.append(branch)
        else:
            unguarded.append(branch)

    groups: list[str] = []
    if guarded:
        groups.append(f"{LEFT_GUARD}(?:{'|'.join(guarded)})")
    if unguarded:
        groups.append(f"(?:{'|'.join(unguarded)})")
    return re.compile("|".join(groups), re.IGNORECASE if fold else 0)


# Moved to `textrules`, which owns the "does this value occur here" decision for
# all four consumers. It lived here because this module needed it first, and while
# it did, the engine's residual sweep answered the whitespace question differently
# -- the divergence `textrules` exists to prevent. Aliased rather than renamed at
# every call site so the local name keeps reading naturally.
_escape_ws_flexible = escape_ws_flexible


def _split_surrogate_match(
    matched: str, known: Collection[str], canonical: Mapping[str, str]
) -> tuple[str, str]:
    """Split a match into ``(surrogate, possessive)``.

    The pattern above carries its boundary guards per alternative, which rules out
    a single named group around the surrogate, so the split happens here instead.
    It is exact rather than heuristic: the whole match is checked against the
    issued set *first*, so a surrogate that legitimately ends in an apostrophe is
    never mistaken for a shorter one wearing a possessive.

    ``canonical`` (from :func:`_canonical_by_shape`) is consulted only after both
    exact checks fail, so the whitespace-flexible matcher cannot change the answer
    for any text that already matched exactly -- it only rescues the wrapped form.
    """
    if matched in known:
        return matched, ""
    for suffix in _POSSESSIVE_SUFFIXES:
        if matched.endswith(suffix) and matched[: -len(suffix)] in known:
            return matched[: -len(suffix)], suffix
    shaped = canonical.get(_collapse_ws(matched))
    if shaped is not None:
        return shaped, ""
    for suffix in _POSSESSIVE_SUFFIXES:
        if matched.endswith(suffix):
            shaped = canonical.get(_collapse_ws(matched[: -len(suffix)]))
            if shaped is not None:
                return shaped, suffix
    return matched, ""
