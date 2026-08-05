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
answered by the rule the EgressGate defines and this module imports -- see
:func:`_compile_surrogate_pattern`, which also explains why a home-grown ``\\b``
here left ``_Maria Torres_`` un-restored and silent.

**Fail-loud on residue.** After restoration this module re-scans its own output
and raises :class:`~secure_context_pipeline.errors.PipelineError` if any token
grammar or any known surrogate survived. A leaked token is a bug that must never
reach a user silently. ``[UNRESOLVED_ENTITY]`` is the one legitimate residue: it
carries no category prefix and no 8-hex tail, so the token grammar cannot match
it (checked at import, below).

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
from collections.abc import Collection, Iterable, Mapping
from typing import NamedTuple, Protocol

from pydantic import BaseModel, ConfigDict

from secure_context_pipeline.audit.logger import DEOBFUSCATE, VAULT_MISS, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import PipelineError, VaultMissError
from secure_context_pipeline.models import MASK, AuditEvent
from secure_context_pipeline.pipeline.egress_gate import _ALNUM, _ALNUM_RE
from secure_context_pipeline.surrogates import TOKEN_RE

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
    elapsed_ms: float = 0.0

    def __repr__(self) -> str:
        return (
            f"RestoreResult(text={MASK!r}, strategy={self.strategy!r}, "
            f"restored_count={self.restored_count}, vault_misses={self.vault_misses}, "
            f"unresolved={self.unresolved!r}, fabricated={self.fabricated!r}, "
            f"lost={self.lost!r}, surrogate_misses={self.surrogate_misses}, "
            f"tokens_seen={self.tokens_seen}, "
            f"surrogates_seen={self.surrogates_seen}, elapsed_ms={self.elapsed_ms:.3f})"
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
        changes no output text and no control flow; it exists only so a vault miss
        can be *classified* -- see the module docstring. Omitting it is supported
        and honest: every miss is then recorded :data:`MISS_INDETERMINATE`.

        Raises :class:`PipelineError` if a token or a known surrogate survives
        the pass. Returns normally with ``[UNRESOLVED_ENTITY]`` spliced in when a
        token ID is simply absent from the vault: an unknown token degrades the
        answer, it never fails the request.
        """
        started = time.perf_counter()
        if strategy not in _KNOWN_STRATEGIES:
            raise PipelineError(reason="unknown_strategy", strategy=str(strategy)[:32])

        supplied: dict[str, str] = {key: value for key, value in (surrogates or {}).items() if key}
        pattern = _compile_surrogate_pattern(supplied) if supplied else None
        minted = None if issued is None else {token_id.lower() for token_id in issued}

        working = text
        surrogate_pass = _SurrogatePass(working, 0, 0, 0, ())
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

        token_pass = await self._restore_tokens(
            session_id, working, minted=minted, run_id=run_id
        )
        working = token_pass.text
        await self._assert_no_tokens(session_id, working, strategy=strategy, run_id=run_id)

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
        self, session_id: str, text: str, *, minted: set[str] | None, run_id: str | None
    ) -> _TokenPass:
        """Resolve every token, then rebuild the string in one left-to-right pass.

        Equivalent to replacing right-to-left, and safer: the output is assembled
        from slices of the *original* string, so an earlier splice can never
        shift a later match's offsets.

        ``minted`` is the lowercased ``issued`` set, or ``None``; it only decides
        how a miss is *labelled*, never what is written into the text.
        """
        matches = list(TOKEN_RE.finditer(text))
        if not matches:
            return _TokenPass(text, 0, 0, (), (), (), 0)

        # Resolve each distinct token ID once. This cache is per call by design:
        # one that outlived the call would outlive its session scope.
        order: list[str] = []
        labels: dict[str, str] = {}
        for match in matches:
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
                await self._emit(
                    session_id,
                    run_id=run_id,
                    event_type=VAULT_MISS,
                    entity_type=labels[token_id],
                    token_id=token_id,
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
                        "token_id": token_id,
                        "entity_type": labels[token_id],
                        "classification": classification,
                    },
                )

        parts: list[str] = []
        cursor = 0
        restored = 0
        missed = 0
        for match in matches:
            span_start, span_end, possessive = _span_and_suffix(text, match)
            if span_end <= cursor:  # fully swallowed by the previous splice
                continue
            parts.append(text[cursor : max(span_start, cursor)])
            value = resolved.get(match.group(3).lower())
            if value is None:
                parts.append(UNRESOLVED_ENTITY + possessive)
                missed += 1
            else:
                parts.append(value + possessive)
                restored += 1
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
        split = [_split_surrogate_match(match.group(0), supplied) for match in matches]

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
        self, session_id: str, text: str, *, strategy: str, run_id: str | None
    ) -> None:
        """In-code guarantee, not just a test: nothing token-shaped reaches the user.

        Scanned with the same matcher used to restore, so detection and
        verification cannot drift apart. Nothing is excluded from this scan --
        not even text that came out of the vault. The token grammar is a
        synthetic high-entropy shape (``CATEGORY_TYPE_8hex``) that a real entity
        value cannot accidentally take, so *any* occurrence in the final answer
        is a leak, whatever produced it. ``[UNRESOLVED_ENTITY]`` is inert against
        the grammar, so a legitimate vault miss does not trip this.
        """
        residue = TOKEN_RE.search(text)
        if residue is None:
            return
        await self._fail(
            session_id,
            run_id=run_id,
            strategy=strategy,
            reason="residual_token_after_restore",
            count=len(TOKEN_RE.findall(text)),
            sample=residue.group(3).lower(),
        )

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
                sample=None,
            )

    async def _fail(
        self,
        session_id: str,
        *,
        run_id: str | None,
        strategy: str,
        reason: str,
        count: int,
        sample: str | None,
    ) -> None:
        """Audit the violation, then raise. Never carries the offending text."""
        detail: dict[str, int | float | str] = {
            "strategy": strategy,
            "outcome": "assertion_failed",
            "reason": reason,
            "residual": count,
        }
        if sample is not None:
            detail["sample_token_id"] = sample
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
            sample_token_id=sample,
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


def _compile_surrogate_pattern(surrogates: Iterable[str]) -> re.Pattern[str] | None:
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
        bare = f"(?!{_ALNUM})" if _ALNUM_RE.match(surrogate[-1]) else ""
        suffix = f"(?:{apostrophe}s(?!{_ALNUM})|{apostrophe}|{bare})"
        branch = f"{re.escape(surrogate)}{suffix}"
        if _ALNUM_RE.match(surrogate[0]):
            guarded.append(branch)
        else:
            unguarded.append(branch)

    groups: list[str] = []
    if guarded:
        groups.append(f"(?<!{_ALNUM})(?:{'|'.join(guarded)})")
    if unguarded:
        groups.append(f"(?:{'|'.join(unguarded)})")
    return re.compile("|".join(groups))


def _split_surrogate_match(matched: str, known: Collection[str]) -> tuple[str, str]:
    """Split a match into ``(surrogate, possessive)``.

    The pattern above carries its boundary guards per alternative, which rules out
    a single named group around the surrogate, so the split happens here instead.
    It is exact rather than heuristic: the whole match is checked against the
    issued set *first*, so a surrogate that legitimately ends in an apostrophe is
    never mistaken for a shorter one wearing a possessive.
    """
    if matched in known:
        return matched, ""
    for suffix in _POSSESSIVE_SUFFIXES:
        if matched.endswith(suffix) and matched[: -len(suffix)] in known:
            return matched[: -len(suffix)], suffix
    return matched, ""
