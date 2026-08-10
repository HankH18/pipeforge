"""The obfuscation engine -- policy, dedupe, splice, audit (build doc section 9.3).

The engine owns everything that must behave **identically under every strategy**,
and the strategy owns only what a surrogate looks like. Concretely, the engine
decides:

1. **Dedupe.** Detections collapse by ``(entity_type, normalize(text))``. A value
   appearing five times is one vault row, one token, and five splices -- which is
   what makes the payload internally consistent and the restore unambiguous.
2. **Determinism.** An entity already mapped in this session reuses its stored
   surrogate, read back from the vault rather than re-derived, so a second call
   in the same session cannot produce a second mapping for the same value.
3. **Engine-level actions** from the registry, applied before any confidence
   test and identically in both modes:

   * ``action: strip`` (``PRIVILEGED_MARKER``) removes the span outright. A typed
     token would advertise the very classification it exists to mask, and a
     privilege banner is constant boilerplate with zero reasoning value -- so
     there is no surrogate and no vault entry, only a ``STRIP`` audit event.
   * ``action: redact`` (``CASE_STRATEGY``) always becomes ``[REDACTED_<TYPE>]``.
     Strategy prose is exactly what privilege protects; a token of it carries no
     reasoning value and a pseudonym of it would *fabricate strategy*. Forcing it
     also closes a hole the leakage harness cannot see, because free text that is
     never obfuscated never enters the vault's originals set and so is invisible
     to the egress gate.
4. **The threshold band.** ``score >= threshold_obfuscate`` (per-entity override
   honoured) obfuscates. ``threshold_redact <= score < threshold_obfuscate``
   becomes ``[REDACTED_<TYPE>]`` with **no vault entry** -- irreversible by
   design. That is the graceful-degradation posture: a span we are unsure about
   is destroyed rather than round-tripped, and the user sees the redaction in the
   final answer.
5. **Right-to-left splicing** by span offset, so every not-yet-applied offset
   stays valid against the original text.
6. **The residual sweep.** After planning the detected spans, every *other*
   occurrence of an already-vaulted value is masked too. NER does not fire on
   every mention of a name, and each survivor is a real leak that the egress gate
   would (correctly) block on. Detection decides what is sensitive; the vault
   decides where it appears. See :meth:`ObfuscationEngine._sweep_residual`.
7. **The manifest.** ``ObfuscationResult.tokens`` declares *every* surrogate
   present in ``obfuscated_text``, and ``spans`` covers every original span. The
   sweep can splice a surrogate for a value this call never detected, so the
   manifest is not simply "what the detector produced" -- it is what the payload
   contains. Callers rely on that: the orchestrator hands the surrogate set to the
   egress gate as *our own output* (an undeclared one is re-detected and blocks
   the request) and builds the pseudonym restore map from the same set (an
   undeclared one is never restored, so the caller reads the fake as the answer).

``entity_type`` is an **opaque string** here. This module contains no entity name
and no tier logic; every entity-specific decision -- category, tier, action,
threshold, per-entity strategy, document-category scoping -- is a registry
lookup. That is what makes "add an entity type by editing ``entities.yaml``
only" true (build doc section 10.4).

No original value reaches a log line, an audit record, or an exception from this
module: only entity types, token IDs, counts, and scores.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from secure_context_pipeline.audit.logger import OBFUSCATE, REDACT, STRIP, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import derive_token_id, normalize
from secure_context_pipeline.detection.detector import resolve_overlaps
from secure_context_pipeline.detection.registry import EntityRegistry, RegistryAction
from secure_context_pipeline.errors import PipelineError, VaultMissError
from secure_context_pipeline.models import (
    AuditEvent,
    Detection,
    EntityAction,
    EntityCategory,
    ObfuscationResult,
    RedactionRecord,
    SpanOut,
    TokenRecord,
)
from secure_context_pipeline.obfuscation.strategies.base import (
    ObfuscationStrategy,
    StrategyContext,
    build_strategy,
)
from secure_context_pipeline.surrogates import format_redaction

# The occurrence rule is imported, not re-derived. The sweep and the gate have now
# disagreed twice -- most recently on whether "_" is a word character -- and a
# disagreement here is the worst kind: the sweep declines to mask a value the gate
# then blocks on, so the document is unprocessable and no test on either side sees
# a contradiction. `textrules` is a leaf module both this and the gate depend on, so
# there is one decision rather than two agreeing copies, and it points downward:
# importing it from `pipeline` (as this did) inverted the layering, since `pipeline`
# already imports `obfuscation`.
from secure_context_pipeline.textrules import word_bounded_pattern
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

logger = logging.getLogger(__name__)

__all__ = ["MAX_TOKEN_COLLISION_RETRIES", "MIN_SWEEP_LEN", "ObfuscationEngine"]

#: Shortest surface form the residual sweep will chase. A one- or two-character
#: value carries no re-identification signal on its own and would match inside
#: unrelated words; it also sits below the egress gate's own scan floor, so
#: leaving it unswept cannot cause a block. Mirrors ``egress_gate.MIN_ORIGINAL_LEN``.
MIN_SWEEP_LEN: Final = 3

#: Truncating HMAC-SHA256 to 4 bytes collides with probability ~n^2/2^33, so at a
#: few thousand entities per session this loop effectively never runs -- but a
#: collision would mis-restore, so it is handled rather than assumed away.
MAX_TOKEN_COLLISION_RETRIES: Final = 8

_REASON_POLICY_STRIP: Final = "policy_strip"
_REASON_POLICY_REDACT: Final = "policy_redact"
_REASON_LOW_CONFIDENCE: Final = "below_obfuscate_threshold"


@dataclass(frozen=True, slots=True)
class _Planned:
    """One surviving detection plus the action policy chose for it."""

    detection: Detection
    action: EntityAction
    reason: str


@dataclass(slots=True)
class _Group:
    """All spans of one distinct ``(entity_type, normalized value)``."""

    entity_type: str
    normalized: str
    first: Detection
    spans: list[Detection] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Replacement:
    """A splice: ``text[start:end]`` becomes ``value``."""

    start: int
    end: int
    value: str


@dataclass(frozen=True, slots=True)
class _Surface:
    """One surface form the residual sweep looks for, and what it splices for it.

    ``action`` exists because not every sweepable value is a *tokenized* one. A
    confidence-band redaction gets no vault row and no surrogate, only a
    ``[REDACTED_<TYPE>]`` marker and a gate needle
    (:meth:`~secure_context_pipeline.vault.session_vault.SessionVault.note_unrestorable`),
    so its residual occurrences have to be masked with the same marker and reported
    as ``REDACTED`` rather than invented a surrogate they do not have. See
    :meth:`ObfuscationEngine._sweep_residual`.
    """

    replacement: str
    entity_type: str
    category: EntityCategory
    score: float
    action: EntityAction = EntityAction.OBFUSCATED


@dataclass(frozen=True, slots=True)
class _SweepBase:
    """Where the residual sweep started, so a second pass can rewind to it.

    Only the sweep's own additions are undone; the detected, redacted and stripped
    spans it was handed are not the sweep's to discard. ``covered`` is kept as a
    copy rather than as a length like the other three, which is a few tuples of
    memory in exchange for not depending on the lists growing in lockstep -- they do
    today, and nothing enforces it.
    """

    replacements: int
    spans: int
    redactions: int
    covered: list[tuple[int, int]]


def _rewind_sweep(
    base: _SweepBase,
    replacements: list[_Replacement],
    spans: list[SpanOut],
    redactions: list[RedactionRecord],
    covered: list[tuple[int, int]],
) -> None:
    """Undo the sweep's splices, spans and redaction records in place, back to ``base``.

    In place, because the scan closure reads these lists by reference and rebinding
    them would leave it appending to the discarded copies.
    """
    del replacements[base.replacements :]
    del spans[base.spans :]
    del redactions[base.redactions :]
    covered[:] = base.covered


class ObfuscationEngine:
    """Applies detections to text: dedupe, tokenize/pseudonymize, redact, strip.

    Usage::

        engine = ObfuscationEngine(
            registry=registry, vault=vault, session_registry=sessions, settings=settings,
            audit=audit,
        )
        result = await engine.obfuscate(session_id, text, detections, doc_category="medical")

    The engine is stateless between calls and safe to share across requests: all
    per-session state lives in the vault and the session registry.
    """

    def __init__(
        self,
        *,
        registry: EntityRegistry,
        vault: SessionVault,
        session_registry: SessionRegistry,
        settings: Settings,
        audit: AuditLogger | None = None,
    ) -> None:
        self._registry = registry
        self._vault = vault
        self._sessions = session_registry
        self._settings = settings
        self._audit = audit

    # -- public API --------------------------------------------------------

    async def obfuscate(
        self,
        session_id: str,
        text: str,
        detections: Sequence[Detection],
        *,
        strategy: str | None = None,
        doc_category: str | None = None,
        run_id: str | None = None,
    ) -> ObfuscationResult:
        """Obfuscate ``text`` according to ``detections`` and registry policy.

        ``strategy`` overrides :attr:`Settings.strategy` for this call; a
        per-entity ``strategy:`` in the registry overrides both, for that entity.
        ``doc_category`` (``medical``/``legal``/``financial``/``general``), when
        given, additionally drops detections the registry scopes out of that
        document category -- defense in depth behind the detector's own scoping.
        ``run_id`` is stamped on every audit event so one ID correlates the whole
        pipeline run (build doc section 9.5.1); it is the only addition to the
        signature in the build doc.

        Raises :class:`~secure_context_pipeline.errors.SessionExpiredError` if the
        session is gone -- there is no key to derive tokens with, and producing an
        un-restorable payload would be worse than failing.
        """
        started = time.perf_counter()
        session_key = await self._sessions.key(session_id)

        planned = self._plan(text, detections, doc_category)
        groups = _group(planned)
        records = await self._resolve_groups(session_id, session_key, groups, strategy)

        replacements: list[_Replacement] = []
        spans: list[SpanOut] = []
        redactions: list[RedactionRecord] = []
        stripped: list[RedactionRecord] = []

        for item in planned:
            detection = item.detection
            if item.action is EntityAction.STRIPPED:
                replacements.append(_Replacement(detection.start, detection.end, ""))
                stripped.append(_record(detection))
                spans.append(_span(detection, EntityAction.STRIPPED, None))
                continue
            if item.action is EntityAction.REDACTED:
                replacements.append(
                    _Replacement(
                        detection.start, detection.end, format_redaction(detection.entity_type)
                    )
                )
                redactions.append(_record(detection))
                spans.append(_span(detection, EntityAction.REDACTED, None))
                # A confidence-band redaction is still a VALUE the detector typed,
                # and it gets no vault row -- which used to leave the EgressGate
                # with no needle for it while pass 2 dropped it for the same
                # numeric reason. Hand it to the gate as an unrestorable needle.
                # Policy redactions (`action: redact`, e.g. CASE_STRATEGY) are
                # deliberately excluded: that span is prose, not a value, and its
                # phrasing recurs in ordinary text. See
                # ``SessionVault.note_unrestorable``.
                #
                # Planting that needle obliges the sweep to clear it: this marks ONE
                # span, and the gate then scans the whole payload for the value. The
                # residual sweep below therefore masks the rest of this value's
                # occurrences with the same marker, or an ordinary document stating a
                # number twice is refused by a needle this call planted -- measured,
                # and argued at ``_sweep_residual``.
                if item.reason == _REASON_LOW_CONFIDENCE:
                    self._vault.note_unrestorable(session_id, detection.text)
                continue
            record = records[(detection.entity_type, normalize(detection.text))]
            replacements.append(_Replacement(detection.start, detection.end, record.surrogate))
            spans.append(_span(detection, EntityAction.OBFUSCATED, record.surrogate))

        # Audited BEFORE the sweep, and the order is load-bearing for the reason
        # ``_sweep_residual`` sets out: the sweep's second read of the originals set
        # must be the last look this call takes at it, because everything after it is
        # window in which a concurrent run's vault write turns this run from a masked
        # value into a refused request. One awaited ``audit.emit`` per entity is by far
        # the largest thing that used to sit in that window -- measured end to end on
        # ``fixtures/medical_note.txt``, 23.5 ms of the 26.5 ms total.
        #
        # Nothing here depends on the sweep: the events describe ``planned`` and
        # ``records``, both final before this line, and the vault rows they name were
        # written by ``_resolve_groups`` further up. The one behaviour this changes is
        # a run whose sweep raises (``SessionExpiredError`` if the session dies
        # mid-call) -- its OBFUSCATE events are now written rather than lost, which
        # describes what actually happened to the vault rather than less.
        await self._audit_result(session_id, run_id, planned, records, strategy)

        swept, swept_records = await self._sweep_residual(
            session_id, text, planned, records, replacements, spans, redactions
        )
        obfuscated = _splice(text, replacements)
        # ``tokens`` declares every surrogate present in ``obfuscated_text`` -- which
        # includes the ones the cross-call sweep spliced in for values this session
        # vaulted on an EARLIER call and the detector missed here. Those have no
        # entry in ``records``, because ``records`` is built from this call's
        # detections, so they have to be appended explicitly. Dedupe on token ID:
        # a value can be both detected here and reached by the sweep under a
        # different surface form (a header's "JOHN SMITH" against a vaulted
        # "John Smith"), and that is one vault row, so it is one token.
        tokens = [records[key] for key in _ordered_keys(planned, records)]
        declared = {record.token_id for record in tokens}
        tokens.extend(record for record in swept_records if record.token_id not in declared)

        logger.info(
            "text obfuscated",
            extra={
                "session_id": session_id,
                "run_id": run_id,
                "spans": len(spans),
                "unique_entities": len(records),
                "redacted": len(redactions),
                "stripped": len(stripped),
                "swept": swept,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            },
        )
        return ObfuscationResult(
            obfuscated_text=obfuscated,
            tokens=tokens,
            redactions=redactions,
            stripped=stripped,
            spans=spans,
        )

    # -- residual sweep ----------------------------------------------------

    async def _sweep_residual(
        self,
        session_id: str,
        text: str,
        planned: Sequence[_Planned],
        records: Mapping[tuple[str, str], TokenRecord],
        replacements: list[_Replacement],
        spans: list[SpanOut],
        redactions: list[RedactionRecord],
    ) -> tuple[int, list[TokenRecord]]:
        """Mask every remaining occurrence of an already-vaulted value.

        The section 9.3 splice replaces only the spans the detector returned. Real
        documents mention the same value more than once and NER does not fire on
        every mention -- "Larkspur Valley Hospital" is detected in a header and
        missed two paragraphs later in prose. Every surviving occurrence is a
        genuine leak: the egress gate blocks on it, which is correct but leaves the
        pipeline unable to process an ordinary document.

        So once a value has been vaulted, it is masked *everywhere*. Detection
        decides **what** is sensitive; the vault decides **where** it appears. This
        runs on the ORIGINAL text before splicing, so offsets stay in original
        space and swept occurrences get real ``SpanOut`` entries for the UI.

        "Everywhere" spans the whole **session**, not just this call. A session is
        long-lived and processes many documents (``POST /ask`` per ``doc_id``), so a
        name vaulted from yesterday's discharge summary and missed by the detector
        in today's referral letter is the same residual leak one paragraph later
        would be -- and the gate blocks the request for it just the same. The
        second pass therefore also chases values this session vaulted on an
        *earlier* call. It costs one regex scan per prior original that is not
        already a surface of this call, and nothing at all on the common
        single-document session, where every vaulted original is already a surface.

        Matching is case-insensitive on word boundaries, longest surface form
        first, so "John Smith" claims its span before a bare "Smith" can. Occurrences
        already covered by a detected span, a redaction, or a strip are left alone.

        Returns the number of occurrences swept **and the prior-call vault records
        that actually reached the payload**. The caller needs the second value
        because ``ObfuscationResult.tokens`` has to declare every surrogate in the
        outbound text, and a surrogate spliced in by this pass has no entry in
        ``records``. Leaving it undeclared is not cosmetic: the orchestrator hands
        that set to the egress gate as "our own output", so an undeclared
        pseudonymized SSN is re-detected by pass 2 and blocks the request; and it
        builds the pseudonym restore map from the same set, so an undeclared fake is
        never restored and the caller reads the fake as though it were the answer.

        **The originals set is read twice, and the second read is the point.** A
        session is shared -- ``POST /ask`` is per ``doc_id``, not per session -- so a
        concurrent run can vault a value between this pass's read and the EgressGate's
        read of the same session-wide set at gate time. If that value occurs in this
        document and this call's detector missed it, the sweep never held it as a
        surface, it goes out in the clear, and the gate refuses the request with
        ``EGRESS_BLOCKED(reason='vault_original')``. That refusal is *correct* -- the
        payload does carry a value the system now knows is sensitive -- so the repair
        is to make this pass see the value, never to make the gate blind to it. The
        comment at the rewind below says why the whole sweep is redone on a late
        arrival rather than appended to.

        **This narrows the window; it does not close it, and it cannot.** A write can
        always land after whichever read is last, so what remains exposed is the
        splice, the caller's prompt obfuscation, the payload assembly, and the gate's
        own dispatch -- and a value vaulted in *that* interval still reaches the gate
        unswept and is still refused, correctly. What changed is only how much of the
        run sits inside the window. Measured end to end through the real orchestrator
        on ``fixtures/medical_note.txt`` (mock provider, n=15, median): the interval
        between the engine's last read of the originals set and the gate's read was
        **26.5 ms before this change and 2.0 ms after** -- 92% of it closed, most of
        that by moving the per-entity audit write above the sweep rather than by the
        second read itself. The failure mode of what remains is a refused request,
        never a released value.

        **A redact-band value is swept too, with its marker rather than a surrogate.**
        A detection scoring in ``[threshold_redact, threshold_obfuscate)`` gets
        ``[REDACTED_<TYPE>]`` and no vault row, and the engine hands the value to the
        gate as an unrestorable needle (``SessionVault.note_unrestorable``). Masking
        only the *labelled* mention then made an ordinary document unprocessable:
        ``Member SSN 452189376 verified against payer records.`` followed by ``Ledger
        reference 452189376 appears in the reconciliation table.`` is ``SSN@0.40`` at
        the first mention and undetected at the second, so the second went out in the
        clear, pass 1 found its own needle there, and the request came back
        ``422 EGRESS_BLOCKED(reason='vault_original')`` -- measured through the real
        ASGI app on three ordinary financial shapes, three of three blocked. Redacting
        the residual is the same decision this call already made about the same value,
        applied consistently; refusing the request is not a safer version of it, it is
        the same policy with the document thrown away.

        Two boundaries of that, both deliberate. It is scoped to
        ``_REASON_LOW_CONFIDENCE``, never to ``action: redact`` policy spans, for the
        reason ``note_unrestorable`` gives: a ``CASE_STRATEGY`` sentence is prose whose
        phrasing recurs, and sweeping it would rewrite ordinary text. And it is scoped
        to *this call*: a gate-only needle from an EARLIER call cannot be swept here,
        because the vault stores it as a bare string with no entity type
        (``_SessionCache.gate_only``) and there is no honest ``<TYPE>`` to print --
        ``_add_prior_session_surfaces`` therefore still leaves an unresolvable original
        alone, which is also what keeps the leakage harness's planted-needle proof
        (``test_the_sweep_never_masks_an_original_it_cannot_resolve_to_a_record``)
        working. What survives is the same word-boundary limit the whole sweep has:
        ``ledgerref452189376x`` is not an occurrence by
        :func:`~secure_context_pipeline.textrules.occurs_as_a_unit`, so the gate blocks
        it -- and that block is the one ``note_unrestorable`` was written to produce.
        """
        covered: list[tuple[int, int]] = [(r.start, r.end) for r in replacements]
        surfaces: dict[str, _Surface] = {}
        for item in planned:
            if item.action is not EntityAction.OBFUSCATED:
                continue
            detection = item.detection
            record = records.get((detection.entity_type, normalize(detection.text)))
            if record is None:
                continue
            surfaces.setdefault(
                detection.text,
                _Surface(
                    record.surrogate, detection.entity_type, detection.category, detection.score
                ),
            )
        # Carried across both reads so the second one costs O(originals that arrived
        # since the first) rather than a second regex scan of every prior original.
        examined: set[str] = set()
        prior = await self._add_prior_session_surfaces(session_id, text, surfaces, examined)

        # LAST, and ``setdefault``, so a redaction marker can only ever claim a surface
        # nothing restorable already claimed. Both earlier sources outrank it and for
        # the same reason: an irreversible mask on a value the vault can restore is a
        # lost answer, not a safer one. This call's own tokenizations outrank it
        # because banding is per (entity_type, value) group and a value can be typed
        # twice -- ``MRN`` above the threshold, ``ACCOUNT_NUMBER`` below it -- and the
        # mask should not depend on which detection came first in offset order. A
        # prior call's vault row outranks it because the row already exists: the value
        # was tokenized on an earlier document in this session, and re-detecting it
        # here at 0.40 does not un-vault it.
        for item in planned:
            if item.action is not EntityAction.REDACTED or item.reason != _REASON_LOW_CONFIDENCE:
                continue
            detection = item.detection
            surfaces.setdefault(
                detection.text,
                _Surface(
                    format_redaction(detection.entity_type),
                    detection.entity_type,
                    detection.category,
                    detection.score,
                    EntityAction.REDACTED,
                ),
            )

        # Insertion-ordered, so the returned records follow sweep order and the
        # ``tokens`` list stays deterministic.
        used: dict[str, None] = {}

        # Total order: longest first, then lexicographic.
        #
        # Longest first is the load-bearing half: where "Smith" and "John Smith" both
        # match one residual, the surname claiming it would splice the surname's
        # surrogate over five characters and leave "John " standing in the clear.
        #
        # The lexicographic tie-break settles equal-length surfaces. ``surfaces`` is
        # filled from two sources -- this call's detections, in offset order, and
        # prior-call originals, in sorted order -- and sorting on length alone is a
        # *partial* order, so a length tie falls through to whichever source inserted
        # first. The same document would then mask a different span depending on which
        # call vaulted the value. Ordering on the surface itself makes the outcome a
        # function of the surface set and nothing else.
        def scan() -> int:
            """The surface sweep, off the event loop.

            Offloaded for the same reason ``EgressGate._scan_originals`` is, and it
            is a concurrency-correctness point rather than a latency one. This limb
            is ``O(surfaces x len(text))`` of synchronous regex with no ``await`` in
            it, so on an ASGI app it is head-of-line blocking for *every* concurrent
            request, not merely a slow response for this one.

            Measured on ``fixtures/legal_brief_large.txt``, worst gap observed by an
            unrelated 5 ms heartbeat during one ``obfuscate``: **464 ms inline, 46 ms
            offloaded.** The engine docstring's O(entities) claim describes the vault
            and the splice; this limb is O(entities x document), which is why it is
            the one that shows up.

            **The GIL does not make this a no-op, and measuring it wrongly says it
            does.** A first attempt at the A/B cancelled the heartbeat as soon as the
            call returned, so the heartbeat never resumed to *observe* the gap and
            reported 39 ms for both arms -- the identical mistake
            ``test_a_long_pass_one_does_not_stall_unrelated_coroutines`` warns about
            in its own docstring. ``re`` holds the GIL, so the thread does not run in
            parallel; what it does is let the interpreter switch every few
            milliseconds instead of not at all, which turns one uninterruptible
            block into slices the loop can run between.

            Pure and self-contained: it reads ``text`` and ``surfaces``, both already
            built, and appends to lists no other coroutine can reach until it
            returns. A thread cannot be cancelled mid-scan, so a cancelled request
            discards the work rather than interrupting it -- the same trade the
            gate's pass 1 makes.
            """
            found = 0
            for surface in sorted(surfaces, key=lambda value: (-len(value), value)):
                if len(surface.strip()) < MIN_SWEEP_LEN:
                    continue
                plan = surfaces[surface]
                redacting = plan.action is EntityAction.REDACTED
                for match in re.finditer(_word_bounded(surface), text, re.IGNORECASE):
                    start, end = match.span()
                    if any(start < c_end and end > c_start for c_start, c_end in covered):
                        continue
                    replacements.append(_Replacement(start, end, plan.replacement))
                    covered.append((start, end))
                    spans.append(
                        SpanOut(
                            entity_type=plan.entity_type,
                            category=plan.category,
                            start=start,
                            end=end,
                            score=plan.score,
                            action=plan.action,
                            # A redaction marker is not a surrogate: nothing restores
                            # it, and reporting one here would put a string in the
                            # restore map that the payload's marker never matches.
                            surrogate=None if redacting else plan.replacement,
                        )
                    )
                    if redacting:
                        redactions.append(
                            RedactionRecord(
                                entity_type=plan.entity_type,
                                start=start,
                                end=end,
                                score=plan.score,
                            )
                        )
                    found += 1
                    used.setdefault(surface, None)
            return found

        # Everything the sweep is about to add, so the second pass can be undone back
        # to exactly the detected/redacted/stripped spans rather than layered on top.
        detected = _SweepBase(len(replacements), len(spans), len(redactions), list(covered))

        swept = await asyncio.to_thread(scan)

        # The second read, as late as this pass can make it. Empty on every
        # single-run session and on every concurrent one where nothing new was
        # vaulted in the interval, which is the overwhelmingly common case.
        late = await self._add_prior_session_surfaces(session_id, text, surfaces, examined)
        if late:
            # Rewind and rescan the WHOLE surface set rather than appending the new
            # surfaces to what the first pass produced. Longest-first is a total order
            # over the whole set, and an append-only second pass breaks it: with
            # "Smith" masked in pass one and "John Smith" arriving in pass two, the
            # long surface's match overlaps a covered span, is skipped, and "John "
            # is left standing beside a surrogate -- readable, and invisible to the
            # gate, which finds neither original verbatim and releases. Redoing the
            # sweep costs one extra scan of a document that just lost a race, and
            # nothing at all on every run that did not.
            prior.update(late)
            _rewind_sweep(detected, replacements, spans, redactions, covered)
            used.clear()
            swept = await asyncio.to_thread(scan)
            logger.info(
                "originals set grew during obfuscation; sweep re-run",
                extra={"session_id": session_id, "late_surfaces": len(late)},
            )

        if swept:
            logger.info("residual occurrences swept", extra={"swept": swept})
        return swept, [prior[surface] for surface in used if surface in prior]

    async def _add_prior_session_surfaces(
        self,
        session_id: str,
        text: str,
        surfaces: dict[str, _Surface],
        examined: set[str],
    ) -> dict[str, TokenRecord]:
        """Add values vaulted on an earlier call that occur in *this* document.

        The vault's original -> record index is cache-only and O(1), but it is keyed
        by ``(entity_type, normalized)`` and a bare original does not carry its type.
        Rather than probe every registry type for every original, the cheap test runs
        first: does the value even occur here? On a single-document session that
        test is skipped entirely, because every vaulted original is already a
        surface of this call.

        A value vaulted under an entity type the registry does not define cannot be
        resolved back to its record here and is left to the egress gate, which is
        the fail-closed outcome rather than a silent one.

        Called **twice** per sweep against a set a concurrent run can grow in
        between, so ``examined`` carries the originals already decided about from one
        call to the next and the second call only pays for what arrived since. Only
        *permanent* decisions are recorded there: below the length floor, and absent
        from ``text``, are both properties of immutable inputs. "No vault record" is
        not -- it is what a redact-band ``note_unrestorable`` needle looks like, and
        also what a concurrent run's value looks like for the moment between its
        cache write and its row -- so an unresolvable original is re-offered on the
        next read rather than written off.

        Returns ``{surface: record}`` for every surface added, so the sweep can
        report which records reached the payload.
        """
        resolved: dict[str, TokenRecord] = {}
        originals = self._vault.originals_for_session(session_id)
        if not originals:
            return resolved
        for original in sorted(originals):
            if original in examined or original in surfaces:
                continue
            if len(original.strip()) < MIN_SWEEP_LEN:
                examined.add(original)
                continue
            if not re.search(_word_bounded(original), text, re.IGNORECASE):
                examined.add(original)
                continue
            record = await self._record_for_original(session_id, original)
            if record is None:
                continue
            examined.add(original)
            # Score 1.0: this is not a detector guess to be graded, it is a value
            # the vault already holds. The UI shows it as certain because it is.
            surfaces[original] = _Surface(
                record.surrogate, record.entity_type, record.category, 1.0
            )
            resolved[original] = record
        return resolved

    async def _record_for_original(self, session_id: str, original: str) -> TokenRecord | None:
        """The vault record for a bare original, found by probing registry types."""
        normalized = normalize(original)
        for entity_type in self._registry.entities:
            record = await self._vault.get_by_original(session_id, entity_type, normalized)
            if record is not None:
                return record
        return None

    # -- policy ------------------------------------------------------------

    def _plan(
        self, text: str, detections: Sequence[Detection], doc_category: str | None
    ) -> list[_Planned]:
        """Drop, scope, de-overlap and classify. Returns spans in offset order.

        De-overlapping runs :func:`detection.detector.resolve_overlaps` -- the same
        function object the detector uses, not a copy of it -- with the same two
        categorical rank dimensions derived from this engine's registry. Splicing
        overlapping spans is undefined, and ``obfuscate`` accepts detections from
        any source, so the pass is not redundant just because ``Detector`` already
        returns disjoint spans. What it must not be is a *second opinion*: the
        surviving label picks the tier, action and threshold applied below, so two
        implementations that rank differently obfuscate the same document
        differently depending on which one ran.
        """
        limit = len(text)
        candidates = [
            detection
            for detection in detections
            if 0 <= detection.start < detection.end <= limit
            and self._in_scope(detection.entity_type, doc_category)
            and self._is_enforceable(detection)
        ]
        entities = self._registry.entities
        policy_types = frozenset(name for name, spec in entities.items() if spec.action is not None)
        pattern_types = frozenset(
            name for name, spec in entities.items() if spec.patterns or spec.gazetteer
        )
        surviving = resolve_overlaps(text, candidates, policy_types, pattern_types)
        # One value, one band. `_classify` reads a single span's score, so the same
        # value detected twice at different confidences was banded twice: tokenized
        # at the site that scored above `threshold_obfuscate` and irreversibly
        # `[REDACTED_<TYPE>]` at the site that scored below it, in the SAME payload.
        # Live on `fixtures/medical_note.txt`, where one phone number scores 0.75 in
        # a labelled line and 0.40 in bare prose.
        #
        # It fails safe -- neither mask discloses the value -- but it contradicts
        # this module's own headline claim ("one vault row, one token, five splices
        # -- which is what makes the payload internally consistent"), and the
        # inconsistency is visible to the model, which sees two different referents
        # for one entity. It also costs a restoration the user was entitled to.
        #
        # The band is therefore decided once per `(entity_type, normalized value)`
        # on the group's MAXIMUM score. Max rather than min or mean because the
        # question is "is this value sensitive", and the most confident sighting is
        # the best evidence available; taking the minimum would let one weak mention
        # downgrade a value the detector was certain about elsewhere. Policy actions
        # (`action: strip`/`redact`) are unaffected -- `_classify` applies those
        # before any confidence test.
        best: dict[tuple[str, str], float] = {}
        for detection in surviving:
            key = (detection.entity_type, normalize(detection.text))
            best[key] = max(best.get(key, 0.0), detection.score)
        # The GROUP score decides the band; the SPAN keeps its own score.
        #
        # A first version passed `detection.model_copy(update={"score": group_max})`
        # into `_classify`, and that copy is what flowed on into `_span()`,
        # `_record()` and the audit `detail={"score": ...}`. Every span of a repeated
        # value was then stamped with the maximum confidence seen anywhere in the
        # document for that value, so `SpanOut.score` -- which the UI renders in a
        # tooltip and the audit trail records -- reported a measurement the detector
        # never made at that offset. Banding on the group is the intended policy;
        # rewriting the evidence to match the policy is not.
        planned = [
            self._classify(
                detection,
                band_score=best[(detection.entity_type, normalize(detection.text))],
            )
            for detection in surviving
        ]
        return [item for item in planned if item is not None]

    def _is_enforceable(self, detection: Detection) -> bool:
        """Reject spans too short for the guarantee to mean anything.

        A one- or two-character span (``RN``, ``MD`` -- credentials Presidio types
        as PERSON) carries no re-identification signal, cannot be swept without
        corrupting unrelated words, and sits below the egress gate's own scan floor.
        Vaulting one puts a value in the originals set that the gate will never
        enforce, so the "zero originals in transit" claim would quietly become
        "zero originals, except the ones too short to check". Dropping it here keeps
        the vault's originals set exactly co-extensive with what the gate enforces.

        Entity-type agnostic, so it stays true for any type added by config.
        """
        return len(normalize(detection.text)) >= MIN_SWEEP_LEN

    def _in_scope(self, entity_type: str, doc_category: str | None) -> bool:
        """Registry document-category scoping. Unknown types are never scoped out.

        Applied only when the caller declares a category: a caller that does not
        know the document's category has not asserted anything the engine should
        act on, and silently dropping detections would be worse than trusting the
        detector that produced them.
        """
        if doc_category is None:
            return True
        spec = self._registry.get(entity_type)
        return spec is None or spec.allowed_in(doc_category)

    def _classify(
        self, detection: Detection, *, band_score: float | None = None
    ) -> _Planned | None:
        """Registry action first, then the confidence band. No entity names here.

        ``band_score`` is the score the BAND is decided on -- the maximum across
        every sighting of this ``(entity_type, normalized value)``. It defaults to
        the span's own score so a direct caller keeps the obvious behaviour.
        ``detection.score`` is left untouched either way, because it is evidence
        (what the detector measured here) rather than policy (what we do about it),
        and `_span`, `_record` and the audit detail all read it.
        """
        action = self._registry.action_of(detection.entity_type)
        if action is RegistryAction.STRIP:
            return _Planned(detection, EntityAction.STRIPPED, _REASON_POLICY_STRIP)
        if action is RegistryAction.REDACT:
            return _Planned(detection, EntityAction.REDACTED, _REASON_POLICY_REDACT)

        threshold = self._registry.threshold_for(
            detection.entity_type, self._settings.threshold_obfuscate
        )
        score = detection.score if band_score is None else band_score
        if score >= threshold:
            return _Planned(detection, EntityAction.OBFUSCATED, "")
        if score >= self._settings.threshold_redact:
            return _Planned(detection, EntityAction.REDACTED, _REASON_LOW_CONFIDENCE)
        # Below the redact floor the detector should already have dropped it;
        # dropping again here keeps the engine correct when called directly.
        return None

    # -- surrogate resolution ---------------------------------------------

    async def _resolve_groups(
        self,
        session_id: str,
        session_key: bytes,
        groups: dict[tuple[str, str], _Group],
        requested: str | None,
    ) -> dict[tuple[str, str], TokenRecord]:
        """One vault row and one surrogate per distinct value."""
        strategies: dict[str, ObfuscationStrategy] = {}
        resolved: dict[tuple[str, str], TokenRecord] = {}

        # Every original in THIS document, known before a single surrogate exists.
        # A strategy whose collision guard reads only the vault sees an incomplete
        # picture -- it cannot avoid a value that has not been written yet -- and a
        # fake that collides with a real original is byte-identical to it in the
        # payload, which the egress gate then cannot tell apart from a leak.
        reserved = frozenset(group.normalized for group in groups.values())

        for key, group in groups.items():
            existing = await self._vault.get_by_original(
                session_id, group.entity_type, group.normalized
            )
            if existing is not None:
                # Determinism within a session: the first mapping wins, forever.
                #
                # Deleting this branch changes no byte of any payload -- ``put`` is
                # idempotent per ``(entity_type, normalize(original))`` and the
                # read-back below returns the first record either way. What it does
                # change is that every repeat mention re-derives a value that
                # collides with ITSELF: its token ID is held by its own row, and
                # every fake the guard draws is already vaulted. Measured on a
                # two-entity document, the second call emits five collision
                # warnings where it should emit none -- burying the one real 32-bit
                # collision this system cannot survive. See
                # ``test_a_value_the_session_already_mapped_is_never_re_derived``.
                resolved[key] = existing
                continue

            token_id = await self._unique_token_id(session_id, session_key, group)
            strategy = self._strategy_for(group.entity_type, requested, session_key, strategies)
            strategy.reserved_originals = reserved
            surrogate = await strategy.make_surrogate(
                group.first, token_id, self._vault, session_id=session_id
            )
            await self._vault.put(
                session_id,
                TokenRecord(
                    session_id=session_id,
                    token_id=token_id,
                    entity_type=group.entity_type,
                    category=group.first.category,
                    surrogate=surrogate,
                    created_at=time.time(),
                ),
                group.first.text,
            )
            # The vault is the authority on what was stored; read it back rather
            # than trusting what we passed in. This is what decides which string
            # reaches the payload, because the splice below reads ``records``, not
            # the strategy's return value -- so if anything else vaulted this value
            # first, our ``put`` was a no-op and the surrogate we just rendered is
            # one the vault does not hold. Splicing it would put a token in the
            # payload that ``get_by_surrogate`` cannot resolve. See
            # ``test_the_payload_carries_the_surrogate_the_vault_actually_holds``.
            stored = await self._vault.get_by_original(
                session_id, group.entity_type, group.normalized
            )
            if stored is None:  # pragma: no cover -- put() succeeded, so this cannot happen
                raise PipelineError(
                    reason="vault_put_not_readable", entity_type=group.entity_type[:64]
                )
            if stored.token_id != token_id:  # pragma: no cover -- pre-resolved above
                logger.warning(
                    "vault re-derived a token id after the surrogate was rendered",
                    extra={"entity_type": group.entity_type, "token_id": stored.token_id},
                )
            resolved[key] = stored

        return resolved

    async def _unique_token_id(self, session_id: str, session_key: bytes, group: _Group) -> str:
        """A token ID unused in this session, re-derived with a counter on collision.

        This is *not* a duplicate of the vault's own collision handling. The
        vault protects its primary key and can re-derive the ID after the fact;
        it cannot rewrite the surrogate string the strategy already rendered
        around that ID. Since the restorer keys on the 8-hex core, an ID chosen
        after the surrogate was built would restore the wrong entity. So the
        engine settles the ID first.

        Scope of that guarantee, stated rather than implied: it holds for one
        ``obfuscate`` call at a time on a session. The check below and the
        ``put`` that follows it are separated by ``make_surrogate``, so two
        coroutines obfuscating the *same* session concurrently can both find one
        ID free and both claim it -- and the second ``put`` then re-derives,
        leaving the payload's surrogate built around an ID no vault row carries.
        The read-back in :meth:`_resolve_groups` detects that and logs it; it
        cannot repair it, because the ID is baked into a string already rendered.
        It needs a 32-bit ID collision *and* two concurrent calls on one session,
        so it is a known remote corner, not a covered one.

        That limit is specific to the ID being *inside* the surrogate, and does not
        generalise: in the far likelier race -- two concurrent calls on the same
        *value* -- the read-back repairs completely, because the splice takes the
        stored record's surrogate rather than the one this call rendered. Only the
        ID-collision case is beyond it.
        """
        for counter in range(MAX_TOKEN_COLLISION_RETRIES + 1):
            token_id = derive_token_id(
                session_key, group.entity_type, group.first.text, counter=counter
            )
            try:
                await self._vault.get_by_token(session_id, token_id)
            except VaultMissError:
                if counter:
                    logger.warning(
                        "token id collision re-derived",
                        extra={
                            "entity_type": group.entity_type,
                            "collision_counter": counter,
                            "token_id": token_id,
                        },
                    )
                return token_id
        raise PipelineError(
            reason="token_collision_unresolved",
            entity_type=group.entity_type[:64],
            attempts=MAX_TOKEN_COLLISION_RETRIES,
        )

    def _strategy_for(
        self,
        entity_type: str,
        requested: str | None,
        session_key: bytes,
        cache: dict[str, ObfuscationStrategy],
    ) -> ObfuscationStrategy:
        """Per-entity ``strategy:`` beats the request, which beats ``SCP_STRATEGY``.

        Instances are cached per call because a strategy is bound to the session
        key it was built with.
        """
        spec = self._registry.get(entity_type)
        name = (spec.strategy if spec is not None and spec.strategy else None) or (
            requested or self._settings.strategy
        )
        strategy = cache.get(name)
        if strategy is None:
            strategy = build_strategy(
                name,
                StrategyContext(
                    registry=self._registry, session_key=session_key, settings=self._settings
                ),
            )
            cache[name] = strategy
        return strategy

    # -- audit -------------------------------------------------------------

    async def _audit_result(
        self,
        session_id: str,
        run_id: str | None,
        planned: Sequence[_Planned],
        records: dict[tuple[str, str], TokenRecord],
        requested: str | None,
    ) -> None:
        """One event per obfuscated entity, per redacted span, per stripped span.

        Per-entity rather than per-batch because the compliance requirement is
        "which entity type, which token, what action" -- a batch count cannot
        answer that. Everything here is a type, an ID, a count or a score.
        """
        audit = self._audit
        if audit is None:
            return
        now = time.time()
        # Imported HERE rather than at module scope, and the reason is a real cycle
        # rather than taste: `pipeline.orchestrator` imports this module to build the
        # engine, so a top-level import back would be an `ImportError` at startup.
        # Copying the four-line classifier instead is the thing that must not happen
        # -- it derives the composition through the *same* `_is_pseudonym` shape
        # predicate the pseudonym restore map and `stats["pseudonyms_issued"]` use,
        # and a second copy of that predicate is a second place for the log and the
        # payload to disagree. Same technique as `strategies/base.py`'s deferred
        # `class_hint_for` import.
        from secure_context_pipeline.pipeline.orchestrator import _emitted_strategy

        occurrences: dict[tuple[str, str], int] = {}
        for item in planned:
            if item.action is EntityAction.OBFUSCATED:
                key = (item.detection.entity_type, normalize(item.detection.text))
                occurrences[key] = occurrences.get(key, 0) + 1

        for key, record in records.items():
            spec = self._registry.get(record.entity_type)
            await audit.emit(
                AuditEvent(
                    ts=now,
                    session_id=session_id,
                    run_id=run_id,
                    event_type=OBFUSCATE,
                    entity_type=record.entity_type,
                    token_id=record.token_id,
                    detail={
                        "occurrences": occurrences.get(key, 0),
                        # The REQUEST, resolved through any per-entity override.
                        "strategy": self._strategy_name(record.entity_type, requested),
                        # ...and the OUTCOME, read off the surrogate this row is
                        # about. The two come apart on every reused record: the vault
                        # has no strategy dimension, so a session's second run splices
                        # whatever its first minted, and this row then claimed
                        # `pseudonymization` for a value that went out as a hash
                        # token. Derived per record, so a mixed payload gets a row
                        # apiece that is true rather than one label smeared over both.
                        "emitted_strategy": _emitted_strategy([record]),
                        "tier": spec.tier if spec is not None else 0,
                    },
                )
            )

        for item in planned:
            if item.action is EntityAction.REDACTED:
                await audit.emit(
                    AuditEvent(
                        ts=now,
                        session_id=session_id,
                        run_id=run_id,
                        event_type=REDACT,
                        entity_type=item.detection.entity_type,
                        detail={"score": round(item.detection.score, 4), "reason": item.reason},
                    )
                )
            elif item.action is EntityAction.STRIPPED:
                await audit.emit(
                    AuditEvent(
                        ts=now,
                        session_id=session_id,
                        run_id=run_id,
                        event_type=STRIP,
                        entity_type=item.detection.entity_type,
                        detail={
                            "span_chars": item.detection.end - item.detection.start,
                            "reason": item.reason,
                        },
                    )
                )

    def _strategy_name(self, entity_type: str, requested: str | None) -> str:
        spec = self._registry.get(entity_type)
        name = (spec.strategy if spec is not None and spec.strategy else None) or (
            requested or self._settings.strategy
        )
        return name[:64]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


#: ``surface`` as a literal pattern that cannot match inside a longer word.
#:
#: This is :func:`~secure_context_pipeline.textrules.word_bounded_pattern` under the
#: name the sweep has always used. The sweep previously built the assertions itself
#: from a shared alphabet, which is how it and the gate came to disagree twice while
#: both importing the same constant: sharing ``ALNUM`` catches a rename, not an edit
#: to the rule. Now there is one decision, in one place, and a divergence would be an
#: ``ImportError`` rather than a silent difference of opinion about what a leak is.
#:
#: An empty surface gets a pattern that never matches; both call sites already filter
#: on :data:`MIN_SWEEP_LEN`, so that is a guard rather than a path.
_word_bounded = word_bounded_pattern


def _group(planned: Sequence[_Planned]) -> dict[tuple[str, str], _Group]:
    """Dedupe the obfuscation set by ``(entity_type, normalize(text))``."""
    groups: dict[tuple[str, str], _Group] = {}
    for item in planned:
        if item.action is not EntityAction.OBFUSCATED:
            continue
        detection = item.detection
        key = (detection.entity_type, normalize(detection.text))
        group = groups.get(key)
        if group is None:
            group = _Group(entity_type=key[0], normalized=key[1], first=detection)
            groups[key] = group
        group.spans.append(detection)
    return groups


def _ordered_keys(
    planned: Sequence[_Planned], records: dict[tuple[str, str], TokenRecord]
) -> list[tuple[str, str]]:
    """Distinct group keys in first-appearance order, for a stable ``tokens`` list."""
    seen: dict[tuple[str, str], None] = {}
    for item in planned:
        if item.action is not EntityAction.OBFUSCATED:
            continue
        key = (item.detection.entity_type, normalize(item.detection.text))
        if key in records:
            seen.setdefault(key, None)
    return list(seen)


def _splice(text: str, replacements: Sequence[_Replacement]) -> str:
    """Apply replacements **right to left**, so pending offsets stay valid.

    Accumulating suffix-first and reversing keeps this linear in the text length;
    repeated slice-and-concat would be quadratic on the 12k-word fixture.
    """
    # First pass, left to right: a stripped span leaves the spaces that framed it
    # behind, so swallow one of them -- but never a character a neighbouring span
    # owns, which is why this needs the ordered neighbours and cannot be decided
    # span-locally.
    ordered = sorted(replacements, key=lambda entry: entry.start)
    adjusted: list[_Replacement] = []
    previous_end = 0
    for index, item in enumerate(ordered):
        start, end = item.start, item.end
        if not item.value:
            following = ordered[index + 1].start if index + 1 < len(ordered) else len(text)
            if start > previous_end and text[start - 1] == " ":
                start -= 1
            elif end < following and text[end : end + 1] == " ":
                end += 1
        adjusted.append(_Replacement(start, end, item.value))
        previous_end = end

    pieces: list[str] = []
    cursor = len(text)
    for item in reversed(adjusted):
        pieces.append(text[item.end : cursor])
        pieces.append(item.value)
        cursor = item.start
    pieces.append(text[:cursor])
    pieces.reverse()
    return "".join(pieces)


def _record(detection: Detection) -> RedactionRecord:
    return RedactionRecord(
        entity_type=detection.entity_type,
        start=detection.start,
        end=detection.end,
        score=detection.score,
    )


def _span(detection: Detection, action: EntityAction, surrogate: str | None) -> SpanOut:
    return SpanOut(
        entity_type=detection.entity_type,
        category=detection.category,
        start=detection.start,
        end=detection.end,
        score=detection.score,
        action=action,
        surrogate=surrogate,
    )
