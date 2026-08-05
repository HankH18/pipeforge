"""EgressGate -- the fail-closed leak scanner (build doc section 9.5.3).

This is the security centerpiece. The zero-PII-in-transit guarantee is an
**egress property, not a detection property**: no detector has 100% recall, so the
claim cannot rest on the detector having found everything. Instead, every byte
that is about to leave the process is checked against the set of values we *know*
are sensitive, and anything unexplained blocks the call.

Two independent passes:

1. **Original-value scan.** The fully serialized outbound payload is searched for
   every original in the session vault, in raw, normalised, and format-character-
   folded form. This catches a splice bug, an un-obfuscated echo, or a value the
   engine missed after detection found it.
2. **Detector re-scan**, skipping spans that are our own surrogates. This catches
   values the detector found *this* time but the engine never vaulted -- and, in
   the adversarial test, values planted directly into the originals set.

The skip-list in pass 2 is load-bearing. Pseudonyms are PII-shaped *by design*: a
fake name is still a name. Without the skip-list every pseudonymization run would
false-positive on its own output.

**Fail-closed** means exactly that: an internal exception in this module blocks
the call. There is no path through ``check()`` that returns normally without both
passes having completed *and* the ``EGRESS_PASS`` record having been written --
every exit is enumerated in :meth:`EgressGate.check`. The second half of that
sentence is conditional on there being a log to write to, and saying so is not a
loophole: ``audit=None`` is a constructor argument, not a runtime state, so it is a
decision an embedder makes once and visibly. Every path that builds this class in
anger passes one (``api/app.py``, ``demo.py``); ``None`` is the no-sink shape unit
tests use, and it changes nothing about either scan.

**What a pass clears is a string, not a request.** The gate is handed bytes and
returns a report identifying those bytes by digest; it has no way to observe what
its caller does next. "The gate ran before the provider call" is therefore a
weaker property than "the gate cleared what the provider received", and only the
second one is the guarantee. Holding the second is the caller's job, and
:meth:`~secure_context_pipeline.pipeline.orchestrator.PipelineOrchestrator._verify_release`
is where this pipeline does it -- by re-deriving the digest from the exact
arguments it hands the provider and refusing to send on a mismatch.

**What pass 1 does and does not promise**, stated as residual risk rather than
implied by omission. It blocks whenever a vaulted original appears in the payload
as a standalone run of text, in any of the three compared forms -- including next
to punctuation, markdown, brackets and currency symbols, and including a value
interrupted by any character that renders as nothing: every Unicode format (``Cf``)
codepoint and every default-ignorable, from the zero-width space to the tag block
that carries the ASCII-smuggling vector (see :data:`_INVISIBLE_RE`). Three gaps
remain:

1. *Embedded in a longer alphanumeric run.* ``Brown`` inside ``Browning`` is not
   an occurrence of ``Brown``, and treating it as one blocks every
   pseudonymization run on its own well-formed output. The same rule means
   ``SSN412-33-7891`` (no separator at all) is not flagged either. This is the
   deliberate trade, it is the same rule the engine's residual sweep applies, and
   the two agreeing is what stops a value being swept everywhere and still
   reported present.
2. *Homoglyph substitution.* Cyrillic U+043E for Latin ``o`` is different bytes;
   catching it needs a confusables table, not another normalisation form.
3. *A lossy or re-writing encoding layer* (base64, percent-encoding, a
   summarizer) applied to outbound text. This pipeline applies none -- the payload
   is assembled from the obfuscated document verbatim -- so this is reachable only
   if some future stage adds one, which would have to bring the gate with it. The
   SDK's JSON serialization is not that stage and is worth saying so out loud,
   because it is the first thing a reviewer points at: it encodes *the exact string
   the gate cleared*, losslessly and reversibly, and the provider decodes it back to
   that string. It can therefore neither conceal a value the gate saw nor introduce
   one it did not. Verified on the wire in ``tests/test_llm.py``, where the request
   body is parsed back out of ``httpx.MockTransport`` and compared to the strings
   handed to the provider.

All three are detection-recall and upstream-integrity questions rather than
scan-form questions; pass 2 and the vault are what cover them.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from collections.abc import Iterable, Sequence
from typing import Final, Protocol

from secure_context_pipeline.audit.logger import EGRESS_BLOCK, EGRESS_PASS, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import normalize
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN, EgressBlockedError
from secure_context_pipeline.models import AuditEvent, Detection, EgressReport
from secure_context_pipeline.surrogates import REDACTION_RE, TOKEN_RE

__all__ = [
    "AUDIT_EMIT_TIMEOUT_S",
    "DEFAULT_TIMEOUT_S",
    "HIGH_SEVERITY_TYPES",
    "MIN_ORIGINAL_LEN",
    "EgressGate",
]

logger = logging.getLogger(__name__)

# Pattern-typed entities with near-zero false-positive rates. A re-scan hit on one
# of these is treated as a real leak and blocks. NER-typed re-hits (names the fake
# generator produced contextually) are logged as warnings instead -- blocking on
# those would make pseudonymization unusable without improving the guarantee.
HIGH_SEVERITY_TYPES = frozenset({"SSN", "MRN", "ACCOUNT_NUMBER", "TAX_ID"})

# Originals shorter than this are not scanned for. A one- or two-character value
# carries no re-identification signal on its own and would match inside almost any
# payload, blocking every call. Stated as a known limitation in the README.
MIN_ORIGINAL_LEN = 3

#: Wall-clock budget for one whole ``check()``. Exceeding it blocks, because a
#: detector that never returns is indistinguishable from one that has not finished
#: yet, and "hold the request open forever" is not a safe answer to either. The
#: budget is generous by well over an order of magnitude: 20k originals against a
#: 54 KB payload complete pass 1 in roughly one second.
DEFAULT_TIMEOUT_S: Final = 30.0

#: Budget for one audit write made *by the gate*. Separate from
#: :data:`DEFAULT_TIMEOUT_S` because the block-path write in
#: :meth:`EgressGate._emit_block` runs from inside ``check()``'s exception handler,
#: which is outside the ``asyncio.timeout`` block and therefore had no budget at
#: all: a wedged audit writer -- an ``asyncio.Lock`` held by a hung coroutine, a
#: stalled fsync -- held the request open forever *after* the decision to block had
#: already been made. Nothing leaks in that state, but "blocked" and "never
#: answered" are different outcomes and only one of them is a security control.
AUDIT_EMIT_TIMEOUT_S: Final = 5.0


class VaultLike(Protocol):
    """The only vault capability the gate needs -- sync and O(1) on the hot path."""

    def originals_for_session(self, session_id: str) -> frozenset[str]: ...


class DetectorLike(Protocol):
    """The only detector capability the gate needs."""

    async def detect(
        self, text: str, doc_category: str | None = None
    ) -> Sequence[Detection]: ...


class EgressGate:
    def __init__(
        self,
        *,
        vault: VaultLike,
        detector: DetectorLike,
        settings: Settings,
        audit: AuditLogger | None = None,
        high_severity: Iterable[str] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._vault = vault
        self._detector = detector
        self._settings = settings
        self._audit = audit
        self._high_severity = frozenset(high_severity) if high_severity else HIGH_SEVERITY_TYPES
        self._timeout_s = timeout_s

    async def check(
        self,
        payload: str,
        session_id: str,
        *,
        surrogates: frozenset[str] = frozenset(),
        run_id: str | None = None,
    ) -> EgressReport:
        """Scan the outbound payload. Returns on pass; raises on ANY doubt.

        NOTE (deviation from the build doc's ``def check(...)`` signature): this is
        ``async`` because pass 2 runs the detector, which offloads spaCy to a worker
        thread. A synchronous gate would either block the event loop or skip the
        re-scan; both are worse than the signature change.

        Every exit from this method is enumerated here, and only the first releases
        the payload:

        * both passes clean *and* ``EGRESS_PASS`` recorded -> return an ``EgressReport``;
        * pass 1 or pass 2 hit -> ``EgressBlockedError(vault_original|detector_rescan)``;
        * anything else raised inside -- vault, detector, audit, the timeout, a bug
          in this module -> ``EgressBlockedError(gate_exception)``;
        * ``asyncio.CancelledError`` -- a ``BaseException``, so neither ``except``
          clause here can absorb it -- propagates, and there is no ``return`` on
          that path either. A cancelled scan is an unfinished scan, never a pass.

        Both ``except`` clauses are exhaustive over ``Exception`` by construction:
        the first re-raises the one error type that already *is* a block, and the
        second converts everything else into one. ``BaseException`` is deliberately
        not caught -- catching it would be the only way to turn an abort into a
        release, and there is no code here that does.

        Recording the pass is inside the guarded region deliberately. A payload whose
        release we cannot evidence is a payload we do not release, so an audit failure
        blocks rather than releasing silently.

        The block-path audit write is *not* inside the ``asyncio.timeout`` block --
        it runs from the exception handler -- so it carries its own budget; see
        :data:`AUDIT_EMIT_TIMEOUT_S`.

        Returning normally is not the only thing a caller must check: it clears
        *these bytes*. The report's ``payload_sha256`` is what a caller uses to
        prove the string it goes on to send is the string that was cleared, which
        :meth:`~secure_context_pipeline.pipeline.orchestrator.PipelineOrchestrator._verify_release`
        does before the provider call.
        """
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self._timeout_s):
                report = await self._run_passes(payload, session_id, surrogates, run_id, started)
                await self._emit_pass(session_id, run_id, report)
        except EgressBlockedError:
            raise
        except Exception as exc:
            logger.error(
                "egress gate failed internally; blocking",
                extra={"session_id": session_id, "run_id": run_id, "error": type(exc).__name__},
            )
            await self._emit_block(session_id, run_id, reason="gate_exception", hit_count=0)
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="gate_exception",
                hit_count=0,
                run_id=None if run_id is None else _clamp(run_id),
            ) from exc

        return report

    # ------------------------------------------------------------------
    async def _run_passes(
        self,
        payload: str,
        session_id: str,
        surrogates: frozenset[str],
        run_id: str | None,
        started: float,
    ) -> EgressReport:
        originals = self._vault.originals_for_session(session_id)

        # --- pass 1: known originals, raw and normalised -------------------
        leaked_count = self._scan_originals(payload, originals)
        if leaked_count:
            await self._emit_block(
                session_id, run_id, reason="vault_original", hit_count=leaked_count
            )
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="vault_original",
                hit_count=leaked_count,
                run_id=None if run_id is None else _clamp(run_id),
            )

        # --- pass 2: detector re-scan, minus our own surrogates ------------
        blocked_types, warnings = await self._rescan(payload, surrogates)
        if blocked_types:
            types = _clamp(",".join(sorted(set(blocked_types))))
            await self._emit_block(
                session_id,
                run_id,
                reason="detector_rescan",
                hit_count=len(blocked_types),
                entity_types=types,
            )
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="detector_rescan",
                hit_count=len(blocked_types),
                entity_types=types,
                run_id=None if run_id is None else _clamp(run_id),
            )

        return EgressReport(
            payload_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            payload_chars=len(payload),
            originals_scanned=len(originals),
            rescan_warnings=warnings,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    def _scan_originals(self, payload: str, originals: frozenset[str]) -> int:
        """Count originals present in the payload. Never records WHICH value matched.

        Deliberately scans the **raw** payload, with no exemption for spans this
        pipeline emitted -- there is no ``surrogates`` argument here on purpose. An
        earlier version masked out its own surrogates so that a coincidental
        pseudonym collision would not block, and that was a mistake worth recording:
        a fake drawn as "Rachel Medina" while "Medina" is a real original puts that
        surname verbatim on the wire, and masking the surrogate span *hid* the leak
        instead of explaining it. The 100-run harness caught it.

        The exemption belongs upstream, where it can be made true rather than
        assumed: the pseudonymization collision guard now rejects any fake sharing a
        word with any original in the document, so the gate is free to stay maximally
        strict here. Pass 2 keeps its skip-list because a *detector* re-hit on a
        well-formed fake is a different question from a byte-exact original.

        Each original is compared in three forms, and any one of them counts as a
        hit. Each additional form only ever *widens* the scan:

        1. **raw** -- the byte-exact value;
        2. **normalised** -- NFKC, whitespace collapsed, casefolded, so a splice bug
           that changed case or broke a value across a line still trips;
        3. **folded** -- normalised with every character that renders as nothing
           removed (:data:`_INVISIBLE_RE`). Those characters are invisible to a
           human reader and to the model, so ``Joh<U+200B>n Smith`` on the wire
           discloses exactly what ``John Smith`` discloses. Without this form, one
           zero-width space is a complete bypass of pass 1.

        O(payload x entities), with a C-level substring pre-filter in
        :func:`_occurs_as_a_unit` doing the rejecting; the scale answer is an
        Aho-Corasick automaton built incrementally per session (README Q1).
        """
        payload_norm = normalize(payload)
        payload_folded = _strip_invisible(payload_norm)
        hits = 0
        for original in originals:
            if len(original.strip()) < MIN_ORIGINAL_LEN:
                continue
            normalized = normalize(original)
            folded = _strip_invisible(normalized)
            forms = (
                (original, payload),
                (normalized, payload_norm),
                (folded, payload_folded),
            )
            if any(
                len(needle) >= MIN_ORIGINAL_LEN and _occurs_as_a_unit(needle, haystack)
                for needle, haystack in forms
            ):
                hits += 1
        return hits

    async def _rescan(
        self, payload: str, surrogates: frozenset[str]
    ) -> tuple[list[str], int]:
        """Re-detect on the payload, ignoring spans that are our own output.

        Two properties of this pass are easy to misread, so both are stated here.

        **The detector runs over the whole payload, and the skip-list is applied to
        its output rather than to its input.** That ordering is the safe one and it
        was measured rather than assumed. Excising the protected spans first -- the
        obvious optimisation, and the one README Q1 used to promise -- changes what
        the detector finds in the text that *remains*: spaCy NER is conditioned on
        surrounding tokens, this project's own ``_resolve_builtin`` picks between
        claimant entity types using character-distance context windows, and removing
        ~23% of the payload's characters moves every chunk boundary. Measured across
        both strategies and three fixtures, the excised scan lost a finding the
        full-payload scan makes in four of six configurations and *gained* one in
        another, so it is a different scan, not a cheaper one. It is also worth
        little: protected spans cover 16-26% of a payload (not the ~95% previously
        claimed) and excision saves 5-6% of this pass, ~2% of end-to-end wall time.
        Finally, the protected-span set is partly derived from ``TOKEN_RE`` over the
        *uploaded document*, so letting it decide what the detector ever sees would
        hand an uploader a lever on the gate's input -- a strictly larger version of
        the token-hint bypass :meth:`_protected_spans` exists to close.

        **The re-scan asks for the category-unscoped entity set** (``doc_category``
        is ``None``): the payload is not a document and carries no category, and
        claiming one would be guessing. The cost is that entities declared
        ``only_in_doc_categories`` are not re-detected here -- today ``DATE``,
        ``AMOUNT``, ``CLIENT_IDENTITY`` and ``CASE_STRATEGY``. None of them is in
        :data:`HIGH_SEVERITY_TYPES`, so no *blocking* decision is affected, and pass 1
        still covers every one of them that was vaulted. It does mean a future
        category-scoped high-severity entity would be invisible to this pass, which
        is a property of the registry rather than of this code, and is why the
        blocking set is documented as a tuning table.
        """
        protected = self._protected_spans(payload, surrogates)
        detections = await self._detector.detect(payload, None)

        blocked: list[str] = []
        warnings = 0
        for det in detections:
            if det.score < self._settings.threshold_obfuscate:
                continue
            if _overlaps(det.start, det.end, protected):
                continue
            if det.entity_type in self._high_severity:
                blocked.append(det.entity_type)
            else:
                # NER-typed re-hit: a fake name the generator produced contextually.
                # Logged, not blocked -- blocking here would make pseudonymization
                # unusable without improving the guarantee.
                warnings += 1
        return blocked, warnings

    @staticmethod
    def _protected_spans(payload: str, surrogates: frozenset[str]) -> list[tuple[int, int]]:
        """Spans that are our own output: tokens, redaction markers, and surrogates.

        A protected span is a hole in pass 2 -- whatever it covers is never
        re-examined -- so it must cover our output and *only* our output.

        For :data:`TOKEN_RE` matches that means the **core**, ``[CATEGORY_TYPE_hash``,
        and never the ``|hint`` tail. The distinction is not cosmetic. ``TOKEN_RE`` is
        deliberately tolerant so it can recognise a token an LLM mangled, and it runs
        over text this pipeline did not write: the outbound payload is assembled from
        an *uploaded document*, so anything token-shaped in that document matches too.
        The hint alphabet is ``[a-z0-9-]``, which spells an SSN, an EIN and a phone
        number, so a crafted upload containing::

            [PHI_NAME_deadbeef|123-45-6789]

        used to be absorbed as one token match and excluded from the re-scan
        wholesale -- and pass 1 is blind to it too whenever the detector missed that
        value in that odd context, so nothing was left looking at it. Bounding the
        hint to 24 characters shrinks the window; refusing to protect it closes the
        shape, regardless of what the grammar is later relaxed to permit.

        Re-scanning our own hints costs nothing: a hint is a gazetteer class label we
        chose (``oral-antidiabetic``), not a value, so a detector hit on one is a
        finding worth having rather than a false positive worth suppressing.

        Surrogates are protected in full, and that is not the same trade: those
        strings are matched by exact equality against what the engine actually
        emitted this run, so the span cannot absorb text we did not write.

        The list is unordered, and deliberately so: :func:`_overlaps` scans it in
        full for every detection, so a sort would cost O(n log n) per call and buy
        nothing. Ordering only starts to matter if that linear scan is ever replaced
        by a search, which is the change that should introduce the sort.
        """
        spans: list[tuple[int, int]] = [
            (m.start(), m.end(3)) for m in TOKEN_RE.finditer(payload)
        ]
        spans.extend(m.span() for m in REDACTION_RE.finditer(payload))
        for surrogate in surrogates:
            if not surrogate:
                continue
            idx = payload.find(surrogate)
            while idx != -1:
                spans.append((idx, idx + len(surrogate)))
                idx = payload.find(surrogate, idx + 1)
        return spans

    # ------------------------------------------------------------------
    async def _emit_pass(self, session_id: str, run_id: str | None, report: EgressReport) -> None:
        if self._audit is None:
            return
        await self._audit.emit(
            AuditEvent(
                ts=time.time(),
                session_id=session_id,
                run_id=run_id,
                event_type=EGRESS_PASS,
                detail={
                    # sha256 hex is exactly 64 chars -- fits the audit detail ceiling.
                    "payload_sha256": report.payload_sha256,
                    "payload_chars": report.payload_chars,
                    "originals_scanned": report.originals_scanned,
                    "rescan_warnings": report.rescan_warnings,
                    "elapsed_ms": round(report.elapsed_ms, 3),
                },
            )
        )

    async def _emit_block(
        self,
        session_id: str,
        run_id: str | None,
        *,
        reason: str,
        hit_count: int,
        entity_types: str = "",
    ) -> None:
        """Record the block. **Never raises, and never blocks for long.**

        This runs on the way to raising ``EgressBlockedError``, so an exception
        escaping here would replace a well-typed block carrying its reason with
        whatever the audit layer threw. The call is stopped either way, but the
        caller (the API's 422 ``EGRESS_BLOCKED`` handler) would see an internal
        error instead of a block, and the reason code would be lost. The block
        itself is already guaranteed by the raise; recording it is best-effort, and
        a failure is loud in the process log.

        The write is bounded by :data:`AUDIT_EMIT_TIMEOUT_S` for the same reason it
        is wrapped at all. On the ``gate_exception`` path this coroutine is awaited
        from ``check()``'s exception handler, which sits *outside* the
        ``asyncio.timeout`` block, so an audit writer that hangs rather than fails
        used to hold the request open indefinitely with the block already decided.
        ``TimeoutError`` is an ``Exception``, so it lands in the same handler as any
        other audit failure and the block proceeds unchanged.
        """
        logger.warning(
            "EGRESS BLOCKED -- provider call suppressed",
            extra={
                "session_id": session_id,
                "run_id": run_id,
                "reason": reason,
                "hit_count": hit_count,
            },
        )
        if self._audit is None:
            return
        try:
            async with asyncio.timeout(AUDIT_EMIT_TIMEOUT_S):
                await self._audit.emit(
                    AuditEvent(
                        ts=time.time(),
                        session_id=_clamp(session_id),
                        run_id=None if run_id is None else _clamp(run_id),
                        event_type=EGRESS_BLOCK,
                        detail={
                            "reason": reason,
                            "hit_count": hit_count,
                            "entity_types": entity_types,
                        },
                    )
                )
        except Exception as exc:  # the block must survive an audit-layer failure
            logger.error(
                "egress block could not be audited; the block itself still stands",
                extra={
                    "session_id": session_id,
                    "run_id": run_id,
                    "reason": reason,
                    "error": type(exc).__name__,
                },
            )


def _clamp(value: str) -> str:
    """Trim an identifier to the shared 64-character detail ceiling.

    ``PipelineError`` refuses any detail string longer than this, so an oversized
    ``session_id`` would turn the ``EgressBlockedError`` construction itself into a
    ``ValueError`` -- the payload is still withheld, but the caller sees an internal
    error rather than ``EGRESS_BLOCKED`` and the reason code never reaches the audit
    trail.
    """
    return value[:MAX_DETAIL_VALUE_LEN]


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < s_end and end > s_start for s_start, s_end in spans)


#: A word character for boundary purposes, **excluding underscore**. Regex ``\w``
#: counts ``_`` as a word character, which hands markdown a free bypass: the emphasis
#: form ``_John Smith_`` puts the original on the wire byte-for-byte while
#: ``(?<!\w)John Smith(?!\w)`` refuses to match it. Underscore is punctuation in prose,
#: so it is a boundary here.
_ALNUM = r"[^\W_]"
_ALNUM_RE = re.compile(_ALNUM)

#: Characters that render as nothing, so a value carrying one discloses exactly what
#: the clean value discloses -- ``John`` and ``Joh<U+200B>n`` are the same disclosure
#: to any reader and to the model. Stripping them before the folded comparison closes
#: what is otherwise a **one-character complete bypass** of pass 1.
#:
#: The set is defined by a Unicode property rather than by taste: every general
#: category ``Cf`` (format) codepoint, plus every non-``Cf`` member of
#: ``Default_Ignorable_Code_Point`` -- variation selectors, the Hangul and Khmer
#: fillers, the combining grapheme joiner. A hand-picked list is the wrong shape here
#: and shipped as one: it named the bidi *overrides* (U+202A-U+202E) but not the bidi
#: *isolates* (U+2066-U+2069) that replaced them, and it named no tag character at
#: all, so ``Joh<U+E0041>n Smith`` -- the standard ASCII-smuggling vector -- walked
#: through the fold and out to the provider. 145 format codepoints were uncovered.
#:
#: Widening only ever *widens*: a stripped form is one more needle OR'd into the
#: comparison in :meth:`EgressGate._scan_originals`, never a replacement for the raw
#: one, so nothing that blocked before stops blocking. It is bounded in the other
#: direction too -- no letter, digit, space or combining *diacritic* is in here, so
#: ``Jos\u00e9`` and ``Jose`` remain different values.
#:
#: Ranges are widened to whole reserved runs (U+2060-U+206F, U+FFF0-U+FFFB,
#: U+13430-U+1343F, U+E0000-U+E0FFF) so a Unicode release that assigns a format
#: character inside one is covered the day it lands rather than the day someone
#: notices. ``test_every_unicode_format_character_is_folded`` re-derives the ``Cf``
#: set from :mod:`unicodedata` and fails on anything this class still misses -- the
#: expectation comes from the Unicode database, not from a copy of this literal.
#:
#: Written as escapes on purpose: a literal zero-width character in this source file
#: would be invisible to the next reader of the very guard that removes it.
_INVISIBLE_RE = re.compile(
    "["
    r"\u00ad"  # soft hyphen
    r"\u034f"  # combining grapheme joiner
    r"\u0600-\u0605\u06dd\u070f\u0890-\u0891\u08e2"  # Arabic/Syriac subtending marks
    r"\u061c"  # Arabic letter mark
    r"\u115f-\u1160"  # Hangul choseong/jungseong fillers
    r"\u17b4-\u17b5"  # Khmer inherent vowels
    r"\u180b-\u180f"  # Mongolian variation selectors + vowel separator
    r"\u200b-\u200f"  # zero-width space/joiners, LRM, RLM
    r"\u202a-\u202e"  # bidi embeddings and overrides
    r"\u2060-\u206f"  # word joiner, invisible operators, bidi isolates, deprecated
    r"\u3164"  # Hangul filler
    r"\ufe00-\ufe0f"  # variation selectors 1-16
    r"\ufeff"  # zero-width no-break space / BOM
    r"\uffa0"  # halfwidth Hangul filler
    r"\ufff0-\ufffb"  # reserved + interlinear annotation anchors
    r"\U000110bd\U000110cd"  # Kaithi number signs
    r"\U00013430-\U0001343f"  # Egyptian hieroglyph format controls
    r"\U0001bca0-\U0001bca3"  # shorthand format controls
    r"\U0001d173-\U0001d17a"  # musical beam/phrase controls
    r"\U000e0000-\U000e0fff"  # language tags, tag characters, VS supplement
    "]"
)


def _strip_invisible(value: str) -> str:
    return _INVISIBLE_RE.sub("", value)


def _occurs_as_a_unit(needle: str, haystack: str) -> bool:
    """Whether ``needle`` appears in ``haystack`` as a unit rather than inside a word.

    Raw substring matching produces false blocks that look exactly like leaks. The
    surname ``Brown`` is a real original; a generated fake surname ``Browning``
    contains it, and a naive ``"brown" in payload`` reports a leak that is not one.
    The 100-run harness surfaced this and it cost real time to tell apart from the
    genuine substring leak it resembles.

    The boundary assertions are therefore applied **per side, and only where they
    mean something** -- a ``\\b``-style guard is only about telling one word from a
    longer word:

    * a side whose adjacent needle character is alphanumeric gets the assertion, so
      ``Brown`` still does not match inside ``Browning``;
    * a side whose adjacent needle character is *not* alphanumeric gets none. The
      earlier unconditional ``(?<!\\w)...(?!\\w)`` asked whether the character before
      ``(`` in ``(415) 555-0123`` was a word character, which has nothing to do with
      word boundaries: it silently passed ``tel(415) 555-0123``, ``USD$1,234.56`` and
      ``Ph.D.degree`` -- each of which carries the original verbatim.

    Underscore counts as a boundary (see :data:`_ALNUM`), which is what makes the
    markdown form ``_John Smith_`` block.

    Because every match requires the literal needle to be present, ``needle in
    haystack`` is an exact pre-filter, not an approximation. It is roughly 40x
    faster than the regex on the overwhelmingly common miss, which is what keeps a
    large per-session originals set off the critical path (20k originals against a
    54 KB payload: ~31 s before, ~1 s after).
    """
    if not needle or needle not in haystack:
        return False
    left = f"(?<!{_ALNUM})" if _ALNUM_RE.match(needle[0]) else ""
    right = f"(?!{_ALNUM})" if _ALNUM_RE.match(needle[-1]) else ""
    if not left and not right:
        return True
    return re.search(left + re.escape(needle) + right, haystack) is not None
