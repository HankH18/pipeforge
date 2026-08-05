"""EgressGate -- the fail-closed leak scanner (build doc section 9.5.3).

This is the security centerpiece. The zero-PII-in-transit guarantee is an
**egress property, not a detection property**: no detector has 100% recall, so the
claim cannot rest on the detector having found everything. Instead, every byte
that is about to leave the process is checked against the set of values we *know*
are sensitive, and anything unexplained blocks the call.

Three passes, of which only the first two were ever independent of the detector:

1. **Original-value scan.** The fully serialized outbound payload is searched for
   every original in the session vault, in raw, normalised, format-character-folded
   and combining-mark-folded form, plus -- for values whose disclosure is carried by
   a long digit run -- with no word-boundary requirement at all
   (:func:`_identifier_needles`), plus -- for an original that is itself a *list* of
   digit-bearing values -- the same four bounded forms again per constituent
   (:func:`_composite_needles`). This catches a splice bug, an un-obfuscated echo,
   or a value the engine missed after detection found it.
2. **Detector re-scan**, skipping spans that are our own surrogates. This catches
   values the detector found *this* time but the engine never vaulted -- and, in
   the adversarial test, values planted directly into the originals set.
3. **Independent-pattern scan** (:data:`_INDEPENDENT_PATTERNS`), over the same
   unprotected text pass 2 examines but with recognisers the detector does not use.
   Pass 2 alone is not a second opinion -- it re-runs the *same* Detector, so a value
   the detector misses is invisible to it for the same reason it was invisible at
   detect time, and pass 1 never learned about it either. Measured, not argued:
   Presidio's ``UsSsnRecognizer.invalidate_result`` scores the canonical example SSNs
   (``123-45-6789``, ``987-65-4320``, ``078-05-1120``), every ``000``/``666`` area
   number, every all-zero group and every mismatched-delimiter spelling at **0.0**, so
   ``Member SSN 123-45-6789`` was never vaulted, never obfuscated, and reached the
   provider in the clear with all three passes silent.

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

**Every path by which a byte can reach the provider**, enumerated, because "the
gate covers the normal path" is not the claim -- one unmediated path and the
headline guarantee is gone. There are eight, and the first is the only one that
carries payload bytes:

1. *The call itself.* ``PipelineOrchestrator.run`` step 7 is the sole invocation of
   a provider anywhere in this package; ``llm/`` is also the only subtree that
   imports a network library at all. It is preceded, in that order, by ``check()``
   and by ``_verify_release``.
2. *Retries.* ``AnthropicProvider`` builds ``system`` and ``messages`` once, before
   the attempt loop, and re-sends the same objects. A retry is the same cleared
   bytes again, never new ones, and every attempt is downstream of one gate pass.
3. *Streaming.* There is none. The non-streaming Messages API is used, and the
   absence of ``stream`` from the request body is asserted on the wire in
   ``tests/test_llm.py``. There is no chunk boundary for a value to straddle.
4. *Timeout and cancellation.* Both abort an in-flight request; neither composes a
   new one. Inside ``check()`` a cancelled scan is an unfinished scan -- see below.
5. *Exceptions.* ``LLMTransportError``/``LLMRefusalError``/``LLMResponseError``
   carry a model name, a machine reason, an attempt count and an HTTP status.
   ``EgressBlockedError`` and the audit rows this module writes carry counts,
   digests and reason codes. No exception, log line or audit detail in this
   module or the orchestrator interpolates payload, original or surrogate text.
6. *Third-party logging.* The SDK logs the whole serialized request body at DEBUG;
   importing ``llm/anthropic_provider.py`` installs a filter that drops it, so a
   host application's ``basicConfig(level=DEBUG)`` cannot turn a log into an egress
   path.
7. *Provider-side transformation after the check.* The only one is the SDK's JSON
   serialization, which is lossless and reversible: it encodes the exact strings the
   gate cleared, and ``tests/test_llm.py`` parses the request body back out of an
   ``httpx.MockTransport`` and compares. It can neither conceal a value the gate saw
   nor introduce one it did not.
8. *The wire dump.* ``demo.py --dump-wire`` captures ``request.content`` and scans
   the literal bytes against the vault's originals before writing them anywhere.

**What pass 1 does and does not promise**, stated as residual risk rather than
implied by omission. It blocks whenever a vaulted original appears in the payload
as a standalone run of text, in any of the compared forms -- including next
to punctuation, markdown, brackets and currency symbols, and including a value
interrupted by any character that renders as nothing: every Unicode format (``Cf``)
codepoint and every default-ignorable, from the zero-width space to the tag block
that carries the ASCII-smuggling vector (see :data:`_INVISIBLE_RE`). It *also*
blocks three shapes that used to walk through, each of which was reachable from an
ordinary uploaded document and each of which was reproduced end-to-end before being
closed:

1. *An identifier glued into a longer alphanumeric run.* ``Brown`` inside
   ``Browning`` is still not an occurrence of ``Brown`` -- treating it as one blocks
   every pseudonymization run on its own well-formed output -- but that boundary rule
   was for years the **only** occurrence test, and the document body is
   attacker-controlled. A vaulted ``TAX_ID`` of ``47-1234567``, detected and
   tokenized from its clean mention, rode out to the provider byte-for-byte inside
   ``batch47-1234567Alpha``; ``MRN: 5567281`` did the same inside ``MRN5567281B``.
   The false-positive trade that justifies the boundary rule is a *name* argument
   (``Brown``/``Browning``), and it does not transfer to a nine-digit identifier, so
   :func:`_identifier_needles` now scans digit-carrying values with no adjacency
   requirement at all. See that function for the exact rule and its cost.
2. *A combining mark spliced into a value.* ``Nathaniel Brightwater`` was vaulted
   from its clean mention and reached the provider as ``Nathaniél
   Brightwater`` -- a different string to every one of the three original forms, and
   identical to ``Nathaniel Brightwater`` for a human reader and for the model. The
   *payload* is now compared in a mark-stripped skeleton form as well
   (:func:`_deaccent`); the needle is deliberately not stripped, which is what keeps
   ``José`` and ``Jose`` distinct values. See :func:`_deaccent`.
3. *One constituent of a composite original.* A vault original is whatever the
   detector called one span, and a span is not always one value: spaCy returns
   ``03/11/2024, 09/17/2024`` as a single ``DATE``, so a string the document contains
   but nobody wrote as a unit became one original -- and every comparison above then
   asked about the composite rather than about the dates in it. This pipeline can
   *manufacture* the fragment, which is what made it worth closing here rather than
   only upstream: a different date in the same document, shifted by the session's
   constant delta, renders as a verbatim word-bounded slice of that original, so a real
   patient date reached the provider inside a string this pipeline invented with pass 1
   and the leakage harness both reporting clean and both correct by their own
   definitions. Detection now splits such a span into one detection per date
   (:func:`~secure_context_pipeline.daterules.split_composite_date`); this pass does not
   rely on that, and derives a needle per constituent itself. The rule is narrow on
   purpose -- see :func:`_composite_needles` for exactly what is excluded and what each
   exclusion costs if it is dropped.

Two gaps remain:

1. *Homoglyph substitution.* Cyrillic U+043E for Latin ``o`` is different bytes;
   catching it needs a confusables table, not another normalisation form. This is
   the same class as the combining mark above and is the obvious next thing to
   close; the difference is that a UTS-39 confusables table is data this project
   does not ship, while ``unicodedata`` already knows what a combining mark is.
2. *A lossy or re-writing encoding layer* (base64, percent-encoding, a
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

Both are detection-recall and upstream-integrity questions rather than scan-form
questions; passes 2 and 3 and the vault are what cover them.

**What the guarantee is, stated so it cannot be read as more than it is.** Pass 1
backstops every value the pipeline *vaulted*, whatever the detector's recall was on
the rest of the document. Passes 2 and 3 backstop high-severity pattern shapes,
whether or not anything vaulted them. What no pass can backstop is a value that is
neither vaulted nor of a shape any recogniser here knows: "zero PII in transit" is
an egress property with respect to the vault, and a recall property with respect to
everything else. Pass 3 exists because the difference between those two sentences
was, until it was added, the whole distance between the headline claim and the code.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Final, NamedTuple, Protocol

from secure_context_pipeline.audit.logger import EGRESS_BLOCK, EGRESS_PASS, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import normalize
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN, EgressBlockedError
from secure_context_pipeline.models import AuditEvent, Detection, EgressReport
from secure_context_pipeline.surrogates import REDACTION_RE, STRICT_TOKEN_RE
from secure_context_pipeline.textrules import delimited_parts, occurs_as_a_unit

__all__ = [
    "AUDIT_EMIT_TIMEOUT_S",
    "DEFAULT_TIMEOUT_S",
    "HIGH_SEVERITY_TYPES",
    "MIN_IDENTIFIER_DIGITS",
    "MIN_IDENTIFIER_RUN_DIGITS",
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
#
# Applied TWICE in _scan_originals, and the two are different questions. On the
# vaulted value it is measured after ``.strip()``, because " ab " is four characters
# of which two are signal and neither of its own ends is alphanumeric -- so no
# boundary assertion applies and it matches inside "The lab ab test", blocking every
# such payload. On each derived form it is measured raw, because normalising and
# folding both shrink a needle and can drop it below the floor after the fact.
MIN_ORIGINAL_LEN = 3

#: How many ASCII digits a vaulted value must carry **in total** before pass 1 scans
#: the whole value as a bare substring -- see :func:`_identifier_needles` for the rule
#: and :func:`_occurs_as_a_unit` for the word-boundary rule being switched off.
#:
#: This floor governs the *whole-value* needle only, the one that keeps separators:
#: ``512-24-8710``, ``(415) 555-0123``. Seven rather than six is what keeps two very
#: common low-entropy shapes out of an unbounded comparison, and both are aggregates
#: of short runs rather than identifiers: a two-digit-year date (``03/12/85``, six
#: digits) and an amount under ``$99,999.99`` (``$1,234.56``, six digits). Scanning
#: those without an adjacency rule blocks on ``Filed 03/12/850`` and
#: ``Line item $1,234.567``, which are ordinary text, not disclosures. Both are pinned
#: by ``test_a_value_below_the_identifier_floor_keeps_the_boundary_rule``.
MIN_IDENTIFIER_DIGITS: Final = 7

#: How long one **contiguous** run of ASCII digits must be before pass 1 scans that
#: run as a bare substring. Six, and it is deliberately *lower* than
#: :data:`MIN_IDENTIFIER_DIGITS` because it answers a different question.
#:
#: These were one constant, and that was a defect of the exact kind this module keeps
#: finding: **one number chosen for one channel's false-positive budget was silently
#: setting another channel's security floor.** Seven was justified against the shapes
#: above -- dates and amounts -- which are aggregates of 2- and 3-digit runs. A
#: *contiguous* six-digit run is not that shape. It is an identifier core, and the
#: shipped registry says so: ``MRN``'s pattern is ``\\K\\d{6,10}``, so the detector
#: vaults six-digit MRNs and the gate then declined to scan them unbounded.
#:
#: That was a live leak, not a theoretical one. Measured on the real detector, the
#: real registry and the real gate, with ``552140`` -- the first row of
#: ``DEV_IDENTIFIER_POSITIVES`` in ``tests/test_detection.py``, a value the detector is
#: *required* to find and vault::
#:
#:     payload:  "Internal routing tag: MRN552140B must match the ledger."
#:     pass 1 bounded forms: miss (the trailing ``B`` denies the right boundary)
#:     pass 1 unbounded:     miss (six digits, below the old single floor)
#:     pass 2:               miss (``MRN``'s pattern ends in ``\\b``, denied by ``B``)
#:     pass 3:               miss (SSN only)
#:     -> RELEASED, with a real vaulted MRN on the wire byte for byte.
#:
#: The false-positive arithmetic at six is run against the right channel this time.
#: :meth:`EgressGate._scan_originals` reads the **outbound payload** and nothing else,
#: and the only run of ``[0-9a-f]`` the pipeline emits into a payload is an 8-hex token
#: ID. A specific six-digit needle lands inside a random 8-hex ID with probability
#: ~3x16^-6 = 1.8e-7; a 251-entity document carries ~251 of them, so a document with
#: five six-digit originals expects 2.2e-4 spurious blocks. A spurious block is also
#: the direction this gate is allowed to be wrong in -- it denies a request, it does
#: not release a value.
#:
#: **The 32-hex ``run_id`` arithmetic that argued for seven belongs to a different
#: scanner.** It is the leakage harness that scans the audit database, where run IDs
#: give a six-digit needle 27 landing sites instead of 3; that floor now lives in
#: ``tests/leakage/test_leakage_harness.py`` under its own name, measured on its own
#: channel. Neither file inherits the other's budget by accident any more.
#:
#: Pinned in both directions: ``test_a_six_digit_identifier_core_glued_to_a_letter_is
#: _blocked`` (the leak above, end to end through the real gate) and
#: ``test_no_shipped_identifier_pattern_can_match_below_the_gate_s_run_floor`` (the
#: registry and this constant can no longer disagree without a red).
MIN_IDENTIFIER_RUN_DIGITS: Final = 6

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
#:
#: The *number* is part of the control, not decoration. The two tests that exercise
#: the wrapper monkeypatch this to 0.05 so they finish quickly, which for a while
#: left the shipped value pinned by nothing at all: raising it to an hour kept the
#: whole gate suite green while restoring exactly the unbounded wait the wrapper was
#: added to remove. ``test_the_block_path_audit_budget_is_short_enough_to_be_a_budget``
#: now reads back the budget the block path actually installs and holds it to a
#: ceiling stated in the test file.
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
        # Offloaded to a worker thread, and that is a correctness fix rather than a
        # performance one. Two things were false while this ran inline:
        #
        # 1. :data:`DEFAULT_TIMEOUT_S` says it is a "budget for one whole check()".
        #    ``asyncio.timeout`` can only fire at a suspension point, and a synchronous
        #    CPU-bound loop has none, so the budget bounded pass 2 and nothing else.
        #    Measured: a 0.5 s budget against a 60k-original scan returned after
        #    **7.35 s**. With the await here, the budget is real for pass 1 too, which
        #    is what makes "hold the request open forever is not a safe answer" true
        #    rather than aspirational.
        # 2. The stall was process-wide, not request-local. This is an ASGI app, so a
        #    scan on the event loop is head-of-line blocking for every concurrent
        #    request: an unrelated coroutine observed a **7.36 s** scheduling gap
        #    during one gate check.
        #
        # The scan is pure -- it reads two immutable arguments and returns an int --
        # so there is nothing to synchronise. A thread cannot be killed mid-scan, so on
        # timeout the request is blocked at the budget while the worker finishes and is
        # discarded; that is the intended semantics, since the alternative is releasing
        # a payload whose scan never completed. Pinned by
        # ``test_the_timeout_bounds_pass_one_and_not_only_the_detector`` and
        # ``test_a_long_pass_one_does_not_stall_unrelated_coroutines``.
        leaked_count = await asyncio.to_thread(self._scan_originals, payload, originals)
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

        # The spans that are our own output. Computed once and handed to both of the
        # payload-side passes: they ask different questions of the same text, and a
        # hole in one that is not a hole in the other would be a bug in the harder
        # direction to see.
        protected = self._protected_spans(payload, surrogates)

        # --- pass 2: detector re-scan, minus our own surrogates ------------
        blocked_types, warnings = await self._rescan(payload, protected)
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

        # --- pass 3: recognisers the detector does not use -----------------
        # Deliberately last, so a payload both passes object to keeps the pass-2
        # reason code it has always had and no existing expectation moves.
        independent = _independent_hits(payload, protected)
        if independent:
            types = _clamp(",".join(sorted(set(independent))))
            await self._emit_block(
                session_id,
                run_id,
                reason="independent_pattern",
                hit_count=len(independent),
                entity_types=types,
            )
            raise EgressBlockedError(
                session_id=_clamp(session_id),
                reason="independent_pattern",
                hit_count=len(independent),
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

        Each original is compared in four bounded forms, and any one of them counts
        as a hit. Each additional form only ever *widens* the scan:

        1. **raw** -- the byte-exact value;
        2. **normalised** -- NFKC, whitespace collapsed, casefolded, so a splice bug
           that changed case or broke a value across a line still trips;
        3. **folded** -- normalised with every character that renders as nothing
           removed (:data:`_INVISIBLE_RE`). Those characters are invisible to a
           human reader and to the model, so ``Joh<U+200B>n Smith`` on the wire
           discloses exactly what ``John Smith`` discloses. Without this form, one
           zero-width space is a complete bypass of pass 1.
        4. **skeleton** -- the folded needle against a folded payload with every
           combining mark removed (:func:`_deaccent`), which is what catches a mark
           spliced into a value. Asymmetric on purpose: only the *haystack* is
           stripped, so ``José`` in the vault still does not match ``Jose`` on the
           wire. Skipped outright when the payload carries no combining mark at all,
           which is the common case and makes this form free there.

        The first three are **not** redundant, and assuming they were is how the
        middle one nearly disappeared unnoticed: on text with no invisible characters,
        folded and normalised are the same needle against the same haystack, so a
        suite whose probes all satisfy two forms at once cannot see the third leave.
        Each has a payload only it can catch, named in a test of its own -- raw:
        ``test_the_raw_form_is_the_only_thing_that_sees_some_leaks`` (``Dr Smith℠``,
        where NFKC expands the symbol and glues an alphanumeric onto the needle in
        both derived forms); normalised:
        ``test_the_normalised_form_is_the_only_thing_that_sees_some_leaks`` (case
        changed, zero-width spaces on both sides, so folding glues the neighbours on);
        folded: the zero-width and default-ignorable parametrizations; skeleton:
        ``test_a_combining_mark_spliced_into_a_value_no_longer_reaches_the_provider``.

        Then, and only for a value that failed all four, the **unbounded identifier
        forms** (:func:`_identifier_needles`): a bare substring test with no adjacency
        requirement, for the digit runs whose disclosure a neighbouring character
        cannot undo. That is a separate step rather than a fifth entry in ``forms``
        because it is the one comparison that is *not* an occurrence-as-a-unit
        question, and writing it as one would hide that.

        Last, for a value that is a **composite** -- two or more values an English list
        glued into one span -- the same four bounded forms again, per constituent
        (:func:`_composite_needles`). A vaulted original is not always one value: the
        detector can hand the engine ``03/11/2024, 09/17/2024`` as a single span, and
        every question above is then being asked about a string the document contains
        but nobody wrote as a unit. Detection now splits that shape upstream
        (:func:`~secure_context_pipeline.daterules.split_composite_date`), which is the
        real fix; this limb is here because the gate's whole posture is that it does
        not trust detection, and "the detector no longer produces composites" is a
        claim about the detector. Constituents go through
        :func:`_occurs_in_any_bounded_form` -- the identical function the whole value
        uses -- so there is no separate question of which forms this limb compares in.

        O(payload x entities), with a C-level substring pre-filter in
        :func:`_occurs_as_a_unit` doing the rejecting; the scale answer is an
        Aho-Corasick automaton built incrementally per session (README Q1).
        """
        payload_norm = normalize(payload)
        payload_folded = _strip_invisible(payload_norm)
        payload_skeleton = _deaccent(payload_folded)
        haystacks = _Haystacks(
            raw=payload,
            normalized=payload_norm,
            folded=payload_folded,
            skeleton=payload_skeleton,
            marked=payload_skeleton != payload_folded,
        )
        hits = 0
        for original in originals:
            if len(original.strip()) < MIN_ORIGINAL_LEN:
                continue
            if _occurs_in_any_bounded_form(original, haystacks):
                hits += 1
                continue
            folded = _strip_invisible(normalize(original))
            if any(needle in payload_skeleton for needle in _identifier_needles(folded)):
                hits += 1
                continue
            if any(
                _occurs_in_any_bounded_form(part, haystacks)
                for part in _composite_needles(original)
            ):
                hits += 1
        return hits

    async def _rescan(
        self, payload: str, protected: list[tuple[int, int]]
    ) -> tuple[list[str], int]:
        """Re-detect on the payload, ignoring spans that are our own output.

        Takes the protected spans rather than the surrogate set because pass 3 needs
        the same list, and computing it twice would let the two passes disagree about
        what our own output is -- the exact class of divergence this module keeps
        finding in itself.

        **This pass is not an independent opinion, and that is why pass 3 exists.**
        It runs the same ``Detector`` that ran at detect time, over text derived from
        the same document, so every blind spot it had then it has again here: a value
        no recogniser anchors on is invisible to detection, never vaulted, therefore
        invisible to pass 1, and invisible here for the third time. That is not a
        hypothetical -- see :data:`_INDEPENDENT_PATTERNS`. What this pass genuinely
        adds is a verdict on text the detector never saw in that arrangement: the
        assembled payload, where obfuscation, splicing and the system prompt have
        moved things around.

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
        Finally, the protected-span set is partly derived by matching a grammar over
        the *uploaded document*, so letting it decide what the detector ever sees
        would hand an uploader a lever on the gate's input -- a strictly larger
        version of the two bypasses :meth:`_protected_spans` exists to close.

        **The re-scan asks for the category-unscoped entity set** (``doc_category``
        is ``None``): the payload is not a document and carries no category, and
        claiming one would be guessing. The cost is that entities declared
        ``only_in_doc_categories`` are not re-detected here -- today ``DATE``,
        ``AMOUNT``, ``CLIENT_IDENTITY`` and ``CASE_STRATEGY``. None of them is in
        :data:`HIGH_SEVERITY_TYPES`, so no *blocking* decision is affected, and pass 1
        still covers every one of them that was vaulted. That last sentence is a claim
        about a *config file* made in a *source file*, which is exactly the shape that
        goes quietly stale, so ``test_no_high_severity_entity_is_scoped_out_of_the_rescan``
        re-derives both sets from the shipped registry and this constant and fails the
        day someone gives a high-severity entity an ``only_in_doc_categories``.

        **A detection is skipped on any overlap with a protected span, not only on
        containment**, and the lenient direction is the deliberate one. The detector
        legitimately returns spans a shade wider than ours -- it claims the whole
        ``[PII_NAME_1a2b3c4d]`` including the closing bracket, while the protected
        core stops at the hash -- so demanding containment would false-block every
        tokenized run on its own placeholders, and a gate that blocks everything
        protects nothing. What makes the leniency affordable is that a protected span
        is now bounded on both sides by characters we chose: it is ``[`` plus one
        unbroken word run, so a value straddling its edge would have to be one the
        detector reads *through* our bracket or our category literal.
        """
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
        re-examined -- so it must cover our output and *only* our output. Two
        independent narrowings are needed to keep that true, because the outbound
        payload is assembled from an *uploaded document* and anything token-shaped in
        that document lands here too.

        **1. The grammar is the one we emit, not the one we tolerate.** The matcher
        is :data:`~secure_context_pipeline.surrogates.STRICT_TOKEN_RE` -- the exact
        shape :func:`~secure_context_pipeline.surrogates.format_surrogate` produces --
        and *not* the tolerant ``TOKEN_RE``. ``TOKEN_RE`` accepts wrong brackets, stray
        whitespace, uppercase hex and ``-`` where we write ``_``, and it accepts them
        for one reason: the restorer reads text an LLM mangled. Nothing on this path
        has been near an LLM. Every token in the payload was written by
        ``format_surrogate`` milliseconds earlier, so here the tolerance buys nothing
        and costs a hole -- one that was open and is worth naming exactly, because it
        is the same shape as the ``|hint`` bypass below, one field to the left. The
        hyphen is the whole mechanism: ``_`` is a regex word character and ``-`` is
        not, so writing the separator as ``-`` manufactures the ``\\b`` that
        ``ACCOUNT_NUMBER``'s pattern needs. An uploaded document containing::

            PII-ACCOUNT12345678-deadbeef

        is a 1.00-confidence ``ACCOUNT_NUMBER`` to the shipped detector, and the
        tolerant matcher excused all of it. Under the strict grammar a protected core
        is ``[`` followed by one unbroken run of word characters beginning with a
        category literal, so it contains no *interior* word boundary at all -- and
        every high-severity recogniser in play, the three registry patterns and
        Presidio's ``US_SSN``, anchors on ``\\b``. That last sentence is a claim about
        a config file and a third-party library, so it is not left as prose:
        ``test_a_high_severity_hit_outside_our_own_output_always_blocks`` runs the
        shipped detector over these shapes and demands the gate's verdict match what
        the detector actually found, which goes red if either side changes.

        **2. The span is the core, never the ``|hint`` tail.** The hint alphabet is
        ``[a-z0-9-]``, which spells an SSN, an EIN and a phone number, so a crafted
        upload containing::

            [PHI_NAME_deadbeef|123-45-6789]

        used to be absorbed as one token match and excluded from the re-scan
        wholesale -- and pass 1 is blind to it too whenever the detector missed that
        value in that odd context, so nothing was left looking at it. Bounding the
        hint to 24 characters shrinks the window; refusing to protect it removes it.

        Re-scanning our own hints costs nothing: a hint is a gazetteer class label we
        chose (``oral-antidiabetic``), not a value, so a detector hit on one is a
        finding worth having rather than a false positive worth suppressing.

        Neither narrowing can cost us a false block on a real token, and the reason is
        deliberately **not** "``format_surrogate`` validates its fields, so its output
        is a ``STRICT_TOKEN_RE`` match by construction". That argument is the tempting
        one and it is not what this rests on: it is a claim about one module's
        validators holding a property that this module needs, with nothing joining
        them. It was once false -- the validators anchored with ``$``, which in Python
        also matches just before a trailing newline, so ``"NAME\\n"`` was an accepted
        entity type that produced a token this matcher rejects, and ``load_registry``
        would take it from a config file. ``surrogates.py`` now anchors ``\\A``/``\\Z``
        and validates with ``fullmatch``, and ``load_registry`` calls
        ``validate_entity_type`` at load, so all three doors are shut.

        The history is recorded in README §8 rather than re-argued here, because a
        docstring that describes a *past* bug has to be re-verified on every refactor
        and nothing re-verifies it. What belongs here is the current contract.

        What the property actually rests on is the other leg: the orchestrator hands
        ``check()`` the exact surrogate strings this run emitted, and those are
        protected in full below by **string equality** -- a stronger claim than any
        regex, since the span then cannot absorb text we did not write, and one no
        grammar drift can weaken.
        ``test_a_surrogate_the_strict_grammar_rejects_is_still_protected`` pins that
        leg on a token this pattern does not recognise, so the mechanism is checked
        rather than asserted.

        The strict matcher is the belt to that pair of braces, and it is what protects
        the token printed in the tokenization system prompt, which belongs to no run.
        One thing it protects with no backstop at all is the **redaction marker**:
        markers are not in the surrogate set, so :data:`REDACTION_RE` is the only
        thing standing behind ``[REDACTED_<TYPE>]``. An entity name that grammar
        rejects leaves our own marker in the re-scan -- more scrutiny rather than
        less, and inert unless the name itself reads as a high-severity identifier --
        but it is a grammar-only guarantee, and the point of writing this down is that
        the token half is not.

        The list is unordered, and deliberately so: :func:`_overlaps` scans it in
        full for every detection, so a sort would cost O(n log n) per call and buy
        nothing. Ordering only starts to matter if that linear scan is ever replaced
        by a search, which is the change that should introduce the sort.
        """
        spans: list[tuple[int, int]] = [
            (m.start(), m.end(3)) for m in STRICT_TOKEN_RE.finditer(payload)
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
#: That sweep can only see the ``Cf`` half, because Python ships no
#: ``Default_Ignorable_Code_Point`` query, and the other half is where a hand-picked
#: list actually goes wrong: a variation selector is ``Mn`` and ``U+3164`` is
#: classed as a *letter*, so neither looks like a control to anyone reading this.
#: ``test_every_default_ignorable_code_point_is_folded`` covers them from a
#: transcription of the standard's own ``DerivedCoreProperties`` ranges.
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


def _deaccent(value: str) -> str:
    """``value`` with every combining mark removed. Applied to the HAYSTACK only.

    :data:`_INVISIBLE_RE` folds characters that render as nothing and deliberately
    stops short of combining diacritics, because a diacritic is *visible* and
    ``José`` and ``Jose`` are two different people. That reasoning is right about the
    needle and wrong about the haystack, and the gap it left was reproduced
    end-to-end rather than argued about: ``Nathaniel Brightwater`` was detected and
    vaulted from a clean mention, a second mention carrying one U+0301 between the
    two names was missed by NER (so never independently vaulted), and it reached the
    provider reading identically to ``Nathaniel Brightwater`` for any human and for
    the model. NFKC does not help -- it *composes*, so ``l`` + U+0301 becomes ``ĺ``,
    which is simply a different letter.

    Stripping only the payload is what makes this safe to add. The comparison
    ``needle in deaccent(payload)`` fires when a mark was spliced into a mark-free
    vaulted value -- the demonstrated attack -- and does not fire when the payload
    legitimately says ``Jose`` and the vault holds ``José``, because the needle keeps
    its accent and ``josé`` is not a substring of ``jose``. Stripping both sides
    would collapse those two into one value and manufacture false blocks on any
    document carrying both spellings, which is the trade
    ``tests/leakage/test_leakage_harness.py`` names and refuses.

    What the asymmetry costs, said plainly: a vaulted value that *itself* carries a
    mark (``José Ruiz``) is not protected against a second mark being spliced into
    it, because the needle is never stripped. That is a strictly smaller residual
    than the one it replaces, and closing it needs the same confusables table the
    homoglyph gap needs.

    NFD-then-strip-then-NFC rather than a character class: the mark can arrive
    precomposed (``ĺ``, U+013A) or as a base plus U+0301, and only decomposition
    makes those the same question. The fast path returns ``value`` unchanged when
    decomposition finds no mark at all, which is every payload that is not carrying
    one -- and every ASCII payload without touching NFC.
    """
    decomposed = unicodedata.normalize("NFD", value)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    if len(stripped) == len(decomposed):
        return value
    return unicodedata.normalize("NFC", stripped)


class _Haystacks(NamedTuple):
    """The four payload forms pass 1 compares against, derived once per scan.

    A tuple rather than four positional arguments because they are always passed
    together and getting two of them the wrong way round is a silent widening or
    narrowing of the scan rather than a type error.
    """

    raw: str
    normalized: str
    folded: str
    skeleton: str
    #: Whether the payload carries a combining mark at all. When it does not, the
    #: skeleton form is the folded form and comparing it again buys nothing.
    marked: bool


def _occurs_in_any_bounded_form(value: str, haystacks: _Haystacks) -> bool:
    """``value`` present in the payload as a unit, in any of the four compared forms.

    The four are documented at :meth:`EgressGate._scan_originals`; this function is
    where they are *applied*, and it exists so that both things pass 1 asks about --
    a whole vaulted original and one constituent of a composite one -- ask in exactly
    the same words. The alternative was a second inline copy of the ``forms`` list for
    the composite limb, i.e. two places that would each have to be edited the next time
    a form is added, which is how this file's siblings acquired the divergences their
    docstrings now record.

    :data:`MIN_ORIGINAL_LEN` is re-checked per *derived* form, not once on the input:
    normalising and folding both shrink a needle and can drop it below the floor after
    the fact.
    """
    normalized = normalize(value)
    folded = _strip_invisible(normalized)
    forms = [
        (value, haystacks.raw),
        (normalized, haystacks.normalized),
        (folded, haystacks.folded),
    ]
    if haystacks.marked:
        forms.append((folded, haystacks.skeleton))
    return any(
        len(needle) >= MIN_ORIGINAL_LEN and _occurs_as_a_unit(needle, haystack)
        for needle, haystack in forms
    )


#: One maximal run of ASCII digits long enough to be an identifier on its own.
_DIGIT_RUN_RE = re.compile(rf"[0-9]{{{MIN_IDENTIFIER_RUN_DIGITS},}}")
_ANY_DIGIT_RE = re.compile(r"[0-9]")


def _identifier_needles(value: str) -> tuple[str, ...]:
    """Forms of ``value`` that disclose it **whatever they are glued to**.

    :func:`_occurs_as_a_unit` refuses to call ``Brown`` inside ``Browning`` an
    occurrence, and it is right to: a generated fake that contains a real surname is
    not a leak, and blocking on it makes pseudonymization unusable. But that argument
    is about *names*, and for years it was the only occurrence test pass 1 had. It
    does not survive contact with a nine-digit identifier, and the document body is
    written by whoever uploads the file:

        The taxpayer EIN 47-1234567 is on file.
        Internal routing tag: batch47-1234567Alpha must match the ledger.

    ``47-1234567`` is detected and tokenized out of line 1, and rides out to the
    provider byte-for-byte in line 2 -- neither swept (the engine's residual sweep
    applies the same boundary rule) nor blocked (pass 1 did too) nor re-detected
    (``TAX_ID``'s pattern anchors on ``\\b``, which ``batch`` denies it). ``batch`` in
    front of it conceals nothing from a reader and nothing from the model.

    So a digit-carrying value is also compared as a bare substring, in two shapes --
    and the two have **different floors**, because they are different claims:

    * **the whole value**, when it contains no letter at all and it carries at least
      :data:`MIN_IDENTIFIER_DIGITS` digits in total -- ``512-24-8710``,
      ``47-1234567``, ``(415) 555-0123``. The separators are part of what is
      disclosed, so the needle keeps them. The floor is seven here because six-digit
      *totals* are mostly dates and amounts (``03/12/85``, ``$1,234.56``), which are
      aggregates of short runs rather than identifiers.
    * **each contiguous digit run of at least :data:`MIN_IDENTIFIER_RUN_DIGITS`**,
      whatever else the value contains. This is the half that matters for a vaulted
      span that includes its own label: ``MRN: 5567281`` never appears in
      ``MRN5567281B``, but ``5567281`` does, and the digits are the secret. It also
      covers ``Account No. 100200300400`` against a bare ``100200300400`` elsewhere
      in the document, and ``BCBS123456789`` against a bare ``123456789``. The floor
      is six here because the shipped registry vaults six-digit MRNs
      (``\\K\\d{6,10}``) and a contiguous six-digit run is an identifier core, not a
      date. See :data:`MIN_IDENTIFIER_RUN_DIGITS` for the leak that proved the two
      floors had to be separate numbers.

    The false-positive risk this accepts is the one the boundary rule was avoiding,
    and it is a different size here. For a name it is ordinary -- Brown/Browning is a
    word list away. For a seven-digit run it needs another number in the payload that
    contains those exact digits contiguously; the arithmetic on the one such run this
    pipeline emits itself (an 8-hex token ID) is in :data:`MIN_IDENTIFIER_DIGITS`.
    Where it does fire on something innocent the result is a blocked request, which
    is the direction this gate is allowed to be wrong in.

    What is in scope is worth stating exactly, because the first draft of this
    docstring said "identifiers" and meant it, and the code says something broader
    and simpler. A value contributes a whole-value needle whenever it is made of
    digits and separators alone and carries seven of them -- which is true of a date
    with a four-digit year (``03/12/1985``, eight digits), of a phone number
    (``(415) 555-0123``), and of an amount over ``$99,999.99``. Those are all values
    a glued neighbour discloses just as completely as it discloses an SSN, and every
    one of them is a HIPAA identifier in a medical record, so the wider rule is the
    right one; it is documented here rather than narrowed because the narrowing
    would have to be a list of shapes, and a list of shapes is the thing this module
    keeps finding it got wrong.

    Values that contribute nothing at all and keep exactly the four bounded forms:
    every name and every value with no digits; short dates (``03/12/85`` -- six
    digits in total, but its longest run is two); amounts below seven digits
    (``$1,234.56`` -- longest run three); docket numbers (``1:23-cv-04567`` --
    letters, and no run reaches six); lab values (``A1C 7.4``).
    """
    if not _ANY_DIGIT_RE.search(value):
        return ()
    stripped = value.strip()
    needles: list[str] = []
    if (
        sum(1 for ch in stripped if "0" <= ch <= "9") >= MIN_IDENTIFIER_DIGITS
        and not any(ch.isalpha() for ch in stripped)
        and len(stripped) >= MIN_ORIGINAL_LEN
    ):
        needles.append(stripped)
    needles.extend(_DIGIT_RUN_RE.findall(stripped))
    return tuple(dict.fromkeys(needles))


def _composite_needles(value: str) -> tuple[str, ...]:
    """The constituents of ``value`` when ``value`` is a *list* of digit-bearing values.

    **The shape this exists for.** A vault original is whatever the detector called one
    span, and a detector span is not always one value. spaCy returns
    ``03/11/2024, 09/17/2024`` as a single ``DATE``, so that composite string -- which
    the document contains but which nobody wrote as a unit -- becomes one original, and
    every other comparison in pass 1 then asks about the composite rather than about
    the dates in it. ``_identifier_needles`` does not rescue it either: its whole-value
    needle is the composite again, and its digit-run needles need six *contiguous*
    digits, while the longest run in that string is four (``2024``). So a payload
    carrying ``03/11/2024`` on its own -- which this pipeline can *manufacture*, by
    shifting a different date in the same document onto it -- passed pass 1 clean, and
    correctly so by pass 1's own definition.

    Detection now splits that span upstream, which is the actual fix. This limb is the
    second opinion: the gate does not get to assume the detector did anything, and
    "composites no longer reach the vault" is a statement about the detector.

    **The rule, and it is deliberately narrow because a block is a denial.** ``value``
    is split on
    :data:`~secure_context_pipeline.textrules.DELIMITER_RE` -- the same grammar
    detection splits on, shared rather than restated -- and contributes needles only
    when it yields **two or more** constituents *and* **every** one of them carries at
    least :data:`MIN_IDENTIFIER_DIGITS` ASCII digits. The needles then keep the
    word-boundary rule; nothing here is compared unbounded.

    **What is excluded, and why each exclusion is load-bearing.** This gate is
    fail-closed, so a false positive is a denied request that looks exactly like a
    leak, and every one of these would have produced them:

    * **Constituents that do not reach the digit floor -- which is every common word.**
      ``April 2024`` must not make ``April`` a needle and ``Park Avenue, Springfield``
      must not make ``Park`` one; a word-bounded needle on an ordinary English word
      denies every payload that happens to use it. Seven digits is not a proxy for
      "identifier" and is not claimed as one -- it is the floor at which a constituent
      stops being a word. It is :data:`MIN_IDENTIFIER_DIGITS` rather than a new number
      because it is the same question that constant already answers: how much digit
      content makes a string specific enough to compare on its own.
    * **Partial qualification.** One constituent below the floor refuses the *whole*
      value, rather than contributing needles for the ones above it. Without that,
      ``Jan 5, 2024`` -- a single date with a comma in it -- would contribute ``2024``,
      and ``2024`` as a word-bounded needle denies essentially every document in the
      corpus. All-or-nothing is also what makes this limb agree with the upstream
      split, which refuses for the same reason.
    * **Bare components of a *non*-composite original.** Vaulted ``John Smith``,
      payload containing ``Smith``, is a real disclosure and is **not** covered here.
      It needs per-entity policy -- a surname is a word, and the leakage harness names
      partial disclosure as outside what it claims for exactly that reason. The
      delimiter requirement is what keeps this rule away from it: whitespace is not a
      delimiter (see :data:`~secure_context_pipeline.textrules.DELIMITER_RE`), so a
      multi-*word* value contributes nothing at all here.
    * **Recursive splitting.** A constituent is taken as it stands and is never split
      again, so no needle here is a fragment of a fragment.
    * **Unbounded comparison.** A constituent is not necessarily an identifier core, so
      it keeps the ``Brown``/``Browning`` boundary rule. The unbounded question is
      :func:`_identifier_needles`'s, and it already reaches inside a composite for any
      digit run long enough to deserve it.

    **The false-positive cost is measured, not asserted.** Over 30 freshly generated
    fixture documents (10 medical, 10 legal, 10 financial) the shipped detector
    returned **1345** spans, of which **211 carried a list delimiter** and **0
    contributed a composite needle** -- because the delimiter-bearing ones are names
    (``Smith, John``), addresses, drug lists and clinical prose, and none of those
    carry seven digits in *every* part. ``$1,234,567.89`` splits into ``$1``, ``234``
    and ``567.89``, all below the floor, which matters because it is an ordinary
    vaulted ``AMOUNT``. The 100-run leakage harness is the thing a spurious block
    would turn red; it was run eight times over this change, 100/100 clean each time.

    That measurement is also the honest summary of what this limb is *for*: on a
    corpus where detection is behaving, it fires on nothing at all. It earns its place
    on the day detection does not.
    """
    if not _ANY_DIGIT_RE.search(value):
        return ()
    parts = delimited_parts(value)
    if len(parts) < 2:
        return ()
    needles: list[str] = []
    for start, end in parts:
        part = value[start:end]
        if sum(1 for ch in part if "0" <= ch <= "9") < MIN_IDENTIFIER_DIGITS:
            return ()
        needles.append(part)
    return tuple(dict.fromkeys(needles))


#: Pass 3's recognisers: high-severity shapes matched by patterns the **detector does
#: not use**, so that a detector miss is not automatically a gate miss.
#:
#: Pass 2 re-runs the same ``Detector`` that ran at detect time. That makes it a
#: second *look*, not a second *opinion*, and the difference is measurable. Presidio's
#: ``UsSsnRecognizer`` scores every candidate through ``invalidate_result``, which
#: returns True -- a hard 0.0, not a low score -- for::
#:
#:     123-45-6789   987-65-4320   078-05-1120     (published example SSNs)
#:     000-xx-xxxx   666-xx-xxxx                   (never-issued area numbers)
#:     xxx-00-xxxx   xxx-xx-0000                   (all-zero group or serial)
#:     111-11-1111                                 (all one digit)
#:     123-45.6789                                 (mismatched delimiters)
#:
#: ``Member SSN 123-45-6789 verified against records.`` therefore reached the provider
#: fully in the clear: never detected, so never vaulted, so nothing for pass 1 to look
#: for, and pass 2 asked the recogniser that had already said no. The registry's own
#: MRN comment admits the general shape of this ("a value neither pattern anchors on
#: is invisible to both"); this constant is the part that stops it being true of the
#: *egress* gate as well as of detection.
#:
#: Scope is deliberately narrow, because pass 3 blocks and a block is a denial:
#:
#: * The **separated** SSN spelling only. A bare ``\\b[0-9]{9}\\b`` rule would fire on
#:   every zip+4, order number and invoice ID in an ordinary document -- the registry
#:   rejects a bare-digit MRN rule for exactly that reason -- and it would fire on
#:   text this pipeline had already handled correctly.
#: * The separator class is ``[-. ]``: Presidio's own, deliberately, because the job
#:   here is to remove Presidio's *validation* blind spot rather than to invent
#:   shapes it never claimed. A spelling outside that class (``123/45/6789``) is not
#:   claimed and is named as residual rather than left to be discovered.
#: * Mismatched separators *are* matched, because rejecting them is one of Presidio's
#:   invalidation rules and therefore one of its blind spots.
#:
#: The space separator was left out of the first version of this constant, on the
#: reasoning that ``100 25 1000`` is a table row and blocking it would be a denial
#: reachable from an ordinary financial document. That reasoning was wrong, and it
#: was wrong in a way worth recording because it is the same mistake this module
#: keeps making -- reasoning about a checker without running the thing it checks.
#: Measured on the shipped detector::
#:
#:     'Ledger row totals 100 25 1000 posted this quarter.'  -> SSN:0.50, BLOCKED
#:     'Member SSN 123 45 6789 verified against records.'    -> nothing,   PASSED
#:
#: Presidio's ``SSN5`` pattern already claims the space spelling at 0.5, so a
#: space-separated table row that is a *valid* SSN has always blocked this pipeline
#: via pass 2. Excluding spaces here therefore bought no false-positive protection at
#: all; all it did was leave the **invalidated** subset -- exactly the example SSNs
#: pass 3 exists for -- able to leave the process, and leave the gate more permissive
#: precisely where Presidio had decided the number was fake. The residual false
#: positives the space class adds are the rows Presidio invalidates and nothing else:
#: an all-zero middle column (``100 00 1000``), an all-zero tail, or a row of one
#: repeated digit.
#:
#: Our own output is exempt by span (:meth:`EgressGate._protected_spans`), which is
#: what keeps a pseudonymized fake SSN -- SSN-shaped by design -- from blocking every
#: run that produces one.
_INDEPENDENT_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("SSN", re.compile(r"\b[0-9]{3}[-. ][0-9]{2}[-. ][0-9]{4}\b")),
)


def _independent_hits(payload: str, protected: list[tuple[int, int]]) -> list[str]:
    """Entity types found by :data:`_INDEPENDENT_PATTERNS` outside our own spans.

    Runs on the raw payload rather than a normalised form because the protected
    spans are raw offsets, and a pass that could not tell our own output apart would
    block every pseudonymization run. The cost is that an SSN split by a zero-width
    character is not seen here; pass 1 sees that one for any value that was vaulted,
    and a value that was neither vaulted nor plainly written is the residual this
    pass narrows rather than closes.
    """
    hits: list[str] = []
    for entity_type, pattern in _INDEPENDENT_PATTERNS:
        for match in pattern.finditer(payload):
            if not _overlaps(match.start(), match.end(), protected):
                hits.append(entity_type)
    return hits


#: The word-boundary occurrence test, owned by
#: :mod:`secure_context_pipeline.textrules` and re-exported here under the name pass 1
#: has always called it. The rule itself -- why the assertions are per-side, why
#: underscore is a boundary, why the ``in`` pre-filter is exact -- is documented at the
#: definition; this module is one of four consumers and deliberately not the owner.
#:
#: **This is not the only occurrence test pass 1 applies**, and the difference matters
#: to anyone reading it as *the* definition of a leak. It is the right rule for a name
#: and the wrong one for an identifier, because the false-positive argument behind it
#: is a word-list argument: ``Browning`` is a real word containing ``Brown``, while
#: ``batch47-1234567Alpha`` is not a real anything containing a taxpayer ID.
#: :func:`_identifier_needles` scans digit-carrying values without this rule for that
#: reason; the engine's residual sweep still applies it, so the two disagree on purpose
#: -- the gate blocks a shape the sweep leaves behind, which is the safe direction for
#: them to differ in.
_occurs_as_a_unit = occurs_as_a_unit
