"""PipelineOrchestrator -- the end-to-end round trip (build doc sections 9.5.1 and 4).

    fetch+decrypt -> detect -> obfuscate -> inject -> EGRESS GATE -> provider -> restore

**Two inputs go through detect -> obfuscate, not one.** The outbound payload is
``{system prompt} + {user prompt} + {obfuscated document}``, so the user prompt is
as much an egress channel as the document is, and for a long time only the document
was treated as one: the prompt was interpolated raw. It was *scanned* -- it is inside
``InjectedPayload.serialized``, which is the string the gate is handed -- but pass 1
only knows values the vault learned from the document, and pass 2 blocks on
:data:`~secure_context_pipeline.pipeline.egress_gate.HIGH_SEVERITY_TYPES` alone, so a
name, a date of birth, an email address or a street address typed into the prompt box
was seen, counted as a ``rescan_warnings`` increment, and shipped. Measured over HTTP
against the real app, with values appearing nowhere in the document::

    NAME       SENT 200  verbatim-in-outbound-payload=True
    DOB        SENT 200  verbatim-in-outbound-payload=True
    EMAIL      SENT 200  verbatim-in-outbound-payload=True
    ADDRESS    SENT 200  verbatim-in-outbound-payload=True
    PHONE      SENT 200  verbatim-in-outbound-payload=True
    DIAGNOSIS  SENT 200  verbatim-in-outbound-payload=True

"The user typed it themselves" is not a defence when the product's one claim is that
no original value reaches the provider: the user is not the party the guarantee
protects, the data subject is, and in the deployment this models the two are
different people. So the prompt is now a first-class input -- see
:meth:`PipelineOrchestrator._detect_and_obfuscate_prompt` for the ordering and for
what that does and does not buy.

Every stage is timed, and every audit event emitted anywhere in the run carries the
same ``run_id``. That single ID is what lets a compliance query reconstruct the
complete detect -> obfuscate -> egress -> LLM -> restore chain for one request.

The ordering is a security property, not a convenience: the provider call is made
*only* on the far side of a passing egress check, and ``EgressBlockedError``
propagates out of ``run()`` before any network call is constructed.

Ordering alone is not quite the whole property, though, and the gap is worth
naming. "The gate ran first" and "the gate cleared *what we sent*" are different
claims, and only the second one is the guarantee. Between the check and the
provider call there is a window in which a later maintainer could reasonably add a
stage -- a prefill, a truncation, a header -- and the ordering test would still
pass while the released bytes were no longer the audited ones. ``run()`` therefore
re-derives the outbound string from the exact arguments it hands the provider and
compares it against the digest the gate recorded; see :meth:`_verify_release`.

The gate answers "did an original leave?". It cannot answer "did the right value
come back?", and that is the other way a run goes wrong invisibly: two originals
issued one surrogate restore to a single value, so one entity's identifier is
printed where another's belongs. :func:`_assert_surrogates_are_distinct` refuses
that run, at step 4d -- before the payload is even assembled.
"""

from __future__ import annotations

import hashlib
import logging
import time
import unicodedata
import uuid
from collections.abc import Sequence

from secure_context_pipeline.audit.logger import (
    DETECT,
    EGRESS_BLOCK,
    LLM_CALL,
    AuditLogger,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
    EgressBlockedError,
    PipelineError,
)
from secure_context_pipeline.llm.base import DetailedLLMProvider
from secure_context_pipeline.models import (
    AuditEvent,
    Detection,
    ObfuscationResult,
    PipelineResult,
    TokenRecord,
)
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.surrogates import STRICT_TOKEN_RE
from secure_context_pipeline.vault.session_vault import SessionVault

__all__ = ["PipelineOrchestrator"]

logger = logging.getLogger(__name__)

#: Page size for reading this run's audit sequence numbers back. See
#: :meth:`PipelineOrchestrator._collect_seq`.
_AUDIT_PAGE = 1000


class PipelineOrchestrator:
    def __init__(
        self,
        *,
        store: EncryptedDocumentStore,
        detector: Detector,
        engine: ObfuscationEngine,
        injector: ContextInjector,
        gate: EgressGate,
        provider: DetailedLLMProvider,
        restorer: Restorer,
        vault: SessionVault,
        settings: Settings,
        audit: AuditLogger | None = None,
    ) -> None:
        self._store = store
        self._detector = detector
        self._engine = engine
        self._injector = injector
        self._gate = gate
        self._provider = provider
        self._restorer = restorer
        self._vault = vault
        self._settings = settings
        self._audit = audit

    async def run(
        self,
        session_id: str,
        user_id: str,
        doc_id: str,
        user_prompt: str,
        strategy: str | None = None,
    ) -> PipelineResult:
        run_id = uuid.uuid4().hex
        chosen = strategy or self._settings.strategy
        stats: dict[str, float] = {}
        t0 = time.perf_counter()

        # The document gets canonical composition in `extraction._normalise`, which
        # is the choke point every stored document passes through. The prompt has no
        # such choke point -- it arrives on the request and goes straight to the
        # detector -- so it is composed here, for the reason spelled out at length
        # in that function: spaCy does not merely score an NFD name lower, it stops
        # emitting the span, and an entity that is never detected is never vaulted,
        # which means no pass of the gate has a needle to look for. Since 3b made
        # the prompt a first-class egress channel, leaving it uncomposed would put
        # the hole straight back in the input the user types by hand -- and typing
        # is precisely where a composed-vs-decomposed accent is decided by the OS's
        # keyboard layout rather than by anyone's intent.
        user_prompt = unicodedata.normalize("NFC", user_prompt)

        # 1-2. Fetch + decrypt. A wrong user's derived key fails GCM auth, which the
        #      store surfaces as NOT_FOUND -- no existence oracle.
        mark = time.perf_counter()
        text = await self._store.get_text(user_id, doc_id)
        doc_category = await self._store.get_category(user_id, doc_id)
        stats["fetch_ms"] = _ms(mark)

        # 3. Detect (chunked, spaCy offloaded to worker threads).
        mark = time.perf_counter()
        detections: Sequence[Detection] = await self._detector.detect(text, doc_category)
        stats["detect_ms"] = _ms(mark)
        stats["entities_detected"] = float(len(detections))

        # 3b. Detect over the prompt as well. Detection is stateless, so running it
        #     here rather than next to the prompt's obfuscation costs nothing and
        #     lets the one DETECT event describe the whole input.
        mark = time.perf_counter()
        prompt_detections: Sequence[Detection] = await self._detector.detect(
            user_prompt, doc_category
        )
        stats["prompt_detect_ms"] = _ms(mark)
        stats["prompt_entities_detected"] = float(len(prompt_detections))

        # ``doc_id`` and ``fetch_ms`` ride on DETECT rather than on a fetch event of
        # their own: build doc section 7 fixes the event-type vocabulary and step 2
        # of the section-4 narrative has no member of it (see README Deviations).
        # A uuid4 hex document ID is not content, and it is what turns "what
        # happened in this session" into "which documents were read" -- the first
        # question a HIPAA access review actually asks.
        #
        # The prompt's counts ride here too, for the same reason and one more: a
        # *second* DETECT event would make "how many entities were in the document"
        # ambiguous for every existing compliance query, and ``prompt_chars`` /
        # ``prompt_count`` are counts, which is all this schema can hold anyway.
        await self._emit(
            AuditEvent(
                ts=time.time(),
                session_id=session_id,
                run_id=run_id,
                event_type=DETECT,
                detail={
                    "count": len(detections),
                    "elapsed_ms": round(stats["detect_ms"], 3),
                    "doc_category": (doc_category or "none")[:64],
                    "chars": len(text),
                    "doc_id": doc_id[:MAX_DETAIL_VALUE_LEN],
                    "fetch_ms": round(stats["fetch_ms"], 3),
                    "prompt_chars": len(user_prompt),
                    "prompt_count": len(prompt_detections),
                    "prompt_elapsed_ms": round(stats["prompt_detect_ms"], 3),
                },
            )
        )

        # 4. Obfuscate: dedupe -> vault -> splice right-to-left.
        mark = time.perf_counter()
        obf: ObfuscationResult = await self._engine.obfuscate(
            session_id,
            text,
            detections,
            strategy=chosen,
            doc_category=doc_category,
            run_id=run_id,
        )
        stats["obfuscate_ms"] = _ms(mark)
        stats["redactions"] = float(len(obf.redactions))
        stats["stripped"] = float(len(obf.stripped))

        # 4b. Obfuscate the prompt, in the same session and deliberately AFTER the
        #     document. See :meth:`_detect_and_obfuscate_prompt`.
        mark = time.perf_counter()
        prompt_obf: ObfuscationResult = await self._detect_and_obfuscate_prompt(
            session_id,
            user_prompt,
            prompt_detections,
            strategy=chosen,
            doc_category=doc_category,
            run_id=run_id,
        )
        stats["prompt_obfuscate_ms"] = _ms(mark)

        # 4c. One token list for the whole payload. Everything downstream that asks
        #     "what did this run put on the wire?" -- the gate's skip-list, the
        #     collision guard, the restorer's issued set and its pseudonym map --
        #     has to be asked about *both* halves of it, and asking it about
        #     ``obf.tokens`` alone was silently correct only while the prompt could
        #     not carry a surrogate. See :func:`_merge_tokens`.
        tokens = _merge_tokens(obf.tokens, prompt_obf.tokens)
        stats["tokens_issued"] = float(len(tokens))
        stats["prompt_tokens_issued"] = float(len(tokens) - len(obf.tokens))
        # 4c-bis. What the payload actually CARRIES, next to what the caller asked
        #     for. See :func:`_pseudonyms_issued` -- this is the run reporting on its
        #     own output shape rather than echoing ``chosen``.
        stats["pseudonyms_issued"] = float(_pseudonyms_issued(tokens))

        # 4d. Distinct originals must own distinct surrogates, checked here rather
        #     than trusted. See :func:`_assert_surrogates_are_distinct`.
        _assert_surrogates_are_distinct(tokens, session_id, run_id)

        # 5. Assemble the payload. Both halves are obfuscated text by this point,
        #    which is what the injector's parameter names now say out loud.
        mark = time.perf_counter()
        payload = self._injector.build(
            strategy=chosen,
            obfuscated_prompt=prompt_obf.obfuscated_text,
            obfuscated_document=obf.obfuscated_text,
        )
        # The exact strings this run spliced into the document. This one line is the
        # load-bearing half of the gate's pass-2 skip-list: ``_protected_spans``
        # protects a token-shaped span by grammar and a surrogate by *string
        # equality*, and only the second is a property of *this* module rather than a
        # hope about another one: string equality cannot drift, whereas "the emitter
        # only ever produces what the matcher accepts" is a claim about two patterns
        # in a third file staying in agreement. (They do today, and it is enforced;
        # they have not always. README §8 carries the history.) Sending ``frozenset()``
        # here would false-block
        # every pseudonymization run on its own well-formed output while leaving the
        # gate's own tests green, since they hand ``check()`` their surrogates
        # directly -- so the seam is pinned from this side by
        # ``test_the_gate_is_handed_the_surrogates_this_run_actually_emitted``.
        surrogates = frozenset(t.surrogate for t in tokens)
        stats["inject_ms"] = _ms(mark)

        # The two strings the provider will be handed, bound to locals here and not
        # re-read from ``payload`` afterwards. Everything from this line to the
        # provider call operates on these exact values.
        system, user = payload.system, payload.user

        # 6. EGRESS GATE. Raises before any provider call is constructed.
        mark = time.perf_counter()
        report = await self._gate.check(
            payload.serialized, session_id, surrogates=surrogates, run_id=run_id
        )
        stats["egress_ms"] = _ms(mark)
        stats["egress_rescan_warnings"] = float(report.rescan_warnings)

        # 6b. The gate cleared a specific string. Prove that is the string we send.
        await self._verify_release(session_id, run_id, report.payload_sha256, system, user)

        # 6c. The gate scanned a specific *set*. Prove it was not empty when we know
        #     it should not have been. See ``_verify_pass_one_had_something_to_scan``.
        await self._verify_pass_one_had_something_to_scan(
            session_id, run_id, len(tokens), report.originals_scanned
        )

        # 7. Provider call -- only reachable past a passing gate, and only with the
        #    bytes that gate cleared.
        mark = time.perf_counter()
        llm = await self._provider.complete_detailed(
            system,
            user,
            model=self._settings.llm_model,
            timeout_s=self._settings.llm_timeout_s,
        )
        stats["llm_ms"] = _ms(mark)
        await self._emit(
            AuditEvent(
                ts=time.time(),
                session_id=session_id,
                run_id=run_id,
                event_type=LLM_CALL,
                detail={
                    "model": llm.model[:64],
                    "provider": self._provider.name[:64],
                    "input_tokens": llm.input_tokens,
                    "output_tokens": llm.output_tokens,
                    "elapsed_ms": round(stats["llm_ms"], 3),
                    "payload_sha256": report.payload_sha256,
                },
            )
        )

        # 8. Restore. LLM output is untrusted text -- string operations only.
        mark = time.perf_counter()
        surrogate_map = self._surrogate_map(tokens)
        restored = await self._restorer.restore(
            session_id,
            llm.text,
            strategy=chosen,
            surrogates=surrogate_map,
            # NOT diagnostics only -- this comment used to say so and it is wrong in
            # three of four cases. Supplying `issued` changes output bytes: an
            # unbracketed token whose ID we did not mint is left VERBATIM instead of
            # being replaced by `[UNRESOLVED_ENTITY]` (README Deviation 49), and a
            # bracketed unminted one is refused a vault lookup it would otherwise be
            # given. `restorer.py` and `tests/test_deobfuscation.py` both retract the
            # "changes no output byte" wording already; this was the copy that was
            # missed. What follows is still true and is the reason it is passed.
            #
            # It lets a VAULT_MISS say
            # WHICH kind of miss it was: a token we minted this run that the vault
            # can no longer resolve (`vault_lost`, an ERROR -- our bug) versus one
            # the model invented (`fabricated`, a WARNING -- expected). Without it
            # every production miss is recorded as `indeterminate`, which is honest
            # but useless to an auditor asking whether the vault lost data.
            issued={token.token_id for token in tokens},
            run_id=run_id,
        )
        stats["restore_ms"] = _ms(mark)
        stats["restored_count"] = float(restored.restored_count)
        stats["unresolved_fabricated"] = float(len(restored.fabricated))
        stats["unresolved_lost"] = float(len(restored.lost))
        stats["vault_misses"] = float(restored.vault_misses)
        stats["total_ms"] = _ms(t0)

        audit_seq = await self._collect_seq(run_id)
        logger.info(
            "pipeline run complete",
            extra={
                "run_id": run_id,
                "session_id": session_id,
                # The strategy ASKED for and the shape actually emitted, side by
                # side: see :func:`_pseudonyms_issued` for why one line cannot be
                # trusted to imply the other. Counts only -- never a surrogate.
                "strategy": chosen,
                "tokens_issued": int(stats["tokens_issued"]),
                "pseudonyms_issued": int(stats["pseudonyms_issued"]),
                "total_ms": round(stats["total_ms"], 1),
            },
        )
        return PipelineResult(
            run_id=run_id,
            restored_text=restored.text,
            obfuscated_payload=payload.serialized,
            raw_llm_response=llm.text,
            strategy=chosen,
            # DOCUMENT spans only, and ``prompt_obf.spans`` is deliberately not
            # merged in. ``SpanOut`` offsets are documented as offsets into the
            # original document and the UI uses them to highlight it; a prompt span
            # carries prompt-space offsets, so appending it would silently
            # mis-highlight a region of the document and there is nothing in the
            # type to say which space a span belongs to. What the prompt did is
            # reported instead as ``prompt_entities_detected`` /
            # ``prompt_tokens_issued`` in ``stats``, as one ``OBFUSCATE`` audit event
            # per vaulted value, and -- in full -- in ``obfuscated_payload``, which
            # carries the obfuscated prompt verbatim. Carrying prompt spans properly
            # needs a span space on ``SpanOut``, which is an API change.
            detections=list(obf.spans),
            stats=stats,
            audit_seq=audit_seq,
        )

    # ------------------------------------------------------------------
    async def _detect_and_obfuscate_prompt(
        self,
        session_id: str,
        user_prompt: str,
        detections: Sequence[Detection],
        *,
        strategy: str,
        doc_category: str | None,
        run_id: str,
    ) -> ObfuscationResult:
        """Run the user prompt through the same engine the document goes through.

        The prompt is half of the outbound payload, and until this existed it was
        the half nothing obfuscated -- reproduced end-to-end over HTTP with six
        entity types, see this module's docstring. The options were (a) detect and
        obfuscate it like the document, (b) block on any detection in it, and (c)
        write the hole down as an accepted boundary. This is (a).

        **Why (a) and not (b).** Blocking is easy to defend and expensive to live
        with: the natural prompt for this product is *"summarise this record for
        Dr Okafor"* or *"compare against the 03/12/1985 admission"*, and (b) turns
        every one of those into a 422 with no way forward. It is also strictly
        weaker where it matters. Blocking on detection protects only what the
        detector finds; obfuscating on detection protects what the detector finds
        **and** -- through the engine's cross-call residual sweep -- every value this
        *session* has already vaulted, whether or not the detector fires on it in
        this short, context-free string. NER on a nine-word question is much worse
        than NER on a clinical note, so that second half is not a rounding error:
        it is the half that catches the common case, a user re-typing a name that
        is in the document they are asking about.

        **Ordering is load-bearing: the document is obfuscated first.** The sweep
        chases values vaulted on an *earlier* call in the same session, so running
        the prompt second means every original the document vaulted is masked in the
        prompt too, with the *same* surrogate -- which is also what keeps the
        cross-reference the user was making intact for the model. Reversing the two
        would leave that to prompt-only NER.

        The residual of that ordering is a value the prompt vaults that also appears
        in the already-obfuscated document text and that the detector missed there.
        That is not a leak: pass 1 of the gate scans the assembled payload against
        the whole session vault, so the value is now vaulted and the request blocks.
        It is a denial, which is the direction this pipeline is allowed to be wrong
        in, and it is the same trade the document half already makes.

        ``doc_category`` is the *document's* category, passed on purpose. The prompt
        carries no category of its own, and ``None`` is not the neutral choice it
        looks like: the registry scopes ``DATE``, ``AMOUNT``, ``CLIENT_IDENTITY`` and
        ``CASE_STRATEGY`` to particular categories, so an uncategorised prompt would
        have a date of birth typed into it fall out of scope entirely. A question
        asked *about* a medical record is a medical question.

        **What this does not buy.** The prompt is now exactly as protected as the
        document and no more: a value no recogniser anchors on is missed here for
        the same reason it is missed there, and the guarantee remains an egress
        property with respect to the vault and a recall property with respect to
        everything else (see :mod:`~secure_context_pipeline.pipeline.egress_gate`).
        What changed is that the prompt is no longer a *category* of input that was
        exempt from the pipeline the product is named after.
        """
        return await self._engine.obfuscate(
            session_id,
            user_prompt,
            detections,
            strategy=strategy,
            doc_category=doc_category,
            run_id=run_id,
        )

    async def _verify_release(
        self,
        session_id: str,
        run_id: str,
        cleared_sha256: str,
        system: str,
        user: str,
    ) -> None:
        """Block unless the bytes about to be sent are the bytes the gate cleared.

        A time-of-check-to-time-of-use guard on the egress gate. The gate hashes
        the string it scanned and puts that digest in ``EGRESS_PASS``; this
        recomputes the digest from the two arguments the provider is about to
        receive and refuses to continue if they disagree.

        What it actually catches, stated narrowly so it is not mistaken for more:

        * a stage inserted between the check and the send that edits either string
          -- a prefill, a truncation, an appended instruction, a re-encode;
        * ``InjectedPayload.serialized`` and the provider call drifting apart, which
          the property's own docstring can only *ask* a maintainer not to do. The
          concatenation is spelled out again here rather than reused, so a change to
          one of the two shows up as a mismatch instead of as agreement;
        * a gate whose report does not describe the payload it was handed, including
          a stale or cached report.

        What it does not catch: a change made consistently in both places. That is a
        deliberate, reviewable edit rather than an accident, and no digest can tell
        the two apart.

        Fails as an ``EgressBlockedError`` because that is what it is -- an
        unreleased payload -- so the API's 422 ``EGRESS_BLOCKED`` handler and the
        audit trail both treat it exactly like any other block.
        """
        outbound = hashlib.sha256(f"{system}\n\n{user}".encode()).hexdigest()
        if outbound == cleared_sha256:
            return
        logger.error(
            "outbound payload does not match the payload the gate cleared; blocking",
            extra={"session_id": session_id, "run_id": run_id},
        )
        # Best-effort, exactly as in ``EgressGate._emit_block``: the block is already
        # guaranteed by the raise below, and an audit-layer failure here must not
        # replace a typed EGRESS_BLOCKED with whatever the log threw.
        try:
            await self._emit(
                AuditEvent(
                    ts=time.time(),
                    session_id=session_id,
                    run_id=run_id,
                    event_type=EGRESS_BLOCK,
                    detail={
                        "reason": "payload_changed_after_check",
                        "hit_count": 0,
                        "entity_types": "",
                    },
                )
            )
        except Exception as exc:
            logger.error(
                "release mismatch could not be audited; the block itself still stands",
                extra={
                    "session_id": session_id,
                    "run_id": run_id,
                    "error": type(exc).__name__,
                },
            )
        raise EgressBlockedError(
            session_id=session_id[:MAX_DETAIL_VALUE_LEN],
            reason="payload_changed_after_check",
            hit_count=0,
            run_id=run_id[:MAX_DETAIL_VALUE_LEN],
        )

    async def _verify_pass_one_had_something_to_scan(
        self,
        session_id: str,
        run_id: str,
        tokens_issued: int,
        originals_scanned: int,
    ) -> None:
        """Block if this run vaulted values and the gate then scanned an empty set.

        Pass 1 is the only gate pass that does not depend on detector recall, and the
        whole "this is an *egress* property, not a *detection* property" argument
        rests on it. It is also the pass that fails **silently** when it fails: with
        an empty originals set it is a no-op that returns 0, and ``EGRESS_PASS`` then
        records ``originals_scanned: 0`` -- byte-identical in the audit trail to a
        document that legitimately contained nothing sensitive, a shape the
        integration suite asserts as normal.

        ``SessionVault.originals_for_session`` returns ``frozenset()`` for an unknown
        or destroyed session. Its docstring calls that "fails *safe*", and for the
        vault's own contract it is: it never invents values. For the gate's contract
        it is the opposite, and nothing was joining the two beliefs -- ``grep
        originals_scanned`` across the repo found the field set, written to the audit
        detail, and asserted in tests, with **no production reader at all**.

        This is that reader, and it is deliberately built from two *different sources*
        rather than one: ``tokens_issued`` is this run's own manifest, accumulated by
        the obfuscation stage, and ``originals_scanned`` comes back from the vault's
        cache through the gate. Agreement between them means something precisely
        because neither is derived from the other. That is the differently-sourced
        cross-check this codebase's recurring defect class calls for, and it is the
        one place it was cheap to add.

        **The predicate is deliberately weak, and that is not laziness.** The tempting
        assertion is ``originals_scanned >= tokens_issued``, and it is wrong: the
        engine dedupes by ``(entity_type, normalize(text))`` while the vault's
        originals set is a set of *strings*, so one value claimed by two entity types
        is two tokens and one original, and the strong form would false-block on
        ordinary documents. What is asserted is only the condition that can never be
        legitimate -- **we vaulted something and the gate saw nothing** -- which is
        exactly the silent no-op above and nothing else.

        Fails as an ``EgressBlockedError`` for the same reason ``_verify_release``
        does: an unscanned payload is an unreleased payload.
        """
        if tokens_issued == 0 or originals_scanned > 0:
            return
        logger.error(
            "egress pass 1 scanned an empty originals set for a run that vaulted "
            "values; blocking",
            extra={
                "session_id": session_id,
                "run_id": run_id,
                "tokens_issued": tokens_issued,
                "originals_scanned": originals_scanned,
            },
        )
        # Best-effort, exactly as in ``_verify_release``: the block below is already
        # guaranteed, and an audit-layer failure must not replace a typed
        # EGRESS_BLOCKED with whatever the writer threw.
        try:
            await self._emit(
                AuditEvent(
                    ts=time.time(),
                    session_id=session_id,
                    run_id=run_id,
                    event_type=EGRESS_BLOCK,
                    detail={
                        "reason": "pass_one_scanned_nothing",
                        "hit_count": 0,
                        "entity_types": "",
                        "tokens_issued": tokens_issued,
                    },
                )
            )
        except Exception as exc:
            logger.error(
                "empty-scan block could not be audited; the block itself still stands",
                extra={
                    "session_id": session_id,
                    "run_id": run_id,
                    "error": type(exc).__name__,
                },
            )
        raise EgressBlockedError(
            session_id=session_id[:MAX_DETAIL_VALUE_LEN],
            reason="pass_one_scanned_nothing",
            hit_count=0,
            run_id=run_id[:MAX_DETAIL_VALUE_LEN],
        )

    def _surrogate_map(
        self, tokens: Sequence[TokenRecord]
    ) -> dict[str, str] | None:
        """The surrogates this run issued that are pseudonyms, as a candidate list.

        Tokenization restores by hash, so a run that issued only tokens needs no map.
        Pseudonyms are ordinary words with no embedded key, so the restorer needs the
        candidate list; the values come back out of the vault rather than being
        carried along the run.

        **Keys, not pairs.** Every value here is ``""``, and that is the interface
        rather than a stub. ``Restorer.restore`` compiles its alternation from
        ``supplied``'s *keys*, and ``_restore_surrogates`` treats a falsy value as
        "not pre-resolved" and looks the surrogate up itself. Doing the lookup here
        as well was duplicated work -- two vault reads per surrogate -- and it moved
        the miss to the wrong place: :class:`VaultMissError` raised here escapes
        ``run()`` and fails the request, while the same miss inside the restorer is
        caught, recorded as a ``VAULT_MISS`` audit event with
        ``reason="surrogate_not_in_vault"``, and rendered as
        ``[UNRESOLVED_ENTITY]``. ``restore``'s own docstring fixes which of those is
        correct -- "an unknown token degrades the answer, it never fails the
        request" -- and degrading is the safe direction anyway: the alternative to a
        visible ``[UNRESOLVED_ENTITY]`` is a fabricated name left in the text
        reading exactly like a real one. So resolution and miss handling both live
        in the restorer, in one place, and this method only answers "which strings
        in the payload are pseudonyms this run issued".

        ``tokens`` is the *merged* list (:func:`_merge_tokens`), so it includes
        surrogates the prompt contributed. Passing only the document's would be the
        quiet failure of this whole change: under pseudonymization a fake reads
        exactly like a real value, so an unmapped prompt pseudonym is not a visible
        ``[UNRESOLVED_ENTITY]`` -- the caller reads the invented name as the answer.

        **Known limitation -- chained restoration under pseudonymization.** The
        restorer runs its surrogate pass before its token pass. A vaulted original
        that is *itself* token-shaped therefore gets substituted in by the surrogate
        pass and then matched again by the token pass, resolving to a second entity's
        value rather than tripping ``_assert_no_tokens`` -- which is what catches the
        equivalent case under tokenization.

        Reaching it needs a same-session **token-ID** collision *and* document text
        matching this project's own token grammar. Stated precisely so the guard at
        step 4d is not mistaken for a fix for this:
        :func:`_assert_surrogates_are_distinct` refuses two originals sharing one
        *surrogate*, which is a different collision. The token-ID half is held
        upstream instead, by the engine's ``_unique_token_id`` and the ``counter``
        argument to
        :func:`~secure_context_pipeline.crypto.keys.derive_token_id` -- so this path
        is reachable only if that invariant breaks.

        It is bounded to one session and discloses nothing across sessions. Recorded
        rather than left silent because it is a wrong-attribution path, and those are
        the ones a reader cannot see. Closing it belongs in the restorer -- ordering
        the token pass first, or re-asserting after the surrogate pass -- not here.
        """
        # Built from the RECORDS, not from this run's strategy string.
        #
        # `if strategy != "pseudonymization": return None` was the whole test, and it
        # is wrong because the vault has no strategy dimension: a run reuses whatever
        # record an earlier call in the same session minted. Order a pseudonymization
        # run then a tokenization run -- which the API allows, since `strategy` is a
        # per-request field, and which a per-entity `strategy:` override in
        # entities.yaml produces on its own -- and the second run splices a PSEUDONYM
        # into the payload while restoring by hash only. The surrogate pass never
        # runs, so the caller is handed the fabricated name as the answer, with
        # `restored_count=0`, `vault_misses=0` and no residual assertion tripped:
        # a fake reads exactly like a real value, which is why nothing downstream
        # notices.
        #
        # A surrogate that is not a `STRICT_TOKEN_RE` match is a pseudonym and needs
        # a map entry whatever the run asked for. Testing the shape of what was
        # actually emitted is the only test that cannot drift from what the payload
        # contains -- the restorer's surrogate pass is gated on this map being
        # non-empty, not on the strategy string, so supplying it under tokenization
        # is exactly what makes the mixed case restore.
        #
        # The shape test itself lives in :func:`_is_pseudonym`, shared with the
        # ``pseudonyms_issued`` stat so that what the run REPORTS about its output
        # and what it actually maps for restoration cannot drift apart.
        mapping = {
            token.surrogate: "" for token in tokens if _is_pseudonym(token.surrogate)
        }
        return mapping or None

    async def _collect_seq(self, run_id: str) -> list[int]:
        """Every audit ``seq`` this run produced, paginated to completion.

        ``query()`` defaults to ``limit=1000``, and the engine emits one
        ``OBFUSCATE`` event per distinct vaulted value: a document with more than a
        thousand entities silently returned a *truncated* ``audit_seq``, which is
        the one field a compliance reviewer would use to check they had the whole
        chain. A short list that looks complete is worse than a slow one.
        """
        if self._audit is None:
            return []
        seqs: list[int] = []
        offset = 0
        while True:
            events = await self._audit.query(run_id=run_id, limit=_AUDIT_PAGE, offset=offset)
            seqs.extend(e.seq for e in events if e.seq is not None)
            if len(events) < _AUDIT_PAGE:
                return seqs
            offset += _AUDIT_PAGE

    async def _emit(self, event: AuditEvent) -> None:
        if self._audit is not None:
            await self._audit.emit(event)


def _merge_tokens(
    document: Sequence[TokenRecord], prompt: Sequence[TokenRecord]
) -> list[TokenRecord]:
    """Every surrogate this run put on the wire, document half first.

    The two halves overlap by design and the overlap must not be counted twice. A
    value mentioned in both the document and the prompt is **one vault row**: the
    engine resolves it to the record that already exists, and the prompt's residual
    sweep splices the document's own surrogate in. So the merge de-duplicates on
    ``token_id`` -- the vault's identity for a value -- and not on ``surrogate``,
    which under pseudonymization is a realistic fake that could in principle be
    drawn twice, and not on object identity, which would keep both copies.

    The document's list is copied through **unchanged**, dupes and all, rather than
    itself de-duplicated. That is deliberate: ``stats["tokens_issued"]`` is derived
    from the length of this list and an integration test holds it equal to the
    session's vault row count, so a de-dupe here would quietly change a number that
    is asserted elsewhere against a different source of truth. What this function
    is allowed to decide is only which *prompt* records are new.

    Order is document-then-prompt and stable, so the surrogate set, the pseudonym
    restore map and the collision guard all see the same sequence every run.
    """
    merged = list(document)
    seen = {record.token_id for record in merged}
    for record in prompt:
        if record.token_id in seen:
            continue
        seen.add(record.token_id)
        merged.append(record)
    return merged


def _is_pseudonym(surrogate: str) -> bool:
    """True if ``surrogate`` is a realistic fake rather than a hash token.

    One predicate, used by both the pseudonym restore map
    (:meth:`PipelineOrchestrator._surrogate_map`) and the ``pseudonyms_issued``
    stat, on purpose: the stat's whole job is to report what that map -- and
    therefore the payload -- contains, so the two must agree by construction. A
    second copy of the shape test is a second place for them to disagree, and a
    disagreement here is exactly the class of defect this stat exists to expose.
    """
    return bool(surrogate) and STRICT_TOKEN_RE.fullmatch(surrogate) is None


def _pseudonyms_issued(tokens: Sequence[TokenRecord]) -> int:
    """How many of this run's surrogates are pseudonyms, from the RECORDS.

    ``strategy`` is what the caller *asked for*; this is what the payload actually
    carries, and the two come apart. The vault has no strategy dimension: a run
    reuses whatever record an earlier call in the same session minted (the long
    comment in :meth:`PipelineOrchestrator._surrogate_map` explains why that reuse
    is correct and must not be "fixed"). Tokenize a document and then re-run the
    same session under pseudonymization, and every surrogate on the wire is a hash
    token while ``PipelineResult.strategy`` -- and the UI banner reading it -- says
    ``pseudonymization``. Nothing else in the response contradicted that, so the
    only honest signal was invisible.

    Reported as a **count alongside** ``tokens_issued`` rather than as an
    ``effective_strategy`` label, for three reasons:

    * No single label is true. Pseudonymization is *legitimately* mixed at the
      record level -- ``PseudonymizationStrategy.make_surrogate`` emits a fake for
      the identifier and temporal tiers and a ``plain_token`` for the content tier
      -- so an ordinary, correct run would be relabelled "mixed" and the label
      would carry no information.
    * ``PipelineResult.strategy`` is documented as a value from a closed literal
      set (``tests/test_models.py``), so it is the wrong field to widen, and adding
      a new field means editing the response model.
    * ``stats`` is the run's self-report and the UI renders every key it finds
      (``ui/app.js`` orders a known prefix and appends the rest), so a count lands
      on the reviewer's screen next to the banner with no schema change.

    So ``pseudonyms_issued == 0`` beside ``tokens_issued == 52`` on a run that asked
    for pseudonymization is the report the response was missing. This changes only
    what the run says about itself -- nothing about what it emits.
    """
    return sum(1 for token in tokens if _is_pseudonym(token.surrogate))


def _assert_surrogates_are_distinct(
    tokens: Sequence[TokenRecord], session_id: str, run_id: str
) -> None:
    """Refuse the run if two distinct originals were issued the same surrogate.

    ``ObfuscationResult.tokens`` is one record per distinct vaulted value, so a
    surrogate appearing twice means two different originals are represented by one
    string on the wire. Nothing downstream can undo that. Restoration resolves a
    surrogate by *string*
    (:meth:`~secure_context_pipeline.vault.session_vault.SessionVault.get_by_surrogate`),
    so both occurrences come back as whichever original the vault indexed -- one
    entity's name, identifier or diagnosis printed where another's belongs, with no
    miss recorded and nothing in the output to suggest it happened. Under
    pseudonymization the surrogate is a realistic fake, so the wrong answer reads
    exactly like the right one.

    That is why this raises rather than logs. Everywhere else this pipeline prefers
    a degraded answer to no answer -- a truncated completion is returned, an
    unresolvable token becomes a visible ``[UNRESOLVED_ENTITY]``. Both of those are
    *legible*: the reader can see something is missing. Silent misattribution is
    not, and in a clinical or legal document it is the one failure a reviewer would
    rather have been an error.

    It runs at step 4d -- before injection, before the gate, before the provider --
    because the collision exists the moment the surrogates do. Failing here costs no
    model call and keeps an ambiguous payload from being assembled at all.

    Reaching this is a bug upstream, not a user input: the pseudonymization strategy
    already rejects a candidate fake that any surrogate in the session has taken
    (``_surrogate_taken``), and tokenization derives the surrogate from a token ID
    the vault guarantees unique. This is the assertion that says so out loud instead
    of assuming it, and it holds for whichever strategy runs -- including one added
    later, whose collision guard nothing here can see.

    The detail carries token IDs and an entity type: synthetic identifiers and a
    config string, both already present in the audit trail. The surrogate itself is
    never reported -- it resolves to a real original.
    """
    issuer: dict[str, str] = {}
    for token in tokens:
        clash = issuer.get(token.surrogate)
        if clash is not None and clash != token.token_id:
            logger.error(
                "two originals share one surrogate; refusing the run",
                extra={
                    "session_id": session_id,
                    "run_id": run_id,
                    "entity_type": token.entity_type,
                    "token_ids": f"{clash},{token.token_id}",
                },
            )
            raise PipelineError(
                reason="surrogate_collision",
                entity_type=token.entity_type[:MAX_DETAIL_VALUE_LEN],
                token_ids=f"{clash},{token.token_id}"[:MAX_DETAIL_VALUE_LEN],
            )
        issuer[token.surrogate] = token.token_id


def _ms(since: float) -> float:
    return (time.perf_counter() - since) * 1000.0
