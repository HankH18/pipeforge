"""PipelineOrchestrator -- the end-to-end round trip (build doc sections 9.5.1 and 4).

    fetch+decrypt -> detect -> obfuscate -> inject -> EGRESS GATE -> provider -> restore

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
that run, at step 4b -- before the payload is even assembled.
"""

from __future__ import annotations

import hashlib
import logging
import time
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
        # ``doc_id`` and ``fetch_ms`` ride on DETECT rather than on a fetch event of
        # their own: build doc section 7 fixes the event-type vocabulary and step 2
        # of the section-4 narrative has no member of it (see README Deviations).
        # A uuid4 hex document ID is not content, and it is what turns "what
        # happened in this session" into "which documents were read" -- the first
        # question a HIPAA access review actually asks.
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
        stats["tokens_issued"] = float(len(obf.tokens))
        stats["redactions"] = float(len(obf.redactions))
        stats["stripped"] = float(len(obf.stripped))

        # 4b. Distinct originals must own distinct surrogates, checked here rather
        #     than trusted. See :func:`_assert_surrogates_are_distinct`.
        _assert_surrogates_are_distinct(obf.tokens, session_id, run_id)

        # 5. Assemble the payload.
        mark = time.perf_counter()
        payload = self._injector.build(
            strategy=chosen, user_prompt=user_prompt, obfuscated_document=obf.obfuscated_text
        )
        surrogates = frozenset(t.surrogate for t in obf.tokens)
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
        surrogate_map = await self._surrogate_map(session_id, obf, chosen)
        restored = await self._restorer.restore(
            session_id,
            llm.text,
            strategy=chosen,
            surrogates=surrogate_map,
            # Diagnostics only -- changes no output byte. It lets a VAULT_MISS say
            # WHICH kind of miss it was: a token we minted this run that the vault
            # can no longer resolve (`vault_lost`, an ERROR -- our bug) versus one
            # the model invented (`fabricated`, a WARNING -- expected). Without it
            # every production miss is recorded as `indeterminate`, which is honest
            # but useless to an auditor asking whether the vault lost data.
            issued={token.token_id for token in obf.tokens},
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
                "strategy": chosen,
                "total_ms": round(stats["total_ms"], 1),
            },
        )
        return PipelineResult(
            run_id=run_id,
            restored_text=restored.text,
            obfuscated_payload=payload.serialized,
            raw_llm_response=llm.text,
            strategy=chosen,
            detections=list(obf.spans),
            stats=stats,
            audit_seq=audit_seq,
        )

    # ------------------------------------------------------------------
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

    async def _surrogate_map(
        self, session_id: str, obf: ObfuscationResult, strategy: str
    ) -> dict[str, str] | None:
        """Surrogate -> original, for pseudonymization only.

        Tokenization restores by hash, so it needs no map. Pseudonyms are ordinary
        words with no embedded key, so the restorer needs the candidate list; the
        values come back out of the vault rather than being carried along the run.

        **Known limitation -- chained restoration under pseudonymization.** The
        restorer runs its surrogate pass before its token pass. A vaulted original
        that is *itself* token-shaped therefore gets substituted in by the surrogate
        pass and then matched again by the token pass, resolving to a second entity's
        value rather than tripping ``_assert_no_tokens`` -- which is what catches the
        equivalent case under tokenization.

        Reaching it needs a same-session **token-ID** collision *and* document text
        matching this project's own token grammar. Stated precisely so the guard at
        step 4b is not mistaken for a fix for this:
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
        if strategy != "pseudonymization":
            return None
        mapping: dict[str, str] = {}
        for token in obf.tokens:
            mapping[token.surrogate] = await self._vault.get_by_surrogate(
                session_id, token.surrogate
            )
        return mapping

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

    It runs at step 4b -- before injection, before the gate, before the provider --
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
