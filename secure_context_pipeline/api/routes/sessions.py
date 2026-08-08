"""``POST /sessions`` and ``DELETE /sessions/{session_id}``.

Both are anonymous and both write durably, which is why
:class:`secure_context_pipeline.api.middleware._RateLimit` meters them; the
delete is a cryptographic erasure, which is why it is owner-scoped and silent
about it.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Response
from fastapi import status as http_status

from secure_context_pipeline.api.deps import (
    _ERRORS,
    DocIdPath,
    ServicesDep,
    UserIdQuery,
    _clamp,
    _owns_session,
    reap_expired_sessions,
)
from secure_context_pipeline.api.schemas import SessionCreateRequest, SessionCreateResponse
from secure_context_pipeline.audit.logger import SESSION_CREATE, VAULT_DESTROY
from secure_context_pipeline.models import AuditEvent

router = APIRouter()


@router.post(
    "/sessions",
    response_model=SessionCreateResponse,
    responses=_ERRORS,
    tags=["sessions"],
    summary="Create a session",
)
async def create_session(
    body: SessionCreateRequest, services: ServicesDep
) -> SessionCreateResponse:
    """Mint a session ID and a fresh 32-byte session key, bound to ``user_id``.

    The key stays inside :class:`SessionRegistry` and is never returned,
    logged, or persisted -- destroying it is what makes the vault
    irrecoverable. The ``user_id`` is recorded with it, and every later
    request presenting this session must claim the same one.

    **This route reaps too, and it is the one route that must.** It is the only
    way a session is created, so it is the only source of future expiries, and it
    needs no credential -- which used to mean an anonymous caller could grow
    ``SessionRegistry._unreaped`` indefinitely and never pay for any of it, while
    some later ``POST /pipeline/run`` paid for all of it at once. Reaping here
    puts a bounded slice of the cost
    (:data:`~secure_context_pipeline.api.constants.MAX_REAP_PER_REQUEST` IDs, ~1.2 ms
    each measured) on the caller creating the sessions, and it holds the
    registry's own queue to whatever expired since the previous request rather
    than to however long it has been since anyone ran a pipeline.
    """
    await reap_expired_sessions(services)
    session_id, expires_at = await services.sessions.create(body.user_id)
    await services.audit.emit(
        AuditEvent(
            ts=time.time(),
            session_id=session_id,
            event_type=SESSION_CREATE,
            detail={
                "ttl_seconds": services.settings.session_ttl_seconds,
                # The actor, not a document value. "No originals in logs"
                # (build doc section 16) is about detected entity values;
                # a compliance log that cannot say *who* acted is not one.
                "user_id": _clamp(body.user_id),
            },
        )
    )
    return SessionCreateResponse(session_id=session_id, expires_at=expires_at)


@router.delete(
    "/sessions/{session_id}",
    status_code=http_status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    tags=["sessions"],
    summary="Log out: destroy the vault and the session key",
)
async def delete_session(
    session_id: DocIdPath, services: ServicesDep, user_id: UserIdQuery
) -> Response:
    """Irreversible. Returns 204 whether or not anything was destroyed.

    **Owner-scoped, and silent about it.** Destruction is cryptographic
    erasure, so letting one user log another one out was an unauthenticated
    way to destroy a stranger's vault permanently. Only a session that is live
    *and* owned by ``user_id`` is touched.

    Deliberately idempotent and oracle-free: unknown, expired, already
    destroyed and *someone else's* all return the same empty 204. Answering
    404 -- or 403 for the last case -- would let a caller probe which session
    IDs are real, which is why the outcome is recorded in the audit log
    instead of in the status code.

    **The key goes first.** Logout is two awaits, so a pipeline run that is
    already in flight -- and already holding the session key -- can be
    scheduled between them. With the rows dropped first, that run's next
    ``put()`` landed *after* the erasure and rebuilt the plaintext cache and a
    durable row for a session that was supposed to be gone. Popping the key
    first makes the window harmless instead of merely narrow: every vault
    ciphertext is AES-GCM under a key derived from the session key, so once
    it is gone no later write can derive one. The vault's tombstone defends
    the same race one layer down; this closes it at the source.

    **An expired session is reaped first, because otherwise this route is a
    no-op on it.** ``_owns_session`` resolves through ``SessionRegistry.owner()``,
    which raises for an expired session and so answers ``False`` -- and the
    branch below is the only thing that calls ``vault.destroy``. So a logout one
    second after the TTL lapsed returned 204 while three decrypted originals
    stayed resident in ``SessionVault._caches`` and three AES-GCM rows stayed on
    disk (measured, at ``session_ttl_seconds=3``: ``cached=True originals=3
    rows=3`` before *and* after the ``DELETE``). That contradicts README gap 7's
    "and not explicitly logged out" and Q4's "during an active session", both of
    which describe the plaintext cache as bounded by the session's life plus an
    explicit logout. The reaper is the destruction path for an expired session,
    and until now no route reached it except ``POST /pipeline/run`` -- which
    logout does not go through.

    ``first=session_id`` hoists this session to the front of the bounded backlog,
    so the caller asking for *this* vault to be gone does not get told 204 while
    its rows wait behind somebody else's expiries. The 204 is unchanged either
    way: the reaper raises nothing, and it cannot turn an unowned session into an
    owned one.
    """
    await reap_expired_sessions(services, first=session_id)
    existed = False
    if await _owns_session(services, session_id, user_id):
        existed = await services.sessions.destroy(session_id)
        await services.vault.destroy(session_id)
    await services.audit.emit(
        AuditEvent(
            ts=time.time(),
            session_id=_clamp(session_id),
            event_type=VAULT_DESTROY,
            detail={"existed": int(existed), "source": "api_logout"},
        )
    )
    return Response(status_code=http_status.HTTP_204_NO_CONTENT)
