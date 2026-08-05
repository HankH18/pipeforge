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
    """
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
    """
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
