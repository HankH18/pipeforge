"""``GET /audit`` and ``GET /audit/verify`` -- compliance reads of the chain.

Both take a *proved* scope rather than a quoted one: the claimed ``user_id`` is
checked against the owner recorded in the log itself, an unproved scope reads as
empty, and the failed proof is metered and recorded. The reasoning is on the two
handlers and on :func:`secure_context_pipeline.api.deps._resolve_audit_scope`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi import status as http_status

from secure_context_pipeline.api.constants import DEFAULT_AUDIT_PAGE, MAX_AUDIT_PAGE
from secure_context_pipeline.api.deps import (
    _ERRORS,
    ApiError,
    OptionalIdQuery,
    ServicesDep,
    UserIdQuery,
    _deny_audit_scope,
    _resolve_audit_scope,
    _same_id,
)
from secure_context_pipeline.api.schemas import AuditQueryResponse, AuditVerifyResponse

router = APIRouter()


@router.get(
    "/audit",
    response_model=AuditQueryResponse,
    responses=_ERRORS,
    tags=["audit"],
    summary="Query the hash-chained audit log",
)
async def query_audit(
    request: Request,
    services: ServicesDep,
    user_id: UserIdQuery,
    session_id: OptionalIdQuery = None,
    run_id: OptionalIdQuery = None,
    event_type: OptionalIdQuery = None,
    since: Annotated[float | None, Query(description="Inclusive epoch-seconds lower bound.")] = None,
    until: Annotated[float | None, Query(description="Inclusive epoch-seconds upper bound.")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_AUDIT_PAGE)] = DEFAULT_AUDIT_PAGE,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditQueryResponse:
    """Compliance reporting. Ordered by ``seq``, i.e. chain order.

    **A scope is mandatory, and the caller must own it.** ``AuditEvent``
    cannot hold an original value (build doc sections 7 and 9.8), which is why
    the *content* of the log is safe to return. What is not safe is the
    *correlation*: a row names the ``session_id`` it belongs to, a
    ``SESSION_CREATE`` row names the owning ``user_id``, and a ``DETECT`` row
    names the ``doc_id`` that was read. Those three identifiers are precisely
    the credentials for the two endpoints that matter --
    ``DELETE /sessions/{session_id}?user_id=...`` (irreversible cryptographic
    erasure) and ``GET /documents/{doc_id}/text?user_id=...`` (original
    plaintext).

    Requiring a scope alone stopped *enumeration* but left the log an
    **assembly oracle**, and that was a live, complete break rather than a
    theoretical one: an anonymous caller holding a single ``run_id`` read the
    session ID and ``doc_id`` out of that run's events, read the owning
    ``user_id`` out of that session's ``SESSION_CREATE``, and then fetched the
    victim's original document text and destroyed their vault -- with no
    session and no credential of its own. The ``user_id`` second factor that
    guards both of those endpoints was being handed out by this one.

    So the scope must be *proved*, not merely quoted: the claimed ``user_id``
    is checked, in constant time, against the owner recorded in the log at
    ``SESSION_CREATE`` (see :func:`_resolve_audit_scope`). An unproved scope
    returns an **empty page**, byte-identical to a scope that does not exist
    or a window that matched nothing -- answering 403 would restore the
    existence oracle the uniform reply exists to deny.

    **And a failed proof is metered and recorded** (:func:`_deny_audit_scope`).
    The proof has no secret to verify -- ``POST /sessions`` mints a session
    for any ``user_id`` asked for -- so it is a right/wrong oracle on a
    human-readable name, and until now a free and invisible one: 500 wrong
    guesses against a real ``run_id`` cost 0.86 ms each, triggered no lockout
    and wrote nothing. Guessing is now throttled per caller and every answered
    guess leaves a row in the chain it is attacking. Neither replaces
    authentication; both close the interim window's *silence*, which is the
    part that made the gap unmonitorable rather than merely open.

    Liveness is deliberately *not* checked, and the ownership proof reads the
    log rather than the registry for exactly that reason: the trail must stay
    readable after the session is destroyed, which is what the vault-miss demo
    and ``demo.py``'s closing audit tail do (build doc section 9.11).
    """
    if not session_id and not run_id:
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            "AUDIT_SCOPE_REQUIRED",
            {"reason": "session_id_or_run_id_required"},
        )
    scope = await _resolve_audit_scope(services, session_id=session_id, run_id=run_id)
    if scope.owner is None or not _same_id(user_id, scope.owner):
        await _deny_audit_scope(request, services, scope, user_id=user_id, run_id=run_id)
        return AuditQueryResponse(events=[], returned=0, limit=limit, offset=offset)
    events = await services.audit.query(
        session_id=session_id,
        run_id=run_id,
        event_type=event_type,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return AuditQueryResponse(events=events, returned=len(events), limit=limit, offset=offset)


@router.get(
    "/audit/verify",
    response_model=AuditVerifyResponse,
    responses=_ERRORS,
    tags=["audit"],
    summary="Verify the audit hash chain",
)
async def verify_audit(
    request: Request,
    services: ServicesDep,
    session_id: OptionalIdQuery = None,
    user_id: OptionalIdQuery = None,
) -> AuditVerifyResponse:
    """Recompute every ``entry_hash`` and re-check every link.

    Reported as data, never as an error: a broken chain is a finding for the
    reader, and a 500 here would hide which answer the checker gave.

    **Unscoped is anonymous by design.** The whole-log form returns a boolean
    and a total count and names nothing -- no session, no run, no user, no
    document. That is the tamper-evidence claim the design wants publicly
    checkable, and it is what the demo UI's "Verify chain" button and
    ``demo.py`` both call.

    **Scoped requires the same ownership proof as ``GET /audit``.** Per
    session, ``length`` is an existence oracle -- zero versus non-zero says
    whether that session ID was ever real -- so it is gated exactly like the
    query it mirrors, and an unproved scope gets ``valid=True, length=0``,
    indistinguishable from a session that never existed. Metered and recorded
    exactly like the query it mirrors, too: this route answers the same
    right/wrong question about ``user_id``, so leaving it unmetered would
    just move the oracle one URL over.
    """
    if session_id:
        if not user_id:
            raise ApiError(
                http_status.HTTP_400_BAD_REQUEST,
                "AUDIT_SCOPE_REQUIRED",
                {"reason": "user_id_required_with_session_id"},
            )
        scope = await _resolve_audit_scope(services, session_id=session_id, run_id=None)
        if scope.owner is None or not _same_id(user_id, scope.owner):
            await _deny_audit_scope(request, services, scope, user_id=user_id, run_id=None)
            return AuditVerifyResponse(valid=True, length=0, session_id=session_id)
    valid = await services.audit.verify_chain(session_id)
    length = await services.audit.length(session_id)
    return AuditVerifyResponse(valid=valid, length=length, session_id=session_id)
