"""``GET /health`` -- liveness, and nothing an anonymous caller may not know.

Reports a *count* of active sessions rather than any session ID: a ``session_id``
is the bearer credential for an irreversible erasure, so no unauthenticated
response may contain one.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Response
from fastapi import status as http_status

from secure_context_pipeline.api.deps import _ERRORS, ServicesDep
from secure_context_pipeline.api.schemas import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    responses=_ERRORS,
    tags=["ops"],
    summary="Liveness: model loaded, database reachable",
)
@router.head(
    "/health",
    response_model=HealthResponse,
    responses=_ERRORS,
    tags=["ops"],
    summary="Liveness, headers only",
    # Two registrations of one handler rather than one `api_route(methods=[...])`.
    # FastAPI derives an operation ID per *route*, not per method, so the combined
    # form emits both operations under `health_health_head` and warns about the
    # duplicate -- a schema an ops tool reads is not the place to ship a collision.
    operation_id="health_head",
)
async def health(services: ServicesDep, response: Response) -> HealthResponse:
    """503 when the detector's model failed to load or the audit DB is
    unreachable -- the two ways this process can be running but useless.

    **``HEAD`` is declared explicitly, and that is not decoration.** FastAPI's
    ``@router.get`` registers ``GET`` only, so a ``HEAD`` request was a *partial*
    match here -- right path, wrong method -- and Starlette therefore kept looking
    and fell through to the catch-all ``Mount("/")`` that ``_mount_ui`` installs
    last. The static mount answered its own miss, so ``curl -I /health`` on a
    perfectly healthy process returned **404** while ``curl /health`` returned 200
    (measured, both). That is the first probe an ops reviewer or a load balancer
    tries, and the mount's whole premise -- "mounted last, so every API route is
    matched first" -- is true only for methods a route actually declares.

    ``HEAD`` reaches the same handler and Starlette drops the body, so the status
    code, the 503 branch and :data:`SECURITY_HEADERS` are the same bytes a ``GET``
    would have produced. The liveness work is a single ``audit.length()``, so
    answering it costs no more than the ``GET`` an unauthenticated caller may
    already make.
    """
    db_reachable = True
    try:
        await services.audit.length()
    except Exception:
        db_reachable = False
        logger.exception("health check: audit database unreachable")

    healthy = services.model_loaded and db_reachable
    if not healthy:
        response.status_code = http_status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="ok" if healthy else "degraded",
        model_loaded=services.model_loaded,
        db_reachable=db_reachable,
        spacy_model=services.settings.spacy_model,
        llm_provider=services.settings.llm_provider,
        llm_model=services.settings.llm_model,
        strategy=services.settings.strategy,
        ui_mounted=services.ui_mounted,
        active_sessions=len(await services.sessions.active_ids()),
    )
