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
async def health(services: ServicesDep, response: Response) -> HealthResponse:
    """503 when the detector's model failed to load or the audit DB is
    unreachable -- the two ways this process can be running but useless."""
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
