"""``POST /pipeline/run`` -- the full round trip.

Detect -> obfuscate -> egress gate -> LLM -> restore, under a session the caller
must both hold and own.
"""

from __future__ import annotations

from fastapi import APIRouter

from secure_context_pipeline.api.deps import (
    _ERRORS,
    ServicesDep,
    SessionHeader,
    _require_session,
)
from secure_context_pipeline.api.schemas import PipelineRunRequest
from secure_context_pipeline.models import PipelineResult

router = APIRouter()


@router.post(
    "/pipeline/run",
    response_model=PipelineResult,
    responses=_ERRORS,
    tags=["pipeline"],
    summary="Detect -> obfuscate -> egress gate -> LLM -> restore",
)
async def run_pipeline(
    body: PipelineRunRequest,
    services: ServicesDep,
    x_session_id: SessionHeader = None,
) -> PipelineResult:
    """The full round trip.

    Returns the run's ``run_id``, which correlates every audit event the run
    emitted (``GET /audit?run_id=...``). A blocked payload never reaches the
    provider: the gate raises before the call is constructed, and the
    response is 422 ``EGRESS_BLOCKED``.

    The other refusal worth knowing about before the demo is **503
    ``AUDIT_UNAVAILABLE``**: an audit log the writer cannot read fails the run
    rather than releasing it unrecorded, and the provider is never called. That
    is the same "no release without a record" property the gate's 422 serves, and
    the body carries ``reason``, the failing ``operation`` and a ``remedy`` -- what
    it answered before was a bare ``500 Internal Server Error`` with no ``code``
    at all, which reads as a bug in this pipeline rather than a corrupt file in
    the data directory.
    """
    session_id = await _require_session(
        services, body.session_id or x_session_id, body.user_id
    )
    return await services.orchestrator.run(
        session_id, body.user_id, body.doc_id, body.prompt, body.strategy
    )
