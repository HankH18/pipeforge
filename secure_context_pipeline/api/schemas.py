"""Wire schemas for the HTTP layer (build doc section 9.9).

Every model here is a *boundary* type, and the boundary is the last place an
original entity value could escape. Two rules govern the whole module:

1. **No schema in this file may carry an original entity value**, with exactly
   two sanctioned exceptions, both user-ward and neither on the outbound path:
   :attr:`DocumentTextResponse.text` (the owner's own document, returned only
   after a successful per-user-key decrypt) and
   ``PipelineResult.restored_text`` (defined in :mod:`~secure_context_pipeline.models`,
   the whole point of the round trip). Error bodies, audit responses, and health
   output are structurally incapable of holding one.
2. **Errors carry structured detail only.** :class:`ErrorResponse.detail` mirrors
   the ``detail`` map of :class:`~secure_context_pipeline.errors.PipelineError`,
   which the exception hierarchy already caps at 64 characters per string value.
   Reasons, counts, and identifiers -- never a matched value, never a payload.

``PipelineResult``, ``SpanOut`` and ``AuditEvent`` are re-used as response models
directly from :mod:`secure_context_pipeline.models` rather than re-declared here:
those are the types the pipeline already guarantees are content-free (``SpanOut``
has offsets but no ``text`` field; ``AuditEvent`` has no free-text field at all),
and duplicating them would create a second schema that could drift into leaking.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from secure_context_pipeline.models import AuditEvent

__all__ = [
    "MAX_ID_LEN",
    "MAX_PROMPT_CHARS",
    "AuditQueryResponse",
    "AuditVerifyResponse",
    "DocumentTextResponse",
    "DocumentUploadResponse",
    "ErrorResponse",
    "HealthResponse",
    "PipelineRunRequest",
    "SessionCreateRequest",
    "SessionCreateResponse",
    "StrategyName",
]

#: Ceiling on caller-supplied identifiers. Identifiers are echoed into structured
#: error details, and :class:`~secure_context_pipeline.errors.PipelineError` caps
#: every string detail at 64 characters -- rejecting an over-long ID at the schema
#: is a clearer 422 than a ``ValueError`` from deep inside the error constructor.
MAX_ID_LEN = 64

#: Ceiling on the user's question. The document is not bounded here (that is the
#: store's business); the prompt is, because it is spliced into the outbound
#: payload verbatim.
MAX_PROMPT_CHARS = 8_000

StrategyName = Literal["tokenization", "pseudonymization"]


class SessionCreateRequest(BaseModel):
    """``POST /sessions``.

    ``user_id`` is the entire auth claim. That is take-home scope and is called
    out as production work in :func:`secure_context_pipeline.api.app.create_app`.
    """

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=MAX_ID_LEN)


class SessionCreateResponse(BaseModel):
    """The session's public half. The session *key* never leaves the process."""

    session_id: str
    expires_at: float


class DocumentUploadResponse(BaseModel):
    """``POST /documents``. Metadata only -- never the text, never an extract."""

    doc_id: str
    doc_category: str | None = None


class DocumentTextResponse(BaseModel):
    """``GET /documents/{doc_id}/text`` -- one of the two sanctioned original-value paths.

    Reached only through a successful decrypt under ``doc_key(user_id)``, so a
    non-owner cannot receive this body at all: the store raises
    :class:`~secure_context_pipeline.errors.StoreAuthError` (``NOT_FOUND``) first,
    indistinguishably from an absent document. Strictly user-ward -- this text is
    never assembled into an outbound payload.
    """

    doc_id: str
    doc_category: str | None = None
    text: str
    chars: int


class PipelineRunRequest(BaseModel):
    """``POST /pipeline/run``.

    ``session_id`` is optional *here* because the session may instead arrive in
    the ``X-Session-Id`` header (build doc section 9.9); the route requires one of
    the two and answers 401 ``SESSION_EXPIRED`` when neither resolves to a live
    session.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: str | None = Field(default=None, max_length=MAX_ID_LEN)
    user_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    doc_id: str = Field(min_length=1, max_length=MAX_ID_LEN)
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)
    strategy: StrategyName | None = None


class AuditQueryResponse(BaseModel):
    """``GET /audit``. Paginated slice of the hash-chained log.

    ``AuditEvent`` cannot hold an original value by construction (build doc
    section 9.8), so this response is safe to expose to a compliance reader
    without further filtering.
    """

    events: list[AuditEvent]
    returned: int
    limit: int
    offset: int


class AuditVerifyResponse(BaseModel):
    """``GET /audit/verify``. Tamper-evidence check over the chain."""

    valid: bool
    length: int
    session_id: str | None = None


class HealthResponse(BaseModel):
    """``GET /health``. Liveness plus the two things that can actually be broken.

    ``model_loaded`` is false when the spaCy pipeline failed to load at startup;
    the app still boots so the failure is *reportable* rather than a container
    that will not start. ``db_reachable`` is probed live, by counting the audit
    log. Either false ⇒ ``status="degraded"`` and HTTP 503.
    """

    status: Literal["ok", "degraded"]
    model_loaded: bool
    db_reachable: bool
    spacy_model: str
    llm_provider: str
    llm_model: str
    strategy: str
    ui_mounted: bool
    active_sessions: int


class ErrorResponse(BaseModel):
    """Every non-2xx body the API produces.

    ``code`` is the domain error's machine code (``SESSION_EXPIRED``,
    ``EGRESS_BLOCKED``, ``NOT_FOUND``, ...). ``detail`` is the exception's
    structured detail map: reasons, counts, identifiers. **Never content.**
    """

    code: str
    detail: dict[str, int | float | str | None] = Field(default_factory=dict)
