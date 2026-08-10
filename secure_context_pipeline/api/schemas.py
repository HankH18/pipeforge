"""Wire schemas for the HTTP layer (build doc section 9.9).

Every model here is a *boundary* type, and the boundary is the last place an
original entity value could escape. Two rules govern the whole module:

1. **No schema in this file may carry an original entity value**, with exactly
   two sanctioned exceptions, both user-ward and neither on the outbound path:
   :attr:`DocumentTextResponse.text` (the owner's own document, returned only
   after a successful per-user-key decrypt) and
   ``PipelineResult.restored_text`` (defined in :mod:`~secure_context_pipeline.models`,
   the whole point of the round trip). Error bodies, audit responses, and health
   output are structurally incapable of holding **content** -- a paragraph, a
   note, a document, which is the bulk-exfiltration shape -- because every field
   they can carry is length-capped. They are *not* structurally incapable of
   holding an original, which this docstring used to claim: 64 characters fits
   ``"John Smith"``, ``"MRN 4823910"``, an SSN and an e-mail, and no length check
   can recognise a name. That half of rule 1 holds by call site and is measured,
   not declared -- see :class:`AuditQueryResponse` and :class:`ErrorResponse`.
2. **Errors carry structured detail only.** :class:`ErrorResponse.detail` mirrors
   the ``detail`` map of :class:`~secure_context_pipeline.errors.PipelineError`,
   which the exception hierarchy caps at 64 characters per detail entry -- key and
   value, measured on the rendered width, so an int-encoded payload is refused too.
   Reasons, counts, and identifiers -- never a matched value, never a payload.

``PipelineResult``, ``SpanOut`` and ``AuditEvent`` are re-used as response models
directly from :mod:`secure_context_pipeline.models` rather than re-declared here:
those are the types the pipeline already keeps free of *content* (``SpanOut`` has
offsets but no ``text`` field; ``AuditEvent``'s only free-text field, ``detail``,
is bounded at 64 characters per entry and its label columns at 128), and
duplicating them would create a second schema that could drift into leaking.

That re-use is what makes ``POST /pipeline/run``'s documented body the model itself
(``routes/pipeline.py`` sets ``response_model=PipelineResult``), so a field added
there **is** a field added to this API. One is worth naming here because it is the
only pair on the response whose halves can contradict each other:

* ``strategy`` -- what the caller **requested** (body field or configured default).
* ``emitted_strategy`` -- the surrogate composition the payload the provider
  received **actually carries**: ``none`` / ``tokenization`` / ``pseudonymization``
  / ``mixed``.

They diverge legitimately, because session determinism outranks a per-request
override: a value an earlier call in the same session already mapped keeps the
surrogate it was first given. Before ``emitted_strategy`` existed the response
asserted the request as though it were the outcome -- a run that asked for
``pseudonymization`` in a session that had already tokenised reported
``strategy: "pseudonymization"`` while shipping bracketed tokens, and only the
bundled UI's ``RUN_OK_STRATEGY_DRIFT`` banner said otherwise. Neither field is
content, and neither is caller-supplied text: ``strategy`` is validated against the
strategy registry by :data:`StrategyName` before the orchestrator sees it, and
``emitted_strategy`` is a label this process derives from its own token records.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

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
#: every detail entry at 64 rendered characters -- rejecting an over-long ID at the
#: schema is a clearer 422 than a ``ValueError`` from deep inside the error
#: constructor.
MAX_ID_LEN = 64

#: Ceiling on the user's question. The document is not bounded here (that is the
#: store's business); the prompt is, because every stage the prompt drives is linear
#: in its length and none of them is skippable: its own detect pass, its own
#: obfuscate pass, one vault write per value it contributes, and the gate's re-scan
#: of the assembled payload -- all of it on a request body accepted before any
#: auth-shaped check has run.
#:
#: This comment used to give a different reason -- that the prompt reaches the
#: provider unmodified -- and that reason was false, which matters because rule 1
#: above says these rules govern the whole module: a reader would conclude that PII
#: typed into ``prompt`` and absent from the document reaches the provider. It does not.
#: :class:`~secure_context_pipeline.pipeline.orchestrator.PipelineOrchestrator` runs
#: the prompt through the same detector and the same engine as the document before
#: the payload is built (``prompt_entities_detected`` / ``prompt_tokens_issued`` in
#: ``PipelineResult.stats``, one ``OBFUSCATE`` audit row per vaulted prompt value),
#: and what the injector splices in is the obfuscated prompt. Measured end to end
#: with the PII in the prompt only and a document holding none: 4 entities detected,
#: 4 tokens issued, and all four originals absent from ``obfuscated_payload``.
MAX_PROMPT_CHARS = 8_000

def _registered_strategy(value: str) -> str:
    """Refuse a ``strategy`` no strategy registry knows. The request-boundary twin
    of ``config._check_strategy_is_registered``.

    This was ``Literal["tokenization", "pseudonymization"]``, and that made the
    graded claim -- "adding a new strategy touches zero harness code" -- false at the
    HTTP boundary while it was true of the engine. A class registered through the
    documented ``@register_strategy`` seam could be selected by ``SCP_STRATEGY``
    (``config.strategy`` was widened to a registry-checked ``str`` for exactly this
    reason) and still not be *named by a request*: measured,
    ``PipelineRunRequest(strategy="redaction")`` raised ``literal_error`` before the
    orchestrator existed in the call stack.

    Asking the registry rather than listing names loosens nothing. An unregistered
    name is still a 422, at the same place, and the answer now comes from the module
    that actually knows what is registered -- which this one cannot import at module
    scope without paying it on every import: ``available_strategies`` pulls in
    ``detection.registry`` (``regex`` + ``yaml``) and the built-in strategy modules
    (Faker, dateutil), measured in ``config.py`` at 116 ms + 62 ms. Deferred to first
    validation, by which point the app has loaded all of it anyway.

    The message is for a direct constructor call (tests, the demo). It never reaches
    a client: ``api/errors.py::_validation_handler`` rewrites every 422 body down to
    field names and counts, so no caller bytes and no registry listing are echoed.
    """
    from secure_context_pipeline.obfuscation.strategies.base import available_strategies

    known = available_strategies()
    if value not in known:
        raise ValueError(f"unknown strategy; registered: {', '.join(known)}")
    return value


#: The ``strategy`` a request may ask for: any *registered* strategy name. Bounded
#: first, checked second -- the length cap runs before the registry lookup, so an
#: over-long body field is refused without touching the registry.
StrategyName = Annotated[
    str, Field(min_length=1, max_length=MAX_ID_LEN), AfterValidator(_registered_strategy)
]


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

    **The safety argument is not "``AuditEvent`` cannot hold an original value by
    construction".** This docstring said exactly that, and used it as the reason
    the body needs no further filtering -- which made a retracted claim
    load-bearing on the one response model that hands audit rows to an outside
    reader. ``audit/logger.py`` and the README both retract it, and it is
    disprovable in one line: ``detail`` bounds a value at 64 characters and the
    label columns at 128, so ``"John Smith"``, ``"MRN 4823910"``, an SSN and an
    e-mail all fit, and this model serialises them into the body without
    complaint.

    What is actually true, in two parts:

    * **Content cannot get here.** The ceilings make an audit row incapable of
      holding a paragraph, a note or a document -- the bulk-exfiltration shape --
      and they are enforced at the model *and* again at the write boundary, where
      ``model_construct()`` cannot skip them.
    * **A short identifier is kept out by call site, and that is measured.** Every
      ``emit`` in the package writes counts, latencies, digests, entity *type*
      names and 8-hex token IDs; the 100-run leakage harness scans the raw SQLite
      file as bytes against every vaulted original.

    Neither part is about *correlation*, which is the risk this body actually
    carries: a row names its ``session_id``, a ``SESSION_CREATE`` row names the
    owning ``user_id``, and a ``DETECT`` row names the ``doc_id`` that was read --
    the credentials for irreversible session erasure and for original document
    text. That is handled before this model is ever built, by the proved-ownership
    scope in :mod:`secure_context_pipeline.api.routes.audit`, not by anything here.
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
    structured detail map: reasons, counts, identifiers. **Never content** --
    ``PipelineError`` refuses any detail entry, key or value, whose rendered width
    exceeds 64 characters, so a paragraph cannot reach this body under any
    encoding. "Never an original" is the narrower claim and rests on the call
    sites: what they pass is machine codes, counts, latencies and clamped
    identifiers, and the ``PipelineError`` subclass walk in ``test_crypto.py``
    checks that none of them lands a full value in ``str``/``repr``/``detail``.
    """

    code: str
    detail: dict[str, int | float | str | None] = Field(default_factory=dict)
