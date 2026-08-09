"""The error-mapping contract: every non-2xx body is ``{code, detail}``.

Which exception becomes which status code is a security control rather than
ergonomics -- "not your document" and "no such document" answer identically, and
validation failures are rewritten to field names so that no error path can echo
a caller's input back. The reasoning for each mapping is on the registration
below and in :mod:`secure_context_pipeline.api.app`'s module docstring.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping

from fastapi import FastAPI, Request, Response
from fastapi import status as http_status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from secure_context_pipeline.api.constants import HTTP_422_UNPROCESSABLE
from secure_context_pipeline.api.deps import ApiError
from secure_context_pipeline.api.schemas import ErrorResponse
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
    AuditUnavailableError,
    EgressBlockedError,
    PayloadTooLargeError,
    PipelineError,
    SessionExpiredError,
    StoreAuthError,
    VaultMissError,
)
from secure_context_pipeline.llm.base import LLMError
from secure_context_pipeline.store.document_store import InvalidCategoryError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception handlers -- the error-mapping contract
# ---------------------------------------------------------------------------
def _json(status_code: int, code: str, detail: dict[str, int | float | str | None]) -> JSONResponse:
    body = ErrorResponse(code=code, detail=detail)
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def _pipeline_handler(
    status_code: int, *, log_level: int = logging.INFO
) -> Callable[[Request, Exception], Awaitable[Response]]:
    """Map a :class:`PipelineError` subclass onto a fixed status code.

    The body is always ``{"code": ..., "detail": {...}}``, built from the
    exception's own structured detail -- which the hierarchy guarantees is
    content-free. Nothing is reformatted, summarised, or enriched here: an error
    path that composed its own message would be a new place for a value to leak.
    """

    async def handler(request: Request, exc: Exception) -> Response:
        if not isinstance(exc, PipelineError):  # pragma: no cover -- registration guarantees it
            raise exc
        logger.log(
            log_level,
            "request rejected",
            extra={
                "route": request.url.path,
                "error_code": exc.code,
                "status_code": status_code,
                "detail_keys": len(exc.detail),
            },
        )
        return _json(status_code, exc.code, dict(exc.detail))

    return handler


async def _api_error_handler(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, ApiError):  # pragma: no cover -- registration guarantees it
        raise exc
    logger.info(
        "request rejected",
        extra={"route": request.url.path, "error_code": exc.code, "status_code": exc.status_code},
    )
    return _json(exc.status_code, exc.code, dict(exc.detail))


#: Stand-in for the caller's own key in an ``extra="forbid"`` rejection. See
#: :func:`_field_name`.
EXTRA_FIELD_MARKER = "<extra>"


def _field_name(err: Mapping[str, object]) -> str:
    """The dotted location of one validation failure, with no caller bytes in it.

    Every part of a pydantic ``loc`` is a name from the *schema* -- except for an
    ``extra_forbidden`` error, where the last part is the key the **caller**
    invented. ``SessionCreateRequest`` and ``PipelineRunRequest`` both declare
    ``extra="forbid"``, so joining ``loc`` verbatim reflected up to
    :data:`MAX_DETAIL_VALUE_LEN` characters of attacker-chosen text straight back
    out of the 422 body: measured on this build, a body carrying
    ``{"evil_field_<script>": 1}`` answered
    ``{"code":"VALIDATION_ERROR","detail":{"errors":1,"fields":"body.evil_field_<script>"}}``.

    That is small -- 64 characters, JSON-escaped, on a response with
    ``content-type: application/json``, ``nosniff`` and a ``default-src 'none'``
    CSP, so it is not a live XSS -- but this module's own docstring promises "no
    error path can echo a caller's input back", and ``app.py`` repeats it. A
    guarantee with one unstated exception is the shape this project keeps finding
    and fixing, so the exception is removed rather than documented.

    ``body.<extra>`` keeps the part a client can act on (an unexpected key, and
    where) and drops the part only the caller already knows. The ``errors`` count
    beside it still reports how many there were; the *names* dedupe to one entry.
    """
    raw = err.get("loc")
    # `errors()` is `list[Any]` to mypy, so the shape is checked rather than trusted;
    # an entry that is not a sequence of parts contributes nothing to the name and
    # certainly must not be `str()`-ed wholesale into the body.
    loc: tuple[object, ...] = tuple(raw) if isinstance(raw, tuple | list) else ()
    if err.get("type") == "extra_forbidden" and loc:
        loc = (*loc[:-1], EXTRA_FIELD_MARKER)
    return ".".join(str(part) for part in loc)


async def _validation_handler(request: Request, exc: Exception) -> Response:
    """Rewrite FastAPI's validation body to field names and counts.

    The default body embeds the offending ``input``. A malformed
    ``/pipeline/run`` body would therefore echo the user's prompt back inside an
    error response, and a future endpoint that accepted document text would echo
    that. Reporting *which fields* failed is all a client needs -- and the field
    name itself is laundered through :func:`_field_name`, because under
    ``extra="forbid"`` the name is the caller's too.
    """
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        raise exc
    fields = sorted({_field_name(err) for err in exc.errors()})
    logger.info(
        "request rejected",
        extra={
            "route": request.url.path,
            "error_code": "VALIDATION_ERROR",
            "status_code": HTTP_422_UNPROCESSABLE,
            "field_count": len(fields),
        },
    )
    return _json(
        HTTP_422_UNPROCESSABLE,
        "VALIDATION_ERROR",
        {"errors": len(exc.errors()), "fields": ",".join(fields)[:MAX_DETAIL_VALUE_LEN]},
    )


async def _http_exception_handler(request: Request, exc: Exception) -> Response:
    """Re-render Starlette's own ``HTTPException`` into :class:`ErrorResponse`.

    "Every non-2xx body is ``{code, detail}``" was not quite true. Anything
    raised outside this module's hierarchy -- a 404 from the static mount, and
    notably the ``400 There was an error parsing the body`` that ``python-multipart``
    raises on a malformed or over-long multipart header -- fell through to
    Starlette's default ``{"detail": "<free text>"}``. A client parsing ``code``
    got ``KeyError`` on exactly the paths where it most needs a machine answer,
    and the free-text half is the one shape in the API that is not built from a
    length-capped structured map.
    """
    if not isinstance(exc, HTTPException):  # pragma: no cover -- registration guarantees it
        raise exc
    code = "NOT_FOUND" if exc.status_code == http_status.HTTP_404_NOT_FOUND else "BAD_REQUEST"
    return _json(exc.status_code, code, {"status": exc.status_code})


def _register_handlers(app: FastAPI) -> None:
    # 401: expired, destroyed, unknown, missing -- one indistinguishable answer.
    app.add_exception_handler(
        SessionExpiredError, _pipeline_handler(http_status.HTTP_401_UNAUTHORIZED)
    )
    # 422: the fail-closed gate refused to release the payload. Surfaced loudly --
    # the structured reason and hit count are the demo's evidence that the block
    # happened, and are also all a caller ever learns: naming the matched value
    # would leak exactly what the gate exists to stop.
    app.add_exception_handler(
        EgressBlockedError,
        _pipeline_handler(HTTP_422_UNPROCESSABLE, log_level=logging.WARNING),
    )
    # 422: the assembled payload is larger than one provider call can carry, refused
    # before the gate runs and before any network call is constructed.
    #
    # Not 413. That status describes the *request entity*, and the request here is a
    # small JSON body naming a document that was uploaded and accepted earlier -- the
    # two codes that do mean "your request was too big", ``UPLOAD_TOO_LARGE`` and
    # ``REQUEST_TOO_LARGE``, answer 413 and are counted by bytes on the wire. This one
    # is a well-formed request the server cannot carry out, which is 422, and it is the
    # same status as ``EGRESS_BLOCKED`` on purpose: both are the pipeline declining to
    # make a provider call, and a client that already branches on 422 for "refused, no
    # model call was made" gets this one right by reading ``code``.
    #
    # WARNING rather than INFO for the same reason the gate's block is: a refusal a
    # caller cannot fix by retrying is worth a line in an operator's log.
    app.add_exception_handler(
        PayloadTooLargeError,
        _pipeline_handler(HTTP_422_UNPROCESSABLE, log_level=logging.WARNING),
    )
    # 404: wrong owner and absent document are byte-identical (build doc section 8).
    app.add_exception_handler(StoreAuthError, _pipeline_handler(http_status.HTTP_404_NOT_FOUND))
    # 404: the session's vault entries are gone -- indistinguishable from never
    # having existed, for the same reason.
    app.add_exception_handler(VaultMissError, _pipeline_handler(http_status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(
        InvalidCategoryError, _pipeline_handler(http_status.HTTP_400_BAD_REQUEST)
    )
    # 503: the audit log is unreadable, so the operation was refused. The pipeline
    # is healthy and a store it depends on is not, which is the same thing
    # ``/health`` already answers 503 for when the audit connection is gone
    # (``test_health_reports_degraded_when_the_audit_database_is_unreachable``) --
    # so this is the existing vocabulary for the condition rather than a new one.
    #
    # Not 500. What this replaces *was* a 500 -- a bare ``text/plain`` "Internal
    # Server Error" with no ``code``, no CSP and no ``nosniff``, because Starlette's
    # ServerErrorMiddleware renders an unhandled exception outside the middleware
    # that adds them -- and the point of the change is that a client can tell "this
    # deployment's audit store is broken, and no request will succeed until an
    # operator restores it" from "the pipeline has a bug". 500 is where the second
    # lives, one registration below.
    #
    # No ``Retry-After``: the condition is not transient. Every retry re-reads the
    # same dead page, and a header inviting one would be the same wrong advice the
    # generic 500 gave. The ``remedy`` field carries what actually works.
    #
    # A NEW CODE IS A THREE-FILE CHANGE in this repo, and the third file is easy to
    # miss: ``tests/test_ui_behaviour.py`` walks every ``PipelineError`` subclass and
    # requires a sentence for its code in ``ui/app.js``'s SENTENCES table (plus a row
    # in that file's ``_CODE_SENTENCES``). Until it has one the demo UI still renders
    # this correctly -- the unknown-code path prints the code and the detail map, and
    # ``test_an_unknown_error_code_still_renders_everything_the_body_carried`` pins
    # that -- which is why ``remedy`` is a field in the body rather than prose the UI
    # is trusted to supply.

    app.add_exception_handler(
        AuditUnavailableError,
        _pipeline_handler(http_status.HTTP_503_SERVICE_UNAVAILABLE, log_level=logging.ERROR),
    )
    # 502: the provider failed. The pipeline is healthy; the upstream is not.
    app.add_exception_handler(
        LLMError, _pipeline_handler(http_status.HTTP_502_BAD_GATEWAY, log_level=logging.ERROR)
    )
    # 500: anything else in the hierarchy. Still structured, still content-free.
    app.add_exception_handler(
        PipelineError,
        _pipeline_handler(http_status.HTTP_500_INTERNAL_SERVER_ERROR, log_level=logging.ERROR),
    )
    app.add_exception_handler(ApiError, _api_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)
    # Everything raised outside the hierarchy above -- a static-mount 404, a
    # multipart parse failure -- still answers the one documented error shape.
    app.add_exception_handler(HTTPException, _http_exception_handler)
