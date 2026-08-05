"""The error-mapping contract: every non-2xx body is ``{code, detail}``.

Which exception becomes which status code is a security control rather than
ergonomics -- "not your document" and "no such document" answer identically, and
validation failures are rewritten to field names so that no error path can echo
a caller's input back. The reasoning for each mapping is on the registration
below and in :mod:`secure_context_pipeline.api.app`'s module docstring.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

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
    EgressBlockedError,
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


async def _validation_handler(request: Request, exc: Exception) -> Response:
    """Rewrite FastAPI's validation body to field names and counts.

    The default body embeds the offending ``input``. A malformed
    ``/pipeline/run`` body would therefore echo the user's prompt back inside an
    error response, and a future endpoint that accepted document text would echo
    that. Reporting *which fields* failed is all a client needs.
    """
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        raise exc
    fields = sorted({".".join(str(part) for part in err.get("loc", ())) for err in exc.errors()})
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
    # 404: wrong owner and absent document are byte-identical (build doc section 8).
    app.add_exception_handler(StoreAuthError, _pipeline_handler(http_status.HTTP_404_NOT_FOUND))
    # 404: the session's vault entries are gone -- indistinguishable from never
    # having existed, for the same reason.
    app.add_exception_handler(VaultMissError, _pipeline_handler(http_status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(
        InvalidCategoryError, _pipeline_handler(http_status.HTTP_400_BAD_REQUEST)
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
