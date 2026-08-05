"""``POST /documents`` and ``GET /documents/{doc_id}/text``.

The upload leaves plaintext nowhere: the original bytes and the extracted text
are both stored as AES-256-GCM ciphertext under a key derived from the caller's
``user_id``. The read-back is one of exactly two endpoints in the system allowed
to return an original value, and access control *is* the decrypt.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, Form, UploadFile
from fastapi import status as http_status

from secure_context_pipeline.api.constants import HTTP_413_TOO_LARGE, MAX_UPLOAD_BYTES
from secure_context_pipeline.api.deps import (
    _ERRORS,
    ApiError,
    DocIdPath,
    ServicesDep,
    UserIdQuery,
)
from secure_context_pipeline.api.schemas import (
    MAX_ID_LEN,
    DocumentTextResponse,
    DocumentUploadResponse,
)
from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.store.document_store import DOC_CATEGORIES, InvalidCategoryError

router = APIRouter()


@router.post(
    "/documents",
    response_model=DocumentUploadResponse,
    responses=_ERRORS,
    tags=["documents"],
    summary="Upload a document (PDF / DOCX / TXT / MD)",
)
async def upload_document(
    services: ServicesDep,
    file: Annotated[UploadFile, File(description="PDF, DOCX, TXT or MD.")],
    user_id: Annotated[str, Form(min_length=1, max_length=MAX_ID_LEN)],
    doc_category: Annotated[
        str | None,
        Form(
            max_length=MAX_ID_LEN,
            description=f"One of {sorted(DOC_CATEGORIES)}; omit for unclassified.",
        ),
    ] = None,
) -> DocumentUploadResponse:
    """Extract, encrypt under ``doc_key(user_id)``, and store.

    Plaintext exists only for the duration of the call: the original bytes
    and the extracted text are both written as AES-256-GCM ciphertext, and
    SQLite holds metadata only. Nothing about the content -- not a length, not
    a first line -- is echoed back.
    """
    if file.size is not None and file.size > MAX_UPLOAD_BYTES:
        raise ApiError(
            HTTP_413_TOO_LARGE,
            "UPLOAD_TOO_LARGE",
            {"max_bytes": MAX_UPLOAD_BYTES, "bytes": file.size},
        )
    # Reached through the app module rather than imported from `deps`, and that
    # is deliberate: `_read_capped` is a substitution seam the API suite already
    # uses (`monkeypatch.setattr(app_module, "_read_capped", ...)`, twice, to
    # prove which of the two upload ceilings actually fires), and a module-level
    # `from ... import` would bind the original past any such substitution. The
    # import is local to keep the package's import graph acyclic.
    from secure_context_pipeline.api import app as app_module

    content = await app_module._read_capped(file)
    if not content:
        raise ApiError(http_status.HTTP_400_BAD_REQUEST, "EMPTY_UPLOAD", {"bytes": 0})

    filename = file.filename or "upload.txt"
    try:
        doc_id = await services.store.put(user_id, filename, content, doc_category)
    except InvalidCategoryError:
        raise  # -> 400, mapped by the registered handler
    except PipelineError as exc:
        # Unsupported or unparseable document: the caller's problem, not a
        # server fault. `exc.detail` carries a suffix and a reason, never bytes.
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST, "UNPROCESSABLE_DOCUMENT", dict(exc.detail)
        ) from exc
    return DocumentUploadResponse(doc_id=doc_id, doc_category=doc_category)


@router.get(
    "/documents/{doc_id}/text",
    response_model=DocumentTextResponse,
    responses=_ERRORS,
    tags=["documents"],
    summary="Original text of a document (owner only)",
)
async def get_document_text(
    services: ServicesDep, doc_id: DocIdPath, user_id: UserIdQuery
) -> DocumentTextResponse:
    """One of exactly two endpoints that may return original values.

    **User-ward only.** This text feeds the demo UI's "original" panel so a
    reviewer can see what the detector found; it is never assembled into an
    outbound payload and never reaches the provider. Access control *is* the
    decrypt: a wrong ``user_id`` derives a different HKDF key, GCM
    authentication fails, and the store raises ``NOT_FOUND`` -- the same
    response, with the same detail, that an absent document produces.
    """
    text = await services.store.get_text(user_id, doc_id)
    category = await services.store.get_category(user_id, doc_id)
    return DocumentTextResponse(
        doc_id=doc_id, doc_category=category, text=text, chars=len(text)
    )
