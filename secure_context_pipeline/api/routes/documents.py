"""``POST /documents`` and ``GET /documents/{doc_id}/text``.

The upload leaves plaintext nowhere: the original bytes and the extracted text
are both stored as AES-256-GCM ciphertext under a key derived from the caller's
``user_id``. The read-back is one of exactly two endpoints in the system allowed
to return an original value, and access control *is* the decrypt.

``POST /documents`` is also the one anonymous route whose cost is measured in
megabytes rather than in rows, so it carries a second meter of its own --
:class:`_ByteMeter`, charged in *durable bytes* -- for the reason set out at
:data:`UPLOAD_BYTES_BURST`.
"""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi import status as http_status

from secure_context_pipeline.api.constants import (
    HTTP_413_TOO_LARGE,
    HTTP_429_TOO_MANY_REQUESTS,
    MAX_UPLOAD_BYTES,
    RATE_LIMIT_MAX_KEYS,
)
from secure_context_pipeline.api.deps import (
    _ERRORS,
    ApiError,
    DocIdPath,
    ServicesDep,
    UserIdQuery,
)
from secure_context_pipeline.api.middleware import _caller_key
from secure_context_pipeline.api.schemas import (
    MAX_ID_LEN,
    DocumentTextResponse,
    DocumentUploadResponse,
)
from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.store.document_store import DOC_CATEGORIES, InvalidCategoryError

router = APIRouter()


# ---------------------------------------------------------------------------
# Per-caller durable-byte metering
# ---------------------------------------------------------------------------
#: Durable bytes one anonymous caller may commit through ``POST /documents`` in a
#: burst, and the rate that budget refills.
#:
#: :data:`~secure_context_pipeline.api.constants.WRITE_BURST` already meters this
#: route -- :class:`~secure_context_pipeline.api.middleware._RateLimit` meters by
#: *method*, so every mutating route is covered and none can be forgotten. What
#: it counts is **requests**, and every number that sized it came from the two
#: cheapest routes it covers: 1 716 bytes of ``audit.db`` per anonymous ``POST
#: /sessions``, 356 per bogus-id ``DELETE``. This route is four orders of
#: magnitude off that. Measured on this build, five anonymous uploads of a
#: 16 777 215-byte body (no session, no ``X-Session-Id``, caller-chosen
#: ``user_id``) grew the data directory by 167 834 235 bytes -- 33 566 847 bytes
#: per request, an amplification of 2.0007x the body, because ``put`` writes both
#: a ``.raw`` and a ``.txt`` blob. At 256 requests of burst and 8.00 accepted
#: requests per second, that is 8.00 GiB of blobs in one burst and 128 MiB/s of
#: bodies -- 256 MiB/s durable -- sustained from one address, forever. Nothing
#: reclaims it: there is no ``DELETE`` on ``/documents``, the store has no TTL and
#: no per-user quota, and ``sweep_orphans`` skips any blob that has a metadata
#: row. The stated impact at :data:`WRITE_BURST` -- "a full disk fails every later
#: write for every user" -- arrives in 31 requests, not 583 000.
#:
#: So the request meter is left exactly as it is and this one is charged in the
#: unit that differs: bytes. 64 MiB of burst is four maximum-size uploads back to
#: back, and 1 MiB/s of refill is one maximum-size upload every 16 s sustained --
#: 128x tighter in body bytes than the request meter alone, and still far above
#: any interactive use of the demo. Measured on this build against the shipped
#: values, with 1 MiB bodies and no credential: 65 uploads accepted in the burst,
#: then 9 accepted against 15 407 refused over 8.0 s, growing the data directory
#: by 18 986 121 bytes -- 2.25 MiB/s durable, against 256 MiB/s before. (2.25
#: rather than 2.01 because the window opened with a part-full bucket, not
#: because the amplification differs: it is 2.0118 for a 1 MiB body, flat across
#: 1, 2, 5 and 10 uploads. The test measures that ratio live rather than pinning
#: it, since it moves the day the store writes a third blob.)
#:
#: It bounds *one caller*; it is not a substitute for a reverse proxy, and
#: it is not a global disk quota. Nothing here changes what a *single* request
#: may allocate: :data:`MAX_BODY_BYTES` and
#: :data:`~secure_context_pipeline.api.constants.MAX_UPLOAD_BYTES` own that, and
#: this meter is charged only after they have both had their say.
UPLOAD_BYTES_BURST = 64 * 1024 * 1024
UPLOAD_BYTES_REFILL_PER_SECOND = 1024.0 * 1024.0

#: Attribute on ``app.state`` holding the live :class:`_ByteMeter`. Distinct from
#: ``rate_limits`` on purpose: that is
#: :class:`~secure_context_pipeline.api.middleware._RateLimits`, a slotted
#: dataclass this module cannot extend, and reaching this one through
#: ``request.app.state`` is what lets a test install a tight meter on a live app
#: without rebuilding it (which would mean loading spaCy again).
UPLOAD_METER_ATTR = "document_upload_bytes"


class _ByteMeter:
    """A per-caller token bucket whose tokens are **bytes**, not requests.

    Same arithmetic and the same bounded-map discipline as
    :class:`~secure_context_pipeline.api.middleware._RateLimiter` -- and
    deliberately a separate class rather than a parameter on that one, because
    the two meters answer different questions and the request meter's contract
    ("one token per state-changing request, before the body is read") is not one
    a cost argument should be able to blur.

    ``take`` either spends ``cost`` tokens and returns ``0.0``, or spends nothing
    and returns the seconds until the bucket holds ``cost``. No sleeping, no
    locking: the whole operation is a few arithmetic steps between two ``await``
    points, so it cannot interleave with itself on one event loop.

    ``_buckets`` is keyed by caller, so an unbounded map would be the very
    memory-growth primitive this exists to remove. Every access re-inserts its
    key, making insertion order a recency order, and the oldest entry is evicted
    past ``max_keys``. Eviction can only ever turn a denied request into an
    allowed one -- a forgotten caller returns with a full bucket, exactly how an
    unseen caller starts -- so it is safe in the direction that matters.

    ``time.monotonic``, never ``time.time``: a clock step backwards would either
    mint tokens or freeze the bucket for the length of the step.
    """

    __slots__ = ("_buckets", "capacity", "max_keys", "refill_per_second")

    def __init__(
        self,
        *,
        capacity: int,
        refill_per_second: float,
        max_keys: int = RATE_LIMIT_MAX_KEYS,
    ) -> None:
        if capacity < 1:
            raise ValueError(f"byte meter capacity must be >= 1, got {capacity}")
        if refill_per_second <= 0.0:
            raise ValueError(f"byte meter refill must be > 0, got {refill_per_second}")
        if max_keys < 1:
            raise ValueError(f"byte meter max_keys must be >= 1, got {max_keys}")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}

    def take(self, key: str, cost: int, *, now: float | None = None) -> float:
        """Spend ``cost`` bytes for ``key``. ``0.0`` if allowed, else seconds to wait.

        ``now`` is injectable so a test can drive refill deterministically rather
        than by sleeping -- the alternative is a test whose green depends on how
        loaded the machine is.
        """
        charge = max(0, cost)
        moment = time.monotonic() if now is None else now
        tokens, last = self._buckets.pop(key, (float(self.capacity), moment))
        elapsed = max(0.0, moment - last)
        tokens = min(float(self.capacity), tokens + elapsed * self.refill_per_second)
        if tokens >= charge:
            tokens -= charge
            wait = 0.0
        else:
            wait = (charge - tokens) / self.refill_per_second
        self._buckets[key] = (tokens, moment)
        while len(self._buckets) > self.max_keys:
            self._buckets.pop(next(iter(self._buckets)))
        return wait

    def tracked(self) -> int:
        """How many callers are currently held. For assertions about the bound."""
        return len(self._buckets)


def _upload_meter(request: Request) -> _ByteMeter:
    """The app's durable-byte meter, built on first use.

    Fail-closed by construction: there is no "no meter installed, pass anyway"
    branch here, because unlike the middleware -- which must never be the reason
    a correctly built app refuses traffic -- an unmetered upload route is the
    defect. Anything already on ``app.state`` under :data:`UPLOAD_METER_ATTR`
    wins, which is the substitution seam the tests use.
    """
    meter = getattr(request.app.state, UPLOAD_METER_ATTR, None)
    if not isinstance(meter, _ByteMeter):
        meter = _ByteMeter(
            capacity=UPLOAD_BYTES_BURST,
            refill_per_second=UPLOAD_BYTES_REFILL_PER_SECOND,
        )
        setattr(request.app.state, UPLOAD_METER_ATTR, meter)
    return meter


@router.post(
    "/documents",
    response_model=DocumentUploadResponse,
    responses=_ERRORS,
    tags=["documents"],
    summary="Upload a document (PDF / DOCX / TXT / MD)",
)
async def upload_document(
    request: Request,
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

    Three ceilings, in this order, and each bounds something the next one cannot.
    :class:`~secure_context_pipeline.api.middleware._BodyLimit` and the request
    meter run above this frame and bound what arrives; ``file.size`` and
    ``_read_capped`` bound what *this* frame buffers; and the byte meter bounds
    what the caller may leave on the disk *after* the response, which is the only
    one of the three that is not reclaimed when the request ends. That last
    charge is deliberately the last thing before ``put`` and not one line
    earlier: it must be paid by every request that is about to write blobs,
    including one whose document turns out to be unparseable, and it must not be
    paid by a request that :data:`MAX_UPLOAD_BYTES` has already refused.
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

    # Charged on the body's own length, not on the durable total: the 2.0007x
    # amplification `put` applies is a property of the store, and a meter that
    # multiplied by a constant here would go quietly wrong the day the store
    # writes a third blob. The budget at `UPLOAD_BYTES_BURST` is stated in body
    # bytes and the amplification is recorded there.
    wait = _upload_meter(request).take(_caller_key(request.scope), len(content))
    if wait > 0.0:
        raise ApiError(
            HTTP_429_TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            {"retry_after_seconds": round(wait, 1)},
        )

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
