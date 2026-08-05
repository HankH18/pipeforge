"""Raw-ASGI middleware, the per-caller meters, and the static UI mount.

Everything here runs *outside* the application, which is the load-bearing part:
the meters and the body limit refuse a request before a handler or a parser sees
any of it, and the security headers are stamped onto those refusals as well as
onto every normal response. :func:`secure_context_pipeline.api.app.create_app`
installs them, and the comment there records why the order is what it is.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass

from fastapi import FastAPI, Response
from fastapi import status as http_status
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secure_context_pipeline.api.constants import (
    HTTP_413_TOO_LARGE,
    HTTP_429_TOO_MANY_REQUESTS,
    MAX_BODY_BYTES,
    METERED_METHODS,
    RATE_LIMIT_MAX_KEYS,
    SECURITY_HEADERS,
    UI_DIRNAME,
)
from secure_context_pipeline.api.schemas import ErrorResponse
from secure_context_pipeline.config import PACKAGE_ROOT

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-caller metering
# ---------------------------------------------------------------------------
class _RateLimiter:
    """A token bucket per caller. Synchronous, in-process, and deliberately dumb.

    ``take()`` either consumes a token and returns ``0.0``, or consumes nothing
    and returns the seconds until one is free. No sleeping, no locking: the whole
    operation is a few arithmetic steps between two ``await`` points, so it cannot
    interleave with itself on one event loop, and a second process would need a
    shared store anyway -- which is the reverse proxy's job, not this one's.

    **Bounded by construction.** ``_buckets`` is keyed by caller, so an unbounded
    map would hand an attacker the memory-growth primitive the limiter is partly
    there to remove. Every access re-inserts its key, which makes the dict's
    insertion order a recency order, and the oldest entry is evicted past
    :data:`RATE_LIMIT_MAX_KEYS`. Evicting is safe in the only direction it can go
    wrong: a forgotten caller comes back with a *full* bucket, which is how an
    unseen caller starts -- eviction can never turn an allowed request into a
    denied one, only the reverse, and reaching the ceiling needs 4 096 distinct
    addresses in one window.

    ``time.monotonic``, never ``time.time``: a clock step backwards would
    otherwise mint tokens (negative elapsed is clamped anyway) or freeze the
    bucket for the length of the step.
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
            raise ValueError(f"rate limiter capacity must be >= 1, got {capacity}")
        if refill_per_second <= 0.0:
            raise ValueError(f"rate limiter refill must be > 0, got {refill_per_second}")
        if max_keys < 1:
            raise ValueError(f"rate limiter max_keys must be >= 1, got {max_keys}")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}

    def take(self, key: str, *, now: float | None = None) -> float:
        """Spend one token for ``key``. ``0.0`` if allowed, else seconds to wait.

        ``now`` is injectable so a test can drive refill deterministically rather
        than by sleeping -- the alternative is a test whose green depends on how
        loaded the machine is.
        """
        moment = time.monotonic() if now is None else now
        tokens, last = self._buckets.pop(key, (float(self.capacity), moment))
        elapsed = max(0.0, moment - last)
        tokens = min(float(self.capacity), tokens + elapsed * self.refill_per_second)
        if tokens >= 1.0:
            tokens -= 1.0
            wait = 0.0
        else:
            wait = (1.0 - tokens) / self.refill_per_second
        self._buckets[key] = (tokens, moment)
        while len(self._buckets) > self.max_keys:
            self._buckets.pop(next(iter(self._buckets)))
        return wait

    def tracked(self) -> int:
        """How many callers are currently held. For assertions about the bound."""
        return len(self._buckets)


@dataclass(slots=True)
class _RateLimits:
    """The app's meters. Held on ``app.state`` so a test can substitute a tight one.

    Reached through ``scope["app"]`` rather than captured at construction, for
    exactly that reason: Starlette sets ``scope["app"]`` before the middleware
    stack runs, so :class:`_RateLimit` reads whatever is installed *now*, and a
    test can swap in a two-token bucket without rebuilding the application (which
    would mean loading spaCy again).
    """

    writes: _RateLimiter
    audit_proofs: _RateLimiter


def _caller_key(scope: Scope) -> str:
    """Who to meter. The peer address, and nothing a request can choose.

    Not ``X-Forwarded-For``: that header is attacker-supplied, so keying on it
    would let one caller mint a fresh budget per request and the meter would read
    as enforced while metering nothing. A deployment behind a proxy therefore
    meters *the proxy* here and must do per-client limiting at the edge, or
    populate ``scope["client"]`` from a trusted hop (``--proxy-headers`` with
    ``--forwarded-allow-ips``) so this key is the real peer again.
    """
    client = scope.get("client")
    if isinstance(client, (tuple, list)) and client:
        return str(client[0])
    return "-"


def _limits(app_state: object) -> _RateLimits | None:
    limits = getattr(app_state, "rate_limits", None)
    return limits if isinstance(limits, _RateLimits) else None


# ---------------------------------------------------------------------------
# Static UI
# ---------------------------------------------------------------------------
class _SecurityHeaders:
    """Stamp :data:`SECURITY_HEADERS` onto every response.

    Raw ASGI rather than ``BaseHTTPMiddleware`` deliberately: the latter buffers
    a streaming response, and the mounted ``StaticFiles`` serves ``FileResponse``
    with ``accept-ranges``. This only rewrites the ``http.response.start``
    message, so bodies, ranges and status codes are untouched.

    ``setdefault``, not assignment: a handler that has already made a narrower
    decision for its own response keeps it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS:
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


async def _send_too_large(send: Send, *, limit: int, received: int) -> None:
    """Emit the one documented error shape straight onto the ASGI channel.

    :class:`_BodyLimit` runs outside the exception middleware, so it cannot raise
    its way to :func:`_json`; the body is built from the same
    :class:`~secure_context_pipeline.api.schemas.ErrorResponse` model so the
    ``{code, detail}`` contract holds on this path too. ``received`` is the
    caller's own byte count, never a byte of what was sent, and ``limit`` comes
    from the middleware instance rather than the module constant so a differently
    configured one cannot report a ceiling it is not enforcing.
    """
    payload = json.dumps(
        ErrorResponse(
            code="REQUEST_TOO_LARGE",
            detail={"max_bytes": limit, "bytes": received},
        ).model_dump(mode="json")
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": HTTP_413_TOO_LARGE,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


async def _send_rate_limited(send: Send, *, retry_after: float) -> None:
    """Emit ``429 RATE_LIMITED`` straight onto the ASGI channel.

    Same reasoning as :func:`_send_too_large`: :class:`_RateLimit` runs outside
    the exception middleware and cannot raise its way to :func:`_json`, so the
    body is built from :class:`ErrorResponse` to keep the ``{code, detail}``
    contract true on this path too. ``Retry-After`` is whole seconds because the
    header's grammar says so, rounded *up* so a client that obeys it is never
    refused twice for the same reason.
    """
    seconds = max(1, math.ceil(retry_after))
    payload = json.dumps(
        ErrorResponse(
            code="RATE_LIMITED",
            detail={"retry_after_seconds": seconds},
        ).model_dump(mode="json")
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": HTTP_429_TOO_MANY_REQUESTS,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
                (b"retry-after", str(seconds).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class _RateLimit:
    """Meter every state-changing request per caller, before its body is read.

    **In middleware, not in a handler, and that is the load-bearing part.** By
    the time a route function's first statement runs, FastAPI has already awaited
    ``request.body()`` to build the model, so a check there answers 429 *after*
    the caller has chosen the allocation -- the identical status code with the
    defect :data:`MAX_BODY_BYTES` exists to remove. Measured: with the meter
    moved into ``create_session`` the refused request's body is read in full;
    from here, zero bytes are pulled off the stream.

    Its position relative to :class:`_BodyLimit` is *not* load-bearing, which is
    worth saying because it looks as though it should be. Measured both ways: a
    throttled caller reads zero bytes under either order, because neither
    middleware pulls the stream itself. What the order decides is only which
    refusal a request that trips both is told -- 429 here, 413 if ``_BodyLimit``
    were outside -- and the throttle is the more actionable of the two, since the
    caller's problem is not this particular body.

    The predicate is :data:`METERED_METHODS`, a *method* rule rather than a path
    list. A path list is the failure mode this codebase keeps rediscovering: a
    checker that shares a blind spot with the thing it checks, going stale the
    moment someone adds a route. ``GET`` is not metered here because it writes
    nothing durable; the one ``GET`` that can be turned into a write --
    ``/audit`` and its deny record -- carries its own tighter meter.

    Reads the limiter from ``scope["app"].state`` on each request rather than
    capturing it, so a test can install a two-token bucket on a live app. If no
    meter is installed the request passes: this middleware must never be the
    reason a correctly built app refuses traffic.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or str(scope.get("method", "")).upper() not in METERED_METHODS:
            await self.app(scope, receive, send)
            return
        limits = _limits(getattr(scope.get("app"), "state", None))
        if limits is not None:
            wait = limits.writes.take(_caller_key(scope))
            if wait > 0.0:
                logger.warning(
                    "request throttled",
                    extra={
                        "route": str(scope.get("path", "")),
                        "error_code": "RATE_LIMITED",
                        "status_code": HTTP_429_TOO_MANY_REQUESTS,
                    },
                )
                await _send_rate_limited(send, retry_after=wait)
                return
        await self.app(scope, receive, send)


class _BodyLimit:
    """Refuse an over-long request body *while it arrives*, not after.

    Raw ASGI, and outside everything else, because that is the only layer at
    which the refusal can precede the allocation. By the time a FastAPI handler
    runs, ``await request.body()`` (JSON) or ``await request.form()`` (multipart)
    has already consumed the stream to completion, and every ceiling downstream
    of that point -- :data:`MAX_ID_LEN`, :data:`MAX_PROMPT_CHARS`,
    :data:`MAX_UPLOAD_BYTES` -- describes what the server will *answer*, not what
    it will *hold*. A caller with no session and no credential chose the second
    number by choosing how much to send.

    Two enforcement points, because either alone is bypassable:

    * a declared ``Content-Length`` over the ceiling is refused before the body
      is read at all -- one round trip, nothing allocated;
    * bytes are counted as they are received, so withholding the header (or
      lying about it, which is the same thing to an ASGI server that streams)
      buys at most one more chunk.

    Going over converts the stream into ``http.disconnect``. The application
    unwinds on its own -- Starlette raises ``ClientDisconnect``, FastAPI renders
    it -- and that response is *suppressed* so this middleware's 413 is the one
    the caller sees; without the suppression the answer would be FastAPI's
    generic ``400``, which says the body was malformed rather than too large.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    def _declared_length(self, scope: Scope) -> int | None:
        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = self._declared_length(scope)
        if declared is not None and declared > self.max_bytes:
            await _send_too_large(send, limit=self.max_bytes, received=declared)
            return

        received = 0
        over = False

        async def limited_receive() -> Message:
            nonlocal received, over
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    over = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            if over:
                return
            await send(message)

        await self.app(scope, limited_receive, guarded_send)
        if over:
            await _send_too_large(send, limit=self.max_bytes, received=received)


class _NullSafeStaticFiles(StaticFiles):
    """``StaticFiles`` that answers 404 for a path it cannot even look up.

    ``lookup_path`` calls ``os.path.realpath``, which raises ``ValueError:
    embedded null byte`` for any URL containing ``%00`` -- so ``GET /app.js%00``
    was an unauthenticated 500 with a full traceback written to the log on every
    request. That is a free log-flooding primitive for an anonymous caller, and a
    500 where the honest answer is "no such file": a NUL cannot name an asset
    that exists, so it is a miss like any other and gets the identical 404.
    """

    async def get_response(self, path: str, scope: Scope) -> Response:
        if "\x00" in path:
            raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND)
        return await super().get_response(path, scope)


def _mount_ui(app: FastAPI) -> bool:
    """Mount ``ui/`` at ``/``, or skip if it is not there yet.

    Mounted **last**, so every API route is matched first. Absence is not fatal:
    the UI is the one deliverable that can lag the API, and a missing static
    directory must never stop the pipeline from serving requests.
    """
    ui_dir = PACKAGE_ROOT / UI_DIRNAME
    if not ui_dir.is_dir():
        logger.warning("demo UI not mounted; directory absent (path=%s)", ui_dir)
        return False
    app.mount("/", _NullSafeStaticFiles(directory=ui_dir, html=True), name="ui")
    logger.info("demo UI mounted at / (path=%s)", ui_dir)
    return True
