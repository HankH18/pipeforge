"""FastAPI layer -- the only network-facing surface (build doc section 9.9).

    POST   /sessions                  create a session          -> {session_id, expires_at}
    DELETE /sessions/{session_id}     logout (owner only)       -> 204
    POST   /documents                 multipart upload          -> {doc_id}
    GET    /documents/{doc_id}/text   owner-only original text  -> {text, ...}
    POST   /pipeline/run              end-to-end round trip     -> PipelineResult
    GET    /audit                     compliance query (owned)  -> {events, ...}
    GET    /audit/verify              hash-chain check          -> {valid, length}
    GET    /health                    liveness                  -> {status, ...}
    GET    /                          demo UI (static mount of ui/)

The properties below are load-bearing, and each one is here because it was once
false. They are the module's contract, not a summary of it.

**Nothing expensive happens per request.** The spaCy pipeline behind Presidio
costs tens of seconds to load. It is built exactly once, in the lifespan, on a
worker thread (:func:`~secure_context_pipeline.detection.detector.warm_up`), and
so are the registry, the encrypted store, the vault, and the orchestrator. A
request handler only wires arguments into an already-constructed pipeline.

**Error mapping is a security control, not ergonomics.**
:class:`~secure_context_pipeline.errors.StoreAuthError` becomes ``404 NOT_FOUND``
so that "not your document" and "no such document" are byte-identical responses
-- an existence oracle would undo the store's per-user key derivation. *Byte*-
identical is the exact claim and the limit of it: the two paths are not
*time*-identical, because a document that exists is read off disk and fails GCM
authentication while an absent one fails at ``open``. Measured on this build,
400 interleaved pairs: median 0.40 ms absent against 0.57 ms not-yours, the
existing document slower in 96% of pairs. A ``doc_id`` is 128 random bits, so
this cannot be used to *find* one; it confirms one the caller already holds.
Equalising it belongs in
:meth:`~secure_context_pipeline.store.document_store.EncryptedDocumentStore._read_blob`,
which is where the asymmetry is.
:class:`~secure_context_pipeline.errors.SessionExpiredError` becomes ``401`` for
expired, destroyed, unknown *and* missing session IDs, for the same reason.
:class:`~secure_context_pipeline.errors.EgressBlockedError` becomes ``422
EGRESS_BLOCKED`` and is surfaced deliberately: a blocked leak is the system
working, and the demo shows it.

**No response body can carry an original entity value** except the two sanctioned
user-ward paths: ``GET /documents/{doc_id}/text`` (owner-only, decrypted under
that user's derived key, never assembled into an outbound payload) and
``PipelineResult.restored_text``. Error details are the exception hierarchy's
structured ``detail`` maps -- reasons, counts, identifiers, capped at 64
characters per value by :class:`~secure_context_pipeline.errors.PipelineError`.
Validation failures are rewritten to field *names* and counts for the same
reason: FastAPI's default body echoes the offending input back.

**Nothing anonymous may learn a live ``session_id``.** A ``session_id`` is the
bearer credential for ``DELETE /sessions/{session_id}``, and that endpoint is
irreversible by design -- it pops the key, which is the cryptographic erasure of
the whole vault. So no unauthenticated response may contain one: ``/health``
reports a *count* of active sessions, and ``GET /audit`` requires the caller to
name a ``session_id`` or ``run_id`` it already holds. Returning the log unscoped
published every live session ID to anyone who asked, which turned an unauthenticated
``GET`` into the ability to destroy every vault in the process.

**And nothing may turn one identifier into the rest of them.** Requiring a scope
stopped enumeration but left ``GET /audit`` an *assembly oracle*, which is the
same break by a longer route: an anonymous caller holding one ``run_id`` read
that run's ``session_id`` and ``doc_id`` from its events, read the owning
``user_id`` from that session's ``SESSION_CREATE``, and thereby held both
credential pairs -- ``(doc_id, user_id)`` for the original plaintext and
``(session_id, user_id)`` for irreversible erasure. The ``user_id`` second factor
guarding those two endpoints was being issued by this third one. So an audit
scope must now be *proved*: the claimed ``user_id`` is checked against the owner
recorded in the log itself, and an unproved scope reads as empty rather than
forbidden.

**And that proof is exactly as strong as ``user_id`` is secret, which is not
very.** ``POST /sessions`` mints a session for any ``user_id`` an anonymous
caller asks for, so a ``user_id`` is an identity *claim*, not a credential, and
these two endpoints answer right-or-wrong about it: measured on this build, 500
wrong guesses against one ``run_id`` returned an identical empty page each time,
wrote no audit row, cost no delay and triggered no lockout, and the 501st -- the
real owner's name -- returned the run's seven events including its ``session_id``
and ``doc_id``. What the proof buys is therefore real but bounded: an attacker
who has come by one ``run_id`` or ``session_id`` must also guess a human-readable
username to complete the chain, where before they were handed it. Closing the
rest of the gap needs authentication, not a better check here -- the check has no
secret to verify -- which is why it heads the production list below.

**So the window before that lands is metered and loud, which is the half that
was missing.** A failed scope proof is charged against a per-caller budget
(:data:`AUDIT_PROOF_BURST`, refilled at
:data:`AUDIT_PROOF_REFILL_PER_SECOND`) and, if it is within budget, writes an
:data:`AUDIT_ACCESS_DENIED` row naming the claimed ``user_id`` -- filed under
the session the scope resolved to, so the *owner* reads their own intruders out
of the same endpoint the intruder is attacking. The meter is charged before the
row is written, so throttling cannot be turned into unbounded log growth. A
correct owner is never metered: only failures cost. This does not make the
``user_id`` a credential; it makes guessing it slow and permanently recorded
instead of free and invisible.

**Anonymous writes are metered too, by method rather than by path.** Every
state-changing request is charged against a second per-caller budget
(:data:`WRITE_BURST`) by :class:`_RateLimit`, before the body is read.
``POST /sessions`` and ``DELETE /sessions/{id}`` take no credential and both
append to a log that is append-only and unprunable *by construction*: measured,
3 000 anonymous session creations grew ``audit.db`` by 1 716 bytes each and the
in-memory registry by one live session each, and a full disk fails every later
write for every user. Metering by method rather than by a list of paths is
deliberate -- a path list is a checker that shares a blind spot with the routes
it checks -- and ``tests/test_api.py`` walks ``app.routes`` to prove no mutating
route escapes it. It bounds one caller; bounding the *log* needs rotation with
each segment's head hash anchored off-box, and bounding concurrency needs the
reverse proxy this process cannot be.

**A session belongs to one user.** ``POST /sessions`` records the creating
``user_id``, and every endpoint that takes both a session and a ``user_id``
checks that they agree -- answering the same ``401 SESSION_EXPIRED`` as an
unknown session, never a distinguishable "wrong user". Unbound, a session ID was
a credential for *anyone's* documents: presenting it with a different ``user_id``
reached that user's data, and the only obstacle was the ``doc_id`` being
unguessable. That is obscurity, and it sat directly underneath the per-user-key
isolation this design claims.

**A request may not choose how much memory the server spends.** Every schema
ceiling here -- ``user_id`` at 64 characters, ``prompt`` at 8 000,
:data:`MAX_UPLOAD_BYTES` at 16 MB -- is checked against a value that has already
been built, and FastAPI builds it from a body it has already read to the end. The
ceilings therefore described the *answer*, not the allocation: one anonymous
``POST /sessions`` streaming a 256 MB body returned the correct ``422`` after the
process had grown by 768 MB. :class:`_BodyLimit` counts bytes as they arrive and
refuses at :data:`MAX_BODY_BYTES`, before the JSON decoder or the multipart
parser sees any of them.

Authentication is the bare ``user_id`` claim the caller sends. That is take-home
scope, and it is deliberate rather than overlooked: the interesting isolation
property (a wrong ``user_id`` derives a different HKDF key and simply cannot
decrypt) holds regardless of how the claim is obtained. It is also the single
assumption the rest of this docstring leans on -- the audit-scope proof, logout's
owner check and ``/documents/{doc_id}/text`` all compare against a string the
caller asserts about itself. **Production work, in priority order:** real
authentication (OIDC/mTLS) so the ``user_id`` is proven rather than asserted;
per-caller rate limiting, since every route here is anonymous and unmetered and
three of them (``POST /sessions``, ``POST /documents``, ``DELETE /sessions/{id}``)
write durably on each call; CSRF protection for the browser client; and a signed,
``HttpOnly`` session cookie in place of the ``X-Session-Id`` header.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, cast

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, Response, UploadFile
from fastapi import Path as PathParam
from fastapi import status as http_status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secure_context_pipeline.api.schemas import (
    MAX_ID_LEN,
    AuditQueryResponse,
    AuditVerifyResponse,
    DocumentTextResponse,
    DocumentUploadResponse,
    ErrorResponse,
    HealthResponse,
    PipelineRunRequest,
    SessionCreateRequest,
    SessionCreateResponse,
)
from secure_context_pipeline.audit.logger import (
    DEFAULT_DB_FILENAME as AUDIT_DB_FILENAME,
)
from secure_context_pipeline.audit.logger import (
    SESSION_CREATE,
    VAULT_DESTROY,
    AuditLogger,
)
from secure_context_pipeline.config import PACKAGE_ROOT, Settings, get_settings
from secure_context_pipeline.deobfuscation.restorer import Restorer
from secure_context_pipeline.detection.detector import Detector, warm_up
from secure_context_pipeline.detection.registry import EntityRegistry, load_registry
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
    EgressBlockedError,
    PipelineError,
    SessionExpiredError,
    StoreAuthError,
    VaultMissError,
)
from secure_context_pipeline.llm.base import LLMError, build_provider
from secure_context_pipeline.models import AuditEvent, PipelineResult
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.context_injector import ContextInjector
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import (
    DOC_CATEGORIES,
    EncryptedDocumentStore,
    InvalidCategoryError,
)
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import (
    DEFAULT_DB_FILENAME as VAULT_DB_FILENAME,
)
from secure_context_pipeline.vault.session_vault import SessionVault

__all__ = [
    "AUDIT_ACCESS_DENIED",
    "AUDIT_PROOF_BURST",
    "AUDIT_PROOF_REFILL_PER_SECOND",
    "CONTENT_SECURITY_POLICY",
    "DEFAULT_AUDIT_PAGE",
    "MAX_AUDIT_PAGE",
    "MAX_BODY_BYTES",
    "MAX_UPLOAD_BYTES",
    "METERED_METHODS",
    "SECURITY_HEADERS",
    "UI_DIRNAME",
    "UPLOAD_CHUNK_BYTES",
    "WRITE_BURST",
    "WRITE_REFILL_PER_SECOND",
    "ApiError",
    "Services",
    "create_app",
    "get_services",
]

logger = logging.getLogger(__name__)

#: Static demo UI, mounted at ``/``. May legitimately be empty or absent while
#: the UI is being built; the mount is skipped rather than fatal in that case.
UI_DIRNAME = "ui"

#: Ceiling on an uploaded file. Keeps a single request from pinning an arbitrary
#: amount of memory in the extractor.
#:
#: On the live route the enforcement is the ``file.size`` pre-check in
#: :func:`upload_document`, not :func:`_read_capped`: Starlette's multipart
#: parser maintains ``UploadFile.size`` as it writes each part, so the size is
#: known before the handler runs whether or not the client declared a
#: ``Content-Length`` (measured -- a chunked upload with no ``Content-Length``
#: arrives with ``file.size`` already set). :func:`_read_capped` is the backstop
#: for an ``UploadFile`` whose size is unknown, and both are downstream of
#: :data:`MAX_BODY_BYTES`, which is the limit that actually bounds allocation.
#:
#: **This literal is load-bearing for a second ceiling.** :data:`MAX_BODY_BYTES`
#: is *defined* in terms of it, so raising this number raises the request-body
#: limit with it -- and every assertion that phrases the body limit relative to
#: these constants keeps agreeing. Changing ``16`` to ``1024`` here re-created the
#: out-of-memory primitive :data:`MAX_BODY_BYTES` exists to remove (measured: an
#: anonymous 256 MB ``POST /sessions`` again answered 422 after +537 MB RSS) with
#: the entire API test file still green. Both ceilings are therefore pinned to
#: absolute byte counts in ``tests/test_api.py``, not to each other.
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

#: Read granularity for :func:`_read_capped`. Small enough that the overshoot
#: past the ceiling is bounded by one chunk, large enough to keep a 16 MB upload
#: to a few hundred reads.
UPLOAD_CHUNK_BYTES = 64 * 1024

#: Ceiling on the *entire* request body, counted as it arrives and enforced by
#: :class:`_BodyLimit` before any handler or parser sees it.
#:
#: :data:`MAX_UPLOAD_BYTES` bounds one field of one route. Every other body was
#: unbounded, and the schema ceilings that look like the bound are not one:
#: ``user_id`` is capped at 64 characters and ``prompt`` at 8 000, but pydantic
#: only rejects a value it has already been handed, and FastAPI only hands it one
#: after ``await request.body()`` has materialised the whole payload. Measured on
#: this build: one anonymous ``POST /sessions`` streaming a 256 MB body answered
#: the correct ``422 VALIDATION_ERROR`` after the process had grown by 768 MB.
#: A cap that allocates first is not a cap; it is an out-of-memory primitive with
#: a polite error, available with no session and no credential.
#:
#: The slack over :data:`MAX_UPLOAD_BYTES` is multipart framing -- boundaries,
#: per-part headers, and the ``user_id``/``doc_category`` fields -- so a 16 MB
#: file still reaches :func:`_read_capped` and still gets ``UPLOAD_TOO_LARGE``.
MAX_BODY_BYTES = MAX_UPLOAD_BYTES + (1024 * 1024)

#: ``GET /audit`` page size. The log is append-only and grows without bound; a
#: compliance reader pages through it, and the route is anonymous, so an
#: unbounded ``limit`` lets one request choose how many rows the process
#: materialises and serialises. Both halves of the enforcement were once free:
#: deleting ``le=MAX_AUDIT_PAGE`` from the ``limit`` parameter and raising this
#: constant to a billion each left the whole API test file green
#: (``limit=1000000000`` went from 422 to 200). The refusal is now asserted at
#: absolute row counts, not relative to this name.
MAX_AUDIT_PAGE = 1_000
DEFAULT_AUDIT_PAGE = 100

#: Sent as a *header* on every response. ``ui/index.html`` already carries the
#: same policy in a ``<meta http-equiv>``, and that is the control for script
#: injection inside the page -- but a meta policy covers only the document that
#: carries it (never ``app.js``, never a JSON body), and ``frame-ancestors`` is
#: ignored in meta by specification. Framing matters here specifically: the demo
#: UI's "Destroy session" button is one click away from an irreversible
#: cryptographic erasure, so an unframable page is a control, not a nicety.
#:
#: Every directive is pinned by
#: ``test_the_content_security_policy_is_restrictive_in_every_directive``, and by
#: value rather than by presence: no source here may name a host, a scheme or a
#: wildcard, and the ``<meta>`` copy in ``ui/index.html`` must declare the same
#: policy minus ``frame-ancestors``. Before that, nothing in the suite referred
#: to this constant at all -- ``script-src https:`` (any host on the internet, on
#: a page whose premise is that nothing reaches a third party), ``img-src *``,
#: ``base-uri 'self'`` and ``form-action 'self'`` were all green.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

#: ``nosniff`` keeps a browser from re-typing a response body it was told is
#: JSON; ``no-referrer`` keeps a ``doc_id`` or ``run_id`` in a URL out of an
#: outbound ``Referer``, which on a page whose premise is "nothing reaches a
#: third party" would be the one header that did.
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
)

#: Starlette renamed ``HTTP_413_REQUEST_ENTITY_TOO_LARGE`` and
#: ``HTTP_422_UNPROCESSABLE_ENTITY`` part-way through the version range this
#: project supports, and reaching for either spelling therefore either emits a
#: ``DeprecationWarning`` or fails outright depending on which one is installed.
#: The literals are the portable spelling; every other code below uses the
#: ``fastapi.status`` constant.
HTTP_413_TOO_LARGE = 413
HTTP_422_UNPROCESSABLE = 422
HTTP_429_TOO_MANY_REQUESTS = 429

#: Written to the hash-chained log every time an audit-scope ownership proof
#: fails -- see :func:`_deny_audit_scope`.
#:
#: The proof at ``GET /audit`` compares a claimed ``user_id`` against the owner
#: recorded at ``SESSION_CREATE``. That check is correct and it is also, on its
#: own, a **silent** right/wrong oracle for a value that is not a secret:
#: measured on this build, 500 wrong guesses against one real ``run_id`` returned
#: an identical empty page each time, cost 0.86 ms each, and wrote **zero** rows
#: to the tamper-evident log they were attacking. The interim window before real
#: authentication lands was therefore not merely open, it was unobservable.
#:
#: A denied proof now leaves a record naming the claimed ``user_id`` and the
#: scope it was claimed against, filed -- when the scope resolves to a session at
#: all -- under *that session*, so the storm is visible to the victim through the
#: very endpoint it is aimed at (``GET /audit?session_id=...``) and to an
#: operator through the chain. Nothing in the record is content: a ``user_id`` is
#: an actor, which ``SESSION_CREATE`` already records, and both halves are clamped
#: by :func:`_clamp` (build doc section 16).
#:
#: **Not in** :data:`~secure_context_pipeline.audit.logger.EVENT_TYPES`, which is
#: the build doc's fixed twelve and is asserted by count in ``tests/test_audit.py``.
#: :meth:`AuditLogger.emit` does not restrict the column, so the row is written and
#: chained like any other; promoting the constant into that module is a one-line
#: change that belongs to whoever owns the audit package.
AUDIT_ACCESS_DENIED = "AUDIT_ACCESS_DENIED"

#: Recorded as the ``session_id`` of a deny row whose scope named only a
#: ``run_id`` that resolved to nothing -- there is no session to file it under.
#: Cannot collide with a real session: :meth:`SessionRegistry.create` mints
#: ``uuid.uuid4().hex``, 32 lowercase hex characters.
UNRESOLVED_SCOPE = "<unresolved-audit-scope>"

#: Per-caller budget for **failed** audit-scope ownership proofs: a burst of
#: :data:`AUDIT_PROOF_BURST`, refilled at :data:`AUDIT_PROOF_REFILL_PER_SECOND`.
#:
#: Deliberately metering *failures only*. A caller that proves its scope is never
#: throttled, so no legitimate traffic is affected, while a username-guessing
#: storm is throttled from the first request -- it fails by construction until it
#: hits. At these numbers a 10 000-name dictionary against one held ``run_id``
#: goes from ~9 s of silence to ~5.5 h that writes ~10 000 rows into the log.
#:
#: The throttle answers ``429 RATE_LIMITED`` rather than the empty page. That is
#: not a new oracle: a caller only reaches the metered path by having *already*
#: been told, by the empty page, that its guess was wrong -- 429 and the empty
#: page carry the same one bit, and the correct owner never sees either.
#:
#: Order matters, and it is tested: the meter is charged **before** the deny row
#: is written, so a throttled request writes nothing. Recording the failure is
#: itself a durable anonymous write, and a monitoring control that an attacker
#: can turn into unbounded disk growth is a trade, not a fix.
AUDIT_PROOF_BURST = 20
AUDIT_PROOF_REFILL_PER_SECOND = 0.5

#: Per-caller budget for every state-changing request, enforced by
#: :class:`_RateLimit` before the body is read.
#:
#: ``POST /sessions`` and ``DELETE /sessions/{id}`` need no session and no
#: credential, and both append to a hash-chained log that is append-only and
#: unprunable *by construction* -- pruning is what tamper-evidence forbids.
#: Measured on this build: 3 000 anonymous ``POST /sessions`` grew ``audit.db`` by
#: 1 716 bytes per request and the in-memory registry by one live session per
#: request (held for ``session_ttl_seconds``, 3 600 by default); 1 000 anonymous
#: ``DELETE`` calls with a bogus id grew it by 356 bytes each. Unmetered, that is
#: ~583 k requests to a gigabyte of unprunable rows, and a full disk fails every
#: later write for every user.
#:
#: The predicate is the HTTP **method**, not a list of paths, and that is the
#: point rather than laziness: a path allow-list is a checker that shares a blind
#: spot with the thing it checks, and it goes stale the moment a route is added.
#: ``tests/test_api.py`` enumerates ``app.routes`` and asserts every mutating
#: method on every registered route is metered, so a narrowing of this rule is
#: caught by the app's own route table.
#:
#: This bounds one caller. It does not bound the *log*: rotation with each
#: segment's head hash anchored off-box is the other half, and it lives in the
#: audit package. Nor does it replace a reverse proxy -- concurrency is a limit
#: this process cannot impose on itself.
WRITE_BURST = 256
WRITE_REFILL_PER_SECOND = 8.0

#: Distinct callers a :class:`_RateLimiter` will track. The limiter must not
#: become the exhaustion primitive it exists to remove, so the map is bounded and
#: evicts least-recently-seen. Eviction is safe in the direction that matters: a
#: forgotten key returns as a full bucket, which is exactly how an unseen caller
#: starts, and reaching the ceiling at all takes 4 096 distinct source addresses.
RATE_LIMIT_MAX_KEYS = 4_096

#: The methods :class:`_RateLimit` meters. ``GET``/``HEAD``/``OPTIONS`` are left
#: alone: they write nothing durable, and ``GET /audit`` has its own, tighter
#: failure meter above.
METERED_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


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
# Application-scoped services
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Services:
    """Everything built once at startup and shared by every request.

    Held on ``app.state.services``. Tests reach in here deliberately -- to mint a
    zero-TTL session, or to plant a value in the vault's originals set -- which
    is the seam that lets the API be tested against the real pipeline rather
    than against mocks of it.
    """

    settings: Settings
    registry: EntityRegistry
    audit: AuditLogger
    store: EncryptedDocumentStore
    sessions: SessionRegistry
    vault: SessionVault
    detector: Detector
    engine: ObfuscationEngine
    gate: EgressGate
    orchestrator: PipelineOrchestrator
    model_loaded: bool
    ui_mounted: bool


class ApiError(Exception):
    """A transport-level failure with no domain exception of its own.

    Domain failures travel as :class:`~secure_context_pipeline.errors.PipelineError`
    subclasses and are mapped by the handlers below; this covers the few cases
    that are purely about HTTP -- an oversized upload, an empty one, a request
    that arrives before the lifespan finished.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        detail: dict[str, int | float | str | None] | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.detail: dict[str, int | float | str | None] = detail or {}
        super().__init__(f"{code}(status={status_code})")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
async def _close_quietly(closers: Iterable[Callable[[], Awaitable[None]]]) -> None:
    """Await every closer, letting none of them stop the others.

    Shutdown is best-effort by nature: a connection that is already gone must not
    prevent the next one from being released.
    """
    for closer in closers:
        try:
            await closer()
        except Exception:
            logger.exception("error closing a resource")


async def _build_services(settings: Settings) -> Services:
    """Construct the whole pipeline. Called once per process, from the lifespan.

    Startup is **transactional**: three aiosqlite connections are opened in
    sequence, and if a later step raises, every earlier one is closed before the
    error propagates. Without that, a half-built startup leaks a connection --
    and, because aiosqlite's worker threads are not daemons, the interpreter can
    no longer exit at all, so the process hangs instead of reporting the failure.
    The realistic trigger is not exotic: ``docker-compose`` bind-mounts ``./data``
    from the host, the container runs as uid 10001, and a root-owned host
    directory makes the *second* open fail while the first has already succeeded.
    """
    started = time.perf_counter()
    data_dir = Path(settings.data_dir)
    await asyncio.to_thread(data_dir.mkdir, parents=True, exist_ok=True)

    registry = load_registry(settings.registry_path)

    # spaCy + Presidio: seconds of CPU, and blocking. Never on the event loop,
    # and never per request (build doc section 12). A failure here is reported
    # through /health rather than refusing to boot -- a container that will not
    # start tells an operator nothing about why.
    model_loaded = True
    try:
        await asyncio.to_thread(warm_up, settings)
    except Exception:
        model_loaded = False
        logger.exception(
            "spacy model failed to load; /health will report degraded",
            extra={"spacy_model": settings.spacy_model},
        )

    # Unwound in reverse on any failure below, including cancellation.
    opened: list[Callable[[], Awaitable[None]]] = []
    try:
        audit = await AuditLogger.open(data_dir / AUDIT_DB_FILENAME)
        opened.append(audit.close)
        store = await EncryptedDocumentStore.open(settings)
        opened.append(store.close)
        sessions = SessionRegistry(settings)
        vault = await SessionVault.open(data_dir / VAULT_DB_FILENAME, sessions)
        opened.append(vault.close)

        # Session keys never survive a restart, so every row left by the previous
        # process is undecryptable garbage. Drop it rather than let a stale
        # session_id look live.
        orphans = await vault.sweep_orphans(await sessions.active_ids())
        # The store's counterpart. `put` writes both blobs and then commits the
        # metadata row, unwinding itself on any exception -- but not on SIGKILL,
        # OOM or power loss, which strand blobs with no row pointing at them.
        # Since `doc_id` only ever comes from a row, those files are unreachable
        # AND uncollectable: permanent disk, bounded only by replacing the volume.
        stranded_blobs = await store.sweep_orphans()

        detector = Detector(registry, settings)
        engine = ObfuscationEngine(
            registry=registry,
            vault=vault,
            session_registry=sessions,
            settings=settings,
            audit=audit,
        )
        gate = EgressGate(vault=vault, detector=detector, settings=settings, audit=audit)
        orchestrator = PipelineOrchestrator(
            store=store,
            detector=detector,
            engine=engine,
            injector=ContextInjector(),
            gate=gate,
            provider=build_provider(settings),
            restorer=Restorer(vault=vault, settings=settings, audit=audit),
            vault=vault,
            settings=settings,
            audit=audit,
        )
    except BaseException:
        # Reverse order, and BaseException rather than Exception: a cancelled
        # startup must unwind too, or the aiosqlite worker threads it already
        # started keep the interpreter alive and the process hangs instead of
        # reporting why it failed.
        await _close_quietly(reversed(opened))
        raise

    logger.info(
        "pipeline ready",
        extra={
            "model_loaded": model_loaded,
            "llm_provider": settings.llm_provider,
            "strategy": settings.strategy,
            "orphan_rows_swept": orphans,
            "orphan_blobs_swept": stranded_blobs,
            "startup_ms": round((time.perf_counter() - started) * 1000.0, 1),
        },
    )
    return Services(
        settings=settings,
        registry=registry,
        audit=audit,
        store=store,
        sessions=sessions,
        vault=vault,
        detector=detector,
        engine=engine,
        gate=gate,
        orchestrator=orchestrator,
        model_loaded=model_loaded,
        ui_mounted=False,
    )


async def _shutdown(services: Services) -> None:
    """Close every connection. Session keys die with the process, by design."""
    await _close_quietly((services.store.close, services.vault.close, services.audit.close))


# ---------------------------------------------------------------------------
# Request-scoped helpers
# ---------------------------------------------------------------------------
def get_services(request: Request) -> Services:
    """The application's :class:`Services`, or 503 if the lifespan has not run."""
    services = cast("Services | None", getattr(request.app.state, "services", None))
    if services is None:
        raise ApiError(http_status.HTTP_503_SERVICE_UNAVAILABLE, "NOT_READY")
    return services


ServicesDep = Annotated[Services, Depends(get_services)]

SessionHeader = Annotated[
    str | None,
    Header(
        alias="X-Session-Id",
        max_length=MAX_ID_LEN,
        description="Live session ID. The body field `session_id` is accepted instead.",
    ),
]


def _same_id(claimed: str, actual: str) -> bool:
    """Constant-time equality for two caller-facing identifiers.

    ``secrets.compare_digest`` accepts ``str`` **only when both sides are pure
    ASCII** and raises ``TypeError`` otherwise. Comparing a recorded owner
    against an attacker-chosen ``user_id`` therefore crashed the request the
    moment the claim carried one non-ASCII character, and nothing rejects such a
    claim earlier: ``POST /sessions`` accepts any 1-64 character string. Two
    consequences, both live before this helper existed. A legitimate
    ``user_id="josé"`` could create a session and then never spend it -- every
    ``POST /pipeline/run`` answered a bare ``500 Internal Server Error``, outside
    the structured-error contract entirely. And an *anonymous* caller could raise
    that 500, with a full traceback logged, against any live session by sending a
    single accented character -- the same free log-flooding primitive that ``%00``
    in a static path used to give (see :class:`_NullSafeStaticFiles`), except on
    the authenticated core route.

    Comparing the UTF-8 encodings is total over every ``str`` and keeps the
    constant-time property the ownership check exists for: ``user_id`` is
    attacker-supplied, and a byte-by-byte early exit leaks the owner's identity
    one character at a time. Length is still observable, as it is for the ``str``
    form, and is bounded to 1..64 by :data:`MAX_ID_LEN`.
    """
    return secrets.compare_digest(claimed.encode("utf-8"), actual.encode("utf-8"))


async def _require_session(services: Services, session_id: str | None, user_id: str) -> str:
    """Resolve a session ID to a *live* session **owned by** ``user_id``, or raise 401.

    Missing, unknown, expired, destroyed **and belonging to someone else** all
    produce one response. The last of those is the point: a session ID used to be
    a credential for any user's documents, so presenting one alongside a
    different ``user_id`` reached that user's data and the only thing preventing
    it was the ``doc_id`` being unguessable -- obscurity, not authorization.

    The mismatch deliberately reuses ``SessionExpiredError`` rather than getting a
    code of its own. A distinct "wrong user" reply would confirm that the session
    ID is real and merely belongs to somebody else, which hands back exactly the
    enumeration oracle the uniform 401 exists to deny. The key itself never leaves
    :class:`SessionRegistry`.
    """
    if not session_id:
        raise SessionExpiredError(session_id="")
    owner = await services.sessions.owner(session_id)
    if not _same_id(user_id, owner):
        raise SessionExpiredError(session_id=_clamp(session_id))
    return session_id


async def _owns_session(services: Services, session_id: str, user_id: str) -> bool:
    """Whether ``session_id`` is live *and* owned by ``user_id``. Never raises.

    Deliberately **not** :meth:`SessionRegistry.belongs_to`, which is otherwise
    exactly this. The original reason was a defect: that helper compared the two
    IDs as ``str`` and so inherited the ``TypeError`` described in
    :func:`_same_id`, which turned ``DELETE /sessions/{id}?user_id=<non-ASCII>``
    into an unauthenticated 500. **That copy has since been fixed** -- verified,
    not assumed: ``belongs_to`` now answers ``True`` for a non-ASCII owner instead
    of raising -- so the two are equivalent again and this is no longer a
    workaround.

    It stays inline anyway, for the reason the workaround exposed rather than the
    workaround itself. The route's promise is that logout is oracle-free, and a
    promise discharged by calling into another component is only as good as that
    component's current implementation; when the two shared a bug, the shared bug
    is precisely what nothing could see. One comparison, in the frame that makes
    the guarantee, using the helper this module can reason about.
    """
    try:
        owner = await services.sessions.owner(session_id)
    except SessionExpiredError:
        return False
    return _same_id(user_id, owner)


def _clamp(value: str) -> str:
    """Clamp a caller-supplied identifier to the structured-detail ceiling."""
    return value[:MAX_DETAIL_VALUE_LEN]


@dataclass(frozen=True, slots=True)
class _AuditScope:
    """What a ``session_id``/``run_id`` pair resolved to.

    ``session_id`` is the session the scope names (directly, or the one the run
    belongs to) or ``None`` if it named nothing. ``owner`` is the ``user_id``
    recorded at that session's ``SESSION_CREATE``, or ``None`` when the scope is
    unreadable -- which callers must treat exactly like a wrong owner.

    Both halves are needed, not just the owner: the owner decides the answer, and
    the session decides where a *denied* attempt gets filed, so that the victim
    can see it in their own scope.
    """

    session_id: str | None
    owner: str | None


async def _resolve_audit_scope(
    services: Services, *, session_id: str | None, run_id: str | None
) -> _AuditScope:
    """The ``user_id`` that owns an audit scope, read out of the log itself.

    The log is the authority here, not :class:`SessionRegistry`, and that is
    required rather than convenient: the audit trail must stay readable *after*
    the session is destroyed (the vault-miss demo and ``demo.py``'s closing tail
    both depend on it), and by then the registry has forgotten the session
    entirely. ``SESSION_CREATE`` records the owning ``user_id`` and the log is
    append-only, so the binding survives exactly as long as the rows it governs.

    A ``run_id`` is resolved one hop further: any event the run emitted names the
    session it belongs to, and that session's ``SESSION_CREATE`` names the owner.

    Returns ``None`` when the scope resolves to nothing, or to a session with no
    recorded owner -- events written by machinery that never went through
    ``POST /sessions``. Callers must treat that identically to a wrong owner:
    fail closed, and give an unreadable scope the same answer as an empty one.

    That ``None`` branch had no test of its own for a while, and every existing
    ownership test exercises only the *wrong-owner* one: they all use a session
    created through ``POST /sessions``, for which this never returns ``None``.
    Inverting the callers' guard to ``owner is not None and not _same_id(...)``
    therefore stayed green while making every ownerless scope world-readable --
    a ``DETECT`` row and its ``doc_id`` came back to an arbitrary ``user_id``,
    and ``/audit/verify`` went from ``length: 0`` to ``length: 1``, restoring the
    existence oracle. ``test_an_audit_scope_with_no_recorded_owner_reads_as_empty``
    covers it, and proves the row is really in the log first, so an empty page
    cannot pass for the wrong reason.

    **The two steps are always both taken.** Short-circuiting the second query
    when the run resolved to nothing made a *real* ``run_id`` measurably slower
    than an absent one on the wrong-owner path -- one audit query against two,
    each a round trip through aiosqlite's worker thread. Measured before the fix,
    300 warmed pairs: median 736 us for a real run against 528 us for a random
    ``uuid4`` hex, +208 us, consistently. The responses are byte-identical by
    design; the clock was not, so a caller holding a ``run_id`` it did not own
    could still confirm the run existed. An unresolved scope now runs the same
    second query against :data:`UNRESOLVED_SCOPE`, which no session can equal --
    ``SessionRegistry.create`` mints 32 hex characters -- so it returns nothing
    and the shape of the work is the same either way.
    """
    target = session_id
    if not target:
        seen = await services.audit.query(run_id=run_id, limit=1)
        target = seen[0].session_id if seen else None
    created = await services.audit.query(
        session_id=UNRESOLVED_SCOPE if target is None else target,
        event_type=SESSION_CREATE,
        limit=1,
    )
    if target is None or not created:
        return _AuditScope(session_id=target, owner=None)
    owner = created[0].detail.get("user_id")
    return _AuditScope(session_id=target, owner=owner if isinstance(owner, str) else None)


async def _deny_audit_scope(
    request: Request,
    services: Services,
    scope: _AuditScope,
    *,
    user_id: str,
    run_id: str | None,
) -> None:
    """Meter a failed audit-scope proof and record it. Raises 429 when metered out.

    Two controls, in this order and only in this order.

    **The meter first.** Recording the failure is a durable, anonymous write, so
    doing it unconditionally would trade a silent oracle for the unbounded
    ``audit.db`` growth described at :data:`WRITE_BURST`. A throttled request is
    refused here and leaves nothing behind, which bounds the rows a guessing
    storm can add to :data:`AUDIT_PROOF_REFILL_PER_SECOND` per caller per second.
    ``test_a_throttled_audit_probe_writes_no_row`` pins the ordering.

    **Then the record.** Every guess that gets an *answer* costs a row, and the
    row names the claimed ``user_id`` and the scope it was claimed against. Filed
    under the session the scope resolved to whenever there is one, so the owner
    reads their own intruders out of ``GET /audit?session_id=...``; under
    :data:`UNRESOLVED_SCOPE` when the scope named nothing, where only an operator
    with the database (or ``/audit/verify``'s total length) sees it.

    An attacker can therefore write rows into a victim's scope, bounded by the
    meter. That is the intended direction: the rows *are* the intrusion record,
    and the alternative -- filing them nowhere the victim can look -- is the
    silence this exists to end.

    Nothing here can carry content. ``user_id`` is an actor, which
    ``SESSION_CREATE`` already records, and the scope identifiers are values the
    caller supplied; both are clamped to :data:`MAX_DETAIL_VALUE_LEN`.
    """
    limits = _limits(request.app.state)
    if limits is not None:
        wait = limits.audit_proofs.take(_caller_key(request.scope))
        if wait > 0.0:
            raise ApiError(
                HTTP_429_TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                {"retry_after_seconds": round(wait, 1)},
            )
    await services.audit.emit(
        AuditEvent(
            ts=time.time(),
            session_id=_clamp(scope.session_id or UNRESOLVED_SCOPE),
            run_id=_clamp(run_id) if run_id else None,
            event_type=AUDIT_ACCESS_DENIED,
            detail={
                "route": request.url.path[:MAX_DETAIL_VALUE_LEN],
                "claimed_user_id": _clamp(user_id),
                "scope_resolved": int(scope.session_id is not None),
            },
        )
    )


async def _read_capped(file: UploadFile) -> bytes:
    """Read an upload, refusing past :data:`MAX_UPLOAD_BYTES`.

    Reading in bounded chunks and stopping one chunk past the ceiling caps this
    frame's allocation at the ceiling rather than at whatever was sent. The
    fallback it replaced -- ``await file.read()`` and then measure -- answered
    413 correctly but only after materialising all of it, so the caller picked
    the allocation.

    Stopping one chunk past the ceiling also means the ``bytes`` this reports is
    a *read total*, not the upload's size: always ``MAX_UPLOAD_BYTES`` rounded up
    to a whole :data:`UPLOAD_CHUNK_BYTES`, i.e. 16 842 752 for every oversize
    body. That is the observable difference between this control and the
    pre-check, and it is what
    ``test_an_oversize_upload_is_refused_before_a_byte_of_it_is_read`` asserts --
    removing the pre-check was once reported as having no testable effect.

    **This is a backstop, not the live enforcement point, and the difference is
    worth stating because it was once documented the other way round.** The claim
    was that ``file.size`` is populated only when the client declares a length,
    which would make the pre-check in :func:`upload_document` advisory and this
    the control that actually holds. It is the reverse: Starlette's multipart
    parser increments ``UploadFile.size`` on every write, so by the time the
    handler runs the size is known exactly -- measured, for a chunked upload sent
    with no ``Content-Length`` at all. The pre-check therefore fires first for
    every real multipart request and this loop never sees an oversize body. What
    is left to it is the case its own test constructs: an ``UploadFile`` whose
    ``size`` is ``None``, which is what a non-multipart caller of this helper
    would hand it.

    **Scope.** Both of those bound what the *handler* buffers, and neither is the
    request-body limit: :class:`_BodyLimit` is, and it runs before the multipart
    parser has spooled anything. Past that, a production deployment still wants a
    reverse proxy's ``client_max_body_size`` in front, because concurrency is a
    limit this process cannot impose on itself.
    """
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(UPLOAD_CHUNK_BYTES):
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            # The count is the caller's own byte total, never a byte of content.
            raise ApiError(
                HTTP_413_TOO_LARGE,
                "UPLOAD_TOO_LARGE",
                {"max_bytes": MAX_UPLOAD_BYTES, "bytes": total},
            )
        chunks.append(chunk)
    return b"".join(chunks)


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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
_ERRORS: dict[int | str, dict[str, object]] = {
    400: {"model": ErrorResponse},
    401: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
    500: {"model": ErrorResponse},
    502: {"model": ErrorResponse},
    503: {"model": ErrorResponse},
}

DocIdPath = Annotated[str, PathParam(min_length=1, max_length=MAX_ID_LEN)]
UserIdQuery = Annotated[str, Query(min_length=1, max_length=MAX_ID_LEN)]
OptionalIdQuery = Annotated[str | None, Query(max_length=MAX_ID_LEN)]


def _register_routes(app: FastAPI) -> None:
    @app.post(
        "/sessions",
        response_model=SessionCreateResponse,
        responses=_ERRORS,
        tags=["sessions"],
        summary="Create a session",
    )
    async def create_session(
        body: SessionCreateRequest, services: ServicesDep
    ) -> SessionCreateResponse:
        """Mint a session ID and a fresh 32-byte session key, bound to ``user_id``.

        The key stays inside :class:`SessionRegistry` and is never returned,
        logged, or persisted -- destroying it is what makes the vault
        irrecoverable. The ``user_id`` is recorded with it, and every later
        request presenting this session must claim the same one.
        """
        session_id, expires_at = await services.sessions.create(body.user_id)
        await services.audit.emit(
            AuditEvent(
                ts=time.time(),
                session_id=session_id,
                event_type=SESSION_CREATE,
                detail={
                    "ttl_seconds": services.settings.session_ttl_seconds,
                    # The actor, not a document value. "No originals in logs"
                    # (build doc section 16) is about detected entity values;
                    # a compliance log that cannot say *who* acted is not one.
                    "user_id": _clamp(body.user_id),
                },
            )
        )
        return SessionCreateResponse(session_id=session_id, expires_at=expires_at)

    @app.delete(
        "/sessions/{session_id}",
        status_code=http_status.HTTP_204_NO_CONTENT,
        responses=_ERRORS,
        tags=["sessions"],
        summary="Log out: destroy the vault and the session key",
    )
    async def delete_session(
        session_id: DocIdPath, services: ServicesDep, user_id: UserIdQuery
    ) -> Response:
        """Irreversible. Returns 204 whether or not anything was destroyed.

        **Owner-scoped, and silent about it.** Destruction is cryptographic
        erasure, so letting one user log another one out was an unauthenticated
        way to destroy a stranger's vault permanently. Only a session that is live
        *and* owned by ``user_id`` is touched.

        Deliberately idempotent and oracle-free: unknown, expired, already
        destroyed and *someone else's* all return the same empty 204. Answering
        404 -- or 403 for the last case -- would let a caller probe which session
        IDs are real, which is why the outcome is recorded in the audit log
        instead of in the status code.

        **The key goes first.** Logout is two awaits, so a pipeline run that is
        already in flight -- and already holding the session key -- can be
        scheduled between them. With the rows dropped first, that run's next
        ``put()`` landed *after* the erasure and rebuilt the plaintext cache and a
        durable row for a session that was supposed to be gone. Popping the key
        first makes the window harmless instead of merely narrow: every vault
        ciphertext is AES-GCM under a key derived from the session key, so once
        it is gone no later write can derive one. The vault's tombstone defends
        the same race one layer down; this closes it at the source.
        """
        existed = False
        if await _owns_session(services, session_id, user_id):
            existed = await services.sessions.destroy(session_id)
            await services.vault.destroy(session_id)
        await services.audit.emit(
            AuditEvent(
                ts=time.time(),
                session_id=_clamp(session_id),
                event_type=VAULT_DESTROY,
                detail={"existed": int(existed), "source": "api_logout"},
            )
        )
        return Response(status_code=http_status.HTTP_204_NO_CONTENT)

    @app.post(
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
        content = await _read_capped(file)
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

    @app.get(
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

    @app.post(
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
        """
        session_id = await _require_session(
            services, body.session_id or x_session_id, body.user_id
        )
        return await services.orchestrator.run(
            session_id, body.user_id, body.doc_id, body.prompt, body.strategy
        )

    @app.get(
        "/audit",
        response_model=AuditQueryResponse,
        responses=_ERRORS,
        tags=["audit"],
        summary="Query the hash-chained audit log",
    )
    async def query_audit(
        request: Request,
        services: ServicesDep,
        user_id: UserIdQuery,
        session_id: OptionalIdQuery = None,
        run_id: OptionalIdQuery = None,
        event_type: OptionalIdQuery = None,
        since: Annotated[float | None, Query(description="Inclusive epoch-seconds lower bound.")] = None,
        until: Annotated[float | None, Query(description="Inclusive epoch-seconds upper bound.")] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_AUDIT_PAGE)] = DEFAULT_AUDIT_PAGE,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> AuditQueryResponse:
        """Compliance reporting. Ordered by ``seq``, i.e. chain order.

        **A scope is mandatory, and the caller must own it.** ``AuditEvent``
        cannot hold an original value (build doc sections 7 and 9.8), which is why
        the *content* of the log is safe to return. What is not safe is the
        *correlation*: a row names the ``session_id`` it belongs to, a
        ``SESSION_CREATE`` row names the owning ``user_id``, and a ``DETECT`` row
        names the ``doc_id`` that was read. Those three identifiers are precisely
        the credentials for the two endpoints that matter --
        ``DELETE /sessions/{session_id}?user_id=...`` (irreversible cryptographic
        erasure) and ``GET /documents/{doc_id}/text?user_id=...`` (original
        plaintext).

        Requiring a scope alone stopped *enumeration* but left the log an
        **assembly oracle**, and that was a live, complete break rather than a
        theoretical one: an anonymous caller holding a single ``run_id`` read the
        session ID and ``doc_id`` out of that run's events, read the owning
        ``user_id`` out of that session's ``SESSION_CREATE``, and then fetched the
        victim's original document text and destroyed their vault -- with no
        session and no credential of its own. The ``user_id`` second factor that
        guards both of those endpoints was being handed out by this one.

        So the scope must be *proved*, not merely quoted: the claimed ``user_id``
        is checked, in constant time, against the owner recorded in the log at
        ``SESSION_CREATE`` (see :func:`_resolve_audit_scope`). An unproved scope
        returns an **empty page**, byte-identical to a scope that does not exist
        or a window that matched nothing -- answering 403 would restore the
        existence oracle the uniform reply exists to deny.

        **And a failed proof is metered and recorded** (:func:`_deny_audit_scope`).
        The proof has no secret to verify -- ``POST /sessions`` mints a session
        for any ``user_id`` asked for -- so it is a right/wrong oracle on a
        human-readable name, and until now a free and invisible one: 500 wrong
        guesses against a real ``run_id`` cost 0.86 ms each, triggered no lockout
        and wrote nothing. Guessing is now throttled per caller and every answered
        guess leaves a row in the chain it is attacking. Neither replaces
        authentication; both close the interim window's *silence*, which is the
        part that made the gap unmonitorable rather than merely open.

        Liveness is deliberately *not* checked, and the ownership proof reads the
        log rather than the registry for exactly that reason: the trail must stay
        readable after the session is destroyed, which is what the vault-miss demo
        and ``demo.py``'s closing audit tail do (build doc section 9.11).
        """
        if not session_id and not run_id:
            raise ApiError(
                http_status.HTTP_400_BAD_REQUEST,
                "AUDIT_SCOPE_REQUIRED",
                {"reason": "session_id_or_run_id_required"},
            )
        scope = await _resolve_audit_scope(services, session_id=session_id, run_id=run_id)
        if scope.owner is None or not _same_id(user_id, scope.owner):
            await _deny_audit_scope(request, services, scope, user_id=user_id, run_id=run_id)
            return AuditQueryResponse(events=[], returned=0, limit=limit, offset=offset)
        events = await services.audit.query(
            session_id=session_id,
            run_id=run_id,
            event_type=event_type,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )
        return AuditQueryResponse(events=events, returned=len(events), limit=limit, offset=offset)

    @app.get(
        "/audit/verify",
        response_model=AuditVerifyResponse,
        responses=_ERRORS,
        tags=["audit"],
        summary="Verify the audit hash chain",
    )
    async def verify_audit(
        request: Request,
        services: ServicesDep,
        session_id: OptionalIdQuery = None,
        user_id: OptionalIdQuery = None,
    ) -> AuditVerifyResponse:
        """Recompute every ``entry_hash`` and re-check every link.

        Reported as data, never as an error: a broken chain is a finding for the
        reader, and a 500 here would hide which answer the checker gave.

        **Unscoped is anonymous by design.** The whole-log form returns a boolean
        and a total count and names nothing -- no session, no run, no user, no
        document. That is the tamper-evidence claim the design wants publicly
        checkable, and it is what the demo UI's "Verify chain" button and
        ``demo.py`` both call.

        **Scoped requires the same ownership proof as ``GET /audit``.** Per
        session, ``length`` is an existence oracle -- zero versus non-zero says
        whether that session ID was ever real -- so it is gated exactly like the
        query it mirrors, and an unproved scope gets ``valid=True, length=0``,
        indistinguishable from a session that never existed. Metered and recorded
        exactly like the query it mirrors, too: this route answers the same
        right/wrong question about ``user_id``, so leaving it unmetered would
        just move the oracle one URL over.
        """
        if session_id:
            if not user_id:
                raise ApiError(
                    http_status.HTTP_400_BAD_REQUEST,
                    "AUDIT_SCOPE_REQUIRED",
                    {"reason": "user_id_required_with_session_id"},
                )
            scope = await _resolve_audit_scope(services, session_id=session_id, run_id=None)
            if scope.owner is None or not _same_id(user_id, scope.owner):
                await _deny_audit_scope(request, services, scope, user_id=user_id, run_id=None)
                return AuditVerifyResponse(valid=True, length=0, session_id=session_id)
        valid = await services.audit.verify_chain(session_id)
        length = await services.audit.length(session_id)
        return AuditVerifyResponse(valid=valid, length=length, session_id=session_id)

    @app.get(
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


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application.

    The uvicorn entrypoint is ``secure_context_pipeline.api.app:create_app
    --factory`` (see the Dockerfile). ``settings`` is injected by tests to point
    the whole pipeline at a temporary data directory; production passes nothing
    and :func:`~secure_context_pipeline.config.get_settings` reads the
    environment.

    Nothing expensive happens here. The model, the stores, and the orchestrator
    are built in the lifespan -- once, when the server starts.
    """
    # A one-slot box rather than a closure variable: the mount happens after the
    # app (and therefore the lifespan) is constructed, and the lifespan needs to
    # report the outcome through /health.
    mounted = [False]

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        resolved = settings if settings is not None else get_settings()
        services = await _build_services(resolved)
        services.ui_mounted = mounted[0]
        app.state.services = services
        try:
            yield
        finally:
            app.state.services = None
            await _shutdown(services)

    app = FastAPI(
        title="Secure Context Pipeline",
        version="1.0.0",
        summary=(
            "Detect, obfuscate and restore sensitive entities around an LLM call, "
            "behind a fail-closed egress gate."
        ),
        lifespan=lifespan,
        # FastAPI's Swagger and ReDoc pages load their JS, CSS and favicon from
        # cdn.jsdelivr.net and fastapi.tiangolo.com. The premise of this system is
        # that a document's contents reach no third party and that the container
        # needs no network, so shipping a built-in page that phones out -- and
        # renders blank on an airgapped reviewer's machine -- argues against the
        # design. The schema itself is unaffected and still served locally at
        # /openapi.json, which any local viewer can render.
        docs_url=None,
        redoc_url=None,
    )
    # The meters, before the routes so ``scope["app"].state`` already has them on
    # the very first request. Two buckets rather than one because they answer
    # different questions: ``writes`` bounds durable growth from anonymous
    # mutations, ``audit_proofs`` bounds guessing at the audit-scope proof and is
    # charged only when a proof *fails*, so it never touches legitimate traffic.
    app.state.rate_limits = _RateLimits(
        writes=_RateLimiter(capacity=WRITE_BURST, refill_per_second=WRITE_REFILL_PER_SECOND),
        audit_proofs=_RateLimiter(
            capacity=AUDIT_PROOF_BURST, refill_per_second=AUDIT_PROOF_REFILL_PER_SECOND
        ),
    )
    # Order matters, and it is the reverse of the call order: the last
    # ``add_middleware`` wins the outermost position. ``_SecurityHeaders`` has to
    # be outside everything so the 413 and the 429 that never reach the
    # application are still stamped with the CSP and ``nosniff`` every other
    # response carries. Between the other two the order is a choice of *answer*,
    # not of protection -- measured, a throttled caller reads zero bytes either
    # way -- and 429 is the more actionable reply for a request that trips both.
    app.add_middleware(_BodyLimit)
    app.add_middleware(_RateLimit)
    app.add_middleware(_SecurityHeaders)
    _register_handlers(app)
    _register_routes(app)
    mounted[0] = _mount_ui(app)
    return app
