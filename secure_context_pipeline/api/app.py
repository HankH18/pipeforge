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

# `secrets` is unused here and imported anyway: `tests/test_api.py` proves that
# `_same_id` routes through `secrets.compare_digest` by patching it through this
# module, which has been the entry point to this layer since before it was split.
# The private names below are re-exported for the same reason -- they are the
# seams the API suite already reaches through, and renaming a seam is a test
# change wearing a refactor's clothes.
import secrets  # noqa: F401
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from secure_context_pipeline.api.constants import (
    AUDIT_ACCESS_DENIED,
    AUDIT_PROOF_BURST,
    AUDIT_PROOF_REFILL_PER_SECOND,
    CONTENT_SECURITY_POLICY,
    DEFAULT_AUDIT_PAGE,
    MAX_AUDIT_PAGE,
    MAX_BODY_BYTES,
    MAX_UPLOAD_BYTES,
    METERED_METHODS,
    SECURITY_HEADERS,
    UI_DIRNAME,
    UNRESOLVED_SCOPE,  # noqa: F401
    UPLOAD_CHUNK_BYTES,
    WRITE_BURST,
    WRITE_REFILL_PER_SECOND,
)
from secure_context_pipeline.api.deps import (  # noqa: F401
    ApiError,
    Services,
    _clamp,
    _resolve_audit_scope,
    _same_id,
    get_services,
)
from secure_context_pipeline.api.deps import (
    # `as` spelling, not decoration: `routes/documents.py` reads this one back
    # through this module (see the comment there), and `no_implicit_reexport`
    # will not let it unless the re-export is explicit.
    _read_capped as _read_capped,
)
from secure_context_pipeline.api.errors import _register_handlers
from secure_context_pipeline.api.lifespan import _build_services, _shutdown
from secure_context_pipeline.api.middleware import (
    _BodyLimit,
    _mount_ui,
    _RateLimit,
    _RateLimiter,
    _RateLimits,
    _SecurityHeaders,
)
from secure_context_pipeline.api.routes import audit, documents, health, pipeline, sessions
from secure_context_pipeline.audit.logger import AuditLogger  # noqa: F401
from secure_context_pipeline.config import Settings, get_settings
from secure_context_pipeline.store.document_store import EncryptedDocumentStore  # noqa: F401
from secure_context_pipeline.vault.session_vault import SessionVault  # noqa: F401

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
    app.include_router(sessions.router)
    app.include_router(documents.router)
    app.include_router(pipeline.router)
    app.include_router(audit.router)
    app.include_router(health.router)
    mounted[0] = _mount_ui(app)
    return app
