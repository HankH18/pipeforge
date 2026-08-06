"""Request-scoped dependencies, and the pieces every route declaration shares.

:class:`Services` is built once in the lifespan and reached through
:func:`get_services`; the helpers below are the ownership proofs, clamps and
caps the route modules call into. Nothing here imports a route module, so the
dependency runs one way and a handler can be imported -- and unit-tested --
without standing up the application.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, Header, Query, Request, UploadFile
from fastapi import Path as PathParam
from fastapi import status as http_status

from secure_context_pipeline.api.constants import (
    AUDIT_ACCESS_DENIED,
    HTTP_413_TOO_LARGE,
    HTTP_429_TOO_MANY_REQUESTS,
    MAX_UPLOAD_BYTES,
    UNRESOLVED_SCOPE,
    UPLOAD_CHUNK_BYTES,
)
from secure_context_pipeline.api.middleware import _caller_key, _limits
from secure_context_pipeline.api.schemas import MAX_ID_LEN, ErrorResponse
from secure_context_pipeline.audit.logger import SESSION_CREATE, VAULT_DESTROY, AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.detection.detector import Detector
from secure_context_pipeline.detection.registry import EntityRegistry
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN, SessionExpiredError
from secure_context_pipeline.models import AuditEvent
from secure_context_pipeline.obfuscation.engine import ObfuscationEngine
from secure_context_pipeline.pipeline.egress_gate import EgressGate
from secure_context_pipeline.pipeline.orchestrator import PipelineOrchestrator
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

logger = logging.getLogger(__name__)



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


async def reap_expired_sessions(services: Services) -> list[str]:
    """Finish the destruction path for sessions the TTL has expired.

    Build doc section 4 step 10 and section 9.4 both say TTL expiry runs the *same*
    destruction path as logout: key popped, vault rows deleted, ``VAULT_DESTROY``
    audited. Only the first of those happened. ``SessionRegistry._sweep_locked``
    drops the dict entry -- correctly, and lazily, on access -- and its own
    ``sweep()`` docstring says "the caller is responsible for the rest"; there was
    no caller. ``sweep()`` appeared exactly once in the tree, in a test.

    So an expired session left its AES-GCM rows in ``vault.db`` and its decrypted
    ``_SessionCache`` resident in RAM until process exit. Confidentiality held --
    the key is gone, so the rows are undecryptable and every cache accessor calls
    ``registry.key()`` first -- but "plaintext lives exactly as long as the process
    holds a live session" was false, and the rows were **unreclaimable**: the API's
    own ``DELETE /sessions`` gates on ``_owns_session``, which calls
    ``sessions.owner()``, which raises for an expired session and returns ``False``,
    so ``vault.destroy`` was skipped. Nothing short of a restart cleared them.

    Called from the request path rather than a timer: expiry is *discovered* on
    access, so the moment a request sweeps the registry is the moment there is
    something to reap. That keeps the process single-threaded in its own bookkeeping
    and adds no background task to reason about.

    Best-effort by construction -- it returns the IDs it reaped and raises nothing.
    A failure to tidy up must not fail the request that happened to notice.
    """
    expired = await services.sessions.sweep()
    for session_id in expired:
        try:
            await services.vault.destroy(session_id)
            await services.audit.emit(
                AuditEvent(
                    ts=time.time(),
                    session_id=_clamp(session_id),
                    event_type=VAULT_DESTROY,
                    detail={"existed": 1, "source": "ttl_expiry"},
                )
            )
        except Exception:
            logger.warning(
                "expired session could not be fully destroyed",
                extra={"session_id": _clamp(session_id)},
            )
    return expired


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
    # Finish the destruction path for anything the TTL has expired, BEFORE deciding
    # this request's fate. Two reasons for the ordering. Expiry is discovered on
    # access, so this is the moment there is something to reap; and the session most
    # likely to be expired is the one being presented right now -- which is exactly
    # the one `DELETE /sessions` cannot clean up, because its ownership check raises
    # for an expired session and skips `vault.destroy`. Reaping here is what makes
    # those rows reclaimable at all. The 401 below is unaffected either way.
    await reap_expired_sessions(services)
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
