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
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Annotated, cast

from fastapi import Depends, Header, Query, Request, UploadFile
from fastapi import Path as PathParam
from fastapi import status as http_status

from secure_context_pipeline.api.constants import (
    AUDIT_ACCESS_DENIED,
    HTTP_413_TOO_LARGE,
    HTTP_429_TOO_MANY_REQUESTS,
    MAX_REAP_PER_REQUEST,
    MAX_UPLOAD_BYTES,
    UNRESOLVED_SCOPE,
    UPLOAD_CHUNK_BYTES,
)
from secure_context_pipeline.api.middleware import _caller_key, _limits
from secure_context_pipeline.api.schemas import MAX_ID_LEN, ErrorResponse
from secure_context_pipeline.audit.logger import (
    SESSION_CREATE,
    SESSION_EXPIRE,
    VAULT_DESTROY,
    AuditLogger,
)
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

#: Destruction attempts one expired session gets before the reaper stops
#: retrying it. Read only by :func:`_requeue_unfinished`; it sits here rather
#: than beside :data:`MAX_REAP_PER_REQUEST` in ``api/constants.py`` because it is
#: a property of this module's retry loop and of nothing else.
#:
#: **What it bounds, precisely.** A failed ID goes back to the *tail* of
#: :attr:`Services.reap_backlog`, so it is never retried twice inside one call --
#: the slice this call is working on was popped before the first destroy ran.
#: Each attempt therefore costs one whole trip through the queue, and a
#: permanently-failing ID costs **8 destroy attempts for the life of the
#: process**, not 8 per request and not one per request for ever. After that it
#: moves to :attr:`Services.reap_failed`, where it stops competing for the
#: 16-per-request budget and stops being able to starve sessions that can still
#: be finished.
#:
#: 8 rather than 1 because every failure this can see is plausibly transient.
#: ``SessionVault.destroy`` swallows ``sqlite3.Error`` itself, so what reaches the
#: reaper is a locked database surfacing outside that class, a cancelled request
#: (which arrives as ``BaseException`` and is handled by the ``finally`` rather
#: than by the retry count), or an ``AuditLogger.emit`` that could not append --
#: none of which is a reason to give up on the first try. 8 rather than 100
#: because the retries are not free: each one is a SQLite DELETE plus two
#: hash-chained audit rows, and they are spent out of the same budget that
#: healthy expiries draw on.
#:
#: Retries are consumed by *failures*, not by time, so an ID that fails once and
#: then succeeds costs one attempt and is finished. The count is not reset by
#: anything the network can reach; only the ``first=`` hoist grants a fresh
#: budget, and that takes a named ``DELETE /sessions/{id}``.
MAX_REAP_ATTEMPTS = 8


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
    #: Session IDs whose key has already been dropped but whose vault rows and
    #: ``VAULT_DESTROY``/``SESSION_EXPIRE`` events are still outstanding, oldest
    #: first. Filled and drained a bounded slice at a time by
    #: :func:`reap_expired_sessions`; see :data:`MAX_REAP_PER_REQUEST`.
    #:
    #: An ordered mapping used as an ordered set, not a ``deque`` and not a
    #: ``set``. The order is load-bearing (FIFO, so nothing starves behind a newer
    #: arrival) and so is O(1) removal by ID, because the reaper is asked to finish
    #: one *named* session ahead of the queue -- ``DELETE /sessions/{id}`` on an
    #: already-expired session has no other way to reclaim its rows. A ``deque``
    #: gives the order and an O(n) ``remove``; a ``set`` gives the removal and no
    #: order.
    #:
    #: ``OrderedDict`` rather than a plain ``dict``, and that is a performance
    #: requirement rather than a preference now that the queue has no ceiling.
    #: A ``dict`` does not compact on delete: removing the oldest leaves a hole,
    #: and ``next(iter(...))`` restarts at slot 0 and walks every hole, so draining
    #: a long queue 16 at a time costs each successive request more than the last.
    #: Measured, filling and then draining with no further inserts -- plain
    #: ``dict``, 200 000 queued: 6 662 ms total and 1 307 us on the worst single
    #: request; ``OrderedDict``, identical loop: 22 ms total and 27 us worst.
    #: ``popitem(last=False)`` is a linked-list unlink, so per-request cost stops
    #: depending on the backlog's depth at all.
    #:
    #: The queue carries **no ceiling of its own**, on purpose and after a defect:
    #: an entry here is the only remaining handle on a session's decrypted
    #: originals, so evicting one leaks strictly more than it saves. See
    #: :data:`MAX_REAP_PER_REQUEST` for the measurement and for what bounds this
    #: instead -- the queue is filled and drained by the same requests, at most one
    #: in against 16 out.
    #:
    #: The value is the number of destruction attempts the ID has **left**, not
    #: ``None``: a destroy that fails is re-queued rather than dropped, and the
    #: count is what stops a permanently-failing ID from being retried for ever.
    #: See :data:`MAX_REAP_ATTEMPTS` and :func:`_requeue_unfinished`.
    reap_backlog: OrderedDict[str, int] = field(default_factory=OrderedDict)
    #: IDs that spent every attempt in :data:`MAX_REAP_ATTEMPTS` without a
    #: destruction completing. Held, never automatically retried, and used as an
    #: ordered set exactly as the backlog is.
    #:
    #: This is where the retry bound is *paid* rather than dodged. Deleting an
    #: exhausted ID would be the 4 096-entry eviction again under a new name --
    #: the entry is still the last handle on that session's decrypted originals,
    #: and a session that cannot be destroyed is precisely the one whose handle
    #: must not be thrown away. Moving it here instead stops it consuming the
    #: 16-per-request budget (so it cannot starve sessions that *can* be
    #: finished), keeps it enumerable for an operator, and leaves it reachable:
    #: :func:`reap_expired_sessions`'s ``first=`` hoist takes an ID back out of
    #: here with a fresh budget, so ``DELETE /sessions/{id}`` still retries the
    #: one session its caller is asking about.
    #:
    #: Bounded by the same argument as the backlog, and more tightly: an entry
    #: can only arrive by way of the backlog, having first cost
    #: :data:`MAX_REAP_ATTEMPTS` failures, so a burst of expiries that all fail is
    #: still one 32-character ID per session some earlier request minted.
    reap_failed: OrderedDict[str, None] = field(default_factory=OrderedDict)


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


def _enqueue_for_reaping(services: Services, expired: list[str]) -> None:
    """Add swept IDs to the backlog, oldest first. Nothing is ever discarded.

    This used to evict the oldest past a 4 096-ID ceiling, and the argument for
    that -- recorded in :data:`MAX_REAP_PER_REQUEST` and in a comment that said it
    in so many words -- was that the key is gone before an ID ever reaches here, so
    a dropped ID leaves nothing but undecryptable rows. That is true of the rows
    and **false of this process**. ``SessionVault.destroy`` is the only thing that
    pops ``SessionVault._caches[session_id]``, and that dict holds originals that
    are *already decrypted* and need no key; ``SessionRegistry.sweep`` drains its
    unreaped set, so an ID dropped from this queue is never offered again. A
    dropped ID therefore meant plaintext resident until process exit, rows left on
    disk with nothing able to reclaim them, no tombstone, and no ``SESSION_EXPIRE``
    or ``VAULT_DESTROY`` in the log.

    So an ID that carries outstanding destruction work is never discarded here.
    Per-request *work* stays bounded where it always was -- in
    :func:`reap_expired_sessions`, at :data:`MAX_REAP_PER_REQUEST` destructions per
    call -- which is the bound that matters, and which this function no longer
    competes with: removing the eviction also removes the one loop in it that could
    run an unbounded number of times in a single request.
    """
    backlog = services.reap_backlog
    for session_id in expired:
        # `setdefault`, not assignment: an ID already queued keeps both its place
        # in the FIFO and whatever is left of its retry budget. Neither can happen
        # today -- `SessionRegistry.sweep` drains its unreaped set, so an ID is
        # offered exactly once -- but refreshing the budget of a failing ID is
        # precisely how a bounded retry turns back into an unbounded one, and that
        # should not depend on a property of a different module.
        backlog.setdefault(session_id, MAX_REAP_ATTEMPTS)


def _requeue_unfinished(services: Services, session_id: str, attempts_left: int) -> None:
    """Put an ID whose destruction did not complete back where a later call finds it.

    ``attempts_left`` is what remains of :data:`MAX_REAP_ATTEMPTS` *after* this
    attempt: callers pass ``budget - 1`` for an ID that was tried and failed, and
    ``budget`` unchanged for one that never got a turn (the request was cancelled
    part-way through the slice), because an attempt that never happened must not
    be charged for one.

    At the **tail**, not the head. A failing ID at the head would be the first
    thing the next call pops, so a handful of them would spend every request's
    whole budget on the same failures while healthy expiries waited behind them --
    the per-request bound would still hold and no session would ever be finished.
    Tail placement makes one retry cost one full trip through the queue, which is
    also what makes :data:`MAX_REAP_ATTEMPTS` a bound on total work rather than on
    work per request.

    Exhausting the budget moves the ID to :attr:`Services.reap_failed` and logs at
    ``error``. It is not deleted, and that is the whole point of the second
    structure: an ID that cannot be destroyed is the one whose decrypted originals
    are still resident, so dropping it is strictly the worst available option.
    """
    if attempts_left > 0:
        services.reap_backlog[session_id] = attempts_left
        return
    services.reap_failed[session_id] = None
    logger.error(
        "expired session could not be destroyed after %d attempts; its decrypted "
        "originals remain resident and its vault rows remain on disk",
        MAX_REAP_ATTEMPTS,
        extra={"session_id": _clamp(session_id), "reap_failed": len(services.reap_failed)},
    )


async def reap_expired_sessions(services: Services, *, first: str | None = None) -> list[str]:
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

    **What that costs, and the bound that pays it.** ``sweep()`` returns every ID
    awaiting destruction, not the ones this caller caused, so the first version of
    this function charged whichever request arrived next for every other caller's
    expiries -- 258 sessions, 311 ms, one request, measured. ``POST /sessions``
    needs no credential, so an anonymous caller filled that queue and an arbitrary
    victim drained it. The sweep still takes everything (it is a set operation
    under the registry's lock, and leaving IDs there is how they got lost before),
    but the *work* is now capped at :data:`MAX_REAP_PER_REQUEST` IDs per call. The
    residual sits in :attr:`Services.reap_backlog`, oldest first, and the next
    request takes the next slice. No caller pays more than a constant.

    The residual is **queued, never dropped**, and that is the half the bound
    cannot be bought at the expense of: an entry in that queue is the last handle
    on a session's decrypted originals, so discarding one strands them in
    ``SessionVault._caches`` for the life of the process. The queue does not need a
    ceiling to be bounded, because it is fed and drained by the same traffic: an ID
    enters only because some earlier request minted the session, so over any window
    at most one ID enters per request while 16 leave. Arrival is bursty -- a
    thousand sessions minted an hour ago expire together and reach one ``sweep()``
    -- but the depth is still bounded by the requests that created them, and every
    request after the burst removes 16. See :func:`_enqueue_for_reaping`.

    **The residency window that bound costs, stated rather than left to be found.**
    Bounding the drain moved the moment an expired session's *already decrypted*
    originals leave ``SessionVault._caches`` from "the first reaping call after the
    expiry is observed" to later, and by exactly this much: an ID that is enqueued
    at 1-based position ``p`` in the backlog is destroyed on the
    ``ceil(p / MAX_REAP_PER_REQUEST)``-th reaping call counted from the call that
    enqueued it. So a burst of ``E`` sessions that expire together and reach one
    ``sweep()`` is fully destroyed after ``ceil(E / 16)`` reaping calls -- 1 call
    for a burst of 16, 63 for a burst of 1 000 -- against 1 call for any size of
    burst before the bound existed. A failed attempt adds one more full trip
    through the queue on top of that (see :func:`_requeue_unfinished`).
    ``test_the_bounded_drain_delays_an_untouched_expiry_by_one_call_per_sixteen``
    pins the arithmetic against the real vault rather than leaving it as prose.

    Three things make that window narrower than the raw formula suggests, and they
    are why 16 was not raised to buy it back. Reaping calls are not scarce: every
    authenticated request runs one through :func:`_require_session`, and so do
    ``POST /sessions`` and ``DELETE /sessions/{id}``, so on a live deployment the
    unit is a request, not a timer tick. ``first=`` collapses the window to a
    single call for the session a caller actually names, which is the case a user
    can observe. And the window governs *residency*, not confidentiality: the
    session key is popped by ``SessionRegistry._sweep_locked`` before an ID can
    reach this queue, so the AES-GCM rows are already undecryptable and every cache
    accessor fails at ``registry.key()`` first. What is waiting is a plaintext
    ``_SessionCache`` that no route can read, on a process that is about to free
    it -- against, on the other side of the trade, an anonymously-fillable queue
    whose whole depth was charged to one arbitrary victim's request (258 sessions,
    311 ms, measured). Raising 16 would shorten the window in proportion and
    lengthen that worst-case request in proportion; the exchange rate is the ~1.2 ms
    per destruction recorded at :data:`MAX_REAP_PER_REQUEST`, so the bound as it
    stands already spends ~19 ms of a request that asked for none of this.

    ``first`` is reaped ahead of the queue when it is outstanding. That is not a
    convenience: ``DELETE /sessions/{id}`` on a session whose TTL has already
    lapsed cannot destroy anything itself -- ``_owns_session`` answers ``False``
    for an expired session, so ``vault.destroy`` is skipped -- and it is the only
    caller that knows *which* session the user is asking to have finished. Without
    the hoist, a logout could return 204 while its rows waited behind an unrelated
    backlog. It is also the one way an ID comes back out of
    :attr:`Services.reap_failed`, with a fresh budget: a named logout is a request
    to retry *this* session, and it is bounded by the caller having to make it.

    Best-effort by construction -- it returns the IDs it **actually destroyed** and
    raises nothing. A failure to tidy up must not fail the request that happened to
    notice, and must not report work it did not do: the return value is what
    ``test_a_flooded_reap_backlog_never_drops_a_session_holding_plaintext`` reads to
    decide the hoisted session is finished.
    """
    _enqueue_for_reaping(services, await services.sessions.sweep())
    backlog = services.reap_backlog
    # The slice this call will work on, ID -> attempts it has left. Ordered (a
    # plain `dict` is), and that order is the order the work is done in.
    slice_: dict[str, int] = {}
    if first is not None:
        budget = backlog.pop(first, None)
        if budget is None and first in services.reap_failed:
            # A named logout is an explicit request to retry this one session, so
            # it comes back out of the dead-letter map with a full budget. Bounded
            # by the caller having to ask, one request at a time, for an ID it
            # already knows.
            del services.reap_failed[first]
            budget = MAX_REAP_ATTEMPTS
        if budget is not None:
            slice_[first] = budget
    # `popitem(last=False)` rather than a slice of `list(backlog)`: the backlog may
    # hold hundreds of thousands of IDs, and materialising all of them to take 16
    # would put the per-request cost this bound exists to remove straight back on
    # this request. It is also why the queue is an `OrderedDict` -- see
    # `Services.reap_backlog` for the measurement.
    while backlog and len(slice_) < MAX_REAP_PER_REQUEST:
        oldest, budget = backlog.popitem(last=False)
        slice_[oldest] = budget
    reaped: list[str] = []
    # Every ID in the slice is off the queue, so the queue is no longer a record
    # that the work is outstanding: from here to the `finally`, this frame is the
    # only handle on it. `taken` is how many of them have reached a verdict --
    # destroyed, or re-queued by the `except` -- and the `finally` puts the rest
    # back. That covers the exit this `except Exception` cannot: `CancelledError`
    # is a `BaseException`, so a client that disconnects mid-drain used to take the
    # whole remaining slice with it, silently and with no failure logged at all --
    # a strictly worse version of the same stranding, and the one a "cancelled
    # request" actually produces.
    taken = 0
    pending = list(slice_)
    try:
        for session_id in pending:
            try:
                await services.vault.destroy(session_id)
                # SESSION_EXPIRE first, then VAULT_DESTROY: the passive death and
                # the teardown it triggers are two facts, and an auditor asking
                # "when did this session end and was it torn down" wants both.
                # `SESSION_EXPIRE` was declared in `audit/logger.py` and never
                # emitted anywhere -- the gap that module's own comment calls "real
                # rather than a spare constant", and that Deviation 26 records.
                # Emitting it here is what makes Deviation 54's claim to close it
                # true; it was written before the event existed.
                for event_type in (SESSION_EXPIRE, VAULT_DESTROY):
                    await services.audit.emit(
                        AuditEvent(
                            ts=time.time(),
                            session_id=_clamp(session_id),
                            event_type=event_type,
                            detail={"existed": 1, "source": "ttl_expiry"},
                        )
                    )
            except Exception:
                # Re-queued, not merely logged. The ID was popped before the
                # destroy was attempted and nothing else ever offers it again --
                # `SessionRegistry.sweep` drains its unreaped set once -- so a
                # logged-and-forgotten failure stranded the session's decrypted
                # originals for the life of the process. Charged one attempt, so
                # a permanently-failing ID cannot be retried for ever.
                _requeue_unfinished(services, session_id, slice_[session_id] - 1)
                logger.warning(
                    "expired session could not be fully destroyed; re-queued",
                    extra={
                        "session_id": _clamp(session_id),
                        "attempts_left": slice_[session_id] - 1,
                    },
                )
            else:
                reaped.append(session_id)
            taken += 1
    finally:
        # Not charged an attempt: these never got one. The interrupted ID is
        # `pending[taken]`, and it is charged nothing either -- a destroy that was
        # cancelled part-way is not evidence that the session cannot be destroyed,
        # and the retry budget exists to bound *failures*, not disconnections.
        for session_id in pending[taken:]:
            _requeue_unfinished(services, session_id, slice_[session_id])
    return reaped


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
    #
    # `first=` is what keeps the second half of that true now that the drain is
    # bounded: the presented session is finished on this request rather than queued
    # behind however many unrelated IDs happen to be ahead of it.
    await reap_expired_sessions(services, first=session_id)
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
