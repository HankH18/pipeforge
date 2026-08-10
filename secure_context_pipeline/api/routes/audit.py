"""``GET /audit`` and ``GET /audit/verify`` -- compliance reads of the chain.

Both take a *proved* scope rather than a quoted one: the claimed ``user_id`` is
checked against the owner recorded in the log itself, an unproved scope reads as
empty, and the failed proof is metered and recorded. The reasoning is on the two
handlers and on :func:`secure_context_pipeline.api.deps._resolve_audit_scope`.

``/audit/verify`` carries a second meter, on *cost* rather than on disclosure or
on durable writes: the chain walk is priced in rows before it runs, because it is
the one read here whose price per request grows with the log and never falls.
See :data:`CHAIN_WALK_ROWS_PER_TOKEN`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request
from fastapi import status as http_status

from secure_context_pipeline.api.constants import (
    DEFAULT_AUDIT_PAGE,
    HTTP_429_TOO_MANY_REQUESTS,
    MAX_AUDIT_PAGE,
)
from secure_context_pipeline.api.deps import (
    _ERRORS,
    ApiError,
    OptionalIdQuery,
    Services,
    ServicesDep,
    UserIdQuery,
    _deny_audit_scope,
    _resolve_audit_scope,
    _same_id,
)
from secure_context_pipeline.api.middleware import _caller_key, _RateLimiter
from secure_context_pipeline.api.schemas import AuditQueryResponse, AuditVerifyResponse

router = APIRouter()

#: Ceiling on ``GET /audit?offset=``. The literal is the top of SQLite's signed
#: 64-bit ``INTEGER`` range, which is exactly where this parameter stopped being
#: data and became a crash. Measured on this build: ``offset=9223372036854775807``
#: answered ``200`` with an empty page, and ``+1`` raised ``OverflowError: Python
#: int too large to convert to SQLite INTEGER`` out of :meth:`AuditLogger.query`
#: at the ``conn.execute`` that binds it.
#:
#: No handler in :func:`_register_handlers` is registered for ``OverflowError``,
#: so it fell through to Starlette's ``ServerErrorMiddleware`` -- which sits
#: *outside* the app's own ``_SecurityHeaders`` middleware. The answer was a bare
#: ``text/plain`` ``500 Internal Server Error``: not the ``{code, detail}`` shape
#: ``api/errors.py`` claims of *every* non-2xx body, and carrying none of the
#: three security headers ``api/app.py`` claims of every response. A full
#: traceback was logged with it. ``GET`` is not in :data:`METERED_METHODS` and a
#: *successful* scope proof charges no meter, so one session -- and ``POST
#: /sessions`` mints one for any ``user_id`` an anonymous caller names -- bought
#: unbounded repeats of that traceback in two requests.
#:
#: Bounding the parameter is what closes it here: an over-range ``offset`` is now
#: refused by the same pydantic validation that already refuses an over-range
#: ``limit``, so it answers ``422 VALIDATION_ERROR`` through
#: :func:`_validation_handler`, inside the middleware, with the headers on. The
#: refusal is pinned to the absolute literal in ``tests/test_api.py`` rather than
#: to this name, for the reason :data:`MAX_AUDIT_PAGE` records: an assertion
#: phrased in terms of the constant keeps agreeing with itself when the constant
#: moves.
MAX_AUDIT_OFFSET = 2**63 - 1

#: Per-caller budget for one chain walk, and the reason the walk needs a budget
#: at all. ``METERED_METHODS`` covers ``POST``/``PUT``/``PATCH``/``DELETE``
#: because those write something durable, and :data:`AUDIT_PROOF_BURST` covers a
#: *failed* scope proof because that writes a row too. Both meters reason about
#: durability; neither bounds **cost**, and ``GET /audit/verify`` is the one read
#: in this API whose cost is unbounded and monotonically rising.
#:
#: :meth:`AuditLogger.verify_chain` recomputes an HMAC-SHA256 over the
#: ``chain_payload`` of every row in ``audit_events`` -- keyed since the chain was
#: keyed, and priced the same, because an HMAC is two compressions more than the
#: bare digest this comment used to name and the walk is dominated by the row
#: fetch either way -- ``_CHAIN_SQL`` has no ``WHERE`` clause, and
#: the scoped form walks the whole chain as well because it has to know each
#: row's predecessor. Measured on this build, anonymously, with no session and no
#: credential of any kind: 0.7 ms at 0 rows, 7.4 ms at 1 000, 35.2 ms at 5 000,
#: 143.3 ms at 20 000 -- linear, about 7.2 us per row -- and 50 back-to-back
#: calls all answered ``200``. The log is append-only and unprunable *by
#: construction* (pruning is what tamper-evidence forbids), so that number only
#: ever climbs: at a million rows one anonymous request is seconds of CPU.
#:
#: A per-caller token bucket is what closes it, and the tokens buy **rows of
#: chain, not requests**. That distinction is the whole design, and it is there
#: because the obvious version was built first and measured doing nothing: one
#: token per request, a burst of 20 and one token per second, against a 20 000-row
#: log answered **all 50** of the same back-to-back anonymous calls, because a
#: walk that costs 752 ms (that machine, under load) refills its own token while
#: it runs. A request meter cannot bound work whose unit price is unbounded; it
#: only reads as though it does, which is the failure mode this repository keeps
#: rediscovering.
#:
#: So the price is ``1 + rows // CHAIN_WALK_ROWS_PER_TOKEN`` tokens, read from
#: ``AuditLogger.length()`` before any hashing starts, and the budget is stated in
#: hashing throughput: :data:`CHAIN_WALK_REFILL_PER_SECOND` x
#: :data:`CHAIN_WALK_ROWS_PER_TOKEN` = 10 000 rows/s, about 72 ms of SHA-256 per
#: second of wall clock -- roughly 7% of one core per caller -- with a burst of
#: :data:`CHAIN_WALK_BURST` tokens, i.e. 120 000 rows (~0.9 s) all at once. The
#: bound therefore holds as the log grows: at a million rows a walk costs the full
#: burst instead of one token, so it is answered once every twelve seconds per
#: caller rather than as fast as the caller can ask.
#:
#: The price is capped at the bucket's capacity on purpose. Without the cap a log
#: past 120 000 rows would be *permanently unverifiable* over HTTP -- no caller
#: could ever afford one walk -- and silently killing the one publicly checkable
#: claim in the system is a worse outcome than serving it slowly.
#:
#: For any log a demo or a small deployment actually has, this is invisible: under
#: 5 000 rows every walk costs one token, so the ``btn-verify`` button in
#: ``ui/app.js`` (click-driven, no polling) gets 24 in a row and two a second
#: after that. ``demo.py`` is unaffected either way -- it calls
#: :meth:`AuditLogger.verify_chain` in-process, not over HTTP.
#:
#: Scoped and unscoped are charged identically, and at the *unfiltered* row count,
#: because they are the same walk: ``verify_chain(session_id=...)`` still hashes
#: every row, it only narrows what it asserts on. Pricing the scoped form by its
#: own session's length, or leaving it unmetered, would move the whole cost one
#: query parameter over -- the failure mode :data:`AUDIT_PROOF_BURST` already
#: records for the oracle it bounds.
#:
#: **What this bounds and what it does not.** One caller, exactly like the other
#: two meters: 4 096 source addresses each get their own bucket, so aggregate load
#: still belongs to a reverse proxy, and bounding the log itself still belongs to
#: rotation with each segment's head hash anchored off-box. It also does not make
#: the walk cheaper -- verifying incrementally from a persisted checkpoint would,
#: and that belongs in the audit package rather than in a route.
CHAIN_WALK_ROWS_PER_TOKEN = 5_000
CHAIN_WALK_BURST = 24
CHAIN_WALK_REFILL_PER_SECOND = 2.0


def _chain_walk_meter(request: Request) -> _RateLimiter:
    """The meter for this route, created on first use and held on ``app.state``.

    Not a module-level bucket: that would be process-global, so two applications
    in one interpreter would share a budget and a test could starve the next test
    with no way to put the budget back. ``app.state`` is the seam
    ``app.state.rate_limits`` already gives the other two meters -- per
    application, and swappable by a test that wants a two-token bucket without
    rebuilding the app (which means loading spaCy again).

    Lazily built rather than constructed in :func:`create_app` so this route
    cannot be deployed without the meter it depends on: an app assembled without
    the usual startup path still gets a bounded walk. That is deliberately the
    opposite default from :class:`_RateLimit`, which passes a request through
    when no meter is installed -- middleware must never be the reason a correctly
    built app refuses traffic, whereas *this* budget is the only thing standing
    between an anonymous caller and an unbounded amount of hashing.
    """
    state = request.app.state
    meter = getattr(state, "audit_chain_walks", None)
    if not isinstance(meter, _RateLimiter):
        meter = _RateLimiter(
            capacity=CHAIN_WALK_BURST, refill_per_second=CHAIN_WALK_REFILL_PER_SECOND
        )
        state.audit_chain_walks = meter
    return meter


async def _charge_chain_walk(request: Request, services: Services) -> None:
    """Price this walk in rows, spend the tokens, or refuse with ``429``.

    Charged *before* the walk, which is the whole point -- a check afterwards
    would refuse the caller only once the work it is paying for had already been
    done. Same ordering rule, and same reason, as the meter in
    :func:`_deny_audit_scope`, which is charged before the row it guards is
    written.

    The count that sets the price is itself a query, so it is not free -- but it
    is a ``COUNT(*)`` against a log whose per-row cost is one SHA-256 of a
    canonical JSON payload, and every request pays at least one token for it, so
    the cheap read is bounded by the same bucket as the expensive one.

    Tokens are spent one at a time and the first shortfall refuses, so a caller
    that cannot afford the whole walk is still charged for the part it could --
    a partial debt, deliberately. Refunding it would let a caller with an empty
    bucket keep asking for free. The loop holds no ``await``, so one request's
    whole price is spent as a single step on the event loop; a suspension inside
    it would let two concurrent requests each pay half a walk and take two.

    The refusal names nothing and is therefore not an oracle: it is the identical
    reply for the unscoped whole-log form, which already reveals no identifier at
    all, and it carries the same ``RATE_LIMITED`` code and ``retry_after_seconds``
    detail as every other throttled answer in this API.
    """
    rows = await services.audit.length()
    meter = _chain_walk_meter(request)
    # Capped at the bucket's own capacity, not at the constant: a differently
    # sized meter (a test's, or a future deployment's) must still be able to buy
    # one walk when it is full, or a long enough log becomes permanently
    # unverifiable over HTTP.
    price = min(meter.capacity, 1 + rows // CHAIN_WALK_ROWS_PER_TOKEN)
    caller = _caller_key(request.scope)
    for _ in range(price):
        wait = meter.take(caller)
        if wait > 0.0:
            raise ApiError(
                HTTP_429_TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                {"retry_after_seconds": round(wait, 1)},
            )


@router.get(
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
    since: Annotated[
        float | None,
        Query(allow_inf_nan=False, description="Inclusive epoch-seconds lower bound."),
    ] = None,
    until: Annotated[
        float | None,
        Query(allow_inf_nan=False, description="Inclusive epoch-seconds upper bound."),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_AUDIT_PAGE)] = DEFAULT_AUDIT_PAGE,
    offset: Annotated[int, Query(ge=0, le=MAX_AUDIT_OFFSET)] = 0,
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

    **``since``/``until`` refuse non-finite bounds**, and the one that mattered
    is ``NaN``. Bare ``float`` accepts the literal string ``nan``, and Python's
    ``sqlite3`` driver binds a ``NaN`` as SQL ``NULL`` -- so ``(:since IS NULL OR
    ts >= :since)`` evaluates ``TRUE`` for every row and the window is dropped
    entirely. Measured on this build against a one-row session: ``since=9e99``
    and ``since=inf`` returned 0 rows, ``until=-inf`` returned 0 rows, and
    ``since=nan`` returned **1** -- the whole unfiltered page, where a ``NaN``
    comparison implies the empty set. That is the one input where this route
    reported a window it was not applying, and a compliance read that silently
    ignores its own filter is worse than one that refuses it. ``inf``/``-inf``
    are refused with it rather than kept: an infinite bound is expressible as no
    bound, so nothing is lost, and it matches ``canonical_json``'s
    ``allow_nan=False`` on the write side of this same log.
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


@router.get(
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

    **Anonymous is not the same as free, and this route used to be both.** The
    reasoning above -- and the one at :data:`METERED_METHODS` -- is entirely
    about *disclosure* and *durable writes*, and neither bounds cost. The walk
    re-hashes every row in the log, the log cannot be pruned, and ``GET`` is not
    a metered method, so an unauthenticated caller could buy an unbounded,
    ever-growing amount of server CPU by repeating a request that discloses
    nothing: measured on this build, 143.3 ms per anonymous call at 20 000 rows,
    with 50 back-to-back calls all answered. :func:`_charge_chain_walk` now prices
    the walk in rows against a per-caller bucket, scoped and unscoped alike,
    before any hashing happens -- see :data:`CHAIN_WALK_ROWS_PER_TOKEN` for why
    the price is in rows rather than in requests. The endpoint stays anonymous; it
    stops being unlimited.
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
    # After the deny path and before the walk: a refused proof has already paid
    # into its own meter and does no hashing, so charging it here as well would
    # bill one request twice.
    await _charge_chain_walk(request, services)
    valid = await services.audit.verify_chain(session_id)
    length = await services.audit.length(session_id)
    return AuditVerifyResponse(valid=valid, length=length, session_id=session_id)
