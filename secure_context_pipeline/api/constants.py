"""Ceilings, policies and identifiers shared across the API layer.

Every value below was part of :mod:`secure_context_pipeline.api.app` and is
unchanged, comment and all. They sit in a module of their own because the
middleware, the request-scoped helpers and the route modules all reach for them
and must not import one another to do it -- the reasoning attached to each one
is that value's contract, not a description of it.
"""

from __future__ import annotations

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
