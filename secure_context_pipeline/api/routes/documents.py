"""``POST /documents``, ``GET /documents/{doc_id}/text`` and ``GET /fixtures/{name}``.

The upload leaves plaintext nowhere: the original bytes and the extracted text
are both stored as AES-256-GCM ciphertext under a key derived from the caller's
``user_id``. The read-back is one of exactly two endpoints in the system allowed
to return an original value, and access control *is* the decrypt.

``POST /documents`` is also the one anonymous route whose cost is measured in
megabytes rather than in rows, so it carries a second meter of its own --
:class:`_ByteMeter`, charged in *durable bytes* -- for the reason set out at
:data:`UPLOAD_BYTES_BURST`.

``GET /fixtures/{name}`` is the third route here and the only one that reads
anything off the server's own disk. It hands the browser the four **synthetic**
demo documents this repo ships so the demo UI's preset dropdown can load one in
a single click instead of naming a path and asking the reviewer to go find it.
It is a *read-only allow-list*, not a file server, and the whole of its security
argument is at :data:`DEMO_FIXTURES` and :func:`_load_shipped_fixtures`.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Annotated

from fastapi import APIRouter, File, Form, Request, Response, UploadFile
from fastapi import Path as PathParam
from fastapi import status as http_status
from fastapi.responses import PlainTextResponse

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
from secure_context_pipeline.config import PACKAGE_ROOT
from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.store.document_store import DOC_CATEGORIES, InvalidCategoryError

logger = logging.getLogger(__name__)

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


# ---------------------------------------------------------------------------
# The four shipped demo fixtures, over HTTP
# ---------------------------------------------------------------------------
#: Where the shipped fixtures live, resolved the same way
#: :data:`~secure_context_pipeline.config.DEFAULT_REGISTRY_PATH` resolves
#: ``entities.yaml`` -- the package's parent -- so a deployment that can find the
#: registry can find these. The Dockerfile's ``COPY fixtures/ fixtures/`` puts
#: them at ``/app/fixtures`` beside ``/app/entities.yaml``, and both are in the
#: image's explicit allow-list rather than in a ``COPY . .``.
FIXTURES_DIR = PACKAGE_ROOT.parent / "fixtures"

#: **The allow-list.** Exact filename -> the ``doc_category`` that document must
#: be scanned under. There is no other way into :data:`FIXTURE_BYTES`, and there
#: is no code path anywhere in this module that turns a caller's string into a
#: filesystem path.
#:
#: A literal table rather than ``FIXTURES_DIR.glob("*.txt")``, and the difference
#: is the whole control. A glob makes the served set a property of the filesystem
#: *at the moment of the request*: a developer's scratch file, a document a
#: reviewer dropped in the directory to try it, a symlink planted by anything that
#: can write there -- each would become world-readable on an anonymous GET the
#: instant it appeared, with no code change and no review. With a table, adding a
#: name is a diff. That these four names are the ones that actually ship is not
#: asserted here, it is measured against ``git ls-files`` by
#: ``tests/test_api_documents.py::test_the_fixture_allow_list_is_exactly_what_the_repo_ships``,
#: so deleting or renaming a fixture fails a test rather than leaving a dead entry.
#:
#: The categories are the same strings the demo UI's ``<option data-cat>`` carries;
#: ``test_the_ui_dropdown_and_the_server_allow_list_are_the_same_four_documents``
#: pins the two together so the dropdown cannot drift into arming a document under
#: a category this server would not have chosen for it.
DEMO_FIXTURES: Mapping[str, str] = MappingProxyType(
    {
        "medical_note.txt": "medical",
        "legal_memo.txt": "legal",
        "financial_disclosure.txt": "financial",
        "legal_brief_large.txt": "legal",
    }
)

#: Longest shipped name is ``financial_disclosure.txt`` at 24 characters, so this
#: is 5.3x the longest thing that can legitimately arrive. It is a ceiling on the
#: *request*, not the control -- a 128-character name is refused by the allow-list
#: exactly as a 4-character one is -- and it is set this loose on purpose: every
#: adversarial name the tests send (``../../etc/passwd``, ``/etc/passwd``,
#: ``....//....//etc/passwd``, a NUL-terminated name, a URL-encoded traversal) is
#: under it and therefore reaches the allow-list, so what refuses them is
#: demonstrably the allow-list and not a length check that fired first.
MAX_FIXTURE_NAME_LEN = 128

#: A file bigger than this is not loaded, and the endpoint answers 404 for it.
#: Largest shipped fixture is ``legal_brief_large.txt`` at 83 029 bytes, so this is
#: 12.6x headroom. It bounds the resident cost of :data:`FIXTURE_BYTES` (the four
#: shipped files total 91 935 bytes) against the one way that number could grow
#: without anyone noticing: an allow-listed *name* whose file someone later made
#: enormous. It is not an upload ceiling; :data:`MAX_UPLOAD_BYTES` still owns what
#: ``POST /documents`` will accept, and these bytes go back through that route.
MAX_FIXTURE_BYTES = 1024 * 1024


def _load_shipped_fixtures(directory: Path) -> dict[str, bytes]:
    """Read the allow-listed files into memory, once, at import.

    **This is the function that makes the endpoint structurally incapable of
    becoming a general file reader.** Holding the bytes rather than reading them
    per request means the request path never touches the filesystem at all: a
    caller's string reaches exactly one operation, ``FIXTURE_BYTES.get(name)``, a
    dict lookup on a table whose keys are literals in this file. There is no
    ``open``, no ``read_bytes`` and no ``/`` operator downstream of the handler
    for a later edit to point somewhere else -- widening this route would take
    *adding* filesystem access to a handler that has none, which is a diff a
    reviewer sees, rather than changing which path an existing read is handed,
    which is a diff that looks like a rename.

    The only string that ever reaches the ``/`` operator is ``allowed``, the
    table's own key. That is why the loop is written over
    ``DEMO_FIXTURES`` and the caller's name never appears here.

    Five refusals, none of which a *request* can reach -- they guard the
    directory, not the caller, and they exist because "the allow-list names it"
    and "the thing on disk under that name is the document we shipped" are
    different claims:

    * a **symlink** is refused outright, so a link planted in ``fixtures/`` under
      an allow-listed name cannot make this route read its target;
    * a path whose real parent is not the real ``directory`` is refused. The
      overlap between these two is measured rather than asserted: deleting either
      one alone still refuses a link pointing *out* of the directory (each catches
      it), and only deleting both lets ``/etc/passwd`` through under the name
      ``medical_note.txt``; the link-to-a-sibling case is caught by the first
      check alone. So the second is redundant today and is kept as the layer that
      survives the first being deleted, which is exactly the mutation that
      demonstrated it;
    * anything that is not a regular file (a FIFO would block the process on
      ``read_bytes``) is refused;
    * a file over :data:`MAX_FIXTURE_BYTES` is refused, so the resident table
      cannot silently grow;
    * bytes that are not valid UTF-8 are refused, and that one is a *correctness*
      guard for the caller rather than a security one: the browser receives this
      body as text and re-encodes it to UTF-8 before posting it back to
      ``POST /documents``, which is lossless for valid UTF-8 and silently
      mangling for anything else -- so a preset run would stop being the same
      document as a hand-picked run, which is the property this whole route is
      written to preserve. All four shipped fixtures are pure ASCII.

    A missing or refused fixture is a warning and an absent key, never an
    exception: this module is imported while the ASGI app is built, and a
    deployment that forgot ``fixtures/`` must still serve the pipeline. The demo
    preset then reports itself unavailable, which is the honest failure.

    Measured on this build: the four shipped files are 91 935 bytes and load in a
    median 0.21 ms over 50 repeats, once, at import.
    """
    loaded: dict[str, bytes] = {}
    try:
        real_dir = directory.resolve(strict=True)
    except OSError:
        logger.warning("demo fixtures not served; directory absent (path=%s)", directory)
        return loaded
    for allowed in DEMO_FIXTURES:
        # `allowed` -- a literal key of the table above -- is the ONLY thing this
        # module ever joins onto a directory. Never a path component that came in
        # over the wire.
        path = directory / allowed
        if path.is_symlink():
            logger.warning("demo fixture refused: symlink (name=%s)", allowed)
            continue
        if not path.is_file():
            logger.warning("demo fixture missing or not a regular file (name=%s)", allowed)
            continue
        try:
            real = path.resolve(strict=True)
        except OSError:
            logger.warning("demo fixture refused: unresolvable (name=%s)", allowed)
            continue
        if real.parent != real_dir:
            logger.warning("demo fixture refused: resolves outside its own directory (%s)", allowed)
            continue
        size = real.stat().st_size
        if size > MAX_FIXTURE_BYTES:
            logger.warning(
                "demo fixture refused: %d bytes exceeds %d (name=%s)",
                size,
                MAX_FIXTURE_BYTES,
                allowed,
            )
            continue
        data = real.read_bytes()
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning("demo fixture refused: not valid UTF-8 (name=%s)", allowed)
            continue
        loaded[allowed] = data
    return loaded


#: The served bytes, keyed by allow-listed name. Built once, at import; ~92 KB
#: resident for the life of the process, which is 0.006% of the ~1.5 GB an
#: ``en_core_web_lg`` worker already holds.
FIXTURE_BYTES: Mapping[str, bytes] = MappingProxyType(_load_shipped_fixtures(FIXTURES_DIR))


@router.get(
    "/fixtures/{name:path}",
    response_class=PlainTextResponse,
    responses=_ERRORS,
    tags=["documents"],
    summary="One of the four shipped demo documents, by exact name (read-only)",
)
async def get_demo_fixture(
    name: Annotated[
        str,
        PathParam(
            max_length=MAX_FIXTURE_NAME_LEN,
            description=f"Exactly one of {sorted(DEMO_FIXTURES)}. Nothing else is served.",
        ),
    ],
) -> Response:
    """Serve one shipped demo fixture so the UI preset can load it in one click.

    **What this discloses: nothing new.** The four documents are *synthetic* --
    generated by ``fixtures/generator.py``, containing no real person, no real
    account and no real record -- and they already ship in the git repository and
    in the container image (``COPY fixtures/ fixtures/``). Anyone who can reach
    this port can already read them out of the clone or the image; serving them
    over HTTP moves no boundary. Nothing here touches the encrypted store, the
    vault or the audit log, and no response from this route can contain a value
    from any of them: it returns bytes from a table built at import, and that
    table's keys are the four literals at :data:`DEMO_FIXTURES`.

    **No session, deliberately, and the reasoning is the point.** A session would
    be pure friction with no security to show for it, for three reasons that all
    have to hold:

    1. It would gate content the same origin already publishes anonymously.
       ``_mount_ui`` serves ``index.html``, ``app.js`` and ``style.css`` to
       anybody, and a synthetic fixture is the same class of shipped asset.
    2. A session is not a credential here. ``POST /sessions`` mints one for any
       ``user_id`` an anonymous caller asks for -- ``api/app.py``'s docstring
       states this and the audit-proof meter exists because of it -- so
       "authenticated" would mean "made one extra anonymous request first".
    3. It would break the thing this endpoint was added to fix. The preset is the
       *first* control a reviewer touches; requiring a session to load a document
       reintroduces an ordering trap in the exact place the friction was.

    The honest counterweight, recorded rather than argued away: this is an
    unauthenticated read that returns bytes the server holds. That is precisely
    why the control is a closed allow-list of four names and not authentication --
    authentication would decide *who* may read, and the property that matters here
    is that there is nothing else to read.

    **It does not bypass the upload path.** This route stores nothing and issues
    no ``doc_id``. The browser takes these bytes straight back to
    ``POST /documents`` as an ordinary multipart file with the same ``user_id``
    and the same ``doc_category``, so a preset run and a hand-picked run of the
    same fixture produce the same stored document and the same detections --
    proved end to end by
    ``test_a_preset_run_and_a_hand_picked_run_of_one_fixture_detect_identically``.

    Anything not in the table is ``404 NOT_FOUND``, and the two 404 reasons are
    deliberately distinguishable (``not_a_shipped_fixture`` against
    ``fixture_not_installed``) because both facts are already public: the
    allow-list is printed in this route's own OpenAPI description. The caller's
    string is never echoed back into the detail.
    """
    data = FIXTURE_BYTES.get(name)
    if data is None:
        raise ApiError(
            http_status.HTTP_404_NOT_FOUND,
            "NOT_FOUND",
            {
                "reason": (
                    "fixture_not_installed" if name in DEMO_FIXTURES else "not_a_shipped_fixture"
                ),
                "shipped": len(DEMO_FIXTURES),
            },
        )
    # `text/plain` with an explicit charset, and `X-Content-Type-Options: nosniff`
    # from `_SecurityHeaders` on top of it, so a browser that navigates here
    # directly renders inert text rather than sniffing the body into markup. No
    # `Content-Disposition: attachment`: these are the demo's documents and a
    # reviewer looking at one in a tab is a feature, and the response-wide CSP
    # (`default-src 'none'`) already makes the page inert if one ever were markup.
    return Response(content=data, media_type="text/plain; charset=utf-8")
