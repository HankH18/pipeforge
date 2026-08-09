"""``POST /documents`` as a *disk* primitive (build doc sections 8, 9.1, 10.8).

``tests/test_api.py`` already covers this route's functional contract -- what it
accepts, what it refuses, what it never echoes back. This file covers the one
property that file's meter section cannot see, because that section drives
``POST /sessions`` and ``DELETE /sessions/{id}`` only: those two anonymous routes
cost *rows*, and this one costs *megabytes*.

Everything here runs against the real app, the real encrypted store and real
AES-GCM through :class:`httpx.ASGITransport`; the growth numbers are read off the
data directory with :func:`os.stat`, which shares no helper, no constant and no
arithmetic with the code under test. The one mock is the LLM, which this route
never reaches.
"""

from __future__ import annotations

import base64
import inspect
import json
import os
import secrets
import subprocess
from collections.abc import AsyncIterator, Iterator, MutableMapping
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from secure_context_pipeline.api.app import (
    MAX_UPLOAD_BYTES,
    WRITE_BURST,
    WRITE_REFILL_PER_SECOND,
    create_app,
)
from secure_context_pipeline.api.routes import documents as documents_module
from secure_context_pipeline.api.routes.documents import (
    DEMO_FIXTURES,
    FIXTURE_BYTES,
    MAX_FIXTURE_BYTES,
    MAX_FIXTURE_NAME_LEN,
    UPLOAD_BYTES_BURST,
    UPLOAD_BYTES_REFILL_PER_SECOND,
    UPLOAD_METER_ATTR,
    _ByteMeter,
    _load_shipped_fixtures,
    get_demo_fixture,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.models import DOC_CATEGORIES

#: ``asyncio_mode = "auto"`` already marks the coroutines; only the loop scope
#: needs saying, and it is said per test rather than as a module-level
#: ``pytestmark`` because this file also holds synchronous tests of the bucket
#: itself, which the module-level form would mark as asyncio too.
_MODULE_LOOP = pytest.mark.asyncio(loop_scope="module")

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "entities.yaml"

#: No session, no ``X-Session-Id``, and a name the caller invented. That is the
#: whole credential story for this route, and it is why its cost is metered.
ANON = "anonymous-uploader"

#: Big enough that the store's two blob writes dominate SQLite's page rounding,
#: small enough that a handful of them do not make this file the slowest in the
#: suite. Incompressible content is irrelevant here -- nothing compresses.
PAYLOAD_BYTES = 1024 * 1024


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def api_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Settings pointed at a throwaway data directory, isolated from other tests."""
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("api-docs-data"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def app(api_settings: Settings) -> FastAPI:
    """One app for the module: a ``Detector`` loads spaCy, which costs tens of seconds."""
    return create_app(api_settings)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """One client, one app, one lifespan, one event loop for the whole module."""
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://scp.test") as http:
            yield http


@pytest.fixture(scope="module")
def data_dir(api_settings: Settings) -> Path:
    return Path(api_settings.data_dir)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _durable_bytes(root: Path) -> int:
    """Every byte the process has left on the disk, counted from the filesystem.

    Deliberately not "ask the store how much it stored": a quota the store
    reports is a checker sharing a blind spot with the thing it checks. This
    walks the tree and sums ``st_size``, which is true whatever the store
    believes -- blobs, WAL, journals and all.
    """
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


async def _upload(client: AsyncClient, payload: bytes, *, name: str = "note.txt") -> int:
    response = await client.post(
        "/documents",
        files={"file": (name, payload, "text/plain")},
        data={"user_id": ANON},
    )
    return response.status_code


@contextmanager
def _byte_meter(app: FastAPI, meter: _ByteMeter) -> Iterator[_ByteMeter]:
    """Install a meter on the live app and put the previous one back.

    The app is module-scoped, so leaving a two-token bucket installed would make
    the next test's green depend on this one's order.
    """
    previous = getattr(app.state, UPLOAD_METER_ATTR, None)
    setattr(app.state, UPLOAD_METER_ATTR, meter)
    try:
        yield meter
    finally:
        if previous is None:
            delattr(app.state, UPLOAD_METER_ATTR)
        else:
            setattr(app.state, UPLOAD_METER_ATTR, previous)


def _generous() -> _ByteMeter:
    """A meter that cannot be the reason anything is refused."""
    return _ByteMeter(capacity=1 << 40, refill_per_second=float(1 << 40))


# ---------------------------------------------------------------------------
# The control
# ---------------------------------------------------------------------------
@_MODULE_LOOP
async def test_an_anonymous_uploader_is_metered_in_durable_bytes_not_in_requests(
    app: FastAPI, client: AsyncClient, data_dir: Path
) -> None:
    """The refusal must come from the *byte* budget, and must precede the blobs.

    Measured on the unmetered build: five anonymous uploads of a 16 777 215-byte
    body grew the data directory by 167 834 235 bytes -- 33 566 847 each, since
    ``put`` writes a ``.raw`` and a ``.txt``. The request meter covers this route
    (it meters by method, so it cannot miss one), but it counts requests, and at
    ``WRITE_BURST``/``WRITE_REFILL_PER_SECOND`` that is 8.00 GiB of burst and
    256 MiB/s sustained from one address with no credential, none of it ever
    reclaimed: there is no ``DELETE`` on ``/documents``, no TTL, no quota, and
    ``sweep_orphans`` skips anything with a metadata row.

    Three assertions, and the third is the one that makes the first two mean
    something. The accepted uploads must *grow* the directory -- without that
    positive control an "unchanged" reading below would pass on a build where
    nothing is ever written. The throttled upload must leave the directory
    byte-for-byte identical, which is what pins the charge *before* the first
    ``_write_blob`` rather than after. And the same request, replayed under a
    meter with budget, must succeed -- otherwise the 429 could equally have come
    from the request meter, and this test would be certifying a control it never
    exercised.
    """
    payload = b"x" * PAYLOAD_BYTES
    # Two uploads' worth of budget and a refill too slow to matter over a test.
    meter = _ByteMeter(capacity=2 * PAYLOAD_BYTES + 1, refill_per_second=1.0)

    with _byte_meter(app, meter):
        before = _durable_bytes(data_dir)
        assert await _upload(client, payload) == 200
        assert await _upload(client, payload) == 200
        after_accepted = _durable_bytes(data_dir)
        # Positive control: accepted uploads really do land on the disk, so the
        # "unchanged" reading below is a refusal and not an inert route.
        assert after_accepted - before >= 2 * 2 * PAYLOAD_BYTES, (
            before,
            after_accepted,
        )

        refused = await client.post(
            "/documents",
            files={"file": ("note.txt", payload, "text/plain")},
            data={"user_id": ANON},
        )
        assert refused.status_code == 429, refused.text
        body = refused.json()
        assert body["code"] == "RATE_LIMITED", body
        assert body["detail"]["retry_after_seconds"] > 0, body
        assert _durable_bytes(data_dir) == after_accepted, (
            "the throttled upload wrote blobs before it was refused; the byte "
            "charge must precede the first _write_blob or it bounds the answer "
            "rather than the disk"
        )

    # The request meter was never the reason: the identical request succeeds the
    # moment the *byte* budget is restored, with no time passing.
    with _byte_meter(app, _generous()):
        assert await _upload(client, payload) == 200


@_MODULE_LOOP
async def test_the_shipped_upload_budget_is_pinned_and_bounds_growth_in_absolute_bytes(
    app: FastAPI, client: AsyncClient, data_dir: Path
) -> None:
    """The numbers actually in front of an anonymous caller, with the amplification measured.

    Every other assertion in this file installs its own meter, so all of them
    stay green if the shipped budget is raised to a terabyte. These are the
    shipped values, by value -- and the durable cost of a byte is *measured here*
    rather than copied from a docstring, because that ratio moves the day the
    store writes a third blob and a hard-coded 2x would keep reporting the old
    bound.
    """
    assert UPLOAD_BYTES_BURST == 64 * 1024 * 1024, UPLOAD_BYTES_BURST
    assert UPLOAD_BYTES_REFILL_PER_SECOND == 1024.0 * 1024.0, UPLOAD_BYTES_REFILL_PER_SECOND

    payload = b"x" * PAYLOAD_BYTES
    with _byte_meter(app, _generous()):
        before = _durable_bytes(data_dir)
        assert await _upload(client, payload) == 200
        durable = _durable_bytes(data_dir) - before
    amplification = durable / PAYLOAD_BYTES
    # Two blobs plus a metadata row: ~2.0x, measured at 2.0007x on a 16 MiB body.
    assert 1.9 <= amplification <= 2.5, (durable, amplification)

    burst_durable = UPLOAD_BYTES_BURST * amplification
    steady_durable = UPLOAD_BYTES_REFILL_PER_SECOND * amplification
    assert burst_durable <= 192 * 1024 * 1024, burst_durable
    assert steady_durable <= 4 * 1024 * 1024, steady_durable

    # And what the request meter alone admits, for the same caller, computed from
    # the shipped constants: this is the number the byte meter exists to cut.
    requests_only = WRITE_REFILL_PER_SECOND * MAX_UPLOAD_BYTES * amplification
    assert requests_only / steady_durable >= 100.0, (requests_only, steady_durable)
    assert WRITE_BURST * MAX_UPLOAD_BYTES * amplification / burst_durable >= 50.0


@_MODULE_LOOP
async def test_an_unprocessable_document_is_charged_before_it_is_rejected(
    app: FastAPI, client: AsyncClient
) -> None:
    """Fail-closed: the budget is spent by every request that reaches ``put``.

    A caller does not have to send a *valid* document to make the server work:
    extraction runs on the bytes either way. Charging after a successful ``put``
    -- the obvious place, one line later -- would hand an attacker a free channel
    of unsupported-suffix uploads, refused with 400 and costing nothing. The
    budget below is exhausted entirely by rejected requests, and the legitimate
    upload that follows is the one that pays for it.
    """
    payload = b"x" * PAYLOAD_BYTES
    meter = _ByteMeter(capacity=2 * PAYLOAD_BYTES, refill_per_second=1.0)

    with _byte_meter(app, meter):
        for _ in range(2):
            rejected = await client.post(
                "/documents",
                files={"file": ("payload.xyz", payload, "application/octet-stream")},
                data={"user_id": ANON},
            )
            assert rejected.status_code == 400, rejected.text
            assert rejected.json()["code"] == "UNPROCESSABLE_DOCUMENT", rejected.text
        assert await _upload(client, payload) == 429


@_MODULE_LOOP
async def test_the_meter_is_built_on_first_use_and_is_the_one_that_is_charged(
    app: FastAPI, client: AsyncClient
) -> None:
    """No installed meter means the shipped budget, not an unmetered route.

    The middleware's rule is the opposite -- an app with no meter installed
    passes traffic, because middleware must never be the reason a correctly built
    app refuses. Here the missing meter *is* the defect, so the route builds one.
    Asserted from the outside: the attribute is absent before the request and
    holds a charged bucket after it.
    """
    previous = getattr(app.state, UPLOAD_METER_ATTR, None)
    if previous is not None:
        delattr(app.state, UPLOAD_METER_ATTR)
    try:
        assert not hasattr(app.state, UPLOAD_METER_ATTR)
        assert await _upload(client, b"y" * 4096) == 200
        built = getattr(app.state, UPLOAD_METER_ATTR)
        assert isinstance(built, _ByteMeter)
        assert built.capacity == UPLOAD_BYTES_BURST
        assert built.refill_per_second == UPLOAD_BYTES_REFILL_PER_SECOND
        assert built.tracked() == 1, built.tracked()
    finally:
        if previous is None:
            delattr(app.state, UPLOAD_METER_ATTR)
        else:
            setattr(app.state, UPLOAD_METER_ATTR, previous)


# ---------------------------------------------------------------------------
# The bucket itself
# ---------------------------------------------------------------------------
def test_the_byte_bucket_refills_at_the_declared_rate() -> None:
    """Driven on an injected clock: a sleeping test is green when the machine is idle."""
    meter = _ByteMeter(capacity=1000, refill_per_second=100.0)
    assert meter.take("caller", 1000, now=0.0) == 0.0
    # Empty. 250 bytes at 100 B/s is 2.5 s, and nothing is spent on refusal.
    assert meter.take("caller", 250, now=0.0) == pytest.approx(2.5)
    assert meter.take("caller", 250, now=2.4) == pytest.approx(0.1, abs=1e-9)
    assert meter.take("caller", 250, now=2.5) == 0.0
    # Refill is capped at the capacity, not accumulated forever.
    assert meter.take("caller", 1000, now=10_000.0) == 0.0
    assert meter.take("caller", 1, now=10_000.0) > 0.0


def test_the_byte_bucket_is_per_caller_and_bounded() -> None:
    """One caller's spending cannot refuse another, and the map cannot grow without bound."""
    meter = _ByteMeter(capacity=100, refill_per_second=1.0, max_keys=4)
    assert meter.take("a", 100, now=0.0) == 0.0
    assert meter.take("a", 100, now=0.0) > 0.0
    assert meter.take("b", 100, now=0.0) == 0.0, "one caller emptied another's bucket"

    for index in range(50):
        meter.take(f"caller-{index}", 1, now=0.0)
    assert meter.tracked() == 4, meter.tracked()
    # Eviction can only ever turn a denied request into an allowed one: the
    # forgotten caller comes back with a full bucket, which is how an unseen
    # caller starts.
    assert meter.take("a", 100, now=0.0) == 0.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"capacity": 0, "refill_per_second": 1.0},
        {"capacity": 10, "refill_per_second": 0.0},
        {"capacity": 10, "refill_per_second": -1.0},
        {"capacity": 10, "refill_per_second": 1.0, "max_keys": 0},
    ],
)
def test_a_meter_that_could_never_refuse_is_refused_at_construction(
    kwargs: dict[str, float]
) -> None:
    """A zero refill is an unsatisfiable budget, not a strict one; say so at build time."""
    with pytest.raises(ValueError):
        _ByteMeter(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# GET /fixtures/{name} -- the shipped demo documents, allow-listed
# ---------------------------------------------------------------------------
#: Every name an attacker would actually send at a route that takes a filename.
#: Each has to be *refused by the allow-list*, which is a stronger claim than "404":
#: a 404 the router produced because the path did not match a segment pattern would
#: leave the allow-list untested, so the assertions below read the refusal's own
#: ``reason`` as well as its status. Sent through :func:`_raw_get` for the same
#: reason -- httpx removes dot segments from a request target before any transport
#: sees it, so a traversal sent through the client tests httpx.
TRAVERSALS = [
    "../../etc/passwd",
    "../fixtures/generator.py",
    "....//....//etc/passwd",
    "/etc/passwd",
    "//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%2f..%2fetc%2fpasswd",
    "%2fetc%2fpasswd",
    "medical_note.txt\x00.png",
    "medical_note.txt\x00",
    "medical_note.txt/../../etc/passwd",
    "medical_note.txt ",
    " medical_note.txt",
    "MEDICAL_NOTE.TXT",
    "medical_note.TXT",
    "generator.py",
    "__init__.py",
    "",
    ".",
    "..",
]


async def _raw_get(app: FastAPI, path: str) -> tuple[int, bytes]:
    """Drive the real ASGI app with a ``scope["path"]`` no URL library would send.

    Middleware, routing, handler and error mapping all run; only the client library
    is removed. That removal is the point: ``httpx`` normalises ``..`` out of a
    request target before the transport is called, so the traversal corpus sent
    through :class:`AsyncClient` would prove something about httpx. A reverse proxy,
    a hand-written socket or a non-conforming client can deliver these paths
    verbatim, and this is what the application does when one arrives.
    """
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: MutableMapping[str, Any]) -> None:
        messages.append(dict(message))

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8", "surrogateescape"),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"scp.test")],
        "client": ("127.0.0.1", 51234),
        "server": ("scp.test", 80),
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return int(status), body


def test_the_fixture_allow_list_is_exactly_what_the_repo_ships() -> None:
    """"Derived from what actually ships" is measured against git, not asserted.

    :data:`DEMO_FIXTURES` is a literal table on purpose -- a runtime glob would serve
    whatever happened to be in the directory -- and the cost of a literal table is
    that it can go stale in either direction. A name deleted from the repo becomes a
    dropdown entry that 404s on the first click; a fixture added to the repo and not
    listed is simply not offered. Both are silent, so both fail here.

    Asked of ``git ls-files`` rather than of the filesystem for the reason the
    ``.gitignore`` incident recorded in ``tests/test_api.py`` established: a file
    present in a working tree and absent from the repository is exactly the failure a
    clean clone hits and a local run cannot see. ``fixtures/generator.py`` and
    ``fixtures/__init__.py`` ship too and must NOT be served, which is what makes the
    ``*.txt`` filter part of the claim rather than a convenience.

    And the third place they have to exist is the image. The Dockerfile builds from an
    explicit allow-list rather than ``COPY . .``, so a directory that is in git and not
    in that list reaches a developer's browser and not a reviewer's container -- the
    exact shape of the ``.gitignore`` incident, mirrored. ``FIXTURES_DIR`` resolves the
    same way ``DEFAULT_REGISTRY_PATH`` does (the package's parent), which is
    ``/app/fixtures`` beside ``/app/entities.yaml`` once that COPY has run.
    """
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY fixtures/ fixtures/" in dockerfile, "the fixtures do not reach the image"
    assert "COPY entities.yaml ./" in dockerfile, (
        "the anchor for the resolution claim moved; FIXTURES_DIR's docstring needs re-reading"
    )

    tracked = subprocess.run(
        ["git", "ls-files", "fixtures/*.txt"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    shipped = {Path(line).name for line in tracked}
    assert shipped, "git ls-files found no fixtures at all -- the query is wrong"
    assert set(DEMO_FIXTURES) == shipped, (set(DEMO_FIXTURES), shipped)
    # Every category is one the store will actually accept, or the preset arms a
    # document under a value POST /documents refuses with INVALID_DOC_CATEGORY.
    assert set(DEMO_FIXTURES.values()) <= set(DOC_CATEGORIES), DEMO_FIXTURES
    # And the two python files that ship in the same directory are not on the list.
    assert not any(name.endswith(".py") for name in DEMO_FIXTURES), DEMO_FIXTURES


@_MODULE_LOOP
async def test_the_endpoint_hands_back_the_shipped_file_byte_for_byte(
    client: AsyncClient,
) -> None:
    """All four, compared against the bytes on disk, with the headers that keep them inert.

    Byte equality is not decoration here: the browser posts what it receives straight
    back to ``POST /documents``, so any transformation on this path -- a re-encode, a
    newline translation, a truncation -- silently makes a preset run a different run
    from the hand-picked one, which is the property this route exists to preserve.

    ``nosniff`` and the response-wide CSP come from ``_SecurityHeaders`` and are
    asserted here rather than taken on trust, because this is the one route that
    returns caller-navigable content from the server's own disk.
    """
    for name, category in DEMO_FIXTURES.items():
        on_disk = (REPO_ROOT / "fixtures" / name).read_bytes()
        response = await client.get(f"/fixtures/{name}")
        assert response.status_code == 200, (name, response.text)
        assert response.content == on_disk, name
        assert response.headers["content-type"] == "text/plain; charset=utf-8", name
        assert response.headers["x-content-type-options"] == "nosniff", name
        assert "default-src 'none'" in response.headers["content-security-policy"], name
        # The category the UI will arm this document under is a real one and the file
        # is not empty, or the preset would meet EMPTY_UPLOAD on the way back in.
        assert category in DOC_CATEGORIES
        assert on_disk, name


@_MODULE_LOOP
@pytest.mark.parametrize("attack", TRAVERSALS)
async def test_no_name_a_caller_can_send_reaches_a_file_off_the_allow_list(
    app: FastAPI, attack: str
) -> None:
    """Traversal, absolute path, encoded traversal and NUL byte, each refused by the list.

    The assertion that matters is not the 404 -- it is *which* 404. A refusal carrying
    ``not_a_shipped_fixture`` came from the allow-list; a bare routing miss would carry
    ``{"status": 404}`` and would mean the allow-list was never consulted, so this
    test would be certifying a control it had not exercised. ``/etc/passwd`` and
    ``fixtures/generator.py`` both exist and are readable by this process, so a route
    that joined the caller's string onto a directory would answer 200 with content
    for at least the traversals; nothing here is a vacuous pass.
    """
    status, body = await _raw_get(app, f"/fixtures/{attack}")
    assert status == 404, (attack, body[:200])
    assert b"root:" not in body, (attack, body[:200])
    assert b"def " not in body, (attack, body[:200])
    payload = json.loads(body)
    assert payload["code"] == "NOT_FOUND", payload
    assert payload["detail"]["reason"] == "not_a_shipped_fixture", (attack, payload)
    # The caller's string is never reflected into the body it gets back.
    assert attack.strip() not in body.decode("utf-8", "replace") or not attack.strip()


@_MODULE_LOOP
async def test_the_allow_listed_name_is_the_positive_control_for_that_corpus(
    app: FastAPI,
) -> None:
    """The refusals above only mean something if the same rig can produce a 200.

    Same :func:`_raw_get`, same scope shape, one name changed. Without this the
    traversal test would pass just as well against a route that answered 404 to
    everything, including a route that did not exist.
    """
    status, body = await _raw_get(app, "/fixtures/medical_note.txt")
    assert status == 200, body[:200]
    assert body == (REPO_ROOT / "fixtures" / "medical_note.txt").read_bytes()


@_MODULE_LOOP
async def test_an_over_long_name_is_bounded_before_it_is_looked_up(app: FastAPI) -> None:
    """The name ceiling is a bound on the request, not the control.

    Stated separately from the corpus above because it answers 422 rather than 404 and
    the difference is worth pinning: the whole traversal corpus is *under* this ceiling
    on purpose, so what refuses those is demonstrably the allow-list. If the ceiling
    ever dropped below them the corpus would start passing for the wrong reason, and
    this is the test that would notice.
    """
    assert MAX_FIXTURE_NAME_LEN >= max(len(a) for a in TRAVERSALS) * 2
    status, body = await _raw_get(app, "/fixtures/" + "a" * (MAX_FIXTURE_NAME_LEN + 1))
    assert status == 422, body[:200]
    payload = json.loads(body)
    assert payload["code"] == "VALIDATION_ERROR", payload
    # Field names and a count. Never the offending string.
    assert payload["detail"] == {"errors": 1, "fields": "path.name"}, payload


def test_the_loader_refuses_a_symlink_planted_under_an_allow_listed_name(
    tmp_path: Path,
) -> None:
    """A link is not the document we shipped, even under a name that is on the list.

    A request cannot create one, so this guards the *directory*: anything that can
    write into ``fixtures/`` -- a build step, a mounted volume, a container escape one
    privilege short of reading the store -- could otherwise turn an allow-listed name
    into a reader for any path the process can open. The positive control in the same
    directory is what makes the refusal a refusal rather than a loader that failed.
    """
    secret = tmp_path / "outside" / "passwd"
    secret.parent.mkdir()
    secret.write_bytes(b"root:x:0:0:")
    directory = tmp_path / "fixtures"
    directory.mkdir()
    (directory / "medical_note.txt").symlink_to(secret)
    (directory / "legal_memo.txt").write_bytes(b"a real one")

    loaded = _load_shipped_fixtures(directory)

    assert "medical_note.txt" not in loaded, "a symlink was followed"
    assert b"root:" not in b"".join(loaded.values())
    assert loaded["legal_memo.txt"] == b"a real one", "positive control: the loader works"


def test_the_loader_refuses_a_symlink_to_a_file_inside_its_own_directory(
    tmp_path: Path,
) -> None:
    """Refused on being a link, not on where the link points.

    The narrower rule -- "reject only what resolves outside" -- reads as equivalent and
    is not: it makes the check depend on the target rather than on the entry, so a link
    whose target is later moved changes what an allow-listed name serves without the
    directory listing changing. Both halves are checked and this pins the stricter one.
    """
    directory = tmp_path / "fixtures"
    directory.mkdir()
    (directory / "real.txt").write_bytes(b"inside")
    (directory / "medical_note.txt").symlink_to(directory / "real.txt")
    assert "medical_note.txt" not in _load_shipped_fixtures(directory)


def test_the_loader_refuses_a_fifo_an_oversize_file_and_bytes_that_are_not_utf8(
    tmp_path: Path,
) -> None:
    """Three ways an allow-listed name can be present and still not be servable.

    A FIFO blocks the process forever on ``read_bytes`` -- an anonymous GET that hangs
    a worker. An oversize file is the one way the resident table can grow after review:
    the name is already approved, only the bytes changed. Non-UTF-8 is the correctness
    guard, not a security one: the browser round-trips this body through text on its
    way back to ``POST /documents``, so bytes that do not survive that would make a
    preset run quietly different from a hand-picked one.
    """
    directory = tmp_path / "fixtures"
    directory.mkdir()
    os.mkfifo(directory / "medical_note.txt")
    (directory / "legal_memo.txt").write_bytes(b"x" * (MAX_FIXTURE_BYTES + 1))
    (directory / "financial_disclosure.txt").write_bytes(b"\xff\xfe not utf-8")
    (directory / "legal_brief_large.txt").write_bytes(b"fine")

    loaded = _load_shipped_fixtures(directory)

    assert set(loaded) == {"legal_brief_large.txt"}, sorted(loaded)
    # And the ceiling is not off by one in the direction that refuses a real fixture.
    (directory / "legal_memo.txt").write_bytes(b"x" * MAX_FIXTURE_BYTES)
    assert "legal_memo.txt" in _load_shipped_fixtures(directory)


def test_a_readable_file_beside_the_fixtures_is_never_loaded(tmp_path: Path) -> None:
    """The gate is the allow-list, not the directory.

    The strongest statement of the property, and the one a later edit would have to
    break on purpose: put a secret in the very directory the loader reads, under a name
    that is not on the list, and it is not loaded -- so nothing a request can say will
    produce it. ``.env`` is the concrete case; the repository's ``.gitignore`` and
    ``.dockerignore`` both name it because it holds ``SCP_MASTER_KEY``, which decrypts
    every document in the store.
    """
    directory = tmp_path / "fixtures"
    directory.mkdir()
    (directory / "medical_note.txt").write_bytes(b"the real one")
    (directory / ".env").write_bytes(b"SCP_MASTER_KEY=hunter2")
    (directory / "generator.py").write_bytes(b"import os")
    (directory / "notes.txt").write_bytes(b"SECRET")

    loaded = _load_shipped_fixtures(directory)

    assert set(loaded) == {"medical_note.txt"}, sorted(loaded)
    joined = b"".join(loaded.values())
    assert b"hunter2" not in joined and b"SECRET" not in joined and b"import os" not in joined


@_MODULE_LOOP
async def test_the_request_path_never_touches_the_filesystem(
    app: FastAPI, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Served from a table built at import, so there is no read for an edit to redirect.

    This is the structural half of "it can never be turned into a general file reader",
    and it is checked rather than argued: every filesystem entry point the handler could
    plausibly acquire is booby-trapped for the duration of one request, and the request
    still answers 200 with the right bytes. A route that read per request -- however
    carefully it validated first -- fails here.

    The corollary a reviewer should take from it: widening this route later means
    *adding* a filesystem call to a handler that has none, which is a visible diff,
    rather than changing which path an existing read is handed, which is not.
    """
    def _explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("the fixture route touched the filesystem")

    monkeypatch.setattr(Path, "read_bytes", _explode)
    monkeypatch.setattr(Path, "read_text", _explode)
    monkeypatch.setattr(Path, "open", _explode)
    monkeypatch.setattr(documents_module, "FIXTURES_DIR", Path("/nonexistent-on-purpose"))

    response = await client.get("/fixtures/medical_note.txt")

    assert response.status_code == 200, response.text
    monkeypatch.undo()
    assert response.content == (REPO_ROOT / "fixtures" / "medical_note.txt").read_bytes()


def test_the_served_table_cannot_be_extended_at_runtime() -> None:
    """A mapping proxy, so nothing can add a fifth entry after the reviewed four.

    Cheap, and it closes the one route back into this table that does not go through
    :func:`_load_shipped_fixtures`: a stray ``FIXTURE_BYTES[name] = data`` anywhere in
    the process -- a debug endpoint, a test helper left in, a plug-in -- would make the
    allow-list a runtime value again.
    """
    assert isinstance(FIXTURE_BYTES, MappingProxyType)
    assert isinstance(DEMO_FIXTURES, MappingProxyType)
    with pytest.raises(TypeError):
        FIXTURE_BYTES["passwd"] = b"root:x:0:0:"  # type: ignore[index]
    with pytest.raises(TypeError):
        DEMO_FIXTURES["passwd"] = "general"  # type: ignore[index]
    assert "passwd" not in FIXTURE_BYTES


@_MODULE_LOOP
async def test_the_fixture_route_takes_no_session_and_can_reach_no_user_data(
    client: AsyncClient,
) -> None:
    """The session decision, pinned in both directions, plus why it is safe.

    **No session, deliberately.** Recorded at the handler and asserted here: an
    anonymous GET with no ``user_id``, no ``X-Session-Id`` and no cookie is served, and
    presenting a bogus session changes nothing -- the route neither requires a session
    nor validates one, so there is no half-state where a reviewer thinks they are
    authenticated.

    The reason that is not a hole is structural rather than a promise, and this is the
    assertion that carries it: the handler's signature takes exactly one parameter, the
    name. It has no ``ServicesDep``, so it cannot reach the encrypted store, the vault,
    the audit log or the registry; there is no ``user_id`` for it to trust and nothing
    behind it that a session would be protecting. Add a services dependency later and
    this fails, which is the moment the session question needs asking again.
    """
    anonymous = await client.get("/fixtures/medical_note.txt")
    assert anonymous.status_code == 200

    with_bogus_session = await client.get(
        "/fixtures/medical_note.txt",
        headers={"X-Session-Id": "not-a-session"},
        params={"user_id": "somebody-else"},
    )
    assert with_bogus_session.status_code == 200
    assert with_bogus_session.content == anonymous.content

    assert list(inspect.signature(get_demo_fixture).parameters) == ["name"]


@_MODULE_LOOP
async def test_a_preset_run_and_a_hand_picked_run_of_one_fixture_detect_identically(
    app: FastAPI, client: AsyncClient
) -> None:
    """The preset does not get its own way into the store, and this is the proof.

    Two round trips over the real app, differing only in where the bytes came from:

    * **preset** -- ``GET /fixtures/medical_note.txt``, then the body decoded and
      re-encoded exactly as a browser does (``res.text()`` into ``new Blob([...])``),
      posted to ``POST /documents`` as multipart;
    * **hand-picked** -- the same file read off disk and posted to the same endpoint,
      which is what the file picker sends.

    Then a full ``POST /pipeline/run`` for each, in one session, and the two detection
    lists are compared span for span. If they ever differ, the preset is a second
    ingestion path wearing the first one's clothes and every claim the demo makes about
    "what the pipeline does to this document" splits in two.

    ``surrogate`` is excluded from the comparison and nothing else is: a token is
    random per span by design, so requiring it to match would pin the obfuscator's
    randomness rather than the detector's determinism. The positive control is the
    length assertion -- an empty detection list would make "identical" vacuous.
    """
    on_disk = (REPO_ROOT / "fixtures" / "medical_note.txt").read_bytes()
    category = DEMO_FIXTURES["medical_note.txt"]

    served = await client.get("/fixtures/medical_note.txt")
    assert served.status_code == 200, served.text
    # The browser's round trip, spelled out: bytes -> text (charset from the header)
    # -> bytes. Asserted rather than assumed, because it is what makes the two uploads
    # comparable at all.
    through_the_browser = served.text.encode("utf-8")
    assert through_the_browser == on_disk

    session = await client.post("/sessions", json={"user_id": "preset-parity"})
    assert session.status_code == 200, session.text
    session_id = session.json()["session_id"]

    runs = {}
    with _byte_meter(app, _generous()):
        for label, payload in (("preset", through_the_browser), ("picked", on_disk)):
            upload = await client.post(
                "/documents",
                files={"file": ("medical_note.txt", payload, "text/plain")},
                data={"user_id": "preset-parity", "doc_category": category},
            )
            assert upload.status_code == 200, (label, upload.text)
            doc_id = upload.json()["doc_id"]
            assert upload.json()["doc_category"] == category

            text = await client.get(
                f"/documents/{doc_id}/text", params={"user_id": "preset-parity"}
            )
            assert text.status_code == 200, (label, text.text)

            run = await client.post(
                "/pipeline/run",
                json={
                    "user_id": "preset-parity",
                    "doc_id": doc_id,
                    "session_id": session_id,
                    "prompt": "Summarize this document and list the key facts.",
                },
            )
            assert run.status_code == 200, (label, run.text)
            runs[label] = (text.json(), run.json())

    preset_text, preset_run = runs["preset"]
    picked_text, picked_run = runs["picked"]

    # Same stored document: the extracted text, its length and its category.
    assert preset_text["text"] == picked_text["text"]
    assert preset_text["chars"] == picked_text["chars"] == len(on_disk.decode("utf-8"))
    assert preset_text["doc_category"] == picked_text["doc_category"] == category

    def spans(result: dict[str, Any]) -> list[tuple[Any, ...]]:
        return [
            (d["entity_type"], d["category"], d["start"], d["end"], d["action"], d["score"])
            for d in result["detections"]
        ]

    # Positive control first: "identical" is worth nothing over two empty lists, and
    # this fixture is the one the README quotes 54 detections for.
    assert len(spans(preset_run)) >= 20, len(spans(preset_run))
    assert spans(preset_run) == spans(picked_run)
    # And the two documents really were stored separately -- otherwise the second run
    # could be reading the first one's row and the comparison would be with itself.
    assert preset_run["run_id"] != picked_run["run_id"]
