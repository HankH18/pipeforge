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
import secrets
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from pathlib import Path

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
from secure_context_pipeline.api.routes.documents import (
    UPLOAD_BYTES_BURST,
    UPLOAD_BYTES_REFILL_PER_SECOND,
    UPLOAD_METER_ATTR,
    _ByteMeter,
)
from secure_context_pipeline.config import Settings

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
