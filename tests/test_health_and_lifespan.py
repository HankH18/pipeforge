"""``GET /health`` and the process lifespan (build doc sections 9.9, 12).

Two properties nothing else in the suite pins.

``/health`` has to answer correctly in the two states that leave this process
running but useless -- the spaCy pipeline failed to load, or the audit database
is gone. Both are *reported* rather than fatal, which is the whole point of the
endpoint: a container that refuses to start tells an operator nothing about why.

``_build_services`` has to be **transactional**. It opens three aiosqlite
connections in sequence, and aiosqlite's worker threads are not daemons, so a
startup that opens two and dies on the third leaves threads that keep the
interpreter alive: the failing container hangs instead of reporting its failure.
Each stage is failed in turn here and the unwind is checked against the live
``aiosqlite.Connection`` *threads* -- the thing that actually holds the process
open -- rather than against any internal flag.

Every failure here is placed with a thin ``_Stage`` shim rather than a fake. All
three resource classes in ``secure_context_pipeline.api.lifespan`` --
``AuditLogger``, ``EncryptedDocumentStore``, ``SessionVault`` -- are wrapped on
every run, because the assertions need a handle on whatever actually opened;
exactly one shim is armed to raise and every other one calls straight through to
the real class. The provider stage replaces a fourth name, ``build_provider``,
which is a function rather than a class. So the connections that do get opened
are real aiosqlite connections and the closers the unwind runs are the real bound
``close`` methods -- the leak this file is about is not something the harness can
fake away. The one genuine stub is the spaCy warm-up (the ``no_model`` fixture):
it costs tens of seconds, it runs before the first connection exists, and no
unwind test analyses a document.

That paragraph used to read "by patching exactly one name ... nothing else is
faked", which measured as three names on every run, four on the provider run, and
``warm_up`` on top. Overstating how little a harness fakes changes what its green
means, so ``test_this_docstring_matches_the_harness`` now pins the prose to the
measurement.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import aiosqlite
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from secure_context_pipeline.api import lifespan as lifespan_module
from secure_context_pipeline.api.app import create_app
from secure_context_pipeline.audit.logger import AuditLogger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.detection.detector import warm_up as real_warm_up
from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.models import EntityCategory, TokenRecord
from secure_context_pipeline.store.document_store import EncryptedDocumentStore
from secure_context_pipeline.vault.session_registry import SessionRegistry
from secure_context_pipeline.vault.session_vault import SessionVault

# The healthy app is module-scoped (spaCy costs tens of seconds), so every test
# in the file shares one event loop -- aiosqlite connections and asyncio.Lock
# instances bind to the loop that first uses them.
pytestmark = pytest.mark.asyncio(loop_scope="module")

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "entities.yaml"

OWNER = "alice"

#: Startup opens these three, in this order. The index of the failing stage is
#: therefore how many connections must be unwound.
STAGES = ("audit", "store", "vault", "provider")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def ok_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Settings for the one fully healthy app, in its own data directory."""
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("health-data"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def ok_app(ok_settings: Settings) -> FastAPI:
    return create_app(ok_settings)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def ok_client(ok_app: FastAPI) -> AsyncIterator[AsyncClient]:
    """``ASGITransport`` does not run lifespan events, so it is entered here."""
    async with ok_app.router.lifespan_context(ok_app):
        transport = ASGITransport(app=ok_app)
        async with AsyncClient(transport=transport, base_url="http://scp.test") as http:
            yield http


@contextlib.asynccontextmanager
async def _running(settings: Settings) -> AsyncIterator[tuple[FastAPI, AsyncClient]]:
    """A throwaway app with its lifespan actually entered, and a client for it."""
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://scp.test") as http:
            yield app, http


def _live_connection_threads() -> frozenset[threading.Thread]:
    """Every aiosqlite worker thread currently alive.

    ``aiosqlite.Connection`` is a ``Thread`` and is not a daemon, so each live
    one keeps the interpreter from exiting. This is the observable the whole
    unwind argument rests on.
    """
    return frozenset(t for t in threading.enumerate() if isinstance(t, aiosqlite.Connection))


async def _leaked_since(baseline: frozenset[threading.Thread]) -> frozenset[threading.Thread]:
    """Connection threads alive now that were not alive at ``baseline``.

    ``close()`` hands the worker a stop sentinel and returns before the thread
    has necessarily finished, so this waits briefly for the unwind to land. With
    a correct unwind it settles in milliseconds; with a leak it never does.
    """
    deadline = time.monotonic() + 5.0
    leaked = _live_connection_threads() - baseline
    while leaked and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
        leaked = _live_connection_threads() - baseline
    return leaked


class _Stage:
    """Stands in for one of the lifespan's resource classes.

    Either opens the real thing and records the instance, or refuses to open at
    all -- which is how a startup failure is placed at an exact stage.
    """

    def __init__(
        self,
        real: Any,
        opened: list[Any],
        *,
        failure: BaseException | None = None,
    ) -> None:
        self._real = real
        self._opened = opened
        self._failure = failure

    async def open(self, *args: Any, **kwargs: Any) -> Any:
        if self._failure is not None:
            raise self._failure
        resource = await self._real.open(*args, **kwargs)
        self._opened.append(resource)
        return resource


def _fails_with(error: BaseException) -> Callable[..., Any]:
    def _fail(*args: Any, **kwargs: Any) -> Any:
        raise error

    return _fail


def _stage_the_failure(
    monkeypatch: pytest.MonkeyPatch, failing_stage: str, opened: list[Any], error: BaseException
) -> None:
    """Make ``failing_stage`` raise ``error``; let the earlier stages open for real."""
    for name, real in (
        ("audit", AuditLogger),
        ("store", EncryptedDocumentStore),
        ("vault", SessionVault),
    ):
        monkeypatch.setattr(
            lifespan_module,
            real.__name__,
            _Stage(real, opened, failure=error if name == failing_stage else None),
        )
    if failing_stage == "provider":
        monkeypatch.setattr(lifespan_module, "build_provider", _fails_with(error))


def _names_replaced_in_lifespan(failing_stage: str) -> frozenset[str]:
    """Which attributes of the lifespan module ``_stage_the_failure`` replaces.

    Measured by diffing the module namespace across a real ``MonkeyPatch``
    context rather than by reading the helper's source, so a patch someone adds
    later is counted whether or not the paragraph at the top of this file gets
    updated with it.
    """
    before = {name: getattr(lifespan_module, name) for name in dir(lifespan_module)}
    with pytest.MonkeyPatch.context() as patcher:
        _stage_the_failure(patcher, failing_stage, [], RuntimeError("never raised: nothing runs"))
        return frozenset(
            name
            for name, original in before.items()
            if getattr(lifespan_module, name) is not original
        )


@pytest.fixture
def no_model(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Skip the spaCy warm-up. The unwind tests never analyse a document."""
    monkeypatch.setattr(lifespan_module, "warm_up", lambda _settings: None)
    yield


def _vault_row_count(db_path: Path) -> int:
    """Rows on disk, read with the stdlib driver rather than through the vault."""
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT count(*) FROM vault_entries").fetchone()[0])
    finally:
        conn.close()


async def _assert_closed(opened: list[Any]) -> None:
    """Every resource the failed startup did open must refuse to serve."""
    for resource in opened:
        if isinstance(resource, AuditLogger):
            with pytest.raises(PipelineError) as audit_closed:
                await resource.length()
            assert audit_closed.value.detail["reason"] == "audit_logger_not_open"
        elif isinstance(resource, SessionVault):
            with pytest.raises(PipelineError) as vault_closed:
                await resource.row_count("no-such-session")
            assert vault_closed.value.detail["reason"] == "vault_closed"


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------
async def test_health_reports_the_running_configuration_and_a_session_count(
    ok_client: AsyncClient, ok_settings: Settings
) -> None:
    """A healthy process answers 200 with what it is actually running, and with a
    *count* of live sessions -- never an ID, which is the bearer credential for
    an irreversible erasure."""
    first = await ok_client.get("/health")
    assert first.status_code == 200, first.text
    assert first.json() == {
        "status": "ok",
        "model_loaded": True,
        "db_reachable": True,
        "spacy_model": ok_settings.spacy_model,
        "llm_provider": "mock",
        "llm_model": ok_settings.llm_model,
        "strategy": ok_settings.strategy,
        # The factory mounts ui/ and the lifespan is told the outcome; the report
        # has to match reality, not a constant.
        "ui_mounted": True,
        "active_sessions": 0,
    }
    assert (await ok_client.get("/")).status_code == 200

    created = []
    for _ in range(3):
        response = await ok_client.post("/sessions", json={"user_id": OWNER})
        assert response.status_code == 200, response.text
        created.append(response.json()["session_id"])

    populated = await ok_client.get("/health")
    assert populated.json()["active_sessions"] == 3
    for session_id in created:
        assert session_id not in populated.text

    logout = await ok_client.delete(f"/sessions/{created[0]}", params={"user_id": OWNER})
    assert logout.status_code == 204, logout.text
    assert (await ok_client.get("/health")).json()["active_sessions"] == 2


async def test_health_reports_a_missing_model_instead_of_refusing_to_boot(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spaCy failure must leave the app *startable* and the fault reportable:
    the lifespan completes, and /health answers 503 degraded with
    ``model_loaded`` false. A container that will not start says nothing about
    why it will not start."""
    monkeypatch.setattr(
        lifespan_module,
        "warm_up",
        _fails_with(RuntimeError("en_core_web_lg is not installed")),
    )

    async with _running(settings) as (app, client):
        assert app.state.services is not None, "the lifespan refused to boot"
        response = await client.get("/health")

    assert response.status_code == 503, response.text
    body = response.json()
    assert body["status"] == "degraded"
    assert body["model_loaded"] is False
    # The other half is genuinely fine, and the report has to say so.
    assert body["db_reachable"] is True
    assert body["spacy_model"] == settings.spacy_model


async def test_health_reports_degraded_when_the_audit_database_is_unreachable(
    settings: Settings,
) -> None:
    """The second running-but-useless state, produced for real by dropping the
    audit connection rather than by patching a flag: /health must probe the
    database live and answer 503 degraded, not raise its way to a 500."""
    async with _running(settings) as (app, client):
        assert (await client.get("/health")).status_code == 200
        await app.state.services.audit.close()

        response = await client.get("/health")
        body = response.json()

    assert response.status_code == 503, response.text
    assert body["status"] == "degraded"
    assert body["db_reachable"] is False
    assert body["model_loaded"] is True


# ---------------------------------------------------------------------------
# Transactional startup
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("no_model")
# Awaits nothing, but the file-wide ``pytestmark`` marks every test asyncio and
# pytest-asyncio warns on a sync function carrying that mark.
async def test_this_docstring_matches_the_harness() -> None:
    """The paragraph at the top of this file is what a reviewer reads instead of
    re-deriving the harness, and it was wrong: it said each failure is forced "by
    patching exactly one name ... nothing else is faked" while
    ``_stage_the_failure`` replaced three names on every run and four on the
    provider run, with ``no_model`` stubbing ``warm_up`` besides. A claim that
    overstates how little a harness fakes changes what its green run means, so
    the prose is pinned here: every name the harness replaces has to be measured
    and then named in the docstring.
    """
    shimmed = frozenset({"AuditLogger", "EncryptedDocumentStore", "SessionVault"})
    assert {stage: _names_replaced_in_lifespan(stage) for stage in STAGES} == {
        "audit": shimmed,
        "store": shimmed,
        "vault": shimmed,
        "provider": shimmed | {"build_provider"},
    }

    # The fake the old wording missed entirely: `no_model` is active for every
    # unwind test in this section.
    assert lifespan_module.warm_up is not real_warm_up, (
        "the no_model fixture no longer stubs the warm-up, so the docstring is stale again"
    )

    doc = __doc__ or ""
    for faked in sorted(shimmed | {"build_provider", "warm_up"}):
        assert faked in doc, f"the harness replaces {faked} and the docstring does not say so"


@pytest.mark.parametrize("failing_stage", STAGES)
@pytest.mark.usefixtures("no_model")
async def test_a_failed_startup_closes_every_connection_it_had_already_opened(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, failing_stage: str
) -> None:
    """Startup is transactional at every stage. A failure at any one of the four
    must leave zero live aiosqlite worker threads behind -- they are not daemons,
    so a single leaked one turns a reportable boot failure into a hung process."""
    opened: list[Any] = []
    boom = RuntimeError(f"{failing_stage} could not be opened")
    _stage_the_failure(monkeypatch, failing_stage, opened, boom)

    baseline = _live_connection_threads()
    with pytest.raises(RuntimeError) as raised:
        await lifespan_module._build_services(settings)

    assert raised.value is boom, "the original failure must reach the caller"
    assert len(opened) == STAGES.index(failing_stage), (
        "startup did not fail at the stage this test placed the failure in"
    )
    assert await _leaked_since(baseline) == frozenset(), (
        f"a failure at the {failing_stage} stage leaked an aiosqlite worker thread"
    )
    await _assert_closed(opened)


@pytest.mark.usefixtures("no_model")
async def test_a_cancelled_startup_unwinds_as_well(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unwind catches ``BaseException``, not ``Exception``. A startup
    cancelled after its three connections are open must still close them:
    ``CancelledError`` is not an ``Exception``, so catching the narrower class
    would let a cancelled boot leak all three worker threads."""
    opened: list[Any] = []
    cancelled = asyncio.CancelledError()
    _stage_the_failure(monkeypatch, "provider", opened, cancelled)

    baseline = _live_connection_threads()
    with pytest.raises(asyncio.CancelledError):
        await lifespan_module._build_services(settings)

    assert len(opened) == 3, "the cancellation did not land after all three opens"
    assert await _leaked_since(baseline) == frozenset(), (
        "a cancelled startup leaked an aiosqlite worker thread"
    )
    await _assert_closed(opened)


@pytest.mark.usefixtures("no_model")
async def test_shutdown_closes_the_rest_when_one_close_raises(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Shutdown is best-effort: a connection that is already gone must not stop
    the next one from being released, and the failure must be logged rather than
    swallowed silently. The store is closed first, so if its refusal aborted the
    loop the vault and the audit log would both survive the shutdown."""
    baseline = _live_connection_threads()
    services = await lifespan_module._build_services(settings)
    try:
        monkeypatch.setattr(
            type(services.store), "close", _fails_with(OSError("the volume went away"))
        )

        with caplog.at_level(logging.ERROR, logger=lifespan_module.__name__):
            await lifespan_module._shutdown(services)

        reported = [
            record
            for record in caplog.records
            if record.name == lifespan_module.__name__ and record.levelno >= logging.ERROR
        ]
        assert [record.message for record in reported] == ["error closing a resource"], (
            "the failing close was not reported exactly once"
        )
        assert reported[0].exc_info is not None, "the traceback was dropped"
        await _assert_closed([services.vault, services.audit])
    finally:
        # The store is the one this test broke; release it for real, even on a
        # failed assertion, so no non-daemon worker thread outlives the file.
        monkeypatch.undo()
        await services.store.close()

    assert await _leaked_since(baseline) == frozenset()


@pytest.mark.usefixtures("no_model")
async def test_startup_sweeps_orphan_vault_rows_and_stranded_blobs(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """Both startup sweeps have to actually run, and report what they removed.

    Session keys die with the process, so vault rows from a previous run are
    undecryptable garbage that also makes a dead session ID look live; a blob
    with no metadata row is disk nothing will ever free. What must *not* go is
    anything the sweeps cannot vouch for -- a blob young enough to be a live
    upload, or a filename they cannot parse.
    """
    data_dir = Path(settings.data_dir)
    blobs = data_dir / "documents"
    blobs.mkdir(parents=True)
    stale = time.time() - 3600.0

    stranded = blobs / f"{uuid.uuid4().hex}.raw"
    stranded.write_bytes(b"ciphertext no doc_id can reach")
    os.utime(stranded, (stale, stale))

    # Young enough to be an upload that is between its blob write and its commit.
    mid_upload = blobs / f"{uuid.uuid4().hex}.txt"
    mid_upload.write_bytes(b"a live put, mid-flight")

    # Old, but not a name this store issued: deleting from a shared directory
    # needs more than "I do not recognise this".
    foreign = blobs / "operator-notes.txt"
    foreign.write_bytes(b"not ours")
    os.utime(foreign, (stale, stale))

    previous_run = SessionRegistry(settings)
    dead_session, _ = await previous_run.create("startup-user")
    vault = await SessionVault.open(data_dir / "vault.db", previous_run)
    try:
        for token_id, entity_type, value in (
            ("a1b2c3d4", "PATIENT_NAME", "Jordan Alvarez"),
            ("b2c3d4e5", "MRN", "9224297"),
        ):
            await vault.put(
                dead_session,
                TokenRecord(
                    session_id=dead_session,
                    token_id=token_id,
                    entity_type=entity_type,
                    category=EntityCategory.PHI,
                    surrogate=f"[PHI_{entity_type}_{token_id}]",
                    created_at=time.time(),
                ),
                value,
            )
    finally:
        # This stands in for the *previous* process; leaving its non-daemon
        # worker thread alive would hang interpreter exit for the whole file.
        await vault.close()
    assert _vault_row_count(data_dir / "vault.db") == 2, "the fixture rows were not written"

    with caplog.at_level(logging.INFO, logger=lifespan_module.__name__):
        async with _running(settings) as (_, client):
            assert (await client.get("/health")).status_code == 200

    assert _vault_row_count(data_dir / "vault.db") == 0, (
        "rows from a session no live key can decrypt survived startup"
    )
    assert not stranded.exists(), "the stranded blob survived startup"
    assert mid_upload.exists(), "the sweep deleted a blob young enough to be a live upload"
    assert foreign.exists(), "the sweep deleted a file whose name it cannot parse"

    ready = [record for record in caplog.records if record.message == "pipeline ready"]
    assert len(ready) == 1
    assert ready[0].orphan_rows_swept == 2
    assert ready[0].orphan_blobs_swept == 1
