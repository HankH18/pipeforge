"""API layer tests (build doc section 10.8).

Everything here runs against the **real** pipeline -- real detector, real
obfuscation engine, real egress gate, real encrypted store, real hash-chained
audit log -- through :class:`httpx.ASGITransport` rather than a live server.
Only the LLM is a mock, and that is a project-wide invariant (build doc section
10): the suite must pass with no API key and no network.

Two structural notes:

* **The app is built once for the module.** Constructing a ``Detector`` loads
  spaCy ``en_core_web_lg``, which costs tens of seconds. A per-test app would
  make this file the slowest thing in the suite for no added coverage.
* **The lifespan is driven explicitly.** ``ASGITransport`` does not run
  lifespan events, so ``app.router.lifespan_context`` is entered by the fixture.
  That is the point: the whole file would be testing a half-built app otherwise,
  and every startup-only guarantee (model warm-up, orphan sweep) would go
  unexercised. Because the module-scoped services own event-loop-bound locks and
  SQLite connections, every test in the file shares one loop
  (``loop_scope="module"``).

Tests share the audit database on purpose -- it is append-only and global, which
is what makes the chain verifiable -- so each test scopes its assertions by its
own ``session_id`` or ``run_id``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import fnmatch
import importlib.metadata
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import pytest_asyncio
from fastapi import FastAPI, UploadFile
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from packaging.requirements import Requirement

from secure_context_pipeline.api import app as app_module
from secure_context_pipeline.api.app import (
    DEFAULT_AUDIT_PAGE,
    MAX_AUDIT_PAGE,
    MAX_BODY_BYTES,
    MAX_UPLOAD_BYTES,
    UPLOAD_CHUNK_BYTES,
    ApiError,
    Services,
    _read_capped,
    create_app,
)
from secure_context_pipeline.api.constants import MAX_REAP_PER_REQUEST, UI_DIRNAME
from secure_context_pipeline.api.deps import (
    MAX_REAP_ATTEMPTS,
    _enqueue_for_reaping,
    reap_expired_sessions,
)
from secure_context_pipeline.api.errors import EXTRA_FIELD_MARKER
from secure_context_pipeline.api.routes.audit import MAX_AUDIT_OFFSET
from secure_context_pipeline.api.routes.documents import DEMO_FIXTURES, FIXTURES_DIR
from secure_context_pipeline.api.schemas import MAX_ID_LEN
from secure_context_pipeline.audit.logger import (
    DETECT,
    EGRESS_PASS,
    LLM_CALL,
    SESSION_CREATE,
)
from secure_context_pipeline.config import DEFAULT_REGISTRY_PATH, PACKAGE_ROOT, Settings
from secure_context_pipeline.detection.registry import GAZETTEER_DIR
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
    UNREADABLE_AUDIT_REMEDY,
    PipelineError,
    SessionExpiredError,
)
from secure_context_pipeline.models import AuditEvent, TokenRecord

# Every test in this module runs on one event loop, shared with the module-scoped
# client fixture. aiosqlite connections and asyncio.Lock instances built during
# the lifespan bind to the loop that first uses them.
pytestmark = pytest.mark.asyncio(loop_scope="module")

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "entities.yaml"

OWNER = "alice"
INTRUDER = "mallory"

#: Deliberately small and unambiguous: one occurrence of each entity, no value
#: that is a substring of another. A larger document would test the detector,
#: which ``tests/test_detection.py`` already does; this file tests the HTTP layer.
DOC_TEXT = """CLINIC INTAKE RECORD

Patient name: David Ochoa.

Date of birth: 04/13/1956.

MRN: 9224297.

Phone: (704) 555-0151.

Reason for visit: routine follow-up.
"""

#: Values that must never appear in an outbound payload, an error body, or the
#: audit log -- but must all come back in ``restored_text``.
ORIGINALS = ("David Ochoa", "9224297", "(704) 555-0151")

PROMPT = "Summarise this record in two sentences."


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def api_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Settings pointed at a throwaway data directory, isolated from other tests."""
    return Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path_factory.mktemp("api-data"),
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )


@pytest.fixture(scope="module")
def app(api_settings: Settings) -> FastAPI:
    return create_app(api_settings)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """One client, one app, one lifespan, one event loop for the whole module."""
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://scp.test") as http:
            yield http


@pytest.fixture
def services(app: FastAPI, client: AsyncClient) -> Services:
    """The live :class:`Services`. Depends on ``client`` so the lifespan has run."""
    built = app.state.services
    assert isinstance(built, Services)
    return built


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _create_session(client: AsyncClient, user_id: str = OWNER) -> str:
    response = await client.post("/sessions", json={"user_id": user_id})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expires_at"] > 0
    session_id: str = body["session_id"]
    return session_id


async def _upload(
    client: AsyncClient,
    user_id: str = OWNER,
    *,
    text: str = DOC_TEXT,
    filename: str = "intake.txt",
    category: str | None = "medical",
) -> str:
    data = {"user_id": user_id}
    if category is not None:
        data["doc_category"] = category
    response = await client.post(
        "/documents",
        files={"file": (filename, text.encode("utf-8"), "text/plain")},
        data=data,
    )
    assert response.status_code == 200, response.text
    doc_id: str = response.json()["doc_id"]
    return doc_id


async def _run(
    client: AsyncClient,
    session_id: str,
    doc_id: str,
    *,
    user_id: str = OWNER,
    prompt: str = PROMPT,
    strategy: str | None = None,
    use_header: bool = False,
) -> Any:
    payload: dict[str, Any] = {"user_id": user_id, "doc_id": doc_id, "prompt": prompt}
    headers: dict[str, str] = {}
    if use_header:
        headers["X-Session-Id"] = session_id
    else:
        payload["session_id"] = session_id
    if strategy is not None:
        payload["strategy"] = strategy
    return await client.post("/pipeline/run", json=payload, headers=headers)


# ---------------------------------------------------------------------------
# 1. Full session lifecycle
# ---------------------------------------------------------------------------
async def test_session_lifecycle_create_upload_run_delete(client: AsyncClient) -> None:
    """create -> upload -> run -> delete, and the session is dead afterwards."""
    session_id = await _create_session(client)
    doc_id = await _upload(client)

    run = await _run(client, session_id, doc_id)
    assert run.status_code == 200, run.text
    assert run.json()["run_id"]

    logout = await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})
    assert logout.status_code == 204
    assert logout.content == b""

    # The key is gone, so the session is indistinguishable from one that never
    # existed -- a second run must be refused, not merely fail to restore.
    after = await _run(client, session_id, doc_id)
    assert after.status_code == 401
    assert after.json()["code"] == "SESSION_EXPIRED"

    # Logout is idempotent and oracle-free: deleting again is still 204.
    assert (
        await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})
    ).status_code == 204


async def test_session_accepted_via_x_session_id_header(client: AsyncClient) -> None:
    """The session may arrive in the header instead of the body (section 9.9)."""
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run = await _run(client, session_id, doc_id, use_header=True)
    assert run.status_code == 200, run.text
    assert run.json()["run_id"]


# ---------------------------------------------------------------------------
# 2. A run returns a well-formed PipelineResult
# ---------------------------------------------------------------------------
async def test_run_returns_well_formed_pipeline_result(client: AsyncClient) -> None:
    session_id = await _create_session(client)
    doc_id = await _upload(client)

    response = await _run(client, session_id, doc_id, strategy="tokenization")
    assert response.status_code == 200, response.text
    result = response.json()

    for field in (
        "run_id",
        "restored_text",
        "obfuscated_payload",
        "raw_llm_response",
        "strategy",
        "detections",
        "stats",
        "audit_seq",
    ):
        assert field in result, field

    assert len(result["run_id"]) == 32
    assert result["strategy"] == "tokenization"
    assert result["detections"], "the intake record must yield at least one detection"
    assert result["stats"]["entities_detected"] >= 1
    for key in ("detect_ms", "obfuscate_ms", "egress_ms", "llm_ms", "restore_ms", "total_ms"):
        assert key in result["stats"], key
    assert result["audit_seq"], "the run must have emitted audit events"

    # SpanOut is the API-safe shape: offsets and an action, never the value.
    for span in result["detections"]:
        assert set(span) <= {
            "entity_type",
            "category",
            "start",
            "end",
            "score",
            "action",
            "surrogate",
        }
        assert "text" not in span

    # The point of the whole system, asserted at the HTTP boundary: nothing
    # original crosses the provider boundary, and everything original comes back.
    for original in ORIGINALS:
        assert original not in result["obfuscated_payload"], original
        assert original not in result["raw_llm_response"], original
        assert original in result["restored_text"], original


async def test_strategy_field_reaches_the_engine(client: AsyncClient) -> None:
    """``strategy`` is not merely echoed: the two modes produce different payloads.

    Tokenization emits opaque ``[PII_NAME_...]`` placeholders; pseudonymization
    emits realistic fakes and therefore none. Both must still restore.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)

    pseudo = await _run(client, session_id, doc_id, strategy="pseudonymization")
    assert pseudo.status_code == 200, pseudo.text
    result = pseudo.json()

    assert result["strategy"] == "pseudonymization"
    assert "[PII_NAME_" not in result["obfuscated_payload"]
    for original in ORIGINALS:
        assert original not in result["obfuscated_payload"], original

    # The mock echoes only the most salient input lines, so which originals come
    # back depends on the response -- but every surrogate it *did* echo must have
    # been reversed. A pseudonym surviving into the answer would be a silent leak
    # of a fake presented as fact.
    surrogates = [span["surrogate"] for span in result["detections"] if span["surrogate"]]
    assert surrogates
    for surrogate in surrogates:
        assert surrogate not in result["restored_text"], surrogate
    assert result["stats"]["restored_count"] >= 1


# ---------------------------------------------------------------------------
# 3. Egress block surfaces as 422
# ---------------------------------------------------------------------------
async def test_egress_block_surfaces_as_422(
    client: AsyncClient, services: Services, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A value the detector never saw is planted in the vault's originals set.

    That is the adversarial case from build doc section 10.5 expressed at the
    API: the gate must block on an original it was told about even though no
    recogniser produced it, and the failure must reach the client as a loud,
    structured 422 -- with no trace of the value itself.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    planted = "ZQXPLANTEDSECRETVALUE"

    monkeypatch.setattr(
        services.vault,
        "originals_for_session",
        lambda _session_id: frozenset({planted}),
    )

    response = await _run(client, session_id, doc_id, prompt=f"Summarise {planted} briefly.")
    assert response.status_code == 422, response.text

    body = response.json()
    assert body["code"] == "EGRESS_BLOCKED"
    assert body["detail"]["reason"] == "vault_original"
    assert body["detail"]["hit_count"] >= 1

    # The error body describes the block; it never quotes what was blocked.
    assert planted not in response.text
    for original in ORIGINALS:
        assert original not in response.text

    # ... and the block is on the record, still without the value.
    audit = await client.get("/audit", params={"session_id": session_id, "user_id": OWNER})
    assert audit.status_code == 200
    event_types = {event["event_type"] for event in audit.json()["events"]}
    assert "EGRESS_BLOCK" in event_types
    assert LLM_CALL not in event_types, "the provider must never have been called"
    assert planted not in audit.text


# ---------------------------------------------------------------------------
# 3b. A corrupt audit log surfaces as 503, not as a bare 500
# ---------------------------------------------------------------------------
def _wreck_every_page_but_the_header(path: Path) -> None:
    """Garbage every page of a real SQLite file except page 1, keeping its length.

    The length is the trick that gets past ``open``: the header records the
    database size in pages, so a *short* file is rejected outright while a
    full-length file whose data pages are dead is opened happily and fails only
    when something reads one. Page 1 survives because that is where the schema
    lives -- ``open`` runs ``CREATE TABLE IF NOT EXISTS`` and has to parse it.
    ``PRAGMA integrity_check`` on the result raises ``database disk image is
    malformed``, which is what the demo's own ``data/audit.db`` reported.

    ``tests/test_audit.py`` zeroes a *single* page, which is the lighter and more
    interesting corruption there. It is not deterministic enough here: this log
    holds nine rows, so its table is one b-tree leaf, and a run that appends to
    that leaf can fail while a filtered ``SELECT`` served from an index still
    succeeds -- measured, and it is why the ``GET /audit`` half of this test read
    ``200`` against a database the same request's writer could not use.
    """
    data = bytearray(path.read_bytes())
    page = 4096
    assert len(data) >= 2 * page, "database is too small for this corruption to be meaningful"
    for start in range(page, len(data), page):
        data[start : start + page] = (b"\xde\xad\xbe\xef" * (page // 4))[: len(data) - start]
    path.write_bytes(bytes(data))


async def test_a_corrupt_audit_log_refuses_the_run_as_a_typed_503(tmp_path: Path) -> None:
    """The reported defect, at the boundary a reviewer actually sees.

    Reproduced against the running demo first: with ``data/audit.db`` corrupt (its
    ``PRAGMA integrity_check`` reporting ``Tree 2 page 2 cell 0: invalid page``),
    ``AuditLogger.emit`` let ``sqlite3.DatabaseError`` escape to the ASGI layer and
    ``POST /pipeline/run`` answered **``500``, ``content-type: text/plain``, body
    ``Internal Server Error``, and no security headers at all** -- no CSP, no
    ``nosniff`` -- because Starlette renders an unhandled exception outside the
    middleware that adds them. Three defects in one response: no ``code`` to branch
    on, an admission that an exception reached the framework, and a shape
    indistinguishable from a bug in the pipeline.

    This drives the whole thing for real: a fresh app on its own data directory, a
    healthy run first, then the live ``audit.db`` physically wrecked on disk and the
    same request repeated. Nothing is monkeypatched -- no patched ``emit``,
    no injected raise -- so what is asserted is the behaviour of the shipped code on
    a file SQLite genuinely cannot read.

    ``raise_app_exceptions`` is left at its default ``True``, which is load-bearing:
    if anything still escapes unhandled, this test *errors* with that exception
    instead of reading a status code off a Starlette-generated 500. The old
    behaviour cannot pass this test by accident.

    The run must still be **refused** -- "no release without a record", pinned by
    ``integration/test_pipeline.py::test_no_release_survives_an_audit_write_that_failed_before_it``
    -- so the provider call count is asserted unchanged across the refused run.
    Only the shape of the refusal changed.
    """
    settings = Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        # Its own directory. The module-scoped app's audit.db is shared by every
        # other test in this file, and this test destroys the one it points at.
        data_dir=tmp_path / "corrupt-audit-data",
        registry_path=REGISTRY_PATH,
        llm_provider="mock",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        services = app.state.services
        assert isinstance(services, Services)

        provider_calls = 0
        real_complete = services.orchestrator._provider.complete_detailed

        async def counting(*args: Any, **kwargs: Any) -> Any:
            nonlocal provider_calls
            provider_calls += 1
            return await real_complete(*args, **kwargs)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://scp.test") as http:
            with mock.patch.object(
                services.orchestrator._provider, "complete_detailed", counting
            ):
                session_id = await _create_session(http)
                doc_id = await _upload(http)

                # Control: the identical request succeeds on a healthy log. Without
                # it the 503 below could come from a broken fixture.
                healthy = await _run(http, session_id, doc_id)
                assert healthy.status_code == 200, healthy.text
                assert provider_calls == 1, "premise: a healthy run reaches the provider"

                # Corrupt the log under the live app. Closed and reopened rather
                # than written behind SQLite's back, so the page cache cannot mask
                # it and the test is deterministic: that is the same file the next
                # request opens, and the demo's own restart-after-corruption case.
                await services.audit.close()
                _wreck_every_page_but_the_header(settings.data_dir / "audit.db")
                async with services.audit:
                    refused = await _run(http, session_id, doc_id)
                    reader = await http.get(
                        "/audit", params={"session_id": session_id, "user_id": OWNER}
                    )

    # FIRST, before anything about the shape of the answer: the run was refused
    # before the payload was sent. Measured to bite -- replacing the writer's raise
    # with "log it and carry on", which is what a resilient-looking audit sink
    # invites, still answers 503 (the run dies later, reading its own seq list back)
    # but the provider has been called by then: 2, not 1, with no record of it.
    assert provider_calls == 1, "the refused run must not have reached the provider"

    assert refused.status_code == 503, refused.text
    assert refused.headers["content-type"].startswith("application/json")
    body = refused.json()
    assert body["code"] == "AUDIT_UNAVAILABLE"
    assert body["detail"]["reason"] == "audit_log_unreadable"
    # ``emit``, not ``query``: the refusal has to come from the WRITE, which is the
    # one that happens before the provider call. See the measurement above.
    assert body["detail"]["operation"] == "emit", "the write path is what refused the run"
    assert body["detail"]["audit_db"] == "audit.db"
    assert body["detail"]["error"] == "DatabaseError"
    assert body["detail"]["remedy"] == UNREADABLE_AUDIT_REMEDY
    # ...and, independently of that constant, the remedy has to be something a
    # reviewer can DO. Comparing an imported constant to itself would pass against
    # `remedy: ""`; these words are typed out here on purpose so that the check does
    # not share its answer with the code it is checking.
    remedy = str(body["detail"]["remedy"])
    assert "restore" in remedy and "data directory" in remedy, remedy

    # The old answer, gone: no free-text 500 body, and no unhandled-exception smell.
    assert "Internal Server Error" not in refused.text
    # An error body is not a place to describe the server's filesystem. The file
    # NAME is what an operator acts on; the path is theirs to know already.
    assert str(settings.data_dir) not in refused.text

    # The bare 500 carried none of these, because ServerErrorMiddleware sits
    # outside the middleware that adds them. A typed refusal is a normal response
    # and gets the same hardening as every other one.
    assert refused.headers["x-content-type-options"] == "nosniff"
    csp = refused.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp

    # The reader half of the same file, at the same boundary: ``GET /audit`` answers
    # the same code rather than a generic 500, and names the call that failed.
    assert reader.status_code == 503, reader.text
    assert reader.json()["code"] == "AUDIT_UNAVAILABLE"
    assert reader.json()["detail"]["operation"] == "query"


# ---------------------------------------------------------------------------
# 4. Expired / unknown / missing session => 401
# ---------------------------------------------------------------------------
async def test_expired_session_is_401(client: AsyncClient, services: Services) -> None:
    """Expired, unknown and missing are one answer -- no session-existence oracle."""
    doc_id = await _upload(client)

    expired_id, _expires_at = await services.sessions.create("test-user", ttl_seconds=0)
    expired = await _run(client, expired_id, doc_id)
    assert expired.status_code == 401
    assert expired.json()["code"] == "SESSION_EXPIRED"

    unknown = await _run(client, uuid.uuid4().hex, doc_id)
    assert unknown.status_code == 401
    assert unknown.json()["code"] == "SESSION_EXPIRED"

    missing = await client.post(
        "/pipeline/run", json={"user_id": OWNER, "doc_id": doc_id, "prompt": PROMPT}
    )
    assert missing.status_code == 401
    assert missing.json()["code"] == "SESSION_EXPIRED"

    # Same code, same shape: a caller cannot tell the three apart.
    assert set(expired.json()) == set(unknown.json()) == set(missing.json())


# ---------------------------------------------------------------------------
# 4b. A session belongs to exactly one user
# ---------------------------------------------------------------------------
async def test_a_session_is_useless_to_any_user_but_its_owner(client: AsyncClient) -> None:
    """The attack this closes: a session ID used to be a credential for *anyone*.

    Unbound, ``mallory``'s session presented with ``user_id=alice`` and alice's
    ``doc_id`` returned alice's PHI with a 200 -- the only obstacle was the
    ``doc_id`` being unguessable, which is obscurity rather than authorization
    and sat directly under the per-user-key isolation claim.

    Black-box separable on purpose: with the binding removed the first request
    below returns 200 and a restored document, so this cannot silently pass if
    the check is dropped.
    """
    alice_session = await _create_session(client, OWNER)
    alice_doc = await _upload(client, OWNER)
    mallory_session = await _create_session(client, INTRUDER)
    mallory_doc = await _upload(client, INTRUDER)

    # The exact attack, verbatim: mallory's own live session, alice's claim.
    stolen = await _run(client, mallory_session, alice_doc, user_id=OWNER)
    assert stolen.status_code == 401, stolen.text
    assert stolen.json()["code"] == "SESSION_EXPIRED"
    for original in ORIGINALS:
        assert original not in stolen.text

    # And the mirror: alice's session cannot be spent on mallory's identity.
    assert (await _run(client, alice_session, mallory_doc, user_id=INTRUDER)).status_code == 401

    # A mismatch is indistinguishable from an unknown session -- naming it a
    # "wrong user" would confirm the session ID is real and merely someone
    # else's, which is the oracle the uniform 401 exists to deny.
    unknown = await _run(client, uuid.uuid4().hex, alice_doc, user_id=OWNER)
    assert unknown.status_code == stolen.status_code
    assert unknown.json()["code"] == stolen.json()["code"]
    assert set(unknown.json()["detail"]) == set(stolen.json()["detail"])

    # The binding is checked, not merely recorded: each owner still works.
    assert (await _run(client, alice_session, alice_doc, user_id=OWNER)).status_code == 200
    assert (await _run(client, mallory_session, mallory_doc, user_id=INTRUDER)).status_code == 200

    # ... including via the header, which is the other way a session arrives.
    header_run = await _run(client, mallory_session, alice_doc, user_id=OWNER, use_header=True)
    assert header_run.status_code == 401


async def test_logout_cannot_destroy_another_users_session(client: AsyncClient) -> None:
    """Destruction is irreversible, so logging someone else out is data loss.

    Kept oracle-free: a stranger's session, an unknown ID and the caller's own
    all answer the same empty 204. The difference is only observable to the
    owner, whose session must still work afterwards -- which is what separates
    this from a no-op if the ownership check is removed.
    """
    alice_session = await _create_session(client, OWNER)
    alice_doc = await _upload(client, OWNER)

    hostile = await client.delete(f"/sessions/{alice_session}", params={"user_id": INTRUDER})
    unknown = await client.delete(f"/sessions/{uuid.uuid4().hex}", params={"user_id": INTRUDER})
    assert hostile.status_code == unknown.status_code == 204
    assert hostile.content == unknown.content == b""

    # Nothing was destroyed: alice's session is untouched.
    survived = await _run(client, alice_session, alice_doc, user_id=OWNER)
    assert survived.status_code == 200, survived.text

    # The owner can still log out, and then it really is gone.
    assert (
        await client.delete(f"/sessions/{alice_session}", params={"user_id": OWNER})
    ).status_code == 204
    after = await _run(client, alice_session, alice_doc, user_id=OWNER)
    assert after.status_code == 401


async def test_docs_ui_is_disabled_so_no_page_reaches_a_third_party(
    client: AsyncClient,
) -> None:
    """FastAPI's Swagger and ReDoc pages load assets from CDNs.

    That contradicts the premise the whole design argues -- nothing about a
    document reaches a third party, and the container needs no network -- and it
    renders blank for an airgapped reviewer. The schema is unaffected.
    """
    assert (await client.get("/docs")).status_code == 404
    assert (await client.get("/redoc")).status_code == 404

    schema = await client.get("/openapi.json")
    assert schema.status_code == 200
    assert schema.json()["info"]["title"] == "Secure Context Pipeline"
    assert "cdn.jsdelivr.net" not in schema.text
    assert "fastapi.tiangolo.com" not in schema.text


# ---------------------------------------------------------------------------
# 5. Audit query filters and chain verification
# ---------------------------------------------------------------------------
async def test_audit_query_filters_and_verify(client: AsyncClient) -> None:
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run = await _run(client, session_id, doc_id)
    assert run.status_code == 200, run.text
    run_id = run.json()["run_id"]

    by_session = await client.get("/audit", params={"session_id": session_id, "user_id": OWNER})
    assert by_session.status_code == 200
    events = by_session.json()["events"]
    assert events
    assert all(event["session_id"] == session_id for event in events)
    assert {SESSION_CREATE, DETECT, EGRESS_PASS, LLM_CALL} <= {e["event_type"] for e in events}

    by_type = await client.get(
        "/audit",
        params={"session_id": session_id, "user_id": OWNER, "event_type": EGRESS_PASS},
    )
    assert by_type.status_code == 200
    typed = by_type.json()["events"]
    assert typed and all(event["event_type"] == EGRESS_PASS for event in typed)

    by_run = await client.get("/audit", params={"run_id": run_id, "user_id": OWNER})
    assert by_run.status_code == 200
    assert by_run.json()["events"]

    # since/until bound the window; a window entirely in the future is empty.
    future = await client.get(
        "/audit",
        params={"session_id": session_id, "user_id": OWNER, "since": 4_102_444_800.0},
    )
    assert future.status_code == 200
    assert future.json()["events"] == []

    # Pagination.
    paged = await client.get(
        "/audit", params={"session_id": session_id, "user_id": OWNER, "limit": 1}
    )
    assert paged.status_code == 200
    assert paged.json()["returned"] == 1
    assert paged.json()["limit"] == 1
    second = await client.get(
        "/audit",
        params={"session_id": session_id, "user_id": OWNER, "limit": 1, "offset": 1},
    )
    assert second.json()["events"][0]["seq"] > paged.json()["events"][0]["seq"]

    verify_all = await client.get("/audit/verify")
    assert verify_all.status_code == 200
    assert verify_all.json()["valid"] is True
    assert verify_all.json()["length"] >= len(events)

    verify_session = await client.get(
        "/audit/verify", params={"session_id": session_id, "user_id": OWNER}
    )
    assert verify_session.json() == {
        "valid": True,
        "length": len(events),
        "session_id": session_id,
    }

    # No audit response may quote a document value.
    for original in ORIGINALS:
        assert original not in by_session.text


# ---------------------------------------------------------------------------
# 6. Run correlation (build doc section 9.5.1)
# ---------------------------------------------------------------------------
async def test_every_audit_event_from_a_run_carries_the_run_id(client: AsyncClient) -> None:
    """One ID correlates the whole detect -> obfuscate -> egress -> LLM -> restore chain."""
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run = await _run(client, session_id, doc_id)
    assert run.status_code == 200, run.text
    result = run.json()
    run_id = result["run_id"]

    by_run = await client.get("/audit", params={"run_id": run_id, "user_id": OWNER})
    run_events = by_run.json()["events"]
    assert run_events
    assert all(event["run_id"] == run_id for event in run_events)
    assert {event["seq"] for event in run_events} == set(result["audit_seq"])

    # Within this session, every run-scoped event belongs to this one run, and
    # the session-scoped events (SESSION_CREATE) carry no run_id at all.
    by_session = await client.get("/audit", params={"session_id": session_id, "user_id": OWNER})
    session_events = by_session.json()["events"]
    correlated = [event for event in session_events if event["run_id"] is not None]
    assert correlated
    assert all(event["run_id"] == run_id for event in correlated)
    assert any(event["run_id"] is None for event in session_events)
    assert len(correlated) == len(run_events)


# ---------------------------------------------------------------------------
# 7. GET /documents/{doc_id}/text is owner-only
# ---------------------------------------------------------------------------
async def test_document_text_is_owner_only_and_gives_no_existence_oracle(
    client: AsyncClient,
) -> None:
    doc_id = await _upload(client, OWNER)

    mine = await client.get(f"/documents/{doc_id}/text", params={"user_id": OWNER})
    assert mine.status_code == 200, mine.text
    body = mine.json()
    assert body["text"] == DOC_TEXT
    assert body["doc_category"] == "medical"
    assert body["chars"] == len(DOC_TEXT)

    wrong_owner = await client.get(f"/documents/{doc_id}/text", params={"user_id": INTRUDER})
    absent_id = uuid.uuid4().hex
    absent = await client.get(f"/documents/{absent_id}/text", params={"user_id": INTRUDER})

    assert wrong_owner.status_code == absent.status_code == 404
    assert wrong_owner.json()["code"] == absent.json()["code"] == "NOT_FOUND"

    # Byte-identical modulo the doc_id the caller itself supplied: "not yours"
    # and "no such document" must be the same answer.
    def scrub(payload: dict[str, Any]) -> dict[str, Any]:
        detail = dict(payload["detail"])
        detail["doc_id"] = "<doc_id>"
        return {**payload, "detail": detail}

    assert scrub(wrong_owner.json()) == scrub(absent.json())
    for original in ORIGINALS:
        assert original not in wrong_owner.text
        assert original not in absent.text


# ---------------------------------------------------------------------------
# 8. Health
# ---------------------------------------------------------------------------
async def test_health_reports_model_and_database(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["db_reachable"] is True
    assert body["llm_provider"] == "mock"
    assert body["spacy_model"]


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------
async def test_upload_rejects_bad_category_and_unsupported_type(client: AsyncClient) -> None:
    bad_category = await client.post(
        "/documents",
        files={"file": ("intake.txt", DOC_TEXT.encode("utf-8"), "text/plain")},
        data={"user_id": OWNER, "doc_category": "astrology"},
    )
    assert bad_category.status_code == 400
    assert bad_category.json()["code"] == "INVALID_DOC_CATEGORY"

    unsupported = await client.post(
        "/documents",
        files={"file": ("payload.exe", b"MZ\x90\x00binary", "application/octet-stream")},
        data={"user_id": OWNER},
    )
    assert unsupported.status_code == 400
    assert unsupported.json()["code"] == "UNPROCESSABLE_DOCUMENT"

    empty = await client.post(
        "/documents", files={"file": ("empty.txt", b"", "text/plain")}, data={"user_id": OWNER}
    )
    assert empty.status_code == 400
    assert empty.json()["code"] == "EMPTY_UPLOAD"


async def test_validation_errors_do_not_echo_the_request_body(client: AsyncClient) -> None:
    """FastAPI's default 422 body embeds the offending input; ours must not."""
    session_id = await _create_session(client)
    response = await client.post(
        "/pipeline/run",
        json={"session_id": session_id, "user_id": OWNER, "doc_id": "x" * 8, "prompt": ""},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "VALIDATION_ERROR"
    assert "prompt" in body["detail"]["fields"]
    assert "input" not in response.text


async def test_upload_rejects_an_overlong_doc_category_without_echoing_it(
    client: AsyncClient,
) -> None:
    """``doc_category`` is bounded at the schema, like every other identifier.

    Unbounded, a hostile category was carried all the way into
    ``InvalidCategoryError`` and 64 characters of it came back in the error body.
    The rejection must happen at the boundary and must not quote the input.
    """
    canary = "CATEGORYCANARY" * 40
    response = await client.post(
        "/documents",
        files={"file": ("intake.txt", DOC_TEXT.encode("utf-8"), "text/plain")},
        data={"user_id": OWNER, "doc_category": canary},
    )
    assert response.status_code == 422, response.text
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert "CATEGORYCANARY" not in response.text


async def test_read_capped_stops_reading_instead_of_buffering_the_whole_body(
    client: AsyncClient,
) -> None:
    """The cap must bound what the handler allocates, not just what it answers.

    ``file.size`` is only a declared length, so the pre-check above the read is
    advisory. The fallback used to be ``await file.read()`` and then measure --
    which answers 413 correctly but only after materialising every byte the
    caller chose to send, so the caller picked the allocation. The refusal has to
    happen *while* the body is consumed, and the assertion below is on how much
    was pulled into memory, because the status code alone cannot tell the two
    implementations apart.
    """
    oversize = MAX_UPLOAD_BYTES + (8 * UPLOAD_CHUNK_BYTES)
    spool = tempfile.SpooledTemporaryFile(max_size=UPLOAD_CHUNK_BYTES)
    spool.write(b"A" * oversize)
    spool.seek(0)
    # No ``size=``: this is exactly the case the advisory pre-check misses.
    upload = UploadFile(file=spool, filename="huge.txt")
    assert upload.size is None

    read_total = 0
    real_read = upload.read

    async def counting_read(size: int = -1) -> bytes:
        nonlocal read_total
        chunk = await real_read(size)
        read_total += len(chunk)
        return chunk

    upload.read = counting_read  # type: ignore[method-assign]

    with pytest.raises(ApiError) as caught:
        await _read_capped(upload)

    assert caught.value.status_code == 413
    assert caught.value.code == "UPLOAD_TOO_LARGE"
    assert caught.value.detail["max_bytes"] == MAX_UPLOAD_BYTES
    # The refusal reports the caller's own byte total and nothing else.
    assert set(caught.value.detail) == {"max_bytes", "bytes"}

    # The point of the fix: it stopped one chunk past the ceiling rather than
    # reading all of it.
    assert read_total <= MAX_UPLOAD_BYTES + UPLOAD_CHUNK_BYTES, read_total
    assert read_total < oversize, "the whole body was buffered before refusing"

    # And a body under the ceiling is still read to completion.
    small = tempfile.SpooledTemporaryFile(max_size=UPLOAD_CHUNK_BYTES)
    small.write(b"B" * (3 * UPLOAD_CHUNK_BYTES))
    small.seek(0)
    assert len(await _read_capped(UploadFile(file=small, filename="ok.txt"))) == (
        3 * UPLOAD_CHUNK_BYTES
    )

    # End to end, an oversize upload is still refused at the HTTP boundary.
    too_big = await client.post(
        "/documents",
        files={"file": ("huge.txt", b"A" * (MAX_UPLOAD_BYTES + 1024), "text/plain")},
        data={"user_id": OWNER},
    )
    assert too_big.status_code == 413
    assert too_big.json()["code"] == "UPLOAD_TOO_LARGE"


# ---------------------------------------------------------------------------
# 9. Logout ordering: the key dies before the rows
# ---------------------------------------------------------------------------
async def test_logout_pops_the_session_key_before_deleting_vault_rows(
    client: AsyncClient, services: Services
) -> None:
    """Logout is two awaits, and their order is a security property.

    An in-flight run already holds the session key, so it can be scheduled
    between them. With the rows deleted first, that run's next ``vault.put()``
    landed *after* the erasure and rebuilt a live cache and a durable row for a
    session that was supposed to be gone. Popping the key first makes the window
    harmless rather than merely narrow: every vault ciphertext is AES-GCM under a
    key derived from the session key, so once it is gone no later write can
    derive one.

    **Why this asserts the order and not an outcome.** The vault independently
    tombstones a destroyed session, so a racing ``put()`` is refused under
    *either* order -- the behaviour is identical and no black-box assertion can
    separate them. The ordering is the defence-in-depth layer underneath that
    tombstone, so it is asserted directly; otherwise nothing stops it being
    quietly flipped back and the system silently losing a layer.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert services.vault.originals_for_session(session_id), "the run must have vaulted something"

    calls: list[str] = []
    real_session_destroy = services.sessions.destroy
    real_vault_destroy = services.vault.destroy
    racing_put: list[str] = []

    async def spy_session_destroy(target: str) -> bool:
        calls.append("session_key")
        return await real_session_destroy(target)

    async def spy_vault_destroy(target: str) -> None:
        calls.append("vault_rows")
        # The interleaving the bug depended on: a write landing mid-logout.
        record = TokenRecord(
            session_id=target,
            token_id="racedtok",
            entity_type="NAME",
            category="PII",
            surrogate="[PII_NAME_racedtok]",
            created_at=time.time(),
        )
        try:
            await services.vault.put(target, record, "Jordan Alvarez")
            racing_put.append("accepted")
        except SessionExpiredError:
            racing_put.append("refused")
        await real_vault_destroy(target)

    services.sessions.destroy = spy_session_destroy  # type: ignore[method-assign]
    services.vault.destroy = spy_vault_destroy  # type: ignore[method-assign]
    try:
        assert (
            await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})
        ).status_code == 204
    finally:
        services.sessions.destroy = real_session_destroy  # type: ignore[method-assign]
        services.vault.destroy = real_vault_destroy  # type: ignore[method-assign]

    assert calls == ["session_key", "vault_rows"], (
        "logout must pop the session key before deleting vault rows"
    )
    assert racing_put == ["refused"]

    # ... and the outcome the ordering exists to guarantee still holds.
    assert not services.vault.originals_for_session(session_id), (
        "a write racing logout resurrected the destroyed session's plaintext"
    )
    after = await _run(client, session_id, doc_id)
    assert after.status_code == 401
    assert after.json()["code"] == "SESSION_EXPIRED"


# ---------------------------------------------------------------------------
# 10. The audit log must not be a session-ID enumeration oracle
# ---------------------------------------------------------------------------
async def test_audit_query_requires_a_scope_and_cannot_enumerate_sessions(
    client: AsyncClient,
) -> None:
    """An unscoped ``GET /audit`` used to hand every live ``session_id`` to anyone.

    That is the whole attack: ``session_id`` is the bearer credential for
    ``DELETE /sessions/{id}``, so an anonymous caller could scrape the log and
    destroy every live vault in the process -- irreversibly, since destruction is
    cryptographic erasure. The log stays readable (compliance, and the demo reads
    it *after* the session is destroyed), but only for a scope the caller already
    holds: a 128-bit ``session_id`` or ``run_id`` that was never published.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run = await _run(client, session_id, doc_id)
    assert run.status_code == 200, run.text
    run_id = run.json()["run_id"]

    unscoped = await client.get("/audit", params={"user_id": OWNER})
    assert unscoped.status_code == 400, unscoped.text
    assert unscoped.json()["code"] == "AUDIT_SCOPE_REQUIRED"
    assert session_id not in unscoped.text

    # Nor does dropping the credential open it up: no scope and no user_id is a
    # rejected request, never a page of the log.
    bare = await client.get("/audit")
    assert bare.status_code >= 400, bare.text
    assert session_id not in bare.text

    # A filter that is not a scope is still not a scope -- otherwise the whole
    # log comes back one event_type at a time.
    for params in ({"event_type": SESSION_CREATE}, {"limit": 1000}, {"since": 0.0}):
        leaky = await client.get("/audit", params={**params, "user_id": OWNER})
        assert leaky.status_code == 400, (params, leaky.text)
        assert session_id not in leaky.text

    # Holding a scope *and* owning it still works, for both kinds, and still
    # after logout.
    by_session = await client.get("/audit", params={"session_id": session_id, "user_id": OWNER})
    assert by_session.status_code == 200
    assert by_session.json()["events"]

    by_run = await client.get("/audit", params={"run_id": run_id, "user_id": OWNER})
    assert by_run.status_code == 200
    assert by_run.json()["events"]

    assert (
        await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})
    ).status_code == 204
    after_logout = await client.get("/audit", params={"session_id": session_id, "user_id": OWNER})
    assert after_logout.status_code == 200
    assert after_logout.json()["events"], "the demo prints the tail after destroying the session"

    # /audit/verify stays open -- it reports a boolean and a count, and echoes
    # back only the session_id the caller itself supplied.
    verify = await client.get("/audit/verify")
    assert verify.status_code == 200
    assert set(verify.json()) == {"valid", "length", "session_id"}
    assert verify.json()["session_id"] is None


async def test_no_unauthenticated_endpoint_discloses_a_live_session_id(
    client: AsyncClient,
) -> None:
    """End-to-end version of the harvest: scrape everything reachable anonymously.

    A live ``session_id`` appearing in any of these bodies re-opens the
    mass-destruction path, whatever the endpoint's own purpose is.

    The ``run_id`` rows below are the ones this test used to be missing. It
    checked only the *unscoped* reads -- the shape of the hole that had already
    been found -- so it went green while ``GET /audit?run_id=...`` was still
    handing the session ID to anybody who asked. A property quantified over
    "every anonymous endpoint" has to be tested over the scoped forms too,
    because those are the ones that return rows.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run = await _run(client, session_id, doc_id)
    assert run.status_code == 200, run.text
    run_id = run.json()["run_id"]

    scraped = [
        await client.get("/audit"),
        await client.get("/audit", params={"limit": 1000}),
        await client.get("/audit", params={"run_id": run_id}),
        await client.get("/audit", params={"run_id": run_id, "user_id": INTRUDER}),
        await client.get("/audit", params={"session_id": session_id, "user_id": INTRUDER}),
        await client.get("/audit/verify"),
        await client.get("/audit/verify", params={"session_id": session_id}),
        await client.get("/health"),
        await client.get("/openapi.json"),
        await client.get("/"),
    ]
    for response in scraped:
        assert session_id not in response.text, response.request.url

    # And the count is all /health gives away -- never the IDs themselves.
    assert isinstance((await client.get("/health")).json()["active_sessions"], int)


async def test_the_audit_log_is_not_a_credential_assembly_oracle(
    client: AsyncClient,
) -> None:
    """The whole break, run forwards: one ``run_id``, no credentials, no session.

    Requiring a *scope* on ``GET /audit`` stopped enumeration but left the log an
    assembly oracle, which reaches the same place by a longer road. Every row
    names its ``session_id``; a ``DETECT`` row names the ``doc_id`` that was
    read; a ``SESSION_CREATE`` row names the owning ``user_id``. Those compose
    into both credential pairs in the system --  ``(doc_id, user_id)`` for
    ``GET /documents/{doc_id}/text``, which returns original plaintext, and
    ``(session_id, user_id)`` for ``DELETE /sessions/{session_id}``, which is
    irreversible cryptographic erasure. The ``user_id`` second factor that guards
    both was being issued by this third endpoint, for free, to anyone.

    Measured before the fix: steps 1-3 below returned 200 with the patient's name,
    MRN and phone number, and step 5 returned 204 and destroyed the vault.
    """
    victim_session = await _create_session(client, OWNER)
    victim_doc = await _upload(client, OWNER)
    run = await _run(client, victim_session, victim_doc, user_id=OWNER)
    assert run.status_code == 200, run.text
    run_id = run.json()["run_id"]

    # The attacker holds exactly one identifier and nothing else.
    step1 = await client.get("/audit", params={"run_id": run_id, "user_id": INTRUDER})
    assert step1.status_code == 200
    assert step1.json()["events"] == [], "a run's events must not be readable by a stranger"
    assert victim_session not in step1.text
    assert victim_doc not in step1.text

    step2 = await client.get("/audit", params={"session_id": victim_session, "user_id": INTRUDER})
    assert step2.json()["events"] == [], "a session's events must not name its owner to a stranger"
    assert OWNER not in step2.text

    # Guessing the scope right is not enough, and neither is holding a live
    # session of one's own: the claim has to match the owner in the log.
    await _create_session(client, INTRUDER)
    assert (await client.get("/audit", params={"run_id": run_id, "user_id": INTRUDER})).json()[
        "events"
    ] == []

    # Unreadable and non-existent are the same answer -- answering 403 to the
    # first would confirm the scope is real, which is the oracle the uniform
    # empty page exists to deny.
    absent = await client.get("/audit", params={"run_id": uuid.uuid4().hex, "user_id": INTRUDER})
    assert absent.status_code == step1.status_code
    assert absent.json() == step1.json()

    # The owner is unaffected -- this is authorization, not an outage.
    owned = await client.get("/audit", params={"run_id": run_id, "user_id": OWNER})
    assert owned.status_code == 200
    assert owned.json()["events"], "the owner must still be able to read their own trail"

    # And the two endpoints the chain led to are still standing.
    assert (
        await client.get(f"/documents/{victim_doc}/text", params={"user_id": INTRUDER})
    ).status_code == 404
    assert (await _run(client, victim_session, victim_doc, user_id=OWNER)).status_code == 200


async def test_audit_verify_is_owner_scoped_and_gives_no_existence_oracle(
    client: AsyncClient,
) -> None:
    """Per-session ``length`` says whether a session ID was ever real.

    Zero versus non-zero is an existence oracle for the one identifier that
    ``DELETE /sessions/{id}`` accepts, so the scoped form is gated exactly like
    the query it mirrors. The unscoped form stays anonymous on purpose: it names
    nothing -- no session, no run, no user, no document -- and a publicly
    checkable tamper-evidence claim is the point of hash-chaining the log.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    assert (await _run(client, session_id, doc_id)).status_code == 200

    owned = await client.get("/audit/verify", params={"session_id": session_id, "user_id": OWNER})
    assert owned.status_code == 200
    assert owned.json()["valid"] is True
    assert owned.json()["length"] > 0

    stranger = await client.get(
        "/audit/verify", params={"session_id": session_id, "user_id": INTRUDER}
    )
    never_existed = await client.get(
        "/audit/verify", params={"session_id": uuid.uuid4().hex, "user_id": INTRUDER}
    )
    # Byte-identical modulo the session_id the caller itself supplied.
    assert stranger.status_code == never_existed.status_code == 200
    assert stranger.json()["length"] == never_existed.json()["length"] == 0
    assert stranger.json()["valid"] == never_existed.json()["valid"]

    # The whole-log form is still open, and still names nothing.
    whole = await client.get("/audit/verify")
    assert whole.status_code == 200
    assert whole.json()["valid"] is True
    assert whole.json()["length"] > 0
    assert whole.json()["session_id"] is None
    assert session_id not in whole.text


async def test_a_non_ascii_user_id_is_never_an_unhandled_500(client: AsyncClient) -> None:
    """``secrets.compare_digest`` on ``str`` raises for any non-ASCII character.

    The session -> ``user_id`` binding is *built* on that comparison, so the
    ownership check crashed on the very input it exists to reject. Two live
    consequences. A legitimate ``user_id`` with an accent could create a session
    and then never spend it: every ``POST /pipeline/run`` answered a bare
    ``500 Internal Server Error``, outside the structured-error contract
    entirely. And an anonymous caller could raise that 500, with a full traceback
    logged, against *any* live session by sending one accented character --
    the same free log-flooding primitive ``%00`` in a static path used to give.

    Nothing rejects the claim earlier (``user_id`` is any 1-64 character string),
    so the comparison itself has to be total. Asserted over every route that
    compares a claim against a recorded owner.
    """
    accented = "josé"
    session_id = await _create_session(client, accented)
    doc_id = await _upload(client, user_id=accented)

    # The owner can spend their own session, all the way through the pipeline.
    mine = await _run(client, session_id, doc_id, user_id=accented)
    assert mine.status_code == 200, mine.text
    assert "David Ochoa" in mine.json()["restored_text"]

    # A stranger's accented claim is refused, not crashed -- and refused with the
    # same 401 as any other wrong owner.
    ascii_session = await _create_session(client, OWNER)
    ascii_doc = await _upload(client, OWNER)
    for claim in ("é", "josé", "ålice", "アリス"):
        hostile = await _run(client, ascii_session, ascii_doc, user_id=claim)
        assert hostile.status_code == 401, (claim, hostile.status_code, hostile.text)
        assert hostile.json()["code"] == "SESSION_EXPIRED"

        # Logout compares the same pair and must not crash either.
        logout = await client.delete(f"/sessions/{ascii_session}", params={"user_id": claim})
        assert logout.status_code == 204, (claim, logout.text)

        # ... and it must not have destroyed anything while failing to compare.
        assert (await _run(client, ascii_session, ascii_doc, user_id=OWNER)).status_code == 200

    # The audit ownership proof compares the same pair, on the same rule.
    assert (
        await client.get("/audit", params={"session_id": session_id, "user_id": accented})
    ).json()["events"], "the accented owner must still read their own trail"
    assert (await client.get("/audit", params={"session_id": session_id, "user_id": "é"})).json()[
        "events"
    ] == []

    # The owner's own logout still works, accent and all.
    assert (
        await client.delete(f"/sessions/{session_id}", params={"user_id": accented})
    ).status_code == 204
    assert (await _run(client, session_id, doc_id, user_id=accented)).status_code == 401


# ---------------------------------------------------------------------------
# 10. Lifespan resource lifecycle
# ---------------------------------------------------------------------------
async def test_lifespan_closes_everything_it_opened_when_startup_fails(
    api_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A startup that dies half-built must not leak the half it already opened.

    ``_build_services`` opens three aiosqlite connections in sequence. If a later
    one raises -- a read-only ``./data`` bind mount is the realistic case, since
    the container runs as uid 10001 -- the earlier connections used to survive
    with their non-daemon worker threads, which both leaks a connection per
    attempt and stops the interpreter from exiting at all.
    """
    from secure_context_pipeline.api import app as app_module

    opened: list[Any] = []
    real_open = app_module.AuditLogger.open

    async def spy_open(db_path: Any) -> Any:
        logger_instance = await real_open(db_path)
        opened.append(logger_instance)
        return logger_instance

    async def explode(_settings: Settings) -> Any:
        raise OSError("data directory is read-only")

    monkeypatch.setattr(app_module.AuditLogger, "open", spy_open)
    monkeypatch.setattr(app_module.EncryptedDocumentStore, "open", explode)

    failing_app = create_app(api_settings)
    with pytest.raises(OSError, match="read-only"):
        async with failing_app.router.lifespan_context(failing_app):
            pass  # pragma: no cover -- the lifespan raises before the body runs

    assert opened, "the audit log must have been opened before the failure"
    for logger_instance in opened:
        with pytest.raises(PipelineError) as caught:
            await logger_instance.length()
        assert caught.value.detail["reason"] == "audit_logger_not_open"


# ---------------------------------------------------------------------------
# 11. The demo UI is served, self-contained, and locked down
# ---------------------------------------------------------------------------
async def test_demo_ui_is_self_contained_and_declares_a_restrictive_csp(
    client: AsyncClient,
) -> None:
    """The UI renders two untrusted strings (document text and LLM output).

    Escaping is the control and is asserted in the JS itself; the CSP is the
    second line, and it is also what makes "no external network references"
    enforced rather than merely true today -- the pipeline's premise is that
    nothing about a document reaches a third party, and a CDN font would.
    """
    index = await client.get("/")
    assert index.status_code == 200, index.text
    body = index.text

    assert "Content-Security-Policy" in body, "the demo UI must ship a CSP"
    policy = body.split("Content-Security-Policy", 1)[1].split(">", 1)[0]
    for directive in ("default-src 'none'", "script-src 'self'", "connect-src 'self'"):
        assert directive in policy, directive
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy

    # Every asset the page pulls is same-origin, and no asset references a host.
    for asset in ("/", "/app.js", "/style.css"):
        response = await client.get(asset)
        assert response.status_code == 200, asset
        assert "http://" not in response.text, asset
        assert "https://" not in response.text, asset


async def test_security_headers_are_sent_on_every_response(client: AsyncClient) -> None:
    """A ``<meta http-equiv>`` CSP cannot express the two things that matter most.

    It governs only the document that carries it -- not ``app.js``, not a JSON
    error body -- and ``frame-ancestors`` is ignored in meta by specification, so
    the page was framable. That is not academic here: the demo UI's "Destroy
    session" button is one click from an irreversible cryptographic erasure, so a
    page a third-party site can frame is a page that can be tricked into erasing
    a vault.
    """
    for path in ("/", "/app.js", "/style.css", "/health", "/openapi.json"):
        response = await client.get(path)
        headers = response.headers
        assert "frame-ancestors 'none'" in headers["content-security-policy"], path
        assert "default-src 'none'" in headers["content-security-policy"], path
        assert "unsafe-inline" not in headers["content-security-policy"], path
        assert headers["x-content-type-options"] == "nosniff", path
        assert headers["referrer-policy"] == "no-referrer", path
        # `no-store` is stamped on every response for the reason the path list in
        # this loop exists: the one route that returns decrypted plaintext
        # (`/documents/{doc_id}/text`) shipped with no `Cache-Control` at all, and
        # a per-route header is a list that goes stale the moment a route is added.
        # Pinned here by value so a narrowing to "the plaintext route only" is a
        # failure rather than a silent policy change.
        assert headers["cache-control"] == "no-store", path

    # Error responses are covered too -- they are the ones an attacker can reach
    # without knowing anything.
    refused = await client.get("/audit")
    assert refused.status_code >= 400
    assert "frame-ancestors 'none'" in refused.headers["content-security-policy"]

    # No CORS: the API is same-origin only, so no cross-site page can read it.
    cross = await client.get("/health", headers={"Origin": "http://evil.test"})
    assert "access-control-allow-origin" not in cross.headers


async def test_every_error_body_is_the_one_documented_shape(client: AsyncClient) -> None:
    """``{"code": ..., "detail": {...}}`` is claimed of *every* non-2xx body.

    It was not true of anything raised outside this module's own hierarchy. A
    malformed or over-long multipart header makes ``python-multipart`` raise
    Starlette's ``HTTPException``, which rendered as ``{"detail": "There was an
    error parsing the body"}`` -- no ``code`` for a client to branch on, and the
    only free-text detail in the API, on a path an anonymous caller controls.
    """
    probes = [
        # multipart parse failure: a filename far past what the parser accepts.
        await client.post(
            "/documents",
            files={"file": ("a" * 5000 + ".txt", b"hello there", "text/plain")},
            data={"user_id": OWNER},
        ),
        await client.get("/no-such-asset.js"),
        await client.get("/docs"),
        await client.get("/audit", params={"user_id": OWNER}),
        await client.post("/pipeline/run", json={"user_id": OWNER, "doc_id": "x", "prompt": ""}),
        await client.get(f"/documents/{uuid.uuid4().hex}/text", params={"user_id": OWNER}),
    ]
    for response in probes:
        assert response.status_code >= 400, response.request.url
        body = response.json()
        assert set(body) == {"code", "detail"}, (response.request.url, body)
        assert isinstance(body["code"], str) and body["code"], response.request.url
        assert isinstance(body["detail"], dict), response.request.url


async def test_a_null_byte_in_a_static_path_is_a_404_not_a_500(client: AsyncClient) -> None:
    """``%00`` reached ``os.path.realpath`` and raised ``ValueError``.

    Unhandled, that is an unauthenticated 500 with a full traceback logged on
    every request -- a free log-flooding primitive, and a server error where the
    truthful answer is "no such file". A NUL cannot name an asset that exists, so
    it must be the same 404 as any other miss, and must stay distinguishable from
    a 500 no matter how the request is spelled.
    """
    for path in ("/app.js%00.txt", "/%00", "/style.css%00", "/foo%00bar", "/sessions/%00"):
        response = await client.get(path)
        assert response.status_code == 404, (path, response.status_code, response.text)

    # A real asset is unaffected.
    assert (await client.get("/app.js")).status_code == 200


# ---------------------------------------------------------------------------
# 12. The image must not be able to carry a secret
# ---------------------------------------------------------------------------
def _copy_sources(copy_line: str) -> list[str]:
    """The source arguments of a ``COPY``, normalised to compare against ``.``.

    Written as a function with its own test (below) because the naive version --
    ``copy_line.split()[1:-1]`` compared against the literal ``"."`` -- passed
    ``COPY ./ ./``, which is byte-for-byte the blanket copy the check exists to
    forbid. Three spellings have to normalise to the same thing: ``.``, ``./``,
    and the exec form ``["." , "."]``; and ``--chown``/``--from`` flags are not
    sources at all, so a flag must not be able to shift the destination out of
    the last position.
    """
    tokens = [
        token.strip("[],\"'") for token in copy_line.split()[1:] if not token.startswith("--")
    ]
    return [(token.rstrip("/") or "/") for token in tokens[:-1]]


async def test_the_copy_source_parser_recognises_every_spelling_of_a_blanket_copy() -> None:
    """The check above is only as good as this parse, so the parse is tested.

    Each line below is a real way to write ``COPY . .``. The previous parser --
    ``split()[1:-1]`` with ``"." not in sources`` -- accepted the second, third
    and fourth of them, which is how a mutation that ships ``.env`` into a layer
    kept the suite green.
    """
    blanket = [
        "COPY . .",
        "COPY ./ ./",
        "COPY --chown=scp:scp . .",
        'COPY [".", "."]',
        "COPY .// ./",
    ]
    for line in blanket:
        assert "." in _copy_sources(line), line

    allowed = [
        "COPY pyproject.toml README.md ./",
        "COPY entities.yaml ./",
        "COPY secure_context_pipeline/ secure_context_pipeline/",
        "COPY --from=base /app /app",
    ]
    for line in allowed:
        assert "." not in _copy_sources(line), line
        assert _copy_sources(line), line


async def test_dockerfile_never_copies_the_working_tree_wholesale() -> None:
    """``COPY . .`` put ``.env`` -- and therefore ``SCP_MASTER_KEY`` -- in a layer.

    The build context is a developer's working tree. ``docker-compose`` requires
    a ``.env`` next to the ``Dockerfile`` (``env_file: .env``), so the file is
    present exactly when the image is built, and the master key decrypts every
    document in the store. It also shipped ``data/`` (real encrypted blobs, the
    vault, the audit chain), ``.git``, and a ~750 MB host virtualenv.

    Asserted statically rather than by building: this must stay true on a machine
    with no Docker daemon, and the property is a property of the recipe.
    """
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    copy_lines = [
        stripped
        for line in dockerfile.splitlines()
        if (stripped := line.strip()).startswith("COPY ")
    ]
    assert copy_lines, "the Dockerfile must copy something"
    for copy_line in copy_lines:
        sources = _copy_sources(copy_line)
        assert sources, f"a COPY with no source: {copy_line}"
        for source in sources:
            assert source not in (".", "..", "*", "/"), (
                f"blanket COPY re-introduces the secret leak: {copy_line}"
            )

    # And the deny-list backstop: asked of the MATCHER, not of the file's spelling.
    #
    # This used to read the file, split it on whitespace and assert the literal token
    # ".env" was among the pieces. That had two faults. It tokenised prose, so a
    # comment containing the word "data/" satisfied it with no rule present at all;
    # and it pinned an exact spelling, so it went red when the rules were rewritten
    # `**/.env` -- a change that denies strictly MORE. Docker anchors a pattern to the
    # context root unless it starts with `**/`, so `.env` covered ./.env only. An
    # assertion that reddens when a deny-list is STRENGTHENED is testing the spelling
    # rather than the property, and the property is what must never regress.
    #
    # `_dockerignored` is the matcher pinned against a real daemon build further down
    # this file, so this asks the same question the daemon answers.
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert _dockerignored(".env", dockerignore)
    # The nested case, which is what the `**/` rewrite actually closed and which the
    # old literal check could never have covered: a seeded secure_context_pipeline/.env
    # shipped in the tagged image while the root .env was correctly excluded.
    assert _dockerignored("secure_context_pipeline/.env", dockerignore)
    assert _dockerignored("secure_context_pipeline/crypto/tls.key", dockerignore)
    assert _dockerignored("data/blob.enc", dockerignore)
    # `data/` stays root-anchored on purpose, and this is the guard that stops a future
    # tidy-up sweeping it into `**/data/`: the gazetteers live under a nested data/ and
    # must still ship, or the detector loses every gazetteer-backed entity type.
    assert not _dockerignored("secure_context_pipeline/detection/data/diagnoses.txt", dockerignore)

    # Nothing may bake a key into the image config either. Only the directives
    # that can actually put a value in a layer are searched -- ``ENV``, ``ARG``
    # and ``RUN``. Scanning the whole file would forbid the *word*, which reads
    # as a win but is not one: it cannot tell a baked-in credential from the
    # comment explaining why baking one in is forbidden, and the comment is the
    # more useful of the two.
    baking = [
        stripped
        for line in dockerfile.splitlines()
        if (stripped := line.strip()).upper().startswith(("ENV ", "ARG ", "RUN "))
    ]
    for directive in baking:
        for name in ("SCP_MASTER_KEY", "ANTHROPIC_API_KEY"):
            assert name not in directive, f"secret baked into a layer: {directive}"


async def test_dockerfile_runs_unprivileged_and_declares_a_healthcheck() -> None:
    """Two hardening steps that were asserted in a comment and nowhere else.

    Without ``USER``, the image runs as root: a process that reads every
    document's ciphertext and holds the master key in its environment would also
    own the bind-mounted ``./data`` on the host. Without ``HEALTHCHECK``, an
    orchestrator cannot tell "listening" from "the spaCy model failed to load and
    every request 503s", which is precisely the failure ``/health`` was built to
    report -- ``_build_services`` deliberately boots anyway so the failure is
    *reportable*, and that only pays off if something asks.

    **``!= "root"`` was not the check it looked like.** Docker resolves ``USER``
    by name *or* by id, so ``USER 0`` is root spelled differently and passed a
    string comparison against ``"root"`` unchanged -- as did ``USER 10001:0``,
    which keeps the uid but takes the root *group*. What is asserted instead is
    the property the rest of the file depends on: the final ``USER`` names the
    account ``useradd`` created (by name or by its uid), and neither its user nor
    its group half is uid/gid 0. That is not a stylistic preference -- ``/app``
    and the data volume are chowned to exactly that account, so any other value
    is simultaneously a privilege bug and a broken mount.
    """
    lines = [
        stripped
        for line in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
        if (stripped := line.strip())
    ]

    # The account has to exist with a fixed, non-zero uid: a bind-mounted volume
    # is chowned to it, and a uid that drifts between builds breaks the mount.
    useradd = [line for line in lines if "useradd" in line]
    assert useradd, "the runtime user must be created explicitly"
    assert "--uid 10001" in useradd[0], useradd[0]
    # `RUN useradd --create-home --uid 10001 scp \` -- drop the continuation.
    created_account = useradd[0].rstrip("\\").split()[-1]
    created_uid = useradd[0].split("--uid", 1)[1].split()[0]
    assert created_uid != "0", useradd[0]

    user_lines = [line for line in lines if line.upper().startswith("USER ")]
    assert user_lines, "the container must not run as root"
    account, _, group = user_lines[-1].split()[1].partition(":")
    assert account not in ("root", "0"), (
        f"USER resolves to uid 0: {user_lines[-1]!r} -- docker accepts a numeric id, "
        f"so comparing against the string 'root' does not exclude root"
    )
    assert group not in ("root", "0"), (
        f"USER takes the root group: {user_lines[-1]!r} -- /app is chowned to "
        f"{created_account}:{created_account}, so gid 0 is both a privilege bug and a "
        f"broken volume"
    )
    assert account in (created_account, created_uid), (
        f"USER {account!r} is not the account useradd created "
        f"({created_account!r}/uid {created_uid!r}); the data volume is chowned to that one"
    )

    healthcheck = [line for line in lines if line.upper().startswith("HEALTHCHECK")]
    assert healthcheck, "the image must declare a HEALTHCHECK"
    assert "--start-period" in healthcheck[0], (
        "en_core_web_lg takes tens of seconds to load; without a start period the "
        "container is killed while it is still warming up"
    )
    assert "/health" in "\n".join(lines), "the healthcheck must probe /health"


async def test_multipart_dependency_is_declared_or_the_app_cannot_boot() -> None:
    """``python-multipart`` is a *boot* dependency, not a lazy import.

    ``POST /documents`` takes ``File``/``Form``, and FastAPI checks for the
    parser while it analyses the route's dependencies -- i.e. inside the
    ``@app.post`` decorator, at ``create_app()``. So a missing declaration is not
    a 500 on first upload that someone notices in staging; it is a container that
    exits before it ever listens. Asserted both ways: the declaration is present,
    and its absence really is fatal at registration.

    **"The substring is present" is not the property.** ``pip`` does not install
    a declaration; it installs one whose *environment marker* evaluates true and
    whose specifier a real version satisfies. Appending ``; python_version<'3'``
    leaves the substring, the file, and this test untouched while guaranteeing the
    wheel is never installed -- so the image builds, the container starts, and
    ``create_app()`` raises at import. The declaration is therefore parsed and
    evaluated the way the installer does, and checked against what is actually
    installed here.
    """
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declarations = [Requirement(text) for text in pyproject["project"]["dependencies"]]
    multipart = [
        requirement
        for requirement in declarations
        if requirement.name.lower().replace("_", "-") == "python-multipart"
    ]
    assert len(multipart) == 1, (
        "python-multipart must be a runtime dependency exactly once: pip install . "
        f"in the Dockerfile is what puts it in the image -- got {multipart}"
    )
    requirement = multipart[0]
    assert requirement.marker is None or requirement.marker.evaluate(), (
        f"{requirement} carries an environment marker that is false here, so pip "
        f"never installs it and the container boot-fails inside create_app()"
    )
    installed = importlib.metadata.version("python-multipart")
    assert requirement.specifier.contains(installed, prereleases=True), (
        f"{requirement} is not satisfied by the installed {installed}"
    )

    # And the failure mode is registration-time, which is what makes the
    # declaration load-bearing rather than a nicety.
    blocked = {"python_multipart": None, "multipart": None}
    with mock.patch.dict(sys.modules, blocked):
        with pytest.raises(RuntimeError, match="python-multipart"):
            create_app()


async def test_lifespan_sweeps_the_orphans_left_by_the_previous_process(
    api_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Session keys die with the process, so every vault row outlives its key.

    Left in place they are undecryptable garbage that still makes a dead
    ``session_id`` look live. The store's counterpart is worse: ``put`` writes
    blobs before it commits the metadata row, so a SIGKILL strands files that
    nothing points at -- unreachable *and* uncollectable, because ``doc_id`` only
    ever comes from a row. Both sweeps run in the lifespan, and nothing asserted
    that they were still wired in.
    """
    from secure_context_pipeline.api import app as app_module

    swept_sessions: list[frozenset[str]] = []
    swept_blobs: list[bool] = []
    real_vault_sweep = app_module.SessionVault.sweep_orphans
    real_store_sweep = app_module.EncryptedDocumentStore.sweep_orphans

    async def spy_vault(self: Any, known_session_ids: Any) -> int:
        known = frozenset(known_session_ids)
        swept_sessions.append(known)
        return await real_vault_sweep(self, known)

    async def spy_store(self: Any, **kwargs: Any) -> int:
        swept_blobs.append(True)
        return await real_store_sweep(self, **kwargs)

    monkeypatch.setattr(app_module.SessionVault, "sweep_orphans", spy_vault)
    monkeypatch.setattr(app_module.EncryptedDocumentStore, "sweep_orphans", spy_store)

    fresh = create_app(api_settings)
    async with fresh.router.lifespan_context(fresh):
        pass

    assert swept_sessions == [frozenset()], (
        "the vault sweep must run at startup, against the live session set -- "
        "which is empty, because keys never survive a restart"
    )
    assert swept_blobs == [True], "the store's stranded-blob sweep must run at startup"


async def test_the_demo_ui_sends_the_credentials_every_route_requires() -> None:
    """The UI is a client of the same contract, and it can silently fall behind.

    ``GET /audit`` now takes a ``user_id`` and proves it. A UI that omits it does
    not break loudly -- ``loadAudit`` swallows the error and renders an empty
    table -- so the audit panel would just quietly stop working, which is exactly
    the sort of "still green, visibly broken" gap a live demo trips over.
    """
    app_js = (REPO_ROOT / "secure_context_pipeline" / "ui" / "app.js").read_text(encoding="utf-8")
    audit_call = app_js.split("'/audit?session_id='", 1)
    assert len(audit_call) == 2, "the UI must query the audit log"
    request = audit_call[1].split(";", 1)[0]
    assert "user_id" in request, "the UI's audit query must present a user_id"

    # Logout is owner-scoped too, and the same silence applies.
    #
    # Was ``"'?user_id=' + encodeURIComponent(userId())" in app_js``. The requirement
    # is unchanged and is still asserted; the exact expression it was pinned to was
    # itself the defect. ``userId()`` re-reads the live input field, so a field
    # retyped mid-demo sent a NON-OWNER delete -- which this route answers 204 while
    # destroying nothing, deliberately, because 204 must not be an ownership oracle --
    # and the UI printed "gone, irreversibly" over a session that then ran again with
    # 200. The UI sends the owner captured at create instead. Narrowed to the logout
    # URL and strengthened: the field reader must not be what scopes it.
    logout = app_js.split("await api('DELETE', '/sessions/'", 1)
    assert len(logout) == 2, "the UI must call the logout route"
    logout_url = logout[1].split(";", 1)[0]
    assert "'?user_id=' + encodeURIComponent(" in logout_url, (
        "the UI's logout must present a user_id"
    )
    assert "userId()" not in logout_url, (
        "logout must be scoped by the owner recorded for the session, not by the live field"
    )


# ---------------------------------------------------------------------------
# 14. Request bodies: the cap has to precede the allocation
# ---------------------------------------------------------------------------
async def _streamed(total_bytes: int, counter: list[int]) -> AsyncIterator[bytes]:
    """Yield ``total_bytes`` in 256 KiB chunks, recording how many were pulled.

    The count is the whole point: a server that answers 413 after reading
    everything and one that stops reading are indistinguishable by status code,
    and it is the second that bounds memory.
    """
    chunk = b"A" * (256 * 1024)
    sent = 0
    while sent < total_bytes:
        take = min(len(chunk), total_bytes - sent)
        counter[0] += take
        sent += take
        yield chunk[:take]


async def test_a_json_body_is_capped_while_it_arrives_not_after(
    client: AsyncClient,
) -> None:
    """``POST /sessions`` is anonymous and had no body limit at all.

    ``user_id`` is capped at 64 characters, which looks like the bound and is
    not one: pydantic can only reject a value FastAPI has already built, and
    FastAPI builds it from ``await request.body()`` -- the whole payload,
    materialised first. Measured on this build before the fix: one anonymous
    request streaming a 256 MB body returned the correct ``422
    VALIDATION_ERROR`` after the process had grown by 768 MB. The status code
    was right and the server was the attacker's to size.

    So the assertion is on how much of the body the transport was asked for, not
    on the status code, because the status code cannot tell the two
    implementations apart.
    """
    pulled = [0]
    oversize = MAX_BODY_BYTES + (16 * 1024 * 1024)
    response = await client.post(
        "/sessions",
        content=_streamed(oversize, pulled),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413, response.text
    body = response.json()
    assert body["code"] == "REQUEST_TOO_LARGE", body
    assert set(body["detail"]) == {"max_bytes", "bytes"}, body
    assert body["detail"]["max_bytes"] == MAX_BODY_BYTES
    # Nothing of the caller's content, only their own byte total.
    assert isinstance(body["detail"]["bytes"], int)

    assert pulled[0] < oversize, "the whole body was read before it was refused"
    assert pulled[0] <= MAX_BODY_BYTES + (256 * 1024), pulled[0]

    # The mechanism is not the whole control. Every assertion above is relative
    # to ``MAX_BODY_BYTES``, so they all stay green if the ceiling is raised to a
    # gigabyte -- which is a cap in name only and still an out-of-memory
    # primitive. The value is pinned too: the ceiling exists to admit one legal
    # upload plus its multipart framing, and nothing else.
    assert MAX_UPLOAD_BYTES < MAX_BODY_BYTES <= 2 * MAX_UPLOAD_BYTES, MAX_BODY_BYTES

    # And the refusal is still a first-class response: same error shape, same
    # security headers as every other path.
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_a_declared_content_length_over_the_ceiling_is_refused_unread(
    client: AsyncClient,
) -> None:
    """The cheap half: an honest client is turned away before it sends anything."""
    pulled = [0]
    oversize = MAX_BODY_BYTES + 4096
    response = await client.post(
        "/sessions",
        content=_streamed(oversize, pulled),
        headers={
            "content-type": "application/json",
            "content-length": str(oversize),
        },
    )
    assert response.status_code == 413, response.text
    assert response.json()["code"] == "REQUEST_TOO_LARGE"
    assert response.json()["detail"]["bytes"] == oversize
    assert pulled[0] == 0, "a declared over-length body must not be read at all"


async def test_a_normal_request_is_untouched_by_the_body_limit(
    client: AsyncClient,
) -> None:
    """The limit must not be reachable by anything a real client sends."""
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    assert (await _run(client, session_id, doc_id)).status_code == 200

    # A file just under the upload ceiling still reaches the route's own check,
    # which is the one that names the *upload* limit rather than the body limit.
    near_ceiling = await client.post(
        "/documents",
        files={"file": ("big.txt", b"A" * (MAX_UPLOAD_BYTES + 1024), "text/plain")},
        data={"user_id": OWNER},
    )
    assert near_ceiling.status_code == 413
    assert near_ceiling.json()["code"] == "UPLOAD_TOO_LARGE", (
        "the body limit must sit far enough above the upload limit that multipart "
        "framing cannot push a legal upload over it"
    )


async def test_an_upload_declares_its_size_even_with_no_content_length(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Which of the two upload caps actually fires, asserted rather than assumed.

    ``MAX_UPLOAD_BYTES`` was documented as "enforced by ``_read_capped`` while
    the body is consumed, not only against a declared ``Content-Length``", and
    ``_read_capped`` was documented as the control that holds when the client
    withholds that header. Both were backwards. Starlette's multipart parser
    increments ``UploadFile.size`` on every write, so the handler knows the exact
    size before it reads a byte -- even for a chunked upload that declared no
    length -- and the pre-check refuses first every time. ``_read_capped``'s own
    test builds an ``UploadFile`` with ``size=None`` and so never exercises the
    route's path.

    Nothing here loosens either control; it pins which one is load-bearing, so
    the next person to delete "the redundant one" finds out from a test rather
    than from a 2 GB resident set.
    """
    from secure_context_pipeline.api import app as app_module

    observed: list[int | None] = []
    real = app_module._read_capped

    async def spy(upload: UploadFile) -> bytes:
        observed.append(upload.size)
        return await real(upload)

    monkeypatch.setattr(app_module, "_read_capped", spy)

    pulled = [0]

    async def body() -> AsyncIterator[bytes]:
        yield (
            b'--B\r\nContent-Disposition: form-data; name="user_id"\r\n\r\n'
            + OWNER.encode()
            + b'\r\n--B\r\nContent-Disposition: form-data; name="file"; '
            b'filename="ok.txt"\r\nContent-Type: text/plain\r\n\r\n'
        )
        async for chunk in _streamed(512 * 1024, pulled):
            yield chunk
        yield b"\r\n--B--\r\n"

    # No content-length: httpx streams this chunked.
    response = await client.post(
        "/documents",
        content=body(),
        headers={"content-type": "multipart/form-data; boundary=B"},
    )
    assert response.status_code == 200, response.text
    assert observed == [512 * 1024], (
        "UploadFile.size must be populated for a chunked multipart upload -- the "
        "route's pre-check depends on it"
    )


async def test_lifespan_unwinds_in_reverse_order_and_on_cancellation(
    api_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two claims ``_build_services`` makes that nothing was checking.

    Its handler is written ``await _close_quietly(reversed(opened))`` inside
    ``except BaseException``, and both halves of that line were free: the suite
    stayed green with the unwinding done in *forward* order, and stayed green
    with ``BaseException`` narrowed to ``Exception``. The second is the one that
    matters -- ``asyncio.CancelledError`` is a ``BaseException``, a startup
    cancelled by a shutdown signal or a failing readiness probe is the ordinary
    case rather than the exotic one, and an unwind that skips it leaves aiosqlite
    worker threads running. Those threads are not daemons, so the interpreter
    cannot exit: the process hangs instead of reporting why it failed to start.
    (Measured: with the unwinding removed entirely, this file's own pytest
    process never exited and had to be killed.)

    Reverse order is asserted because it is documented, and because LIFO is the
    only teardown order that stays correct if a later resource ever comes to
    depend on an earlier one.
    """
    from secure_context_pipeline.api import app as app_module

    for failure in (OSError("data directory is read-only"), asyncio.CancelledError()):
        closed: list[str] = []
        real_audit_close = app_module.AuditLogger.close
        real_store_close = app_module.EncryptedDocumentStore.close

        async def audit_close(
            self: Any, _real: Any = real_audit_close, _log: list[str] = closed
        ) -> None:
            _log.append("audit")
            await _real(self)

        async def store_close(
            self: Any, _real: Any = real_store_close, _log: list[str] = closed
        ) -> None:
            _log.append("store")
            await _real(self)

        async def vault_open(_path: Any, _registry: Any, _exc: BaseException = failure) -> Any:
            raise _exc

        monkeypatch.setattr(app_module.AuditLogger, "close", audit_close)
        monkeypatch.setattr(app_module.EncryptedDocumentStore, "close", store_close)
        monkeypatch.setattr(app_module.SessionVault, "open", vault_open)

        failing_app = create_app(api_settings)
        with pytest.raises(type(failure)):
            async with failing_app.router.lifespan_context(failing_app):
                pass  # pragma: no cover -- the lifespan raises before the body runs

        assert closed == ["store", "audit"], (
            f"{type(failure).__name__}: everything opened must be closed, newest "
            f"first -- got {closed}"
        )
        monkeypatch.undo()


async def test_identifier_comparison_is_constant_time_over_bytes() -> None:
    """``_same_id`` guards two ownership checks and both compare a secret-ish
    string against an attacker-supplied one.

    Rewriting it as ``claimed == actual`` keeps every other test in this file
    green, which is the whole reason this one exists: ``==`` on ``str`` exits at
    the first differing character, so the owner's ``user_id`` can be recovered
    one character at a time by an attacker who can time the reply -- and the
    reply is a ``401`` or an empty audit page that anyone may request, without
    limit. There is no behavioural difference to assert, so the assertion is that
    the comparison is routed through :func:`secrets.compare_digest`, and over
    ``bytes`` rather than ``str``: the ``str`` form raises ``TypeError`` on any
    non-ASCII input, which was itself an unauthenticated 500.
    """
    from secure_context_pipeline.api import app as app_module

    seen: list[tuple[type, type]] = []
    real = secrets.compare_digest

    def spy(left: Any, right: Any) -> bool:
        seen.append((type(left), type(right)))
        return bool(real(left, right))

    with mock.patch.object(app_module.secrets, "compare_digest", spy):
        assert app_module._same_id("alice", "alice") is True
        assert app_module._same_id("alice", "mallory") is False
        # Non-ASCII on either side must still reach compare_digest, not raise.
        assert app_module._same_id("josé", "josé") is True
        assert app_module._same_id("josé", "alice") is False

    assert len(seen) == 4, "every comparison must go through compare_digest"
    assert all(pair == (bytes, bytes) for pair in seen), seen


# ---------------------------------------------------------------------------
# 15. Ceilings and policies pinned by value, not only by mechanism
#
# Every test below exists because a mutation to a documented control left the
# rest of this file green. The pattern in all of them is the same: the control
# was asserted *relative to the constant that expresses it*, so changing the
# constant changed the control and the assertion together and nothing could see
# it. Each one therefore pins an absolute, externally meaningful value -- a byte
# count, a row count, a directive -- observed over HTTP wherever that is possible.
# ---------------------------------------------------------------------------
def _csp_directives(policy: str) -> dict[str, tuple[str, ...]]:
    """A CSP string parsed into ``{directive: (source, ...)}``."""
    parsed: dict[str, tuple[str, ...]] = {}
    for directive in policy.split(";"):
        parts = directive.split()
        if parts:
            parsed[parts[0].lower()] = tuple(parts[1:])
    return parsed


async def test_the_content_security_policy_is_restrictive_in_every_directive(
    client: AsyncClient,
) -> None:
    """``CONTENT_SECURITY_POLICY`` appeared in no assertion in this file at all.

    ``test_security_headers_are_sent_on_every_response`` checks that the header
    is *present* and names ``frame-ancestors 'none'`` and ``default-src 'none'``;
    it says nothing about the other six directives. So the policy could be
    rewritten to ``script-src https:`` -- which permits a script from any host on
    the internet, on a page whose entire premise is that nothing about a document
    reaches a third party -- or to ``base-uri 'self'`` and ``form-action 'self'``,
    and the suite stayed at 39 passed. Both mutations were run; both were green.

    Every directive is pinned to a value, and the values are pinned by a *rule*
    rather than a snapshot: no source may name a host, a scheme or a wildcard, so
    only ``'none'`` and ``'self'`` are admissible spellings at all.

    The last assertion is the one that keeps the two copies of the policy honest.
    ``ui/index.html`` carries the same policy in a ``<meta http-equiv>``, because
    a meta policy is what governs the document itself; the header exists because
    a meta policy governs *only* that document (never ``app.js``, never a JSON
    body) and because ``frame-ancestors`` is ignored in meta by specification.
    Two copies of one policy is two things that can drift apart -- and widening
    only the meta copy was also green -- so they are required to agree exactly,
    modulo the one directive that cannot be expressed in meta.
    """
    response = await client.get("/")
    assert response.status_code == 200, response.text
    header = _csp_directives(response.headers["content-security-policy"])

    # 'none' is a *deny*: default-src is the fallback for every fetch directive
    # not named; base-uri stops a <base> tag from re-pointing every relative URL
    # on the page; form-action stops a form POST to anywhere; frame-ancestors is
    # the clickjacking control, and "Destroy session" is one click from an
    # irreversible cryptographic erasure.
    for directive in ("default-src", "base-uri", "form-action", "frame-ancestors"):
        assert header.get(directive) == ("'none'",), (directive, header.get(directive))
    # 'self' is same-origin only: the page's own script, style, XHR and images.
    for directive in ("script-src", "style-src", "connect-src", "img-src"):
        assert header.get(directive) == ("'self'",), (directive, header.get(directive))

    assert set(header) == {
        "default-src",
        "base-uri",
        "form-action",
        "frame-ancestors",
        "script-src",
        "style-src",
        "connect-src",
        "img-src",
    }, sorted(header)

    for directive, sources in header.items():
        for source in sources:
            assert source in ("'none'", "'self'"), (
                f"{directive} {source!r} names a host, scheme or wildcard; the "
                f"container needs no network and the page must reach nothing"
            )

    meta_attribute = response.text.split('http-equiv="Content-Security-Policy"', 1)[1]
    meta = _csp_directives(meta_attribute.split('content="', 1)[1].split('"', 1)[0])
    assert meta == {
        directive: sources
        for directive, sources in header.items()
        if directive != "frame-ancestors"
    }, (meta, header)


async def test_the_audit_page_ceiling_is_an_absolute_number_of_rows(
    client: AsyncClient,
) -> None:
    """``MAX_AUDIT_PAGE`` also appeared in no assertion in this file.

    ``limit`` is declared ``Query(ge=1, le=MAX_AUDIT_PAGE)``, and both halves of
    that were free: deleting ``le=MAX_AUDIT_PAGE`` was green, and so was raising
    the constant to 1_000_000_000 -- measured, ``limit=1000000000`` went from
    ``422`` to ``200``. The log is append-only and unbounded, and this route is
    anonymous, so an unbounded page size is a request that decides how many rows
    the process materialises and serialises.

    The probes are absolute numbers, deliberately not written in terms of
    ``MAX_AUDIT_PAGE``: an assertion phrased relative to the constant is exactly
    what the constant's mutation satisfies.
    """
    session_id = await _create_session(client)
    scope = {"session_id": session_id, "user_id": OWNER}

    at_the_ceiling = await client.get("/audit", params={**scope, "limit": MAX_AUDIT_PAGE})
    assert at_the_ceiling.status_code == 200, at_the_ceiling.text

    for limit in (MAX_AUDIT_PAGE + 1, 10_001, 100_000, 1_000_000_000):
        refused = await client.get("/audit", params={**scope, "limit": limit})
        assert refused.status_code == 422, (limit, refused.status_code, refused.text)
        assert refused.json()["code"] == "VALIDATION_ERROR", (limit, refused.text)

    assert 1 <= DEFAULT_AUDIT_PAGE <= MAX_AUDIT_PAGE <= 10_000, (
        DEFAULT_AUDIT_PAGE,
        MAX_AUDIT_PAGE,
    )


async def test_an_audit_offset_past_sqlites_integer_range_is_refused_with_the_headers_on(
    client: AsyncClient,
) -> None:
    """``limit`` had a ceiling; ``offset`` was ``Query(ge=0)`` with none.

    ``AuditLogger.query`` binds ``offset`` straight into SQLite, whose
    ``INTEGER`` is signed 64-bit. Measured on this build:
    ``offset=9223372036854775807`` answered ``200`` and an empty page, and that
    value ``+1`` raised ``OverflowError: Python int too large to convert to
    SQLite INTEGER``. ``_register_handlers`` registers ``PipelineError``,
    ``ApiError``, ``RequestValidationError`` and ``HTTPException`` -- nothing
    covers ``OverflowError`` -- so it left the app entirely and Starlette's
    ``ServerErrorMiddleware``, which sits *outside* ``_SecurityHeaders``,
    answered a bare ``text/plain`` ``500 Internal Server Error`` and logged a
    full traceback. Two anonymous requests reached it: ``POST /sessions`` mints a
    session for any ``user_id`` named, and ``GET`` is not in ``METERED_METHODS``
    while a *successful* scope proof charges no meter, so the repeat was free.

    **The headers are asserted, not just the status**, and that is the whole
    point of this test rather than padding: the 500 carried no
    ``content-security-policy``, no ``x-content-type-options`` and no
    ``referrer-policy``, because the failure mode was specifically an exception
    escaping the middleware stack. A test that checked only for "not a 500"
    would pass against a 500 that had merely been given a nicer body.

    The probes are absolute integers, deliberately not written in terms of
    ``MAX_AUDIT_OFFSET`` -- an assertion phrased relative to the constant is
    exactly what raising the constant satisfies, which is the same trap
    ``test_the_audit_page_ceiling_is_an_absolute_number_of_rows`` records.
    """
    session_id = await _create_session(client)
    scope = {"session_id": session_id, "user_id": OWNER}

    at_the_ceiling = await client.get(
        "/audit", params={**scope, "offset": 9_223_372_036_854_775_807}
    )
    assert at_the_ceiling.status_code == 200, at_the_ceiling.text
    assert at_the_ceiling.json()["offset"] == 9_223_372_036_854_775_807

    for offset in (9_223_372_036_854_775_808, 18_446_744_073_709_551_616, 10**30):
        refused = await client.get("/audit", params={**scope, "offset": offset})
        assert refused.status_code == 422, (offset, refused.status_code, refused.text)
        assert refused.json() == {
            "code": "VALIDATION_ERROR",
            "detail": {"errors": 1, "fields": "query.offset"},
        }, (offset, refused.text)
        assert refused.headers["content-type"].startswith("application/json"), offset
        assert "frame-ancestors 'none'" in refused.headers["content-security-policy"], offset
        assert refused.headers["x-content-type-options"] == "nosniff", offset
        assert refused.headers["referrer-policy"] == "no-referrer", offset

    assert MAX_AUDIT_OFFSET == 9_223_372_036_854_775_807, MAX_AUDIT_OFFSET


async def test_a_nan_audit_window_is_refused_rather_than_silently_dropped(
    client: AsyncClient,
) -> None:
    """``since``/``until`` were bare ``float | None``, and pydantic accepts ``nan``.

    Python's ``sqlite3`` driver binds a ``NaN`` as SQL ``NULL``, so the guard
    ``(:since IS NULL OR ts >= :since)`` evaluated ``TRUE`` for every row and the
    bound was dropped entirely -- the request that asked for a window got the
    whole unfiltered page instead of the empty set a ``NaN`` comparison implies.

    Measured on this build against a session with one row: no window returned 1,
    ``since=9e99`` returned 0, ``since=inf`` returned 0, ``until=-inf`` returned
    0, and ``since=nan`` returned **1**. Every other value behaved; ``NaN`` was
    the single input where a compliance read reported a filter it was not
    applying, which is worse than refusing it.

    So the assertion that bites is not the status code but that the response is
    *not the unfiltered page*: a fix that answered 200-and-zero-rows would also
    be acceptable, and a regression back to 200-and-every-row is what this
    catches. ``inf``/``-inf`` are refused with ``nan`` because an infinite bound
    is expressible as no bound at all, and because ``canonical_json`` already
    refuses non-finite floats on the write side of this same log.
    """
    session_id = await _create_session(client)
    scope = {"session_id": session_id, "user_id": OWNER}

    unfiltered = await client.get("/audit", params=scope)
    assert unfiltered.status_code == 200, unfiltered.text
    assert unfiltered.json()["returned"] >= 1, unfiltered.text

    # A finite window still filters, and a finite window in the future is empty.
    future = await client.get("/audit", params={**scope, "since": 4_102_444_800.0})
    assert future.status_code == 200, future.text
    assert future.json()["returned"] == 0, future.text

    for param, value in (
        ("since", "nan"),
        ("since", "NaN"),
        ("until", "nan"),
        ("since", "inf"),
        ("until", "-inf"),
    ):
        refused = await client.get("/audit", params={**scope, param: value})
        assert refused.status_code == 422, (param, value, refused.status_code, refused.text)
        assert refused.json() == {
            "code": "VALIDATION_ERROR",
            "detail": {"errors": 1, "fields": f"query.{param}"},
        }, (param, value, refused.text)
        # The defect was never the status code -- it was that `nan` answered 200
        # with every row the unscoped read returns.
        assert refused.text != unfiltered.text, (param, value)
        assert "frame-ancestors 'none'" in refused.headers["content-security-policy"], (
            param,
            value,
        )
        assert refused.headers["x-content-type-options"] == "nosniff", (param, value)
        assert refused.headers["referrer-policy"] == "no-referrer", (param, value)


async def test_an_audit_scope_with_no_recorded_owner_reads_as_empty(
    client: AsyncClient, services: Services
) -> None:
    """``_audit_scope_owner`` returns ``None`` for a scope whose owner it cannot
    prove, and its docstring says callers "must treat that identically to a wrong
    owner: fail closed". Nothing checked the ``None`` half.

    The existing ownership tests all exercise the *wrong-owner* branch -- a real
    session created through ``POST /sessions``, queried by a stranger. Inverting
    ``if owner is None or not _same_id(...)`` to ``if owner is not None and
    not _same_id(...)`` leaves every one of them green, because for those scopes
    ``owner`` is never ``None``. What that inversion actually does is make every
    scope with *no* ``SESSION_CREATE`` row world-readable: rows written by
    machinery that did not come through the API, by a previous process, or by any
    path that emits before the session row lands. Measured with the inversion
    applied: this test's ``DETECT`` row came back to ``user_id=anyone-at-all``,
    ``doc_id`` and all, and ``/audit/verify`` went from ``length: 0`` to
    ``length: 1`` -- the existence oracle the uniform empty answer exists to deny.

    The row is proved to *be* in the log first. Without that, an empty answer is
    equally consistent with "the emit silently did nothing", and the test would
    pass for the wrong reason.
    """
    orphan_session = uuid.uuid4().hex
    orphan_run = uuid.uuid4().hex
    secret_doc = f"doc-{uuid.uuid4().hex}"
    await services.audit.emit(
        AuditEvent(
            ts=time.time(),
            session_id=orphan_session,
            run_id=orphan_run,
            event_type=DETECT,
            detail={"count": 3, "doc_id": secret_doc},
        )
    )
    written = await services.audit.query(session_id=orphan_session, limit=10)
    assert written, "the row must really be in the log, or an empty page proves nothing"
    assert written[0].detail["doc_id"] == secret_doc

    for params in (
        {"session_id": orphan_session, "user_id": OWNER},
        {"session_id": orphan_session, "user_id": INTRUDER},
        {"run_id": orphan_run, "user_id": OWNER},
        {"run_id": orphan_run, "user_id": INTRUDER},
    ):
        response = await client.get("/audit", params=params)
        assert response.status_code == 200, (params, response.text)
        assert response.json()["events"] == [], (params, response.text)
        assert secret_doc not in response.text, params
        assert orphan_session not in response.text, params
        assert orphan_run not in response.text, params

    verify = await client.get(
        "/audit/verify", params={"session_id": orphan_session, "user_id": OWNER}
    )
    assert verify.status_code == 200, verify.text
    assert verify.json()["length"] == 0, (
        "an unprovable scope must be indistinguishable from one that never existed"
    )
    assert verify.json()["valid"] is True, verify.text


async def test_an_oversize_upload_is_refused_before_a_byte_of_it_is_read(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Which control answers, and what it costs, both observable on the wire.

    Removing the ``file.size`` pre-check from ``upload_document`` was reported as
    the one fix with no behavioural difference to test, on the grounds that
    ``_read_capped`` produces the same ``413 UPLOAD_TOO_LARGE`` with the same
    detail keys. It does not: ``_read_capped`` stops one chunk past the ceiling,
    so ``detail.bytes`` becomes the read total -- ``16842752``, which is
    ``MAX_UPLOAD_BYTES`` rounded up to a whole ``UPLOAD_CHUNK_BYTES`` -- instead
    of the file's real size, a different number on the wire for the same request.
    And the handler buffers 16 MB to get there rather than refusing at zero cost.

    So this asserts both halves: the reported size is the upload's own, and
    ``_read_capped`` is never entered. ``_read_capped`` keeps its own test (the
    ``size is None`` case) and neither control is loosened here -- what is pinned
    is which of the two fires, and what that costs.
    """
    assert MAX_UPLOAD_BYTES <= 16 * 1024 * 1024, (
        "16 MB is the documented upload ceiling; raising the constant raises "
        "MAX_BODY_BYTES with it, and this test would then allocate whatever it names"
    )
    from secure_context_pipeline.api import app as app_module

    entered: list[int | None] = []
    real = app_module._read_capped

    async def spy(upload: UploadFile) -> bytes:
        entered.append(upload.size)
        return await real(upload)

    monkeypatch.setattr(app_module, "_read_capped", spy)

    oversize = MAX_UPLOAD_BYTES + 500_000
    assert oversize % UPLOAD_CHUNK_BYTES != 0, (
        "the size must not land on a chunk boundary, or the two controls would "
        "report the same number and this test could not tell them apart"
    )
    assert oversize + 4096 < MAX_BODY_BYTES, "the body limit must not be what answers here"

    response = await client.post(
        "/documents",
        files={"file": ("big.txt", b"A" * oversize, "text/plain")},
        data={"user_id": OWNER},
    )
    assert response.status_code == 413, response.text
    body = response.json()
    assert body["code"] == "UPLOAD_TOO_LARGE", body
    assert body["detail"]["max_bytes"] == MAX_UPLOAD_BYTES, body
    assert body["detail"]["bytes"] == oversize, (
        f"the 413 must report the upload's own size; {body['detail']['bytes']} is a "
        f"partial read total, which means the pre-check no longer fires"
    )
    assert entered == [], "an upload past the ceiling must not be read at all"

    # The backstop is still wired in and still names the same ceiling: a legal
    # upload goes all the way through the helper.
    ok = await client.post(
        "/documents",
        files={"file": ("small.txt", DOC_TEXT.encode("utf-8"), "text/plain")},
        data={"user_id": OWNER},
    )
    assert ok.status_code == 200, ok.text
    assert entered == [len(DOC_TEXT.encode("utf-8"))], entered


async def test_the_request_body_ceiling_is_an_absolute_number_of_bytes(
    client: AsyncClient,
) -> None:
    """The 413 is proved against a byte count that names neither constant.

    ``MAX_BODY_BYTES`` is *defined* as ``MAX_UPLOAD_BYTES + 1 MB``, and the body
    limit's own test asserts only ``MAX_UPLOAD_BYTES < MAX_BODY_BYTES <= 2 *
    MAX_UPLOAD_BYTES`` -- which a gigabyte satisfies. So changing one literal,
    ``MAX_UPLOAD_BYTES = 16 * 1024 * 1024`` to ``1024 * 1024 * 1024``, raised the
    request-body ceiling to 1 GB with the whole file still green, and measured
    with that mutation applied the anonymous 256 MB ``POST /sessions`` again
    returned ``422 VALIDATION_ERROR`` after the process grew by 537 MB. That is
    the out-of-memory primitive the limit was added to remove, restored by a
    one-token edit that every relative assertion in the file agrees with.

    A cap is a number of bytes, so the test sends a number of bytes.
    """
    assert MAX_UPLOAD_BYTES <= 16 * 1024 * 1024, MAX_UPLOAD_BYTES
    assert MAX_BODY_BYTES <= 24 * 1024 * 1024, MAX_BODY_BYTES

    sent = 24 * 1024 * 1024
    assert MAX_BODY_BYTES < sent
    pulled = [0]
    response = await client.post(
        "/sessions",
        content=_streamed(sent, pulled),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413, (
        f"a {sent}-byte anonymous body must be refused outright, not parsed and "
        f"then rejected: got {response.status_code} {response.text[:200]}"
    )
    assert response.json()["code"] == "REQUEST_TOO_LARGE", response.text
    assert pulled[0] < sent, "the whole body was read before it was refused"


async def test_caller_supplied_identifiers_are_bounded_at_the_boundary(
    client: AsyncClient,
) -> None:
    """``user_id`` at 64 characters is claimed in the module docstring; nothing
    checked it on a query parameter or a header.

    Deleting ``max_length=MAX_ID_LEN`` from ``UserIdQuery``, from ``DocIdPath``,
    from ``OptionalIdQuery`` and from the ``X-Session-Id`` header declaration were
    all green. None is cosmetic: these strings are compared in constant time
    against a recorded owner, echoed into structured error detail, and written
    into the audit log, and neither a query string, a path segment nor a header
    is covered by ``_BodyLimit`` -- they are bounded by the ASGI server's header
    ceiling, which is far larger.

    The three declarations are asserted separately because they are separate
    declarations: dropping the cap on ``DocIdPath`` alone left every other probe
    here answering 422 while ``GET /documents/<5000 characters>/text`` went from
    ``422 VALIDATION_ERROR`` to ``404`` and ``DELETE /sessions/<5000 characters>``
    to ``204`` -- measured. Nothing crashes at that length *today*, but only
    because ``StoreAuthError`` truncates its own detail; the module docstring's
    reason for the ceiling is that an over-long identifier must never reach
    ``PipelineError``'s constructor, and "another component happens to truncate
    it" is precisely the kind of guarantee this codebase does not accept.

    The last two assertions pin ``_clamp``, which is the reason an over-long
    identifier could never reach ``PipelineError``'s own 64-character check and
    raise a ``ValueError`` from inside the error constructor -- i.e. turn a
    handled 401 into an unhandled 500. Making ``_clamp`` the identity function is
    invisible over HTTP *today*, and only because ``MAX_ID_LEN`` happens to equal
    ``MAX_DETAIL_VALUE_LEN``; that coincidence is asserted rather than assumed,
    because it is what makes the whole route safe.
    """
    from secure_context_pipeline.api import app as app_module

    over = "z" * (MAX_ID_LEN + 1)
    probes = [
        # UserIdQuery
        await client.get("/audit", params={"session_id": "s", "user_id": over}),
        await client.get(f"/documents/{uuid.uuid4().hex}/text", params={"user_id": over}),
        await client.delete(f"/sessions/{uuid.uuid4().hex}", params={"user_id": over}),
        # OptionalIdQuery
        await client.get("/audit", params={"session_id": over, "user_id": OWNER}),
        await client.get("/audit", params={"run_id": over, "user_id": OWNER}),
        await client.get("/audit/verify", params={"session_id": over, "user_id": OWNER}),
        # DocIdPath -- the path segment, not the query string
        await client.get(f"/documents/{over}/text", params={"user_id": OWNER}),
        await client.delete(f"/sessions/{over}", params={"user_id": OWNER}),
        # the X-Session-Id header
        await client.post(
            "/pipeline/run",
            json={"user_id": OWNER, "doc_id": uuid.uuid4().hex, "prompt": PROMPT},
            headers={"X-Session-Id": over},
        ),
    ]
    for response in probes:
        assert response.status_code == 422, (
            response.request.url,
            response.request.headers.get("x-session-id", ""),
            response.status_code,
            response.text,
        )
        assert response.json()["code"] == "VALIDATION_ERROR", response.text
        # And the rejection does not echo the offending value back.
        assert over not in response.text

    # The *floor* is load-bearing too, and for a reason that is easy to lose.
    # ``_resolve_audit_scope`` answers ``owner=None`` for a scope whose owner it
    # cannot prove, and both callers reject that before comparing. Returning ``""``
    # there instead of ``None`` -- an ordinary-looking fail-open edit -- is
    # byte-identical over HTTP on every route, but *only* because an empty
    # ``user_id`` is unsendable: ``min_length=1`` rejects it on ``GET /audit``
    # and the ``user_id_required_with_session_id`` guard rejects it on
    # ``/audit/verify``. Those two are what make the empty string unreachable, so
    # they are asserted rather than relied on.
    blank = await client.get("/audit", params={"session_id": "s", "user_id": ""})
    assert blank.status_code == 422, blank.text
    blank_verify = await client.get("/audit/verify", params={"session_id": "s", "user_id": ""})
    assert blank_verify.status_code == 400, blank_verify.text
    assert blank_verify.json()["code"] == "AUDIT_SCOPE_REQUIRED", blank_verify.text

    assert MAX_ID_LEN <= MAX_DETAIL_VALUE_LEN, (
        "an identifier the schema admits must fit in a structured error detail, or "
        "PipelineError raises ValueError from inside an exception handler"
    )
    assert app_module._clamp("y" * 500) == "y" * MAX_DETAIL_VALUE_LEN
    assert len(app_module._clamp("y" * 500)) == MAX_DETAIL_VALUE_LEN


# ---------------------------------------------------------------------------
# 16. The interim window before real authentication is metered and loud
#
# ``user_id`` is asserted, not proven -- that is take-home scope and the module
# docstring says so. What was NOT scope was that the window be *silent*: the
# audit-scope proof answered right-or-wrong about a human-readable username with
# no delay, no lockout and no record, so a dictionary attack against a leaked
# ``run_id`` was free and invisible in the tamper-evident log it was aimed at.
# Measured before these tests existed: 500 wrong guesses -> 500 identical empty
# 200s, 0.86 ms each, ZERO rows written; the 501st (the real owner) returned the
# run's events including its ``doc_id``, and that ``doc_id`` plus the guessed
# username read the victim's plaintext.
#
# Every test below drives its own meters through ``app.state.rate_limits`` and
# restores them, so exhausting a budget here cannot starve another test.
# ---------------------------------------------------------------------------
def _wide_meter() -> Any:
    """A meter that cannot fire, for the axis a test is *not* exercising."""
    return app_module._RateLimiter(capacity=1_000_000, refill_per_second=1_000_000.0)


def _tight_meter(capacity: int) -> Any:
    """``capacity`` tokens and effectively no refill for the length of a test."""
    return app_module._RateLimiter(capacity=capacity, refill_per_second=1e-9)


@contextlib.contextmanager
def _meters(app: FastAPI, *, writes: Any = None, audit_proofs: Any = None) -> Any:
    """Install fresh meters for one test and put the originals back.

    Always *fresh*: reusing the module-scoped buckets would let one test spend
    another's budget, and the whole file shares one app (and therefore one
    caller key -- ``ASGITransport`` reports the same client for every request).
    """
    original = app.state.rate_limits
    app.state.rate_limits = app_module._RateLimits(
        writes=writes if writes is not None else _wide_meter(),
        audit_proofs=audit_proofs if audit_proofs is not None else _wide_meter(),
    )
    try:
        yield
    finally:
        app.state.rate_limits = original


async def test_a_failed_audit_scope_proof_is_recorded_in_the_chain_it_attacks(
    app: FastAPI, client: AsyncClient
) -> None:
    """A wrong-user probe must leave a mark, and leave it where the victim looks.

    The ownership proof itself is correct and stays correct -- the response is
    still the byte-identical empty page, because answering 403 would restore the
    existence oracle. What is new is that the attempt is no longer *free of
    consequence*: it writes an ``AUDIT_ACCESS_DENIED`` row naming the claimed
    ``user_id``, filed under the session the scope resolved to, so the owner
    reads their own intruders out of ``GET /audit?session_id=...`` -- the very
    endpoint being attacked.

    Deleting the ``_deny_audit_scope`` call from ``query_audit`` restores the
    silence and fails here; so does filing the row under a scope the owner cannot
    read, which is the mistake that would make the record technically present and
    practically useless.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run = await _run(client, session_id, doc_id)
    assert run.status_code == 200, run.text
    run_id = run.json()["run_id"]

    owned = {"user_id": OWNER, "session_id": session_id}
    before = (await client.get("/audit", params={**owned, "limit": MAX_AUDIT_PAGE})).json()
    chain_before = (await client.get("/audit/verify")).json()["length"]

    with _meters(app):
        # Two probes: one naming the session directly, one naming only the run.
        by_session = await client.get(
            "/audit", params={"user_id": INTRUDER, "session_id": session_id}
        )
        by_run = await client.get("/audit", params={"user_id": INTRUDER, "run_id": run_id})
        by_verify = await client.get(
            "/audit/verify", params={"user_id": INTRUDER, "session_id": session_id}
        )

    # The answers are unchanged: still empty, still not a 403.
    assert by_session.status_code == 200 and by_session.json()["events"] == [], by_session.text
    assert by_run.status_code == 200 and by_run.json()["events"] == [], by_run.text
    assert by_verify.json() == {"valid": True, "length": 0, "session_id": session_id}

    # But three rows now exist that did not before, and the owner can see them.
    after = (await client.get("/audit", params={**owned, "limit": MAX_AUDIT_PAGE})).json()
    denies = [
        event for event in after["events"] if event["event_type"] == app_module.AUDIT_ACCESS_DENIED
    ]
    assert len(denies) == 3, (
        f"three denied probes must leave three rows the owner can read; got {len(denies)}. "
        f"before={before['returned']} after={after['returned']}"
    )
    assert all(row["detail"]["claimed_user_id"] == INTRUDER for row in denies), denies
    assert {row["detail"]["route"] for row in denies} == {"/audit", "/audit/verify"}, denies
    # The run-scoped probe is filed against the run it named, so a compliance
    # reader can correlate the attempt with the run that leaked the identifier.
    assert [row["run_id"] for row in denies].count(run_id) == 1, denies

    # The intruder still cannot read their own rows -- the record is for the
    # victim and the operator, and the probe is not its own oracle.
    theirs = await client.get("/audit", params={"user_id": INTRUDER, "session_id": session_id})
    assert theirs.json()["events"] == [], theirs.text

    # And the chain is still verifiable with the new rows in it: a monitoring
    # control that breaks tamper-evidence would be a downgrade, not a fix.
    verified = await client.get("/audit/verify")
    assert verified.json()["valid"] is True, verified.text
    assert verified.json()["length"] > chain_before, verified.text


async def test_audit_scope_guessing_is_throttled_but_the_owner_never_is(
    app: FastAPI, client: AsyncClient
) -> None:
    """The oracle is bounded per caller, and bounding it must not bound the owner.

    Both halves matter. Without the meter a 10 000-name dictionary against one
    held ``run_id`` costs about nine seconds; with it, the same dictionary is
    rationed to ``AUDIT_PROOF_REFILL_PER_SECOND`` answers a second. And because
    only *failures* are charged, the real owner's queries never touch the budget
    -- a meter that throttled correct answers would be denial of service dressed
    up as a control, and this test fails if someone reaches for that shortcut.

    The numbers are absolute rather than written in terms of the constants: an
    assertion phrased relative to ``AUDIT_PROOF_BURST`` is exactly what raising
    ``AUDIT_PROOF_BURST`` satisfies.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run_id = (await _run(client, session_id, doc_id)).json()["run_id"]

    with _meters(app, audit_proofs=_tight_meter(5)):
        statuses = [
            (
                await client.get("/audit", params={"user_id": f"guess{i}", "run_id": run_id})
            ).status_code
            for i in range(40)
        ]
        # Exactly five answered; every later guess is refused outright.
        assert statuses.count(200) == 5, statuses
        assert statuses[:5] == [200] * 5, statuses
        assert set(statuses[5:]) == {429}, statuses

        refused = await client.get("/audit", params={"user_id": "guess999", "run_id": run_id})
        assert refused.json()["code"] == "RATE_LIMITED", refused.text
        assert refused.json()["detail"]["retry_after_seconds"] > 0, refused.text

        # The owner is unaffected by the storm aimed at them.
        owner = await client.get("/audit", params={"user_id": OWNER, "run_id": run_id})
        assert owner.status_code == 200, owner.text
        assert owner.json()["returned"] > 0, owner.text

        # ...and the other audit route shares the budget, or the oracle just
        # moves one URL over.
        moved = await client.get(
            "/audit/verify", params={"user_id": "guess999", "session_id": session_id}
        )
        assert moved.status_code == 429, moved.text

    # With the meters restored the module's own budget is untouched.
    normal = await client.get("/audit", params={"user_id": OWNER, "run_id": run_id})
    assert normal.status_code == 200, normal.text


async def test_a_throttled_audit_probe_writes_no_row(app: FastAPI, client: AsyncClient) -> None:
    """The meter is charged *before* the record is written, and the order is the point.

    Recording a denied proof is a durable, anonymous write into a log that is
    append-only and unprunable by construction. Writing it first -- or writing it
    unconditionally -- would trade a silent oracle for the unbounded ``audit.db``
    growth that ``WRITE_BURST`` exists to bound: an attacker would simply keep
    probing to keep writing. Swapping the two statements in ``_deny_audit_scope``
    leaves every other assertion in this file green and fails here.
    """
    session_id = await _create_session(client)

    with _meters(app, audit_proofs=_tight_meter(2)):
        before = (await client.get("/audit/verify")).json()["length"]
        answered = 0
        for i in range(60):
            probe = await client.get(
                "/audit", params={"user_id": f"flood{i}", "session_id": session_id}
            )
            answered += probe.status_code == 200
        after = (await client.get("/audit/verify")).json()["length"]

    assert answered == 2, answered
    assert after - before == 2, (
        f"60 probes against a 2-token budget must write exactly 2 rows; wrote {after - before}. "
        f"A throttled probe that still records turns the monitoring control into the "
        f"disk-exhaustion primitive it was added alongside."
    )


@contextlib.contextmanager
def _walk_meter(app: FastAPI, capacity: int) -> Any:
    """Install a tight chain-walk meter for one test and put the original back.

    Held on ``app.state.audit_chain_walks`` rather than inside
    ``app.state.rate_limits``, so ``_meters`` does not reach it and this has to
    save and restore it separately -- the module shares one app, and a budget
    left spent here would throttle whichever test ran next.
    """
    original = getattr(app.state, "audit_chain_walks", None)
    app.state.audit_chain_walks = _tight_meter(capacity)
    try:
        yield
    finally:
        app.state.audit_chain_walks = original


async def test_the_chain_walk_is_bounded_per_caller_however_long_the_log_gets(
    app: FastAPI, client: AsyncClient, services: Services
) -> None:
    """``GET /audit/verify`` was anonymous *and* free, and only the first is by design.

    The route re-hashes every row in ``audit_events`` -- ``_CHAIN_SQL`` has no
    ``WHERE`` clause -- and the log is append-only and unprunable, so the cost of
    one request rises forever: measured on this build, 7.4 ms at 1 000 rows,
    35.2 ms at 5 000, 143.3 ms at 20 000, and 50 back-to-back anonymous calls all
    answered 200. ``GET`` is not in ``METERED_METHODS`` (nothing durable is
    written) and no scope proof is required (nothing is disclosed), so both
    existing meters reasoned past it: they bound *writes* and *guessing*, not
    *work*.

    The assertion that matters is the third one -- the number of chain walks
    actually performed, counted by wrapping ``AuditLogger.verify_chain`` itself.
    Counting 429s instead would only prove the meter answers 429; it would stay
    green if the handler walked the chain and *then* refused, which is the
    ordering half of this control. Nothing here reads the meter's own state, so
    the checker shares no machinery with the thing it checks.

    The scoped form is charged from the same bucket, because it is the same
    whole-chain walk: metering only the unscoped form would move the cost one
    query parameter over, which is the mistake ``AUDIT_PROOF_BURST`` already
    records for the oracle it bounds.

    ``test_a_long_log_costs_more_of_the_same_budget_than_a_short_one`` covers the
    other half -- that the price rises with the log -- which is what keeps this
    bound true as the append-only log grows.
    """
    session_id = await _create_session(client)
    walks = 0
    real_verify = services.audit.verify_chain

    async def counted_verify(scope: str | None = None) -> bool:
        nonlocal walks
        walks += 1
        return await real_verify(scope)

    with mock.patch.object(services.audit, "verify_chain", counted_verify), _walk_meter(app, 3):
        answers = [await client.get("/audit/verify") for _ in range(25)]
        statuses = [answer.status_code for answer in answers]
        # The owner-scoped form shares the exhausted budget: same walk, same cost.
        scoped = await client.get(
            "/audit/verify", params={"session_id": session_id, "user_id": OWNER}
        )

    assert statuses[:3] == [200] * 3, statuses
    assert set(statuses[3:]) == {429}, statuses
    assert walks == 3, (
        f"25 anonymous requests against a 3-token budget must cost 3 chain walks; cost {walks}. "
        f"A meter charged after the walk leaves every status-code assertion above green."
    )
    assert scoped.status_code == 429, scoped.text
    assert walks == 3, f"the scoped form must share the budget, not open a second one: {walks}"

    # The walks that were paid for covered a real, non-empty chain -- a bound that
    # holds because there was nothing to hash would prove nothing.
    assert answers[0].json()["length"] > 0, answers[0].text
    refused = answers[3].json()
    assert refused["code"] == "RATE_LIMITED", refused
    assert refused["detail"]["retry_after_seconds"] > 0, refused
    # Anonymous, and still anonymous: the refusal names nothing either.
    assert session_id not in answers[3].text

    # With the budget restored the tamper check still answers -- this is a bound
    # on cost, not an outage on the one publicly checkable claim in the system.
    restored = await client.get("/audit/verify")
    assert restored.status_code == 200, restored.text
    assert restored.json()["valid"] is True, restored.text


async def test_a_long_log_costs_more_of_the_same_budget_than_a_short_one(
    app: FastAPI, client: AsyncClient, services: Services
) -> None:
    """The price is rows of chain, not requests, and that is not a refinement.

    One token per request was built first and measured doing nothing: a burst of
    20 with one token per second, against a 20 000-row log, answered **all 50** of
    a back-to-back anonymous flood, because a walk that takes 752 ms refills its
    own token while it runs. The log is append-only and unprunable, so the walk
    gets slower forever while a request meter's ceiling stays put -- it reads as
    enforced while metering nothing.

    Both halves are driven through the same budget so the comparison means
    something: twelve tokens buys twelve walks of a short log and one walk of a
    50 000-row one. The long log is *reported* rather than written, and
    deliberately: appending 50 000 rows to the module's shared audit database
    would slow every later test in this file and change the chain length other
    tests measure deltas against. What is asserted is the route's own arithmetic
    against the count it is given, observed from outside by counting the walks
    that actually happened.
    """
    walks = 0
    real_verify = services.audit.verify_chain
    real_length = services.audit.length

    async def counted_verify(scope: str | None = None) -> bool:
        nonlocal walks
        walks += 1
        return await real_verify(scope)

    async def long_log(scope: str | None = None, **filters: Any) -> int:
        return 50_000 if scope is None and not filters else await real_length(scope, **filters)

    with mock.patch.object(services.audit, "verify_chain", counted_verify):
        with mock.patch.object(services.audit, "length", long_log), _walk_meter(app, 12):
            long_statuses = [(await client.get("/audit/verify")).status_code for _ in range(12)]
        long_walks = walks

        walks = 0
        with _walk_meter(app, 12):
            short_statuses = [(await client.get("/audit/verify")).status_code for _ in range(12)]
        short_walks = walks

        # The scoped form is priced by the *whole* log too, because it hashes the
        # whole log: ``verify_chain(session_id=...)`` narrows what it asserts on,
        # not what it reads. Pricing it by its own session's handful of rows would
        # hand any session owner the unbounded walk this meter just took away.
        walks = 0
        owned = {"session_id": await _create_session(client), "user_id": OWNER}
        with mock.patch.object(services.audit, "length", long_log), _walk_meter(app, 12):
            first_scoped = await client.get("/audit/verify", params=owned)
            second_scoped = await client.get("/audit/verify", params=owned)
        scoped_walks = walks

        # A log so long that the unclamped price exceeds any bucket. The price is
        # capped at the bucket's capacity, so a full bucket still buys exactly one
        # walk: an uncapped price would make a long enough chain permanently
        # unverifiable over HTTP, which is a silent end to the one claim this
        # system offers to be checked on -- a worse outcome than serving it slowly.
        walks = 0

        async def enormous_log(scope: str | None = None, **filters: Any) -> int:
            return 10_000_000 if scope is None and not filters else await real_length(scope)

        with mock.patch.object(services.audit, "length", enormous_log), _walk_meter(app, 12):
            enormous = await client.get("/audit/verify")
            starved = await client.get("/audit/verify")
        enormous_walks = walks

    assert long_walks == 1, (
        f"a 50 000-row chain must cost 11 of the 12 tokens, leaving room for one walk; "
        f"got {long_walks} walks and statuses {long_statuses}. A flat price per request "
        f"buys 12 -- and buys them faster the longer the log gets."
    )
    assert long_statuses.count(200) == 1, long_statuses
    assert set(long_statuses[1:]) == {429}, long_statuses

    # Same budget, same twelve requests, a log of a few hundred rows: all twelve.
    assert short_walks == 12, (short_walks, short_statuses)
    assert short_statuses == [200] * 12, short_statuses
    assert (await client.get("/audit/verify")).json()["length"] < 5_000, (
        "this file's shared log must stay under one token's worth of rows, or the "
        "contrast above is measuring the wrong thing"
    )

    assert first_scoped.status_code == 200, first_scoped.text
    assert scoped_walks == 1, (
        f"the owner-scoped form walks the whole chain, so it must be priced by the whole "
        f"chain: 12 tokens buys one 50 000-row walk, not two. Got {scoped_walks}, second "
        f"answer {second_scoped.status_code}."
    )
    assert second_scoped.status_code == 429, second_scoped.text

    assert enormous.status_code == 200, enormous.text
    assert enormous_walks == 1, (
        f"a full bucket must always buy one walk however long the log is; got "
        f"{enormous_walks}. An uncapped price makes the chain permanently unverifiable."
    )
    assert starved.status_code == 429, starved.text


async def test_every_mutating_route_is_metered_including_ones_added_later(
    app: FastAPI, client: AsyncClient
) -> None:
    """Enumerated from ``app.routes``, not from a hand-written list of paths.

    The recurring defect in this codebase is a checker that shares a blind spot
    with the thing it checks, so the write meter keys on the HTTP *method* and
    this test asks the application's own route table which routes that has to
    cover. Narrowing ``_RateLimit`` to an allow-list of paths -- the obvious
    "safer" edit -- fails here for whichever route the list forgets, and so does
    adding a new anonymous ``POST`` without thinking about it.

    Driven over HTTP with an empty budget rather than inspected: the claim is
    that the request is *refused*, and refused before it is read, which only the
    wire can show. No route needs credentials to demonstrate it, because the
    refusal happens in middleware, above the application entirely.
    """
    mutating = sorted(
        {
            (route.path, method)
            for route in app.routes
            if isinstance(route, APIRoute)
            for method in route.methods
            if method in {"POST", "PUT", "PATCH", "DELETE"}
        }
    )
    # Pinned by value so that *adding* a mutating route is a deliberate act:
    # the loop below then has to cover it, and this line is where someone
    # notices. Both anonymous ones are here, and so is the irreversible logout.
    assert mutating == [
        ("/documents", "POST"),
        ("/pipeline/run", "POST"),
        ("/sessions", "POST"),
        ("/sessions/{session_id}", "DELETE"),
    ], mutating

    with _meters(app, writes=_tight_meter(1)):
        first = await client.post("/sessions", json={"user_id": OWNER})
        assert first.status_code == 200, first.text  # the single token
        for path, method in mutating:
            url = re.sub(r"\{[^}]+\}", uuid.uuid4().hex, path)
            response = await client.request(method, url, params={"user_id": OWNER})
            assert response.status_code == 429, (method, url, response.status_code, response.text)
            assert response.json()["code"] == "RATE_LIMITED", (method, url, response.text)
            assert int(response.headers["retry-after"]) >= 1, (method, url, response.headers)
            # The 429 never reaches the application, so it is the outermost
            # middleware that must still stamp it -- an unframable, no-referrer
            # error page is not a nicety when the UI is one click from erasure.
            assert response.headers["content-security-policy"] == (
                app_module.CONTENT_SECURITY_POLICY
            ), (method, url, dict(response.headers))
            assert response.headers["referrer-policy"] == "no-referrer", (method, url)

        # Reads are deliberately NOT metered here: they write nothing durable,
        # and /audit carries its own tighter failure meter.
        assert (await client.get("/health")).status_code in (200, 503)


async def test_anonymous_durable_writes_are_bounded_and_the_body_is_never_read(
    app: FastAPI, client: AsyncClient
) -> None:
    """``POST /sessions`` needs no credential and appends to an unprunable log.

    Measured on the unmetered build: 3 000 anonymous session creations grew
    ``audit.db`` by 1 716 bytes *each*, never reclaimed -- pruning is precisely
    what tamper-evidence forbids -- and left 3 000 live sessions in memory for the
    full TTL. That is ~583 k requests to a gigabyte of rows a compliance system
    may not delete, and a full disk fails every later write for every user.

    Two properties, and the second is the one that is easy to get wrong: the
    refusal must happen *before* the body is read, or the cap describes the
    answer rather than the allocation -- the same mistake ``MAX_BODY_BYTES``
    exists to correct one layer down. The obvious implementation, a check at the
    top of ``create_session``, has that defect and nothing else can see it:
    FastAPI has already run ``await request.body()`` to build the model before a
    handler's first statement executes, so the status code is identical and the
    allocation is the caller's to choose. That is what the byte count below
    pins, and the positive control immediately before it is what stops the count
    from passing because nothing was ever sent.
    """
    pulled = [0]
    payload = json.dumps({"user_id": OWNER}).encode("utf-8")

    async def counting_body() -> Any:
        pulled[0] += len(payload)
        yield payload

    with _meters(app, writes=_tight_meter(3)):
        allowed = [
            (
                await client.post(
                    "/sessions",
                    content=counting_body(),
                    headers={"content-type": "application/json"},
                )
            ).status_code
            for _ in range(3)
        ]
        assert allowed == [200, 200, 200], allowed
        # Positive control: an *accepted* request really does pull the body
        # through this counter, so a zero below means "refused unread" rather
        # than "the counter was never wired up".
        assert pulled[0] == 3 * len(payload), (pulled[0], len(payload))

        before_bytes = pulled[0]
        refused = await client.post(
            "/sessions",
            content=counting_body(),
            headers={"content-type": "application/json"},
        )
        assert refused.status_code == 429, refused.text
        assert pulled[0] == before_bytes, (
            "the throttled request's body was read before it was refused; a meter "
            "that runs after the body is parsed still lets the caller choose the "
            "allocation, which is the defect MAX_BODY_BYTES exists to remove"
        )

        # And a bogus-id DELETE -- no session, no credential, still a durable
        # audit write on the unmetered build -- is refused too.
        deleted = await client.delete(f"/sessions/{uuid.uuid4().hex}", params={"user_id": INTRUDER})
        assert deleted.status_code == 429, deleted.text


async def test_the_shipped_meters_are_pinned_to_absolute_numbers(app: FastAPI) -> None:
    """The budgets themselves, by value.

    Every other assertion in this section installs its own meter, so all of them
    stay green if the shipped constants are raised to a billion -- which is the
    same "assert the control relative to the constant that expresses it" failure
    the whole of section 15 exists to correct. These are the numbers that are
    actually in front of an anonymous caller.
    """
    limits = app.state.rate_limits
    assert isinstance(limits, app_module._RateLimits)

    assert app_module.WRITE_BURST == 256, app_module.WRITE_BURST
    assert app_module.WRITE_REFILL_PER_SECOND == 8.0, app_module.WRITE_REFILL_PER_SECOND
    assert app_module.AUDIT_PROOF_BURST == 20, app_module.AUDIT_PROOF_BURST
    assert app_module.AUDIT_PROOF_REFILL_PER_SECOND == 0.5, app_module.AUDIT_PROOF_REFILL_PER_SECOND
    # The live app must actually be built from them.
    assert (limits.writes.capacity, limits.writes.refill_per_second) == (256, 8.0)
    assert (limits.audit_proofs.capacity, limits.audit_proofs.refill_per_second) == (20, 0.5)

    # Sustained cost of the write budget, stated in the units the finding was
    # measured in: 1 716 durable bytes per anonymous POST /sessions.
    bytes_per_second = app_module.WRITE_REFILL_PER_SECOND * 1_716
    hours_to_a_gigabyte = (1024**3) / bytes_per_second / 3600
    assert hours_to_a_gigabyte > 12, (
        f"the write budget lets one caller add a gigabyte of unprunable audit rows in "
        f"{hours_to_a_gigabyte:.1f} h; unmetered it was 0.2 h, and the log cannot be pruned"
    )


async def test_the_rate_limiter_refills_at_the_rate_it_claims() -> None:
    """The bucket arithmetic, driven by an injected clock rather than by sleeping.

    A meter tested by sleeping is a meter whose green depends on machine load,
    and the two properties worth pinning are both exact: a spent bucket refuses
    until enough time has passed, and it never accumulates past its capacity --
    without the ceiling, an idle caller banks an unbounded burst and the "burst"
    number stops meaning anything.
    """
    limiter = app_module._RateLimiter(capacity=3, refill_per_second=2.0)

    assert [limiter.take("a", now=0.0) for _ in range(3)] == [0.0, 0.0, 0.0]
    # Spent. The wait is exactly one token's worth at the declared rate.
    assert limiter.take("a", now=0.0) == pytest.approx(0.5)
    assert limiter.take("a", now=0.25) == pytest.approx(0.25)
    assert limiter.take("a", now=0.5) == 0.0
    # A different caller has its own budget.
    assert limiter.take("b", now=0.5) == 0.0

    # Idle for an hour: still capacity, not 7 200 tokens.
    assert [limiter.take("a", now=3600.0) for _ in range(3)] == [0.0, 0.0, 0.0]
    assert limiter.take("a", now=3600.0) > 0.0

    # A clock that steps *backwards* must be a no-op, not a punishment. Without
    # the clamp on ``elapsed`` the bucket goes negative by the size of the step,
    # so a 50-second step back locks the caller out for 51 seconds -- and the
    # failure scales with the step, which is the wrong direction for a control
    # whose whole job is to be bounded. ``time.monotonic`` cannot step back
    # today; the clamp is what keeps that from being load-bearing.
    spent = app_module._RateLimiter(capacity=1, refill_per_second=1.0)
    assert spent.take("c", now=100.0) == 0.0
    assert spent.take("c", now=50.0) == pytest.approx(1.0), (
        "a backwards clock step drove the bucket negative; the wait must be one "
        "token's worth, not the size of the step"
    )

    # The map of callers is bounded, or the meter is the exhaustion primitive it
    # exists to remove. Eviction is least-recently-seen and can only ever be
    # generous -- a forgotten caller returns with a full bucket.
    bounded = app_module._RateLimiter(capacity=1, refill_per_second=1.0, max_keys=4)
    for i in range(1_000):
        bounded.take(f"caller-{i}", now=0.0)
    assert bounded.tracked() == 4, bounded.tracked()

    for bad in ({"capacity": 0}, {"refill_per_second": 0.0}, {"max_keys": 0}):
        kwargs: dict[str, Any] = {"capacity": 1, "refill_per_second": 1.0, **bad}
        with pytest.raises(ValueError):
            app_module._RateLimiter(**kwargs)


async def test_resolving_an_audit_scope_costs_the_same_whether_the_run_exists(
    client: AsyncClient, services: Services
) -> None:
    """Counted, not clocked: the wrong-user path must issue the same queries either way.

    ``_resolve_audit_scope`` used to short-circuit -- one audit query for a
    ``run_id`` that resolved to nothing, two for one that resolved -- so a real
    ``run_id`` was measurably slower than a random one on the path that is
    supposed to be indistinguishable. Measured on the short-circuiting build over
    300 warmed pairs: median 947 us against 684 us, the real run slower in
    289 of 300 pairs. After equalising: 1 007 us against 982 us, 197 of 300.

    Asserted as a query *count* rather than as a duration, deliberately. A
    wall-clock assertion on a 25 us difference is a flaky test, and the residual
    difference is not this function's to remove -- it is SQLite returning a row
    against returning none, which lives in ``AuditLogger.query``. What this pins
    is the part that was a whole missing round trip through aiosqlite's worker
    thread, which is the part that made the channel large enough to read.
    """
    session_id = await _create_session(client)
    doc_id = await _upload(client)
    run_id = (await _run(client, session_id, doc_id)).json()["run_id"]

    calls: list[dict[str, Any]] = []
    real_query = services.audit.query

    async def counting_query(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return await real_query(**kwargs)

    with mock.patch.object(services.audit, "query", counting_query):
        calls.clear()
        await app_module._resolve_audit_scope(services, session_id=None, run_id=run_id)
        resolved = len(calls)

        calls.clear()
        await app_module._resolve_audit_scope(services, session_id=None, run_id=uuid.uuid4().hex)
        absent = len(calls)

    assert resolved == absent == 2, (
        f"a run that resolves cost {resolved} queries and one that does not cost {absent}; "
        f"the wrong-owner reply is byte-identical either way, so the clock must not "
        f"say which one the caller holds"
    )

    # The unresolved probe must still be *answered* as unowned, not accidentally
    # matched: the sentinel it queries cannot be a session ID.
    assert len(app_module.UNRESOLVED_SCOPE) != 32 or not all(
        char in "0123456789abcdef" for char in app_module.UNRESOLVED_SCOPE
    ), "the sentinel must not be shaped like the uuid4 hex SessionRegistry mints"
    scope = await app_module._resolve_audit_scope(
        services, session_id=None, run_id=uuid.uuid4().hex
    )
    assert scope.owner is None and scope.session_id is None, scope


def _dockerignore_match(pattern: str, path: str) -> bool:
    """Docker's pattern rule: segment-wise, so ``*`` never crosses a ``/``.

    Deliberately **not** :func:`fnmatch.fnmatch` over the whole string, which is
    the intuitive spelling and the wrong one: it lets ``*`` swallow separators,
    so ``data`` would appear to match ``a/b/data`` and this checker would agree
    with a mistake instead of catching it. ``**`` is the only segment that spans
    directories, exactly as ``filepath.Match`` plus moby's extension behaves.
    """
    pat = pattern.split("/")
    seg = path.split("/")

    def walk(i: int, j: int) -> bool:
        if i == len(pat):
            return j == len(seg)
        if pat[i] == "**":
            return any(walk(i + 1, k) for k in range(j, len(seg) + 1))
        if j == len(seg):
            return False
        return fnmatch.fnmatchcase(seg[j], pat[i]) and walk(i + 1, j + 1)

    return walk(0, 0)


def _dockerignored(path: str, dockerignore: str) -> bool:
    """Whether Docker would keep ``path`` out of the build context.

    Patterns are relative to the context root, a later line wins, ``!`` negates,
    and a pattern that matches a *parent directory* excludes everything beneath
    it -- which is the whole reason ``data/`` removes ``data/store.db``.
    """
    parts = path.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    excluded = False
    for raw in dockerignore.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        pattern = line.lstrip("!").strip().strip("/")
        if pattern and any(_dockerignore_match(pattern, prefix) for prefix in prefixes):
            excluded = not negate
    return excluded


async def test_the_dockerignore_matcher_agrees_with_a_real_docker_build() -> None:
    """The checker below is only as good as this parse, so the parse is pinned.

    Every expectation here was *measured* against the real daemon, not reasoned
    about: a throwaway context carrying ``.env``, ``data/blob.enc`` and
    ``secure_context_pipeline/detection/data/diagnoses.txt`` was built with this
    repository's ``.dockerignore``, and the manifest of what actually reached the
    image contained the gazetteer and neither of the other two.

    The last case is the one that matters and the one that is easy to get
    backwards. ``.gitignore`` and ``.dockerignore`` do **not** share a rule:
    ``data/`` in ``.gitignore`` matches a directory called ``data`` at *any*
    depth, while in ``.dockerignore`` it is anchored to the context root. A
    checker that assumed either file's semantics for the other would be wrong in
    one direction or the other, and the direction that hurts is treating the
    gazetteers as shipped when they are not.
    """
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")

    # Measured against the daemon: excluded.
    assert _dockerignored(".env", dockerignore)
    assert _dockerignored("data/blob.enc", dockerignore)
    assert _dockerignored(".venv/lib/python3.11/site-packages/x.py", dockerignore)
    assert _dockerignored("audit.db", dockerignore)
    # Measured against the daemon: shipped.
    assert not _dockerignored("secure_context_pipeline/detection/data/diagnoses.txt", dockerignore)
    assert not _dockerignored("entities.yaml", dockerignore)
    assert not _dockerignored("secure_context_pipeline/api/app.py", dockerignore)

    # And the matcher itself: `*` is segment-local, `**` is not.
    assert _dockerignore_match("data", "data")
    assert not _dockerignore_match("data", "a/data")
    assert _dockerignore_match("**/data", "a/b/data")
    assert _dockerignore_match("*.db", "audit.db")
    assert not _dockerignore_match("*.db", "a/audit.db")


def _git(*args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes] | None:
    """Run a git query in this checkout, or ``None`` when there is no tree to ask.

    Deliberately shells out rather than reading ``.gitignore`` and reimplementing
    git's matcher. A reimplementation of the matcher is exactly what shipped the
    bug this helper exists to catch: the pattern ``data/`` was *read* as anchored
    by a human and applied unanchored by git, and any hand-written checker would
    have been written from the same misreading. ``git ls-files`` is the other
    implementation.

    ``None`` -- no ``.git``, no git binary -- is the honest answer outside a
    working tree (a ``git archive`` tarball, an installed wheel) and callers skip
    the question rather than faking an answer to it.

    ``core.excludesFile`` is pinned empty so the answers are **this repository's**,
    not this developer's. The machine-global file is real here -- git falls back to
    ``~/.config/git/ignore`` with no config at all, and on the author's machine that
    file carries a rule -- and a guard that read it would pass or fail per laptop.
    ``tests/test_build_context.py`` makes the same distinction from the other side.
    ``.git/info/exclude`` is the one residue: per-clone, and there is no flag for it.
    """
    if not (REPO_ROOT / ".git").exists():
        return None
    try:
        return subprocess.run(
            ["git", "-c", f"core.excludesFile={os.devnull}", *args],
            cwd=REPO_ROOT,
            input=stdin,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - no git binary
        return None


def _git_index() -> frozenset[str] | None:
    """Every path in git's index, repo-relative. ``None`` outside a working tree.

    The whole index in one call rather than ``git ls-files --error-unmatch`` per
    path, because the list of things to ask about is *derived* and grows: a
    per-file subprocess puts a cost on adding an asset to that list, and that is
    the kind of cost that gets a check quietly narrowed later. ``-z`` so a name
    needing quoting cannot be misread as two names.
    """
    completed = _git("ls-files", "-z")
    if completed is None or completed.returncode != 0:  # pragma: no cover - not a tree
        return None
    return frozenset(filter(None, completed.stdout.decode("utf-8", "replace").split("\0")))


def _git_ignored(paths: Sequence[str]) -> frozenset[str] | None:
    """Which of ``paths`` an ignore rule in *this repository* matches.

    A different question from :func:`_git_index`, and the one that names the
    cause rather than the symptom. ``git ls-files`` reports the index as it
    stands today; ignoring is what silently empties it. A file that is both
    tracked and ignored passes the index check while sitting one ``git rm
    --cached``, one ``.gitignore`` tidy-up, or one clone-and-re-add away from
    vanishing -- which is precisely how the gazetteers left the repository.

    ``--no-index`` is what makes this about the rule: without it, git declines to
    answer for a path that is already tracked, i.e. it answers only in the case
    where the answer no longer matters.
    """
    if not paths:  # pragma: no cover - the caller always derives a non-empty list
        return frozenset()
    completed = _git(
        "check-ignore", "--stdin", "-z", "--no-index", stdin="\0".join(paths).encode("utf-8")
    )
    # 0 = something matched, 1 = nothing matched. Anything else (128) is git
    # refusing the question, and a refusal must never read as "nothing is ignored".
    if completed is None or completed.returncode not in (0, 1):  # pragma: no cover - no tree
        return None
    return frozenset(filter(None, completed.stdout.decode("utf-8", "replace").split("\0")))


#: Repo-relative paths this guard derives and is nevertheless allowed not to
#: require. **Empty on purpose.** The check below refuses an entry that no longer
#: names a derived asset, so a name parked here to quiet a red run rots into a
#: failure of its own instead of into silent, permanent coverage loss.
ASSETS_EXEMPT_FROM_SHIPPING: frozenset[str] = frozenset()

#: File names that are never a runtime asset wherever they turn up -- OS and
#: interpreter droppings, not content this system loads or serves. Deliberately a
#: deny-list of junk rather than an allow-list of extensions: a new ``.svg``,
#: ``.woff2`` or ``.map`` under ``ui/`` is an asset and has to be covered the day
#: it lands, which an extension allow-list would silently skip.
NEVER_A_RUNTIME_ASSET = frozenset({".DS_Store"})


def _repo_relative(path: Path) -> str:
    """A path constant re-expressed against *this checkout*, not the import site.

    The constants are read from the imported package because that is the honest
    answer to "where does the running process look for this": ``load_registry``
    opens :data:`DEFAULT_REGISTRY_PATH`, the recognizers open files under
    :data:`GAZETTEER_DIR`, ``_mount_ui`` serves ``PACKAGE_ROOT / UI_DIRNAME``, and
    ``GET /fixtures/{name}`` reads :data:`FIXTURES_DIR`. Only their *shape* is
    taken from the constant; the tree they are then checked in is always
    ``REPO_ROOT``, because an editable or wheel install resolves those constants
    into some other directory entirely -- and a guard that graded that directory
    would be grading a copy of the repository nobody is about to clone.
    """
    return path.resolve().relative_to(PACKAGE_ROOT.parent).as_posix()


def _same_origin_references(html: str) -> list[str]:
    """Relative ``src=``/``href=`` targets in ``html``: the files the page needs.

    Absolute URLs, protocol-relative URLs, ``data:`` URIs, bare fragments and
    root-anchored paths are not files sitting beside ``index.html``, so the static
    mount is not what has to be able to open them and they are not asserted here.
    """
    found = []
    for value in re.findall(r'(?:src|href)="([^"]+)"', html):
        target = value.split("?")[0].split("#")[0]
        if not target or ":" in target or "//" in target or target.startswith(("/", "#")):
            continue
        found.append(target)
    return sorted(set(found))


def _dockerfile_copy_sources() -> list[str]:
    """Every context path a ``COPY`` brings into the image.

    ``--from=`` lines copy out of an earlier build stage rather than out of the
    build context, so their sources are not repository paths and nothing in this
    tree can be checked against them.
    """
    return sorted(
        {
            source
            for line in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
            if (stripped := line.strip()).startswith("COPY ") and "--from" not in stripped
            for source in _copy_sources(stripped)
        }
    )


def _files_the_image_ships(root: Path, copied: Sequence[str], dockerignore: str) -> set[str]:
    """Everything under ``root`` a ``COPY`` carries in and ``.dockerignore`` keeps.

    A directory source is walked rather than trusted, which is what makes a file
    added to ``ui/`` tomorrow covered tomorrow instead of on the day somebody
    remembers to extend a list.
    """
    shipped: set[str] = set()
    for source in copied:
        base = root / source
        candidates = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for path in candidates:
            relative = path.relative_to(root).as_posix()
            if path.name in NEVER_A_RUNTIME_ASSET or _dockerignored(relative, dockerignore):
                continue
            shipped.add(relative)
    return shipped


def _assets_the_code_names() -> dict[str, str]:
    """Repo-relative asset -> the code that names it and cannot run without it.

    Every entry is derived from a constant or from a file the constant points at,
    so renaming ``ui/`` or moving the gazetteer directory moves this check with
    it. The registry is read from the working tree deliberately: it is what the
    author is about to ship, so a gazetteer added and not yet committed is
    covered today rather than after the commit that would have broken the clone.
    That is safe only because ``entities.yaml`` is itself in the returned mapping
    and therefore has to answer the same tracked-by-git question it drives.
    """
    named: dict[str, str] = {}

    registry = _repo_relative(DEFAULT_REGISTRY_PATH)
    named[registry] = "config.DEFAULT_REGISTRY_PATH -- load_registry fails closed without it"
    assert (REPO_ROOT / registry).is_file(), (
        f"{registry} is where DEFAULT_REGISTRY_PATH points and it is not on disk; "
        f"nothing in this system starts"
    )

    registry_text = (REPO_ROOT / registry).read_text(encoding="utf-8")
    gazetteers = re.findall(r"^\s*gazetteer:\s*(\S+)\s*$", registry_text, flags=re.MULTILINE)
    assert gazetteers, "entities.yaml must name the gazetteers this test is about"
    gazetteer_dir = _repo_relative(GAZETTEER_DIR)
    for filename in gazetteers:
        named[f"{gazetteer_dir}/{filename}"] = f"entities.yaml names `gazetteer: {filename}`"

    ui_dir = _repo_relative(PACKAGE_ROOT / UI_DIRNAME)
    # `_mount_ui` mounts this directory with `html=True`; `index.html` is the
    # fixed name Starlette then serves at `/`, so its absence is a blank demo.
    index = f"{ui_dir}/index.html"
    assert (REPO_ROOT / index).is_file(), f"{index} is absent, so _mount_ui serves nothing at /"
    named[index] = "_mount_ui serves this directory at / with html=True"
    references = _same_origin_references((REPO_ROOT / index).read_text(encoding="utf-8"))
    assert references, "index.html references no local file at all; the reference scan is broken"
    for reference in references:
        named[f"{ui_dir}/{reference}"] = f"index.html loads it (`{reference}`)"

    fixtures_dir = _repo_relative(FIXTURES_DIR)
    assert DEMO_FIXTURES, "the fixture allow-list is empty, so GET /fixtures/{name} serves nothing"
    for filename in DEMO_FIXTURES:
        named[f"{fixtures_dir}/{filename}"] = "on the DEMO_FIXTURES allow-list"

    return named


async def test_every_runtime_asset_the_registry_needs_actually_reaches_the_image() -> None:
    """``entities.yaml`` names gazetteer files, and ``load_registry`` fails closed.

    Three separate things have to be true for a stranger to start this system, and
    the interesting one is the third:

    1. every asset the running code names is on disk;
    2. a ``COPY`` in the ``Dockerfile`` brings it into the image, and
       ``.dockerignore`` does not filter it back out;
    3. **git tracks it**, so it survives ``git clone``.

    (3) is asserted because it was once false, and the earlier version of this
    test could not see that. ``.gitignore`` read ``data/``; in git's grammar an
    unanchored pattern matches a directory of that name at *any* depth, so it also
    matched ``secure_context_pipeline/detection/data/``. Both gazetteers were
    untracked, a fresh clone could not start -- ``demo.py`` exited 2 on
    ``ConfigError(reason='registry_gazetteer_missing', entity_type='DIAGNOSIS')``
    and the suite raised 457 errors -- and none of that was visible locally,
    because an ignored file leaves ``git status`` clean and every local run works.
    This test asserted ``(REPO_ROOT / relative).is_file()``, which reads the
    author's working tree, where the file was present the whole time. **The
    checker shared the blind spot of the thing it checked**: it could only observe
    the state that the bug does not affect. That is the defect class this project
    has been hunting, in its packaging form, and the fix is to ask a source that
    does not share the blind spot -- git's own index, via ``git ls-files``.

    That fix was then applied to two files out of seven, and to the wrong source
    for the one that mattered most. The asset list came from ``gazetteer:`` lines,
    so structurally it could never cover anything but the two gazetteers, while
    ``entities.yaml`` itself, ``ui/app.js``, ``ui/index.html`` and ``ui/style.css``
    were covered by nobody. Worse, the registry was read off the **working tree**
    -- so untracking ``entities.yaml`` left this test reading the present-on-disk
    copy and passing, which is the same blind spot one level up: git was asked
    about the gazetteers and the filesystem was asked about the file that names
    them. Measured in a real clone: ``git rm --cached entities.yaml ui/app.js
    ui/index.html ui/style.css`` and the suite was ``2693 passed, 1 skipped``,
    exit 0, while ``entities.yaml`` alone is a total start failure on that clone.

    So the list is now derived rather than enumerated, from two directions that do
    not share a source:

    * what the **code names** -- ``DEFAULT_REGISTRY_PATH``, the ``gazetteer:``
      entries it points at, ``GAZETTEER_DIR``, ``PACKAGE_ROOT / UI_DIRNAME`` and
      the files ``index.html`` itself loads, ``FIXTURES_DIR`` and
      ``DEMO_FIXTURES``. These get the on-disk half of (1): a named file that is
      missing is a failure even if nothing ships it.
    * what the **image carries** -- every file under a ``COPY`` source that
      ``.dockerignore`` does not remove. This is what makes a ``ui/`` asset added
      tomorrow covered tomorrow, and it is checked against the directory listing
      independently, so narrowing the sweep cannot quietly narrow the coverage.

    The ignore rule is now ``/data/``: runtime blobs still ignored, gazetteers
    tracked. The image escapes the whole question only because ``.dockerignore``
    reads the same line differently -- its patterns are anchored to the context
    root -- which is why the two ignore files must *not* be harmonised, and why
    adding ``**/data/`` to ``.dockerignore`` fails this test.

    Outside a git working tree (an exported tarball, a wheel) the answer is
    ``None`` and (3) is skipped rather than faked, because there is no index to
    disagree with the disk: in that world (1) already *is* the whole question.
    """
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")

    copied = _dockerfile_copy_sources()
    assert copied, "no COPY source parsed out of the Dockerfile; the parser or the file moved"
    for source in copied:
        assert (REPO_ROOT / source).exists(), (
            f"the Dockerfile copies `{source}`, which is not in this tree at all -- "
            f"`docker build` fails on that COPY line, so nothing downstream of it is real"
        )

    assets = _assets_the_code_names()
    for relative in _files_the_image_ships(REPO_ROOT, copied, dockerignore):
        assets.setdefault(relative, "a COPY carries it into the image")

    # The mounted UI directory, listed directly rather than through the sweep, so
    # that a file `.dockerignore` removes -- or one the sweep stops walking -- is a
    # failure here instead of a silent hole. This is the limb that covers a UI
    # asset added by somebody who never read this test.
    ui_dir = REPO_ROOT / _repo_relative(PACKAGE_ROOT / UI_DIRNAME)
    on_disk_ui = {
        path.relative_to(REPO_ROOT).as_posix()
        for path in ui_dir.rglob("*")
        if path.is_file() and path.name not in NEVER_A_RUNTIME_ASSET
    }
    assert on_disk_ui, f"{ui_dir} holds no files, so _mount_ui serves an empty site"
    assert on_disk_ui <= set(assets), (
        f"these files sit in the mounted UI directory and this guard does not cover them: "
        f"{sorted(on_disk_ui - set(assets))}. A UI asset is covered the day it lands or not "
        f"at all; if `.dockerignore` is what dropped it, the developer's browser loads it "
        f"and the reviewer's container answers 404"
    )

    assert ASSETS_EXEMPT_FROM_SHIPPING <= set(assets), (
        f"ASSETS_EXEMPT_FROM_SHIPPING names paths this guard no longer derives: "
        f"{sorted(ASSETS_EXEMPT_FROM_SHIPPING - set(assets))}. Delete them rather than "
        f"leaving an exemption that has quietly stopped meaning anything"
    )
    checked = {
        relative: why
        for relative, why in sorted(assets.items())
        if relative not in ASSETS_EXEMPT_FROM_SHIPPING
    }

    tracked = _git_index()
    for relative, why in checked.items():
        assert (REPO_ROOT / relative).is_file(), (
            f"{relative} is not on disk, and the running system needs it: {why}"
        )
        assert any(relative == source or relative.startswith(f"{source}/") for source in copied), (
            f"no COPY in the Dockerfile brings {relative} into the image ({why}); "
            f"copied={copied}"
        )
        assert not _dockerignored(relative, dockerignore), (
            f".dockerignore filters {relative} out of the build context ({why}), so the "
            f"container starts without a file the running code opens"
        )
        if tracked is not None:
            assert relative in tracked, (
                f"{relative} exists on disk but git does not track it, so it is absent "
                f"from a fresh clone and from any archive built out of the index -- it "
                f"is needed because {why}. Check `git check-ignore -v {relative}`: an "
                f"unanchored ignore pattern matches a directory of that name at any depth."
            )

    # And the rule rather than the index: a file can be tracked *and* ignored, which
    # is how the gazetteers were one `git rm --cached` away from gone while every
    # index check passed.
    ignored = _git_ignored(list(checked))
    if ignored is not None:
        assert not ignored, (
            f"an ignore rule in this repository matches {sorted(ignored)}, which the "
            f"running code opens. They are tracked today and one `git rm --cached`, one "
            f".gitignore tidy-up or one clone-and-re-add from being gone. Run "
            f"`git check-ignore -v` on them and anchor the rule with a leading slash"
        )


async def test_the_runtime_asset_derivation_covers_every_family_it_claims_to() -> None:
    """The guard above is only as good as its derivation, so the derivation is pinned.

    Written after the derivation had been narrowed once already: the previous
    version enumerated assets from ``gazetteer:`` lines, which *structurally*
    could not cover ``entities.yaml`` or anything under ``ui/`` no matter how the
    tree changed. A limb that silently returns nothing is the same failure with
    better manners, and neither shows up as a red test in the guard itself --
    a guard over an empty list passes.

    Filenames are deliberately not frozen here: ``ui/`` is under active edit and a
    rename must not be a test failure. What is pinned is that each family is
    *reached*, and the anchors -- the registry filename, the gazetteer directory,
    the UI directory, the fixtures directory -- which the Dockerfile's ``COPY``
    lines and both ignore files are written against by name.
    """
    named = _assets_the_code_names()

    registry = _repo_relative(DEFAULT_REGISTRY_PATH)
    gazetteer_dir = _repo_relative(GAZETTEER_DIR)
    ui_dir = _repo_relative(PACKAGE_ROOT / UI_DIRNAME)
    fixtures_dir = _repo_relative(FIXTURES_DIR)
    assert (registry, gazetteer_dir, ui_dir, fixtures_dir) == (
        "entities.yaml",
        "secure_context_pipeline/detection/data",
        "secure_context_pipeline/ui",
        "fixtures",
    ), (registry, gazetteer_dir, ui_dir, fixtures_dir)

    assert registry in named, "the registry limb is gone; entities.yaml is unguarded again"
    for prefix, family in (
        (f"{gazetteer_dir}/", "gazetteer"),
        (f"{ui_dir}/", "UI"),
        (f"{fixtures_dir}/", "fixture"),
    ):
        assert any(key.startswith(prefix) for key in named), (
            f"the {family} limb derived nothing under {prefix}; a guard over an empty "
            f"list passes, so this is coverage loss that reports itself as green"
        )
    # The four documents the allow-list serves, and both gazetteers the registry
    # names, reached by derivation rather than by being written out here.
    assert {f"{fixtures_dir}/{name}" for name in DEMO_FIXTURES} <= set(named), named
    assert sum(key.startswith(f"{gazetteer_dir}/") for key in named) >= 2, named

    # The reference scan decides which UI files are *named* requirements, so its
    # two failure directions are pinned: swallowing an off-host URL as a local
    # file, and dropping a local file because it carries a query or a fragment.
    assert _same_origin_references(
        '<link rel="stylesheet" href="style.css"><script src="app.js?v=2"></script>'
        '<link rel="icon" href="favicon.png#i"><a href="https://example.test/x">'
        '<img src="data:image/png;base64,AA=="><a href="/health"><a href="#main">'
    ) == ["app.js", "favicon.png", "style.css"]

    # And the sweep's filter: `.dockerignore` decides what ships, so a rule that
    # removes a file must remove it from the list this guard requires in git too --
    # otherwise the guard demands that git track a file the image never sees.
    root = Path(tempfile.mkdtemp())
    try:
        (root / "pkg" / "sub").mkdir(parents=True)
        for relative in ("pkg/keep.js", "pkg/sub/drop.pyc", "pkg/.DS_Store", "solo.txt"):
            (root / relative).write_text("x", encoding="utf-8")
        shipped = _files_the_image_ships(root, ["pkg", "solo.txt"], "**/*.py[cod]\n")
        assert shipped == {"pkg/keep.js", "solo.txt"}, shipped
    finally:
        shutil.rmtree(root, ignore_errors=True)


async def test_ttl_expiry_runs_the_whole_destruction_path(
    client: AsyncClient, services: Services
) -> None:
    """Build doc section 4 step 10: expiry destroys like logout, not only the key.

    Only the key half happened. `SessionRegistry._sweep_locked` drops the dict
    entry, and its own `sweep()` docstring says "the caller is responsible for the
    rest (vault rows, VAULT_DESTROY audit event)" -- there was no caller. `sweep()`
    appeared exactly once in the whole tree, in a test.

    So an expired session left AES-GCM rows in vault.db and a decrypted
    `_SessionCache` resident in RAM until process exit, and they were
    **unreclaimable**: `DELETE /sessions` gates on `_owns_session` ->
    `sessions.owner()`, which raises for an expired session and returns False, so
    `vault.destroy` was skipped. Nothing short of a restart cleared them.

    Asserted through the HTTP surface rather than by calling the reaper, because
    the property is "a request discovers the expiry and finishes the job";
    calling the helper directly would only prove the helper works.
    """
    doc_id = await _upload(client)

    # A session that is alive long enough to vault something, then expires.
    session_id, _expires = await services.sessions.create(OWNER, ttl_seconds=1)
    run = await _run(client, session_id, doc_id)
    assert run.status_code == 200, run.text
    assert await services.vault.row_count(session_id) > 0, "premise: the vault holds rows"
    assert session_id in services.vault.cached_session_ids(), "premise: plaintext is cached"

    await asyncio.sleep(1.2)

    # Any authenticated request now finishes the destruction path. This one gets its
    # 401, which is correct and is not what is under test.
    assert (await _run(client, session_id, doc_id)).status_code == 401

    assert await services.vault.row_count(session_id) == 0, "vault rows survived expiry"
    assert session_id not in services.vault.cached_session_ids(), "plaintext cache survived"
    events = await services.audit.query(session_id=session_id)
    destroys = [e for e in events if e.event_type == "VAULT_DESTROY"]
    assert destroys, "expiry emitted no VAULT_DESTROY"
    assert destroys[-1].detail["source"] == "ttl_expiry"
    # And SESSION_EXPIRE, which was declared in `audit/logger.py` from the first
    # commit and never emitted anywhere -- the gap Deviation 26 records. The two
    # are different facts (the session died; the vault was torn down) and an
    # auditor reconstructing a timeline wants both.
    expires = [e for e in events if e.event_type == "SESSION_EXPIRE"]
    assert expires, "expiry emitted no SESSION_EXPIRE"
    assert expires[-1].detail["source"] == "ttl_expiry"
    assert await services.audit.verify_chain() is True


async def test_a_health_poll_does_not_disarm_the_ttl_reaper(
    client: AsyncClient, services: Services
) -> None:
    """The regression that made the reaper a no-op in the shipped container.

    `reap_expired_sessions` was the only caller that KEPT `SessionRegistry.sweep()`'s
    return value, but six accessors call `_sweep_locked()` and discard it. Whichever
    observed an expiry first removed the ID permanently, so the reaper never saw it
    and the vault rows survived to process exit.

    Not a rare race: the shipped Dockerfile polls `GET /health` every 30 seconds and
    that route calls `active_ids`. Reverting the fix leaves the whole suite green,
    which is why this test exists -- the only direct `sweep()` test disqualifies
    itself in its own comment, because it exercises the case where nothing else has
    touched the registry, i.e. the case the bug does not affect.
    """
    doc_id = await _upload(client)
    session_id, _ = await services.sessions.create(OWNER, ttl_seconds=1)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert await services.vault.row_count(session_id) > 0, "premise: the vault holds rows"

    await asyncio.sleep(1.2)

    # The health poll observes the expiry first and drops the key. Before the fix
    # this consumed the only notification the reaper would ever get.
    assert (await client.get("/health")).status_code == 200

    # A later authenticated request must still finish the destruction path.
    assert (await _run(client, session_id, doc_id)).status_code == 401
    assert await services.vault.row_count(session_id) == 0, (
        "the health poll swallowed the expiry: the reaper never saw it and the "
        "vault rows are stranded until process exit"
    )
    assert session_id not in services.vault.cached_session_ids()

    # The other half of the same mechanism: the drain must be once-only.
    # Everything above passes whether or not `_drain_unreaped_locked` calls
    # `self._unreaped.clear()`, because the FIRST reap succeeds either way. With
    # the `clear()` removed, three consecutive `sweep()` calls each returned the
    # same expired ID (measured), and since `reap_expired_sessions` runs on every
    # authenticated request, one expired session then appends a SESSION_EXPIRE and
    # a VAULT_DESTROY to the hash chain per request for the life of the process
    # while `_unreaped` grows without bound.
    assert (await _run(client, session_id, doc_id)).status_code == 401

    # Asserted from the auditor's side rather than off the registry's internals:
    # a session expires once, so a reader of the log must see exactly one of each
    # event, no matter how many requests happened to observe the expiry.
    destroys = await services.audit.length(session_id=session_id, event_type="VAULT_DESTROY")
    assert destroys == 1, f"expiry re-reaped: {destroys} VAULT_DESTROY events for one session"
    expires = await services.audit.length(session_id=session_id, event_type="SESSION_EXPIRE")
    assert expires == 1, f"expiry re-reaped: {expires} SESSION_EXPIRE events for one session"
    assert await services.sessions.sweep() == [], "the unreaped drain was not consumed"
    assert await services.audit.verify_chain() is True


# ---------------------------------------------------------------------------
# The reaper's *bound*. The tests above prove it runs; these prove what it costs.
# ---------------------------------------------------------------------------
async def _drain_reap_backlog(services: Services) -> None:
    """Empty the shared backlog so a following test's arithmetic is exact.

    The app is module-scoped, so :attr:`Services.reap_backlog` is shared state and
    a test that left entries in it would silently change what the next one
    measures. Bounded by construction: each call clears at least one entry.
    """
    while services.reap_backlog:
        await reap_expired_sessions(services)


async def test_one_request_is_never_charged_with_every_other_callers_expiries(
    client: AsyncClient, services: Services
) -> None:
    """The reaper runs on the request path, so its cost has to be a constant.

    `SessionRegistry.sweep()` returns every ID awaiting destruction -- not the ones
    this caller caused -- and each one costs a `vault.destroy` plus two hash-chained
    audit rows. The first version of `reap_expired_sessions` did all of them inside
    whichever request happened to arrive next. Measured on a real app at
    `session_ttl_seconds=1`: 258 anonymous sessions, then one reap, **311 ms in one
    request**. `POST /sessions` needs no session and no credential, so the queue is
    anonymously fillable and the caller who pays is not the caller who filled it --
    a work-amplification primitive with a 204 on the front of it.

    Two properties, and both are needed. **Bounded**: one request reaps at most
    `MAX_REAP_PER_REQUEST`, whatever the backlog. **Lossless**: the residual is not
    dropped on the floor to buy that bound -- it stays queued and later requests
    finish it, so `test_ttl_expiry_runs_the_whole_destruction_path`'s guarantee
    still holds for every session, just not all in one request.

    Counted in IDs rather than milliseconds on purpose. A wall-clock assertion here
    would be measuring the machine, and this suite already has one budget test that
    goes red on a loaded runner; the number of vault destroys a request performs is
    the thing the bound actually controls.
    """
    await _drain_reap_backlog(services)
    minted = [
        (await services.sessions.create(f"reap-filler-{i}", ttl_seconds=0))[0]
        for i in range(MAX_REAP_PER_REQUEST * 3 + 5)
    ]
    # `create` sweeps *before* inserting, so the most recent mint is expired but not
    # yet observed. One read forces the final sweep, which makes the count below the
    # whole batch rather than the whole batch minus one.
    await services.sessions.active_ids()

    # One anonymous request. It has no session and asks for nothing; under the
    # unbounded reaper it inherited all 53 destructions anyway.
    assert (await client.post("/sessions", json={"user_id": "bystander"})).status_code == 200

    assert len(services.reap_backlog) == len(minted) - MAX_REAP_PER_REQUEST, (
        f"one request drained {len(minted) - len(services.reap_backlog)} expired sessions; "
        f"the ceiling is {MAX_REAP_PER_REQUEST}. An arbitrary caller is being charged for "
        "expiries it did not cause."
    )
    reaped_first = [
        sid for sid in minted if await services.audit.length(session_id=sid) > 0
    ]
    assert len(reaped_first) == MAX_REAP_PER_REQUEST

    # Lossless: keep issuing requests and every one of them gets finished. The
    # iteration ceiling is generous but finite -- a reaper that stopped making
    # progress would hang the suite otherwise, which is not a failure report.
    for _ in range(len(minted)):
        if not services.reap_backlog:
            break
        await reap_expired_sessions(services)
    assert services.reap_backlog == {}, "the residual never drained"

    for session_id in minted:
        events = await services.audit.query(session_id=session_id)
        kinds = {event.event_type for event in events}
        assert kinds == {"SESSION_EXPIRE", "VAULT_DESTROY"}, (
            f"{session_id} was bounded out of its own destruction path: {sorted(kinds)}"
        )
    assert await services.audit.verify_chain() is True


async def test_a_flooded_reap_backlog_never_drops_a_session_holding_plaintext(
    client: AsyncClient, services: Services
) -> None:
    """The queue was bounded by evicting the oldest, and that evicted the *plaintext*.

    The ceiling was `MAX_REAP_BACKLOG` (4 096) and its justification was written
    down twice: the key is popped by `_sweep_locked` before an ID can reach this
    queue, so a dropped ID leaves only undecryptable rows behind. True of the
    SQLite rows. False of `SessionVault._caches`, which holds originals that are
    **already decrypted** and need no key -- and `SessionVault.destroy` is the only
    thing that pops it, while `SessionRegistry.sweep` drains its unreaped set, so a
    dropped ID is never offered again by anything.

    Measured against the real registry and the real vault before the ceiling came
    out, one expired session queued ahead of a 4 096-ID flood:

        flooded 4096, evicted 1, victim still queued: False
        PLAINTEXT CACHE STILL RESIDENT: True   originals: ['943-41-9520']
        vault rows still on disk: 1   tombstoned: False
        audit events for the victim: []

    `POST /sessions` needs no credential, so the flood is anonymous and the victim
    is somebody else. What the ceiling actually capped was a 32-character ID; what
    it abandoned was that ID's decrypted originals, for the life of the process.

    So the assertion is that nothing carrying outstanding destruction work is ever
    discarded, however long the queue gets -- and then that the victim really is
    destroyed, from the vault's side and the auditor's, rather than merely still
    being on a list. Per-request work stays bounded by `MAX_REAP_PER_REQUEST`,
    which `test_one_request_is_never_charged_with_every_other_callers_expiries`
    pins; the two tests are the two halves of the same requirement.

    The ghosts are removed by hand rather than drained: draining them would cost a
    vault DELETE and two hash-chained audit rows each (~1.2 ms), which measures
    SQLite rather than the queue and would dominate this file's runtime.
    """
    await _drain_reap_backlog(services)
    doc_id = await _upload(client)
    session_id, _expires = await services.sessions.create(OWNER, ttl_seconds=1)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert services.vault.originals_for_session(session_id), (
        "premise: the vault holds this session's decrypted originals"
    )
    assert await services.vault.row_count(session_id) > 0, "premise: the vault holds rows"

    await asyncio.sleep(1.2)
    # The reaper's own first line, called directly so the queue can be observed
    # between the enqueue and the drain -- which is exactly the window the
    # eviction ran in.
    _enqueue_for_reaping(services, await services.sessions.sweep())
    assert session_id in services.reap_backlog, "premise: the victim is queued, and oldest"
    queued = len(services.reap_backlog)

    ghosts = [f"ghost-{i:06d}" for i in range(8_192)]
    _enqueue_for_reaping(services, ghosts)
    assert session_id in services.reap_backlog, (
        "an ID with outstanding destruction work was dropped from the queue: nothing "
        "will ever call vault.destroy for it, so its decrypted originals stay in "
        "SessionVault._caches until the process exits"
    )
    assert len(services.reap_backlog) == queued + len(ghosts), (
        "the queue discarded entries under load; every entry is the last handle on "
        "a session's plaintext"
    )

    # And the queue having no ceiling must not put the per-request cost back: one
    # call, 8 192 IDs waiting, still finishes the hoisted session plus a constant.
    reaped = await reap_expired_sessions(services, first=session_id)
    assert session_id in reaped, "the hoist did not finish the session it was given"
    # The hoisted session is spent *from* the budget, not added to it, so the
    # total is the ceiling exactly -- a caller cannot buy a seventeenth
    # destruction by naming one.
    assert len(reaped) == MAX_REAP_PER_REQUEST, (
        f"one request reaped {len(reaped)} sessions with {len(ghosts)} queued; the "
        f"ceiling is {MAX_REAP_PER_REQUEST}. Removing the backlog ceiling must not "
        "remove the per-request bound with it."
    )
    for ghost in ghosts:
        services.reap_backlog.pop(ghost, None)

    await _drain_reap_backlog(services)
    assert session_id not in services.vault.cached_session_ids()
    assert services.vault.originals_for_session(session_id) == frozenset(), (
        "decrypted originals survived the reap"
    )
    assert await services.vault.row_count(session_id) == 0
    kinds = {event.event_type for event in await services.audit.query(session_id=session_id)}
    assert {"SESSION_EXPIRE", "VAULT_DESTROY"} <= kinds, (
        f"the expiry went unaudited: {sorted(kinds)}"
    )
    assert await services.audit.verify_chain() is True


async def test_a_destruction_that_fails_is_requeued_instead_of_stranding_the_session(
    client: AsyncClient, services: Services
) -> None:
    """A transient failure used to be as permanent as the eviction that preceded it.

    The ID is popped off `reap_backlog` *before* `vault.destroy` is attempted, and
    the `except Exception` at the bottom of the loop only logged. So one failed
    attempt -- a locked SQLite file, a `commit()` that raised outside the
    `sqlite3.Error` the vault catches for itself -- put the ID in the same place
    the 4 096-entry ceiling used to put it: nowhere. `SessionRegistry.sweep`
    drains its unreaped set once, so nothing offers the ID again; the decrypted
    originals stay in `SessionVault._caches` until the process exits, the rows
    stay on disk with no path left that can delete them (every other route gates
    on an ownership check that raises for an expired session), and neither
    `SESSION_EXPIRE` nor `VAULT_DESTROY` is ever written.

    Measured on this app before the fix, one forced failure on a session holding
    real plaintext:

        after failed reap:  queued again: False  originals: frozenset({'04/13/1956',
                            '9224297', 'David Ochoa', '(704) 555-0151'})  rows: 4
        after draining to
        exhaustion:         queued again: False  originals: (the same four)  rows: 4

    -- identical, because there was nothing left in the backlog to drain.

    So the failure path re-queues, and the proof is in two halves: the ID survives
    the failed attempt, and a *later* call actually finishes it. Asserting only the
    first would pass against a re-queue that put the ID back in a structure the
    drain never looks at.
    """
    await _drain_reap_backlog(services)
    doc_id = await _upload(client)
    session_id, _expires = await services.sessions.create(OWNER, ttl_seconds=1)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert services.vault.originals_for_session(session_id), (
        "premise: the vault holds this session's decrypted originals"
    )
    assert await services.vault.row_count(session_id) > 0, "premise: the vault holds rows"

    await asyncio.sleep(1.2)
    _enqueue_for_reaping(services, await services.sessions.sweep())
    assert session_id in services.reap_backlog, "premise: the victim is queued"

    real_destroy = services.vault.destroy
    calls: list[str] = []

    async def _locked_once(target: str) -> None:
        calls.append(target)
        if target == session_id and len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        await real_destroy(target)

    with mock.patch.object(services.vault, "destroy", _locked_once):
        reaped = await reap_expired_sessions(services)
        assert session_id not in reaped, (
            "the reaper reported a session it did not destroy; the return value is "
            "what a caller would use to decide the work is done"
        )
        # The failure really did strand something -- otherwise the re-queue below
        # would be proving nothing.
        assert services.vault.originals_for_session(session_id), (
            "premise: the failed destroy left the decrypted originals resident"
        )
        assert session_id in services.reap_backlog, (
            "a session whose destruction failed was dropped from the queue: nothing "
            "will ever call vault.destroy for it again, so its decrypted originals "
            "stay in SessionVault._caches until the process exits and its rows stay "
            "on disk untombstoned and unaudited"
        )

    # A later request finishes it, which is the half that makes the re-queue real.
    await _drain_reap_backlog(services)
    assert session_id not in services.vault.cached_session_ids()
    assert services.vault.originals_for_session(session_id) == frozenset(), (
        "decrypted originals survived the retry"
    )
    assert await services.vault.row_count(session_id) == 0, "vault rows survived the retry"
    kinds = {event.event_type for event in await services.audit.query(session_id=session_id)}
    assert {"SESSION_EXPIRE", "VAULT_DESTROY"} <= kinds, (
        f"the retried expiry went unaudited: {sorted(kinds)}"
    )
    assert await services.audit.verify_chain() is True


async def test_a_cancelled_request_does_not_take_the_slice_it_was_draining_with_it(
    client: AsyncClient, services: Services
) -> None:
    """`except Exception` cannot see the failure a disconnect actually produces.

    `asyncio.CancelledError` is a `BaseException` in 3.8 and later, so a client
    that goes away mid-drain -- the concrete "cancelled request" case -- did not
    reach the handler at the bottom of the loop at all. It unwound
    `reap_expired_sessions` from the middle of a slice that had already been popped
    off `reap_backlog`, so the session being destroyed **and every session behind it
    in the slice** were stranded at once, with not even the warning line the caught
    case produced. The queue is the only record that the work is outstanding, and
    for the length of that loop the queue no longer holds it.

    Charged nothing: a cancellation is evidence about the client, not about whether
    the session can be destroyed, so the retry budget -- which exists to bound
    *failures* -- comes back untouched. That is asserted on the number, not just on
    membership, because a re-queue that silently spent an attempt would look
    identical here and would let sixteen disconnects retire a session that was
    never actually tried.
    """
    await _drain_reap_backlog(services)
    doc_id = await _upload(client)
    session_id, _expires = await services.sessions.create(OWNER, ttl_seconds=1)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert services.vault.originals_for_session(session_id), (
        "premise: the vault holds this session's decrypted originals"
    )

    await asyncio.sleep(1.2)
    first_ghost = f"cancel-ghost-{uuid.uuid4().hex}"
    behind = [f"cancel-behind-{uuid.uuid4().hex}" for _ in range(2)]
    _enqueue_for_reaping(services, [first_ghost])
    _enqueue_for_reaping(services, await services.sessions.sweep())
    _enqueue_for_reaping(services, behind)
    assert list(services.reap_backlog) == [first_ghost, session_id, *behind], (
        "premise: the drain order is ghost, victim, then two that never get a turn"
    )

    real_destroy = services.vault.destroy

    async def _disconnect_at_the_victim(target: str) -> None:
        if target == session_id:
            raise asyncio.CancelledError
        await real_destroy(target)

    with (
        mock.patch.object(services.vault, "destroy", _disconnect_at_the_victim),
        pytest.raises(asyncio.CancelledError),
    ):
        await reap_expired_sessions(services)

    assert await services.audit.length(session_id=first_ghost) > 0, (
        "premise: the drain really had started, so the slice was really in flight"
    )
    assert services.vault.originals_for_session(session_id), (
        "premise: the cancelled destroy left the decrypted originals resident"
    )
    for stranded in (session_id, *behind):
        assert stranded in services.reap_backlog, (
            f"{stranded} was lost when the request was cancelled: it had already been "
            "popped off the queue, and nothing offers a swept ID a second time"
        )
        assert services.reap_backlog[stranded] == MAX_REAP_ATTEMPTS, (
            "a cancelled request spent one of the session's destruction attempts; "
            "the budget bounds failures, and a disconnect is not one"
        )

    await _drain_reap_backlog(services)
    assert services.vault.originals_for_session(session_id) == frozenset()
    assert await services.vault.row_count(session_id) == 0
    assert await services.audit.verify_chain() is True


async def test_a_destruction_that_always_fails_is_retried_a_bounded_number_of_times(
    client: AsyncClient, services: Services
) -> None:
    """The other half of the re-queue: it must not become an unbounded retry loop.

    Re-queueing a failed ID is only safe if the retries are finite. Put back with
    no counter, an ID whose destroy can never succeed -- a corrupt row, a disk that
    is gone -- takes one of the sixteen slots in *every* request for the life of
    the process, and sixteen of them take all of them, so healthy expiries queue
    behind failures that will never clear. That is the same starvation the
    per-request bound exists to prevent, arriving through the failure path.

    So an ID gets `MAX_REAP_ATTEMPTS` attempts **in total**, not per request: the
    re-queue goes to the tail, and the slice this call works on was popped before
    the first destroy ran, so a failure can never be retried inside the call that
    produced it. What is asserted here is that total -- the destroy is called
    exactly eight times however many reaping calls follow -- because a bound that
    is really "eight per request" would pass an assertion on the queue alone.

    Exhausting the budget must not *drop* the ID, which would be the 4 096-entry
    eviction all over again with a counter in front of it: the session whose
    destruction keeps failing is by definition the one still holding decrypted
    originals. It moves to `reap_failed`, where it is out of the budget's way but
    still enumerable and still reachable -- and the last assertions here are that
    a named logout gets it back out and finishes it, because a dead-letter map
    nothing can drain is only a leak with better manners.
    """
    await _drain_reap_backlog(services)
    doc_id = await _upload(client)
    session_id, _expires = await services.sessions.create(OWNER, ttl_seconds=1)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert services.vault.originals_for_session(session_id), (
        "premise: the vault holds this session's decrypted originals"
    )

    await asyncio.sleep(1.2)
    real_destroy = services.vault.destroy
    calls: list[str] = []

    async def _always_locked(target: str) -> None:
        calls.append(target)
        if target == session_id:
            raise sqlite3.OperationalError("database is locked")
        await real_destroy(target)

    extra_calls = 5
    with mock.patch.object(services.vault, "destroy", _always_locked):
        for _ in range(MAX_REAP_ATTEMPTS + extra_calls):
            await reap_expired_sessions(services)

        assert calls.count(session_id) == MAX_REAP_ATTEMPTS, (
            f"{MAX_REAP_ATTEMPTS + extra_calls} reaping calls produced "
            f"{calls.count(session_id)} destroy attempts for one permanently-failing "
            f"session; the budget is {MAX_REAP_ATTEMPTS} attempts for the life of the "
            "process, so this ID is still taking a slot out of every request"
        )
        assert session_id not in services.reap_backlog, (
            "an ID that can never be destroyed is still in the queue healthy expiries "
            "are drained from"
        )
        assert session_id in services.reap_failed, (
            "the exhausted ID was discarded rather than held: nothing can enumerate "
            "it, nothing can retry it, and its decrypted originals are still resident"
        )
        assert services.vault.originals_for_session(session_id), (
            "premise: the failures really did leave the originals resident"
        )

        # A named logout is the one thing that takes an ID back out of the
        # dead-letter map. Under the patch it fails again, and is re-queued with a
        # fresh budget rather than going straight back to `reap_failed`.
        assert await reap_expired_sessions(services, first=session_id) == []
        assert calls.count(session_id) == MAX_REAP_ATTEMPTS + 1
        assert session_id in services.reap_backlog, (
            "the hoist did not rescue the dead letter: DELETE /sessions/{id} is the "
            "only retry an operator has"
        )
        assert session_id not in services.reap_failed

    # And with the fault cleared, the rescued ID really is finished.
    await _drain_reap_backlog(services)
    assert session_id not in services.vault.cached_session_ids()
    assert services.vault.originals_for_session(session_id) == frozenset()
    assert await services.vault.row_count(session_id) == 0
    kinds = {event.event_type for event in await services.audit.query(session_id=session_id)}
    assert {"SESSION_EXPIRE", "VAULT_DESTROY"} <= kinds, (
        f"the rescued expiry went unaudited: {sorted(kinds)}"
    )
    assert await services.audit.verify_chain() is True


async def test_the_bounded_drain_delays_an_untouched_expiry_by_one_call_per_sixteen(
    client: AsyncClient, services: Services
) -> None:
    """The price of the per-request bound, measured instead of assumed.

    Before the bound, one reaping call finished every expiry it found, so an
    expired session's decrypted originals left `SessionVault._caches` on the first
    request after the expiry was observed. Bounding the drain at
    `MAX_REAP_PER_REQUEST` moved that to `ceil(p / 16)` calls for a session at
    1-based position `p` in the backlog -- `ceil(E / 16)` for the last of a burst
    of `E` sessions that expire together and reach one `sweep()`.

    That window is a real cost of a deliberate trade (the alternative is the
    311 ms an anonymous caller could charge to an arbitrary victim's request), and
    the reaper's docstring now states it. This is what stops the statement from
    being prose: it drives the real vault to the boundary and asserts both sides of
    it -- resident on call `ceil(E/16) - 1`, gone on call `ceil(E/16)`. An
    assertion on the second alone would also pass for a reaper that finished
    everything on the first call, which is the behaviour the bound removed.

    The escape hatch is not re-proved here:
    `test_a_flooded_reap_backlog_never_drops_a_session_holding_plaintext` already
    shows `first=` finishing a named session on the spot with 8 192 IDs queued
    ahead of it, which is why the window applies only to sessions nobody touches.
    """
    await _drain_reap_backlog(services)
    doc_id = await _upload(client)
    session_id, _expires = await services.sessions.create(OWNER, ttl_seconds=1)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert services.vault.originals_for_session(session_id), (
        "premise: the vault holds this session's decrypted originals"
    )

    await asyncio.sleep(1.2)
    # Ghosts first, then the real expiry, so the victim is deterministically last
    # in the FIFO -- `SessionRegistry.sweep` returns its IDs sorted, which would
    # otherwise put the victim at an arbitrary depth.
    ghosts = [f"window-ghost-{i:04d}" for i in range(MAX_REAP_PER_REQUEST * 3)]
    _enqueue_for_reaping(services, ghosts)
    _enqueue_for_reaping(services, await services.sessions.sweep())
    queued = len(services.reap_backlog)
    assert queued == len(ghosts) + 1, "premise: the victim is queued exactly once, at the back"

    expected_calls = -(-queued // MAX_REAP_PER_REQUEST)
    assert expected_calls > 1, "premise: the burst is deeper than one call's budget"

    for call in range(1, expected_calls):
        await reap_expired_sessions(services)
        assert services.vault.originals_for_session(session_id), (
            f"the victim was destroyed on call {call} of an expected {expected_calls}; "
            f"either the drain is no longer bounded at {MAX_REAP_PER_REQUEST} or the "
            "queue is no longer FIFO, and the window the reaper documents is wrong"
        )

    await reap_expired_sessions(services)
    assert services.vault.originals_for_session(session_id) == frozenset(), (
        f"{queued} sessions expired together and the last of them still held decrypted "
        f"originals after {expected_calls} reaping calls; the documented window is "
        f"ceil({queued} / {MAX_REAP_PER_REQUEST}) = {expected_calls}"
    )
    assert session_id not in services.vault.cached_session_ids()
    assert await services.vault.row_count(session_id) == 0
    assert not services.reap_backlog, "the burst did not drain in the calls it should have"
    assert await services.audit.verify_chain() is True


async def test_logging_out_after_the_ttl_lapsed_still_destroys_the_vault(
    client: AsyncClient, services: Services
) -> None:
    """`DELETE /sessions/{id}` was a no-op on exactly the session that needed it.

    Everything the route does is behind `_owns_session`, which resolves through
    `SessionRegistry.owner()` -- and that raises for an expired session, so the
    helper answers False and `vault.destroy` is skipped. The route still answered
    204. Measured at `session_ttl_seconds=3`, one run, sleep 3.5 s, then DELETE:
    `cached=True originals=3 rows=3` before, and the identical line after.

    That is the difference between README gap 7's "no eviction ... and not
    explicitly logged out" and what shipped: logging out explicitly did not evict
    either, once the TTL had passed. The reaper is the destruction path for an
    expired session and no route reached it except `POST /pipeline/run`, which a
    logout does not go through.

    The `MAX_REAP_PER_REQUEST * 2` ghosts are the second half of the test. With the
    drain bounded, a plain FIFO reap would spend its whole budget on them and leave
    this user's rows queued behind strangers' expiries while answering 204, so
    `delete_session` hoists the session it was asked about to the front. Without
    the ghosts a FIFO drain and a hoisting drain are indistinguishable here.
    """
    await _drain_reap_backlog(services)
    doc_id = await _upload(client)
    session_id, _expires = await services.sessions.create(OWNER, ttl_seconds=1)
    assert (await _run(client, session_id, doc_id)).status_code == 200
    assert await services.vault.row_count(session_id) > 0, "premise: the vault holds rows"
    assert session_id in services.vault.cached_session_ids(), "premise: plaintext is cached"

    await asyncio.sleep(1.2)
    _enqueue_for_reaping(
        services, [f"ghost-{uuid.uuid4().hex}" for _ in range(MAX_REAP_PER_REQUEST * 2)]
    )

    # The logout is the FIRST request to touch this session after it expired: no
    # pipeline run in between, so nothing else can have run the reaper for it.
    logout = await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})
    assert logout.status_code == 204, logout.text

    assert await services.vault.row_count(session_id) == 0, (
        "logout after the TTL lapsed left the AES-GCM rows on disk -- and nothing "
        "else can remove them, because every other path gates on the same "
        "ownership check that just failed"
    )
    assert session_id not in services.vault.cached_session_ids(), (
        "decrypted originals stayed resident in SessionVault._caches after an explicit logout"
    )
    events = await services.audit.query(session_id=session_id)
    assert "SESSION_EXPIRE" in {event.event_type for event in events}
    assert await services.audit.verify_chain() is True
    await _drain_reap_backlog(services)


# ---------------------------------------------------------------------------
# Two small surface defects: a missing header and a missing method
# ---------------------------------------------------------------------------
async def test_the_endpoint_that_returns_plaintext_forbids_caching(
    client: AsyncClient,
) -> None:
    """`GET /documents/{doc_id}/text` is one of exactly two routes allowed to emit
    original plaintext, and it was the one the header set forgot.

    Measured before the fix: a 200 carrying decrypted PHI came back with
    `content-security-policy`, `x-content-type-options` and `referrer-policy` and
    **no `cache-control` at all** -- and `grep -rni "no-store"` matched nothing in
    the tree. Without it the body is storable by any intermediary and by the
    browser's own back/forward and disk caches, so the plaintext outlives the
    request, the session TTL and the cryptographic erasure that is supposed to end
    it, on a machine this process does not control. The design was already
    reasoning about this exact class of leakage one paragraph earlier, for a
    `doc_id` in an outbound `Referer`.

    Asserted on the plaintext route specifically as well as on the general sweep
    above, because this is the response where the header is load-bearing rather
    than hygienic: a stale `/health` in a cache is a stale liveness answer, a
    stale `/documents/.../text` is the document.
    """
    doc_id = await _upload(client)
    response = await client.get(f"/documents/{doc_id}/text", params={"user_id": OWNER})
    assert response.status_code == 200, response.text
    assert "David Ochoa" in response.json()["text"], "premise: this body carries plaintext"
    assert response.headers["cache-control"] == "no-store"


async def test_head_is_answered_by_the_route_and_not_by_the_static_mount(
    client: AsyncClient,
) -> None:
    """`curl -I /health` returned 404 on a perfectly healthy process.

    FastAPI's `@router.get` registers GET only, so a HEAD request matched the path
    but not the method; Starlette kept looking and fell through to the catch-all
    `Mount("/")` that `_mount_ui` installs last, which answered its own static-file
    miss. `middleware.py`'s premise -- "mounted last, so every API route is matched
    first" -- holds only for methods a route actually declares, and HEAD appeared
    nowhere in the README or in `tests/`.

    It matters for the least exotic reader there is: a load balancer's default
    probe and the first thing an ops reviewer types. The status and the headers
    must be the GET's, which is what distinguishes a real answer from the mount's.
    """
    head = await client.head("/health")
    get = await client.get("/health")
    assert head.status_code == get.status_code == 200
    assert head.headers["content-type"] == "application/json"
    for header in ("content-security-policy", "x-content-type-options", "cache-control"):
        assert head.headers[header] == get.headers[header], header
    assert head.content == b"", "HEAD must carry no body"


async def test_an_unknown_body_field_name_is_not_echoed_into_the_422(
    client: AsyncClient,
) -> None:
    """"No error path can echo a caller's input back" had one unstated exception.

    `SessionCreateRequest` and `PipelineRunRequest` both declare `extra="forbid"`,
    and pydantic's `extra_forbidden` error puts the caller's own key in `loc` --
    which `_validation_handler` joined straight into `fields`. Measured before the
    fix: a body carrying `{"evil_field_<script>": 1}` answered
    `{"errors":1,"fields":"body.evil_field_<script>"}`, i.e. up to 64 characters of
    attacker-chosen text reflected out of the endpoint whose whole documented
    purpose is not reflecting the caller's input.

    Not a live XSS -- the response is `application/json` under `nosniff` and a
    `default-src 'none'` CSP -- which is the reason to fix it rather than to argue
    about it: the guarantee is what other components are entitled to rely on, and
    an exception nobody wrote down is the one that gets relied on wrongly.

    The canary is a real-shaped original, not a marker string: it is exactly the
    kind of value a client would put in a field name by accident, and the point is
    that no part of it survives.
    """
    canary = "CANARY-David-Ochoa-123-45-6789"
    response = await client.post("/sessions", json={"user_id": OWNER, canary: 1})
    assert response.status_code == 422, response.text
    body = response.text
    assert canary not in body, f"the 422 echoed the caller's own field name: {body}"
    assert "David" not in body and "Ochoa" not in body
    detail = response.json()["detail"]
    assert detail["fields"] == f"body.{EXTRA_FIELD_MARKER}"
    assert detail["errors"] == 1

    # The rewrite must not have flattened *declared* field names too -- naming the
    # schema's own fields is what makes a 422 actionable, and only the caller's
    # half is secret.
    missing = await client.post("/sessions", json={})
    assert missing.status_code == 422
    assert missing.json()["detail"]["fields"] == "body.user_id"
