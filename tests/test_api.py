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
import importlib.metadata
import secrets
import sys
import tempfile
import time
import tomllib
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import pytest_asyncio
from fastapi import FastAPI, UploadFile
from httpx import ASGITransport, AsyncClient
from packaging.requirements import Requirement

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
from secure_context_pipeline.api.schemas import MAX_ID_LEN
from secure_context_pipeline.audit.logger import (
    DETECT,
    EGRESS_PASS,
    LLM_CALL,
    SESSION_CREATE,
)
from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
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
    assert (await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})).status_code == 204


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
    assert (
        await _run(client, mallory_session, mallory_doc, user_id=INTRUDER)
    ).status_code == 200

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

    hostile = await client.delete(
        f"/sessions/{alice_session}", params={"user_id": INTRUDER}
    )
    unknown = await client.delete(
        f"/sessions/{uuid.uuid4().hex}", params={"user_id": INTRUDER}
    )
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
        assert (await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})).status_code == 204
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

    assert (await client.delete(f"/sessions/{session_id}", params={"user_id": OWNER})).status_code == 204
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

    step2 = await client.get(
        "/audit", params={"session_id": victim_session, "user_id": INTRUDER}
    )
    assert step2.json()["events"] == [], "a session's events must not name its owner to a stranger"
    assert OWNER not in step2.text

    # Guessing the scope right is not enough, and neither is holding a live
    # session of one's own: the claim has to match the owner in the log.
    await _create_session(client, INTRUDER)
    assert (
        await client.get("/audit", params={"run_id": run_id, "user_id": INTRUDER})
    ).json()["events"] == []

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

    owned = await client.get(
        "/audit/verify", params={"session_id": session_id, "user_id": OWNER}
    )
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
    assert (
        await client.get("/audit", params={"session_id": session_id, "user_id": "é"})
    ).json()["events"] == []

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
        token.strip("[],\"'")
        for token in copy_line.split()[1:]
        if not token.startswith("--")
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

    # And the deny-list backstop names the two things that must never ship.
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert ".env" in dockerignore
    assert "data/" in dockerignore

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
    app_js = (REPO_ROOT / "secure_context_pipeline" / "ui" / "app.js").read_text(
        encoding="utf-8"
    )
    audit_call = app_js.split("'/audit?session_id='", 1)
    assert len(audit_call) == 2, "the UI must query the audit log"
    request = audit_call[1].split(";", 1)[0]
    assert "user_id" in request, "the UI's audit query must present a user_id"

    # Logout is owner-scoped too, and the same silence applies.
    assert "'?user_id=' + encodeURIComponent(userId())" in app_js, (
        "the UI's logout must present a user_id"
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
    # ``_audit_scope_owner`` answers ``None`` for a scope whose owner it cannot
    # prove, and both callers reject that before comparing. Returning ``""``
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
