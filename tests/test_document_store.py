"""Document store tests (build doc sections 8, 9.1, 10.1).

The security-relevant assertions here are the ones that read the *artifacts*
rather than the API: the bytes actually on disk, and every column of every row
of the metadata database. A store that returned the right plaintext through
``get_text`` while leaving cleartext in a file or a table would pass a naive
round-trip test and fail these.

All personal-looking data is synthesised in-module -- no real names, no real
identifiers, nothing copied from a fixture of a real record.
"""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest

from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.keys import build_key_provider
from secure_context_pipeline.errors import PipelineError, StoreAuthError
from secure_context_pipeline.store import document_store, extraction
from secure_context_pipeline.store.document_store import (
    DOC_CATEGORIES,
    RAW_SUFFIX,
    TEXT_SUFFIX,
    DocumentStore,
    EncryptedDocumentStore,
    InvalidCategoryError,
)

# --- synthetic content ------------------------------------------------------

USER_A = "user-alpha-0001"
USER_B = "user-beta-0002"

#: Invented outright: the name, the record number and the address do not
#: correspond to any person, and the pattern is deliberately unusual so the
#: disk/database scans below cannot pass by coincidence.
SYNTHETIC_TEXT = (
    "Encounter note for Marisol Quintanilla-Vex, record ZQX-4417-PLUM.\n"
    "Address: 88 Nonexistent Causeway, Fictionville.\n"
    "Assessment: patient reports intermittent dizziness after standing.\n"
)
SYNTHETIC_BYTES = SYNTHETIC_TEXT.encode("utf-8")

#: Substrings that must never appear in a blob file or a metadata row.
PLAINTEXT_MARKERS = (
    "Marisol",
    "Quintanilla-Vex",
    "ZQX-4417-PLUM",
    "Nonexistent Causeway",
    "dizziness",
)

FILENAME = "encounter.txt"


# --- helpers ----------------------------------------------------------------


def blob_dir(settings: Settings) -> Path:
    return Path(settings.data_dir) / "documents"


def db_path(settings: Settings) -> Path:
    return Path(settings.data_dir) / "documents.db"


def dump_all_rows(settings: Settings) -> list[tuple[Any, ...]]:
    """Every column of every row of every table, as raw tuples."""
    connection = sqlite3.connect(db_path(settings))
    try:
        tables = [
            str(name)
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        ]
        rows: list[tuple[Any, ...]] = []
        for table in tables:
            rows.extend(connection.execute(f"SELECT * FROM {table}"))
        return rows
    finally:
        connection.close()


def read_every_file(settings: Settings) -> list[tuple[str, bytes]]:
    """Every file the store created under ``data_dir`` -- blobs, database, journals."""
    return [
        (path.name, path.read_bytes())
        for path in sorted(Path(settings.data_dir).rglob("*"))
        if path.is_file()
    ]


@pytest.fixture
async def store(settings: Settings) -> Any:
    async with EncryptedDocumentStore(settings) as opened:
        yield opened


# --- 1. round trip ----------------------------------------------------------


async def test_round_trip_txt(store: EncryptedDocumentStore) -> None:
    """put -> get_text / get_raw returns exactly what went in."""
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    assert len(doc_id) == 32
    assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES

    expected_text = await extraction.extract_text(FILENAME, SYNTHETIC_BYTES)
    assert await store.get_text(USER_A, doc_id) == expected_text
    # Sanity: the extractor did not silently drop the payload.
    for marker in PLAINTEXT_MARKERS:
        assert marker in expected_text


async def test_store_satisfies_the_protocol(store: EncryptedDocumentStore) -> None:
    assert isinstance(store, DocumentStore)


async def test_round_trip_is_extraction_agnostic(
    store: EncryptedDocumentStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Storage does not depend on which extractor ran.

    ``extract_text`` is stubbed so the assertion is about the store alone: a
    PDF's *raw* bytes must survive verbatim while ``get_text`` returns whatever
    the extractor produced.
    """

    async def fake_extract(filename: str, content: bytes) -> str:
        return "extracted surface text\n"

    monkeypatch.setattr(extraction, "extract_text", fake_extract)

    pdf_bytes = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\nnot really a pdf"
    doc_id = await store.put(USER_A, "scan.pdf", pdf_bytes, "medical")

    assert await store.get_raw(USER_A, doc_id) == pdf_bytes
    assert await store.get_text(USER_A, doc_id) == "extracted surface text\n"


# --- 2. what is actually on disk -------------------------------------------


async def test_blobs_on_disk_are_ciphertext(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Read the files directly: no plaintext, and both blobs differ from input."""
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    raw_file = blob_dir(settings) / f"{doc_id}{RAW_SUFFIX}"
    text_file = blob_dir(settings) / f"{doc_id}{TEXT_SUFFIX}"
    assert raw_file.is_file()
    assert text_file.is_file()

    for path in (raw_file, text_file):
        on_disk = path.read_bytes()
        assert on_disk != SYNTHETIC_BYTES
        assert SYNTHETIC_BYTES not in on_disk
        for marker in PLAINTEXT_MARKERS:
            assert marker.encode("utf-8") not in on_disk, f"{marker!r} leaked into {path.name}"
        # nonce (12 B) + tag (16 B) of overhead, at minimum.
        assert len(on_disk) >= len(SYNTHETIC_BYTES) + 28


async def test_no_plaintext_anywhere_under_the_data_dir(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Sweep every file the store created -- blobs, database, WAL journal."""
    await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    await store.close()  # checkpoint the WAL so nothing is hiding in -wal

    files = read_every_file(settings)
    for name, blob in files:
        for marker in PLAINTEXT_MARKERS:
            assert marker.encode("utf-8") not in blob, f"{marker!r} leaked into {name}"
    assert len(files) >= 3  # two blobs plus the database


# --- 3. wrong user ----------------------------------------------------------


async def test_wrong_user_raises_store_auth_error_coded_not_found(
    store: EncryptedDocumentStore,
) -> None:
    """A different derived key fails GCM auth and surfaces as NOT_FOUND."""
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    with pytest.raises(StoreAuthError) as raw_err:
        await store.get_raw(USER_B, doc_id)
    with pytest.raises(StoreAuthError) as text_err:
        await store.get_text(USER_B, doc_id)

    assert raw_err.value.code == "NOT_FOUND"
    assert text_err.value.code == "NOT_FOUND"
    assert StoreAuthError.code == "NOT_FOUND"


async def test_wrong_user_error_carries_no_content(store: EncryptedDocumentStore) -> None:
    """The exception may name the document; it may never quote it."""
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    with pytest.raises(StoreAuthError) as err:
        await store.get_text(USER_B, doc_id)

    rendered = f"{err.value} {err.value!r} {err.value.detail}"
    for marker in PLAINTEXT_MARKERS:
        assert marker not in rendered
    assert FILENAME not in rendered


async def test_tampered_ciphertext_is_rejected(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Flipping one byte of the blob fails authentication rather than decoding."""
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    raw_file = blob_dir(settings) / f"{doc_id}{RAW_SUFFIX}"

    blob = bytearray(raw_file.read_bytes())
    blob[-1] ^= 0x01
    raw_file.write_bytes(bytes(blob))

    with pytest.raises(StoreAuthError):
        await store.get_raw(USER_A, doc_id)


async def test_blob_swapped_between_documents_fails_aad_binding(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """AAD binds ciphertext to one (user, doc); an attacker cannot splice blobs."""
    first = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    second = await store.put(USER_A, "other.txt", b"an unrelated synthetic note\n", "general")

    victim = blob_dir(settings) / f"{second}{RAW_SUFFIX}"
    victim.write_bytes((blob_dir(settings) / f"{first}{RAW_SUFFIX}").read_bytes())

    with pytest.raises(StoreAuthError):
        await store.get_raw(USER_A, second)


async def test_the_two_blobs_of_one_document_share_one_aad(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Where the AAD binding stops, pinned rather than assumed.

    The build doc fixes ``AAD = doc:<user_id>:<doc_id>``, and a document's
    ``.raw`` and ``.txt`` are encrypted under the same key with that same AAD.
    They are therefore interchangeable *with each other* -- the binding is to the
    (user, document) pair, not to the role of the blob within it. The module
    docstring says so; this test is what stops that claim from drifting into the
    stronger one it would be nicer to make.

    The consequence is bounded to integrity: an attacker who can already write
    the data directory can make ``get_raw`` return the extracted text of the
    *same* document for the *same* owner, who could read both anyway. Adding a
    role to the AAD would close it and would deviate from the specified value.
    """
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    raw_path = blob_dir(settings) / f"{doc_id}{RAW_SUFFIX}"
    text_path = blob_dir(settings) / f"{doc_id}{TEXT_SUFFIX}"

    # Distinct ciphertexts (fresh nonce each), same AAD.
    assert raw_path.read_bytes() != text_path.read_bytes()

    raw_path.write_bytes(text_path.read_bytes())
    assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_TEXT.encode("utf-8")

    # The binding still holds where it is claimed to: another user cannot read
    # either half, whichever way round they are on disk.
    with pytest.raises(StoreAuthError):
        await store.get_raw(USER_B, doc_id)


# --- 4. no existence oracle -------------------------------------------------


async def test_absent_and_foreign_documents_are_indistinguishable(
    store: EncryptedDocumentStore,
) -> None:
    """A doc that never existed and another user's doc fail identically."""
    real_doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    absent_doc_id = uuid.uuid4().hex

    with pytest.raises(StoreAuthError) as foreign:
        await store.get_text(USER_B, real_doc_id)
    with pytest.raises(StoreAuthError) as absent:
        await store.get_text(USER_B, absent_doc_id)

    assert type(foreign.value) is type(absent.value)
    assert foreign.value.code == absent.value.code == "NOT_FOUND"
    # Same detail *shape*, and each names only the doc_id the caller asked for --
    # so the response reveals nothing the caller did not already supply.
    assert foreign.value.detail.keys() == absent.value.detail.keys()
    assert foreign.value.detail == {"doc_id": real_doc_id}
    assert absent.value.detail == {"doc_id": absent_doc_id}
    # Substituting the requested id makes the two messages identical.
    assert str(foreign.value).replace(real_doc_id, "X") == str(absent.value).replace(
        absent_doc_id, "X"
    )


async def test_get_category_gives_no_oracle_either(store: EncryptedDocumentStore) -> None:
    """Metadata lookups are user-scoped in SQL, not filtered after the fact."""
    real_doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "legal")
    absent_doc_id = uuid.uuid4().hex

    with pytest.raises(StoreAuthError) as foreign:
        await store.get_category(USER_B, real_doc_id)
    with pytest.raises(StoreAuthError) as absent:
        await store.get_category(USER_B, absent_doc_id)

    assert foreign.value.code == absent.value.code == "NOT_FOUND"
    assert foreign.value.detail.keys() == absent.value.detail.keys()


@pytest.mark.parametrize(
    "hostile_doc_id",
    ["../../etc/passwd", "..%2Fescape", "", "NOT-HEX", "a" * 400],
)
async def test_malformed_doc_id_is_refused_not_resolved(
    store: EncryptedDocumentStore, hostile_doc_id: str
) -> None:
    """Path-traversal attempts get the same NOT_FOUND, with a bounded detail."""
    with pytest.raises(StoreAuthError) as err:
        await store.get_raw(USER_A, hostile_doc_id)
    assert err.value.code == "NOT_FOUND"
    detail = err.value.detail["doc_id"]
    assert isinstance(detail, str)
    assert len(detail) <= 64


# --- 5. metadata holds no plaintext ----------------------------------------


async def test_metadata_table_contains_no_plaintext(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Dump every row of every table and look for the document text."""
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    rows = dump_all_rows(settings)

    assert rows, "expected at least the inserted metadata row"
    dumped = " | ".join(repr(row) for row in rows)

    assert SYNTHETIC_TEXT not in dumped
    for marker in PLAINTEXT_MARKERS:
        assert marker not in dumped, f"{marker!r} leaked into the metadata database"
    # The row exists and holds metadata only.
    assert doc_id in dumped
    assert USER_A in dumped
    assert FILENAME in dumped


async def test_metadata_columns_are_exactly_the_specified_schema(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """No content column can be added without this failing."""
    await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    connection = sqlite3.connect(db_path(settings))
    try:
        columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(documents)")]
    finally:
        connection.close()

    assert columns == [
        "doc_id",
        "user_id",
        "filename",
        "doc_category",
        "created_at",
        "size_bytes",
    ]


# --- 6. doc_category --------------------------------------------------------


@pytest.mark.parametrize("category", sorted(DOC_CATEGORIES))
async def test_doc_category_round_trips(store: EncryptedDocumentStore, category: str) -> None:
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, category)
    assert await store.get_category(USER_A, doc_id) == category


async def test_doc_category_may_be_none(store: EncryptedDocumentStore) -> None:
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, None)
    assert await store.get_category(USER_A, doc_id) is None


@pytest.mark.parametrize("bad", ["MEDICAL", "medical ", "hr", "", "general;drop"])
async def test_invalid_doc_category_is_rejected(
    store: EncryptedDocumentStore, settings: Settings, bad: str
) -> None:
    """Rejected before anything is written -- no blob, no row."""
    with pytest.raises(InvalidCategoryError) as err:
        await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, bad)

    assert isinstance(err.value, PipelineError)
    assert err.value.code == "INVALID_DOC_CATEGORY"
    assert list(blob_dir(settings).iterdir()) == []
    assert await store.list_docs(USER_A) == []


# --- 7. identical content, different users ---------------------------------


async def test_identical_content_from_two_users_yields_different_ciphertext(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Different derived keys and different AAD ⇒ no cross-user correlation."""
    doc_a = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    doc_b = await store.put(USER_B, FILENAME, SYNTHETIC_BYTES, "medical")

    blob_a = (blob_dir(settings) / f"{doc_a}{RAW_SUFFIX}").read_bytes()
    blob_b = (blob_dir(settings) / f"{doc_b}{RAW_SUFFIX}").read_bytes()

    assert blob_a != blob_b
    # Beyond the nonce: the ciphertext bodies differ too, so an observer cannot
    # tell that the two users uploaded the same file.
    assert blob_a[12:] != blob_b[12:]
    assert await store.get_raw(USER_A, doc_a) == await store.get_raw(USER_B, doc_b)


async def test_same_user_same_content_still_gets_a_fresh_nonce(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Nonces are drawn per blob, never derived or reused."""
    first = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    second = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    blob_1 = (blob_dir(settings) / f"{first}{RAW_SUFFIX}").read_bytes()
    blob_2 = (blob_dir(settings) / f"{second}{RAW_SUFFIX}").read_bytes()

    assert blob_1[:12] != blob_2[:12]
    assert blob_1 != blob_2


async def test_key_provider_is_the_seam(settings: Settings) -> None:
    """A store built on an injected provider behaves identically (KMS-compatible)."""
    provider = build_key_provider(settings)
    async with EncryptedDocumentStore(settings, provider) as scoped:
        doc_id = await scoped.put(USER_A, FILENAME, SYNTHETIC_BYTES, "financial")
        assert await scoped.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES


#: User IDs chosen to break naive key/AAD framing: prefixes, suffixes, and IDs
#: that straddle the ``:`` delimiter used by ``doc:<user_id>:<doc_id>``. If the
#: HKDF ``info`` were built by concatenation without the whole ID being the
#: terminal field, ``"al" + "ice"`` would derive the same key as ``"alice"``.
CONFUSABLE_USER_IDS = (
    "al",
    "ali",
    "alic",
    "alice",
    "alice2",
    "alice:",
    ":alice",
    "al:ice",
    "doc:alice",
    "alice ",
    "ALICE",
    "alicé",
)


async def test_confusable_user_ids_derive_distinct_keys(settings: Settings) -> None:
    """Prefix/suffix/delimiter-straddling user IDs must never share a document key."""
    provider = build_key_provider(settings)
    keys = {user_id: provider.doc_key(user_id) for user_id in CONFUSABLE_USER_IDS}

    assert len(set(keys.values())) == len(CONFUSABLE_USER_IDS), "two user IDs share a key"


async def test_confusable_user_ids_cannot_read_each_others_documents(
    store: EncryptedDocumentStore,
) -> None:
    """Every pair in the confusable set is isolated, in both directions.

    This is the concrete form of the framing question: ``"al"`` holding a
    ``doc_id`` that starts with ``"ice:"`` would produce the same AAD string as
    ``"alice"`` holding the rest of it. It is unreachable for two independent
    reasons -- the derived keys differ, and ``doc_id`` is constrained to 32 hex
    characters -- and this pins both.
    """
    # Bodies are keyed by index, not by the user ID itself: several of these IDs
    # differ only in whitespace or case, which text normalisation would erase.
    bodies = {
        user_id: f"document body number {index}"
        for index, user_id in enumerate(CONFUSABLE_USER_IDS)
    }
    docs = {
        user_id: await store.put(user_id, FILENAME, body.encode(), "general")
        for user_id, body in bodies.items()
    }

    for owner, doc_id in docs.items():
        assert await store.get_text(owner, doc_id) == f"{bodies[owner]}\n"
        for other in CONFUSABLE_USER_IDS:
            if other == owner:
                continue
            with pytest.raises(StoreAuthError) as err:
                await store.get_text(other, doc_id)
            assert err.value.code == "NOT_FOUND"
            with pytest.raises(StoreAuthError):
                await store.get_raw(other, doc_id)
            with pytest.raises(StoreAuthError):
                await store.get_category(other, doc_id)
        assert [meta.doc_id for meta in await store.list_docs(owner)] == [doc_id]


# --- 8. list_docs scoping ---------------------------------------------------


async def test_list_docs_is_scoped_to_the_owning_user(store: EncryptedDocumentStore) -> None:
    mine_first = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    mine_second = await store.put(USER_A, "second.txt", b"another synthetic note\n", "general")
    theirs = await store.put(USER_B, "theirs.txt", b"a third synthetic note\n", "legal")

    mine = await store.list_docs(USER_A)
    assert {meta.doc_id for meta in mine} == {mine_first, mine_second}
    assert theirs not in {meta.doc_id for meta in mine}

    other = await store.list_docs(USER_B)
    assert [meta.doc_id for meta in other] == [theirs]

    assert await store.list_docs("user-gamma-0003") == []


async def test_list_docs_returns_metadata_only(store: EncryptedDocumentStore) -> None:
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    (meta,) = await store.list_docs(USER_A)

    assert meta.doc_id == doc_id
    assert meta.filename == FILENAME
    assert meta.doc_category == "medical"
    assert meta.size_bytes == len(SYNTHETIC_BYTES)
    assert meta.created_at > 0

    dumped = repr(meta)
    for marker in PLAINTEXT_MARKERS:
        assert marker not in dumped


# --- lifecycle --------------------------------------------------------------


async def test_metadata_survives_reopening(settings: Settings) -> None:
    """One connection per instance, but the store on disk outlives the instance."""
    async with EncryptedDocumentStore(settings) as first:
        doc_id = await first.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    async with EncryptedDocumentStore(settings) as second:
        assert await second.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES
        assert await second.get_category(USER_A, doc_id) == "medical"
        assert [meta.doc_id for meta in await second.list_docs(USER_A)] == [doc_id]


async def test_close_is_idempotent(settings: Settings) -> None:
    opened = await EncryptedDocumentStore.open(settings)
    await opened.close()
    await opened.close()
    # And it reopens on demand rather than failing.
    assert await opened.list_docs(USER_A) == []
    await opened.close()


async def test_wal_mode_is_enabled(store: EncryptedDocumentStore, settings: Settings) -> None:
    await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    connection = sqlite3.connect(db_path(settings))
    try:
        (mode,) = connection.execute("PRAGMA journal_mode").fetchone()
    finally:
        connection.close()
    assert str(mode).lower() == "wal"


async def test_unsupported_file_type_stores_nothing(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """An extraction failure must not leave a half-written document behind."""
    with pytest.raises(PipelineError):
        await store.put(USER_A, "payload.exe", b"MZ\x90\x00 not a document", "general")

    assert list(blob_dir(settings).iterdir()) == []
    assert await store.list_docs(USER_A) == []


# --- 9. partial writes leave nothing behind ---------------------------------


@pytest.mark.parametrize("failing_write", [1, 2])
async def test_a_failed_blob_write_leaves_no_orphan(
    store: EncryptedDocumentStore, settings: Settings, failing_write: int
) -> None:
    """Either blob write failing must roll the whole ``put`` back.

    ``put`` writes ``.raw`` then ``.txt`` then the metadata row. A disk that
    fills up between the two writes used to leave the ``.raw`` blob on disk with
    no row pointing at it: unreachable through the API, so nothing would ever
    delete it, and it counts against the disk for the life of the deployment.
    """
    real_write = store._write_blob
    attempts = 0

    async def failing_blob_write(path: Path, blob: bytes) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == failing_write:
            raise OSError(28, "No space left on device")
        await real_write(path, blob)

    store._write_blob = failing_blob_write  # type: ignore[method-assign]

    with pytest.raises(OSError, match="No space left"):
        await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    assert list(blob_dir(settings).iterdir()) == []
    assert await store.list_docs(USER_A) == []


async def test_a_failed_metadata_insert_leaves_no_orphan(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Both blobs land, then the row fails: both blobs must be removed."""
    connection = await store._connection()
    real_execute = connection.execute

    async def failing_execute(sql: str, *args: Any, **kwargs: Any) -> Any:
        if sql.startswith("INSERT INTO documents"):
            raise sqlite3.OperationalError("database is locked")
        return await real_execute(sql, *args, **kwargs)

    connection.execute = failing_execute  # type: ignore[method-assign]
    try:
        with pytest.raises(sqlite3.OperationalError):
            await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    finally:
        connection.execute = real_execute  # type: ignore[method-assign]

    assert list(blob_dir(settings).iterdir()) == []
    assert await store.list_docs(USER_A) == []


async def test_a_cancelled_put_leaves_no_orphan(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """A client disconnecting mid-upload is a cancellation, not an exception.

    ``CancelledError`` derives from ``BaseException``, so an ``except Exception``
    cleanup handler would let it sail past and strand the first blob.
    """
    real_write = store._write_blob
    writes = 0

    async def cancel_on_second_write(path: Path, blob: bytes) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise asyncio.CancelledError
        await real_write(path, blob)

    store._write_blob = cancel_on_second_write  # type: ignore[method-assign]

    with pytest.raises(asyncio.CancelledError):
        await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")

    assert list(blob_dir(settings).iterdir()) == []
    assert await store.list_docs(USER_A) == []


# --- 9b. unclean shutdown leaves collectable orphans ------------------------


async def kill_mid_put(store: EncryptedDocumentStore, monkeypatch: pytest.MonkeyPatch) -> None:
    """Land both blobs on disk with no metadata row and no cleanup.

    A ``SIGKILL``, an OOM kill or a power cut between the blob writes and the
    commit runs no ``except`` handler at all, so modelling it means suppressing
    ``put``'s unwind as well as failing the insert. What is left behind is
    exactly what a post-crash data directory looks like.
    """
    connection = await store._connection()
    real_execute = connection.execute

    async def failing_execute(sql: str, *args: Any, **kwargs: Any) -> Any:
        if sql.startswith("INSERT INTO documents"):
            raise sqlite3.OperationalError("process died")
        return await real_execute(sql, *args, **kwargs)

    async def no_cleanup(doc_id: str, path: Path) -> None:
        return None

    monkeypatch.setattr(connection, "execute", failing_execute)
    monkeypatch.setattr(store, "_unlink_quietly", no_cleanup)
    with pytest.raises(sqlite3.OperationalError):
        await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    monkeypatch.undo()


async def test_sweep_orphans_collects_blobs_left_by_an_unclean_shutdown(
    store: EncryptedDocumentStore, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metadata is the source of truth, so a blob with no row is unreachable disk.

    ``put`` unwinds itself on every exception including cancellation, but a
    process that is killed runs no handler. Nothing else in the store can ever
    name those files again -- ``doc_id`` only comes from a row -- so without a
    sweep they are permanent.
    """
    live = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    await kill_mid_put(store, monkeypatch)

    orphans = sorted(p.name for p in blob_dir(settings).iterdir() if not p.name.startswith(live))
    assert len(orphans) == 2, "the crash simulation did not strand both blobs"

    removed = await store.sweep_orphans(min_age_seconds=0)

    assert removed == 2
    assert sorted(p.name for p in blob_dir(settings).iterdir()) == [
        f"{live}{RAW_SUFFIX}",
        f"{live}{TEXT_SUFFIX}",
    ]
    # The surviving document is untouched and still decrypts.
    assert await store.get_text(USER_A, live) == SYNTHETIC_TEXT
    assert await store.get_raw(USER_A, live) == SYNTHETIC_BYTES


async def test_sweep_orphans_collects_a_half_written_document(
    store: EncryptedDocumentStore, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash between the two blob writes strands exactly one file, not a pair."""
    real_write = store._write_blob
    writes = 0

    async def die_before_the_second_write(path: Path, blob: bytes) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError(5, "I/O error")
        await real_write(path, blob)

    async def no_cleanup(doc_id: str, path: Path) -> None:
        return None

    monkeypatch.setattr(store, "_write_blob", die_before_the_second_write)
    monkeypatch.setattr(store, "_unlink_quietly", no_cleanup)
    with pytest.raises(OSError, match="I/O error"):
        await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    monkeypatch.undo()

    assert len(list(blob_dir(settings).iterdir())) == 1
    assert await store.sweep_orphans(min_age_seconds=0) == 1
    assert list(blob_dir(settings).iterdir()) == []


async def test_sweep_orphans_spares_a_document_being_written_right_now(
    store: EncryptedDocumentStore, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The age margin is what makes the sweep safe to run against a live store.

    Between ``put``'s blob writes and its commit the blobs exist with no row --
    indistinguishable, by state alone, from a crash orphan. Deleting them there
    would corrupt an upload in flight, so recency is the tie-breaker.
    """
    await kill_mid_put(store, monkeypatch)
    before = sorted(p.name for p in blob_dir(settings).iterdir())
    assert len(before) == 2

    assert await store.sweep_orphans() == 0
    assert sorted(p.name for p in blob_dir(settings).iterdir()) == before


async def test_sweep_orphans_leaves_files_it_does_not_recognise(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """A delete loop over a shared directory must not act on names it cannot parse."""
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    strangers = ["README", "notes.txt.bak", f"{'z' * 32}{RAW_SUFFIX}", "short.raw"]
    for name in strangers:
        (blob_dir(settings) / name).write_bytes(b"not ours\n")

    assert await store.sweep_orphans(min_age_seconds=0) == 0
    assert sorted(p.name for p in blob_dir(settings).iterdir()) == sorted(
        [*strangers, f"{doc_id}{RAW_SUFFIX}", f"{doc_id}{TEXT_SUFFIX}"]
    )


async def test_sweep_orphans_on_a_clean_store_is_a_no_op(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """The startup path costs one query and one directory listing when nothing is wrong."""
    for index in range(3):
        await store.put(USER_A, f"note-{index}.txt", SYNTHETIC_BYTES, "medical")

    assert await store.sweep_orphans(min_age_seconds=0) == 0
    assert len(list(blob_dir(settings).iterdir())) == 6
    assert len(await store.list_docs(USER_A)) == 3


# --- 10. the traversal guard runs before any I/O ----------------------------


@pytest.mark.parametrize(
    "hostile_doc_id",
    ["../../etc/passwd", "../vault", "..%2Fescape", "", "NOT-HEX", "a" * 400, "x" * 32],
)
async def test_malformed_doc_id_never_reaches_the_filesystem(
    store: EncryptedDocumentStore, monkeypatch: pytest.MonkeyPatch, hostile_doc_id: str
) -> None:
    """The ``doc_id`` guard must reject *before* the path is opened.

    Asserting only on the error is not enough: with the guard deleted every case
    below still raises ``StoreAuthError``, because the traversal target happens
    not to exist or fails to decrypt. What actually distinguishes a guarded store
    is that the caller-supplied string never becomes a path that gets opened.
    """
    opened: list[Any] = []

    def refuse_to_open(path: Any, *args: Any, **kwargs: Any) -> Any:
        opened.append(path)
        raise AssertionError(f"filesystem touched with a rejected doc_id: {path!r}")

    monkeypatch.setattr(document_store.aiofiles, "open", refuse_to_open)

    for accessor in (store.get_raw, store.get_text):
        with pytest.raises(StoreAuthError) as err:
            await accessor(USER_A, hostile_doc_id)
        assert err.value.code == "NOT_FOUND"
    assert opened == []
