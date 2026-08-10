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
import base64
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from httpx import ASGITransport, AsyncClient

from secure_context_pipeline.api.app import create_app
from secure_context_pipeline.api.constants import MAX_UPLOAD_BYTES
from secure_context_pipeline.audit import logger as audit_logger
from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.aead import decrypt, doc_aad, encrypt
from secure_context_pipeline.crypto.keys import build_key_provider
from secure_context_pipeline.errors import PipelineError, StoreAuthError
from secure_context_pipeline.store import document_store, extraction
from secure_context_pipeline.store.document_store import (
    DOC_CATEGORIES,
    NOT_FOUND_FLOOR_S,
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


async def test_get_text_fails_closed_on_an_authentic_blob_that_is_not_utf8(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """A text blob that authenticates but is not utf-8 must raise, never decode lossily.

    ``get_text``'s ``UnicodeDecodeError`` handler is documented as unreachable
    via ``put``, and that is true -- GCM has authenticated the very bytes ``put``
    encoded as utf-8. It does not follow that the handler is untestable, and
    "unreachable, therefore no test" is how a fail-closed branch quietly becomes
    a fail-open one: replacing ``plaintext.decode("utf-8")`` with
    ``decode("utf-8", errors="replace")`` -- returning U+FFFD-riddled text out of
    a corrupt store instead of ``NOT_FOUND`` -- changed nothing any assertion
    could observe.

    What AES-GCM prevents is an *attacker* forging such a blob. A test holds the
    key, so it can forge one, and so could a future edit to ``put`` that wrote
    raw bytes where it means to write encoded text. The forgery is done with the
    store's own key and its own AAD so that the blob is authentic in every
    respect except its encoding.

    The middle assertion is the one that stops this test from passing for the
    wrong reason: it proves the blob really does decrypt, so the refusal has to
    be coming from the decode step rather than from the ``CryptoAuthError`` path
    that every other tampering test in this file exercises.
    """
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    text_path = blob_dir(settings) / f"{doc_id}{TEXT_SUFFIX}"

    key = store._keys.doc_key(USER_A)
    aad = doc_aad(USER_A, doc_id)
    # A lone continuation byte and a bare 0x80: invalid utf-8 in any position.
    not_utf8 = b"\xff\xfe\x80 encounter note \x80\xff"
    text_path.write_bytes(encrypt(key, not_utf8, aad))

    assert decrypt(key, text_path.read_bytes(), aad, scope="document_text") == not_utf8, (
        "the forged blob must authenticate, or this test proves nothing about the decode"
    )

    with pytest.raises(StoreAuthError) as err:
        await store.get_text(USER_A, doc_id)
    assert err.value.code == "NOT_FOUND"
    # Same response an absent document produces: a corrupt store is not a
    # distinguishable one.
    assert "�" not in str(err.value)

    # Scoped to the damaged blob: the raw half is untouched and still readable.
    assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES


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


# --- 3b. the TIMING half of "indistinguishable" -----------------------------
#
# The two tests above close the CONTENT oracle: same exception, same code, same
# detail keys. They say nothing about how long the answer took, and the answer took
# very different lengths of time -- an absent doc_id failed at ENOENT before a byte
# of crypto while a wrong-owner one was read off disk in full and only then rejected
# by AES-GCM. Measured on this machine before the floor existed, medians over 400
# samples per arm: 2.85x at 5.6 KB, 10.4x at 2.25 MiB, 18.8x at 8 MiB, 34.3x at
# 16 MiB, growing linearly with the blob because the cost is the decrypt.
#
# Section 9.1 asks for the two to be indistinguishable "so there is no existence
# oracle". A byte-identical body on a distinguishable schedule is still an oracle,
# so these are the other half of that requirement.

#: Timing samples per arm. Enough that a real gap cannot hide in scheduler noise,
#: small enough that the pad (8 ms each) keeps the whole section around a second.
_TIMING_SAMPLES = 25


def _floor_bypassed(store: EncryptedDocumentStore) -> None:
    """Turn the floor off on this store instance, for measuring what it hides."""
    store._not_found_floor_s = 0.0


async def _time_not_found(call: Any, *args: Any) -> float:
    """Seconds a single expected-``StoreAuthError`` call takes. Raises if it succeeds."""
    started = time.perf_counter()
    try:
        await call(*args)
    except StoreAuthError:
        return time.perf_counter() - started
    raise AssertionError(f"{call.__qualname__} unexpectedly succeeded")


async def _sample(call: Any, *args: Any) -> list[float]:
    for _ in range(3):  # warm the page cache and the analyzer-free paths
        await _time_not_found(call, *args)
    return [await _time_not_found(call, *args) for _ in range(_TIMING_SAMPLES)]


async def test_a_wrong_owner_and_an_absent_document_are_indistinguishable_in_time(
    store: EncryptedDocumentStore,
) -> None:
    """The oracle itself: enumerate stored ``doc_id``s with a stopwatch. Closed.

    Compared on the **minimum** of each arm, not the mean or the median, and that
    is the robustness argument rather than a shortcut: contention can only ever make
    a sample slower, so the minimum is the one statistic a loaded machine cannot
    inflate. It is also the statistic an attacker would use, for the same reason.

    A 4 MiB document, because the gap this closes is proportional to blob size and a
    few-kilobyte document makes a real 2.85x regression look like 0.1 ms of noise.
    At 4 MiB the pre-floor arms were 0.15 ms and 1.49 ms -- a ratio no tolerance
    below an order of magnitude can absorb.

    The positive control runs first and with the floor switched off, so this test
    fails if the *measurement* stops working, rather than passing because both arms
    became equally unmeasurable.
    """
    body = b"x" * (4 * 1024 * 1024)
    doc_id = await store.put(USER_A, FILENAME, body, "medical")
    absent = uuid.uuid4().hex

    _floor_bypassed(store)
    bare_absent = min(await _sample(store.get_text, USER_B, absent))
    bare_wrong = min(await _sample(store.get_text, USER_B, doc_id))
    assert bare_wrong / bare_absent > 3.0, (
        f"positive control failed: unpadded, the two arms measured {bare_absent * 1e3:.3f} ms "
        f"and {bare_wrong * 1e3:.3f} ms. If they are already equal here, this test can no "
        "longer tell a closed oracle from a broken stopwatch."
    )

    store._not_found_floor_s = NOT_FOUND_FLOOR_S
    absent_min = min(await _sample(store.get_text, USER_B, absent))
    wrong_min = min(await _sample(store.get_text, USER_B, doc_id))
    ratio = wrong_min / absent_min
    assert 0.9 <= ratio <= 1.15, (
        f"timing oracle: absent={absent_min * 1e3:.4f} ms wrong-owner={wrong_min * 1e3:.4f} ms "
        f"ratio={ratio:.2f}x"
    )
    assert abs(wrong_min - absent_min) < 0.001, "arms differ by more than a millisecond"


@pytest.mark.parametrize(
    ("reason", "doc_id_for"),
    [
        pytest.param("absent", lambda real: uuid.uuid4().hex, id="absent"),
        pytest.param("wrong_owner", lambda real: real, id="wrong-owner"),
        pytest.param("malformed", lambda real: "../../etc/passwd", id="malformed"),
    ],
)
@pytest.mark.parametrize("method", ["get_text", "get_raw", "get_category"])
async def test_every_not_found_reason_waits_out_the_floor(
    store: EncryptedDocumentStore, reason: str, doc_id_for: Any, method: str
) -> None:
    """Not just the two arms in the finding -- every reason, on every read method.

    Padding only "absent" against "wrong owner" would close the named oracle and
    leave "malformed doc_id vs absent" open right beside it, which is the same
    defect one input class to the left. The floor is applied per *public read*, so
    the property to assert is that no ``StoreAuthError`` from any of the three
    arrives early, whatever produced it.
    """
    real = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    elapsed = await _time_not_found(getattr(store, method), USER_B, doc_id_for(real))
    assert elapsed >= NOT_FOUND_FLOOR_S, (
        f"{method}/{reason} returned NOT_FOUND after {elapsed * 1e3:.3f} ms, "
        f"inside the {NOT_FOUND_FLOOR_S * 1e3:.1f} ms floor"
    )


@pytest.mark.parametrize("prior_work_s", [0.0, 0.0053])
async def test_the_floor_converges_on_its_deadline_rather_than_sleeping_to_it(
    store: EncryptedDocumentStore, prior_work_s: float
) -> None:
    """``asyncio.sleep(remaining)`` alone leaves a signal, inverted. Pin the fix.

    A single sleep wakes late by an amount that grows with how long it was asked to
    sleep, so the arm that did the *least* work overshoots the *most*. Measured at an
    8 ms floor: 9.028 ms after no work, 8.202 ms after 5.3 ms of it -- monotone,
    0.83 ms wide, and readable as the same existence bit with the sign flipped.
    ``_wait_out_floor`` sleeps to within a slack and then yields to the deadline,
    which brings both to 8.007 ms.

    Both parametrisations are asserted against the same absolute band, which is what
    makes the assertion about *convergence* rather than about either arm on its own:
    a plain sleep fails the ``0.0`` case at ~1.03 ms over and passes the ``0.0053``
    one at ~0.20 ms over, so a single-value test would have been a coin flip.
    ``min`` for the reason the test above gives -- load can only add.
    """
    samples = []
    for _ in range(12):
        started = time.perf_counter() - prior_work_s
        await store._wait_out_floor(started)
        samples.append(time.perf_counter() - started)
    overshoot = min(samples) - NOT_FOUND_FLOOR_S
    assert overshoot >= 0.0, "the floor returned EARLY, which breaks the guarantee"
    assert overshoot < 0.0005, (
        f"floor overshoot {overshoot * 1e3:.3f} ms after {prior_work_s * 1e3:.1f} ms of "
        "prior work; the deadline is being slept to rather than converged on"
    )


async def test_a_successful_read_is_not_slowed_by_the_floor(
    store: EncryptedDocumentStore,
) -> None:
    """The floor pads refusals only, and that restraint has to be asserted.

    A document's owner is already distinguishable from everybody else by receiving
    the document, so spending latency to hide a difference the response body
    announces buys nothing and would put the floor on the hot path of every legitimate
    read. Without this test, "pad everything" passes every other assertion in this
    section while making the pipeline 8 ms slower per document for no security gain.
    """
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    started = time.perf_counter()
    assert await store.get_text(USER_A, doc_id) == SYNTHETIC_TEXT
    assert time.perf_counter() - started < NOT_FOUND_FLOOR_S


async def test_the_not_found_floor_covers_the_api_upload_ceiling(
    store: EncryptedDocumentStore,
) -> None:
    """Calibration: the floor is sized from ``MAX_UPLOAD_BYTES``, so check it still is.

    The floor only hides a wrong-owner read whose decrypt finishes *inside* it, so
    the constant is only meaningful relative to the largest blob that can exist.
    ``MAX_UPLOAD_BYTES`` is what bounds a ``.raw`` blob, and ``document_store``
    deliberately does not import it -- the store must not depend on the HTTP layer --
    so the linkage lives here or nowhere.

    Measured against the real ceiling rather than extrapolated from a small blob,
    because the whole failure mode being guarded is a cost that grows with size.
    A failure here means the constant needs raising *on this hardware*; it does not
    mean the mechanism is broken.
    """
    _floor_bypassed(store)
    doc_id = await store.put(USER_A, FILENAME, b"y" * MAX_UPLOAD_BYTES, None)
    worst = max(await _sample(store.get_raw, USER_B, doc_id))
    assert worst < NOT_FOUND_FLOOR_S, (
        f"a wrong-owner read of a {MAX_UPLOAD_BYTES}-byte blob costs {worst * 1e3:.2f} ms, "
        f"which is outside the {NOT_FOUND_FLOOR_S * 1e3:.1f} ms floor -- so the largest "
        "document the API accepts is still distinguishable from an absent one. Raise "
        "NOT_FOUND_FLOOR_S and re-measure the table above it."
    )


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


async def test_concurrent_connection_opens_exactly_one_connection(settings: Settings) -> None:
    """Racing ``_connection`` must not leak an aiosqlite thread.

    ``aiosqlite`` backs every connection with a **non-daemon** thread, so a
    connection that is opened, overwritten by a racing opener and never closed
    keeps the interpreter alive at shutdown: the process hangs instead of
    exiting. The vault has exactly this test; the store has the same
    double-check under the same kind of lock and had no test at all, so deleting
    it kept the whole suite green. It opens six connections for six callers and
    strands five of them -- measured, not inferred.
    """
    store = EncryptedDocumentStore(settings)
    # ``aiosqlite.Connection`` *is* the thread, so these objects are exactly the
    # threads that would be stranded.
    connections: list[Any] = []
    real_connect = document_store.aiosqlite.connect

    def counting_connect(*args: Any, **kwargs: Any) -> Any:
        connection = real_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(document_store.aiosqlite, "connect", counting_connect)
        await asyncio.gather(*(store._connection() for _ in range(6)))

    assert len(connections) == 1, f"{len(connections)} connections opened, expected 1"

    # The one connection is the one the store actually uses.
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES
    await store.close()

    deadline = time.monotonic() + 5.0
    while any(connection.is_alive() for connection in connections):
        assert time.monotonic() < deadline, "an aiosqlite thread outlived close()"
        await asyncio.sleep(0.01)


async def test_a_close_landing_mid_upload_does_not_strand_the_write(
    settings: Settings,
) -> None:
    """A shutdown between the blob writes and the metadata INSERT must not break the put.

    ``put`` used to resolve its connection *before* two real awaits and use it
    after them, so an ordinary ``close`` landing in that window -- a shutdown
    while an upload is in flight -- made the INSERT raise a bare
    ``ValueError: no active connection``: an unstructured 500 out of a method
    documented to raise ``PipelineError`` and nothing else. No existing test
    could see it, because every other test closes the store only once its puts
    have finished.

    The handle is now resolved inside ``_write_lock`` and ``close`` takes that
    same lock, so the two serialise. The upload finishes against a reopened
    connection, which is the behaviour ``test_close_is_idempotent`` already
    documents for every other accessor.
    """
    store = await EncryptedDocumentStore.open(settings)
    real_write = store._write_blob
    parked = asyncio.Event()
    resume = asyncio.Event()

    async def park_after_the_first_write(path: Path, blob: bytes) -> None:
        await real_write(path, blob)
        if not parked.is_set():
            parked.set()
            await resume.wait()

    store._write_blob = park_after_the_first_write  # type: ignore[method-assign]
    upload = asyncio.create_task(store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical"))
    await parked.wait()
    assert not upload.done(), "the upload was supposed to park between its two blob writes"

    await store.close()
    resume.set()
    doc_id = await upload

    assert await store.get_text(USER_A, doc_id) == SYNTHETIC_TEXT
    assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES
    assert [meta.doc_id for meta in await store.list_docs(USER_A)] == [doc_id]
    await store.close()


async def test_connection_never_hands_out_the_connection_close_is_closing(
    settings: Settings,
) -> None:
    """``close`` must detach ``self._db`` *before* it awaits the connection closed.

    ``_connection``'s fast path reads ``self._db`` with no lock held at all --
    the docstring's "resolved while ``_open_lock`` is still held" argument covers
    only the slow path below it. While ``close`` cleared the attribute *after*
    ``await self._db.close()``, that unlocked read returned the very connection
    being closed, and the caller's next statement raised
    ``ValueError: no active connection``. Detaching first makes the fast path
    structurally unable to observe a half-closed connection.
    """
    store = await EncryptedDocumentStore.open(settings)
    original = store._db
    assert original is not None

    entered = asyncio.Event()
    release = asyncio.Event()
    real_close = original.close

    async def parked_close() -> None:
        entered.set()
        await release.wait()
        await real_close()

    original.close = parked_close  # type: ignore[method-assign]
    closer = asyncio.create_task(store.close())
    await entered.wait()

    handed_out = await store._connection()
    assert handed_out is not original, "the store handed out the connection it was closing"

    release.set()
    await closer
    # The replacement is a working connection, not a husk.
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES
    await store.close()

    deadline = time.monotonic() + 5.0
    while original.is_alive() or handed_out.is_alive():
        assert time.monotonic() < deadline, "an aiosqlite thread outlived close()"
        await asyncio.sleep(0.01)


async def test_close_waits_for_an_in_flight_metadata_write(settings: Settings) -> None:
    """``close`` takes ``_write_lock``, so it cannot detach mid-INSERT.

    ``put`` yields between its ``execute`` and its ``commit``. A ``close`` that
    only took ``_open_lock`` could land there, close the connection, and leave
    the commit to fail on a dead handle -- a shutdown turning a nearly-complete
    upload into an unstructured error. Taking ``_write_lock`` makes the shutdown
    *wait* for the write it interrupted instead of racing it.

    What this test does **not** prove is the acquisition *order*. An earlier
    version of this docstring claimed "this test would hang rather than fail if
    that order were inverted", and that is false: swapping ``close`` to take
    ``_open_lock`` outside ``_write_lock`` leaves all of this file green,
    including this test, because ``put`` only reaches for ``_open_lock`` when
    ``self._db`` is ``None`` and nothing here opens a connection concurrently
    with a close. Removing ``_write_lock`` from ``close`` altogether is what this
    test catches -- a removal, not an inversion. The order is pinned separately,
    by ``test_close_and_a_first_upload_do_not_deadlock_on_the_two_locks``.
    """
    store = await EncryptedDocumentStore.open(settings)
    db = await store._connection()
    real_commit = db.commit
    at_commit = asyncio.Event()
    proceed = asyncio.Event()

    async def parked_commit() -> None:
        at_commit.set()
        await proceed.wait()
        await real_commit()

    db.commit = parked_commit  # type: ignore[method-assign]
    try:
        upload = asyncio.create_task(store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical"))
        await at_commit.wait()

        closer = asyncio.create_task(store.close())
        for _ in range(10):
            await asyncio.sleep(0)
        assert not closer.done(), (
            "close() detached the connection out from under an in-flight INSERT"
        )

        proceed.set()
        doc_id = await upload
        await closer
    finally:
        db.commit = real_commit  # type: ignore[method-assign]

    async with EncryptedDocumentStore(settings) as reopened:
        assert [meta.doc_id for meta in await reopened.list_docs(USER_A)] == [doc_id]
        assert await reopened.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES


def lock_waiters(lock: asyncio.Lock) -> int:
    """How many coroutines are parked on ``lock``.

    ``asyncio.Lock`` publishes no waiter count, and the two lock-ordering tests
    below need one: both have to place a coroutine on a specific queue before
    releasing the next, and "it has not finished yet" is not the same statement.
    """
    waiters = getattr(lock, "_waiters", None) or ()
    return sum(1 for waiter in waiters if not waiter.cancelled())


async def park_on_lock(lock: asyncio.Lock, expected: int, *, what: str) -> None:
    """Run the event loop until ``expected`` coroutines are queued on ``lock``.

    Bounded, and every caller must unpark its coroutines and close its store in a
    ``finally``. Both tests below park a real upload on an ``asyncio.Event`` and
    hold a live aiosqlite connection while they do it; raising from here without
    that cleanup leaves a non-daemon thread alive and the *process* hangs at
    exit, turning a red test into the CI job timeout ``pyproject.toml`` says a
    security suite cannot afford. Measured: it hangs, it does not report.
    """
    for _ in range(2_000):
        if lock_waiters(lock) >= expected:
            return
        await asyncio.sleep(0.001)
    raise AssertionError(f"{what}: {lock_waiters(lock)} queued on the lock, expected {expected}")


async def test_close_and_a_first_upload_do_not_deadlock_on_the_two_locks(
    settings: Settings,
) -> None:
    """``close`` must take ``_write_lock`` **outside** ``_open_lock``, not inside.

    This is the half of the ordering claim that
    ``test_close_waits_for_an_in_flight_metadata_write`` does not establish.
    ``put`` holds ``_write_lock`` and then asks ``_connection`` for
    ``_open_lock``; ``close`` wants both. Acquire them in the opposite order and
    the two are a textbook AB-BA: whichever holds ``_open_lock`` waits forever
    for ``_write_lock``, and vice versa.

    Nothing in this file used to build that interleaving, so the inversion was
    invisible -- 61 green -- even though the deadlock is real and reachable: a
    shutdown arriving while the *first* upload of the process is still resolving
    its connection. The store is therefore constructed rather than ``open``ed, so
    ``self._db`` is ``None`` and ``put`` must take the slow path that needs
    ``_open_lock``; the upload is parked in the gap between the two acquires; and
    the close is queued while it sits there.

    A deadlock cannot be asserted by waiting forever, so the tasks are given a
    bounded window and the test fails on what is still pending. Under the shipped
    order both finish in milliseconds.
    """
    store = EncryptedDocumentStore(settings)
    assert store._db is None, "the deadlock needs put to open the connection itself"

    entered = asyncio.Event()
    release = asyncio.Event()
    real_connection = store._connection

    async def parked_connection() -> Any:
        # Parks *after* put has taken _write_lock and *before* _open_lock.
        if not entered.is_set():
            entered.set()
            await release.wait()
        return await real_connection()

    store._connection = parked_connection  # type: ignore[method-assign]

    upload = asyncio.create_task(store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical"))
    closer: asyncio.Task[None] | None = None
    try:
        await entered.wait()
        assert store._write_lock.locked(), "put should be holding _write_lock here"
        assert not store._open_lock.locked(), "put has not asked for _open_lock yet"

        closer = asyncio.create_task(store.close())
        await park_on_lock(store._write_lock, 1, what="close never queued on _write_lock")
        assert not store._open_lock.locked(), (
            "close is holding _open_lock while it waits for _write_lock -- that is the AB-BA"
        )

        release.set()
        _done, pending = await asyncio.wait({upload, closer}, timeout=5.0)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        assert not pending, (
            "close() and the first put() deadlocked on _write_lock/_open_lock: "
            f"{len(pending)} of 2 tasks never completed"
        )

        doc_id = upload.result()
        closer.result()
        assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES
    finally:
        # Unconditional, and covering the assertions above as well as the wait:
        # a failure that leaves the upload parked on ``release`` strands an
        # aiosqlite thread, and the process then hangs at exit instead of
        # reporting the failure. Unpark first, then drain, then close.
        release.set()
        for task in (upload, closer):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (upload, closer) if task is not None), return_exceptions=True
        )
        store._connection = real_connection  # type: ignore[method-assign]
        await store.close()


async def test_a_second_upload_never_uses_a_handle_a_queued_close_will_detach(
    settings: Settings,
) -> None:
    """``put`` must resolve its connection *inside* ``_write_lock``, not merely after the blobs.

    ``test_a_close_landing_mid_upload_does_not_strand_the_write`` moved the
    resolution after the two blob writes, which closes the window it was written
    for. It does not close this one, and hoisting the resolution just *outside*
    the ``async with self._write_lock`` -- one line, still after the blobs --
    keeps the entire repository green while restoring the original bug.

    The interleaving that shows it needs three participants, which is why no
    single-upload test can see it: upload #1 holds ``_write_lock`` at its commit,
    a ``close`` queues behind it, and upload #2 queues behind the close. When the
    close finally runs it detaches the connection, so any handle upload #2
    resolved *before* joining that queue is already dead by the time it reaches
    the front. Resolving under the lock means upload #2 asks after the close has
    finished and simply reopens -- the documented "a closed store reopens on next
    use" behaviour.

    Measured on the hoisted version, the failure is
    ``ValueError: no active connection`` -- a bare, unstructured error out of a
    method whose contract is ``PipelineError`` and nothing else, which is exactly
    what ``put``'s comment says this ordering prevents.
    """
    store = await EncryptedDocumentStore.open(settings)
    db = await store._connection()

    at_commit = asyncio.Event()
    proceed = asyncio.Event()
    real_commit = db.commit

    async def parked_commit() -> None:
        if not at_commit.is_set():
            at_commit.set()
            await proceed.wait()
        await real_commit()

    db.commit = parked_commit  # type: ignore[method-assign]

    first = asyncio.create_task(store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical"))
    tasks: list[asyncio.Task[Any]] = [first]
    try:
        await at_commit.wait()
        assert store._write_lock.locked(), "upload #1 should be holding _write_lock at its commit"

        closer = asyncio.create_task(store.close())
        tasks.append(closer)
        await park_on_lock(store._write_lock, 1, what="close never queued on _write_lock")

        second = asyncio.create_task(store.put(USER_B, "second.txt", SYNTHETIC_BYTES, "legal"))
        tasks.append(second)
        await park_on_lock(store._write_lock, 2, what="upload #2 never queued behind the close")

        proceed.set()
        doc_one = await first
        await closer
        # The assertion: not "it raised the right error" but "it did not raise".
        doc_two = await second
    finally:
        # Upload #2 *reopens* the store after the close detaches it, so a second
        # aiosqlite connection -- and therefore a second non-daemon thread -- is
        # live here on the success path, and upload #1 may still be parked on
        # ``proceed`` on a failure path. Neither shows up as a failed assertion:
        # both hang the interpreter at exit, which is the failure mode
        # ``test_concurrent_connection_opens_exactly_one_connection`` exists for.
        proceed.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await store.close()

    async with EncryptedDocumentStore(settings) as reopened:
        assert await reopened.get_raw(USER_A, doc_one) == SYNTHETIC_BYTES
        assert await reopened.get_raw(USER_B, doc_two) == SYNTHETIC_BYTES
        assert [meta.doc_id for meta in await reopened.list_docs(USER_A)] == [doc_one]
        assert [meta.doc_id for meta in await reopened.list_docs(USER_B)] == [doc_two]


async def test_get_category_refuses_a_malformed_doc_id_before_the_database(
    store: EncryptedDocumentStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``get_category``'s own guard must refuse, not the empty result set.

    The query is parameterised, so a hostile ``doc_id`` can never reach query
    construction, and every case below already answers ``NOT_FOUND`` from a row
    that does not exist. Deleting the guard therefore changed nothing any
    existing assertion could observe -- which is precisely why it needs one that
    watches the *mechanism*: an unvalidated, caller-supplied string must not
    reach the metadata query at all. ``test_malformed_doc_id_never_reaches_the_filesystem``
    makes the same argument for the blob path.
    """
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "legal")
    assert await store.get_category(USER_A, doc_id) == "legal"

    connection = await store._connection()
    reached: list[str] = []
    real_execute = connection.execute

    async def recording_execute(sql: str, *args: Any, **kwargs: Any) -> Any:
        if "FROM documents" in sql:
            reached.append(sql)
        return await real_execute(sql, *args, **kwargs)

    monkeypatch.setattr(connection, "execute", recording_execute)
    for hostile in ("../../etc/passwd", "..%2Fescape", "", "NOT-HEX", "a" * 400, "x" * 31):
        with pytest.raises(StoreAuthError) as err:
            await store.get_category(USER_A, hostile)
        assert err.value.code == "NOT_FOUND"
        detail = err.value.detail["doc_id"]
        assert isinstance(detail, str)
        assert len(detail) <= 64
    assert reached == [], f"a rejected doc_id reached the metadata query: {reached}"


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
        # WAS ``pytest.raises(sqlite3.OperationalError)``. The subject of this test
        # is the unwind, not the exception class, and the class changed for a
        # reason that is itself a fix: a raw driver exception escaping a store
        # method is a bare ``500 Internal Server Error`` with no ``code`` and no
        # security headers at the HTTP boundary, which is what
        # ``DocumentStoreUnavailableError`` exists to replace. The driver error is
        # asserted below as the ``__cause__``, so this pair is strictly stronger
        # than the single check it replaces: it still fails if ``put`` stops
        # raising, and it now also fails if the refusal is invented rather than
        # chained from a real failure.
        with pytest.raises(document_store.DocumentStoreUnavailableError) as caught:
            await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
        assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
        assert caught.value.detail["operation"] == "put"
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
    # WAS ``pytest.raises(sqlite3.OperationalError)``; see the note in
    # ``test_a_failed_metadata_insert_leaves_no_orphan``. This helper only needs
    # ``put`` to die after both blobs land, and the ``__cause__`` check keeps it
    # honest about what killed it.
    with pytest.raises(document_store.DocumentStoreUnavailableError) as caught:
        await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
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


# --- 12. a documents.db this process cannot read ----------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent

API_OWNER = "alice"

#: One occurrence of each entity, no value that is a substring of another -- the
#: same shape ``tests/test_api.py`` uses, so what the ASGI test below measures is
#: the refusal and not the detector.
API_DOC_TEXT = """CLINIC INTAKE RECORD

Patient name: David Ochoa.

MRN: 9224297.

Phone: (704) 555-0151.
"""


async def api_run(http: AsyncClient, session_id: str, doc_id: str) -> Any:
    return await http.post(
        "/pipeline/run",
        json={
            "user_id": API_OWNER,
            "doc_id": doc_id,
            "prompt": "Summarise this record in two sentences.",
            "session_id": session_id,
        },
    )


def wreck_every_page_but_the_header(path: Path) -> None:
    """Garbage every page of a real SQLite file except page 1, keeping its length.

    Genuinely corrupt, not a patched raise. The length is what gets past ``open``:
    the header records the database size in pages, so a *short* file is rejected
    outright while a full-length file whose data pages are dead is opened happily
    and fails only when something reads one. Page 1 survives because that is where
    the schema lives, and ``_connection`` runs ``CREATE TABLE IF NOT EXISTS`` and
    has to parse it.

    :func:`integrity_check` on the result reports ``database disk image is
    malformed``, and every test below calls it rather than trusting this function.
    """
    data = bytearray(path.read_bytes())
    page = 4096
    assert len(data) >= 2 * page, "database is too small for this corruption to be meaningful"
    for start in range(page, len(data), page):
        data[start : start + page] = (b"\xde\xad\xbe\xef" * (page // 4))[: len(data) - start]
    path.write_bytes(bytes(data))


def drop_metadata_files(settings: Settings) -> None:
    """Delete ``documents.db`` and its WAL sidecars, leaving every blob in place.

    The state a next ``_connection()`` rebuilds an empty schema over -- which is
    how the control in the sweep test gets a *readable* database with no rows.
    """
    main = db_path(settings)
    main.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(f"{main}{suffix}").unlink(missing_ok=True)


def integrity_check(path: Path) -> str:
    """``PRAGMA integrity_check`` through the stdlib driver, errors included."""
    connection = sqlite3.connect(path)
    try:
        try:
            return str(connection.execute("PRAGMA integrity_check").fetchone())
        except sqlite3.DatabaseError as exc:
            return f"{type(exc).__name__}: {exc}"
    finally:
        connection.close()


async def store_two_and_wreck(store: EncryptedDocumentStore, settings: Settings) -> str:
    """Store two documents, then physically wreck the metadata file underneath.

    Closed and re-opened around the corruption rather than written behind SQLite's
    back, so the page cache cannot mask it: the returned store reads the same bytes
    a restarted process would. Two documents, not one, so that a sweep which
    deletes "everything" is visibly different from one that deletes nothing.
    """
    doc_id = await store.put(USER_A, FILENAME, SYNTHETIC_BYTES, "medical")
    await store.put(USER_A, "second.txt", SYNTHETIC_BYTES, None)
    await store.close()
    wreck_every_page_but_the_header(db_path(settings))
    assert "malformed" in integrity_check(db_path(settings)), (
        f"the file is still readable, so nothing below measures a refusal: "
        f"{integrity_check(db_path(settings))}"
    )
    await store._connection()
    return doc_id


async def test_a_corrupt_metadata_database_refuses_get_category_rather_than_unclassified(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """``None`` is a filing decision; an unreadable file is not one.

    The two are one keystroke apart and the cheap fix -- ``except sqlite3.Error:
    return None`` -- is silent by construction. Measured on the real detector with
    a medical intake record: category ``medical`` yields 5 detections, ``None``
    yields 4, and the one that disappears is ``DATE``, which carries
    ``only_in_doc_categories: [medical]``. The date went to the provider in
    cleartext inside a ``200`` whose egress gate reported clean.
    """
    doc_id = await store_two_and_wreck(store, settings)

    with pytest.raises(document_store.DocumentStoreUnavailableError) as caught:
        await store.get_category(USER_A, doc_id)

    error = caught.value
    # Not `StoreAuthError`, which would be indistinguishable from "no such
    # document", and not `None`, which is a real category answer.
    assert not isinstance(error, StoreAuthError)
    assert error.code == "DOCUMENT_STORE_UNAVAILABLE"
    assert error.detail["reason"] == "document_store_unreadable"
    assert error.detail["operation"] == "get_category"
    assert error.detail["store_db"] == "documents.db"
    assert error.detail["error"] == "DatabaseError"
    assert isinstance(error.__cause__, sqlite3.DatabaseError)

    # Nothing derived from the driver or the filesystem: `api/errors.py` writes
    # this map into the HTTP body verbatim.
    rendered = f"{error!r} {error} {sorted(error.detail.items())}"
    assert str(db_path(settings)) not in rendered
    assert str(settings.data_dir) not in rendered
    assert "malformed" not in rendered
    # ...and the remedy is something an operator can act on, spelled out here
    # rather than compared to the imported constant, which would pass against
    # `remedy: ""`.
    remedy = str(error.detail["remedy"])
    assert remedy == document_store.UNREADABLE_STORE_REMEDY
    assert "restore" in remedy and "re-upload" in remedy


async def test_a_corrupt_metadata_database_refuses_list_docs_rather_than_answering_empty(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """An empty library is a fact about a user, not about a broken file."""
    await store_two_and_wreck(store, settings)
    with pytest.raises(document_store.DocumentStoreUnavailableError) as caught:
        await store.list_docs(USER_A)
    assert caught.value.detail["operation"] == "list_docs"
    assert isinstance(caught.value.__cause__, sqlite3.DatabaseError)


async def test_a_corrupt_metadata_database_refuses_put_and_leaves_no_orphan_blob(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """An upload against an unreadable index refuses, and unwinds both blobs.

    Metadata is the source of truth, so a ``doc_id`` returned for a row that was
    never written names a document nothing can ever reach -- and two blobs that
    nothing can ever delete, because ``sweep_orphans`` needs to read the same file.
    """
    await store_two_and_wreck(store, settings)
    before = sorted(path.name for path in blob_dir(settings).iterdir())

    with pytest.raises(document_store.DocumentStoreUnavailableError) as caught:
        await store.put(USER_A, "third.txt", SYNTHETIC_BYTES, "medical")

    assert caught.value.detail["operation"] == "put"
    assert isinstance(caught.value.__cause__, sqlite3.DatabaseError)
    assert sorted(path.name for path in blob_dir(settings).iterdir()) == before


async def test_a_corrupt_metadata_database_refuses_the_sweep_before_a_single_unlink(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """The dangerous one: here degrading is not a smaller answer, it is a larger act.

    ``sweep_orphans`` deletes every blob whose ``doc_id`` is missing from the set
    the SELECT returned, so ``known`` is a *keep* list. A read failure swallowed
    into an empty set does not collect fewer orphans -- it deletes the whole store.
    The control below measures exactly that, on a readable database: with the rows
    gone, the identical call removes all 4 blobs. So the assertion that the corrupt
    run removes 0 is measuring the refusal and not an empty directory.
    """
    await store_two_and_wreck(store, settings)
    before = sorted(path.name for path in blob_dir(settings).iterdir())
    assert len(before) == 4, before

    with pytest.raises(document_store.DocumentStoreUnavailableError) as caught:
        await store.sweep_orphans(min_age_seconds=0)

    assert caught.value.detail["operation"] == "sweep_orphans"
    assert sorted(path.name for path in blob_dir(settings).iterdir()) == before

    # The control: an EMPTY keep-list over a readable database really does delete
    # everything, so the refusal above is what stood between the corruption and
    # the blobs.
    await store.close()
    drop_metadata_files(settings)
    async with EncryptedDocumentStore(settings) as fresh:
        assert await fresh.sweep_orphans(min_age_seconds=0) == 4
    assert list(blob_dir(settings).iterdir()) == []


async def test_the_blob_read_path_still_answers_while_the_metadata_database_is_rubble(
    store: EncryptedDocumentStore, settings: Settings
) -> None:
    """Why the refusal has to come from ``get_category``, stated as a measurement.

    ``get_text`` and ``get_raw`` open a file and decrypt it; they never touch
    SQLite. So a corrupt ``documents.db`` does not make them return empty text --
    it makes them keep working, which is exactly why the fail-closed behaviour has
    to be proved at the methods that DO query the database rather than assumed for
    the store as a whole. The orchestrator calls ``get_text`` and then
    ``get_category``, so the run is refused one line after this succeeds.
    """
    doc_id = await store_two_and_wreck(store, settings)

    assert await store.get_raw(USER_A, doc_id) == SYNTHETIC_BYTES
    assert await store.get_text(USER_A, doc_id) != ""
    assert "Marisol" in await store.get_text(USER_A, doc_id)


def test_the_document_store_and_the_audit_log_share_one_unreadable_rule() -> None:
    """One rule for three files, checked rather than asserted in a comment.

    This proves agreement, not correctness -- the corrupt-file tests above are what
    prove the rule is right. It exists because ``documents.db`` reproduced the audit
    log's defect exactly, long after that one was fixed, and a tuple copied into a
    second module with no link between them is how that happens again.
    """
    assert document_store._UNREADABLE == audit_logger._UNREADABLE
    assert document_store._UNREADABLE == (sqlite3.Error, ValueError, TypeError)


async def test_a_corrupt_document_store_refuses_a_pipeline_run_over_the_real_asgi_app(
    tmp_path: Path,
) -> None:
    """The reported defect at the boundary a reviewer actually sees.

    The sibling of ``test_api.py::test_a_corrupt_audit_log_refuses_the_run_as_a_typed_503``,
    on the third of the three SQLite stores. A fresh app on its own data directory,
    a healthy run first, then the live ``documents.db`` physically wrecked on disk
    and the same request repeated. Nothing is monkeypatched -- no patched accessor,
    no injected raise -- so what is asserted is the behaviour of the shipped code on
    a file SQLite genuinely cannot read.

    ``raise_app_exceptions`` is left at its default ``True``, which is load-bearing:
    anything still escaping unhandled makes this test *error* with that exception
    rather than read a status code off a Starlette-generated 500. The old behaviour
    -- ``sqlite3.DatabaseError`` out of ``get_category``, rendered as ``500
    text/plain Internal Server Error`` with no CSP and no ``nosniff`` -- cannot pass
    this test by accident.

    The fail-closed half is asserted positively as well as negatively. The
    tempting degradation here answers ``200`` with an empty document: measured, 0
    entities detected, the egress gate clean, and a summary of a document that was
    never read. So this checks not merely that the status is an error but that the
    response carries no ``detections`` and no clean-bill-of-health body.
    """
    settings = Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        data_dir=tmp_path / "corrupt-documents-data",
        registry_path=REPO_ROOT / "entities.yaml",
        llm_provider="mock",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        services = app.state.services
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
                session_id = (
                    await http.post("/sessions", json={"user_id": API_OWNER})
                ).json()["session_id"]
                doc_id = (
                    await http.post(
                        "/documents",
                        files={"file": ("intake.txt", API_DOC_TEXT.encode(), "text/plain")},
                        data={"user_id": API_OWNER, "doc_category": "medical"},
                    )
                ).json()["doc_id"]

                # Control: the identical request succeeds on a healthy store, and
                # really does detect something -- otherwise "0 detections" below
                # would be the normal answer rather than the fail-open signature.
                healthy = await api_run(http, session_id, doc_id)
                assert healthy.status_code == 200, healthy.text
                assert provider_calls == 1, "premise: a healthy run reaches the provider"
                assert healthy.json()["stats"]["entities_detected"] >= 3
                assert "David Ochoa" in healthy.json()["restored_text"]

                # Wreck the file under the live app. Closed and reopened rather
                # than written behind SQLite's back, so the page cache cannot mask
                # it: this is the same file the next request opens.
                await services.store.close()
                wreck_every_page_but_the_header(settings.data_dir / "documents.db")
                assert "malformed" in integrity_check(settings.data_dir / "documents.db")
                await services.store._connection()

                refused = await api_run(http, session_id, doc_id)

    # FIRST, before anything about the shape of the answer: the run was refused
    # before the payload was sent.
    assert provider_calls == 1, "the refused run must not have reached the provider"

    body = refused.json()
    assert body["code"] == "DOCUMENT_STORE_UNAVAILABLE"
    assert body["detail"]["reason"] == "document_store_unreadable"
    assert body["detail"]["operation"] == "get_category"
    assert body["detail"]["store_db"] == "documents.db"
    assert body["detail"]["error"] == "DatabaseError"
    assert body["detail"]["remedy"] == document_store.UNREADABLE_STORE_REMEDY

    # 500 is what the `PipelineError` catch-all in `api/errors.py` answers, and it
    # is pinned rather than loosened to `>= 500` so the remaining gap is visible:
    # the audit sibling answers **503** because that module registers
    # `AuditUnavailableError` explicitly, and registering this class the same way is
    # a change in `api/errors.py`, outside this change's grant. When that
    # registration lands this line becomes 503 -- deliberately, not by accident.
    assert refused.status_code == 500, refused.text

    # Fail CLOSED, asserted as the absence of the fail-open answer: no detections,
    # no restored text, no clean bill of health over a document nothing read.
    assert "detections" not in body
    assert "restored_text" not in refused.text
    assert "entities_detected" not in refused.text

    # The bare 500 was `text/plain`, carried no `code`, and had none of these
    # headers, because ServerErrorMiddleware renders outside the middleware that
    # adds them.
    assert refused.headers["content-type"].startswith("application/json")
    assert "Internal Server Error" not in refused.text
    assert refused.headers["x-content-type-options"] == "nosniff"
    csp = refused.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp

    # No filesystem path and no driver text in the body.
    assert str(settings.data_dir) not in refused.text
    assert "malformed" not in refused.text
    assert "sqlite" not in refused.text.lower()
    assert "Traceback" not in refused.text
