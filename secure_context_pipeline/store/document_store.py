"""Encrypted document store (build doc sections 8 and 9.1).

Two blobs are written per document and both are AES-256-GCM ciphertext:

    <data_dir>/documents/<doc_id>.raw   nonce || AESGCM(user_doc_key, original bytes)
    <data_dir>/documents/<doc_id>.txt   nonce || AESGCM(user_doc_key, extracted text)

The key is ``KeyProvider.doc_key(user_id)`` -- an HKDF derivation of the master
key, computed on demand and never stored -- and the AAD is
``doc:<user_id>:<doc_id>``. Three properties follow from that construction rather
than from an access-control check in this module:

* **Per-user isolation is cryptographic.** A different ``user_id`` derives a
  different key, so reading another user's blob fails GCM authentication instead
  of returning their plaintext.
* **Blobs do not travel between documents.** The AAD binds ciphertext to one
  (user, doc) pair, so copying ``a.raw`` over ``b.raw`` on disk fails
  authentication. An attacker with write access to the data directory can
  destroy documents but cannot make one decrypt as another. The binding stops at
  the pair, though, and the build doc fixes the AAD at ``doc:<user>:<doc_id>``:
  a document's own ``.raw`` and ``.txt`` share it and are therefore
  interchangeable *with each other*. That is an integrity edge with no
  confidentiality consequence -- both halves already decrypt only for the owner,
  who could read either one anyway -- and closing it would mean deviating from
  the specified AAD.
* **No existence oracle in the response.** Every failure -- absent document,
  wrong owner, truncated blob, tampered ciphertext -- surfaces as one
  :class:`~secure_context_pipeline.errors.StoreAuthError`, whose ``code`` is
  ``NOT_FOUND`` by design. "Wrong user" and "no such document" are
  indistinguishable in the exception and in its detail. They are *not*
  indistinguishable in latency: a wrong-owner read pays a full blob read before
  GCM rejects it, an absent one fails at ``open()``. That side channel is
  measured and accepted in the README threat model, not denied here.

SQLite holds metadata only: doc_id, user_id, filename, category, timestamp and a
byte count. No document content and no extracted text ever reaches a row, so the
database is not a second copy of the plaintext -- but the metadata itself is
cleartext, filenames included, which is a deliberate and separately argued
trade (README threat model). Encryption is application-layer AES-GCM only --
SQLCipher is a locked-out decision (build doc section 3), and per-record AAD
binding is strictly stronger than whole-file encryption here.

**Crash recovery.** ``put`` unwinds its own partial writes on any exception,
including cancellation, but a ``SIGKILL`` or a power cut between the blob writes
and the metadata commit leaves blobs with no row pointing at them. Metadata is
the source of truth, so those blobs are unreachable rather than dangerous;
:meth:`EncryptedDocumentStore.sweep_orphans` collects them at startup, the same
role :meth:`SessionVault.sweep_orphans` plays for vault rows.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self, runtime_checkable

import aiofiles
import aiofiles.os
import aiosqlite

from secure_context_pipeline.config import Settings
from secure_context_pipeline.crypto.aead import decrypt, doc_aad, encrypt
from secure_context_pipeline.crypto.keys import KeyProvider, build_key_provider
from secure_context_pipeline.errors import (
    MAX_DETAIL_VALUE_LEN,
    CryptoAuthError,
    PipelineError,
    StoreAuthError,
)
from secure_context_pipeline.models import DOC_CATEGORIES
from secure_context_pipeline.store import extraction

__all__ = [
    "DOC_CATEGORIES",
    "RAW_SUFFIX",
    "TEXT_SUFFIX",
    "DocumentMeta",
    "DocumentStore",
    "EncryptedDocumentStore",
    "InvalidCategoryError",
]

logger = logging.getLogger(__name__)

#: Re-exported from `models` so this module's public name is unchanged. The set is
#: defined there because `detection/registry.py` validates against it too and cannot
#: import the store; see the note at its definition for the fail-open that caused.
#: These drive the registry's ``only_in_doc_categories`` scoping (build doc section
#: 9.2): a legal document resolves ``PERSON`` to ``CLIENT_IDENTITY``, a medical one
#: does not. ``None`` means "unclassified" and is always allowed.

RAW_SUFFIX = ".raw"
TEXT_SUFFIX = ".txt"

#: Subdirectory of ``settings.data_dir`` holding ciphertext blobs.
_BLOB_DIRNAME = "documents"
#: SQLite file holding metadata -- never content.
_DB_FILENAME = "documents.db"

#: ``uuid4().hex``. Enforced on every lookup: ``doc_id`` arrives from the API
#: layer and is interpolated into a filesystem path, so anything that is not
#: exactly 32 lowercase hex characters is rejected before it can touch the disk.
_DOC_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
  doc_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, filename TEXT NOT NULL,
  doc_category TEXT, created_at REAL NOT NULL, size_bytes INTEGER NOT NULL
);
"""
_INDEX = "CREATE INDEX IF NOT EXISTS documents_user_idx ON documents (user_id, created_at);"


class InvalidCategoryError(PipelineError):
    """``doc_category`` was not one of :data:`DOC_CATEGORIES` (or ``None``).

    Rejected at ``put`` rather than coerced to ``general``: a mis-filed document
    would silently lose the category-scoped detection rules that make its most
    sensitive entities detectable at all.
    """

    code = "INVALID_DOC_CATEGORY"

    def __init__(self, *, value: str) -> None:
        super().__init__(value=value)


@dataclass(frozen=True, slots=True)
class DocumentMeta:
    """One row of the ``documents`` table. Metadata only -- never content."""

    doc_id: str
    filename: str
    doc_category: str | None
    created_at: float
    size_bytes: int


@runtime_checkable
class DocumentStore(Protocol):
    """The storage seam (build doc section 9.1).

    Only the three spec-mandated methods are part of the protocol, so an
    alternative backend (S3 + KMS, a managed blob store) can satisfy it without
    inheriting this implementation's SQLite metadata model.
    """

    async def put(
        self, user_id: str, filename: str, content: bytes, doc_category: str | None
    ) -> str:
        """Store a document and return its new ``doc_id``."""
        ...

    async def get_text(self, user_id: str, doc_id: str) -> str:
        """Extracted text for ``doc_id``, or :class:`StoreAuthError` if not this user's."""
        ...

    async def get_raw(self, user_id: str, doc_id: str) -> bytes:
        """Original uploaded bytes, or :class:`StoreAuthError` if not this user's."""
        ...


def _safe_doc_id(doc_id: str) -> str:
    """A ``doc_id`` short enough to sit inside a structured error detail.

    ``PipelineError`` caps string details at 64 characters; a caller-supplied
    ``doc_id`` is not length-bounded, so truncate rather than let the guard turn
    a lookup failure into a ``ValueError``.
    """
    return doc_id[:MAX_DETAIL_VALUE_LEN]


def _validate_category(doc_category: str | None) -> str | None:
    if doc_category is None:
        return None
    if doc_category not in DOC_CATEGORIES:
        raise InvalidCategoryError(value=doc_category[:MAX_DETAIL_VALUE_LEN])
    return doc_category


class EncryptedDocumentStore:
    """File-backed, per-user-encrypted :class:`DocumentStore`.

    One ``aiosqlite`` connection per instance, opened in WAL mode on first use.
    Every read is async (``aiofiles`` for blobs, ``aiosqlite`` for metadata) --
    a synchronous ``open()`` here would stall the event loop for every other
    request while a 50 MB blob comes off disk.

    Preferred entry point is the async context manager, which guarantees the
    connection is closed::

        async with EncryptedDocumentStore(settings) as store:
            doc_id = await store.put(user_id, "notes.txt", raw, "medical")
            text = await store.get_text(user_id, doc_id)
    """

    def __init__(self, settings: Settings, key_provider: KeyProvider | None = None) -> None:
        self._settings = settings
        self._keys: KeyProvider = (
            key_provider if key_provider is not None else build_key_provider(settings)
        )
        data_dir = Path(settings.data_dir)
        self._blob_dir = data_dir / _BLOB_DIRNAME
        self._db_path = data_dir / _DB_FILENAME
        # One metadata syscall at construction, not per request: the tree must
        # exist before any await can write into it. Mode 0o700 so the blobs are
        # unreadable to other local users even before AES-GCM is considered.
        self._blob_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._db: aiosqlite.Connection | None = None
        self._open_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    # -- lifecycle ----------------------------------------------------------

    @classmethod
    async def open(cls, settings: Settings, key_provider: KeyProvider | None = None) -> Self:
        """Build a store with its connection already established."""
        store = cls(settings, key_provider)
        await store._connection()
        return store

    async def _connection(self) -> aiosqlite.Connection:
        """The instance's single connection, opened and migrated on first use.

        The connection is returned from a *local*, resolved while ``_open_lock``
        is still held. Returning ``self._db`` after the ``async with`` instead
        would re-read shared state that :meth:`close` sets back to ``None``, and
        the only thing making that safe is that releasing an ``asyncio.Lock``
        happens not to yield to the event loop -- so a single added ``await``
        would turn a declared ``aiosqlite.Connection`` into ``None``. Binding
        the local makes it a property of the code rather than of the scheduler.

        That argument covers the slow path only. The lock-free fast path at the
        top reads ``self._db`` with no lock at all, and is safe for a separate,
        equally deliberate reason: :meth:`close` swaps ``self._db`` to ``None``
        *before* it awaits the connection closed, so a non-``None`` value read
        here is never one that a close is already part-way through. While
        ``close`` detached only afterwards, this path handed callers the exact
        connection being closed -- observed, not theorised -- and the next
        statement to use it raised ``ValueError: no active connection``.
        """
        cached = self._db
        if cached is not None:
            return cached
        async with self._open_lock:
            db = self._db
            if db is None:
                await aiofiles.os.makedirs(self._blob_dir, exist_ok=True)
                db = await aiosqlite.connect(self._db_path)
                db.row_factory = aiosqlite.Row
                # WAL: readers never block the writer, which matters as soon as
                # an upload and a retrieval overlap.
                await db.execute("PRAGMA journal_mode=WAL")
                await db.execute("PRAGMA synchronous=NORMAL")
                await db.execute(_SCHEMA)
                await db.execute(_INDEX)
                await db.commit()
                self._db = db
                logger.debug("document store opened (data_dir=%s)", self._db_path.parent)
            return db

    async def close(self) -> None:
        """Close the metadata connection. Idempotent.

        Two orderings here are load-bearing and neither is cosmetic.

        ``_write_lock`` is taken **before** ``_open_lock``. :meth:`put` resolves
        its connection while already holding ``_write_lock``, and
        :meth:`_connection` takes ``_open_lock`` inside that -- so this method
        must acquire them in the same order or the two deadlock. Taking
        ``_write_lock`` at all is what stops a shutdown from detaching the
        connection out from under an upload that is between its blob writes and
        its metadata INSERT.

        ``self._db`` is detached **before** the connection is awaited closed, so
        :meth:`_connection`'s lock-free fast path can never return the very
        connection this method is closing.
        """
        async with self._write_lock:
            async with self._open_lock:
                db, self._db = self._db, None
            if db is not None:
                await db.close()

    async def __aenter__(self) -> Self:
        await self._connection()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    # -- paths --------------------------------------------------------------

    def _raw_path(self, doc_id: str) -> Path:
        return self._blob_dir / f"{doc_id}{RAW_SUFFIX}"

    def _text_path(self, doc_id: str) -> Path:
        return self._blob_dir / f"{doc_id}{TEXT_SUFFIX}"

    # -- writes -------------------------------------------------------------

    async def put(
        self, user_id: str, filename: str, content: bytes, doc_category: str | None
    ) -> str:
        """Extract, encrypt and store a document; return its ``doc_id``.

        ``doc_category`` is required, matching the :class:`DocumentStore`
        protocol and build doc section 9.1. Defaulting it to ``None`` would let a
        caller silently file a document as unclassified, and an unclassified
        document loses the category-scoped registry rules that make its most
        sensitive entities detectable at all -- the same argument
        :class:`InvalidCategoryError` makes for rejecting a bad category rather
        than coercing it. Pass ``None`` deliberately when that is the intent.

        Both the original bytes and the extracted text are encrypted under
        ``doc_key(user_id)`` with ``AAD = doc:<user_id>:<doc_id>``. Document
        *content* exists in plaintext only in this frame's locals: no byte of it
        reaches the disk or the log, which record counts and durations only. The
        metadata row is a separate matter and is cleartext by design -- filename,
        user_id, category, size -- see the module docstring.

        Raises:
            InvalidCategoryError: ``doc_category`` outside :data:`DOC_CATEGORIES`.
            PipelineError: the file type is unsupported or unparseable
                (from :mod:`~secure_context_pipeline.store.extraction`).
        """
        category = _validate_category(doc_category)
        # Derived before any I/O: an empty user_id must fail before a blob
        # exists, not after.
        key = self._keys.doc_key(user_id)
        doc_id = uuid.uuid4().hex
        started = time.perf_counter()

        text = await extraction.extract_text(filename, content)

        aad = doc_aad(user_id, doc_id)
        raw_blob = encrypt(key, content, aad)
        text_blob = encrypt(key, text.encode("utf-8"), aad)

        # One failure domain for both blob writes and the metadata insert. The
        # second write failing (ENOSPC, EIO) used to leave the first blob behind
        # with no row pointing at it: unreachable, undeletable, and counted
        # against the disk forever. BaseException, not Exception, because a
        # cancelled upload -- a client disconnecting mid-request is the normal
        # case, not the exotic one -- must clean up too.
        try:
            await self._write_blob(self._raw_path(doc_id), raw_blob)
            await self._write_blob(self._text_path(doc_id), text_blob)
            # Resolved *inside* ``_write_lock``, which ``close`` also takes
            # before it detaches the connection. Resolving it before the blob
            # writes instead meant this frame carried a handle across two real
            # awaits, so a ``close`` landing there -- a shutdown during an
            # upload, not an exotic interleaving -- made the INSERT raise a bare
            # ``ValueError: no active connection`` out of a method that raises
            # ``PipelineError`` and nothing else. Under the lock the connection
            # cannot be detached between resolving it and using it.
            async with self._write_lock:
                db = await self._connection()
                await db.execute(
                    "INSERT INTO documents "
                    "(doc_id, user_id, filename, doc_category, created_at, size_bytes) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (doc_id, user_id, filename, category, time.time(), len(content)),
                )
                await db.commit()
        except BaseException:
            # Metadata is the source of truth; an orphan blob is unreachable but
            # still ciphertext on disk, so drop it rather than leave it behind.
            await self._unlink_quietly(doc_id, self._raw_path(doc_id))
            await self._unlink_quietly(doc_id, self._text_path(doc_id))
            raise

        # Counts and durations only -- never a byte of content, never the text.
        logger.info(
            "document stored (doc_id=%s, user_id=%s, category=%s, bytes=%d, "
            "text_chars=%d, elapsed_ms=%.1f)",
            doc_id,
            user_id,
            category,
            len(content),
            len(text),
            (time.perf_counter() - started) * 1000.0,
        )
        return doc_id

    async def _write_blob(self, path: Path, blob: bytes) -> None:
        async with aiofiles.open(path, "wb") as handle:
            await handle.write(blob)

    async def _unlink_quietly(self, doc_id: str, path: Path) -> None:
        """Best-effort blob removal. A blob that was never written is not an orphan."""
        try:
            await aiofiles.os.remove(path)
        except FileNotFoundError:
            return
        except OSError:
            logger.warning("orphan blob left on disk (doc_id=%s, kind=%s)", doc_id, path.suffix)

    # -- reads --------------------------------------------------------------

    async def get_raw(self, user_id: str, doc_id: str) -> bytes:
        """The original uploaded bytes.

        Raises:
            StoreAuthError: absent, not this user's, or failing authentication --
                the three are deliberately indistinguishable.
        """
        return await self._read_blob(user_id, doc_id, self._raw_path(doc_id), scope="document_raw")

    async def get_text(self, user_id: str, doc_id: str) -> str:
        """The extracted text.

        Raises:
            StoreAuthError: absent, not this user's, or failing authentication.
        """
        plaintext = await self._read_blob(
            user_id, doc_id, self._text_path(doc_id), scope="document_text"
        )
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            # Unreachable via put(): GCM already authenticated these exact bytes
            # as the utf-8 we wrote. Mapped to the same error anyway so a corrupt
            # store can never become a distinguishable response.
            raise StoreAuthError(doc_id=_safe_doc_id(doc_id)) from exc

    async def _read_blob(self, user_id: str, doc_id: str, path: Path, *, scope: str) -> bytes:
        if not _DOC_ID_RE.match(doc_id):
            # Path-traversal guard and not-found in one: a caller-supplied
            # "../../etc/passwd" is refused before it reaches the filesystem.
            raise StoreAuthError(doc_id=_safe_doc_id(doc_id))
        key = self._keys.doc_key(user_id)
        try:
            async with aiofiles.open(path, "rb") as handle:
                blob = await handle.read()
        except OSError as exc:
            raise StoreAuthError(doc_id=_safe_doc_id(doc_id)) from exc
        try:
            return decrypt(key, blob, doc_aad(user_id, doc_id), scope=scope)
        except CryptoAuthError as exc:
            # The whole point of section 8: the wrong user gets NOT_FOUND, with
            # the same detail an absent document would produce.
            raise StoreAuthError(doc_id=_safe_doc_id(doc_id)) from exc

    # -- metadata -----------------------------------------------------------

    async def get_category(self, user_id: str, doc_id: str) -> str | None:
        """This document's category, or ``None`` if it was stored unclassified.

        Scoped by ``user_id`` in the query itself, so another user's document is
        as absent as one that never existed.

        Raises:
            StoreAuthError: no such document *for this user*.
        """
        if not _DOC_ID_RE.match(doc_id):
            raise StoreAuthError(doc_id=_safe_doc_id(doc_id))
        db = await self._connection()
        async with db.execute(
            "SELECT doc_category FROM documents WHERE doc_id = ? AND user_id = ?",
            (doc_id, user_id),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise StoreAuthError(doc_id=_safe_doc_id(doc_id))
        category = row["doc_category"]
        return None if category is None else str(category)

    # -- recovery -----------------------------------------------------------

    async def sweep_orphans(self, *, min_age_seconds: float = 60.0) -> int:
        """Delete blobs with no metadata row; return how many files went.

        Run at startup, alongside :meth:`SessionVault.sweep_orphans`.

        ``put`` writes both blobs and *then* commits the row, and unwinds itself
        on any exception including cancellation -- but not on ``SIGKILL``, OOM
        kill or power loss. Those leave ciphertext on disk that no ``doc_id``
        can reach: metadata is the source of truth, so an unreferenced blob is
        not a security problem, it is disk that nothing will ever free. Without
        this sweep the only bound on that growth is redeploying the volume.

        ``min_age_seconds`` is the safety margin against sweeping a document
        that is being written *right now*: a concurrent ``put`` has its blobs on
        disk for the width of one commit before its row exists, and deleting
        them there would corrupt a live upload. Startup has no concurrent
        writer, so the margin is belt-and-braces rather than the mechanism.

        Each file is judged on its own, not as half of a pair: a crash between
        the ``.raw`` and the ``.txt`` write strands exactly one of them. Names
        this method cannot parse are left alone -- it deletes files, and "I do
        not recognise this" is not grounds to remove it from a shared directory.
        """
        db = await self._connection()
        async with db.execute("SELECT doc_id FROM documents") as cursor:
            rows = await cursor.fetchall()
        known = {str(row["doc_id"]) for row in rows}

        cutoff = time.time() - max(min_age_seconds, 0.0)
        removed = 0
        scanned = 0
        for path in sorted(await asyncio.to_thread(lambda: list(self._blob_dir.iterdir()))):
            if path.suffix not in (RAW_SUFFIX, TEXT_SUFFIX):
                continue
            scanned += 1
            doc_id = path.stem
            if doc_id in known or not _DOC_ID_RE.match(doc_id):
                continue
            try:
                stat = await aiofiles.os.stat(path)
            except OSError:
                continue
            if stat.st_mtime > cutoff:
                continue
            await self._unlink_quietly(doc_id, path)
            removed += 1

        logger.info(
            "orphan document blobs swept (scanned=%d, removed=%d, documents=%d)",
            scanned,
            removed,
            len(known),
        )
        return removed

    async def list_docs(self, user_id: str) -> list[DocumentMeta]:
        """Metadata for this user's documents, newest first. Never another user's."""
        db = await self._connection()
        async with db.execute(
            "SELECT doc_id, filename, doc_category, created_at, size_bytes FROM documents "
            "WHERE user_id = ? ORDER BY created_at DESC, doc_id",
            (user_id,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            DocumentMeta(
                doc_id=str(row["doc_id"]),
                filename=str(row["filename"]),
                doc_category=None if row["doc_category"] is None else str(row["doc_category"]),
                created_at=float(row["created_at"]),
                size_bytes=int(row["size_bytes"]),
            )
            for row in rows
        ]
