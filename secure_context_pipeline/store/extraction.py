"""Text extraction from an in-memory byte blob (build doc section 9.1).

This module is deliberately *pure*: it takes ``bytes`` in and returns ``str``
out. It never touches the filesystem, never encrypts, never persists. The
:class:`~secure_context_pipeline.store.document_store.DocumentStore` calls it
and owns everything else.

Two guardrails from build doc section 16 are load-bearing here:

1. **No content in logs or exceptions.** Every log line and every
   :class:`PipelineError` detail carries only a kind, a suffix, a byte/page/char
   count, or a duration. Document text -- which by assumption is unredacted PII
   at this point in the pipeline -- never leaves this module except as the
   return value. Parse failures are logged by exception *class name* only,
   because a parser traceback can embed raw stream bytes.
2. **Never block the event loop.** Extraction is CPU-bound and the underlying
   libraries are synchronous, so :func:`extract_text` is a thin ``async``
   shell over ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import time
import zipfile
from collections.abc import Iterator
from pathlib import PurePosixPath

from docx import Document as open_docx
from docx.table import Table
from docx.text.paragraph import Paragraph
from pypdf import PdfReader

from secure_context_pipeline.errors import PipelineError

__all__ = [
    "KIND_DOCX",
    "KIND_PDF",
    "KIND_TXT",
    "MAX_DOCX_UNCOMPRESSED_BYTES",
    "SUPPORTED_SUFFIXES",
    "detect_kind",
    "extract_text",
]

logger = logging.getLogger(__name__)

KIND_PDF = "pdf"
KIND_DOCX = "docx"
KIND_TXT = "txt"

SUPPORTED_SUFFIXES: frozenset[str] = frozenset({".pdf", ".docx", ".txt", ".md"})

#: ``%PDF-`` -- required by the PDF spec to be the first bytes of the file.
_PDF_MAGIC = b"%PDF-"
#: Local file header of any ZIP archive; OOXML (.docx) is a ZIP container.
_ZIP_MAGIC = b"PK\x03\x04"
#: UTF-8 byte order mark. Editors on Windows emit it; it is metadata, not text.
_UTF8_BOM = b"\xef\xbb\xbf"
#: The one member that distinguishes a WordprocessingML package from any
#: other ZIP (an .xlsx, a .jar, a plain .zip).
_DOCX_MEMBER = "word/document.xml"

#: Longest suffix echoed back in an error detail. ``PipelineError`` caps every
#: string detail at 64 chars; this keeps us far inside that and stops a
#: pathological filename from becoming the error message.
_MAX_SUFFIX_LEN = 16

#: Ceiling on the total *declared* uncompressed size of a DOCX package.
#:
#: A DOCX is a ZIP, and a ZIP of highly repetitive XML compresses at ~1000:1.
#: The API caps an upload at 16 MB, so without this guard a 190 KB upload
#: expands to 200 MB of RSS and a 16 MB one to gigabytes -- a single-request
#: memory-exhaustion DoS that never touches the crypto or the detector.
#:
#: Summing ``ZipInfo.file_size`` from the central directory is *sound*, not just
#: a heuristic: CPython's ``zipfile`` truncates a member's decompressed output at
#: the declared ``file_size`` and then fails the CRC check, so a lying header
#: cannot deliver more bytes than it declares. Reading the directory costs no
#: decompression at all.
#:
#: 128 MiB is 8x the upload ceiling -- far above any real document (a DOCX is
#: mostly already-compressed media plus XML that deflates ~10:1) and far below
#: what would threaten the process.
#:
#: **What this does not bound: member count.** The ceiling is on declared
#: *bytes*, and an archive of hundreds of thousands of empty members declares
#: zero. Reading the central directory then costs a ``ZipInfo`` object per
#: member -- measured at ~110 MB of transient RSS for an archive at the 16 MB
#: upload cap, paid inside ``zipfile.ZipFile()`` before any check can run, since
#: CPython parses the whole directory during construction. That is a ~7x
#: amplification against the ~1000x this constant closes, it is transient rather
#: than retained, and bounding it means hand-parsing the end-of-central-directory
#: record before handing the blob to ``zipfile``. Left as a known residual
#: (``test_docx_with_many_members_is_a_known_residual`` pins the behaviour) rather
#: than silently implied to be covered.
MAX_DOCX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024

#: 4+ newlines == 3+ consecutive blank lines. Collapsed to 3 newlines, i.e. at
#: most 2 blank lines. Paragraph boundaries (``\n\n``) are never touched: the
#: detector chunks on them (build doc section 9.2).
_EXCESS_BLANK_LINES = re.compile(r"\n{4,}")


# ---------------------------------------------------------------------------
# type detection
# ---------------------------------------------------------------------------


def _suffix(filename: str) -> str:
    """Lowercased extension of ``filename``, tolerant of Windows separators."""
    normalised = filename.replace("\\", "/")
    return PurePosixPath(normalised).suffix.lower()


def _short_suffix(filename: str) -> str:
    """A suffix short enough to be safe inside a structured error detail."""
    return _suffix(filename)[:_MAX_SUFFIX_LEN]


def _is_docx_zip(content: bytes) -> bool:
    """True if the ZIP blob carries a WordprocessingML main document part."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return _DOCX_MEMBER in archive.namelist()
    except (zipfile.BadZipFile, OSError, ValueError):
        # Truncated or otherwise unreadable central directory. Member names are
        # stored uncompressed in the local headers, so a substring probe is a
        # sound last resort.
        return _DOCX_MEMBER.encode("ascii") in content


def detect_kind(filename: str, content: bytes) -> str:
    """Return ``"pdf"``, ``"docx"`` or ``"txt"`` for this blob.

    Magic bytes win over the filename: a ``.txt`` holding a DOCX package is a
    DOCX, and a ``.docx`` holding plain text is text. The suffix is consulted
    only when the bytes carry no recognisable signature, which is the normal
    case for text.

    Raises:
        PipelineError: ``reason="unsupported_document_type"`` when the blob is
            neither a PDF nor a DOCX and the suffix is not in
            :data:`SUPPORTED_SUFFIXES`. Carries the suffix, never the content.
    """
    if content.startswith(_PDF_MAGIC):
        return KIND_PDF

    if content.startswith(_ZIP_MAGIC):
        if _is_docx_zip(content):
            return KIND_DOCX
        # A ZIP that is not a Word package: .xlsx, .pptx, .zip, .jar...
        raise PipelineError(
            reason="unsupported_document_type",
            suffix=_short_suffix(filename),
            detected="zip_not_docx",
        )

    suffix = _suffix(filename)
    if suffix in SUPPORTED_SUFFIXES:
        # Includes .pdf/.docx whose magic bytes disagreed -- the bytes are not
        # a container, so the only remaining honest reading is text.
        return KIND_TXT

    raise PipelineError(
        reason="unsupported_document_type",
        suffix=_short_suffix(filename),
        detected="unknown",
    )


# ---------------------------------------------------------------------------
# decoding
# ---------------------------------------------------------------------------


def _try_decode(content: bytes, encoding: str) -> str | None:
    """``content.decode(encoding)``, or ``None`` when it does not fit."""
    try:
        return content.decode(encoding)
    except UnicodeDecodeError:
        return None


def _decode_text(content: bytes) -> str:
    """Decode bytes to ``str``, degrading rather than raising.

    ``utf-8`` -> ``utf-8-sig`` (strips a BOM) -> ``latin-1`` with replacement,
    which cannot fail for any byte sequence, so a text-ish file always yields
    text. A leading BOM is tried under ``utf-8-sig`` *first*: plain ``utf-8``
    would also succeed but would glue a U+FEFF onto the first token, which then
    survives into detector offsets.
    """
    if content.startswith(_UTF8_BOM):
        decoded = _try_decode(content, "utf-8-sig")
        if decoded is not None:
            return decoded
        content = content[len(_UTF8_BOM) :]

    decoded = _try_decode(content, "utf-8")
    if decoded is not None:
        return decoded

    logger.debug("text decode fell back to latin-1 (bytes=%d)", len(content))
    return content.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# per-format extraction (synchronous -- always called on a worker thread)
# ---------------------------------------------------------------------------


def _extract_pdf(content: bytes) -> str:
    """Concatenate page text with blank lines between pages."""
    try:
        reader = PdfReader(io.BytesIO(content))
        pages = list(reader.pages)
    except Exception as exc:  # pypdf raises a wide family on malformed input
        raise PipelineError(
            reason="pdf_parse_failed",
            error=type(exc).__name__,
            bytes=len(content),
        ) from None

    parts: list[str] = []
    for index, page in enumerate(pages):
        try:
            page_text = page.extract_text()
        except Exception as exc:  # one bad page must not lose the whole document
            # Class name only: a pypdf message can quote raw stream bytes.
            logger.warning(
                "pdf page extraction failed (page=%d, error=%s)", index, type(exc).__name__
            )
            page_text = None
        parts.append(page_text or "")

    logger.debug("pdf extracted (pages=%d, bytes=%d)", len(pages), len(content))
    return "\n\n".join(parts)


def _iter_docx_text(blocks: Iterator[Paragraph | Table]) -> Iterator[str]:
    """Yield paragraph and table-cell text in document order, recursively.

    ``iter_inner_content`` is python-docx's document-order walk, so a table
    that sits between two paragraphs is emitted between them rather than
    appended at the end. Cells are walked the same way, which picks up nested
    tables.

    A merged cell occupies every grid slot it spans, so ``row.cells`` hands back
    the *same* ``<w:tc>`` element once per slot. Dedupe is therefore per table,
    not per row: a horizontal merge repeats within one row, but a vertical merge
    repeats across rows, and row-scoped bookkeeping emits it once per row.
    """
    for block in blocks:
        if isinstance(block, Table):
            seen: set[int] = set()
            # lxml hands out one proxy object per underlying element only while
            # a reference to it is alive; drop the last one and CPython is free
            # to reuse its id() for a different element. Holding the proxies for
            # the length of the table keeps identity comparison sound.
            alive: list[object] = []
            for row in block.rows:
                for cell in row.cells:
                    # ``_tc`` is the shared <w:tc> element and the only handle
                    # python-docx exposes for merged-cell identity.
                    element = cell._tc
                    marker = id(element)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    alive.append(element)
                    yield from _iter_docx_text(cell.iter_inner_content())
        else:
            yield block.text


def _declared_uncompressed_size(content: bytes) -> int | None:
    """Total ``file_size`` over the ZIP central directory, or ``None`` if unreadable.

    No member is decompressed: only the directory is parsed. ``None`` means the
    directory could not be read at all, in which case python-docx will reject the
    package on its own.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return sum(info.file_size for info in archive.infolist())
    except (zipfile.BadZipFile, OSError, ValueError):
        return None


def _extract_docx(content: bytes) -> str:
    """Paragraph text plus every table cell, newline-joined, in document order."""
    declared = _declared_uncompressed_size(content)
    if declared is not None and declared > MAX_DOCX_UNCOMPRESSED_BYTES:
        # Decompression bomb: refuse before python-docx materialises the package.
        # Counts only -- the archive's own member names are attacker-controlled.
        logger.warning(
            "docx rejected: declared expansion exceeds the limit "
            "(bytes=%d, uncompressed=%d, limit=%d)",
            len(content),
            declared,
            MAX_DOCX_UNCOMPRESSED_BYTES,
        )
        raise PipelineError(
            reason="docx_expansion_limit",
            bytes=len(content),
            uncompressed=declared,
            limit=MAX_DOCX_UNCOMPRESSED_BYTES,
        )
    try:
        document = open_docx(io.BytesIO(content))
        # The walk is inside the guard, not just the open. python-docx accepts a
        # package whose main part is well-formed XML but *not* WordprocessingML
        # -- ``word/document.xml`` holding ``<a/>`` is enough -- and only fails
        # when the body is first traversed, which for a generator means at the
        # ``list()``. That escaped as a bare ``AttributeError`` from lxml: an
        # unstructured 500 for a plain file upload, and a traceback out of a
        # parser this module promises will never surface one.
        lines = list(_iter_docx_text(document.iter_inner_content()))
    except Exception as exc:
        raise PipelineError(
            reason="docx_parse_failed",
            error=type(exc).__name__,
            bytes=len(content),
        ) from None

    logger.debug("docx extracted (blocks=%d, bytes=%d)", len(lines), len(content))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------


def _normalise(text: str) -> str:
    """Trim trailing whitespace per line, cap blank runs, end with one newline.

    Returns ``""`` for anything with no visible characters -- a scanned PDF or
    an empty upload is not an error, it is a document with no text.
    """
    if not text.strip():
        return ""

    unified = text.replace("\r\n", "\n").replace("\r", "\n")
    stripped = "\n".join(line.rstrip() for line in unified.split("\n"))
    collapsed = _EXCESS_BLANK_LINES.sub("\n\n\n", stripped)
    return collapsed.strip("\n") + "\n"


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------


def _extract_sync(filename: str, content: bytes) -> str:
    """The whole CPU-bound path: detect, dispatch, normalise. Thread-only."""
    kind = detect_kind(filename, content)
    if kind == KIND_PDF:
        raw = _extract_pdf(content)
    elif kind == KIND_DOCX:
        raw = _extract_docx(content)
    else:
        raw = _decode_text(content)
    return _normalise(raw)


async def extract_text(filename: str, content: bytes) -> str:
    """Extract plain text from an uploaded document.

    Dispatches on :func:`detect_kind`. All parsing runs on a worker thread via
    ``asyncio.to_thread`` -- pypdf, python-docx and the ZIP sniff are
    synchronous and CPU-bound, and a 50-page PDF on the event loop would stall
    every other request (build doc section 16).

    Returns:
        Normalised text, ending in exactly one ``\\n``, or ``""`` when the
        document holds no text at all.

    Raises:
        PipelineError: and nothing else. Unsupported type
            (``unsupported_document_type``), a DOCX whose declared expansion
            exceeds :data:`MAX_DOCX_UNCOMPRESSED_BYTES` (``docx_expansion_limit``),
            or a container the parser could not open *or walk*
            (``pdf_parse_failed`` / ``docx_parse_failed``). Every parser
            exception is converted here rather than propagated, so a caller never
            sees a pypdf or lxml traceback; details are structured codes and
            counts only.
    """
    started = time.perf_counter()
    text = await asyncio.to_thread(_extract_sync, filename, content)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    # Suffix, not filename: a filename can itself be a personal identifier.
    logger.info(
        "extract_text done (suffix=%s, bytes=%d, chars=%d, elapsed_ms=%.1f)",
        _short_suffix(filename),
        len(content),
        len(text),
        elapsed_ms,
    )
    return text
