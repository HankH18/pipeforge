"""Tests for :mod:`secure_context_pipeline.store.extraction` (build doc section 9.1).

Every fixture in this file is built programmatically from synthetic strings --
no binaries are committed and no real personal data appears anywhere (build doc
section 16). ``asyncio_mode = "auto"`` is set in ``pyproject.toml``, so plain
``async def test_*`` functions run without a decorator.
"""

from __future__ import annotations

import asyncio
import inspect
import io
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest
from docx import Document as new_docx
from pypdf import PdfReader, PdfWriter

from secure_context_pipeline.errors import PipelineError
from secure_context_pipeline.store import extraction
from secure_context_pipeline.store.extraction import (
    KIND_DOCX,
    KIND_PDF,
    KIND_TXT,
    MAX_DOCX_UNCOMPRESSED_BYTES,
    SUPPORTED_SUFFIXES,
    detect_kind,
    extract_text,
)

# Synthetic strings only -- invented company/report language, no personal data.
PARA_ONE = "Synthetic quarterly summary for the fictional Northwind test corpus."
PARA_TWO = "Second paragraph, retained to prove paragraph boundaries survive."
CELL_HEADER = "Region"
CELL_VALUE = "Zone-Alpha"
MERGED_CELL_VALUE = "Zone-Merged"
PDF_LINE = "Synthetic extraction probe line"


# ---------------------------------------------------------------------------
# fixture builders
# ---------------------------------------------------------------------------


def build_docx_bytes(tmp_path: Path) -> bytes:
    """A .docx with a paragraph, then a 2x2 table, then a paragraph."""
    document = new_docx()
    document.add_paragraph(PARA_ONE)

    table = document.add_table(rows=2, cols=2)
    table.cell(0, 0).text = CELL_HEADER
    table.cell(0, 1).text = "Headcount"
    table.cell(1, 0).text = CELL_VALUE
    table.cell(1, 1).text = "42"

    document.add_paragraph(PARA_TWO)

    path = tmp_path / "synthetic.docx"
    document.save(str(path))
    return path.read_bytes()


def build_text_pdf_bytes(line: str) -> bytes:
    """A minimal, byte-exact single-page PDF whose content stream draws ``line``.

    Written by hand rather than with a PDF library because none of our
    dependencies expose a text-drawing API. Object offsets are computed while
    assembling so the xref table is genuinely valid.
    """
    escaped = line.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    stream = f"BT /F1 24 Tf 72 700 Td ({escaped}) Tj ET".encode("ascii")

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "
        + str(len(stream)).encode("ascii")
        + b" >>\nstream\n"
        + stream
        + b"\nendstream",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n"

    xref_offset = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode("ascii")
    out += f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    return bytes(out)


def build_blank_pdf_bytes() -> bytes:
    """A structurally valid PDF with one page and no text operators."""
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# 1. TXT round-trip: plain UTF-8, UTF-8 with BOM, latin-1
# ---------------------------------------------------------------------------


async def test_txt_plain_utf8_round_trip() -> None:
    body = "Ünicode café — em dash and ünlaut survive."
    assert await extract_text("notes.txt", body.encode("utf-8")) == body + "\n"


async def test_txt_markdown_suffix_is_supported() -> None:
    assert ".md" in SUPPORTED_SUFFIXES
    extracted = await extract_text("readme.md", b"# Heading\n\nBody text.")
    assert extracted == "# Heading\n\nBody text.\n"


async def test_txt_utf8_bom_is_stripped() -> None:
    body = "Café résumé with a byte order mark."
    raw = body.encode("utf-8-sig")

    assert raw.startswith(b"\xef\xbb\xbf")
    result = await extract_text("bom.txt", raw)

    assert result == body + "\n"
    assert "﻿" not in result


async def test_txt_latin1_falls_back_without_raising() -> None:
    body = "Café résumé encodé en latin-1."
    raw = body.encode("latin-1")

    with pytest.raises(UnicodeDecodeError):
        raw.decode("utf-8")

    assert await extract_text("legacy.txt", raw) == body + "\n"


async def test_empty_text_file_returns_empty_string() -> None:
    assert await extract_text("empty.txt", b"") == ""
    assert await extract_text("blank.txt", b"   \n\n \t \n") == ""


# ---------------------------------------------------------------------------
# 2. DOCX: paragraphs and table cells, in document order
# ---------------------------------------------------------------------------


async def test_docx_includes_paragraphs_and_table_cells_in_order(tmp_path: Path) -> None:
    raw = build_docx_bytes(tmp_path)

    text = await extract_text("synthetic.docx", raw)

    for fragment in (PARA_ONE, CELL_HEADER, "Headcount", CELL_VALUE, "42", PARA_TWO):
        assert fragment in text, f"missing {fragment!r}"

    # Document order: paragraph, then the table, then the closing paragraph.
    assert text.index(PARA_ONE) < text.index(CELL_HEADER) < text.index(CELL_VALUE)
    assert text.index(CELL_VALUE) < text.index(PARA_TWO)

    # Cells and paragraphs are newline-joined, and each cell is its own line.
    assert CELL_VALUE in text.split("\n")
    assert text.endswith("\n")


async def test_docx_table_cell_is_not_duplicated(tmp_path: Path) -> None:
    raw = build_docx_bytes(tmp_path)
    text = await extract_text("synthetic.docx", raw)
    assert text.count(CELL_VALUE) == 1


def build_merged_table_docx(tmp_path: Path, *, direction: str) -> bytes:
    """A 3x3 table with one cell merged across a row or down a column.

    A merged cell occupies every grid slot it spans, and python-docx returns the
    *same* ``<w:tc>`` element for each of them, so an extractor that does not
    track element identity emits the text once per slot.
    """
    document = new_docx()
    table = document.add_table(rows=3, cols=3)
    for row_index in range(3):
        for column_index in range(3):
            table.cell(row_index, column_index).text = f"r{row_index}c{column_index}"
    target = table.cell(0, 2) if direction == "horizontal" else table.cell(2, 0)
    table.cell(0, 0).merge(target)
    table.cell(0, 0).text = MERGED_CELL_VALUE

    path = tmp_path / f"merged-{direction}.docx"
    document.save(str(path))
    return path.read_bytes()


@pytest.mark.parametrize("direction", ["horizontal", "vertical"])
async def test_merged_table_cell_is_emitted_exactly_once(tmp_path: Path, direction: str) -> None:
    """A merged cell spans three grid slots; its text must appear once, not three times.

    The vertical case is the one that regressed: dedupe scoped to a single row
    catches a horizontal merge and misses a vertical one entirely.
    """
    raw = build_merged_table_docx(tmp_path, direction=direction)

    # The premise, established without python-docx: the merged text is written
    # into the package exactly once. Both the fixture builder and the extractor
    # go through python-docx, so "it came out once" would otherwise rest on that
    # one library agreeing with itself. Any repetition in the output is
    # therefore the extractor's, not the document's.
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        document_xml = archive.read("word/document.xml")
    assert document_xml.count(MERGED_CELL_VALUE.encode()) == 1, (
        "the fixture does not hold the merged value exactly once"
    )

    text = await extract_text("merged.docx", raw)

    assert text.count(MERGED_CELL_VALUE) == 1, text
    # The surviving unmerged cells are still all there, each exactly once.
    survivors = (
        ["r1c0", "r1c1", "r1c2", "r2c0", "r2c1", "r2c2"]
        if direction == "horizontal"
        else ["r0c1", "r0c2", "r1c1", "r1c2", "r2c1", "r2c2"]
    )
    for cell in survivors:
        assert text.count(cell) == 1, f"{cell!r} appears {text.count(cell)} times in {text!r}"


async def test_distinct_cells_are_never_collapsed(tmp_path: Path) -> None:
    """Identity-based dedupe must not swallow distinct cells that share text.

    Deduping a whole table by element identity is only sound if the identity keys
    stay valid for the length of the walk; a wide table with repeated values is
    where a recycled key would show up as silently missing content.
    """
    document = new_docx()
    table = document.add_table(rows=12, cols=6)
    for row_index in range(12):
        for column_index in range(6):
            # Every cell holds the *same* text: only element identity can tell
            # them apart, so nothing can be dropped by comparing strings.
            table.cell(row_index, column_index).text = CELL_VALUE
    path = tmp_path / "wide.docx"
    document.save(str(path))

    text = await extract_text("wide.docx", path.read_bytes())

    assert text.count(CELL_VALUE) == 12 * 6


# ---------------------------------------------------------------------------
# 3. PDF extraction returns a str and does not raise
# ---------------------------------------------------------------------------


async def test_pdf_with_text_extracts_the_line() -> None:
    raw = build_text_pdf_bytes(PDF_LINE)

    assert raw.startswith(b"%PDF-")
    text = await extract_text("probe.pdf", raw)

    assert isinstance(text, str)
    # Whitespace inside a PDF text object is a layout artefact; compare tokens.
    assert text.split() == PDF_LINE.split()
    assert text.endswith("\n")


async def test_pdf_blank_page_yields_empty_string() -> None:
    text = await extract_text("blank.pdf", build_blank_pdf_bytes())

    assert isinstance(text, str)
    assert text == ""


async def test_multi_page_pdf_is_joined_and_does_not_raise() -> None:
    writer = PdfWriter()
    for line in ("Page one synthetic marker", "Page two synthetic marker"):
        writer.append(PdfReader(io.BytesIO(build_text_pdf_bytes(line))))
    buffer = io.BytesIO()
    writer.write(buffer)

    text = await extract_text("merged.pdf", buffer.getvalue())

    assert isinstance(text, str)
    assert "Page one synthetic marker" in text
    assert "Page two synthetic marker" in text
    assert text.index("Page one") < text.index("Page two")


# ---------------------------------------------------------------------------
# 4. detect_kind trusts magic bytes over the suffix
# ---------------------------------------------------------------------------


def test_detect_kind_happy_paths(tmp_path: Path) -> None:
    assert detect_kind("a.pdf", build_text_pdf_bytes(PDF_LINE)) == KIND_PDF
    assert detect_kind("a.docx", build_docx_bytes(tmp_path)) == KIND_DOCX
    assert detect_kind("a.txt", b"plain") == KIND_TXT
    assert detect_kind("a.md", b"# plain") == KIND_TXT


def test_detect_kind_prefers_magic_bytes_over_suffix(tmp_path: Path) -> None:
    docx_bytes = build_docx_bytes(tmp_path)
    pdf_bytes = build_text_pdf_bytes(PDF_LINE)

    # Mislabelled as text, but the bytes are a Word package.
    assert detect_kind("actually_a_word_doc.txt", docx_bytes) == KIND_DOCX
    assert detect_kind("actually_a_pdf.txt", pdf_bytes) == KIND_PDF

    # ...and the reverse: a .docx / .pdf name over plain text bytes.
    assert detect_kind("actually_text.docx", b"just some plain text") == KIND_TXT
    assert detect_kind("actually_text.pdf", b"just some plain text") == KIND_TXT


async def test_extract_text_follows_the_magic_bytes(tmp_path: Path) -> None:
    docx_bytes = build_docx_bytes(tmp_path)

    text = await extract_text("mislabelled.txt", docx_bytes)

    # Parsed as DOCX, not decoded as a ZIP's raw bytes.
    assert PARA_ONE in text
    assert "PK" not in text.split("\n")[0]


def test_detect_kind_rejects_a_non_word_zip() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("xl/workbook.xml", "<workbook/>")

    with pytest.raises(PipelineError) as excinfo:
        detect_kind("sheet.docx", buffer.getvalue())

    assert excinfo.value.detail["reason"] == "unsupported_document_type"


# ---------------------------------------------------------------------------
# 5. Unsupported type raises PipelineError -- with structured detail only
# ---------------------------------------------------------------------------


def test_unsupported_type_raises_pipeline_error() -> None:
    with pytest.raises(PipelineError) as excinfo:
        detect_kind("x.bin", b"\x00\x01\x02")

    assert excinfo.value.detail["reason"] == "unsupported_document_type"
    assert excinfo.value.detail["suffix"] == ".bin"


async def test_extract_text_propagates_unsupported_type() -> None:
    with pytest.raises(PipelineError):
        await extract_text("x.bin", b"\x00\x01\x02")


def test_unsupported_error_carries_no_content() -> None:
    secret = "SYNTHETIC-CANARY-TOKEN-9999"
    payload = b"\x00\x01\x02" + secret.encode("ascii")

    with pytest.raises(PipelineError) as excinfo:
        detect_kind("payload.bin", payload)

    rendered = f"{excinfo.value} {excinfo.value!r} {excinfo.value.detail}"
    assert secret not in rendered
    for value in excinfo.value.detail.values():
        assert not isinstance(value, str) or len(value) <= 64


def test_unsupported_error_suffix_stays_short() -> None:
    with pytest.raises(PipelineError) as excinfo:
        detect_kind("f." + "z" * 200, b"\x00\x01\x02")

    suffix = excinfo.value.detail["suffix"]
    assert isinstance(suffix, str)
    assert len(suffix) <= 16


# ---------------------------------------------------------------------------
# 6. Normalisation
# ---------------------------------------------------------------------------


async def test_blank_line_runs_collapse_and_output_ends_with_one_newline() -> None:
    # "alpha", five blank lines, "bravo".
    raw = ("alpha" + "\n" * 6 + "bravo").encode("utf-8")

    text = await extract_text("gaps.txt", raw)

    assert text == "alpha\n\n\nbravo\n"  # five blank lines -> two
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    assert "\n\n\n\n" not in text


async def test_paragraph_boundaries_survive_normalisation() -> None:
    raw = b"First paragraph.\n\nSecond paragraph.\n\nThird paragraph."

    text = await extract_text("paras.txt", raw)

    assert text == "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.\n"
    assert len(text.split("\n\n")) == 3  # the detector chunks on these


async def test_trailing_whitespace_is_stripped_per_line() -> None:
    raw = b"line one   \t\nline two  \r\nline three\n"

    text = await extract_text("ws.txt", raw)

    assert text == "line one\nline two\nline three\n"
    assert "\r" not in text


async def test_many_trailing_newlines_collapse_to_exactly_one() -> None:
    text = await extract_text("tail.txt", b"only line\n\n\n\n\n\n\n")
    assert text == "only line\n"


# ---------------------------------------------------------------------------
# 6b. Hostile uploads: decompression bombs and XML entity attacks
# ---------------------------------------------------------------------------

_CONTENT_TYPES_XML = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
    'content-types"><Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.wordprocessingml.document.main+xml"/></Types>'
)
_RELS_XML = (
    '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/'
    '2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    "</Relationships>"
)


def build_docx_package(document_xml: bytes) -> bytes:
    """A minimal, structurally valid OOXML package wrapping ``document_xml``.

    Hand-built rather than produced by python-docx because these tests need the
    main part to hold bytes python-docx would never write.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES_XML)
        archive.writestr("_rels/.rels", _RELS_XML)
        archive.writestr("word/document.xml", document_xml)
    return buffer.getvalue()


async def test_the_expansion_ceiling_sits_between_the_upload_cap_and_the_process(
) -> None:
    """The limit is a policy number, so state it independently of the module.

    Every other assertion about the guard builds its input from
    ``MAX_DOCX_UNCOMPRESSED_BYTES`` and then reads the same constant back out of
    the error, which holds for *any* value it might have -- including one so low
    that ordinary documents are refused, or so high that the guard is decorative.
    The bound that matters is the relationship to the API's 16 MB upload cap.
    """
    upload_cap = 16 * 1024 * 1024
    assert MAX_DOCX_UNCOMPRESSED_BYTES > upload_cap, "a ceiling below the upload cap is unreachable"
    assert MAX_DOCX_UNCOMPRESSED_BYTES <= 32 * upload_cap, "a ceiling this high bounds nothing"


async def test_docx_decompression_bomb_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tiny upload that expands past the ceiling is rejected without expanding it.

    Repetitive XML deflates at roughly 1000:1, so an upload well inside the API's
    16 MB limit can materialise gigabytes. The guard reads the ZIP central
    directory only -- CPython's ``zipfile`` truncates a member at its declared
    ``file_size``, so the declared total is an upper bound on what any parser
    can be made to allocate.

    "Without expanding it" is the half that the error alone cannot show: a guard
    that opened the package first and checked afterwards would raise exactly the
    same ``PipelineError``, just after paying the allocation the limit exists to
    prevent. So python-docx is replaced by a tripwire -- reaching it at all is
    the failure.
    """

    def must_not_be_reached(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("python-docx opened the package before the size guard ran")

    monkeypatch.setattr(extraction, "open_docx", must_not_be_reached)

    payload = b"<?xml version='1.0'?><a>" + b"A" * (MAX_DOCX_UNCOMPRESSED_BYTES + 1) + b"</a>"
    bomb = build_docx_package(payload)
    assert len(bomb) < 1_000_000, "the bomb must be small enough to pass an upload limit"

    with pytest.raises(PipelineError) as err:
        await extract_text("bomb.docx", bomb)

    assert err.value.detail["reason"] == "docx_expansion_limit"
    assert err.value.detail["limit"] == MAX_DOCX_UNCOMPRESSED_BYTES
    uncompressed = err.value.detail["uncompressed"]
    assert isinstance(uncompressed, int)
    assert uncompressed > MAX_DOCX_UNCOMPRESSED_BYTES
    # Counts only -- no member name, no byte of the payload.
    assert "A" * 32 not in str(err.value)


async def test_a_zip_posing_as_docx_fails_structurally_not_with_a_traceback() -> None:
    """A package that opens but is not WordprocessingML must still raise ``PipelineError``.

    ``word/document.xml`` holding well-formed XML that is not a Word body passes
    the container sniff *and* ``open_docx``; python-docx only fails when the body
    is traversed. Guarding the open alone let a bare ``AttributeError`` from lxml
    escape ``extract_text`` -- an unstructured 500 for an ordinary file upload,
    and a raw parser traceback out of the one module that promises never to
    surface one.
    """
    payload = build_docx_package(b"<?xml version='1.0'?><notAWordDocument/>")

    with pytest.raises(PipelineError) as err:
        await extract_text("poser.docx", payload)

    assert err.value.detail["reason"] == "docx_parse_failed"
    # Class name only: a parser message can quote raw stream bytes.
    assert err.value.detail["error"] == "AttributeError"
    assert "notAWordDocument" not in str(err.value)


async def test_docx_with_many_members_is_a_known_residual() -> None:
    """The size ceiling bounds declared bytes, not member count. Pinned, not claimed.

    An archive of empty members declares zero uncompressed bytes and sails
    through the guard, while the central-directory parse allocates a ``ZipInfo``
    per member. The cost is real but bounded and transient (~7x the upload size
    in peak RSS, versus the ~1000x the guard closes), and it is paid inside
    ``zipfile.ZipFile()`` before any check of ours could run.

    This test exists so the guard's scope cannot quietly be restated as "DOCX
    bombs are handled": it asserts what actually happens, so a future member-count
    bound has to change the test rather than merely the docstring.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES_XML)
        archive.writestr("_rels/.rels", _RELS_XML)
        archive.writestr("word/document.xml", b"<?xml version='1.0'?><a/>")
        for index in range(5000):
            archive.writestr(f"pad/{index}", b"")
    payload = buffer.getvalue()

    # The archive really is tiny once expanded -- measured by decompressing it
    # here rather than by asking ``_declared_uncompressed_size``, which is the
    # function the guard itself uses and so cannot be the witness for whether
    # the guard was given anything to object to.
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        actual_expanded = sum(len(archive.read(name)) for name in archive.namelist())
        member_count = len(archive.namelist())
    assert actual_expanded < MAX_DOCX_UNCOMPRESSED_BYTES
    assert member_count > 5000, "the residual is about member count, so there must be many"

    # So the package is accepted rather than refused. Documented, not desired.
    with pytest.raises(PipelineError) as err:
        await extract_text("many.docx", payload)
    assert err.value.detail["reason"] == "docx_parse_failed", (
        "rejection must come from the parser, not from the expansion guard"
    )


async def test_a_large_but_honest_docx_still_extracts(tmp_path: Path) -> None:
    """The bomb guard must not reject documents that merely compress well."""
    document = new_docx()
    for index in range(2000):
        document.add_paragraph(f"{PARA_ONE} {index}")
    path = tmp_path / "long.docx"
    document.save(str(path))

    text = await extract_text("long.docx", path.read_bytes())

    assert text.count(PARA_ONE) == 2000


async def test_docx_external_entity_is_not_expanded(tmp_path: Path) -> None:
    """XXE: an external entity in the main part must not read a local file."""
    secret = tmp_path / "secret.txt"
    secret.write_text("XXE-CANARY-9f3b21", encoding="utf-8")
    document_xml = f"""<?xml version="1.0"?>
<!DOCTYPE w:document [ <!ENTITY xxe SYSTEM "file://{secret}"> ]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body><w:p><w:r><w:t>probe:&xxe;</w:t></w:r></w:p></w:body>
</w:document>""".encode()

    try:
        text = await extract_text("xxe.docx", build_docx_package(document_xml))
    except PipelineError:
        return  # Refusing to parse it at all is an equally good outcome.
    assert "XXE-CANARY-9f3b21" not in text


async def test_docx_entity_expansion_bomb_does_not_run(tmp_path: Path) -> None:
    """"Billion laughs": nested entity definitions must not be expanded."""
    document_xml = b"""<?xml version="1.0"?>
<!DOCTYPE w:document [
 <!ENTITY a "aaaaaaaaaa"> <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
 <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"> <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
 <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;"> <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
 <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:body><w:p><w:r><w:t>&g;</w:t></w:r></w:p></w:body>
</w:document>"""

    try:
        text = await extract_text("laughs.docx", build_docx_package(document_xml))
    except PipelineError:
        return
    assert len(text) < 10_000, "entity expansion produced a document larger than its source"


# ---------------------------------------------------------------------------
# 7. The event loop is never blocked
# ---------------------------------------------------------------------------


def test_extract_text_is_a_coroutine_function() -> None:
    assert inspect.iscoroutinefunction(extract_text)


async def test_extract_text_offloads_work_to_a_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behavioural proof that parsing goes through ``asyncio.to_thread``."""
    calls: list[str] = []
    real_to_thread = asyncio.to_thread

    async def spy_to_thread(func: Any, /, *args: Any, **kwargs: Any) -> Any:
        calls.append(getattr(func, "__name__", repr(func)))
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", spy_to_thread)

    text = await extract_text("offload.txt", b"content routed through a worker thread")

    assert text.endswith("\n")
    assert calls, "extract_text did not await asyncio.to_thread"
    assert calls == ["_extract_sync"]


async def test_extraction_runs_off_the_event_loop_thread() -> None:
    """The parse must not execute on the loop's own thread."""
    loop_thread = threading.get_ident()
    seen: list[int] = []

    real_to_thread = asyncio.to_thread

    async def recording(func: Any, /, *args: Any, **kwargs: Any) -> Any:
        def wrapper() -> Any:
            seen.append(threading.get_ident())
            return func(*args, **kwargs)

        return await real_to_thread(wrapper)

    original = asyncio.to_thread
    asyncio.to_thread = recording
    try:
        await extract_text("thread.txt", b"payload")
    finally:
        asyncio.to_thread = original

    assert seen and all(tid != loop_thread for tid in seen)
