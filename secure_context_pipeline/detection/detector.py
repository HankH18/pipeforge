"""Presidio-backed detection (build doc sections 9.2, 12, 16).

The detector is the only component that ever sees an original document in full.
Three things it must get exactly right:

1. **Absolute offsets.** Chunks are analysed independently, so every
   :class:`~secure_context_pipeline.models.Detection` carries offsets translated
   back into the original text. The obfuscation engine splices by those offsets;
   an off-by-one here is a leak. Before returning, ``detect`` checks
   ``text[d.start:d.end] == d.text`` for every detection and raises
   :class:`DetectionInvariantError` if it does not hold -- a raise rather than an
   ``assert`` so that ``python -O`` cannot strip the guard.
2. **Never on the event loop.** spaCy and Presidio are synchronous and CPU-bound.
   Chunks go through ``asyncio.to_thread`` behind a semaphore (build doc section 16).
3. **No content in logs or exceptions.** Entity types, counts, offsets, scores and
   durations only -- including on the failure path, where the exception's
   ``reason`` is the *class name* of the underlying error, never its message.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from bisect import bisect_right
from collections.abc import Sequence
from typing import Any

from presidio_analyzer import AnalyzerEngine, EntityRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

from secure_context_pipeline.config import Settings
from secure_context_pipeline.daterules import split_composite_date
from secure_context_pipeline.detection.recognizers import (
    build_recognizers,
    gazetteer_occurrences,
)
from secure_context_pipeline.detection.registry import (
    TIER_TEMPORAL,
    EntityRegistry,
    EntitySpec,
)
from secure_context_pipeline.errors import DetectionError, PipelineError
from secure_context_pipeline.models import Detection

__all__ = [
    "CHUNK_OVERLAP_CHARS",
    "CONTEXT_WINDOW_AFTER",
    "CONTEXT_WINDOW_BEFORE",
    "DEFAULT_SPACY_MODEL",
    "GAZETTEER_MERGE_MAX_STEPS",
    "PRESIDIO_LOGGER_NAME",
    "DetectionInvariantError",
    "Detector",
    "get_analyzer",
    "reset_analyzer_cache",
    "resolve_overlaps",
    "warm_up",
]

logger = logging.getLogger(__name__)


class DetectionInvariantError(PipelineError):
    """A structural invariant of the detection path did not hold.

    Lives here rather than in :mod:`secure_context_pipeline.errors` for the reason
    that module documents for ``LLMError`` and ``InvalidCategoryError``: it is
    implementation detail of one package and nothing catches it by type.

    Raised instead of ``assert`` because ``python -O`` strips assert statements, and
    these two invariants are the ones that must not be strippable. The engine vaults
    ``detection.text`` while splicing ``text[start:end]``: if those ever diverge, the
    vault holds a value that never appeared in the document and de-obfuscation
    restores the wrong string into the user's answer -- silently, with nothing red
    anywhere. A production deployment running ``-O`` would have no guard at all.

    Detail is offsets, lengths and entity types only. Never a span: that is an
    original value (build doc section 16).
    """

    code = "DETECTION_INVARIANT"


def _verify_offsets(text: str, detections: Sequence[Detection]) -> None:
    """Every detection must still address its own text in ``text``."""
    for detection in detections:
        if text[detection.start : detection.end] != detection.text:
            raise DetectionInvariantError(
                reason="offset_drift",
                entity_type=detection.entity_type[:64],
                start=detection.start,
                end=detection.end,
                text_chars=len(text),
                detection_chars=len(detection.text),
            )


DEFAULT_SPACY_MODEL = "en_core_web_lg"
LANGUAGE = "en"

# Context window used when deciding which registry entity claims a built-in hit.
# Asymmetric on purpose: labels sit before their value ("DOB: 1985-03-12"), and a
# trailing window only has to catch the occasional "1985-03-12 (date of birth)".
#
# These are the OUTER bound, not the window itself -- see ``_context_window_start``.
# 60 characters of plain lookback reaches over an intervening field, and a chart
# header puts three differently-labelled dates inside one:
#
#     Name: Chelsea Hammond   DOB: 03/12/1985   Admitted: 07/01/2024
#
# (Same header as ``_context_window_start``'s docstring, and the same name for the
# reason given there: the one this example used to carry is a live NER recall miss.)
#
# Every one of those dates starts within 60 characters of the single ``DOB:``, so
# all three were typed DOB/PII. Over-claiming that way leaks nothing -- every one of
# them is still vaulted and masked -- but the entity type and category are wrong in
# the outbound surrogate, in the audit row and in the UI panel, and build doc section
# 9.2 splits DATE_TIME into DOB and DATE precisely so that distinction means
# something. UNDER-claiming is the other thing entirely: outside a medical document
# DOB is the only claimant of DATE_TIME, so a date that loses its context word is not
# re-typed, it is dropped. ``_resolve_builtin`` is where that asymmetry is enforced.
CONTEXT_WINDOW_BEFORE = 60
CONTEXT_WINDOW_AFTER = 30

# Characters a field LABEL is made of: letters, the blanks inside a multi-word
# label, and the punctuation real labels carry ("D.O.B.", "Acct. No.", "MRN #").
# Deliberately excludes digits, so the walk-back in ``_context_window_start`` stops
# at the previous field's value rather than eating through it.
_LABEL_RUN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz .,/#&()-'"
)

# Presidio's DEBUG path has call sites that log document content. Build doc section
# 16 forbids that unconditionally and carves out no exception for debug paths, so
# the third-party logger is muted the moment this module is imported.
PRESIDIO_LOGGER_NAME = "presidio-analyzer"


class _BelowInfoFilter(logging.Filter):
    """Drops every record below INFO, whatever level the logger is set to."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.INFO


def _mute_presidio_content_logging() -> None:
    """Silence Presidio's sub-INFO stream in a way a caller cannot undo.

    Which content, concretely: ``lemma_context_aware_enhancer`` emits
    ``"Context list is: %s"`` -- the lemmatised words surrounding a match, joined
    into one string. That is document content, and on this registry it is *live*,
    not hypothetical. ``AnalyzerEngine.analyze`` folds ad-hoc recognizers into the
    same list it passes to the enhancer, so every ``patterns:`` and ``gazetteer:``
    entity here is context-enhanced exactly like a registered one (measured: an
    ``MRN`` hit scores 0.70 bare and 1.00 with "medical record chart" in front of
    it). Any registry entity carrying ``context:`` therefore drives that log line
    with words lifted out of the document, at DEBUG, on every match.

    ``setLevel(INFO)`` on its own is only advisory. Any caller that later runs
    ``logging.getLogger("presidio-analyzer").setLevel(DEBUG)`` -- or a
    ``dictConfig``/``fileConfig`` naming the logger, which is exactly what a host
    application's "enable debug logging" flag does -- undoes it. ``Logger.handle``
    consults the logger's filters for every record it processes *regardless of
    level*, so a filter holds where a level does not.
    """
    presidio_logger = logging.getLogger(PRESIDIO_LOGGER_NAME)
    if presidio_logger.level < logging.INFO:
        presidio_logger.setLevel(logging.INFO)
    if not any(isinstance(existing, _BelowInfoFilter) for existing in presidio_logger.filters):
        presidio_logger.addFilter(_BelowInfoFilter())


_mute_presidio_content_logging()

# Warming the engine compiles every predefined recognizer's regex and loads the
# spaCy pipeline, so the first real request does not pay for either -- and the
# shared Pattern objects are read-only by the time worker threads touch them.
_WARMUP_TEXT = "Warm up: call Jane Roe on 2020-01-02 about 123-45-6789."

_ANALYZER_LOCK = threading.Lock()
_ANALYZERS: dict[str, AnalyzerEngine] = {}

_PARAGRAPH_BREAK = re.compile(r"\n[ \t]*\n+")
_SOFT_BREAK = re.compile(r"(?<=[.!?])[ \t]+|\n+")

# Chunks are analysed independently, so a chunk boundary that lands inside an entity
# used to cut it in half: the regex either matched the truncated prefix -- vaulting
# ``MRN: 447190`` and shipping the trailing ``2`` -- or, once the surviving fragment
# no longer satisfied the pattern, matched nothing at all and the whole identifier
# went out in the clear. A paragraph long enough to need the hard cut in
# ``_split_oversized`` hits this with no adversary involved.
#
# Each chunk is therefore *analysed* over a window running this far into the next
# chunk. Chunking itself is untouched -- the window only widens what the analyzer
# sees, never what ``chunk_text`` returns -- so offsets stay relative to the chunk's
# own absolute start, a straddling entity is matched whole by at least one window,
# and the duplicate the neighbouring window finds is collapsed by resolve_overlaps.
#
# Must exceed the longest span the registry can produce -- the widest is
# CASE_STRATEGY's ~40-character prefix plus its 240-character sentence tail.
# ``test_chunk_overlap_exceeds_the_longest_registry_span`` pins that relationship
# mechanically, so widening a registry quantifier past this fails there rather than
# silently reintroducing boundary truncation.
CHUNK_OVERLAP_CHARS = 512

# How many times ``Detector._merge_gazetteer_run`` may widen one span. Each step
# appends the tail of one further gazetteer term, so this is a bound on the length
# of the term CHAIN a single detection can absorb, not on characters.
#
# Two is what the shipped gazetteers can actually reach, measured by pairing all 208
# diagnosis terms and all 170 medication terms against each other: exactly 4 pairs
# overlap word-wise (``gestational diabetes``/``type 1 diabetes``/``type 2 diabetes``
# each into ``diabetes mellitus``, and ``overactive bladder`` into ``bladder
# cancer``), and no term begins with ``mellitus`` or ``cancer``, so no chain of three
# exists. Four is that doubled -- headroom for a gazetteer edit, and still small
# enough that a pathological future term list cannot walk a span across a paragraph.
#
# Termination does not depend on it: every step strictly increases the span's end,
# which is bounded by the document length. The cap bounds OVER-CAPTURE, which is the
# failure mode the merge rule introduces and the one worth a hard ceiling.
GAZETTEER_MERGE_MAX_STEPS = 4


# ---------------------------------------------------------------------------
# Analyzer singleton
# ---------------------------------------------------------------------------
def _build_analyzer(spacy_model: str) -> AnalyzerEngine:
    _mute_presidio_content_logging()
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": LANGUAGE, "model_name": spacy_model}],
        }
    )
    nlp_engine = provider.create_engine()
    engine: AnalyzerEngine = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=[LANGUAGE],
    )
    engine.analyze(text=_WARMUP_TEXT, language=LANGUAGE)
    return engine


def get_analyzer(spacy_model: str = DEFAULT_SPACY_MODEL) -> AnalyzerEngine:
    """The process-wide ``AnalyzerEngine`` for ``spacy_model``.

    Loading ``en_core_web_lg`` costs seconds and is most of the 2 s obfuscation
    budget, so it happens once per process, not once per request. Double-checked
    locking keyed by model name: concurrent first callers build one engine.
    """
    cached = _ANALYZERS.get(spacy_model)
    if cached is not None:
        return cached
    with _ANALYZER_LOCK:
        cached = _ANALYZERS.get(spacy_model)
        if cached is None:
            started = time.perf_counter()
            cached = _build_analyzer(spacy_model)
            _ANALYZERS[spacy_model] = cached
            logger.info(
                "analyzer_ready model=%s elapsed_ms=%.0f",
                spacy_model,
                (time.perf_counter() - started) * 1000.0,
            )
        return cached


def warm_up(settings: Settings | None = None) -> None:
    """Build the analyzer now -- FastAPI lifespan and ``demo.py`` call this."""
    get_analyzer(settings.spacy_model if settings is not None else DEFAULT_SPACY_MODEL)


def reset_analyzer_cache() -> None:
    """Forget every cached analyzer. Tests only; the next call reloads spaCy."""
    with _ANALYZER_LOCK:
        _ANALYZERS.clear()


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------
def _paragraphs(text: str) -> list[tuple[int, str]]:
    """``(absolute offset, paragraph)`` pairs whose concatenation *is* ``text``.

    Each paragraph keeps its own trailing blank-line separator, which is what makes
    offset arithmetic downstream a plain addition.
    """
    parts: list[tuple[int, str]] = []
    pos = 0
    for match in _PARAGRAPH_BREAK.finditer(text):
        parts.append((pos, text[pos : match.end()]))
        pos = match.end()
    if pos < len(text):
        parts.append((pos, text[pos:]))
    return parts


def _split_oversized(offset: int, body: str, max_chars: int) -> list[tuple[int, str]]:
    """Fallback split for a single paragraph longer than ``max_chars``.

    Cuts on sentence ends and newlines; a run with no boundary at all is hard-cut
    at ``max_chars`` so the function always terminates.
    """
    pieces: list[tuple[int, str]] = []
    boundaries = [match.end() for match in _SOFT_BREAK.finditer(body)]
    boundaries.append(len(body))

    start = 0
    cut = 0
    for boundary in boundaries:
        if boundary - start <= max_chars:
            cut = boundary
            continue
        if cut > start:
            pieces.append((offset + start, body[start:cut]))
            start = cut
        while boundary - start > max_chars:
            pieces.append((offset + start, body[start : start + max_chars]))
            start += max_chars
        cut = boundary
    if start < len(body):
        pieces.append((offset + start, body[start:]))
    return pieces


def chunk_text(text: str, max_chars: int) -> list[tuple[int, str]]:
    """Split on paragraph boundaries into chunks of at most ``max_chars``.

    Returns ``(absolute offset, chunk)`` pairs that concatenate back to ``text``
    exactly -- the invariant the offset checks in ``detect`` rely on. Losing or
    reordering text here raises :class:`DetectionInvariantError` rather than
    corrupting every downstream splice.
    """
    if not text:
        return []

    chunks: list[tuple[int, str]] = []
    buffer: list[str] = []
    buffer_start = 0
    buffer_len = 0

    for offset, paragraph in _paragraphs(text):
        if len(paragraph) > max_chars:
            if buffer:
                chunks.append((buffer_start, "".join(buffer)))
                buffer, buffer_len = [], 0
            chunks.extend(_split_oversized(offset, paragraph, max_chars))
            continue
        if buffer and buffer_len + len(paragraph) > max_chars:
            chunks.append((buffer_start, "".join(buffer)))
            buffer, buffer_len = [], 0
        if not buffer:
            buffer_start = offset
        buffer.append(paragraph)
        buffer_len += len(paragraph)

    if buffer:
        chunks.append((buffer_start, "".join(buffer)))

    # Not an assert: every absolute offset downstream is derived from these chunk
    # starts, so silently losing or reordering text here corrupts the splice.
    rebuilt = "".join(body for _, body in chunks)
    if rebuilt != text:
        raise DetectionInvariantError(
            reason="chunking_lost_text",
            chars=len(text),
            rebuilt_chars=len(rebuilt),
            chunks=len(chunks),
            max_chars=max_chars,
        )
    return chunks


# ---------------------------------------------------------------------------
# Degenerate-run normalisation
# ---------------------------------------------------------------------------
# spaCy's tokenizer is quadratic in the length of an unbroken run of a character it
# splits into one token apiece, and an underscore signature rule or a ``*****``
# markdown separator is exactly that shape. Measured on ``en_core_web_lg`` with
# nothing else in the loop, tokenizing ``'Signature: ' + '_' * n``:
#
#     n =  1,000     90 ms       n =  4,000   1,432 ms      n = 16,000  22,938 ms
#     n =  2,000    357 ms       n =  8,000   5,668 ms
#
# A clean 4x per doubling, against 119 ms for 4,050 characters of ordinary prose.
# ``_`` ``*`` ``=`` ``#`` all do it (~4,000 tokens from 4,000 characters); ``.``
# ``-`` ``/`` and whitespace do not. End to end that made an 8 KB document of
# underscores cost 15.1 s -- as long as the shipped 83 KB ``legal_brief_large.txt``
# -- where 8 KB of prose costs 0.8 s, and the pipeline pays it twice because
# ``EgressGate`` pass 2 re-runs this detector over the payload. Every route is
# anonymous, so a ~20x CPU amplification is reachable by anyone who can POST a file.
#
# Such a run carries no entity by construction: every registry pattern and every NER
# span contains at least one letter or digit, so a stretch containing neither can be
# shortened before the analyzer sees it without any value going unvaulted -- the
# worst a boundary landing in the dropped middle can do is move a span's edge across
# punctuation. ``[\W_]`` is that stretch: every character that is neither a Unicode
# letter nor a Unicode digit (``\W`` alone would exempt ``_``, the reported case).
#
# Only the middle goes. Keeping a head and a tail leaves the sentence structure spaCy
# reads either side of the run intact -- the blank line before it, the newline after
# -- rather than fusing two paragraphs into one.
#
# The quadratic term is *per run*, so bounding every run at 64 characters makes total
# tokenizer cost linear in document length rather than merely shifting the threshold.
# Measured through ``Detector.detect`` on 7,950 characters of underscores: 7,070 ms
# before, 16.7 ms after, with the same two detections either side. The shape that
# still survives -- 64-character runs separated by single letters, which the collapse
# leaves alone by design -- costs 1,455 ms at 8 KB against 389 ms for 8 KB of prose:
# 3.7x rather than the 18x it was. What is left is a bound on absolute cost, which
# this is not and is not meant to be; the detect phase still has no wall-clock ceiling
# of the kind ``EgressGate.DEFAULT_TIMEOUT_S`` gives pass 2.
_DEGENERATE_HEAD = 32
_DEGENERATE_TAIL = 32
_DEGENERATE_RUN_RE = re.compile(rf"[\W_]{{{_DEGENERATE_HEAD + _DEGENERATE_TAIL + 1},}}")


def _collapse_degenerate_runs(text: str) -> tuple[str, list[tuple[int, int]]]:
    """``(text with over-long letterless runs shortened, offset breakpoints)``.

    Breakpoints are ascending ``(offset in the collapsed text, characters dropped
    before that offset)`` pairs, and are the only thing that can translate an
    analyzer result back onto the original -- see :func:`_restore_offset`.
    """
    matches = list(_DEGENERATE_RUN_RE.finditer(text))
    if not matches:
        return text, []

    pieces: list[str] = []
    breaks: list[tuple[int, int]] = []
    cursor = 0
    dropped = 0
    for match in matches:
        start, end = match.span()
        pieces.append(text[cursor : start + _DEGENERATE_HEAD])
        join = start + _DEGENERATE_HEAD - dropped
        dropped += end - start - _DEGENERATE_HEAD - _DEGENERATE_TAIL
        breaks.append((join, dropped))
        cursor = end - _DEGENERATE_TAIL
    pieces.append(text[cursor:])
    return "".join(pieces), breaks


def _restore_offset(breaks: Sequence[tuple[int, int]], offset: int) -> int:
    """Translate ``offset`` in collapsed text back into the text it was collapsed from.

    Monotonic, and exact everywhere a character survived -- which is everywhere an
    entity can start or end, because the dropped characters are letterless.
    """
    index = bisect_right(breaks, offset, key=lambda item: item[0])
    return offset + (breaks[index - 1][1] if index else 0)


# ---------------------------------------------------------------------------
# Overlap resolution
# ---------------------------------------------------------------------------
def resolve_overlaps(
    text: str,
    candidates: Sequence[Detection],
    policy_types: frozenset[str] = frozenset(),
    pattern_types: frozenset[str] = frozenset(),
) -> list[Detection]:
    """Sorted, strictly non-overlapping spans that **cover every candidate**.

    Public and shared on purpose. The obfuscation engine re-runs this over the
    spans it is about to splice, because splicing overlapping spans is undefined
    and ``ObfuscationEngine.obfuscate`` accepts detections from *any* source, not
    only from :class:`Detector`. That second call used to be a hand-written copy
    of this function in :mod:`~secure_context_pipeline.obfuscation.engine`,
    described in its own docstring as mirroring this one -- and it had drifted:
    it carried no ``pattern_types`` dimension and no specificity guard on the
    union-covering winner, so the two disagreed about *which label* an overlap
    keeps. The label picks the entity's tier, action and threshold, so the two
    copies could route the same spans to different pseudonymization paths. One
    implementation with two call sites cannot drift; two cannot be kept honest by
    a docstring.

    Explicit greedy pass: candidates are ranked and the winner of an overlap is the
    one that survives. The build doc's rule is score, then span length, then
    earliest start. Adjacent spans (``a.end == b.start``) are not overlaps and are
    both kept.

    Two categorical dimensions rank **above** all of that, in this order.

    ``policy_types`` (entities carrying ``action: strip`` or ``action: redact``)
    comes first. A policy action is a categorical rule -- "content of this kind must
    never leave" -- not a confidence-weighted detection, so its score is a detector
    artifact that should not decide whether it survives. Without this, a
    10-character span that spaCy mis-tags as PERSON at 0.85 evicts the
    129-character ``CASE_STRATEGY`` span at 0.7 that *contains* it, and privileged
    strategy prose reaches the provider unredacted.

    ``pattern_types`` (entities backed by a registry ``patterns:`` or ``gazetteer:``
    entry) comes second. A hand-written regex for ``MRN`` or ``CASE_ID`` is a
    narrow, auditable claim about one shape of string; ``PERSON`` and ``DATE_TIME``
    are a general-purpose model's guess, and Presidio hands that guess a flat 0.85
    while a registry pattern starts at 0.70. Score alone therefore lets the guess
    take the label off the specific claim whenever no context word happens to be in
    range -- measured on the recall corpus, spaCy reads ``Email
    awhitlock@mailer.example`` as one PERSON and ``24-ARB-00912`` as a DATE_TIME.
    Neither is a leak (the span is masked either way, see below) but the label is
    what picks the pseudonymization tier, so a docket number was being run through
    the date-shift path.

    **The loser is absorbed, never merely dropped.** Ranking alone decides *whose
    label* survives; it must not decide *whether the text is protected*. A plain
    drop is only safe when the winner fully contains the loser. On a partial
    overlap the loser's uncovered remainder stays in the document in the clear, and
    that is a live leak, not a theoretical one:

        "We should to press the causation defence at the hearing, keep our damages
        expert on reserve, and avoid concession before we depose Priyanka
        Raghunathan, their economist."

    ``CASE_STRATEGY``'s bounded sentence tail stops one character into the name, so
    it overlaps ``CLIENT_IDENTITY`` without containing it -- any bound does this to
    some sentence, which is why widening the bound is not a fix. The old code
    dropped the name and shipped ``[REDACTED_CASE_STRATEGY]riyanka Raghunathan`` to
    the provider. The same shape occurs with no policy entity involved at all: a
    spaCy ``PERSON`` span at 0.85 that runs into the ``MRN:`` label outranks the
    ``MRN`` pattern hit at 0.7 and clips it, leaking the digits.

    So an overlapping candidate widens the winner to the union of the two spans.
    Every candidate is then covered by exactly one kept span, whatever the ranking
    decided, and the failure mode flips from under-redaction to over-redaction.
    """

    def categorical(detection: Detection) -> tuple[int, int]:
        """The two rank dimensions that are rules rather than confidence."""
        return (
            0 if detection.entity_type in policy_types else 1,
            0 if detection.entity_type in pattern_types else 1,
        )

    ranked = sorted(
        candidates,
        key=lambda d: (
            *categorical(d),
            -d.score,
            -(d.end - d.start),
            d.start,
            d.entity_type,
        ),
    )
    kept: list[Detection] = []
    for candidate in ranked:
        touching = [
            index
            for index, other in enumerate(kept)
            if candidate.start < other.end and other.start < candidate.end
        ]
        if not touching:
            kept.append(candidate)
            continue
        # ``kept`` is in rank order and ``candidate`` ranks below all of it, so
        # ``members`` runs best-ranked first. The union cannot reach any span outside
        # ``touching`` -- its bounds come from the candidate or from a span that
        # already overlaps the candidate, so there is no gap for an untouched span to
        # hide in, and one pass suffices.
        members = [kept[index] for index in touching] + [candidate]
        start = min(member.start for member in members)
        end = max(member.end for member in members)
        # A span that already *is* the union takes the label, outranked on score or
        # not: otherwise a fragment steals it from the entity that contains it. That
        # happens for real -- spaCy types the bare digits of a boundary-clipped
        # ``MRN: 4471902`` as DATE_TIME at 0.85, which outranks the 0.7 pattern hit on
        # the whole identifier, and the merged span would have been labelled DATE.
        #
        # Covering the union is only a *proxy* for being the more specific claim,
        # though, and the categorical dimensions are direct evidence of it. So a
        # union-covering member has to be at least as specific as the best-ranked
        # one to take the label: spaCy reading ``Email awhitlock@mailer.example`` as
        # a single PERSON covers the union and would otherwise relabel a
        # pattern-matched EMAIL as a NAME.
        best_class = categorical(members[0])
        winner = next(
            (
                member
                for member in members
                if member.start == start
                and member.end == end
                and categorical(member) == best_class
            ),
            members[0],
        )
        if winner.start != start or winner.end != end:
            winner = winner.model_copy(
                update={"start": start, "end": end, "text": text[start:end]}
            )
        kept[touching[0]] = winner
        for index in reversed(touching[1:]):
            del kept[index]
    kept.sort(key=lambda d: (d.start, d.end))
    return kept


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
#: A field label the detector may safely cut an NER span back to: a short run of
#: letters and spaces carrying **no lowercase letter**, immediately followed by a
#: colon in the surrounding text. Bounded, because it is matched against document
#: text.
#:
#: The no-lowercase requirement is what separates a label from a surname, and it was
#: not there at first. ``[A-Za-z][A-Za-z ]{0,20}`` accepts ``Whitfield`` exactly as
#: readily as ``DOB``, so a wrapped person name whose surname happened to be
#: followed by a colon -- a transcript speaker line, a contact line, a name
#: introducing a quote -- was cut back to the given name and the surname was never
#: vaulted. It then reached the provider in the clear, and the gate did not object:
#: ``NAME``/``CLIENT_IDENTITY`` are not high-severity, so pass 2 logs a warning and
#: passes. Under pseudonymization the payload read ``Stone\nWhitfield`` -- an
#: invented given name glued to the real surname.
#:
#: Field labels in these documents are written ``DOB``, ``MRN``, ``SSN``, ``NPI``;
#: surnames are not. The rule is deliberately narrow because the two directions cost
#: different things: failing to trim a real label masks it as part of the name,
#: which is cosmetic, while trimming a real name drops a value nobody then vaults.
#: Only one of those is a disclosure.
#:
#: The character class admits the punctuation labels carry, not only letters and
#: spaces. ``[A-Z][A-Z ]{0,20}`` was the first spelling and it made the rule turn on
#: how the *label* happened to be typed: ``DOB`` was trimmed and ``D.O.B.`` was not,
#: so the exact ``'David Ochoa\n    D.O.B.'`` composite the trim exists to prevent
#: came back verbatim on a spelling ``entities.yaml`` itself ships DOB context for
#: (``d.o.b`` is in DOB's ``context:``, precisely because real charts write it that
#: way). Digits stay out: a run carrying one is a value, not a label.
_FIELD_LABEL_TAIL_RE = re.compile(r"[A-Z][A-Z .,/#&()-]{0,24}\Z")

#: A ``Label: value`` line, anchored at the start of the line. Lazy, so it binds the
#: FIRST colon: the label is the run that *introduces* the value, not everything up
#: to the last colon on the line. Digits are outside the class on purpose -- it is
#: what keeps ``"in Case No. 9:19-cv-19197 was entered by attorney Sara"`` from
#: reading as a labelled field, which is a real line in the shipped legal corpus and
#: the only near-miss the measurement below found.
_FIELD_LINE_RE = re.compile(r"[ \t]*[A-Za-z][A-Za-z .,/#&'()-]{0,40}?:")

#: The same shape matched at the start of the *next* field's label.
_NEXT_LABEL_RE = re.compile(r"[A-Za-z][A-Za-z .,/#&'()-]{0,40}?:")


def _context_window_start(text: str, start: int) -> int:
    """Where the backward context window for a span at ``start`` begins.

    ``CONTEXT_WINDOW_BEFORE`` characters back, except that **the nearest preceding
    field label owns the value that follows it**, so the window never reaches back
    over one label to borrow the previous one. One label, one value.

    That rule is what a fixed 60-character lookback cannot express. Measured on a
    chart header the shipped medical fixture is written in::

        PATIENT CHART
        Name: Chelsea Hammond   DOB: 03/12/1985   Admitted: 07/01/2024
        Discharged: 07/09/2024

    all three dates start within 60 characters of the one ``DOB:``, so all three
    were claimed by DOB even though ``Admitted:`` and ``Discharged:`` carry their
    own, contrary labels. With the window clamped, ``03/12/1985`` still sees ``DOB``
    and the other two see only their own labels, so they fall through to DATE.

    **That name used to be ``Priyanka Raghunathan``, which was an own goal**: spaCy
    emits no ``PERSON`` for that string in this field-shaped frame, so the worked
    example for the clamp handed a reader a header whose patient name is never
    detected and therefore never vaulted. The recall miss is real and is declared in
    the README's section 1 boundary list, along with why no pass of the egress gate
    can backstop it; the example here uses a name the detector does claim, because
    illustrating one rule with a live instance of a different failure teaches the
    wrong thing. Nothing about the clamp changed.

    The clamp is the start of the run of label characters ending at the nearest
    colon before ``start``. Digits are not label characters (:data:`_LABEL_RUN_CHARS`),
    which is what stops the walk at the *previous* field's value: in the header above
    the walk back from ``Admitted:`` halts on the ``5`` of ``1985``. Where a field's
    value is itself alphabetic the walk runs on into it and the window is wider than
    one label -- accepted, because that direction only ever *keeps* context, and
    over-claiming still masks the value while losing it does not.

    **This function narrows a window; it must never be the reason a span ends up
    with no claimant.** Falling through to DATE is only available inside a medical
    document, so outside one a clamp that hides the birth word does not re-type the
    date, it deletes it. ``Detector._resolve_builtin`` is what keeps that from
    happening: it re-scores under the unclamped window whenever the clamped pass
    leaves nothing standing. Read the two together.

    A span with no colon anywhere behind it -- ordinary prose, "Chelsea was born
    03/12/1985" -- gets the full 60 characters unchanged.
    """
    floor = max(0, start - CONTEXT_WINDOW_BEFORE)
    colon = text.rfind(":", floor, start)
    if colon == -1:
        return floor
    label_start = colon
    while label_start > floor and text[label_start - 1] in _LABEL_RUN_CHARS:
        label_start -= 1
    return label_start


def _is_field_label_tail(text: str, start: int, newline: int, end: int) -> bool:
    """Whether ``text[newline:end]`` is a wrapped-on field LABEL rather than value.

    The distinction the newline alone cannot make. ``'David Ochoa\n    DOB'`` is a
    name that ran into the next field's label -- the tail is ``DOB`` and the document
    continues ``: 1974-03-02`` -- so cutting at the break recovers the real name.
    ``'Margaret\n    Whitfield, who signed...'`` is one name across a soft wrap;
    cutting it there throws the surname away and, because the discarded half is then
    never vaulted, sends it to the provider in the clear.

    Three accepted shapes, in the order they are tested.

    1. The tail is only whitespace -- the span merely ran past the end of its line.
    2. The tail *is* a label by its own shape (:data:`_FIELD_LABEL_TAIL_RE`: no
       lowercase letter, no digit) and a colon follows it. ``DOB:``, ``D.O.B.:``,
       ``MRN #:``.
    3. **The tail is the first words of the NEXT field's label.** Shape alone cannot
       reach this one: ``Date``, ``Social Security`` and ``Phone`` are Title Case,
       which is exactly the shape of a surname, so rule 2 must keep refusing them.
       Position can. The tail qualifies only when all three hold:

       * the span's own line *begins* with a label (``_FIELD_LINE_RE``) whose colon
         is before the span -- the span is a labelled field's VALUE;
       * the tail begins its own line, with nothing but indentation before it;
       * the tail continues, on that line, into a colon -- and the tail is a
         **strict prefix** of that label, i.e. the span cut a multi-word label in
         half. A surname followed by a colon is the *whole* tail, never a prefix of
         a longer one, so ``'Margaret\n    Whitfield: she attests...'`` cannot
         satisfy this however it is punctuated. That is the clause that makes rule 3
         safe rather than merely narrow.

    Measured before shipping rule 3, over every newline-crossing NER span the
    detector produced on 160 documents -- 20 generator seeds x 4 kinds, each read
    both at its native layout and re-wrapped at 62 columns, which is what a real PDF
    or DOCX extraction produces and the shape that made the blanket trim leak.

    1,047 such spans. 922 are a value wrapped mid-run; ground truth is the
    generator's own ledger of planted person names, so "the tail carries a planted
    name word" is a fact about the fixture rather than a judgement about the text.
    Rules 1 and 2 trim 99 of the other 125 and **0** of the 922. Rule 3 trims 12
    more -- every remaining NAME that ran into a multi-word label -- and still **0**
    of the 922, so the disclosure direction is unchanged and measured, not argued.
    The 14 left over are two shapes, both correctly declined: place and organisation
    names wrapped mid-value that the person-name ledger does not list, and a
    Title-Case label that is complete rather than cut in half, which is the case the
    strict-prefix clause refuses on purpose because a surname looks exactly like it.

    Independently, over the same corpus at its native layout, the number of
    detections whose text contains a line break went from 8 to 2, and the number of
    planted name words left uncovered by any detection did not move (110).
    """
    tail = text[newline:end].strip()
    if not tail:
        return True
    if _FIELD_LABEL_TAIL_RE.fullmatch(tail) is not None:
        # The colon lives just past the span -- it is what makes the tail a label
        # rather than a capitalised word that happens to follow a wrap.
        if text[end : end + 2].lstrip().startswith(":"):
            return True
    line_start = text.rfind("\n", 0, start) + 1
    head = _FIELD_LINE_RE.match(text, line_start)
    if head is None or head.end() > start:
        return False
    if text[newline + 1 : end].lstrip() != tail:
        return False
    line_end = text.find("\n", end)
    rest = text[end : line_end if line_end != -1 else len(text)]
    label = _NEXT_LABEL_RE.match(tail + rest)
    return label is not None and label.end() > len(tail) + 1


class Detector:
    """Registry-driven PII/PHI/legal/financial detection over a document."""

    def __init__(self, registry: EntityRegistry, settings: Settings) -> None:
        self._registry = registry
        self._settings = settings
        self._recognizers: list[EntityRecognizer] = list(build_recognizers(registry))
        self._aliases = registry.presidio_aliases()
        # Entities whose registry action is categorical (strip/redact). These
        # outrank score in overlap resolution -- see resolve_overlaps.
        self._policy_types = frozenset(
            name for name, spec in registry.entities.items() if spec.action is not None
        )
        self._declaration_order = {name: index for index, name in enumerate(registry.entities)}
        # Entities served by a recognizer this package builds, rather than by one of
        # Presidio's. Used twice: Presidio reports these under the registry name so
        # no remapping is needed, and they are the more specific claim when they
        # overlap a built-in hit -- see resolve_overlaps.
        self._custom_names = frozenset(
            name for name, spec in registry.entities.items() if spec.patterns or spec.gazetteer
        )
        # entity_type -> its gazetteer file, for the SAME-TYPE, gazetteer-only merge
        # in ``_merge_gazetteer_run``. Keyed off ``spec.gazetteer`` rather than off a
        # name so a gazetteer entity added by config tomorrow is covered with no code
        # change, and so a ``patterns:`` entity can never enter the merge.
        self._gazetteer_files = {
            name: spec.gazetteer
            for name, spec in registry.entities.items()
            if spec.gazetteer
        }
        self._context_patterns: dict[str, re.Pattern[str] | None] = {
            name: (
                re.compile(
                    r"\b(?:" + "|".join(re.escape(word) for word in spec.context) + r")\b",
                    re.IGNORECASE,
                )
                if spec.context
                else None
            )
            for name, spec in registry.entities.items()
        }
        self._entity_cache: dict[str | None, tuple[str, ...]] = {}

    # -- analyzer ----------------------------------------------------------
    @property
    def analyzer(self) -> AnalyzerEngine:
        """The shared process-wide engine. Identical across ``Detector`` instances."""
        return get_analyzer(self._settings.spacy_model)

    # -- public API --------------------------------------------------------
    async def detect(self, text: str, doc_category: str | None = None) -> list[Detection]:
        """Detect every registry entity allowed in ``doc_category``.

        Offsets on the returned detections are absolute into ``text``. Output is
        sorted by start and strictly non-overlapping. Everything below the redact
        floor is dropped here; the engine decides obfuscate-vs-redact from ``score``.
        """
        if not text.strip():
            return []

        started = time.perf_counter()
        entities = self._entities_for(doc_category)
        if not entities:
            return []

        chunks = chunk_text(text, self._settings.chunk_max_chars)
        semaphore = asyncio.Semaphore(self._settings.detect_concurrency)

        # Capped at one chunk so the overlap can never analyse more than the document
        # twice over, however small ``chunk_max_chars`` is configured.
        overlap = min(CHUNK_OVERLAP_CHARS, self._settings.chunk_max_chars)

        # A deadline on STARTING a chunk, checked after the semaphore is acquired --
        # which is the last instant before work would begin, and therefore the only
        # place the check bounds anything. Checked before acquiring instead, a chunk
        # could sit in the queue past the deadline and then start anyway.
        #
        # What this buys, stated exactly, because the obvious stronger claim is false:
        # no chunk STARTS after the deadline, so the wall clock is bounded by
        # ``detect_timeout_s`` plus the duration of the chunks already running --
        # at most ``detect_concurrency`` of them, each capped by ``chunk_max_chars``.
        # It is NOT "detect returns within detect_timeout_s", and it cannot be:
        # ``asyncio.to_thread`` hands the work to a thread, and Python threads are not
        # cancellable. An ``asyncio.timeout`` around the gather below would have read
        # like the stronger claim while delivering less than this one -- the caller
        # would be freed and the CPU would keep burning, with the orphaned threads
        # holding pool slots so later requests queued behind work nobody awaited.
        #
        # Measured for scale: the largest shipped fixture (12,062 words) detects in
        # 2,816 ms against a 30 s deadline, so this fires on pathological input and
        # contention rather than in the normal case.
        deadline = time.perf_counter() + self._settings.detect_timeout_s

        async def analyse(index: int, offset: int, body: str) -> list[Any]:
            # Widened past the chunk's own end so an entity straddling the boundary
            # is seen whole; offsets stay relative to ``offset`` either way.
            window = text[offset : offset + len(body) + overlap]
            async with semaphore:
                if time.perf_counter() > deadline:
                    raise DetectionError(chunk_index=index, reason="detect_deadline")
                try:
                    return await asyncio.to_thread(self._analyze_sync, window, entities)
                except Exception as exc:
                    logger.error(
                        "detect_chunk_failed chunk=%d chars=%d error=%s",
                        index,
                        len(window),
                        type(exc).__name__,
                    )
                    raise DetectionError(
                        chunk_index=index, reason=type(exc).__name__[:64]
                    ) from exc

        per_chunk = await asyncio.gather(
            *(analyse(index, offset, body) for index, (offset, body) in enumerate(chunks))
        )

        candidates: list[Detection] = []
        for (offset, _body), results in zip(chunks, per_chunk, strict=True):
            for result in results:
                detection = self._to_detection(result, text, offset, doc_category)
                if detection is not None:
                    merged = self._merge_gazetteer_run(text, detection)
                    candidates.extend(self._split_composite_dates(text, merged))

        kept = resolve_overlaps(text, candidates, self._policy_types, self._custom_names)
        _verify_offsets(text, kept)

        logger.debug(
            "detect_done chars=%d chunks=%d candidates=%d kept=%d elapsed_ms=%.1f",
            len(text),
            len(chunks),
            len(candidates),
            len(kept),
            (time.perf_counter() - started) * 1000.0,
        )
        return kept

    # -- internals ---------------------------------------------------------
    def _analyze_sync(self, body: str, entities: tuple[str, ...]) -> list[Any]:
        """Runs on a worker thread -- never on the event loop (section 16).

        The single choke point both callers of the detector go through: ``detect``
        here and ``EgressGate`` pass 2, which re-enters by calling ``detect`` again.
        Collapsing degenerate runs here therefore covers both, and covers every
        chunk, without either of them knowing about it. Offsets returned are relative
        to ``body``, exactly as they were before the collapse existed.
        """
        normalized, breaks = _collapse_degenerate_runs(body)
        results: list[Any] = self.analyzer.analyze(
            text=normalized,
            language=LANGUAGE,
            entities=list(entities),
            ad_hoc_recognizers=self._recognizers,
        )
        if breaks:
            for result in results:
                result.start = _restore_offset(breaks, result.start)
                result.end = _restore_offset(breaks, result.end)
        return results

    def _entities_for(self, doc_category: str | None) -> tuple[str, ...]:
        """Recognizer selectors for this document: built-in names plus registry names.

        Restricting the request is how ``only_in_doc_categories`` is enforced at the
        recognizer level -- ``AMOUNT``'s recognizer is never even run outside a
        financial document -- and it keeps irrelevant built-ins off the hot path.
        """
        cached = self._entity_cache.get(doc_category)
        if cached is not None:
            return cached

        requested: list[str] = []
        for name in self._registry.types_for_doc(doc_category):
            spec = self._registry.spec(name)
            if spec.presidio and spec.presidio not in requested:
                requested.append(spec.presidio)
            if name in self._custom_names and name not in requested:
                requested.append(name)

        resolved = tuple(requested)
        self._entity_cache[doc_category] = resolved
        return resolved

    def _has_context(
        self, spec: EntitySpec, text: str, end: int, window_start: int
    ) -> bool:
        """True when one of ``spec.context`` occurs on a word boundary near the span.

        ``window_start`` is where the backward window begins; the caller chooses it,
        because the same span is scored under two of them -- see ``_resolve_builtin``.
        """
        pattern = self._context_patterns.get(spec.name)
        if pattern is None:
            return False
        window = text[window_start : end + CONTEXT_WINDOW_AFTER]
        return pattern.search(window) is not None

    def _claimant_in_window(
        self,
        claimants: tuple[str, ...],
        text: str,
        end: int,
        doc_category: str | None,
        window_start: int,
    ) -> str | None:
        """Best claimant for a built-in hit, scored with one particular window."""
        best: str | None = None
        best_key: tuple[int, int] | None = None
        for name in claimants:
            spec = self._registry.spec(name)
            if not spec.allowed_in(doc_category):
                continue
            has_context = self._has_context(spec, text, end, window_start)
            if spec.requires_context and not has_context:
                continue
            score = (2 if has_context else 0) + (1 if spec.only_in_doc_categories else 0)
            key = (-score, self._declaration_order[name])
            if best_key is None or key < best_key:
                best, best_key = name, key
        return best

    def _resolve_builtin(
        self, builtin: str, text: str, start: int, end: int, doc_category: str | None
    ) -> str | None:
        """Pick the registry entity that owns a Presidio built-in hit.

        Several registry entities may claim the same built-in (``PERSON`` ->
        ``NAME`` or ``CLIENT_IDENTITY``; ``DATE_TIME`` -> ``DOB`` or ``DATE``).
        Candidates are filtered by document category and by ``requires_context``,
        then scored: +2 for a context-word hit, +1 for being scoped to a document
        category (a scoped entity is the more specific claim). Highest score wins,
        ties break on registry declaration order. No survivor means the hit is not
        something this registry cares about, and it is dropped.

        **The label clamp may re-type a hit; it may never zero it.** Scoring runs
        twice. First with the clamped window (:func:`_context_window_start`), which
        is what stops a chart header's one ``DOB:`` from claiming the ``Admitted:``
        date three fields along. If that leaves no survivor at all, it runs again
        with the plain ``CONTEXT_WINDOW_BEFORE`` lookback and that answer stands.

        Without the second pass the clamp is a disclosure, not a refinement. Outside
        a medical document DOB is the ONLY claimant of ``DATE_TIME`` -- ``DATE``
        carries ``only_in_doc_categories: [medical]`` -- and DOB is
        ``requires_context: true``, so a clamp that cuts the birth word out of the
        window drops the date entirely: never detected, never vaulted, and pass 2
        re-runs this same blind detector, so the real date of birth reaches the
        provider in the clear. ``"Date of birth\\nReported: 01/17/1977"`` is that
        document. Falling back cannot lose a hit the unclamped window kept, because
        the fallback window *is* the unclamped one and it is consulted exactly when
        the clamped pass returned nothing.
        """
        claimants = self._aliases.get(builtin)
        if not claimants:
            return None

        clamped = _context_window_start(text, start)
        resolved = self._claimant_in_window(claimants, text, end, doc_category, clamped)
        if resolved is not None:
            return resolved

        floor = max(0, start - CONTEXT_WINDOW_BEFORE)
        if floor == clamped:
            return None
        return self._claimant_in_window(claimants, text, end, doc_category, floor)

    def _to_detection(
        self, result: Any, text: str, offset: int, doc_category: str | None
    ) -> Detection | None:
        start = offset + result.start
        end = offset + result.end
        if start < 0 or end > len(text) or start >= end:
            logger.warning(
                "detection_offsets_out_of_range entity_type=%s start=%d end=%d",
                result.entity_type,
                start,
                end,
            )
            return None

        raw_type = str(result.entity_type)
        if raw_type in self._custom_names:
            entity_type: str | None = raw_type
        else:
            entity_type = self._resolve_builtin(raw_type, text, start, end, doc_category)
        if entity_type is None:
            return None

        spec = self._registry.spec(entity_type)
        if not spec.allowed_in(doc_category):
            return None

        # A temporal value only functions as an IDENTIFIER when it carries a numeral.
        # Presidio's DATE_TIME recogniser also fires on relative expressions -- "daily",
        # "overnight", "the last twelve hours" -- which are ordinary prose, not
        # identifiers. Vaulting those poisons the egress gate's originals set: once
        # "daily" is a known original, every payload containing the word blocks.
        # Registry-driven so it stays config-only (see entities.yaml -> require_digit).
        if spec.require_digit and not any(ch.isdigit() for ch in text[start:end]):
            return None

        # An NER-derived span never crosses a line break. spaCy runs a PERSON past
        # the end of its line and into the next field's LABEL -- on
        # `fixtures/medical_note.txt`, the demo's primary fixture, it returns
        # `'David Ochoa\n    DOB'` as one NAME. Three things follow, and the third is
        # the one that matters:
        #
        #   1. the splice collapses two lines, so the payload reads
        #      `Patient name: [PII_NAME_...]: [PII_DOB_...]` and the DOB label is
        #      destroyed -- a reviewer meets this in the first thirty seconds;
        #   2. the vaulted original becomes `'David Ochoa\n    DOB'`, so the bare
        #      name is *never* an original and the egress gate has no needle for the
        #      patient's own full name;
        #   3. the next field's label is masked as part of the person's identity,
        #      which is wrong in the direction that looks right.
        #
        # Scoped to `presidio:`-backed entities, and the scope is load-bearing rather
        # than cautious. Pattern-backed entities include the sentence-tail
        # recognisers -- `CASE_STRATEGY`, `SETTLEMENT_TERM`, `LAB_RESULT` -- which
        # are *required* to span a hard wrap: every document reaching the detector
        # has been through `extraction.py` and arrives hard-wrapped, which is the
        # whole subject of Deviation 32. Trimming those at the first newline cut
        # `action: redact` back to the first line of its own strategy sentence and
        # shipped the rest, and five recall tests said so.
        #
        # Those five tests no longer say so, and the comment claimed they did for
        # longer than it was true. They caught the BLANKET trim; once the trim was
        # narrowed to `_is_field_label_tail` a strategy sentence stopped satisfying
        # the condition anyway, so deleting `spec.presidio` here left the whole suite
        # green while `'attorney work\nPRODUCT:'` -- an `action: strip` privilege
        # assertion whose tail is a shape rule 2 accepts -- was truncated to
        # `'attorney work'` and `PRODUCT:` went out on the wire. The scope is now
        # pinned directly, by
        # `test_a_pattern_backed_span_is_never_trimmed_at_a_label_shaped_wrap`.
        #
        # **And the newline alone is not the condition.** Trimming every NER span at
        # its first line break was the first attempt and it LEAKED, for the mirror
        # of the reason pattern spans must not be trimmed: the same wrapping that
        # makes a strategy sentence cross a line makes a *name* cross one. spaCy
        # returns `'Margaret\n    Whitfield'` as one PERSON; blanket-trimming vaulted
        # only `Margaret` and sent the surname to the provider verbatim, with the
        # gate silent because it had no needle for a value nobody vaulted. Measured
        # on `legal_brief_large.txt` re-wrapped at 62 columns -- what a real PDF or
        # DOCX extraction produces -- 14 verbatim surname occurrences of 8 clients
        # reached the outbound payload. The shipped copy of that fixture is
        # *unwrapped* (mean line 527 chars), which is exactly why the suite could not
        # see it.
        #
        # So the trim fires only where the tail after the line break is a FIELD
        # LABEL rather than more of the value -- three shapes, all of them and the
        # measurement behind them in `_is_field_label_tail`. A tail that continues
        # the value (`Whitfield, who signed...`) is kept, and the whole wrapped span
        # is vaulted and spliced as one.
        if spec.presidio:
            newline = text.find("\n", start, end)
            if newline != -1 and _is_field_label_tail(text, start, newline, end):
                end = newline
            end = start + len(text[start:end].rstrip())
            if start >= end:
                return None

        score = float(result.score)
        if score < self._floor_for(entity_type):
            return None

        return Detection(
            entity_type=entity_type,
            category=spec.category,
            start=start,
            end=end,
            text=text[start:end],
            score=score,
        )

    def _merge_gazetteer_run(self, text: str, detection: Detection) -> Detection:
        """``detection``, widened to cover every gazetteer term that OVERLAPS it.

        The rule, exactly, because a merge rule that is loose is a rule that vaults
        text which is not a value:

        * **Same entity type only, and only a gazetteer-backed one.** The terms
          consulted are the ones from *this* entity's own gazetteer file
          (``self._gazetteer_files``), so a ``DIAGNOSIS`` can only ever absorb
          diagnosis text. Nothing merges unrelated entities into a super-span --
          that job belongs to :func:`resolve_overlaps`, which unions overlapping
          spans of any type *after* they are all found, and which cannot help here
          because the span this recovers is one Presidio never emitted.
        * **Overlapping, not adjacent.** The absorbed term must share at least one
          character with the span. See below.
        * **Rightward only**, and see below for why that is complete rather than
          half a rule.
        * **Bounded** by :data:`GAZETTEER_MERGE_MAX_STEPS`.

        Every character of the result therefore lies inside some curated clinical
        term, so "merging swallowed a sentence" is not a bad outcome this rule can
        reach: it would take a gazetteer whose terms chain across the sentence.

        **Why the merge is needed at all.** Presidio compiles a deny-list into one
        alternation and searches it, so matching is leftmost-first and
        non-overlapping. ``diagnoses.txt`` ships ``type 2 diabetes`` and ``diabetes
        mellitus`` but not the compound, and on

            "Primary Diagnosis: Type 2 diabetes mellitus, stable."

        the scan matches ``Type 2 diabetes`` at 19 and resumes at 34, so ``diabetes
        mellitus`` -- which starts at 26, *inside* the first match -- is never tried.
        The payload went out as ``Primary Diagnosis: [PHI_DIAGNOSIS_815d497e]
        mellitus``. ``gazetteer_terms``' longest-first ordering does not reach this:
        it resolves two terms starting at the SAME offset, and these start at
        different ones. Neither does the egress gate, structurally -- pass 1 scans
        for whole vaulted originals, the vaulted original is ``Type 2 diabetes``,
        and that string does not contain ``mellitus``. The run reported
        ``egress_rescan_warnings=0`` and outcome ``ok``.

        **Why rightward extension alone is complete.** A term ``T`` that overlapped
        the span on the LEFT would start before it, at a word start Presidio's scan
        had already passed. Leftmost-first means the scan can only have passed that
        offset by consuming a match that covers it -- i.e. ``T`` overlaps *that*
        earlier hit, and rightward extension from the earlier hit reaches it. Worked
        through: terms ``aa bb``, ``bb cc dd``, ``dd`` over ``"aa bb cc dd"`` give
        Presidio ``[0,5)`` and ``[9,11)``; extending ``[0,5)`` rightward finds ``bb
        cc dd`` at 3 and reaches 11, and :func:`resolve_overlaps` then absorbs the
        second hit. Adding a leftward pass would find nothing and would cost a scan
        per hit.

        **Why overlap and not one-space adjacency.** Zero-gap adjacency cannot occur
        at all -- both terms are word-boundary anchored, so the character between two
        of them is a non-word character. That leaves "separated by a single space",
        and taking it would join two spans that are *both already detected and both
        already vaulted*: it closes no disclosure, and it replaces two true values in
        the vault with one string that is not a value.

        Measured over the four shipped fixtures plus 240 generated documents (60
        seeds x 4 kinds; 244 documents, 610 gazetteer detections): same-type
        detections separated by exactly one space occur **0** times, and all 61
        consecutive same-type pairs within twelve characters of each other are
        separated by ``" and "``. So the looser rule would have fired 0 times on the
        whole corpus.

        The honest companion number is that **this** rule also fires 0 times on that
        corpus -- the compound shape is reachable, as the reproduction above shows,
        but neither gazetteer's overlapping pairs appear in the shipped or generated
        text, so no corpus count separates the two rules. What separates them is what
        each can be wrong ABOUT: every character this rule adds lies inside a curated
        term the span already overlaps, while the space rule would swallow a
        separator and two independently-true values on the first document that writes
        a problem list as ``hypertension hyperlipidemia``. Pairing all 208 diagnosis
        terms and all 170 medication terms gives the whole reachable class: 4
        overlapping pairs, all in ``diagnoses.txt``.

        **Offsets.** ``start`` never moves and ``text`` is re-sliced from the
        document, so the invariant ``text[start:end] == detection.text`` that
        ``_verify_offsets`` enforces holds by construction rather than by arithmetic.
        A term cannot match across a line break -- the terms are literals whose only
        whitespace is a single space -- so the widened span stays on its own line.
        """
        filename = self._gazetteer_files.get(detection.entity_type)
        if filename is None:
            return detection

        end = detection.end
        for _step in range(GAZETTEER_MERGE_MAX_STEPS):
            # Occurrences BEGINNING strictly inside the span: one starting at
            # ``detection.start`` is the span's own term (or a shorter one it
            # contains), and one starting at ``end`` is not an overlap.
            reach = max(
                (
                    occurrence_end
                    for _occurrence_start, occurrence_end in gazetteer_occurrences(
                        filename, text, detection.start + 1, end
                    )
                ),
                default=end,
            )
            if reach <= end:
                break
            end = reach

        if end == detection.end:
            return detection
        logger.debug(
            "gazetteer_run_merged entity_type=%s chars=%d added=%d",
            detection.entity_type,
            end - detection.start,
            end - detection.end,
        )
        return detection.model_copy(
            update={"end": end, "text": text[detection.start : end]}
        )

    def _split_composite_dates(self, text: str, detection: Detection) -> list[Detection]:
        """``[detection]``, or one detection per date when the span is a *list* of them.

        spaCy returns ``03/11/2024, 09/17/2024`` as a **single** ``DATE`` span. Two
        things follow from that, and neither is visible from inside this module:

        1. *Security.* The engine vaults ``detection.text``, so the whole composite
           string -- a string that appears in the document but is not one value --
           becomes one vault original. Both leak scanners in this project ask whether a
           **whole** vaulted original occurs in the outbound payload. Neither asks
           about a fragment, and the pipeline can manufacture one: a different date in
           the same document, shifted by the session's constant delta, can render as a
           verbatim, word-bounded *slice* of that composite. A real patient date then
           travels to the provider inside a string this pipeline invented, with both
           scanners reporting clean and both of them correct by their own definitions.
        2. *Utility.* ``03/11/2024, 09/17/2024`` does not parse as a date, so Tier 2
           degrades the whole span to a plain token and every interval it carried is
           lost -- from a line of ordinary clinical prose ("Prior ambulatory visits:
           ..."), not from anything adversarial. Split, each date gets the session
           shift, and the intervals inside the list survive exactly as the intervals
           between any other pair of dates in the document do.

        The rule for *when* to split is
        :func:`~secure_context_pipeline.daterules.split_composite_date` and is
        deliberately all-or-nothing; see it. What this method owns is scope and
        offsets.

        **Scope** is the registry's temporal tier
        (:data:`~secure_context_pipeline.detection.registry.TIER_TEMPORAL`) and nothing
        else. A span that already parses is untouched -- the splitter refuses it -- and
        so is every non-date entity type: a comma inside a name or an address is part
        of the value, not a list separator, and there is no second reading of it worth
        guessing at. The predicate is the ``tier:`` field rather than an entity name or
        a Presidio built-in, so a temporal entity added by config tomorrow is covered
        with no code change and ``detection/`` still branches on no registry name at
        all -- which
        ``tests/test_detection.py::test_no_entity_name_is_hardcoded_in_detection_code``
        enforces, and which is why the tier constants now live in ``registry.py``.

        Requiring the tier *and* the all-must-parse rule is belt and braces on purpose.
        Either alone would probably do: no non-temporal span in the shipped corpus is a
        list of parseable dates, and no temporal span that is not such a list splits.
        But "probably" is doing the work in both sentences, and the cost of being wrong
        is a detection whose text is not the value the engine thinks it vaulted.

        **Offsets are verified rather than computed and trusted.** ``start`` and
        ``end`` come out of arithmetic on two independent numbers -- the detection's
        own absolute start and an offset relative to its text -- and the engine
        *splices* by whatever this returns while *vaulting* ``detection.text``, so the
        two disagreeing is a value silently swapped for another one. Every emitted
        detection's text is therefore taken by slicing the document, and the slice is
        compared against the substring the splitter actually identified. A mismatch
        raises :class:`DetectionInvariantError` rather than emitting the detection, and
        raises rather than asserts so ``python -O`` cannot remove the check.
        """
        spec = self._registry.get(detection.entity_type)
        if spec is None or spec.tier != TIER_TEMPORAL:
            return [detection]

        parts = split_composite_date(detection.text)
        if not parts:
            return [detection]

        constituents: list[Detection] = []
        for relative_start, relative_end in parts:
            start = detection.start + relative_start
            end = detection.start + relative_end
            expected = detection.text[relative_start:relative_end]
            if text[start:end] != expected:
                raise DetectionInvariantError(
                    reason="composite_split_offset_drift",
                    entity_type=detection.entity_type[:64],
                    start=start,
                    end=end,
                    text_chars=len(text),
                    detection_chars=len(expected),
                )
            constituents.append(
                detection.model_copy(update={"start": start, "end": end, "text": text[start:end]})
            )
        return constituents

    def _floor_for(self, entity_type: str) -> float:
        """Lowest score worth returning for ``entity_type``.

        The redact threshold is the floor: anything between it and the obfuscate
        threshold is still returned, because the engine turns that band into
        ``[REDACTED_<TYPE>]``. A per-entity ``threshold`` override that sits *below*
        the redact floor lowers it -- the registry author asked for that entity to be
        obfuscated at a lower confidence, and dropping it here would silently ignore
        the override.

        **What the floor costs, stated plainly, because the build doc reads two ways
        on it.** Section 9.2 specifies the three bands this implements. Section 2
        bullet 8 says something stronger -- "entities detected below the
        obfuscation-confidence threshold are **redacted**, never passed through raw"
        -- and taken literally that is a floor of zero, since ``threshold_obfuscate``
        is 0.5 and everything under it would have to be redacted. The two cannot both
        hold, and this code implements 9.2. The price is measurable:

            'The ledger reference 412337891 was archived.'
                Presidio US_SSN [21:30] score=0.05      floor(SSN) = 0.3
                detect(general) -> []   detect(financial) -> []

        so a value Presidio *did* type as an SSN reaches the provider verbatim. Two
        spellings behave the same way (``41233-7891``, ``412-337891``); the properly
        formatted ``412-33-7891`` scores 0.85 and is vaulted, and the bare digits
        with a nearby "SSN" score inside the redact band and become
        ``[REDACTED_SSN]``. So the gap is exactly "9-digit-shaped, no supporting
        context", where Presidio's own confidence is 0.05 and the same string is far
        more often an order number or a ledger reference than an SSN.

        **Removing the discard here changes nothing on the wire**, which is worth
        knowing before anyone tries it: ``ObfuscationEngine._classify`` drops the
        same band again ("Below the redact floor the detector should already have
        dropped it"). Measured end to end with this method forced to ``0.0`` -- the
        detector returns ``SSN 412337891 0.05`` and the payload is byte-identical,
        because the engine then discards it. Closing bullet 8 means changing the
        engine's band policy, not this floor, and it means accepting redaction of
        every 9-digit run in every document.
        """
        override = self._registry.threshold_for(entity_type, self._settings.threshold_obfuscate)
        return min(self._settings.threshold_redact, override)
