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
from collections.abc import Sequence
from typing import Any

from presidio_analyzer import AnalyzerEngine, EntityRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

from secure_context_pipeline.config import Settings
from secure_context_pipeline.daterules import split_composite_date
from secure_context_pipeline.detection.recognizers import build_recognizers
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
CONTEXT_WINDOW_BEFORE = 60
CONTEXT_WINDOW_AFTER = 30

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
#: letters and spaces, immediately followed by a colon in the surrounding text.
#: Bounded, because it is matched against document text.
_FIELD_LABEL_TAIL_RE = re.compile(r"[A-Za-z][A-Za-z ]{0,20}\Z")


def _is_field_label_tail(text: str, newline: int, end: int) -> bool:
    """Whether ``text[newline:end]`` is a wrapped-on field LABEL rather than value.

    The distinction the newline alone cannot make. ``'David Ochoa\n    DOB'`` is a
    name that ran into the next field's label -- the tail is ``DOB`` and the document
    continues ``: 1974-03-02`` -- so cutting at the break recovers the real name.
    ``'Margaret\n    Whitfield, who signed...'`` is one name across a soft wrap;
    cutting it there throws the surname away and, because the discarded half is then
    never vaulted, sends it to the provider in the clear.

    Two accepted shapes: a tail that is only whitespace (the span merely ran past the
    end of its line), and a tail that looks like a label AND is followed by a colon.
    Everything else is treated as part of the value.
    """
    tail = text[newline:end].strip()
    if not tail:
        return True
    if _FIELD_LABEL_TAIL_RE.fullmatch(tail) is None:
        return False
    # The colon lives just past the span -- it is what makes the tail a label rather
    # than a capitalised word that happens to follow a wrap.
    return text[end : end + 2].lstrip().startswith(":")


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

        async def analyse(index: int, offset: int, body: str) -> list[Any]:
            # Widened past the chunk's own end so an entity straddling the boundary
            # is seen whole; offsets stay relative to ``offset`` either way.
            window = text[offset : offset + len(body) + overlap]
            async with semaphore:
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
                    candidates.extend(self._split_composite_dates(text, detection))

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
        """Runs on a worker thread -- never on the event loop (section 16)."""
        results: list[Any] = self.analyzer.analyze(
            text=body,
            language=LANGUAGE,
            entities=list(entities),
            ad_hoc_recognizers=self._recognizers,
        )
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

    def _has_context(self, spec: EntitySpec, text: str, start: int, end: int) -> bool:
        """True when one of ``spec.context`` occurs on a word boundary near the span."""
        pattern = self._context_patterns.get(spec.name)
        if pattern is None:
            return False
        window = text[max(0, start - CONTEXT_WINDOW_BEFORE) : end + CONTEXT_WINDOW_AFTER]
        return pattern.search(window) is not None

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
        """
        claimants = self._aliases.get(builtin)
        if not claimants:
            return None

        best: str | None = None
        best_key: tuple[int, int] | None = None
        for name in claimants:
            spec = self._registry.spec(name)
            if not spec.allowed_in(doc_category):
                continue
            has_context = self._has_context(spec, text, start, end)
            if spec.requires_context and not has_context:
                continue
            score = (2 if has_context else 0) + (1 if spec.only_in_doc_categories else 0)
            key = (-score, self._declaration_order[name])
            if best_key is None or key < best_key:
                best, best_key = name, key
        return best

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
        # So the trim fires only on the shape actually observed in the `David Ochoa`
        # case: the tail after the line break is a FIELD LABEL -- a short run of
        # letters and spaces immediately followed by a colon -- or is nothing but
        # whitespace. A tail that continues the value (`Whitfield, who signed...`) is
        # kept, and the whole wrapped span is vaulted and spliced as one.
        if spec.presidio:
            newline = text.find("\n", start, end)
            if newline != -1 and _is_field_label_tail(text, newline, end):
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
        """
        override = self._registry.threshold_for(entity_type, self._settings.threshold_obfuscate)
        return min(self._settings.threshold_redact, override)
