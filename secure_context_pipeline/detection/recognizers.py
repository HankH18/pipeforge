"""Translate the entity registry into Presidio recognizers (build doc sections 6.2, 9.2, 12).

Three kinds of registry entry produce three different outcomes here:

``patterns``
    One :class:`~presidio_analyzer.PatternRecognizer` per entity, one
    :class:`~presidio_analyzer.Pattern` per regex, ``supported_entity`` set to the
    *registry* name (``MRN``, not some Presidio built-in). The registry's
    ``context`` words are attached so Presidio's context enhancer can boost them.

``gazetteer``
    A deny-list ``PatternRecognizer`` built from the TSV terms in
    ``detection/data/``. Presidio compiles a deny-list into a single alternation
    regex with ``\\W`` lookarounds, so matches are word-boundary safe; matching is
    case-insensitive by design (clinical vocabulary is written every which way).

``presidio``
    Nothing is built. Those entities ride Presidio's built-in recognizers and are
    remapped onto registry names by :mod:`secure_context_pipeline.detection.detector`.

Two performance rules from build doc section 12 are enforced here rather than left
to chance: every regex is compiled and every gazetteer alternation is built **once**,
at recognizer-construction time. That also removes a latent data race -- Presidio
compiles a ``Pattern`` lazily inside ``analyze()``, and chunks are analysed from
four worker threads.

Nothing in this module logs or raises matched text. The gazetteer files hold only
generic clinical vocabulary, but a *match* is an original value (build doc section 16).
"""

from __future__ import annotations

import logging
import re

from presidio_analyzer import Pattern, PatternRecognizer

from secure_context_pipeline.detection.registry import (
    GAZETTEER_DIR,
    EntityRegistry,
    EntitySpec,
)
from secure_context_pipeline.errors import ConfigError

__all__ = [
    "GAZETTEER_FLAGS",
    "GAZETTEER_SCORE",
    "PATTERN_FLAGS",
    "PATTERN_SCORE",
    "build_gazetteer_recognizer",
    "build_pattern_recognizer",
    "build_recognizers",
    "class_hint_for",
    "gazetteer_occurrences",
    "gazetteer_terms",
    "load_gazetteer",
    "normalise_term",
]

logger = logging.getLogger(__name__)

# Base confidence for a hand-written registry regex. High enough to clear
# SCP_THRESHOLD_OBFUSCATE on its own; context words lift it the rest of the way.
PATTERN_SCORE = 0.7

# An exact match against a curated clinical term list is a stronger signal than a
# shape-based regex, so gazetteer hits start higher.
GAZETTEER_SCORE = 0.8

# Case sensitivity is a property of each registry regex and must be preserved:
# INSURANCE_ID's ``[A-Z]{2,4}`` means uppercase, CASE_ID's ``[a-z]{2}`` means
# lowercase, and PRIVILEGED_MARKER opts into case folding with a leading ``(?i)``.
# Presidio's default global flags include IGNORECASE, which would silently erase
# that distinction and turn ``[A-Z]{2,4}\\d{7,12}`` into a match for any four
# letters, so pattern recognizers get DOTALL|MULTILINE only.
PATTERN_FLAGS = re.DOTALL | re.MULTILINE

# Gazetteer terms are stored casefolded and matched case-insensitively.
GAZETTEER_FLAGS = re.DOTALL | re.MULTILINE | re.IGNORECASE

_COMMENT_PREFIX = "#"

# A single space is enough to force Presidio to compile every pattern it owns.
_WARMUP_TEXT = " "

# filename -> {normalised term: class_hint}. Parsed once per process.
_GAZETTEER_CACHE: dict[str, dict[str, str]] = {}

# filename -> the anchored alternation used by ``gazetteer_occurrences``. Built once
# per process for the same reason the recognizers are: 208 diagnosis alternatives
# recompiled per call would be paid once per gazetteer hit per document.
_GAZETTEER_MATCHER_CACHE: dict[str, re.Pattern[str]] = {}

#: The first character of a word. Every gazetteer term begins with one -- the
#: deny-list's ``(?:^|(?<=\W))`` prefix says so -- so these are the only offsets
#: ``gazetteer_occurrences`` has to try, which is what keeps an overlap-aware scan
#: proportional to the word count rather than to the character count.
_WORD_START_RE = re.compile(r"\b\w")


def normalise_term(term: str) -> str:
    """Canonical gazetteer key: whitespace-collapsed and casefolded."""
    return " ".join(term.split()).casefold()


def load_gazetteer(filename: str) -> dict[str, str]:
    """Parse ``detection/data/<filename>`` into ``normalised term -> class_hint``.

    The file is TSV (``term<TAB>class_hint``); ``#`` lines and blank lines are
    ignored. Results are cached module-level, so the file is read once per process
    no matter how many recognizers or lookups ask for it.
    """
    cached = _GAZETTEER_CACHE.get(filename)
    if cached is not None:
        return cached

    path = GAZETTEER_DIR / filename
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(reason="gazetteer_unreadable", gazetteer=filename[:64]) from exc

    table: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIX):
            continue
        # Partitioned on the RAW line, not on `stripped`. The guard below exists to
        # reject a line whose TERM is empty -- `"\toral-antidiabetic"`, a hint with
        # no term, which is what a mis-edited TSV row looks like -- and partitioning
        # the stripped line defeated it: `.strip()` eats the leading tab, so the
        # HINT was promoted to the term position and silently registered as a
        # detection term. `oral-antidiabetic` would have become a MEDICATION the
        # detector matches on. The guard was not dead code to delete; it was a live
        # guard the line above it had disarmed.
        #
        # Latent rather than live on the shipped files -- both gazetteers have zero
        # leading-tab lines -- but it is the same fail-open-on-a-config-typo class
        # as the `only_in_doc_categories` defect, and a gazetteer is exactly the
        # kind of file that gets hand-edited.
        term, _, hint = line.partition("\t")
        key = normalise_term(term)
        if not key:
            continue
        table[key] = hint.strip()

    logger.debug("gazetteer_loaded file=%s terms=%d", filename, len(table))
    _GAZETTEER_CACHE[filename] = table
    return table


def gazetteer_terms(filename: str) -> list[str]:
    """Deny-list terms, longest first.

    Presidio joins a deny-list into one alternation and alternation is
    leftmost-first, so ordering by descending length keeps ``type 2 diabetes``
    from being clipped to a shorter competing entry that starts at the same offset.
    """
    return sorted(load_gazetteer(filename), key=lambda term: (-len(term), term))


def _gazetteer_matcher(filename: str) -> re.Pattern[str]:
    """An ANCHORED copy of the deny-list alternation Presidio builds for ``filename``.

    Byte-for-byte the same boundary conditions as
    ``PatternRecognizer._deny_list_to_regex`` -- ``(?:^|(?<=\\W))`` in front,
    ``(?:(?=\\W)|$)`` behind, the same ``re.escape`` per term, the same
    :data:`GAZETTEER_FLAGS` -- and the same longest-first term order, so the
    alternative this returns at a given offset is the alternative Presidio's
    recognizer would return there. Copying the boundary spelling rather than
    inventing one is the point: a matcher with *different* boundaries would report
    occurrences the recognizer cannot produce, and the detector's merge would then
    widen a span over text no gazetteer hit covers.

    Anchored rather than searched because the caller supplies the offsets. Presidio
    searches, and a search is leftmost-first and non-overlapping -- which is exactly
    the property :func:`gazetteer_occurrences` exists to work around.
    """
    cached = _GAZETTEER_MATCHER_CACHE.get(filename)
    if cached is not None:
        return cached
    terms = gazetteer_terms(filename)
    if not terms:
        raise ConfigError(reason="gazetteer_empty", gazetteer=filename[:64])
    compiled = re.compile(
        r"(?:^|(?<=\W))(?:" + "|".join(re.escape(term) for term in terms) + r")(?:(?=\W)|$)",
        GAZETTEER_FLAGS,
    )
    _GAZETTEER_MATCHER_CACHE[filename] = compiled
    return compiled


def gazetteer_occurrences(
    filename: str, text: str, start: int = 0, end: int | None = None
) -> list[tuple[int, int]]:
    """``(start, end)`` for every term of ``filename`` BEGINNING in ``text[start:end]``.

    Overlap-aware, which is the whole reason this exists next to the recognizer that
    already matches the same terms. Presidio compiles a deny-list into one
    alternation and *searches* it, and a search is leftmost-first and
    non-overlapping: after ``type 2 diabetes`` matches at offset 19 the scan resumes
    at 34, so ``diabetes mellitus`` -- which starts at 26, inside the first match --
    is never tried. This tries every word start independently, so both are reported.

    Ends are not clamped to ``end``: a term that BEGINS inside the window and runs
    past it is precisely the occurrence a caller extending a span is looking for.

    One occurrence per word start, the longest, because the alternation is ordered
    longest-first. That loses nothing a caller here needs -- a shorter term at the
    same offset is contained in the longer one, so it can neither widen a span nor
    contribute a class the longer term does not already carry.

    Cost is one anchored match attempt per word in the window. Measured over all
    four shipped fixtures (91,935 characters) against BOTH gazetteers: 29,740
    attempts, 57.2 ms in total, against 2,825 ms for a single ``Detector.detect``
    pass over the largest fixture alone. That is the ceiling and not the bill --
    callers in this package scan only the inside of a gazetteer hit, at most a
    handful of words each.
    """
    matcher = _gazetteer_matcher(filename)
    limit = len(text) if end is None else min(end, len(text))
    found: list[tuple[int, int]] = []
    for word in _WORD_START_RE.finditer(text, max(start, 0), limit):
        hit = matcher.match(text, word.start())
        if hit is not None:
            found.append((hit.start(), hit.end()))
    return found


def class_hint_for(
    registry: EntityRegistry, entity_type: str, matched_text: str
) -> str | None:
    """Class hint for a gazetteer-backed match, for Tier-3 annotated tokens.

    ``[PHI_MEDICATION_2f4a|oral-antidiabetic]`` -- the obfuscation engine calls this
    with the original matched span and gets back the class column only. Returns
    ``None`` for a non-gazetteer entity, an unknown term, or a blank class column.

    **A merged span is not a term, and dropping its hint would be a silent utility
    regression.** ``Detector._merge_gazetteer_run`` widens ``Type 2 diabetes`` to
    ``Type 2 diabetes mellitus`` so the tail cannot be stranded in the clear; that
    string is not a row in ``diagnoses.txt``, so the exact lookup misses and the
    Tier-3 token would fall back from ``[PHI_DIAGNOSIS_815d497e|endocrine-metabolic]``
    to a bare ``[PHI_DIAGNOSIS_815d497e]``. The class is what the LLM reasons with,
    so closing a leak by deleting clinical signal is only half a fix.

    So an unmatched span falls back to the terms it CONTAINS -- and only when they
    agree. ``type 2 diabetes`` and ``diabetes mellitus`` are both
    ``endocrine-metabolic``, so the merged span keeps that class as a fact rather
    than a guess. Where the constituents disagree the fallback declines: the only
    disagreeing pair the shipped gazetteers admit is ``overactive bladder``
    (``renal``) with ``bladder cancer`` (``oncologic``), and emitting either one for
    ``overactive bladder cancer`` would tell the model something false about the
    patient. Measured over both files, all 208 diagnoses and 170 medications: 4
    term pairs can overlap at all, 3 agree on their class and 1 does not.

    The containment test is the word-boundary one (:func:`gazetteer_occurrences`),
    not a substring test, which is what keeps ``metforminol`` -- a term that merely
    *contains* ``metformin`` -- returning ``None`` as it always has.
    """
    spec = registry.get(entity_type)
    if spec is None or not spec.gazetteer:
        return None
    table = load_gazetteer(spec.gazetteer)
    normalised = normalise_term(matched_text)
    hint = table.get(normalised)
    if hint is not None:
        return hint or None
    hints = {
        table.get(normalise_term(normalised[start:end]), "")
        for start, end in gazetteer_occurrences(spec.gazetteer, normalised)
    }
    if len(hints) != 1:
        return None
    return hints.pop() or None


def _precompile(recognizer: PatternRecognizer) -> None:
    """Force Presidio to compile every pattern now rather than mid-request.

    ``PatternRecognizer`` compiles lazily on first ``analyze`` and caches the result
    on the ``Pattern`` object. Doing it here means the compile cost is paid at
    startup and the ``Pattern`` objects are read-only by the time four detection
    threads share them.
    """
    recognizer.analyze(text=_WARMUP_TEXT, entities=list(recognizer.supported_entities))


def build_pattern_recognizer(spec: EntitySpec) -> PatternRecognizer:
    """A ``PatternRecognizer`` for a ``patterns:`` registry entry."""
    if not spec.patterns:
        raise ConfigError(reason="entity_has_no_patterns", entity_type=spec.name[:64])
    patterns = [
        Pattern(name=f"{spec.name}_{index}", regex=expression, score=PATTERN_SCORE)
        for index, expression in enumerate(spec.patterns)
    ]
    recognizer = PatternRecognizer(
        supported_entity=spec.name,
        name=f"{spec.name}PatternRecognizer",
        patterns=patterns,
        context=list(spec.context),
        global_regex_flags=PATTERN_FLAGS,
    )
    _precompile(recognizer)
    return recognizer


def build_gazetteer_recognizer(spec: EntitySpec) -> PatternRecognizer:
    """A deny-list ``PatternRecognizer`` for a ``gazetteer:`` registry entry.

    The anchored twin used by :func:`gazetteer_occurrences` is built here too, and
    for the reason in this module's header rather than for tidiness: both regexes
    are compiled ONCE, at construction, so no request pays the compile and no two
    threads race to populate the same cache entry mid-detection.
    """
    if not spec.gazetteer:
        raise ConfigError(reason="entity_has_no_gazetteer", entity_type=spec.name[:64])
    terms = gazetteer_terms(spec.gazetteer)
    if not terms:
        raise ConfigError(reason="gazetteer_empty", entity_type=spec.name[:64])
    _gazetteer_matcher(spec.gazetteer)
    recognizer = PatternRecognizer(
        supported_entity=spec.name,
        name=f"{spec.name}GazetteerRecognizer",
        deny_list=terms,
        deny_list_score=GAZETTEER_SCORE,
        context=list(spec.context),
        global_regex_flags=GAZETTEER_FLAGS,
    )
    _precompile(recognizer)
    return recognizer


def build_recognizers(registry: EntityRegistry) -> list[PatternRecognizer]:
    """Every custom recognizer the registry asks for, in declaration order.

    ``presidio:``-backed entities are deliberately absent: they are served by
    Presidio's built-in recognizers and remapped in the detector.
    """
    recognizers: list[PatternRecognizer] = []
    for spec in registry.entities.values():
        if spec.patterns:
            recognizers.append(build_pattern_recognizer(spec))
        if spec.gazetteer:
            recognizers.append(build_gazetteer_recognizer(spec))
    logger.debug("recognizers_built count=%d", len(recognizers))
    return recognizers
