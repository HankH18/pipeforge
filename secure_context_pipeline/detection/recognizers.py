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
    "gazetteer_terms",
    "load_gazetteer",
    "normalise_term",
    "reset_gazetteer_cache",
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
        term, _, hint = stripped.partition("\t")
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


def class_hint_for(
    registry: EntityRegistry, entity_type: str, matched_text: str
) -> str | None:
    """Class hint for a gazetteer-backed match, for Tier-3 annotated tokens.

    ``[PHI_MEDICATION_2f4a|oral-antidiabetic]`` -- the obfuscation engine calls this
    with the original matched span and gets back the class column only. Returns
    ``None`` for a non-gazetteer entity, an unknown term, or a blank class column.
    """
    spec = registry.get(entity_type)
    if spec is None or not spec.gazetteer:
        return None
    hint = load_gazetteer(spec.gazetteer).get(normalise_term(matched_text))
    return hint or None


def reset_gazetteer_cache() -> None:
    """Drop the parsed-gazetteer cache. Tests only."""
    _GAZETTEER_CACHE.clear()


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
    """A deny-list ``PatternRecognizer`` for a ``gazetteer:`` registry entry."""
    if not spec.gazetteer:
        raise ConfigError(reason="entity_has_no_gazetteer", entity_type=spec.name[:64])
    terms = gazetteer_terms(spec.gazetteer)
    if not terms:
        raise ConfigError(reason="gazetteer_empty", entity_type=spec.name[:64])
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
