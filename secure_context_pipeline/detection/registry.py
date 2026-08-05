"""Entity registry model + loader (build doc section 6.2).

This module is the *only* place that knows what an entity type means. Everything
downstream -- engine, vault, restorer, audit -- treats ``entity_type`` as an
opaque string, which is what makes config-only extensibility real.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

# Presidio's PatternRecognizer does ``import regex as re`` and evaluates every
# ``patterns:`` entry with it. Validating with the standard library's ``re`` would be
# checking a different language than the one that runs -- see ``_compilable``.
import regex  # type: ignore[import-untyped]
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.models import EntityCategory
from secure_context_pipeline.surrogates import validate_entity_type

__all__ = [
    "GAZETTEER_DIR",
    "EntityRegistry",
    "EntitySpec",
    "RegistryAction",
    "load_registry",
]

GAZETTEER_DIR = Path(__file__).resolve().parent / "data"


class RegistryAction(StrEnum):
    """Engine-level policy override for a whole entity type."""

    STRIP = "strip"
    REDACT = "redact"


class EntitySpec(BaseModel):
    """One entry in ``entities.yaml``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    category: EntityCategory
    presidio: str | None = None
    patterns: tuple[str, ...] = ()
    gazetteer: str | None = None
    context: tuple[str, ...] = ()
    requires_context: bool = False
    require_digit: bool = False
    only_in_doc_categories: tuple[str, ...] = ()
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    strategy: str | None = None
    tier: int = Field(default=1, ge=1, le=4)
    hint: bool = False
    action: RegistryAction | None = None

    @field_validator("patterns")
    @classmethod
    def _compilable(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        """Reject at load any pattern the engine that will run it cannot compile.

        Compiled with ``regex``, not ``re``: ``regex`` is what
        ``presidio_analyzer.pattern_recognizer`` imports, so it is what actually
        evaluates every ``patterns:`` entry against document text. The two dialects
        are not the same language -- ``regex`` accepts a variable-width lookbehind,
        ``\\K`` and a possessive quantifier, and ``re`` raises on all three -- and
        validating with the wrong one is the shape of mistake this codebase keeps
        finding: a checker that does not share the semantics of the thing it checks.
        It failed both ways. A pattern only the real engine understands was refused at
        startup though it would have run correctly, and a pattern ``re`` accepts but
        ``regex`` rejects would have passed load and raised inside a request instead.
        """
        for pattern in v:
            try:
                regex.compile(pattern)
            except regex.error as exc:
                raise ValueError(f"uncompilable pattern: {exc}") from exc
        return v

    def allowed_in(self, doc_category: str | None) -> bool:
        """True when this entity may be detected in a document of ``doc_category``."""
        if not self.only_in_doc_categories:
            return True
        return doc_category is not None and doc_category in self.only_in_doc_categories

    @property
    def is_recognizer_backed(self) -> bool:
        return bool(self.presidio or self.patterns or self.gazetteer)


class EntityRegistry(BaseModel):
    model_config = ConfigDict(frozen=True)

    categories: tuple[EntityCategory, ...]
    entities: dict[str, EntitySpec]

    # -- lookups ------------------------------------------------------------
    def spec(self, entity_type: str) -> EntitySpec:
        try:
            return self.entities[entity_type]
        except KeyError as exc:
            raise ConfigError(reason="unknown_entity_type", entity_type=entity_type[:64]) from exc

    def get(self, entity_type: str) -> EntitySpec | None:
        return self.entities.get(entity_type)

    def category_of(self, entity_type: str) -> EntityCategory:
        return self.spec(entity_type).category

    def tier_of(self, entity_type: str) -> int:
        return self.spec(entity_type).tier

    def action_of(self, entity_type: str) -> RegistryAction | None:
        spec = self.get(entity_type)
        return spec.action if spec else None

    def threshold_for(self, entity_type: str, default: float) -> float:
        spec = self.get(entity_type)
        if spec is not None and spec.threshold is not None:
            return spec.threshold
        return default

    # -- grouped views used by recognizers.py --------------------------------
    def presidio_backed(self) -> dict[str, EntitySpec]:
        return {k: v for k, v in self.entities.items() if v.presidio}

    def pattern_backed(self) -> dict[str, EntitySpec]:
        return {k: v for k, v in self.entities.items() if v.patterns}

    def gazetteer_backed(self) -> dict[str, EntitySpec]:
        return {k: v for k, v in self.entities.items() if v.gazetteer}

    def presidio_aliases(self) -> dict[str, tuple[str, ...]]:
        """Presidio built-in name -> the registry entity types that claim it."""
        out: dict[str, list[str]] = {}
        for name, spec in self.entities.items():
            if spec.presidio:
                out.setdefault(spec.presidio, []).append(name)
        return {k: tuple(v) for k, v in out.items()}

    def types_for_doc(self, doc_category: str | None) -> tuple[str, ...]:
        return tuple(n for n, s in self.entities.items() if s.allowed_in(doc_category))


class _StrictLoader(yaml.SafeLoader):
    """``SafeLoader`` that refuses a mapping with a duplicate key.

    YAML's own rule is last-one-wins, so ``yaml.safe_load`` accepts a registry that
    declares ``MRN:`` twice and silently discards the first definition. The file
    loads clean, every test passes, and detection quietly runs with only one of the
    two pattern sets -- the exact "fails at request time instead of at load"
    behaviour this loader exists to prevent. Duplicate entity names are the likely
    result of a merge conflict or a copy-paste edit to ``entities.yaml``, which is
    precisely when silence is most expensive.
    """


def _reject_duplicate_keys(
    loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ConfigError(reason="registry_duplicate_key", entity_type=str(key)[:64])
        seen.add(key)
    mapping: dict[Any, Any] = loader.construct_mapping(node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _reject_duplicate_keys
)


def load_registry(path: str | Path | None = None) -> EntityRegistry:
    """Load and validate ``entities.yaml``.

    Raises :class:`ConfigError` on a missing file, malformed YAML, a duplicate
    entity name, an entity name the surrogate grammar cannot express, an unknown
    category, a reference to a missing gazetteer, or an uncompilable pattern.
    """
    registry_path = Path(path) if path is not None else Path("entities.yaml")
    if not registry_path.is_file():
        raise ConfigError(reason="registry_not_found", path=registry_path.name[:64])

    try:
        raw: Any = yaml.load(
            registry_path.read_text(encoding="utf-8"),
            # _StrictLoader subclasses SafeLoader and adds only the duplicate-key
            # rejection safe_load lacks, so no arbitrary object can be constructed.
            Loader=_StrictLoader,  # noqa: S506
        )
    except yaml.YAMLError as exc:
        raise ConfigError(reason="registry_yaml_invalid") from exc

    if not isinstance(raw, dict):
        raise ConfigError(reason="registry_not_a_mapping")

    raw_categories = raw.get("categories") or [c.value for c in EntityCategory]
    try:
        categories = tuple(EntityCategory(c) for c in raw_categories)
    except ValueError as exc:
        raise ConfigError(reason="registry_unknown_category") from exc

    raw_entities = raw.get("entities")
    if not isinstance(raw_entities, dict) or not raw_entities:
        raise ConfigError(reason="registry_no_entities")

    entities: dict[str, EntitySpec] = {}
    for name, body in raw_entities.items():
        if not isinstance(body, dict):
            raise ConfigError(reason="registry_entity_not_a_mapping", entity_type=str(name)[:64])

        # An entity type is an opaque string to the engine, vault, restorer and audit
        # -- that is what makes config-only extensibility real. It is *not* opaque to
        # the surrogate grammar: ``format_surrogate`` builds
        # ``[{category}_{entity_type}_{token_id}]`` and ``TOKEN_RE`` only matches
        # ``[A-Z][A-Z0-9_]*``. So a perfectly reasonable-looking config addition --
        # ``2FA_CODE`` (leading digit) or ``MedicalId`` (lowercase) -- emits a token
        # that is vaulted and spliced but which the restorer can never match and
        # which never enters the egress gate's skip-list. The value would be
        # obfuscated and then silently never restored.
        #
        # The formatters validate too, but that fires deep inside a request, long
        # after the config was accepted. Startup is the honest place to fail: the
        # extensibility guarantee is only safe to offer if a name that cannot work is
        # rejected when it is introduced.
        validate_entity_type(str(name))

        fields = dict(body)
        for key in ("patterns", "context", "only_in_doc_categories"):
            value = fields.get(key)
            if isinstance(value, str):
                fields[key] = (value,)
            elif isinstance(value, list):
                fields[key] = tuple(value)
        try:
            spec = EntitySpec(name=str(name), **fields)
        except Exception as exc:  # pydantic ValidationError or ValueError
            raise ConfigError(reason="registry_entity_invalid", entity_type=str(name)[:64]) from exc

        if spec.category not in categories:
            raise ConfigError(reason="registry_category_not_declared", entity_type=spec.name[:64])
        if spec.gazetteer and not (GAZETTEER_DIR / spec.gazetteer).is_file():
            raise ConfigError(reason="registry_gazetteer_missing", entity_type=spec.name[:64])
        if not spec.is_recognizer_backed:
            raise ConfigError(reason="registry_entity_has_no_recognizer", entity_type=spec.name[:64])

        entities[spec.name] = spec

    return EntityRegistry(categories=categories, entities=entities)
