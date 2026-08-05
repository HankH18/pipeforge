"""Obfuscation strategy ABC + the config-selected registry (build doc section 9.3).

A strategy answers exactly one question: *given a detected span and the token ID
the engine derived for it, what string goes into the outbound payload?* It does
not decide **whether** a span is obfuscated, redacted or stripped -- that is
engine policy, and it must behave identically under every strategy (build doc
section 9.3, engine step 4). Keeping that split is what makes a new strategy a
drop-in: it can only change what a surrogate looks like, never what the pipeline
protects.

Adding a strategy is **one class plus one registry entry, with zero engine
changes**::

    @register_strategy
    class MyStrategy(ObfuscationStrategy):
        name = "mine"
        async def make_surrogate(self, detection, token_id, vault, *, session_id):
            return self.plain_token(detection, token_id)

``tests/test_obfuscation.py::test_dummy_strategy_plugs_in_with_zero_engine_changes``
asserts exactly that.

Deviation from the build doc's ABC signature (documented as required)
---------------------------------------------------------------------
The doc writes ``make_surrogate(self, detection, token_id, vault)``. This adds a
keyword-only ``session_id``: :class:`~secure_context_pipeline.vault.session_vault.SessionVault`
is a *multi-session* object -- every one of its accessors takes the session ID --
so a strategy that needs the vault (the Tier-1 collision guard checks the fake
against this session's originals and issued surrogates) cannot use it without
one. The alternative, binding a vault handle per session, would mean allocating a
wrapper object per request on the hot path to avoid passing a string.

Construction is uniform: every strategy takes a single :class:`StrategyContext`,
so :func:`build_strategy` can instantiate a class it has never seen. The context
carries the session key, which is why it never renders itself in a repr.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib import import_module
from typing import TYPE_CHECKING, ClassVar, TypeVar, cast

from secure_context_pipeline.config import Settings
from secure_context_pipeline.detection.registry import EntityRegistry
from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.models import Detection
from secure_context_pipeline.surrogates import format_surrogate

if TYPE_CHECKING:  # pragma: no cover -- import cycle avoidance only
    from secure_context_pipeline.vault.session_vault import SessionVault

logger = logging.getLogger(__name__)

__all__ = [
    "HINT_LOOKUP_OPTION",
    "STRATEGIES",
    "HintLookup",
    "ObfuscationStrategy",
    "StrategyContext",
    "available_strategies",
    "build_strategy",
    "register_strategy",
    "resolve_hint_lookup",
]

#: ``StrategyContext.options`` key overriding the gazetteer hint lookup. Exists
#: so a caller (or a test) can supply the class-hint source without importing
#: the detection package -- see :func:`resolve_hint_lookup`.
HINT_LOOKUP_OPTION = "hint_lookup"

#: Signature of ``detection.recognizers.class_hint_for``.
HintLookup = Callable[[EntityRegistry, str, str], str | None]


@dataclass(frozen=True, slots=True, repr=False)
class StrategyContext:
    """Everything a strategy may need, in one uniform constructor argument.

    ``session_key`` is the live session key. It is never rendered by ``__repr__``
    and never logged; it exists here so strategies can derive Faker seeds and the
    date shift from it (build doc section 8) without reaching for the registry.
    """

    registry: EntityRegistry
    session_key: bytes = field(repr=False)
    settings: Settings | None = None
    options: Mapping[str, object] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Counts and option *names* only -- never the key, never option values."""
        return (
            f"StrategyContext(entities={len(self.registry.entities)}, "
            f"session_key='***', options={sorted(self.options)})"
        )

    __str__ = __repr__


class ObfuscationStrategy(ABC):
    """Turns a detected span into the surrogate that replaces it.

    Subclasses implement :meth:`make_surrogate` and set :attr:`name`; everything
    else here is shared machinery so that two strategies cannot drift on the
    token grammar (:func:`~secure_context_pipeline.surrogates.format_surrogate`
    is the single authority) or on hint policy.
    """

    #: Config string that selects this strategy (``SCP_STRATEGY``, the per-entity
    #: ``strategy:`` override, or the API's per-request ``strategy`` field).
    name: ClassVar[str]

    def __init__(self, ctx: StrategyContext) -> None:
        self.ctx = ctx
        #: Normalised originals for EVERY entity in the current document, set by the
        #: engine before any surrogate is generated. The vault only knows what has
        #: been written so far, which makes a collision guard built on it
        #: order-dependent: a fake generated early can collide with a real value
        #: vaulted later, and the two are then byte-identical in the payload. Seeding
        #: the full set up front makes the guard complete rather than incremental.
        self.reserved_originals: frozenset[str] = frozenset()

    # -- shared accessors ---------------------------------------------------

    @property
    def registry(self) -> EntityRegistry:
        """The entity registry. All entity-specific behaviour is looked up here."""
        return self.ctx.registry

    @property
    def session_key(self) -> bytes:
        """The live session key. Never log this, never put it in an error."""
        return self.ctx.session_key

    def option(self, key: str, default: object = None) -> object:
        """Read a per-strategy knob from :attr:`StrategyContext.options`."""
        return self.ctx.options.get(key, default)

    # -- shared helpers -----------------------------------------------------

    def plain_token(self, detection: Detection, token_id: str, hint: str | None = None) -> str:
        """The canonical ``[CATEGORY_TYPE_hash8]`` surrogate.

        Every strategy needs this: tokenization emits nothing else, and
        pseudonymization falls back to it for Tier-3/Tier-4 entities and for any
        value it cannot safely fake (an unparseable date, an exhausted collision
        guard). Routing all of them through one call is what guarantees the
        restorer's grammar holds for every surrogate we ever emit.
        """
        return format_surrogate(detection.category.value, detection.entity_type, token_id, hint)

    def hint_for(self, detection: Detection) -> str | None:
        """Gazetteer class hint for this span, or ``None``.

        ``None`` whenever the entity is not configured ``hint: true``, is not
        gazetteer-backed, or the term carries no class column -- in every one of
        those cases the caller emits a plain token. The hint is a *utility*
        upgrade, so an unavailable lookup degrades the surrogate, never fails it.
        """
        spec = self.registry.get(detection.entity_type)
        if spec is None or not spec.hint:
            return None
        override = self.option(HINT_LOOKUP_OPTION)
        lookup = cast(HintLookup, override) if callable(override) else resolve_hint_lookup()
        return lookup(self.registry, detection.entity_type, detection.text)

    # -- contract -----------------------------------------------------------

    @abstractmethod
    async def make_surrogate(
        self,
        detection: Detection,
        token_id: str,
        vault: SessionVault,
        *,
        session_id: str,
    ) -> str:
        """Return the replacement string for ``detection``.

        ``token_id`` is already collision-resolved by the engine and is the ID the
        vault row will carry, so a surrogate may embed it. Implementations must
        never log, raise, or otherwise emit ``detection.text``.
        """
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"

    __str__ = __repr__


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------

#: ``{name: class}``. Selection is by config string; see :func:`build_strategy`.
STRATEGIES: dict[str, type[ObfuscationStrategy]] = {}

_S = TypeVar("_S", bound=ObfuscationStrategy)

#: Modules holding the shipped strategies. Imported lazily by
#: :func:`build_strategy` rather than by this module, because they import *this*
#: module to register themselves -- and lazily rather than from the package
#: ``__init__`` so that importing the ABC alone stays free of Faker/dateutil.
_BUILTIN_MODULES: tuple[str, ...] = ("tokenization", "pseudonymization")


def register_strategy(cls: type[_S]) -> type[_S]:
    """Class decorator: add ``cls`` to :data:`STRATEGIES` under ``cls.name``."""
    name = getattr(cls, "name", "")
    if not name:
        raise ConfigError(reason="strategy_missing_name", strategy=cls.__name__[:64])
    existing = STRATEGIES.get(name)
    if existing is not None and existing is not cls:
        logger.warning("strategy name re-registered", extra={"strategy": name[:64]})
    STRATEGIES[name] = cls
    return cls


def _load_builtins() -> None:
    """Import the shipped strategy modules so their registrations have run."""
    for module in _BUILTIN_MODULES:
        import_module(f"{__package__}.{module}")


def available_strategies() -> tuple[str, ...]:
    """Every selectable strategy name, built-ins included. Sorted, for display."""
    _load_builtins()
    return tuple(sorted(STRATEGIES))


def build_strategy(name: str, ctx: StrategyContext) -> ObfuscationStrategy:
    """Instantiate the strategy called ``name``.

    Raises :class:`~secure_context_pipeline.errors.ConfigError` for an unknown
    name -- an unrecognised ``SCP_STRATEGY`` or per-entity ``strategy:`` override
    must fail loudly at the call, never silently fall back to a weaker mode.
    """
    _load_builtins()
    try:
        cls = STRATEGIES[name]
    except KeyError as exc:
        raise ConfigError(reason="unknown_strategy", strategy=name[:64]) from exc
    return cls(ctx)


# ---------------------------------------------------------------------------
# Class-hint lookup seam
# ---------------------------------------------------------------------------


def _no_hint(registry: EntityRegistry, entity_type: str, matched_text: str) -> str | None:
    """Fallback lookup: no hints. Tier-3 surrogates degrade to plain tokens."""
    return None


_HINT_LOOKUP: HintLookup | None = None


def resolve_hint_lookup() -> HintLookup:
    """``detection.recognizers.class_hint_for``, resolved on first use.

    Deliberately *not* a module-level import: ``recognizers`` imports
    ``presidio_analyzer``, which pulls in the analyzer stack and eventually
    spaCy. Obfuscation is the graded, dependency-light half of the pipeline and
    must stay importable -- and fast to import -- without it. Only a Tier-3
    entity configured ``hint: true`` ever triggers the resolution.
    """
    global _HINT_LOOKUP
    if _HINT_LOOKUP is None:
        try:
            from secure_context_pipeline.detection.recognizers import class_hint_for
        except ImportError:  # pragma: no cover -- detection extras absent
            logger.info("class hint lookup unavailable; Tier-3 tokens will be un-annotated")
            _HINT_LOOKUP = _no_hint
        else:
            _HINT_LOOKUP = class_hint_for
    return _HINT_LOOKUP
