"""Obfuscation strategy ABC + the config-selected registry (build doc section 9.3).

A strategy answers exactly one question: *given a detected span and the token ID
the engine derived for it, what string goes into the outbound payload?* It does
not decide **whether** a span is obfuscated, redacted or stripped -- that is
engine policy, and it must behave identically under every strategy (build doc
section 9.3, engine step 4). Keeping that split is what makes a new strategy a
drop-in: it can only change what a surrogate looks like, never what the pipeline
protects.

Adding a strategy is **one class plus one registry entry, with zero harness
changes**::

    @register_strategy
    class MyStrategy(ObfuscationStrategy):
        name = "mine"
        restores_via = RestoreMode.TOKEN_ID
        async def make_surrogate(self, detection, token_id, vault, *, session_id):
            return self.plain_token(detection, token_id)

``tests/test_obfuscation.py::test_dummy_strategy_plugs_in_with_zero_engine_changes``
asserts the engine half; ``tests/test_extensibility.py::test_a_third_strategy_runs_
the_whole_pipeline_with_no_harness_change`` asserts the pipeline half by running
:class:`~secure_context_pipeline.pipeline.orchestrator.PipelineOrchestrator` end to
end under a strategy defined in the test file.

**Why :attr:`~ObfuscationStrategy.restores_via` is mandatory rather than defaulted.**
It is the one thing a plug-in knows that no other component can infer, and until it
existed the claim above was true of the engine and false of the pipeline. Measured
at ``058dd18`` with a third strategy registered and nothing else changed: detection,
obfuscation and the egress gate all ran, and the request then died in
:meth:`~secure_context_pipeline.deobfuscation.restorer.Restorer.restore` with
``PipelineError(reason='unknown_strategy')`` -- a frozenset of the two shipped names
in ``restorer.py`` -- while ``POST /pipeline/run`` refused the same name with
``literal_error`` before the orchestrator was reached. Both now ask this module
instead: the restorer via :func:`restore_mode`, the request schema via
:func:`available_strategies`, and ``Settings.strategy`` via
``config._check_strategy_is_registered`` -- the same widening ``llm_provider`` and
``key_provider`` already had. It is required rather than defaulted because neither
value is right for both shipped strategies, so a default would let a plug-in be
registered without its author ever answering the question the restorer asks;
:func:`register_strategy` therefore refuses a class that omits it.

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
from enum import StrEnum
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
    "RestoreMode",
    "StrategyContext",
    "available_strategies",
    "build_strategy",
    "register_strategy",
    "resolve_hint_lookup",
    "restore_mode",
]

#: ``StrategyContext.options`` key overriding the gazetteer hint lookup. Exists
#: so a caller (or a test) can supply the class-hint source without importing
#: the detection package -- see :func:`resolve_hint_lookup`.
HINT_LOOKUP_OPTION = "hint_lookup"

#: Signature of ``detection.recognizers.class_hint_for``.
HintLookup = Callable[[EntityRegistry, str, str], str | None]


class RestoreMode(StrEnum):
    """What the deobfuscator needs in order to undo a strategy's output.

    Every strategy declares one, as :attr:`ObfuscationStrategy.restores_via`. It is
    the *requirement*, not an inventory of shapes: the restorer's token pass always
    runs, so a strategy that emits pseudonyms for some tiers and plain tokens for
    the rest declares :attr:`SURROGATE_LOOKUP` -- the harder of the two -- and its
    token-shaped output is still restored by the pass that always runs.
    :attr:`TOKEN_ID` is therefore the narrower claim: *nothing* I emit needs the
    map.

    **What a wrong declaration costs, stated exactly, because it is less than it
    sounds.** It does not lose a value: ``PipelineOrchestrator._surrogate_map``
    decides which surrogates need the map from the *shape of what was actually
    emitted* rather than from this attribute -- deliberately, so that the map and
    the payload cannot drift -- so a pseudonym is mapped whatever its strategy
    declared. What a wrong declaration produces today is a wrong ``restore_mode``
    in the ``DEOBFUSCATE`` audit row. The attribute is required anyway because it is
    the question :class:`~secure_context_pipeline.deobfuscation.restorer.Restorer`
    asks *instead of* matching the strategy name against a hardcoded pair, and
    because there is no default that is right for both shipped strategies.
    """

    #: The surrogate embeds the token ID, so the restorer resolves it by looking
    #: that ID up in the vault. Needs nothing carried along the run.
    TOKEN_ID = "token_id"  # noqa: S105 -- a restore mechanism's name, not a credential

    #: The surrogate is an ordinary string with no key in it (a realistic fake), so
    #: the restorer can only find it via the run's surrogate map and
    #: ``vault.get_by_surrogate``. ``PipelineOrchestrator._surrogate_map`` builds
    #: that map from the emitted *records*, not from this declaration, so a strategy
    #: never has to arrange for it.
    SURROGATE_LOOKUP = "surrogate_lookup"


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

    #: How :class:`~secure_context_pipeline.deobfuscation.restorer.Restorer` gets
    #: the original back out of what :meth:`make_surrogate` returns. **Required** --
    #: :func:`register_strategy` refuses a class that leaves it unset, because the
    #: restorer asks the registry for this instead of matching the name against a
    #: hardcoded pair. See :class:`RestoreMode` for which of the two to declare.
    restores_via: ClassVar[RestoreMode]

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
    """Class decorator: add ``cls`` to :data:`STRATEGIES` under ``cls.name``.

    Refuses a class that declares no :attr:`~ObfuscationStrategy.restores_via`, at
    import time and by name. That is deliberately the same shape as the missing-name
    refusal beside it: both are things only the strategy author knows, and both fail
    the *import* rather than the run. The alternative -- a default -- is unavailable
    for an honest reason rather than a stylistic one: the two shipped strategies
    declare different values, so there is no default that is right for both, and a
    plug-in inheriting either one would be making a claim its author never read.
    """
    name = getattr(cls, "name", "")
    if not name:
        raise ConfigError(reason="strategy_missing_name", strategy=cls.__name__[:64])
    if not isinstance(getattr(cls, "restores_via", None), RestoreMode):
        raise ConfigError(reason="strategy_missing_restore_mode", strategy=name[:64])
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


def restore_mode(name: str) -> RestoreMode | None:
    """The :class:`RestoreMode` strategy ``name`` declares, or ``None`` if unknown.

    The deobfuscator's question, and the reason this module owns the answer: what
    ``Restorer.restore`` needs to know about a strategy is not its *name* but how
    its output comes apart, and the only component that knows that is the strategy
    itself. ``None`` means no registered class claims the name -- the caller decides
    what that is worth (the restorer refuses the run; a display path may not care).

    Cheap after the first call: :func:`_load_builtins` is an ``import_module`` on an
    already-imported module, and the restorer calls this once per ``restore()``, not
    once per token.
    """
    _load_builtins()
    cls = STRATEGIES.get(name)
    return None if cls is None else cls.restores_via


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
