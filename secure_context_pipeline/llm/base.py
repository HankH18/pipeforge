"""LLM provider layer -- protocol, response model, errors, and registry.

Build doc section 9.6 and locked decision #6: the pipeline talks to *one*
interface, so the fail-closed egress gate (section 9.5.3) wraps every provider
that will ever exist.  Locked decision #9 governs everything downstream of a
call made through this module: **the LLM is never a control-flow
decision-maker.**  Provider output is untrusted text -- string operations only,
never ``eval``, never a branch on its content, never an instruction to follow.

Two protocols are declared:

``LLMProvider``
    The contract copied verbatim from build doc section 9.6.  Nothing may be
    added to it; a future provider only has to satisfy this.

``DetailedLLMProvider``
    ``LLMProvider`` plus :meth:`complete_detailed`, which additionally reports
    token usage so the orchestrator can put ``input_tokens`` / ``output_tokens``
    into the ``LLM_CALL`` audit detail (cost and latency visibility, no
    content).  Every provider in this package implements it, and it is a strict
    subtype of ``LLMProvider`` -- so anything typed against the doc's protocol
    accepts one.

Adding a provider (OpenAI, say) is *one class plus one registry entry*: write the
class and decorate it with ``@register_provider("openai")``.  Stated precisely,
because "no other file changes" would be an overclaim -- the decorator only runs
once the module is imported, so a *bundled* provider also needs its module name in
:data:`BUILTIN_PROVIDER_MODULES`: one line, in this file, and the only edit
outside the new module.  A provider registered from outside the package -- a
plugin, or a test -- needs no edit here at all, since it imports itself and
:func:`register_provider` does the rest; that is what
``test_new_provider_name_is_selectable_with_zero_other_changes`` demonstrates.
Either way nothing anywhere branches on a provider name.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar, runtime_checkable

from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import MAX_DETAIL_VALUE_LEN, ConfigError, PipelineError
from secure_context_pipeline.models import MASK

__all__ = [
    "BUILTIN_PROVIDER_MODULES",
    "PROVIDERS",
    "DetailedLLMProvider",
    "LLMError",
    "LLMProvider",
    "LLMRefusalError",
    "LLMResponse",
    "LLMResponseError",
    "LLMTransportError",
    "ProviderFactory",
    "build_provider",
    "estimate_tokens",
    "load_builtin_providers",
    "register_provider",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, repr=False)
class LLMResponse:
    """One completed provider call.

    ``text`` is untrusted model output.  It is masked in ``repr``/``str`` for the
    same reason :class:`~secure_context_pipeline.models.TokenRecord` masks its
    surrogate: under pseudonymization the response is full of realistic fakes a
    reader could mistake for real values, and an accidental ``f"{response}"`` in
    a log line must not become a disclosure.  Token counts and the model name are
    safe to log and are exactly what the ``LLM_CALL`` audit event records.
    """

    text: str
    input_tokens: int
    output_tokens: int
    model: str

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def __repr__(self) -> str:
        return (
            f"LLMResponse(text={MASK!r}, chars={len(self.text)}, "
            f"input_tokens={self.input_tokens}, output_tokens={self.output_tokens}, "
            f"model={self.model!r})"
        )

    __str__ = __repr__


# ---------------------------------------------------------------------------
# Errors -- structured detail only, never content (build doc section 16)
# ---------------------------------------------------------------------------


class LLMError(PipelineError):
    """Base for provider-layer failures."""

    code = "LLM_ERROR"


class LLMRefusalError(LLMError):
    """The provider declined the request (``stop_reason == "refusal"``).

    Carries the machine-readable policy category only.  The refusal explanation
    and any partial content are deliberately dropped: the outbound payload is
    derived from a customer document, so nothing echoed back from it may enter an
    exception message.
    """

    code = "LLM_REFUSAL"

    def __init__(self, *, model: str, category: str | None = None, attempt: int = 1) -> None:
        super().__init__(
            model=_bounded(model),
            stop_reason="refusal",
            category=_bounded(category),
            attempt=attempt,
        )


class LLMTransportError(LLMError):
    """The provider call failed and is not (or is no longer) retryable."""

    code = "LLM_TRANSPORT_ERROR"

    def __init__(
        self,
        *,
        model: str,
        reason: str,
        attempts: int,
        status_code: int | None = None,
    ) -> None:
        super().__init__(
            model=_bounded(model),
            reason=_bounded(reason),
            attempts=attempts,
            status_code=status_code,
        )


class LLMResponseError(LLMError):
    """A 2xx response arrived but carried nothing usable (e.g. no text blocks)."""

    code = "LLM_RESPONSE_ERROR"

    def __init__(self, *, model: str, reason: str, stop_reason: str | None = None) -> None:
        super().__init__(
            model=_bounded(model),
            reason=_bounded(reason),
            stop_reason=_bounded(stop_reason),
        )


def _bounded(value: str | None) -> str | None:
    """Clamp a detail string to the audit/exception ceiling.

    Defense in depth only -- every call site passes a short machine code.
    """
    if value is None:
        return None
    return value[:MAX_DETAIL_VALUE_LEN]


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMProvider(Protocol):
    """The provider contract, verbatim from build doc section 9.6."""

    name: str

    async def complete(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> str: ...


@runtime_checkable
class DetailedLLMProvider(LLMProvider, Protocol):
    """:class:`LLMProvider` plus token-usage reporting.

    ``complete()`` returns the plain ``str`` the doc's protocol promises and
    delegates to ``complete_detailed()``; the orchestrator calls the latter when
    it wants usage numbers for the ``LLM_CALL`` audit event.
    """

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse: ...


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

#: Anything constructible from a ``Settings``.  Provider *classes* satisfy this
#: (a class is callable), so the registry is literally ``dict[str, type]`` at
#: runtime -- the alias just gives mypy --strict the argument and return types.
ProviderFactory = Callable[[Settings], DetailedLLMProvider]

_FactoryT = TypeVar("_FactoryT", bound=ProviderFactory)

#: ``settings.llm_provider`` -> factory.  Mutable on purpose: a test (or a
#: downstream package) can drop a class in here and it becomes selectable with
#: zero changes anywhere else.
PROVIDERS: dict[str, ProviderFactory] = {}

#: Modules that self-register on import.  Imported lazily by
#: :func:`build_provider` so this module has no import cycle with them.
BUILTIN_PROVIDER_MODULES: tuple[str, ...] = (
    "secure_context_pipeline.llm.mock_provider",
    "secure_context_pipeline.llm.anthropic_provider",
)

_builtins_loaded = False


def register_provider(name: str) -> Callable[[_FactoryT], _FactoryT]:
    """Class decorator that publishes a provider under ``name``."""

    def _decorate(factory: _FactoryT) -> _FactoryT:
        PROVIDERS[name] = factory
        return factory

    return _decorate


def load_builtin_providers() -> None:
    """Import the bundled providers so they register themselves. Idempotent.

    The "already loaded" latch is set *after* every import has succeeded, and
    that ordering is the whole point. Latching first would make a single failed
    import permanent for the life of the process: the registry stays empty, the
    next call returns without retrying, and the failure finally surfaces from
    :func:`build_provider` as ``unknown_llm_provider`` -- an error that sends a
    reader to the settings file instead of to the module that actually broke.
    """
    global _builtins_loaded
    if _builtins_loaded:
        return
    for module in BUILTIN_PROVIDER_MODULES:
        importlib.import_module(module)
    _builtins_loaded = True


def build_provider(settings: Settings) -> DetailedLLMProvider:
    """Select and construct the provider named by ``settings.llm_provider``.

    Returns a :class:`DetailedLLMProvider`, which *is* an :class:`LLMProvider`
    -- callers that only need the doc's protocol can annotate it as such.
    """
    load_builtin_providers()
    name = settings.llm_provider
    factory = PROVIDERS.get(name)
    if factory is None:
        raise ConfigError(reason="unknown_llm_provider", provider=_bounded(name))
    provider = factory(settings)
    logger.debug(
        "llm_provider_selected provider=%s model=%s timeout_s=%s",
        name,
        settings.llm_model,
        settings.llm_timeout_s,
    )
    return provider


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def estimate_tokens(text: str) -> int:
    """A deterministic, network-free token estimate for the mock provider.

    Never used for billing or limits -- only so ``MockProvider`` can populate
    :class:`LLMResponse` with plausible, reproducible counts.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)
