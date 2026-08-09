"""Settings -- the ONLY component in the package that reads the environment.

Everything else receives a ``Settings`` instance. The master key and the API key
are ``repr=False``, are scrubbed by the overridden ``__repr__`` below, **and** are
replaced with ``'***'`` by a field serializer, so neither ``repr()`` nor
``model_dump()``/``model_dump_json()`` at their default settings can emit one.

The serializer is the part that actually matters. ``repr=False`` only covers
``repr()``; before the serializer was added, ``Settings(...).model_dump_json()``
emitted the base64 master key in full -- one debug endpoint, one structured log
line, or one ``JSONResponse(content=settings.model_dump())`` away from publishing
the key that every per-user document key is derived from.

**The masks stop there, and the boundary is worth stating exactly, because it is
narrower than "the secrets are masked" sounds.** A ``field_serializer`` constrains
*serialization*. It cannot constrain attribute access, and pydantic keeps field
values in the instance ``__dict__``, so the master key is present in full in::

    settings.master_key                        dict(settings) / list(settings)
    settings.__dict__ / vars(settings)         pickle.dumps(settings)
    copy.deepcopy(settings).__dict__           settings.model_copy().__dict__
    settings.model_dump(serialize_as_any=True) and its ``model_dump_json`` twin

The last pair is the one that reads as a contradiction and is not: passing
``serialize_as_any=True`` asks pydantic for *duck-typed* serialization -- serialize
each value by its runtime type -- which deliberately bypasses the declared schema,
and with it every ``field_serializer`` on this class. ``model_dump(...)`` masking
in one call and leaking in the other is pydantic behaving as documented.

None of that is closeable by adding a third serializer; it would take a
self-masking value type (``pydantic.SecretStr``), which is a change to this
class's public read API. So the honest statement of the guarantee is: **the two
accidental exits are masked, the deliberate ones are not.** Read the raw bytes via
:meth:`Settings.master_key_bytes` -- the supported path -- and never hand a
``Settings`` to a generic object dumper. ``tests/test_models.py::THIRD_EXIT_LEAKS``
measures the full list above on every run, so this paragraph fails a test rather
than quietly going stale if it drifts in either direction.

The deliberate consequence of masking: a dumped ``Settings`` does not round-trip --
``Settings(**settings.model_dump())`` raises, because ``'***'`` is not base64. That
is the correct direction to fail in. Use ``model_copy(update=...)`` to derive a
variant; it copies field values rather than serializing them.
"""

from __future__ import annotations

import base64
import binascii
import functools
from pathlib import Path

from pydantic import AliasChoices, Field, field_serializer, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.models import MASK

__all__ = ["DEFAULT_REGISTRY_PATH", "PACKAGE_ROOT", "Settings", "get_settings"]

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_REGISTRY_PATH = PACKAGE_ROOT.parent / "entities.yaml"


#: Strategy names that need no registry lookup to validate. **A fast path, not a
#: gate:** a name that is not here is looked up in the live registry rather than
#: refused, so the closed-set behaviour this replaced does not survive in it.
#:
#: The lookup it skips is not cheap and it is not layered the way the rest of this
#: module is. ``obfuscation.strategies.base`` imports ``Settings`` from here, so
#: importing it at module scope is a cycle; and reaching it pulls in
#: ``detection.registry`` with ``regex`` and ``yaml`` behind it -- measured at 116
#: ms of import plus 62 ms to load the built-in strategy modules, paid by every
#: process that so much as constructs a ``Settings``. Deferring it costs nothing on
#: the two names the package ships and everything is still checked for the third:
#: a plug-in name reaches :func:`_check_strategy_is_registered`, which imports the
#: registry it was registered in -- by which point that module is loaded anyway,
#: because registration happens on import.
_BUILTIN_STRATEGIES: frozenset[str] = frozenset({"tokenization", "pseudonymization"})


def _check_strategy_is_registered(name: str) -> None:
    """Refuse a ``strategy`` no strategy registry knows, at construction time.

    See the ``strategy`` field for why this check lives here rather than in
    ``build_strategy``: that function runs per span, so leaving the check to it
    would convert a startup refusal into a per-request 500.
    """
    if name in _BUILTIN_STRATEGIES:
        return
    from secure_context_pipeline.obfuscation.strategies.base import available_strategies

    known = available_strategies()
    if name not in known:
        raise ConfigError(reason="unknown_strategy", strategy=name[:64], known=",".join(known))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # --- secrets -------------------------------------------------------------
    master_key: str = Field(default="", repr=False)
    anthropic_api_key: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("ANTHROPIC_API_KEY"),
    )

    # --- llm -----------------------------------------------------------------
    # `str`, not `Literal["mock", "anthropic"]`, and the difference is the
    # difference between the extensibility claim being true and being nearly true.
    # Build doc section 9.6: "Provider selection by settings string. Adding OpenAI
    # later = one class + one registry entry." With a closed Literal that was false
    # -- a third-party or plugin provider registered via `@register_provider` could
    # never be *selected*, because `SCP_LLM_PROVIDER=openai` failed validation
    # before `build_provider` ever saw it. `llm/base.py`'s module docstring even
    # says "one line, in this file, and the only edit outside the new module",
    # which was a second edit short.
    #
    # Nothing is loosened by this. An unknown name still fails closed, and still at
    # startup: `build_provider` raises `ConfigError(reason="unknown_llm_provider")`
    # when the registry has no factory for it, and the lifespan builds the provider
    # during startup. The check simply moved to the layer that actually knows what
    # is registered -- which `config` cannot import without a cycle, since
    # `llm/base.py` imports `Settings` from here.
    llm_provider: str = "mock"
    llm_model: str = "claude-opus-5"
    llm_timeout_s: float = 60.0
    llm_max_retries: int = 3
    llm_max_tokens: int = 16000

    # --- obfuscation ---------------------------------------------------------
    # `str` plus a registry check in `_check` below, not a closed Literal. Build doc
    # section 9.3 makes a strategy "new class + registry entry", selected "by config
    # string", and `tests/test_obfuscation.py::test_dummy_strategy_plugs_in_with_
    # zero_engine_changes` claims "nothing else moves" -- while a Literal here meant
    # a strategy registered through the documented `@register_strategy` seam could
    # never be *named* by `SCP_STRATEGY`, and `build_strategy`'s
    # `ConfigError("unknown_strategy")` branch was unreachable from a validated
    # Settings. Measured: `Settings(strategy="redaction")` raised `literal_error`
    # before any registry was consulted.
    #
    # Why the check is here rather than left to `build_strategy`, which is where the
    # equivalent `llm_provider` check lives: `build_provider` runs once, in the
    # lifespan. `build_strategy` runs *per span* inside the engine, so widening this
    # field without a check would have turned an unknown `SCP_STRATEGY` from a
    # startup refusal into an HTTP 500 on every run that touches an entity -- the
    # same defect shape the per-entity `strategy:` override has. Fail-closed and
    # fail-early are both preserved.
    #
    # Widening this field alone was necessary and not sufficient, and the residual is
    # now closed too: `api/schemas.py::StrategyName` was still a `Literal` of the same
    # two names, so a plug-in strategy was selectable by `SCP_STRATEGY` and not by a
    # request, and `deobfuscation/restorer.py` matched the strategy name against a
    # hardcoded pair, so a run under a third name reached the restorer and died with
    # `unknown_strategy` after the payload had already gone to the provider. Both ask
    # `obfuscation.strategies.base` now -- the schema via `available_strategies`, the
    # restorer via `restore_mode` -- so the three checks share one source of truth.
    strategy: str = "tokenization"
    threshold_obfuscate: float = Field(default=0.5, ge=0.0, le=1.0)
    threshold_redact: float = Field(default=0.3, ge=0.0, le=1.0)

    # --- session / storage ---------------------------------------------------
    session_ttl_seconds: int = Field(default=3600, gt=0)
    data_dir: Path = Path("./data")
    # `str`, not `Literal["env", "mock_kms"]`, for exactly the reason `llm_provider`
    # above is a `str`. `crypto/keys.py::build_key_provider` says "Select a provider
    # by config string. Adding a real KMS = one class + one entry", README section 3
    # sells `KeyProvider` as "cloud-compatible by construction", and build doc
    # section 8 makes the row config-selectable -- while a closed Literal here
    # refused `SCP_KEY_PROVIDER=aws_kms` before `build_key_provider` was ever
    # consulted, so the third entry was unreachable and the `unknown_key_provider`
    # branch was dead code. Measured: `Settings(key_provider="aws_kms")` raised
    # `literal_error` while `llm_provider="openai"` was accepted -- one seam widened,
    # its twin not.
    #
    # Nothing is loosened. `build_key_provider` raises
    # `ConfigError(reason="unknown_key_provider")` for a name it has no class for,
    # and it runs inside `EncryptedDocumentStore.__init__`, which the lifespan
    # builds during startup -- so an unknown name still fails closed, still before
    # the first request, just at the layer that actually knows what is registered.
    key_provider: str = "env"

    # --- detection tuning ----------------------------------------------------
    registry_path: Path = DEFAULT_REGISTRY_PATH
    chunk_max_chars: int = Field(default=8000, gt=0)
    detect_concurrency: int = Field(default=4, gt=0)
    #: Deadline for a whole ``Detector.detect`` call, in seconds. Matches the egress
    #: gate's ``DEFAULT_TIMEOUT_S`` so the same operation is bounded the same way on
    #: both sides -- pass 2 of the gate IS a detector run, and it was bounded there
    #: while stage-3 detection was not bounded at all.
    #:
    #: This is a deadline on STARTING work, not a cancellation, and the difference is
    #: the whole reason it is spelled this way. Chunks run in ``asyncio.to_thread`` and
    #: Python threads cannot be cancelled: an ``asyncio.timeout`` around the gather
    #: would free the caller while the worker threads kept burning CPU and holding
    #: pool slots, so later requests would queue behind work nobody is waiting for.
    #: See :meth:`~secure_context_pipeline.detection.detector.Detector.detect` for the
    #: bound this actually buys, which is real but is NOT "detect finishes within
    #: ``detect_timeout_s``".
    detect_timeout_s: float = Field(default=30.0, gt=0)
    spacy_model: str = "en_core_web_lg"

    @field_validator("data_dir", "registry_path")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return v.expanduser()

    @field_serializer("master_key", "anthropic_api_key", when_used="always")
    @staticmethod
    def _mask_secret(value: str | None) -> str | None:
        """Mask secrets on ``model_dump``/``model_dump_json`` at default settings.

        ``repr=False`` masks only ``repr()``. Default serialization is the other
        accidental exit, and it is the one that reaches HTTP responses and
        structured logs. It is not *every* exit -- see the module docstring for the
        attribute-access paths this cannot reach, and ``serialize_as_any=True``,
        which opts out of this serializer by design.
        """
        return None if value is None else MASK

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if not self.master_key:
            raise ConfigError(
                reason="master_key_missing", hint="set_SCP_MASTER_KEY_see_env_example"
            )
        try:
            raw = base64.b64decode(self.master_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError(reason="master_key_not_base64") from exc
        if len(raw) != 32:
            raise ConfigError(reason="master_key_wrong_length", length=len(raw))
        if self.threshold_redact > self.threshold_obfuscate:
            raise ConfigError(
                reason="redact_floor_above_obfuscate_threshold",
                redact=self.threshold_redact,
                obfuscate=self.threshold_obfuscate,
            )
        if self.llm_provider == "anthropic" and not self.anthropic_api_key:
            raise ConfigError(reason="anthropic_selected_without_api_key")
        _check_strategy_is_registered(self.strategy)
        return self

    def master_key_bytes(self) -> bytes:
        """The 32-byte master key. Validated at construction; never logged."""
        return base64.b64decode(self.master_key, validate=True)

    def __repr__(self) -> str:
        return (
            f"Settings(llm_provider={self.llm_provider!r}, llm_model={self.llm_model!r}, "
            f"strategy={self.strategy!r}, key_provider={self.key_provider!r}, "
            f"data_dir={str(self.data_dir)!r}, master_key='***', anthropic_api_key='***')"
        )

    __str__ = __repr__


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton.

    Startup fails loudly with a :class:`ConfigError` when ``SCP_MASTER_KEY`` is
    absent or malformed -- there is no insecure fallback, because a generated or
    defaulted master key would silently make every "encrypted at rest" claim in
    the threat model false. Generate one with::

        python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"

    Cached, so the ``.env`` file is read once per process; ``cache_clear()`` is
    the supported way to pick up a change (the test suite uses it).
    """
    return Settings()
