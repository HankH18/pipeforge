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
from typing import Literal

from pydantic import AliasChoices, Field, field_serializer, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.models import MASK

__all__ = ["DEFAULT_REGISTRY_PATH", "PACKAGE_ROOT", "Settings", "get_settings"]

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_REGISTRY_PATH = PACKAGE_ROOT.parent / "entities.yaml"


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
    llm_provider: Literal["mock", "anthropic"] = "mock"
    llm_model: str = "claude-opus-5"
    llm_timeout_s: float = 60.0
    llm_max_retries: int = 3
    llm_max_tokens: int = 16000

    # --- obfuscation ---------------------------------------------------------
    strategy: Literal["tokenization", "pseudonymization"] = "tokenization"
    threshold_obfuscate: float = Field(default=0.5, ge=0.0, le=1.0)
    threshold_redact: float = Field(default=0.3, ge=0.0, le=1.0)

    # --- session / storage ---------------------------------------------------
    session_ttl_seconds: int = Field(default=3600, gt=0)
    data_dir: Path = Path("./data")
    key_provider: Literal["env", "mock_kms"] = "env"

    # --- detection tuning ----------------------------------------------------
    registry_path: Path = DEFAULT_REGISTRY_PATH
    chunk_max_chars: int = Field(default=8000, gt=0)
    detect_concurrency: int = Field(default=4, gt=0)
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
            raise ConfigError(reason="master_key_missing", hint="set_SCP_MASTER_KEY_see_env_example")
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
