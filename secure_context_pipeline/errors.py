"""Exception hierarchy.

HARD REQUIREMENT (build doc section 16): no exception may ever carry an original
entity value. Constructors here accept *structured* detail only -- token IDs,
entity types, counts, latencies. The base class enforces a 64-character ceiling
on every string value as defense in depth, mirroring the identical guard on
``AuditEvent.detail`` in :mod:`secure_context_pipeline.models`.

The real control is that no call site passes an original; this guard exists so
that a future call site which tries to cannot do so silently.

**Where the rest of the hierarchy lives.** This module holds the errors that cross
package boundaries. Three subpackages define their own ``PipelineError`` subclasses
next to the code that raises them, deliberately -- they are implementation detail of
one package and nothing else catches them by type:

* ``llm/base.py`` -- ``LLMError``, ``LLMRefusalError``, ``LLMTransportError``,
  ``LLMResponseError``
* ``store/document_store.py`` -- ``InvalidCategoryError``
* ``detection/detector.py`` -- ``DetectionInvariantError``

Every one of them inherits ``PipelineError``, so the 64-character detail ceiling
and the "structured detail only" contract apply uniformly across all of them.
"""

from __future__ import annotations

from typing import ClassVar

__all__ = [
    "MAX_DETAIL_VALUE_LEN",
    "ConfigError",
    "CryptoAuthError",
    "DetectionError",
    "EgressBlockedError",
    "PipelineError",
    "SessionExpiredError",
    "StoreAuthError",
    "VaultMissError",
]

MAX_DETAIL_VALUE_LEN = 64

DetailValue = int | float | str | None


class PipelineError(Exception):
    """Base for every pipeline error. Carries structured detail, never content."""

    code: ClassVar[str] = "PIPELINE_ERROR"

    def __init__(self, **detail: DetailValue) -> None:
        for key, value in detail.items():
            if isinstance(value, str) and len(value) > MAX_DETAIL_VALUE_LEN:
                raise ValueError(
                    f"{type(self).__name__}: detail field {key!r} exceeds "
                    f"{MAX_DETAIL_VALUE_LEN} chars; exceptions must not carry content"
                )
        self.detail: dict[str, DetailValue] = detail
        rendered = ", ".join(f"{k}={v!r}" for k, v in detail.items())
        super().__init__(f"{self.code}({rendered})")

    def __repr__(self) -> str:
        rendered = ", ".join(f"{k}={v!r}" for k, v in self.detail.items())
        return f"{type(self).__name__}({rendered})"


class ConfigError(PipelineError):
    """Settings or registry could not be loaded."""

    code = "CONFIG_ERROR"


class EgressBlockedError(PipelineError):
    """The fail-closed egress gate refused to release the payload.

    Raised before any provider call is made. ``reason`` is a short machine code
    (``vault_original`` | ``detector_rescan`` | ``gate_exception``), never the
    matched text.
    """

    code = "EGRESS_BLOCKED"

    def __init__(
        self,
        *,
        session_id: str,
        reason: str,
        hit_count: int,
        entity_types: str = "",
        run_id: str | None = None,
    ) -> None:
        super().__init__(
            session_id=session_id,
            reason=reason,
            hit_count=hit_count,
            entity_types=entity_types,
            run_id=run_id,
        )


class VaultMissError(PipelineError):
    """No vault entry for this (session_id, token_id) -- or the session is gone."""

    code = "VAULT_MISS"

    def __init__(self, *, session_id: str, token_id: str | None = None) -> None:
        super().__init__(session_id=session_id, token_id=token_id)


class SessionExpiredError(PipelineError):
    """Session TTL elapsed or the session was destroyed; its key is unrecoverable."""

    code = "SESSION_EXPIRED"

    def __init__(self, *, session_id: str) -> None:
        super().__init__(session_id=session_id)


class DetectionError(PipelineError):
    """The detector failed on a chunk."""

    code = "DETECTION_ERROR"

    def __init__(self, *, chunk_index: int, reason: str) -> None:
        super().__init__(chunk_index=chunk_index, reason=reason)


class CryptoAuthError(PipelineError):
    """AES-GCM authentication failed.

    Means the key, the AAD, or the ciphertext is wrong -- e.g. a vault row copied
    across sessions, or a document opened with another user's derived key. Callers
    map this onto a domain error (``StoreAuthError`` / ``VaultMissError``) so the
    distinction never reaches an external caller as an oracle.
    """

    code = "CRYPTO_AUTH_FAILED"

    def __init__(self, *, scope: str) -> None:
        super().__init__(scope=scope)


class StoreAuthError(PipelineError):
    """Document decryption failed authentication.

    Deliberately surfaced to callers as *not found*: distinguishing "wrong user"
    from "absent" would be an existence oracle (build doc section 8).
    """

    code = "NOT_FOUND"

    def __init__(self, *, doc_id: str) -> None:
        super().__init__(doc_id=doc_id)
