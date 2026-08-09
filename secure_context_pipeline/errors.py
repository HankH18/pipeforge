"""Exception hierarchy.

HARD REQUIREMENT (build doc section 16): no exception may ever carry an original
entity value. Constructors here accept *structured* detail only -- token IDs,
entity types, counts, latencies. The base class enforces a 64-character ceiling
on **both halves of every detail entry, measured on the rendered width**, which
is the same guard ``AuditEvent.detail`` applies in
:mod:`secure_context_pipeline.models` -- deliberately the same, because
``api/errors.py`` writes ``dict(exc.detail)`` straight into the HTTP body, so
this map is a wire surface with the same exposure shape as an audit row.

"Mirroring the identical guard" is what this docstring said while the two had
already diverged: ``models.py`` moved to ``len(str(value))`` and grew a key
bound, and this module was still testing ``isinstance(value, str)`` on the value
alone. That gap was reachable in exactly the shape ``models.py`` documents -- a
408-character clinical note encodes to a 983-digit int, which passed the ceiling
here and rendered verbatim into ``str(exc)``, recoverable with one ``to_bytes``.

The real control is that no call site passes an original; this guard exists so
that a future call site which tries to cannot do so silently -- which a
type-conditional check cannot deliver, since silence for every non-``str``
member of ``DetailValue`` is precisely the failure it is supposed to prevent.

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
    "OVERSIZED_PAYLOAD_REASON",
    "OVERSIZED_PAYLOAD_REMEDY",
    "UNREADABLE_AUDIT_REASON",
    "UNREADABLE_AUDIT_REMEDY",
    "AuditUnavailableError",
    "ConfigError",
    "CryptoAuthError",
    "DetectionError",
    "EgressBlockedError",
    "PayloadTooLargeError",
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
            # Both halves of the entry, both measured on the RENDERED width --
            # the same two checks `AuditEvent._reject_long_values` runs, in the
            # same order. They are re-derived here rather than asserted to be
            # equivalent because the two had already drifted apart underneath a
            # docstring that said they were identical, and nothing compared them.
            #
            # `isinstance(value, str)` was the whole check, and `DetailValue` is
            # `int | float | str | None`. An int has no length, so the payload the
            # audit model refuses walked through here: 408 characters of clinical
            # note becomes a 983-digit int, which `__init__` accepted and
            # `super().__init__` rendered into a 1,004-character `str(exc)` --
            # and `api/errors.py` puts `dict(exc.detail)` into the response body.
            # A ceiling that only bites the encoding an honest caller would have
            # used is not a ceiling.
            #
            # The KEY is bounded for the same reason it is in `models.py`: it is
            # serialised into the body alongside the value, so bounding one of
            # them bounds nothing. No shipped call site builds a dynamic key (they
            # all arrive as kwargs literals), so this is a hardening gap rather
            # than a live leak -- which is the kind that survives, because nothing
            # exercises it.
            #
            # `str(None)` is 4 chars, so an absent optional detail still passes.
            if len(key) > MAX_DETAIL_VALUE_LEN:
                raise ValueError(
                    f"{type(self).__name__}: detail key {key!r} exceeds "
                    f"{MAX_DETAIL_VALUE_LEN} chars; exceptions must not carry content"
                )
            if len(str(value)) > MAX_DETAIL_VALUE_LEN:
                raise ValueError(
                    f"{type(self).__name__}: detail field {key!r} exceeds "
                    f"{MAX_DETAIL_VALUE_LEN} chars when rendered; exceptions must "
                    "not carry content"
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


#: What an operator does about an unreadable audit log. A constant, not a formatted
#: string: it is written into an HTTP body by ``api/errors.py``, and the one rule
#: this hierarchy has is that nothing derived from a document or a prompt may go
#: there. 60 characters, under :data:`MAX_DETAIL_VALUE_LEN`.
UNREADABLE_AUDIT_REMEDY = "restore it from backup or start a fresh data directory"

#: The machine half of the same fact, and the word the audit module already used:
#: ``query`` and ``length`` have raised ``reason="audit_log_unreadable"`` since the
#: file-level corruption test was written. Defined once so the writer cannot drift
#: from the two readers.
UNREADABLE_AUDIT_REASON = "audit_log_unreadable"


class AuditUnavailableError(PipelineError):
    """The audit log could not be read or written, so the operation was refused.

    Raised by every :class:`~secure_context_pipeline.audit.logger.AuditLogger` entry
    point that touches a database it cannot read -- the writer (``emit``) and the two
    readers (``query``, ``length``) -- and mapped to **503** by ``api/errors.py``.

    **Why this exists as its own code.** A physically corrupt ``audit.db`` -- one
    4 KiB page overwritten, which ``PRAGMA integrity_check`` reports as ``Tree 2
    page 2 cell 0: invalid page`` and which ``AuditLogger.open`` accepts -- made
    ``emit`` escape with a raw ``sqlite3.DatabaseError``. Measured through the real
    ASGI app: ``POST /pipeline/run`` answered ``500`` with ``content-type:
    text/plain``, the body ``Internal Server Error``, **and none of the security
    headers** -- no CSP, no ``nosniff`` -- because Starlette's ``ServerErrorMiddleware``
    renders that response outside the middleware that adds them. Three things were
    wrong with it and only the first is cosmetic: it carries no ``code`` for a client
    to branch on, it says an unhandled exception reached the framework, and it is
    byte-identical to what a genuine bug in the pipeline produces.

    ``PIPELINE_ERROR`` would have fixed the first two and not the third, which is the
    one that matters here: the pipeline is *healthy*, and the demo UI's sentence for
    that code ends "Run again; if it repeats, the server log carries the traceback",
    which is advice that cannot work -- every retry reads the same dead page.

    **The run is still refused, and that is not what changed.** "No release without a
    record" is pinned by
    ``integration/test_pipeline.py::test_no_release_survives_an_audit_write_that_failed_before_it``;
    this class only replaces the *shape* of the refusal. Verified on the same corrupt
    file: the provider call count is unchanged across the refused run.

    **Every value here is bounded by construction rather than validated.** The base
    class raises ``ValueError`` above :data:`MAX_DETAIL_VALUE_LEN`, and this
    constructor runs *on* the failure path -- a raise out of it would put back the
    bare 500 it exists to remove. A file name and an exception class name are not
    content, so clipping them loses nothing, and the caller passes the *name* rather
    than the path: ``str(tmp_path / "audit.db")`` is routinely over 64 characters, and
    a server's directory layout is not something an error body owes a client.
    """

    code = "AUDIT_UNAVAILABLE"

    def __init__(self, *, operation: str, audit_db: str, error: str) -> None:
        super().__init__(
            reason=UNREADABLE_AUDIT_REASON,
            operation=operation[:MAX_DETAIL_VALUE_LEN],
            audit_db=audit_db[:MAX_DETAIL_VALUE_LEN],
            error=error[:MAX_DETAIL_VALUE_LEN],
            remedy=UNREADABLE_AUDIT_REMEDY,
        )


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


#: What a caller does about a document too large for one provider call. A constant
#: rather than a formatted string, for the reason :data:`UNREADABLE_AUDIT_REMEDY` is
#: one: ``api/errors.py`` writes ``dict(exc.detail)`` straight into the HTTP body, so
#: nothing derived from a document or a prompt may go there. 55 characters, under
#: :data:`MAX_DETAIL_VALUE_LEN`.
OVERSIZED_PAYLOAD_REMEDY = "split the document and run each part as its own request"

#: The machine half of the same fact. Defined once because three readers share it --
#: this constructor, the ``EGRESS_BLOCK`` audit detail the orchestrator writes on the
#: same path, and the test that asserts the two agree -- and a fourth copy is a fourth
#: place for them to drift.
OVERSIZED_PAYLOAD_REASON = "payload_over_context_limit"


class PayloadTooLargeError(PipelineError):
    """The assembled payload is larger than one provider call can carry.

    Raised by :class:`~secure_context_pipeline.pipeline.orchestrator.PipelineOrchestrator`
    at step 5b -- after the payload is assembled and **before** the egress gate scans it
    -- and mapped to **422** by ``api/errors.py``. The ceiling and its derivation live
    in :data:`~secure_context_pipeline.pipeline.context_injector.MAX_PAYLOAD_CHARS`,
    next to the code that assembles the string being measured.

    **Why this exists as its own code.** ``ContextInjector.build`` emits one payload
    holding the whole obfuscated document and ``run()`` makes exactly one provider call
    with it, so past the model's input window the request fails as a **non-retryable
    HTTP 400** -- the shape ``llm/anthropic_provider.py`` already documents for a
    rejected parameter. That reached the caller as ``LLM_TRANSPORT_ERROR``, i.e. as
    "the upstream is broken", after paying for detection, obfuscation, a full detector
    re-scan inside the gate, and a network round trip. None of that is true or useful:
    the pipeline is healthy, the upstream is healthy, and the one thing the caller can
    do about it -- send less document -- is not in that answer.

    ``EGRESS_BLOCKED`` would have been the wrong reuse for the opposite reason. Its
    sentence in the demo UI, and the whole weight the README puts on it, is *the control
    caught a leak*; a document that is merely long has leaked nothing, and burning the
    product's loudest signal on a size refusal would make the signal mean less.

    **The two numbers are the message.** ``payload_chars`` and ``limit_chars`` are what
    turn "too large" into "too large by 3.2x", which is the difference between a caller
    who splits the document once and a caller who guesses. Both are counts, which is
    all this hierarchy may carry: a character count of a document is not a document.
    """

    code = "PAYLOAD_TOO_LARGE"

    def __init__(
        self,
        *,
        session_id: str,
        payload_chars: int,
        limit_chars: int,
        run_id: str | None = None,
    ) -> None:
        super().__init__(
            reason=OVERSIZED_PAYLOAD_REASON,
            session_id=session_id[:MAX_DETAIL_VALUE_LEN],
            payload_chars=payload_chars,
            limit_chars=limit_chars,
            run_id=run_id[:MAX_DETAIL_VALUE_LEN] if run_id is not None else None,
            remedy=OVERSIZED_PAYLOAD_REMEDY,
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
