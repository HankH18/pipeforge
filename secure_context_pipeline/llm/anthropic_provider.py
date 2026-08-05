"""Anthropic provider -- the only component in the package that talks to a network.

Build doc section 9.6.  Everything reaching :meth:`AnthropicProvider.complete`
has already cleared the fail-closed egress gate (section 9.5.3), so this module's
job is narrow: make the call, retry the failures that are worth retrying, and
hand back text plus token counts.  It never inspects, parses, or branches on the
model's answer -- locked decision #9 -- and it never puts payload bytes into a log
line or an exception (build doc section 16); only model name, token counts,
latency, attempt number and short machine codes.  The *SDK* does put the whole
request body in a DEBUG log line, so importing this module muzzles that stream --
see :func:`_mute_sdk_content_logging`.

Request shape (current API -- these differ from older examples):

* ``output_config={"effort": "low"}`` -- this is a pure data-plane call, we do
  not want the model reasoning about the document.
* No ``temperature`` / ``top_p`` / ``top_k`` and no
  ``thinking={"type": "enabled", "budget_tokens": N}``: all four are removed on
  this model family and return HTTP 400.
* ``max_retries=0`` on the client, so the retry policy below is the *only* one
  in play and a 429 storm cannot be silently multiplied by the SDK's own
  backoff.
* Response text is accumulated from every ``text`` block.  A ``thinking`` block
  can precede it, so ``content[0]`` is never indexed.

Retries: at most :data:`MAX_ATTEMPTS` attempts, exponential backoff with jitter,
and only on 429 / 5xx / timeouts / connection failures.  Classification is by the
SDK's typed exceptions *and* by the HTTP status, never by string-matching a
message -- so a 529 (overloaded) is retried whichever exception class the SDK
renders it as.

Terminal responses each have their own outcome, and none of them returns a
silently degraded answer: ``stop_reason == "refusal"`` raises
:class:`~secure_context_pipeline.llm.base.LLMRefusalError` carrying the policy
category and nothing else; a 2xx with no text block raises
:class:`~secure_context_pipeline.llm.base.LLMResponseError`; a truncated answer
(``max_tokens``) is returned but logged as ``LLM_TRUNCATED``.  All three are
exercised over ``httpx.MockTransport``, i.e. through the real SDK's own parser,
in ``tests/test_llm.py``.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Final

import anthropic
import httpx
from anthropic.types import Message, MessageParam

from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import ConfigError
from secure_context_pipeline.llm.base import (
    LLMRefusalError,
    LLMResponse,
    LLMResponseError,
    LLMTransportError,
    register_provider,
)

__all__ = [
    "ANTHROPIC_LOGGER_NAME",
    "BACKOFF_BASE_S",
    "BACKOFF_CAP_S",
    "BACKOFF_FACTOR",
    "EFFORT",
    "JITTER_RATIO",
    "MAX_ATTEMPTS",
    "MAX_BACKOFF_S",
    "AnthropicProvider",
    "backoff_delay",
    "classify_error",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Third-party log muzzle -- build doc section 16
# ---------------------------------------------------------------------------

#: Root of the SDK's logger namespace.  ``anthropic._base_client`` emits
#: ``"Request options: %s"`` at DEBUG with the *entire* serialized request body
#: as its argument -- ``system`` and ``messages`` in full, on every call and
#: every retry.
ANTHROPIC_LOGGER_NAME: Final = "anthropic"


class _BelowInfoFilter(logging.Filter):
    """Drops every record below INFO, whatever level the logger is set to."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.INFO


def _mute_sdk_content_logging() -> None:
    """Silence the SDK's sub-INFO stream, the same way Presidio's is silenced.

    Build doc section 16 forbids content in logs unconditionally and carves out no
    exception for debug paths, and
    :func:`~secure_context_pipeline.detection.detector._mute_presidio_content_logging`
    already applies that rule to the other third-party library that logs document
    text.  This is the same defect in the other direction: turn on debug logging
    anywhere in the host application -- one ``dictConfig``, one ``ANTHROPIC_LOG``,
    one ``logging.basicConfig(level=DEBUG)`` -- and the outbound payload lands in
    the log stream in full.

    What that payload contains bounds the severity honestly: it has cleared the
    fail-closed EgressGate, so it is surrogates rather than originals.  The rule is
    still the rule, and losing the distinction between "our logs are clean" and
    "our logs are clean unless somebody enables debug" is exactly how a
    zero-content claim stops being true.  Inspecting the literal outbound body is
    already served by a mechanism that is *safe* -- ``demo.py --dump-wire`` scans
    the captured bytes against the vault originals set first -- so nothing worth
    keeping is lost here.

    A level alone is advisory: any later ``setLevel(DEBUG)`` on the SDK's loggers
    undoes it.  ``Logger.handle`` consults a logger's own filters for every record
    regardless of level, and ancestor filters are *not* consulted for a child's
    records, so the filter is attached to each existing logger in the namespace
    and the level is set on the root of it for any created later.
    """
    root = logging.getLogger(ANTHROPIC_LOGGER_NAME)
    if root.level < logging.INFO:
        root.setLevel(logging.INFO)
    names = [ANTHROPIC_LOGGER_NAME] + [
        name
        for name in logging.root.manager.loggerDict
        if name.startswith(ANTHROPIC_LOGGER_NAME + ".")
    ]
    for name in names:
        target = logging.getLogger(name)
        if not any(isinstance(existing, _BelowInfoFilter) for existing in target.filters):
            target.addFilter(_BelowInfoFilter())


_mute_sdk_content_logging()

#: Build doc section 9.6: "retries: max 3".  Three *attempts* total, not three
#: retries after the first try.
MAX_ATTEMPTS: Final = 3
BACKOFF_BASE_S: Final = 0.5
BACKOFF_FACTOR: Final = 2.0
BACKOFF_CAP_S: Final = 8.0
JITTER_RATIO: Final = 0.25
#: Hard ceiling on any single sleep, asserted by the test suite.
MAX_BACKOFF_S: Final = BACKOFF_CAP_S * (1.0 + JITTER_RATIO)

#: Reasoning depth. Low: we are asking for a summary of an already-redacted
#: document, not for analysis worth paying thinking tokens for.
EFFORT: Final = "low"

# SystemRandom rather than the `random` module: jitter is not security-relevant,
# but the package is linted with bandit rules and a seeded PRNG here would be
# noise in the audit.
_JITTER_SOURCE: Final = secrets.SystemRandom()


def backoff_delay(attempt: int) -> float:
    """Exponential backoff with additive jitter, capped at :data:`MAX_BACKOFF_S`."""
    base = min(BACKOFF_BASE_S * (BACKOFF_FACTOR ** (attempt - 1)), BACKOFF_CAP_S)
    return base + _JITTER_SOURCE.uniform(0.0, base * JITTER_RATIO)


def classify_error(exc: anthropic.APIError) -> tuple[bool, str, int | None]:
    """``(retryable, machine_reason, status_code)`` for an SDK exception.

    Structured data only -- the exception class and the HTTP status, never a
    message string.  ``RateLimitError`` is checked before its ``APIStatusError``
    parent, and ``APITimeoutError`` before its ``APIConnectionError`` parent.

    The status is consulted *as well as* the class, because "should this be sent
    again?" is a property of the response rather than of which exception the SDK
    happened to construct for it.  A 429 that arrives as a bare
    ``APIStatusError`` is still a rate limit; classifying it ``client_error``
    would turn a routine backoff into a hard failure.  Same for 408, which is a
    timeout the *server* reported rather than one the client observed -- the
    build doc puts both in the retry set (section 9.6).  Every other 4xx is never
    retryable: the request will not become valid by being sent again.
    """
    if isinstance(exc, anthropic.RateLimitError):
        return True, "rate_limit", exc.status_code
    if isinstance(exc, anthropic.APIStatusError):
        status = exc.status_code
        if status >= 500:
            return True, "server_error", status
        if status == 429:
            return True, "rate_limit", status
        if status == 408:
            return True, "timeout", status
        return False, "client_error", status
    if isinstance(exc, anthropic.APITimeoutError):
        return True, "timeout", None
    if isinstance(exc, anthropic.APIConnectionError):
        return True, "connection_error", None
    return False, "api_error", None


@register_provider("anthropic")
class AnthropicProvider:
    """Provider backed by ``anthropic.AsyncAnthropic``."""

    name: str = "anthropic"

    def __init__(self, settings: Settings, *, http_client: httpx.AsyncClient | None = None) -> None:
        """Build the client.

        ``http_client`` is the seam ``demo.py --dump-wire`` uses: pass an
        ``httpx.AsyncClient`` carrying a request event hook and the literal
        outbound request body can be captured and shown to a reviewer, which is
        the strongest possible evidence for the zero-PII-in-transit claim.
        """
        api_key = settings.anthropic_api_key
        if not api_key:
            raise ConfigError(reason="anthropic_api_key_missing")

        self._settings = settings
        # Clamp to the doc's ceiling: our backoff is the only retry in play, and
        # `max_retries=0` below means the SDK never adds its own on top.
        self._max_attempts = max(1, min(settings.llm_max_retries, MAX_ATTEMPTS))

        if http_client is None:
            self._client = anthropic.AsyncAnthropic(
                api_key=api_key,
                max_retries=0,
                timeout=settings.llm_timeout_s,
            )
        else:
            self._client = anthropic.AsyncAnthropic(
                api_key=api_key,
                max_retries=0,
                timeout=settings.llm_timeout_s,
                http_client=http_client,
            )

    @property
    def max_attempts(self) -> int:
        return self._max_attempts

    async def complete(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> str:
        response = await self.complete_detailed(
            system, user, model=model, timeout_s=timeout_s
        )
        return response.text

    async def complete_detailed(
        self, system: str, user: str, *, model: str, timeout_s: float = 60.0
    ) -> LLMResponse:
        messages: list[MessageParam] = [{"role": "user", "content": user}]
        reason = "not_attempted"
        status: int | None = None

        for attempt in range(1, self._max_attempts + 1):
            started = time.perf_counter()
            try:
                raw = await self._client.messages.create(
                    model=model,
                    max_tokens=self._settings.llm_max_tokens,
                    system=system,
                    messages=messages,
                    output_config={"effort": EFFORT},
                    timeout=timeout_s,
                )
            except anthropic.APIError as exc:
                retryable, reason, status = classify_error(exc)
                logger.warning(
                    "LLM_CALL_FAILED model=%s attempt=%d/%d reason=%s status=%s "
                    "retryable=%s elapsed_ms=%.1f",
                    model,
                    attempt,
                    self._max_attempts,
                    reason,
                    status,
                    retryable,
                    (time.perf_counter() - started) * 1000.0,
                )
                if not retryable or attempt >= self._max_attempts:
                    raise LLMTransportError(
                        model=model, reason=reason, attempts=attempt, status_code=status
                    ) from exc
                await asyncio.sleep(backoff_delay(attempt))
                continue

            return self._decode(
                raw, model, attempt, (time.perf_counter() - started) * 1000.0
            )

        # Only reachable if the loop never ran; kept so the function has no
        # implicit `None` return path.
        raise LLMTransportError(
            model=model, reason=reason, attempts=self._max_attempts, status_code=status
        )

    def _decode(
        self, raw: Message, model: str, attempt: int, elapsed_ms: float
    ) -> LLMResponse:
        """Turn an SDK ``Message`` into an :class:`LLMResponse`.

        Checks ``stop_reason`` *before* touching ``content``.
        """
        stop_reason = raw.stop_reason

        if stop_reason == "refusal":
            category = raw.stop_details.category if raw.stop_details is not None else None
            logger.warning(
                "LLM_REFUSAL model=%s attempt=%d category=%s elapsed_ms=%.1f",
                model,
                attempt,
                category,
                elapsed_ms,
            )
            # No content, no explanation: the payload derives from a customer
            # document and must not reach an exception message.
            raise LLMRefusalError(model=model, category=category, attempt=attempt)

        if stop_reason == "max_tokens":
            # Returned, not failed: a truncated answer with its values restored
            # beats no answer. But it is called out on its own rather than folded
            # into "expected", because the tail of a truncated response can be a
            # half-written token -- `[PHI_NAME_1a2b` matches no grammar, so it
            # survives restoration as visible debris. Not a disclosure (the ID is
            # synthetic and partial), but the one artefact that makes a user
            # distrust the answer, and an operator should see it in the log.
            logger.warning(
                "LLM_TRUNCATED model=%s attempt=%d max_tokens=%d output_tokens=%d",
                model,
                attempt,
                self._settings.llm_max_tokens,
                raw.usage.output_tokens,
            )
        elif stop_reason not in ("end_turn", "stop_sequence", None):
            logger.warning(
                "LLM_UNEXPECTED_STOP model=%s attempt=%d stop_reason=%s",
                model,
                attempt,
                stop_reason,
            )

        # A thinking block may precede the text; never index content[0].
        chunks: list[str] = []
        for block in raw.content:
            if block.type == "text":
                chunks.append(block.text)
        text = "".join(chunks)

        usage = raw.usage
        logger.info(
            "LLM_CALL model=%s attempt=%d stop_reason=%s blocks=%d text_blocks=%d "
            "input_tokens=%d output_tokens=%d elapsed_ms=%.1f",
            model,
            attempt,
            stop_reason,
            len(raw.content),
            len(chunks),
            usage.input_tokens,
            usage.output_tokens,
            elapsed_ms,
        )

        if not text:
            raise LLMResponseError(
                model=model, reason="no_text_blocks", stop_reason=stop_reason
            )

        return LLMResponse(
            text=text,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            model=str(raw.model),
        )
