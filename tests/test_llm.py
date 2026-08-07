"""Tests for the LLM provider layer (build doc sections 9.6, 10.7).

Everything here runs with no network and no API key.  The Anthropic provider is
exercised against a stub client so the retry policy, the request shape, and the
response decoding are all covered without a single socket being opened; the one
test that does talk to the real API is marked ``real_llm`` and skips itself when
``ANTHROPIC_API_KEY`` is absent.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
from collections.abc import Callable, Iterator
from typing import Any

import anthropic
import httpx
import pytest
from anthropic.types import Message, RefusalStopDetails, TextBlock, ThinkingBlock, Usage

from secure_context_pipeline.config import Settings
from secure_context_pipeline.errors import ConfigError, PipelineError
from secure_context_pipeline.llm.anthropic_provider import (
    ANTHROPIC_LOGGER_NAME,
    EFFORT,
    MAX_ATTEMPTS,
    MAX_BACKOFF_S,
    AnthropicProvider,
    backoff_delay,
    classify_error,
)
from secure_context_pipeline.llm.base import (
    PROVIDERS,
    DetailedLLMProvider,
    LLMProvider,
    LLMRefusalError,
    LLMResponse,
    LLMResponseError,
    LLMTransportError,
    build_provider,
    load_builtin_providers,
)
from secure_context_pipeline.llm.mock_provider import (
    COREFERENCE_SENTENCE,
    DOC_MUTATION_CLASSES,
    EXCERPT_HEADER,
    MUTATION_CLASSES,
    SURROGATE_TOKEN_RE,
    MockProvider,
    build_response,
    find_tokens,
    plan_mutations,
    render_mutation,
)
from secure_context_pipeline.surrogates import TOKEN_RE, format_surrogate

MASTER_KEY = base64.b64encode(bytes(range(32))).decode()
FAKE_API_KEY = "sk-ant-not-a-real-key"

# Seven distinct surrogates, one of them hint-annotated -- enough to force the
# mock through every mutation class exactly as the build doc's robustness matrix
# (section 10.7) requires.
#
# Every hash here is EIGHT hex characters, and the annotated one deliberately is
# too. The build doc's prose writes that example as `[PHI_MEDICATION_2f4a|...]`,
# and a four-hex ID cannot exist: section 8 fixes token IDs at
# `hexdigest()[:8]`, `format_surrogate` rejects anything else, and the restorer's
# `TOKEN_RE` demands `{8}`. With the doc's literal string here, `hint_stripped`
# -- the one mutation section 9.6 calls out by name -- was being exercised on a
# token the restorer provably cannot match, so the fixture asserted coverage it
# did not have. The shorthand form is not lost: it is pinned as its own case in
# `tests/test_deobfuscation.py`.
SURROGATES = (
    "[PHI_NAME_1a2b3c4d]",
    "[PHI_MRN_00ff11aa]",
    "[PII_SSN_deadbeef]",
    "[FIN_ACCOUNT_NUMBER_0123abcd]",
    "[LEGAL_CASE_NUMBER_99887766]",
    "[PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]",
    "[PHI_DIAGNOSIS_aabbccdd]",
)

TOKENIZED_PAYLOAD = "\n".join(
    (
        "Patient record under review.",
        f"Name: {SURROGATES[0]}   MRN: {SURROGATES[1]}",
        f"SSN on file: {SURROGATES[2]}",
        f"Billing account {SURROGATES[3]} is linked to matter {SURROGATES[4]}.",
        f"Current therapy: {SURROGATES[5]} for {SURROGATES[6]}.",
        "Summarise the encounter.",
    )
)

# Pseudonymization mode: realistic fakes, nothing matching the surrogate regex.
PSEUDONYMIZED_PAYLOAD = "\n".join(
    (
        "Patient record under review.",
        "Name: Marisol Ferraro    MRN: 4471902",
        "Primary care contact is Dr. Aurelio Banks at Northgate Family Medicine.",
        "Billing account 7781-2245-9930 is linked to matter Halloran v. Brightwater.",
        "Current therapy: metformin for type 2 diabetes mellitus.",
        "Summarise the encounter.",
    )
)

# What pseudonymization *actually* emits: Tier-1 realistic fakes AND Tier-3
# class-annotated tokens in one payload (build doc 9.3). Neither of the two
# fixtures above has this shape, which is how the mock's token-vs-fakes branch
# went unnoticed.
MIXED_TIER_PAYLOAD = "\n".join(
    (
        "Patient record under review.",
        "Name: Marisol Ferraro, seen at Northgate Family Medicine on 04/11/2019.",
        f"Therapy: {SURROGATES[5]} for {SURROGATES[6]}.",
        f"Billing account 7781-2245-9930 is linked to matter {SURROGATES[4]}.",
        "Summarise the encounter.",
    )
)


# ---------------------------------------------------------------------------
# Fixtures and stubs
# ---------------------------------------------------------------------------


@pytest.fixture
def settings_factory(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Settings]:
    """Build hermetic ``Settings`` without touching the developer's real env."""

    def _make(*, api_key: str | None = FAKE_API_KEY, **overrides: Any) -> Settings:
        monkeypatch.setenv("SCP_MASTER_KEY", MASTER_KEY)
        if api_key is None:
            monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        else:
            monkeypatch.setenv("ANTHROPIC_API_KEY", api_key)
        return Settings(_env_file=None, **overrides)

    return _make


@pytest.fixture
def registry() -> Iterator[dict[str, Any]]:
    """Snapshot ``PROVIDERS`` so a test can mutate it and leave no trace."""
    load_builtin_providers()
    snapshot = dict(PROVIDERS)
    yield PROVIDERS
    PROVIDERS.clear()
    PROVIDERS.update(snapshot)


def make_message(
    *,
    content: list[Any] | None = None,
    stop_reason: str | None = "end_turn",
    stop_details: RefusalStopDetails | None = None,
    input_tokens: int = 1234,
    output_tokens: int = 567,
    model: str = "claude-opus-5",
) -> Message:
    if content is None:
        content = [TextBlock(type="text", text="ok", citations=None)]
    return Message(
        id="msg_test_0001",
        content=content,
        model=model,
        role="assistant",
        stop_reason=stop_reason,
        stop_details=stop_details,
        stop_sequence=None,
        type="message",
        usage=Usage(input_tokens=input_tokens, output_tokens=output_tokens),
    )


def status_error(kind: type[anthropic.APIStatusError], status: int) -> anthropic.APIStatusError:
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx.Response(status_code=status, request=request)
    return kind("stubbed failure", response=response, body=None)


class FakeMessages:
    """Stand-in for ``client.messages``: replays a scripted sequence."""

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class FakeClient:
    def __init__(self, script: list[Any]) -> None:
        self.messages = FakeMessages(script)
        self.max_retries = 0


def stubbed_provider(settings: Settings, script: list[Any]) -> tuple[AnthropicProvider, FakeClient]:
    provider = AnthropicProvider(settings)
    fake = FakeClient(script)
    provider._client = fake  # type: ignore[assignment]
    return provider, fake


@pytest.fixture
def sleep_recorder(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace ``asyncio.sleep`` so backoff is instant and observable."""
    delays: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return delays


# ---------------------------------------------------------------------------
# MockProvider -- determinism
# ---------------------------------------------------------------------------


async def test_mock_provider_is_byte_identical_across_calls() -> None:
    first = await MockProvider().complete("sys", TOKENIZED_PAYLOAD, model="mock-1")
    second = await MockProvider().complete("sys", TOKENIZED_PAYLOAD, model="mock-1")
    assert first == second
    assert first.encode() == second.encode()


async def test_mock_provider_determinism_is_independent_of_instance_and_call_count() -> None:
    provider = MockProvider()
    outputs = [await provider.complete("sys", TOKENIZED_PAYLOAD, model="mock-1") for _ in range(5)]
    assert len(set(outputs)) == 1
    assert outputs[0] == build_response(TOKENIZED_PAYLOAD)


async def test_mock_provider_reports_deterministic_token_usage() -> None:
    a = await MockProvider().complete_detailed("sys", TOKENIZED_PAYLOAD, model="mock-1")
    b = await MockProvider().complete_detailed("sys", TOKENIZED_PAYLOAD, model="mock-1")
    assert (a.input_tokens, a.output_tokens) == (b.input_tokens, b.output_tokens)
    assert a.input_tokens > 0
    assert a.output_tokens > 0
    assert a.model == "mock-1"


# ---------------------------------------------------------------------------
# MockProvider -- mutation coverage
# ---------------------------------------------------------------------------


def test_plan_covers_every_exported_mutation_class() -> None:
    plan = plan_mutations(TOKENIZED_PAYLOAD)
    assert {mutation for _, mutation in plan} == set(MUTATION_CLASSES)
    # The five named in the build doc are all inside the exported catalogue.
    assert set(DOC_MUTATION_CLASSES) <= set(MUTATION_CLASSES)


async def test_mock_provider_emits_every_mutation_class() -> None:
    output = await MockProvider().complete("sys", TOKENIZED_PAYLOAD, model="mock-1")
    emitted = set()
    for token, mutation in plan_mutations(TOKENIZED_PAYLOAD):
        assert render_mutation(token, mutation) in output, (token, mutation)
        emitted.add(mutation)
    assert emitted == set(MUTATION_CLASSES)


def test_each_mutation_renders_the_shape_the_restorer_must_tolerate() -> None:
    token = "[PHI_NAME_1a2b3c4d]"
    assert render_mutation(token, "possessive") == "[PHI_NAME_1a2b3c4d]'s"
    assert render_mutation(token, "bold") == "**[PHI_NAME_1a2b3c4d]**"
    assert render_mutation(token, "upper_hash") == "[PHI_NAME_1A2B3C4D]"
    assert render_mutation(token, "bracket_dropped") == "PHI_NAME_1a2b3c4d"
    assert render_mutation(token, "verbatim") == token
    annotated = "[PHI_MEDICATION_2f4a1b3c|oral-antidiabetic]"
    assert render_mutation(annotated, "hint_stripped") == "[PHI_MEDICATION_2f4a1b3c]"


def test_every_rendered_mutation_is_matchable_by_the_restorers_grammar() -> None:
    """The claim the test above only *names*, asserted against the real matcher.

    "The shape the restorer must tolerate" is a statement about
    ``surrogates.TOKEN_RE``, and until it was checked against ``TOKEN_RE`` the
    fixture could carry -- and did carry -- a token the restorer cannot match.
    Every mutation the mock assigns must be matchable, and must still carry the
    same 8-hex ID, because restoration keys on that ID alone.
    """
    for token, mutation in plan_mutations(TOKENIZED_PAYLOAD):
        rendered = render_mutation(token, mutation)
        match = TOKEN_RE.search(rendered)
        assert match is not None, (token, mutation, rendered)
        expected = token.strip("[]").split("|")[0].rsplit("_", 1)[-1]
        assert match.group(3).lower() == expected.lower(), (mutation, rendered)


def test_the_build_docs_shortened_example_hash_cannot_be_issued() -> None:
    """Why the fixture above uses 8 hex where the build doc's prose uses 4.

    ``[PHI_MEDICATION_2f4a|oral-antidiabetic]`` appears verbatim in sections
    9.3, 9.5.2 and 10.7, and 10.7 lists it among the forms that must restore.
    It cannot be minted, so there is never anything behind it to restore -- and
    the mock accepts it only so the doc's illustration is recognised rather than
    silently ignored.
    """
    assert SURROGATE_TOKEN_RE.fullmatch("[PHI_MEDICATION_2f4a|oral-antidiabetic]")
    with pytest.raises(ConfigError) as excinfo:
        format_surrogate("PHI", "MEDICATION", "2f4a", "oral-antidiabetic")
    assert excinfo.value.detail["reason"] == "malformed_token_id"
    # No fixture in this file relies on the unmintable form any more.
    for surrogate in SURROGATES:
        assert TOKEN_RE.search(surrogate) is not None, surrogate


async def test_mock_provider_echoes_every_input_token() -> None:
    output = await MockProvider().complete("sys", TOKENIZED_PAYLOAD, model="mock-1")
    tokens = find_tokens(TOKENIZED_PAYLOAD)
    assert set(tokens) == set(SURROGATES)
    plan = dict(plan_mutations(TOKENIZED_PAYLOAD))
    for token in tokens:
        assert render_mutation(token, plan[token]) in output, token


async def test_mock_provider_preserves_every_token_hash() -> None:
    """Whatever the mutation, the hash survives -- restoration keys on it alone."""
    output = (await MockProvider().complete("sys", TOKENIZED_PAYLOAD, model="m")).lower()
    for token in find_tokens(TOKENIZED_PAYLOAD):
        token_hash = token.strip("[]").split("|")[0].rsplit("_", 1)[-1]
        assert token_hash.lower() in output, token_hash


async def test_mock_provider_emits_exactly_one_coreference_sentence() -> None:
    output = await MockProvider().complete("sys", TOKENIZED_PAYLOAD, model="mock-1")
    assert output.count(COREFERENCE_SENTENCE) == 1


def test_mock_output_is_a_pure_function_of_the_payload() -> None:
    """No randomness, no clock: identical in, identical out; new token, new line."""
    assert build_response(TOKENIZED_PAYLOAD) == build_response(TOKENIZED_PAYLOAD)
    assert build_response("") == build_response("")
    extended = build_response(f"{TOKENIZED_PAYLOAD}\nAlso noted: [PHI_ALLERGY_5566aabb].")
    assert extended != build_response(TOKENIZED_PAYLOAD)
    assert "[PHI_ALLERGY_5566aabb]" in extended.replace("**", "")


# ---------------------------------------------------------------------------
# MockProvider -- quoting token-free lines
# ---------------------------------------------------------------------------


async def test_pseudonymization_payload_has_no_surrogate_tokens() -> None:
    assert find_tokens(PSEUDONYMIZED_PAYLOAD) == ()
    assert plan_mutations(PSEUDONYMIZED_PAYLOAD) == ()


async def test_mock_provider_echoes_salient_lines_when_no_tokens_found() -> None:
    output = await MockProvider().complete("sys", PSEUDONYMIZED_PAYLOAD, model="mock-1")
    # The restorer needs the surrogate strings back verbatim as anchors.
    assert "Marisol Ferraro" in output
    assert "Halloran v. Brightwater" in output
    assert "metformin" in output
    assert output.count(COREFERENCE_SENTENCE) == 1


async def test_mock_quotes_token_free_lines_even_when_the_payload_has_tokens() -> None:
    """The gap this closes: a real pseudonymization payload is BOTH shapes at once.

    Tier-1 entities become realistic fakes in prose and Tier-3 entities become
    class-annotated tokens (build doc 9.3), so the payload carries fakes *and*
    tokens. Branching on "are there any tokens?" therefore took the token branch
    on every real pseudonymization run, quoted no fakes at all, and left the
    restorer's surrogate pass with nothing to anchor on end to end. Measured on
    the shipped fixtures before the fix: 0 of 14, 0 of 18 and 0 of 19 Tier-1/2
    fakes were ever echoed.
    """
    output = await MockProvider().complete("sys", MIXED_TIER_PAYLOAD, model="mock-1")

    # Tokens: still echoed exactly once each, under their assigned mutation.
    for token, mutation in plan_mutations(MIXED_TIER_PAYLOAD):
        assert render_mutation(token, mutation) in output, (token, mutation)
    # Fakes: now echoed too, which is what gives the surrogate pass its anchors.
    for fake in ("Marisol Ferraro", "Northgate Family Medicine", "04/11/2019"):
        assert fake in output, fake
    assert EXCERPT_HEADER in output
    assert output.count(COREFERENCE_SENTENCE) == 1


async def test_quoted_lines_never_carry_a_token() -> None:
    """Quoting a token line verbatim would smuggle in an un-mutated second copy.

    The mutation catalogue is the whole point of the mock: a verbatim token
    restores whether or not the mangled forms do, so an extra clean copy would
    quietly weaken every restoration assertion downstream. Checked against both
    grammars -- the mock's own and the restorer's tolerant one.
    """
    output = await MockProvider().complete("sys", MIXED_TIER_PAYLOAD, model="mock-1")
    quoted = [line[2:] for line in output.splitlines() if line.startswith("- ")]
    excerpts = [line for line in quoted if line in MIXED_TIER_PAYLOAD]

    assert excerpts, "no line was quoted verbatim, so this test proves nothing"
    for line in excerpts:
        assert SURROGATE_TOKEN_RE.search(line) is None, line
        assert TOKEN_RE.search(line) is None, line

    # And the payload really did contain token lines that were therefore skipped.
    assert any(SURROGATE_TOKEN_RE.search(line) for line in MIXED_TIER_PAYLOAD.splitlines())


async def test_quoting_is_still_deterministic_with_tokens_present() -> None:
    provider = MockProvider()
    outputs = [await provider.complete("sys", MIXED_TIER_PAYLOAD, model="mock-1") for _ in range(3)]
    assert len(set(outputs)) == 1
    assert outputs[0] == build_response(MIXED_TIER_PAYLOAD)


async def test_pseudonymization_fallback_is_deterministic() -> None:
    first = await MockProvider().complete("sys", PSEUDONYMIZED_PAYLOAD, model="mock-1")
    second = await MockProvider().complete("sys", PSEUDONYMIZED_PAYLOAD, model="mock-1")
    assert first == second


async def test_mock_provider_survives_an_empty_payload() -> None:
    output = await MockProvider().complete("sys", "", model="mock-1")
    assert output.count(COREFERENCE_SENTENCE) == 1


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------


def test_build_provider_returns_mock_for_mock_setting(
    settings_factory: Callable[..., Settings],
) -> None:
    provider = build_provider(settings_factory(llm_provider="mock"))
    assert isinstance(provider, MockProvider)
    assert provider.name == "mock"


def test_build_provider_returns_anthropic_for_anthropic_setting(
    settings_factory: Callable[..., Settings],
) -> None:
    provider = build_provider(settings_factory(llm_provider="anthropic"))
    assert isinstance(provider, AnthropicProvider)
    assert provider.name == "anthropic"


def test_mock_provider_satisfies_both_protocols() -> None:
    provider = MockProvider()
    assert isinstance(provider, LLMProvider)
    assert isinstance(provider, DetailedLLMProvider)


def test_dispatch_is_data_driven(
    registry: dict[str, Any], settings_factory: Callable[..., Settings]
) -> None:
    """Swapping the entry swaps the provider -- no branch in build_provider."""

    class Dummy(MockProvider):
        name: str = "dummy"

    registry["mock"] = Dummy
    provider = build_provider(settings_factory(llm_provider="mock"))
    assert isinstance(provider, Dummy)


def test_new_provider_name_is_selectable_with_zero_other_changes(
    registry: dict[str, Any],
) -> None:
    """The whole cost of adding OpenAI later: one class, one registry entry."""

    class Dummy:
        name: str = "dummy"

        def __init__(self, settings: Settings | None = None) -> None:
            self.settings = settings

        async def complete(
            self, system: str, user: str, *, model: str, timeout_s: float = 60.0
        ) -> str:
            return "dummy"

        async def complete_detailed(
            self, system: str, user: str, *, model: str, timeout_s: float = 60.0
        ) -> LLMResponse:
            return LLMResponse(text="dummy", input_tokens=1, output_tokens=1, model=model)

    registry["dummy"] = Dummy

    # Built through the VALIDATED constructor, from the environment variable a
    # deployer would actually set. `Settings.model_construct(...)` is pydantic's
    # validation-BYPASS path, and using it here meant this test could not observe
    # the one thing it exists to prove: `llm_provider` was a closed
    # `Literal["mock", "anthropic"]`, so `SCP_LLM_PROVIDER=dummy` raised
    # `literal_error` and a third-party provider was registrable but never
    # selectable. The test asserted "zero other changes" while stepping around the
    # change that was required.
    settings = Settings(
        master_key=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        llm_provider="dummy",
    )
    provider = build_provider(settings)
    assert isinstance(provider, Dummy)
    assert isinstance(provider, DetailedLLMProvider)


def test_unknown_provider_raises_config_error(registry: dict[str, Any]) -> None:
    registry.pop("mock", None)
    with pytest.raises(ConfigError) as excinfo:
        build_provider(Settings.model_construct(llm_provider="mock"))
    assert excinfo.value.detail["reason"] == "unknown_llm_provider"


def test_a_failed_builtin_import_stays_retryable(
    registry: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """One bad import must not latch "no providers" for the life of the process.

    Setting the loaded-flag before the imports run makes a single transient
    import failure permanent: the registry stays empty, every later call returns
    without retrying, and the real cause finally surfaces from
    ``build_provider`` as ``unknown_llm_provider`` -- pointing a reader at the
    settings file instead of at the module that actually failed.
    """
    import secure_context_pipeline.llm.base as module

    original_modules = module.BUILTIN_PROVIDER_MODULES
    monkeypatch.setattr(module, "_builtins_loaded", False)
    monkeypatch.setattr(
        module, "BUILTIN_PROVIDER_MODULES", ("secure_context_pipeline.llm.no_such_module",)
    )

    with pytest.raises(ModuleNotFoundError):
        load_builtin_providers()
    assert module._builtins_loaded is False, "a failed load must not mark itself done"

    # Retryable means retryable: the second call really does try again, instead
    # of returning silently and leaving the registry empty forever.
    with pytest.raises(ModuleNotFoundError):
        load_builtin_providers()

    monkeypatch.setattr(module, "BUILTIN_PROVIDER_MODULES", original_modules)
    load_builtin_providers()
    assert module._builtins_loaded is True
    assert {"mock", "anthropic"} <= set(registry)


# ---------------------------------------------------------------------------
# AnthropicProvider -- construction and request shape
# ---------------------------------------------------------------------------


def test_client_is_built_with_max_retries_zero(
    settings_factory: Callable[..., Settings],
) -> None:
    """Our backoff must be the only retry in play -- no double-retry."""
    provider = AnthropicProvider(settings_factory(llm_provider="anthropic"))
    assert provider._client.max_retries == 0
    assert provider.max_attempts == MAX_ATTEMPTS


async def test_injected_http_client_is_used(
    settings_factory: Callable[..., Settings],
) -> None:
    """The seam that lets demo.py --dump-wire capture the literal outbound body."""
    captured: list[bytes] = []

    async def capture(request: httpx.Request) -> None:
        captured.append(request.content)

    http_client = httpx.AsyncClient(event_hooks={"request": [capture]})
    try:
        provider = AnthropicProvider(
            settings_factory(llm_provider="anthropic"), http_client=http_client
        )
        assert provider._client._client is http_client
        assert provider._client._client.event_hooks["request"] == [capture]
    finally:
        await http_client.aclose()


def test_missing_api_key_raises_config_error(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(api_key=None, llm_provider="mock")
    with pytest.raises(ConfigError) as excinfo:
        AnthropicProvider(settings)
    assert excinfo.value.detail["reason"] == "anthropic_api_key_missing"


async def test_request_omits_removed_params_and_sets_low_effort(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    provider, fake = stubbed_provider(settings, [make_message()])

    await provider.complete("SYSTEM", "USER", model="claude-opus-5", timeout_s=12.5)

    sent = fake.messages.calls[0]
    # Removed on this model family -- any of these returns HTTP 400.
    for banned in ("temperature", "top_p", "top_k", "thinking"):
        assert banned not in sent, banned
    assert sent["output_config"] == {"effort": EFFORT}
    assert sent["max_tokens"] == settings.llm_max_tokens == 16000
    assert sent["model"] == "claude-opus-5"
    assert sent["system"] == "SYSTEM"
    assert sent["messages"] == [{"role": "user", "content": "USER"}]
    assert sent["timeout"] == 12.5


async def test_wire_level_request_body_through_the_real_sdk(
    settings_factory: Callable[..., Settings],
) -> None:
    """Drive the genuine SDK over a mock transport -- no stubbed client, no socket.

    The stubbed-client tests above only prove what we *hand* the SDK. This proves
    what the SDK actually puts on the wire, which is the claim the demo's
    ``--dump-wire`` mode makes to a reviewer.
    """
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "msg_wire",
                "type": "message",
                "role": "assistant",
                "model": "claude-opus-5",
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "content": [
                    {"type": "thinking", "thinking": "hidden", "signature": "sig"},
                    {"type": "text", "text": "wire-level text"},
                ],
                "usage": {"input_tokens": 77, "output_tokens": 5},
            },
        )

    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        response = await provider.complete_detailed(
            "SYS", "USER", model="claude-opus-5", timeout_s=9.0
        )

    body = captured["body"]
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert body["output_config"] == {"effort": EFFORT}
    assert body["max_tokens"] == 16000
    assert body["model"] == "claude-opus-5"
    assert body["system"] == "SYS"
    assert body["messages"] == [{"role": "user", "content": "USER"}]
    for banned in ("temperature", "top_p", "top_k", "thinking"):
        assert banned not in body, banned

    # And the real SDK response parser walks past the thinking block.
    assert response.text == "wire-level text"
    assert (response.input_tokens, response.output_tokens) == (77, 5)


def _message_json(**overrides: Any) -> dict[str, Any]:
    """A minimal Messages-API response body, as JSON on the wire."""
    body: dict[str, Any] = {
        "id": "msg_wire",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "content": [{"type": "text", "text": "ok"}],
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }
    body.update(overrides)
    return body


async def test_wire_level_request_carries_the_expected_headers_and_no_streaming(
    settings_factory: Callable[..., Settings],
) -> None:
    """Request shape includes what is *around* the JSON, not just the JSON.

    A reviewer asking "is this the real API contract?" is asking about the
    version header and the auth mechanism as much as the body -- and about what
    is absent: no ``stream``, and the key never in the URL or a query string.
    """
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=_message_json())

    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        await provider.complete("SYS", "USER", model="claude-opus-5")

    assert seen["method"] == "POST"
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["x-api-key"] == FAKE_API_KEY
    assert seen["headers"]["anthropic-version"]
    assert seen["headers"]["content-type"].startswith("application/json")
    # No Authorization bearer, and the key is nowhere near the URL.
    assert "authorization" not in seen["headers"]
    assert FAKE_API_KEY not in seen["url"]
    # Non-streaming: the pipeline needs the whole answer before it can restore it.
    assert "stream" not in seen["body"] or seen["body"]["stream"] is False


async def test_wire_level_529_overloaded_is_retried_then_succeeds(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    """ "What happens on a 529?" answered through the real SDK, not a stub.

    529 (overloaded) has no dedicated exception class in the SDK's status map, so
    it arrives as the generic ``>=500`` case. Classifying by status as well as by
    class is what keeps it retryable; classifying by class name alone would have
    turned a transient overload into a hard failure.
    """
    statuses: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if len(statuses) < 2:
            statuses.append(529)
            return httpx.Response(
                529, json={"type": "error", "error": {"type": "overloaded_error"}}
            )
        statuses.append(200)
        return httpx.Response(
            200,
            json=_message_json(content=[{"type": "text", "text": "back online"}]),
        )

    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        response = await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert statuses == [529, 529, 200]
    assert response.text == "back online"
    assert len(sleep_recorder) == 2
    assert all(0.0 < delay <= MAX_BACKOFF_S for delay in sleep_recorder)


async def test_wire_level_529_gives_up_after_max_attempts(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    """A persistent overload fails as a classified transport error, not a hang."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(529, json={"type": "error", "error": {"type": "overloaded_error"}})

    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        with pytest.raises(LLMTransportError) as excinfo:
            await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert calls == MAX_ATTEMPTS
    assert excinfo.value.detail["status_code"] == 529
    assert excinfo.value.detail["reason"] == "server_error"
    assert excinfo.value.detail["attempts"] == MAX_ATTEMPTS
    assert len(sleep_recorder) == MAX_ATTEMPTS - 1


async def test_wire_level_refusal_is_surfaced_without_its_content(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    """A refusal parsed by the real SDK, including ``stop_details``.

    The stubbed test above constructs ``RefusalStopDetails`` by hand, which
    proves our decoding but not that the field survives the wire. Here it comes
    back as JSON and the SDK parses it -- and the refusal is terminal, so it must
    not be retried and must not carry the partial content or the explanation into
    the exception: the payload derives from a customer document.
    """
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json=_message_json(
                stop_reason="refusal",
                stop_details={
                    "type": "refusal",
                    "category": "cyber",
                    "explanation": "a long explanation naming SECRET PARTIAL",
                },
                content=[{"type": "text", "text": "SECRET PARTIAL"}],
            ),
        )

    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        with pytest.raises(LLMRefusalError) as excinfo:
            await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert calls == 1, "a refusal is a decision, not a transient failure"
    assert sleep_recorder == []
    error = excinfo.value
    assert error.detail["category"] == "cyber"
    assert error.detail["stop_reason"] == "refusal"
    rendered = f"{error}{error!r}"
    assert "SECRET PARTIAL" not in rendered
    assert "explanation" not in rendered


async def test_wire_level_truncated_answer_is_returned_and_flagged(
    settings_factory: Callable[..., Settings], caplog: pytest.LogCaptureFixture
) -> None:
    """``max_tokens`` degrades the answer; it does not fail the request.

    Returning it is the right call -- a truncated answer with its values restored
    beats no answer -- but it is logged distinctly, because a truncated response
    can end mid-token and leave debris no grammar will match.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_message_json(
                stop_reason="max_tokens",
                content=[{"type": "text", "text": "The chart lists [PHI_NAME_1a2b"}],
            ),
        )

    caplog.set_level(logging.WARNING, logger="secure_context_pipeline.llm.anthropic_provider")
    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        response = await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert response.text == "The chart lists [PHI_NAME_1a2b"
    assert "LLM_TRUNCATED" in caplog.text
    # The debris a reviewer would ask about: not a disclosure, because the ID is
    # synthetic and only half of it arrived -- and no grammar claims it.
    assert TOKEN_RE.search(response.text) is None


async def test_wire_level_empty_content_raises_rather_than_returning_blank(
    settings_factory: Callable[..., Settings],
) -> None:
    """A 200 with only a thinking block is not an answer."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_message_json(
                content=[{"type": "thinking", "thinking": "only thinking", "signature": "s"}]
            ),
        )

    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        with pytest.raises(LLMResponseError) as excinfo:
            await provider.complete_detailed("s", "u", model="claude-opus-5")
    assert excinfo.value.detail["reason"] == "no_text_blocks"


async def test_wire_level_400_is_not_retried(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    """The other side of the retry set, proven at the same level as the 529."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            400, json={"type": "error", "error": {"type": "invalid_request_error"}}
        )

    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        with pytest.raises(LLMTransportError) as excinfo:
            await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert calls == 1
    assert sleep_recorder == []
    assert excinfo.value.detail["status_code"] == 400


async def test_no_payload_bytes_reach_the_logs_on_any_wire_outcome(
    settings_factory: Callable[..., Settings],
    sleep_recorder: list[float],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Build doc section 16, checked across every terminal path at once.

    The provider is the last place a payload could escape into an operator's
    console, so the no-content rule is asserted over the whole set of outcomes
    rather than one at a time.
    """
    secret_system = "SYSTEM Marisol Ferraro 123-45-6789"
    secret_user = "USER Northgate Family Medicine 4471902"
    responses: list[httpx.Response] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    cases: list[tuple[list[httpx.Response], type[BaseException] | None]] = [
        ([httpx.Response(200, json=_message_json())], None),
        ([httpx.Response(529, json={}) for _ in range(MAX_ATTEMPTS)], LLMTransportError),
        ([httpx.Response(400, json={})], LLMTransportError),
        (
            [
                httpx.Response(
                    200,
                    json=_message_json(
                        stop_reason="refusal",
                        stop_details={
                            "type": "refusal",
                            "category": "cyber",
                            "explanation": secret_user,
                        },
                    ),
                )
            ],
            LLMRefusalError,
        ),
        ([httpx.Response(200, json=_message_json(content=[]))], LLMResponseError),
    ]

    caplog.set_level(logging.DEBUG)
    settings = settings_factory(llm_provider="anthropic")
    for script, expected in cases:
        responses = list(script)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            provider = AnthropicProvider(settings, http_client=http_client)
            if expected is None:
                await provider.complete("s", "u", model="claude-opus-5")
            else:
                with pytest.raises(expected) as excinfo:
                    await provider.complete_detailed(
                        secret_system, secret_user, model="claude-opus-5"
                    )
                rendered = f"{excinfo.value}{excinfo.value!r}"
                for fragment in ("Marisol", "Northgate", "123-45-6789", "4471902"):
                    assert fragment not in rendered, (fragment, rendered)

    for fragment in ("Marisol", "Northgate", "123-45-6789", "4471902"):
        assert fragment not in caplog.text, fragment


async def test_the_sdks_own_debug_stream_cannot_echo_the_request_body(
    settings_factory: Callable[..., Settings], caplog: pytest.LogCaptureFixture
) -> None:
    """The SDK logs the entire outbound body at DEBUG. That is muzzled on import.

    ``anthropic._base_client`` emits ``"Request options: %s"`` with ``system`` and
    ``messages`` in full, on every call and every retry. Build doc section 16
    forbids content in logs with no exception for debug paths, and the detector
    already applies exactly this muzzle to Presidio's context-word logging -- so
    the same rule, applied the same way, to the other third-party library that
    logs text. Turning the level back up must not undo it, which is why the
    filter is attached rather than the level merely lowered.
    """
    for name in (ANTHROPIC_LOGGER_NAME, "anthropic._base_client"):
        logging.getLogger(name).setLevel(logging.DEBUG)  # a host app's debug flag

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_message_json())

    caplog.set_level(logging.DEBUG)
    settings = settings_factory(llm_provider="anthropic")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        provider = AnthropicProvider(settings, http_client=http_client)
        await provider.complete("SYSTEM Marisol Ferraro", "USER 123-45-6789", model="claude-opus-5")

    assert "Request options" not in caplog.text
    assert "Marisol Ferraro" not in caplog.text
    assert "123-45-6789" not in caplog.text
    # Our own INFO line still gets through: the muzzle is sub-INFO only.
    assert "LLM_CALL model=claude-opus-5" in caplog.text


# ---------------------------------------------------------------------------
# AnthropicProvider -- retry policy (no network)
# ---------------------------------------------------------------------------


async def test_rate_limit_is_retried_twice_then_succeeds(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    script: list[Any] = [
        status_error(anthropic.RateLimitError, 429),
        status_error(anthropic.RateLimitError, 429),
        make_message(content=[TextBlock(type="text", text="recovered", citations=None)]),
    ]
    provider, fake = stubbed_provider(settings, script)

    response = await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert response.text == "recovered"
    assert len(fake.messages.calls) == 3 == MAX_ATTEMPTS
    assert len(sleep_recorder) == 2


async def test_server_error_is_retried_and_gives_up_after_max_attempts(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    script: list[Any] = [status_error(anthropic.InternalServerError, 503) for _ in range(3)]
    provider, fake = stubbed_provider(settings, script)

    with pytest.raises(LLMTransportError) as excinfo:
        await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert len(fake.messages.calls) == MAX_ATTEMPTS
    assert len(sleep_recorder) == MAX_ATTEMPTS - 1
    assert excinfo.value.detail["reason"] == "server_error"
    assert excinfo.value.detail["attempts"] == MAX_ATTEMPTS


async def test_timeout_is_retried(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    script: list[Any] = [
        anthropic.APITimeoutError(request=request),
        make_message(content=[TextBlock(type="text", text="late but fine", citations=None)]),
    ]
    provider, fake = stubbed_provider(settings, script)

    response = await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert response.text == "late but fine"
    assert len(fake.messages.calls) == 2
    assert len(sleep_recorder) == 1


async def test_bad_request_is_not_retried(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    """4xx other than 429 will not become valid by being sent again."""
    settings = settings_factory(llm_provider="anthropic")
    script: list[Any] = [status_error(anthropic.BadRequestError, 400), make_message()]
    provider, fake = stubbed_provider(settings, script)

    with pytest.raises(LLMTransportError) as excinfo:
        await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert len(fake.messages.calls) == 1
    assert sleep_recorder == []
    assert excinfo.value.detail["reason"] == "client_error"
    assert excinfo.value.detail["status_code"] == 400
    assert excinfo.value.detail["attempts"] == 1


@pytest.mark.parametrize("status", [401, 403, 404, 422])
async def test_other_4xx_statuses_are_not_retried(
    status: int, settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    provider, fake = stubbed_provider(settings, [status_error(anthropic.APIStatusError, status)])
    with pytest.raises(LLMTransportError):
        await provider.complete_detailed("s", "u", model="claude-opus-5")
    assert len(fake.messages.calls) == 1
    assert sleep_recorder == []


async def test_a_429_that_is_not_a_ratelimiterror_is_still_retried(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    """Retryability is a property of the response, not of the SDK's class choice.

    ``RateLimitError`` is only how *today's* SDK renders a 429.  If a 429 ever
    arrives as the plain ``APIStatusError`` parent -- a changed status-to-class
    mapping, a proxy, a wrapper -- classifying it by class alone downgrades a
    routine rate limit into a hard, un-retried failure.
    """
    settings = settings_factory(llm_provider="anthropic")
    script: list[Any] = [
        status_error(anthropic.APIStatusError, 429),
        make_message(content=[TextBlock(type="text", text="recovered", citations=None)]),
    ]
    provider, fake = stubbed_provider(settings, script)

    response = await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert response.text == "recovered"
    assert len(fake.messages.calls) == 2
    assert len(sleep_recorder) == 1


def test_retry_set_is_decided_by_status_as_well_as_by_class() -> None:
    """429 and 408 are retryable by number; every other 4xx is not."""
    assert classify_error(status_error(anthropic.APIStatusError, 429)) == (
        True,
        "rate_limit",
        429,
    )
    # 408 is a timeout the server reported rather than one the client observed.
    assert classify_error(status_error(anthropic.APIStatusError, 408)) == (
        True,
        "timeout",
        408,
    )
    for status in (400, 401, 403, 404, 409, 410, 422):
        assert classify_error(status_error(anthropic.APIStatusError, status)) == (
            False,
            "client_error",
            status,
        ), status


def test_classification_uses_typed_exceptions_not_message_text() -> None:
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    assert classify_error(status_error(anthropic.RateLimitError, 429)) == (
        True,
        "rate_limit",
        429,
    )
    assert classify_error(status_error(anthropic.APIStatusError, 500))[0] is True
    assert classify_error(status_error(anthropic.APIStatusError, 400))[0] is False
    assert classify_error(anthropic.APITimeoutError(request=request)) == (
        True,
        "timeout",
        None,
    )
    assert classify_error(anthropic.APIConnectionError(request=request)) == (
        True,
        "connection_error",
        None,
    )


async def test_backoff_is_bounded_and_non_decreasing(
    settings_factory: Callable[..., Settings], sleep_recorder: list[float]
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    script: list[Any] = [status_error(anthropic.RateLimitError, 429) for _ in range(3)]
    provider, _ = stubbed_provider(settings, script)

    with pytest.raises(LLMTransportError):
        await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert len(sleep_recorder) == MAX_ATTEMPTS - 1
    for delay in sleep_recorder:
        assert 0.0 < delay <= MAX_BACKOFF_S
    # Exponential: the second wait is longer than the first even at worst-case jitter.
    assert sleep_recorder[1] > sleep_recorder[0]


def test_backoff_delay_never_exceeds_the_cap() -> None:
    for attempt in range(1, 25):
        delay = backoff_delay(attempt)
        assert 0.0 < delay <= MAX_BACKOFF_S


# ---------------------------------------------------------------------------
# AnthropicProvider -- response decoding
# ---------------------------------------------------------------------------


async def test_text_is_collected_past_a_leading_thinking_block(
    settings_factory: Callable[..., Settings],
) -> None:
    """content[0] is never indexed blindly."""
    settings = settings_factory(llm_provider="anthropic")
    message = make_message(
        content=[
            ThinkingBlock(type="thinking", thinking="internal", signature="sig"),
            TextBlock(type="text", text="first half. ", citations=None),
            TextBlock(type="text", text="second half.", citations=None),
        ]
    )
    provider, _ = stubbed_provider(settings, [message])

    response = await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert response.text == "first half. second half."
    assert "internal" not in response.text


async def test_usage_is_captured_into_the_response(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    message = make_message(input_tokens=4242, output_tokens=99, model="claude-opus-5")
    provider, _ = stubbed_provider(settings, [message])

    response = await provider.complete_detailed("s", "u", model="claude-opus-5")

    assert response.input_tokens == 4242
    assert response.output_tokens == 99
    assert response.total_tokens == 4341
    assert response.model == "claude-opus-5"


async def test_refusal_raises_a_structured_pipeline_error(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    message = make_message(
        content=[TextBlock(type="text", text="SECRET PARTIAL", citations=None)],
        stop_reason="refusal",
        stop_details=RefusalStopDetails(
            type="refusal", category="cyber", explanation="a long explanation"
        ),
    )
    provider, _ = stubbed_provider(settings, [message])

    with pytest.raises(LLMRefusalError) as excinfo:
        await provider.complete_detailed("s", "u", model="claude-opus-5")

    error = excinfo.value
    assert isinstance(error, PipelineError)
    assert error.detail["category"] == "cyber"
    assert error.detail["stop_reason"] == "refusal"
    # No content, no explanation.
    assert "SECRET PARTIAL" not in str(error)
    assert "a long explanation" not in str(error)


async def test_empty_content_raises_rather_than_returning_blank(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    message = make_message(
        content=[ThinkingBlock(type="thinking", thinking="only thinking", signature="s")]
    )
    provider, _ = stubbed_provider(settings, [message])

    with pytest.raises(LLMResponseError) as excinfo:
        await provider.complete_detailed("s", "u", model="claude-opus-5")
    assert excinfo.value.detail["reason"] == "no_text_blocks"


async def test_complete_delegates_to_complete_detailed(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(llm_provider="anthropic")
    message = make_message(content=[TextBlock(type="text", text="hello", citations=None)])
    provider, _ = stubbed_provider(settings, [message])
    assert await provider.complete("s", "u", model="claude-opus-5") == "hello"


# ---------------------------------------------------------------------------
# No-content-in-logs guarantees
# ---------------------------------------------------------------------------


def test_llm_response_repr_masks_the_model_output() -> None:
    response = LLMResponse(
        text="Marisol Ferraro was seen on 2026-01-04",
        input_tokens=10,
        output_tokens=20,
        model="claude-opus-5",
    )
    for rendered in (repr(response), str(response), f"{response}"):
        assert "Marisol" not in rendered
        assert "***" in rendered
        assert "input_tokens=10" in rendered


def test_transport_error_carries_only_machine_detail() -> None:
    error = LLMTransportError(
        model="claude-opus-5", reason="rate_limit", attempts=3, status_code=429
    )
    rendered = str(error)
    assert "claude-opus-5" in rendered
    assert set(error.detail) == {"model", "reason", "attempts", "status_code"}


# ---------------------------------------------------------------------------
# Real-network smoke test -- skipped unless a key is present
# ---------------------------------------------------------------------------


@pytest.mark.real_llm
@pytest.mark.skipif(not os.getenv("ANTHROPIC_API_KEY"), reason="ANTHROPIC_API_KEY not set")
async def test_real_llm_smoke() -> None:
    settings = Settings(master_key=MASTER_KEY, llm_provider="anthropic")
    provider = AnthropicProvider(settings)
    response = await provider.complete_detailed(
        "Reply with the single word: acknowledged.",
        "Reply now.",
        model=settings.llm_model,
        timeout_s=settings.llm_timeout_s,
    )
    assert response.text.strip()
    assert response.input_tokens > 0
    assert response.output_tokens > 0
    assert response.model
