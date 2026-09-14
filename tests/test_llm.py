from __future__ import annotations

from helpers import StubTransport

from logkompass.config import Provider
from logkompass.llm import LlmClient, LlmError, extract_text, strip_thinking

LOCAL = Provider(
    name="local",
    base_url="http://127.0.0.1:8081/v1/",
    model="qwen3-27b",
    extra_body={"chat_template_kwargs": {"enable_thinking": False}},
)
CLOUD = Provider(
    name="openrouter-free",
    base_url="https://openrouter.ai/api/v1",
    model="free-model",
    api_key="secret",
)


def test_request_shape_and_thinking_switch():
    transport = StubTransport(["hello"])
    LlmClient([LOCAL], transport=transport, retries=0).complete("sys", "user")
    call = transport.calls[0]
    assert call["url"] == "http://127.0.0.1:8081/v1/chat/completions"
    assert call["payload"]["chat_template_kwargs"] == {"enable_thinking": False}
    assert call["payload"]["messages"][0]["role"] == "system"
    assert call["payload"]["stream"] is False
    assert "Authorization" not in call["headers"]


def test_api_key_becomes_a_bearer_header():
    transport = StubTransport(["hello"])
    LlmClient([CLOUD], transport=transport, retries=0).complete("sys", "user")
    assert transport.calls[0]["headers"]["Authorization"] == "Bearer secret"


def test_chain_falls_through_to_the_next_provider():
    calls = []

    def transport(url, payload, headers, timeout):
        calls.append(url)
        if "8081" in url:
            raise OSError("connection refused")
        return {"model": "free-model", "choices": [{"message": {"content": "cloud answer"}}]}

    result = LlmClient([LOCAL, CLOUD], transport=transport, retries=0).complete("s", "u")
    assert result.provider == "openrouter-free"
    assert result.text == "cloud answer"
    assert len(calls) == 2


def test_retry_happens_once_per_provider():
    transport = StubTransport(error=OSError("boom"))
    client = LlmClient([LOCAL], transport=transport, retries=1)
    try:
        client.complete("s", "u")
    except LlmError:
        pass
    assert len(transport.calls) == 2


def test_all_providers_failing_raises_with_details():
    client = LlmClient([LOCAL], transport=StubTransport(error=OSError("boom")), retries=0)
    try:
        client.complete("s", "u")
    except LlmError as error:
        assert "boom" in str(error)
    else:
        raise AssertionError("expected LlmError")


def test_unavailable_providers_are_skipped():
    disabled = Provider(
        name="cloud", base_url="https://x/v1", model="m", available=False,
        unavailable_reason="api key env var not set",
    )
    client = LlmClient([disabled], transport=StubTransport(["x"]), retries=0)
    try:
        client.complete("s", "u")
    except LlmError as error:
        assert "no usable LLM provider" in str(error)
    else:
        raise AssertionError("expected LlmError")


def test_thinking_blocks_are_removed():
    assert strip_thinking("<think>plan plan</think>\nreal answer") == "real answer"
    assert strip_thinking("stray reasoning</think>answer") == "answer"
    assert strip_thinking("clean") == "clean"


def test_empty_content_is_an_error():
    try:
        extract_text({"choices": [{"message": {"content": "<think>only thinking</think>"}}]})
    except LlmError:
        return
    raise AssertionError("expected LlmError")


def test_content_parts_are_joined():
    text = extract_text(
        {"choices": [{"message": {"content": [{"text": "a"}, {"text": "b"}]}}]}
    )
    assert text == "ab"
