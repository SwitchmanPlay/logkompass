from __future__ import annotations

from pathlib import Path

from helpers import GOOD_FIVE_LINES, StubTransport, sample_aggregate

from logkompass.config import Provider
from logkompass.digest import (
    five_lines,
    format_message,
    looks_like_reasoning,
    make_digest,
    render_template,
    validate,
)
from logkompass.llm import LlmClient

GOLDEN = Path(__file__).parent / "fixtures" / "golden_digest.txt"


def client_for(transport, name="local"):
    provider = Provider(name=name, base_url="http://127.0.0.1:8081/v1", model="qwen3-27b")
    return LlmClient([provider], transport=transport, retries=0)


def test_template_digest_matches_the_golden_file():
    result = make_digest(sample_aggregate(), client=None)
    assert result.path == "template_fallback"
    assert format_message(result).splitlines()[:-1] == GOLDEN.read_text().splitlines()[:-1]


def test_template_always_returns_five_lines():
    assert len(render_template(sample_aggregate())) == 5
    empty = {"day": "2026-09-20", "host": "h", "totals": {}, "comparison": {}}
    assert len(render_template(empty)) == 5


def test_model_output_is_used_when_it_validates():
    result = make_digest(sample_aggregate(), client=client_for(StubTransport([GOOD_FIVE_LINES])))
    assert result.path == "local_llm"
    assert result.provider == "local"
    assert len(result.lines) == 5
    assert "model: " in format_message(result)


def test_cloud_provider_is_labelled_as_cloud():
    transport = StubTransport([GOOD_FIVE_LINES])
    result = make_digest(
        sample_aggregate(), client=client_for(transport, name="openrouter-free")
    )
    assert result.path == "cloud_llm"


def test_hallucinated_ip_is_rejected_and_template_takes_over():
    bad = GOOD_FIVE_LINES.replace("198.51.100.7", "10.13.37.66")
    result = make_digest(sample_aggregate(), client=client_for(StubTransport([bad])))
    assert result.path == "template_fallback"
    assert "not in the aggregate" in " ".join(result.errors)
    assert "failed validation" in format_message(result)


def test_short_answer_is_rejected():
    result = make_digest(sample_aggregate(), client=client_for(StubTransport(["one line only"])))
    assert result.path == "template_fallback"
    assert "fewer than five" in " ".join(result.errors)


def test_unreachable_model_falls_back_and_reports_the_error():
    transport = StubTransport(error=OSError("connection refused"))
    result = make_digest(sample_aggregate(), client=client_for(transport))
    assert result.path == "template_fallback"
    assert "connection refused" in " ".join(result.errors)
    assert "model unreachable" in format_message(result) or result.notice


def test_markdown_bullets_are_stripped():
    text = "\n".join(f"- line {i}" for i in range(1, 6))
    assert five_lines(text) == [f"line {i}" for i in range(1, 6)]


def test_validate_accepts_ips_present_in_the_input():
    ok, reason = validate(sample_aggregate(), ["198.51.100.7 was loud"] * 5)
    assert ok and reason == "ok"


def test_validate_rejects_a_rambling_line():
    ok, _ = validate(sample_aggregate(), ["word " * 60] * 5)
    assert not ok


def test_format_message_can_mask_ips():
    result = make_digest(sample_aggregate(), client=None)
    assert "198.51.100.x" in format_message(result, mask=True)
    assert "198.51.100.7" not in format_message(result, mask=True)


# A real leaked sample: the model restated the task and echoed JSON fields
# instead of producing the five-line briefing.
LEAKED_REASONING = "\n".join(
    [
        "LogKompass honeypot-01, 2026-09-27",
        "The user wants a daily SSH briefing based on the JSON. I need to write five lines.",
        "Let me analyze the JSON:",
        "**Volume and comparison to 7-day average**:",
        "totals.events = 1858",
    ]
)


def test_reasoning_leak_is_detected_and_rejected():
    lines = LEAKED_REASONING.splitlines()
    assert looks_like_reasoning(lines) is True
    ok, reason = validate(sample_aggregate(), lines)
    assert ok is False and "reasoning" in reason


def test_clean_briefing_is_not_flagged_as_reasoning():
    assert looks_like_reasoning(GOOD_FIVE_LINES.splitlines()) is False


def test_make_digest_falls_back_to_template_on_reasoning_leak():
    transport = StubTransport(replies=[LEAKED_REASONING])
    result = make_digest(sample_aggregate(), client=client_for(transport))
    assert result.path == "template_fallback"
    assert any("reasoning" in e for e in result.errors)
