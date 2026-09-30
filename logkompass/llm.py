"""OpenAI compatible chat client with an ordered provider chain.

Why a chain: the first provider is the local Qwen3 on the workstation. If it is off,
asleep or the RPC backend died, the next provider (a free hosted model, or none) takes
over. Whichever path ran is recorded, never hidden.

Stdlib only on purpose: one less dependency to install on a 1 GB free tier box.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .config import Provider

THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class LlmError(RuntimeError):
    pass


@dataclass
class LlmResult:
    text: str
    provider: str
    model: str
    latency_ms: int
    attempts: list[str] = field(default_factory=list)


def strip_thinking(text: str) -> str:
    """Qwen3 emits <think> blocks unless told not to. Never ship them to Telegram."""
    cleaned = THINK_RE.sub("", text or "")
    if "</think>" in cleaned:
        cleaned = cleaned.split("</think>", 1)[1]
    return cleaned.strip()


def default_transport(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8", "replace"))


def extract_text(response: dict) -> str:
    choices = response.get("choices") or []
    if not choices:
        raise LlmError("response contained no choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, list):  # some servers return content parts
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    text = strip_thinking(content or "")
    if not text:
        raise LlmError("response contained no text")
    return text


class LlmClient:
    def __init__(self, providers: list[Provider], transport=None, retries: int = 1) -> None:
        self.providers = [p for p in providers if p.available]
        self.transport = transport or default_transport
        self.retries = max(0, retries)
        self.attempts: list[str] = []

    def _payload(self, provider: Provider, system: str, user: str) -> dict:
        payload = {
            "model": provider.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": provider.temperature,
            "max_tokens": provider.max_tokens,
            "stream": False,
        }
        payload.update(provider.extra_body or {})
        return payload

    def _headers(self, provider: Provider) -> dict:
        headers = {"Content-Type": "application/json", "User-Agent": "logkompass/0.1"}
        if provider.api_key:
            headers["Authorization"] = f"Bearer {provider.api_key}"
        headers.update(provider.headers or {})
        return headers

    def complete(self, system: str, user: str, accept=None) -> LlmResult:
        """Return the first provider whose output is usable.

        ``accept`` is an optional ``str -> bool`` guard. When given, a provider
        that answers but whose text fails the guard (e.g. a reasoning leak or an
        ungrounded briefing) is treated like a failure, so the chain moves on to
        the next model instead of returning garbage.
        """
        self.attempts = []
        if not self.providers:
            raise LlmError("no usable LLM provider configured")
        for provider in self.providers:
            url = provider.base_url.rstrip("/") + "/chat/completions"
            for attempt in range(self.retries + 1):
                started = time.monotonic()
                try:
                    response = self.transport(
                        url,
                        self._payload(provider, system, user),
                        self._headers(provider),
                        provider.timeout_seconds,
                    )
                    text = extract_text(response)
                except Exception as error:  # noqa: BLE001 - any failure means: next provider
                    self.attempts.append(
                        f"{provider.name} attempt {attempt + 1}: {type(error).__name__}: {error}"
                    )
                    continue
                if accept is not None and not accept(text):
                    self.attempts.append(
                        f"{provider.name} attempt {attempt + 1}: rejected (unusable output)"
                    )
                    continue
                latency = int((time.monotonic() - started) * 1000)
                self.attempts.append(f"{provider.name} attempt {attempt + 1}: ok")
                return LlmResult(
                    text=text,
                    provider=provider.name,
                    model=response.get("model") or provider.model,
                    latency_ms=latency,
                    attempts=list(self.attempts),
                )
        raise LlmError("all providers failed: " + " | ".join(self.attempts))
