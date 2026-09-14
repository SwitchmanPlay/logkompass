"""Telegram sink. Stdlib only, chunked, quiet-hours aware."""

from __future__ import annotations

import json
import urllib.request

MAX_LEN = 3900


def chunks(text: str, size: int = MAX_LEN) -> list[str]:
    if len(text) <= size:
        return [text]
    out: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(current) + len(line) > size and current:
            out.append(current)
            current = ""
        current += line
    if current:
        out.append(current)
    return out


def default_transport(url: str, payload: dict, timeout: float = 30.0) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8", "replace"))


def send(
    token: str,
    chat_id: str,
    text: str,
    disable_notification: bool = False,
    transport=None,
) -> dict:
    if not token or not chat_id:
        raise ValueError("telegram token and chat_id are required")
    post = transport or default_transport
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    sent = 0
    for chunk in chunks(text):
        response = post(
            url,
            {
                "chat_id": chat_id,
                "text": chunk,
                "disable_notification": disable_notification,
                "disable_web_page_preview": True,
            },
        )
        if not response.get("ok", False):
            raise RuntimeError(f"telegram rejected the message: {response}")
        sent += 1
    return {"ok": True, "sink": "telegram", "chunks": sent, "silent": disable_notification}
