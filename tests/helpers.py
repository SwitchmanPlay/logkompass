"""Shared test builders. No network, no real log files, no real model."""

from __future__ import annotations

import itertools

from logkompass.models import Event
from logkompass.store import Store
from logkompass.util import sha1

_counter = itertools.count()


def make_event(
    ts: str = "2026-09-20T10:00:00Z",
    kind: str = "failed_password",
    ip: str | None = "198.51.100.7",
    username: str | None = "root",
    host: str = "canary-01",
    method: str | None = "password",
    key_fp: str | None = None,
    raw: str | None = None,
) -> Event:
    text = raw or f"synthetic {kind} {username} {ip} #{next(_counter)}"
    return Event(
        ts=ts,
        host=host,
        kind=kind,
        raw=text,
        raw_hash=sha1(text),
        username=username,
        ip=ip,
        port=54321,
        method=method,
        key_fp=key_fp,
    )


def minutes(base: str, count: int, step: int = 1, **kwargs) -> list[Event]:
    from datetime import timedelta

    from logkompass.util import iso, parse_iso

    start = parse_iso(base)
    return [make_event(ts=iso(start + timedelta(minutes=i * step)), **kwargs) for i in range(count)]


def memory_store() -> Store:
    return Store.open(":memory:")


def sample_aggregate() -> dict:
    """Fixed input used by the golden digest test."""
    return {
        "day": "2026-09-20",
        "host": "canary-01",
        "totals": {"events": 4193, "failed": 4102, "accepted": 4, "distinct_ips": 212},
        "kinds": {"failed_password": 2100, "invalid_user": 2002, "accepted_publickey": 4},
        "top_ips": [
            {
                "ip": "198.51.100.7",
                "count": 890,
                "country": "NL",
                "as_org": "Example Hosting",
                "first_seen": "2026-09-14",
                "users": 14,
            }
        ],
        "top_users": [
            {"username": "root", "count": 1877},
            {"username": "admin", "count": 420},
            {"username": "ubuntu", "count": 311},
        ],
        "countries": {"CN": 41, "US": 33, "NL": 19},
        "findings": [
            {"rule_id": "R01_burst", "severity": "medium", "ip": "198.51.100.7", "count": 890},
            {
                "rule_id": "R05_new_country_success",
                "severity": "high",
                "ip": "84.112.0.9",
                "username": "danya",
                "detail": "AT, first successful login from this country",
            },
        ],
        "comparison": {
            "events_vs_7day_avg": 1.18,
            "seven_day_avg_events": 3553.0,
            "days_of_history": 7,
            "new_ips_today": 47,
        },
        "privacy": {"ips_masked": False},
    }


class StubTransport:
    """Fake OpenAI-compatible endpoint."""

    def __init__(self, replies=None, error: Exception | None = None) -> None:
        self.replies = list(replies or [])
        self.error = error
        self.calls: list[dict] = []

    def __call__(self, url, payload, headers, timeout):
        self.calls.append({"url": url, "payload": payload, "headers": headers})
        if self.error is not None:
            raise self.error
        text = self.replies.pop(0) if self.replies else "ok"
        return {"model": payload["model"], "choices": [{"message": {"content": text}}]}


GOOD_FIVE_LINES = "\n".join(
    [
        "4193 auth events from 212 IPs, 18 percent above the 7-day average.",
        "Loudest source 198.51.100.7, NL, Example Hosting, 890 attempts, first seen 14 Sep.",
        "Mostly password guessing against root, admin and ubuntu across 14 usernames.",
        "High: accepted login from a new country, AT, user danya. Looks like you.",
        "No action needed. Password auth stays open by design on this host.",
    ]
)
