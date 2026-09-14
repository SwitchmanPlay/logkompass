"""sshd message -> Event.

One compiled pattern per kind, ordered from most specific to least. Anything that
falls through lands in the `other` bucket and is counted, never dropped: the parse
rate is a metric, not a silent failure.
"""

from __future__ import annotations

import re

from .models import Event
from .util import is_ip, sha1

# (kind, pattern, method)
PATTERNS: list[tuple[str, re.Pattern[str], str | None]] = [
    (
        "accepted_publickey",
        re.compile(
            r"^Accepted publickey for (?P<username>\S+) from (?P<ip>\S+) port "
            r"(?P<port>\d+) ssh2(?::\s*(?P<keytype>\S+)\s+(?P<key_fp>\S+))?"
        ),
        "publickey",
    ),
    (
        "accepted_password",
        re.compile(
            r"^Accepted password for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "password",
    ),
    (
        "invalid_user",
        re.compile(
            r"^Failed password for invalid user (?P<username>.+?) from (?P<ip>\S+) "
            r"port (?P<port>\d+)"
        ),
        "password",
    ),
    (
        "invalid_user",
        re.compile(
            r"^Failed (?:publickey|none) for invalid user (?P<username>.+?) from "
            r"(?P<ip>\S+) port (?P<port>\d+)"
        ),
        "publickey",
    ),
    (
        "invalid_user",
        re.compile(r"^Invalid user (?P<username>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
        None,
    ),
    (
        "failed_password",
        re.compile(r"^Failed password for (?P<username>.+?) from (?P<ip>\S+) port (?P<port>\d+)"),
        "password",
    ),
    (
        "failed_password",
        re.compile(
            r"^Failed (?:publickey|none) for (?P<username>.+?) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "publickey",
    ),
    (
        "max_auth_exceeded",
        re.compile(
            r"^error: maximum authentication attempts exceeded for (?:invalid user )?"
            r"(?P<username>.+?) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        None,
    ),
    (
        "preauth_disconnect",
        re.compile(
            r"^(?:Disconnected|Connection closed) (?:from|by) "
            r"(?:(?:authenticating|invalid) user (?P<username>\S+) )?"
            r"(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
        ),
        None,
    ),
    (
        "preauth_disconnect",
        re.compile(r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        "kex_failure",
        re.compile(r"^Unable to negotiate with (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        "kex_failure",
        re.compile(r"^fatal: .*? from (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        "banner_garbage",
        re.compile(r"^banner exchange: Connection from (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        "banner_garbage",
        re.compile(
            r"^Bad protocol version identification .*? from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        None,
    ),
]

ANY_IP_RE = re.compile(r"(?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7})")


def _clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().strip(":")
    return candidate if is_ip(candidate) else None


def _fallback_ip(message: str) -> str | None:
    for match in ANY_IP_RE.finditer(message):
        if is_ip(match.group(0)):
            return match.group(0)
    return None


def parse_line(message: str, ts: str, host: str = "localhost") -> Event:
    """Parse one sshd log message. Never raises, never returns None."""
    text = message.strip()
    for kind, pattern, method in PATTERNS:
        match = pattern.match(text)
        if not match:
            continue
        groups = match.groupdict()
        port = groups.get("port")
        username = groups.get("username")
        return Event(
            ts=ts,
            host=host,
            kind=kind,
            raw=text,
            raw_hash=sha1(text),
            username=username.strip() if username else None,
            ip=_clean_ip(groups.get("ip")) or _fallback_ip(text),
            port=int(port) if port and port.isdigit() else None,
            method=method,
            key_fp=groups.get("key_fp"),
        )
    return Event(
        ts=ts,
        host=host,
        kind="other",
        raw=text,
        raw_hash=sha1(text),
        ip=_fallback_ip(text),
    )


def parse_rate(events: list[Event]) -> float:
    """Share of lines that matched a real pattern. README material."""
    if not events:
        return 1.0
    matched = sum(1 for e in events if e.kind != "other")
    return matched / len(events)
