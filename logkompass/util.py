"""Small helpers: time, hashing, IP masking, durations."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone

UTC = timezone.utc

IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    """Canonical storage format: second-resolution UTC, Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


def day_bounds(day: str) -> tuple[str, str]:
    """Return [start, end) ISO bounds for a YYYY-MM-DD day in UTC."""
    start = parse_iso(day + "T00:00:00Z")
    return iso(start), iso(start + timedelta(days=1))


def parse_duration(spec: str) -> timedelta:
    """Accept 45m, 24h, 7d or a plain number of hours."""
    text = str(spec).strip().lower()
    if not text:
        raise ValueError("empty duration")
    unit = text[-1]
    if unit.isdigit():
        return timedelta(hours=float(text))
    amount = float(text[:-1])
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "d":
        return timedelta(days=amount)
    raise ValueError(f"unsupported duration unit: {spec}")


def is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def mask_ip(value: str | None) -> str | None:
    """Drop the last IPv4 octet or the last 64 bits of IPv6. GDPR hygiene."""
    if not value:
        return value
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return value
    if isinstance(addr, ipaddress.IPv4Address):
        return ".".join(value.split(".")[:3]) + ".x"
    groups = addr.exploded.split(":")[:4]
    return ":".join(groups) + "::x"


def mask_text(text: str) -> str:
    return IPV4_RE.sub(lambda m: mask_ip(m.group(0)) or m.group(0), text)


def in_quiet_hours(hour: int, quiet: tuple[int, int] | None) -> bool:
    """quiet=(23, 7) means 23:00 up to but not including 07:00."""
    if not quiet:
        return False
    start, end = int(quiet[0]), int(quiet[1])
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end
