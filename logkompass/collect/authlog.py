"""File based fallback collector with byte offset and inode tracking.

Rotation detection: if the inode changed or the file shrank, the offset resets to 0.
Without that, a rotated log is silently never read again.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime

from ..models import Event
from ..parse import parse_line
from ..util import UTC, iso, now_utc, parse_iso

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z))\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
SSH_PROCS = ("sshd", "sshd-session", "sshd-auth")


@dataclass
class AuthlogBatch:
    events: list[Event] = field(default_factory=list)
    offset: int = 0
    inode: int | None = None
    rotated: bool = False
    skipped: int = 0


def split_line(line: str, now: datetime | None = None) -> tuple[str, str, str] | None:
    """Return (ts_iso, host, message) for a syslog line, or None if unparseable."""
    match = ISO_RE.match(line.strip())
    if match:
        return iso(parse_iso(match.group("ts"))), match.group("host"), match.group("message")
    match = SYSLOG_RE.match(line.strip())
    if not match:
        return None
    reference = now or now_utc()
    stamp = match.group("ts")
    try:
        naive = datetime.strptime(f"{reference.year} {stamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    moment = naive.replace(tzinfo=UTC)
    if (moment - reference).days > 1:  # December log read in January
        moment = moment.replace(year=reference.year - 1)
    return iso(moment), match.group("host"), match.group("message")


def events_from_lines(
    lines: list[str], host: str = "localhost", now: datetime | None = None
) -> AuthlogBatch:
    batch = AuthlogBatch()
    for line in lines:
        if not line.strip():
            continue
        parts = split_line(line, now=now)
        if parts is None:
            batch.skipped += 1
            continue
        ts, line_host, message = parts
        if not any(proc in line for proc in SSH_PROCS):
            batch.skipped += 1
            continue
        batch.events.append(parse_line(message, ts, line_host or host))
    return batch


def read_authlog(
    path: str,
    offset: int = 0,
    inode: int | None = None,
    max_lines: int = 50000,
    host: str = "localhost",
    reader=None,
    now: datetime | None = None,
) -> AuthlogBatch:
    if reader is not None:
        lines, new_offset, new_inode, rotated = reader(path, offset, inode)
    else:
        stat = os.stat(path)
        rotated = (inode is not None and stat.st_ino != inode) or stat.st_size < offset
        start = 0 if rotated else offset
        with open(path, "r", errors="replace") as handle:
            handle.seek(start)
            lines = handle.readlines()[:max_lines]
            new_offset = handle.tell()
        new_inode = stat.st_ino
    batch = events_from_lines(lines, host=host, now=now)
    batch.offset = new_offset
    batch.inode = new_inode
    batch.rotated = rotated
    return batch
