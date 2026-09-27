"""Collector for a Cowrie honeypot's JSON event log.

Cowrie writes one JSON object per line (``output_jsonlog``). Unlike sshd, it
captures the passwords attackers try and the commands they run once "inside",
so those land in the Event's ``password`` and ``command`` fields.

Reading mirrors :mod:`logkompass.collect.authlog`: a byte offset plus inode,
resetting to zero when the file rotates, so a run is idempotent and resumable.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from ..models import Event
from ..util import iso, parse_iso, sha1

# Cowrie eventid -> (our kind). Everything else (client.version, kex,
# direct-tcpip, …) is background noise we intentionally skip.
EVENT_KINDS = {
    "cowrie.session.connect": "cowrie_connect",
    "cowrie.login.failed": "cowrie_login_failed",
    "cowrie.login.success": "cowrie_login_success",
    "cowrie.command.input": "cowrie_command",
    "cowrie.session.closed": "cowrie_session",
}


@dataclass
class CowrieBatch:
    events: list[Event] = field(default_factory=list)
    offset: int = 0
    inode: int | None = None
    rotated: bool = False
    skipped: int = 0


def _event_from_record(record: dict, line: str, host_default: str) -> Event | None:
    kind = EVENT_KINDS.get(record.get("eventid"))
    ip = record.get("src_ip")
    stamp = record.get("timestamp")
    if kind is None or not ip or not stamp:
        return None
    try:
        ts = iso(parse_iso(stamp))
    except (ValueError, TypeError):
        return None
    port = record.get("src_port")
    return Event(
        ts=ts,
        host=record.get("sensor") or host_default,
        kind=kind,
        raw=line,
        raw_hash=sha1(line),
        username=record.get("username"),
        ip=ip,
        port=int(port) if isinstance(port, int) else None,
        method="ssh",
        password=record.get("password"),
        command=record.get("input"),
    )


def events_from_cowrie_lines(lines: list[str], host: str = "localhost") -> CowrieBatch:
    batch = CowrieBatch()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            batch.skipped += 1
            continue
        event = _event_from_record(record, line, host)
        if event is None:
            batch.skipped += 1
            continue
        batch.events.append(event)
    return batch


def read_cowrie(
    path: str,
    offset: int = 0,
    inode: int | None = None,
    max_lines: int = 50000,
    host: str = "localhost",
    reader=None,
) -> CowrieBatch:
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
    batch = events_from_cowrie_lines(lines, host=host)
    batch.offset = new_offset
    batch.inode = new_inode
    batch.rotated = rotated
    return batch
