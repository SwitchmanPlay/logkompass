"""Read sshd events out of journald as JSON, resuming from a saved cursor.

Ubuntu 24.04 cloud images often ship without rsyslog, so /var/log/auth.log may not
exist at all. Journald is the reliable source, which is why it is the default.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from ..models import Event
from ..parse import parse_line
from ..util import UTC, iso


@dataclass
class JournalBatch:
    events: list[Event] = field(default_factory=list)
    cursor: str | None = None
    skipped: int = 0


def build_command(unit: str, cursor: str | None, max_lines: int) -> list[str]:
    cmd = ["journalctl", "-u", unit, "-o", "json", "--no-pager", "-n", str(max_lines)]
    if cursor:
        cmd += ["--after-cursor", cursor]
    return cmd


def default_runner(cmd: list[str]) -> str:
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"journalctl failed ({completed.returncode}): {completed.stderr.strip()[:200]}"
        )
    return completed.stdout


def record_timestamp(record: dict) -> str | None:
    raw = record.get("__REALTIME_TIMESTAMP")
    if raw:
        try:
            return iso(datetime.fromtimestamp(int(raw) / 1_000_000, tz=UTC))
        except (ValueError, OSError):
            return None
    return None


def events_from_json(text: str, host_default: str = "localhost") -> JournalBatch:
    batch = JournalBatch()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            batch.skipped += 1
            continue
        message = record.get("MESSAGE")
        if isinstance(message, list):  # journald returns byte arrays for odd payloads
            message = "".join(chr(c) for c in message if isinstance(c, int))
        ts = record_timestamp(record)
        if not message or not ts:
            batch.skipped += 1
            continue
        host = record.get("_HOSTNAME") or host_default
        batch.events.append(parse_line(str(message), ts, host))
        if record.get("__CURSOR"):
            batch.cursor = record["__CURSOR"]
    return batch


def read_journal(
    unit: str = "ssh",
    cursor: str | None = None,
    max_lines: int = 50000,
    runner=None,
    host: str = "localhost",
) -> JournalBatch:
    run = runner or default_runner
    output = run(build_command(unit, cursor, max_lines))
    return events_from_json(output, host_default=host)
