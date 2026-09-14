from __future__ import annotations

import json
from pathlib import Path

from helpers import memory_store

from logkompass.collect import collect_once
from logkompass.collect.authlog import events_from_lines, read_authlog, split_line
from logkompass.collect.journald import build_command, events_from_json
from logkompass.config import Config

JOURNAL = Path(__file__).parent / "fixtures" / "journal.json"
SSHD = Path(__file__).parent / "fixtures" / "sshd_lines.txt"


def test_journal_command_includes_the_cursor():
    assert build_command("ssh", None, 100) == [
        "journalctl", "-u", "ssh", "-o", "json", "--no-pager", "-n", "100",
    ]
    assert build_command("ssh", "s=abc", 100)[-2:] == ["--after-cursor", "s=abc"]


def test_journal_json_is_parsed_and_the_cursor_is_kept():
    batch = events_from_json(JOURNAL.read_text())
    assert len(batch.events) >= 4
    assert batch.cursor
    assert batch.events[0].ts.endswith("Z")
    assert any(event.kind == "invalid_user" for event in batch.events)


def test_broken_journal_lines_are_counted_not_fatal():
    batch = events_from_json('{"MESSAGE": "x"}\nnot json\n')
    assert batch.skipped == 2
    assert batch.events == []


def test_collect_once_is_idempotent_and_saves_the_cursor():
    store = memory_store()
    cfg = Config.from_dict({"paths": {"db": ":memory:"}}, env={})
    text = JOURNAL.read_text()

    def runner(cmd):
        return text if "--after-cursor" not in cmd else ""

    first = collect_once(store, cfg, runner=runner)
    assert first["inserted"] == first["lines"] > 0
    assert store.get_state("journal_cursor")
    second = collect_once(store, cfg, runner=runner)
    assert second["lines"] == 0


def test_syslog_line_split():
    parts = split_line(
        "Sep 20 10:00:01 canary-01 sshd[1234]: Failed password for root from "
        "198.51.100.7 port 41022 ssh2"
    )
    assert parts is not None
    ts, host, message = parts
    assert host == "canary-01"
    assert message.startswith("Failed password")
    assert ts.endswith("Z")


def test_authlog_fixture_produces_events():
    lines = SSHD.read_text().splitlines()
    prefixed = [f"Sep 20 10:00:0{i % 10} canary-01 sshd[1]: {line}" for i, line in enumerate(lines)]
    batch = events_from_lines(prefixed)
    assert len(batch.events) == len(prefixed)


def test_non_ssh_lines_are_skipped():
    batch = events_from_lines(["Sep 20 10:00:01 canary-01 cron[9]: pam_unix session opened"])
    assert batch.events == []
    assert batch.skipped == 1


def test_authlog_rotation_resets_the_offset():
    seen = {}

    def reader(path, offset, inode):
        seen["offset"] = offset
        return ([], 0, 99, True)

    batch = read_authlog("/var/log/auth.log", offset=5000, inode=1, reader=reader)
    assert batch.rotated is True
    assert batch.inode == 99


def test_authlog_collect_tracks_offset_state(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Sep 20 10:00:01 canary-01 sshd[1]: Failed password for root from "
        "198.51.100.7 port 41022 ssh2\n"
    )
    store = memory_store()
    cfg = Config.from_dict(
        {"collect": {"source": "authlog", "authlog_path": str(log)}}, env={}
    )
    first = collect_once(store, cfg)
    assert first["inserted"] == 1
    assert int(store.get_state("authlog_offset")) > 0
    second = collect_once(store, cfg)
    assert second["lines"] == 0


def test_journal_fixture_is_valid_json_lines():
    for line in JOURNAL.read_text().splitlines():
        if line.strip():
            json.loads(line)
