from __future__ import annotations

from pathlib import Path

from helpers import memory_store

from logkompass.collect import collect_once
from logkompass.collect.cowrie import events_from_cowrie_lines, read_cowrie
from logkompass.config import Config

COWRIE = Path(__file__).parent / "fixtures" / "cowrie.json"


def _events():
    return events_from_cowrie_lines(COWRIE.read_text().splitlines(), host="svr01")


def test_cowrie_lines_map_to_events():
    batch = _events()
    # connect + 2 failed + 1 success + 1 command + 1 closed = 6 mapped
    assert len(batch.events) == 6
    # client.version and direct-tcpip.request are ignored, not fatal
    assert batch.skipped == 2


def test_failed_login_captures_credentials():
    events = _events().events
    failed = [e for e in events if e.kind == "cowrie_login_failed"]
    assert len(failed) == 2
    first = failed[0]
    assert first.username == "root"
    assert first.password == "123456"
    assert first.ip == "203.0.113.10"
    assert first.is_failed is True
    assert first.ts.endswith("Z")


def test_successful_login_is_accepted_and_keeps_password():
    events = _events().events
    ok = [e for e in events if e.kind == "cowrie_login_success"]
    assert len(ok) == 1
    assert ok[0].is_accepted is True
    assert ok[0].username == "root"
    assert ok[0].password == "root"


def test_command_input_is_captured():
    events = _events().events
    cmds = [e for e in events if e.kind == "cowrie_command"]
    assert len(cmds) == 1
    assert cmds[0].command == "uname -a; cat /etc/passwd"
    assert cmds[0].ip == "198.51.100.7"


def test_broken_cowrie_lines_are_counted_not_fatal():
    batch = events_from_cowrie_lines(['not json', '{"eventid":"cowrie.session.connect"}'])
    # second line has no src_ip/timestamp -> skipped; both skipped, no crash
    assert batch.events == []
    assert batch.skipped == 2


def test_store_round_trips_password_and_command():
    store = memory_store()
    batch = _events()
    store.insert_events(batch.events)
    rows = store.events_on_day("2026-09-27")
    creds = {(e.username, e.password) for e in rows if e.kind == "cowrie_login_failed"}
    assert ("root", "123456") in creds
    cmd = [e for e in rows if e.kind == "cowrie_command"][0]
    assert cmd.command == "uname -a; cat /etc/passwd"


def test_read_cowrie_tracks_offset_and_is_idempotent(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text(COWRIE.read_text())
    store = memory_store()
    cfg = Config.from_dict(
        {"collect": {"source": "cowrie", "cowrie_json_path": str(log)}}, env={}
    )
    first = collect_once(store, cfg)
    assert first["inserted"] == 6
    assert int(store.get_state("cowrie_offset")) > 0
    second = collect_once(store, cfg)
    assert second["lines"] == 0


def test_rotation_resets_offset():
    def reader(path, offset, inode):
        return ([], 0, 42, True)

    batch = read_cowrie("/x/cowrie.json", offset=999, inode=1, reader=reader)
    assert batch.rotated is True
    assert batch.inode == 42
