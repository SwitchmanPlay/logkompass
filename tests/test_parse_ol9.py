"""Oracle Linux 9 / OpenSSH 9.8 wording.

The live deployment sat at parse_rate 0.38 for two reasons, both regression
tested here:
  1. "Connection reset by ..." was missing, so real preauth attacks fell into
     the other bucket and never reached the rules;
  2. systemd and PAM lifecycle lines were scored as parser failures.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logkompass.models import IGNORED_KINDS
from logkompass.parse import is_ignored, parse_line, parse_rate

TS = "2026-09-16T10:00:00Z"
FIXTURE = Path(__file__).parent / "fixtures" / "sshd_lines_ol9.txt"


@pytest.mark.parametrize(
    "message,username,ip,port",
    [
        (
            "Connection reset by authenticating user root 62.60.130.0 port 62114 [preauth]",
            "root",
            "62.60.130.0",
            62114,
        ),
        (
            "Connection reset by invalid user wronguser 78.104.125.0 port 52162 [preauth]",
            "wronguser",
            "78.104.125.0",
            52162,
        ),
        ("Connection reset by 35.203.211.0 port 58552 [preauth]", None, "35.203.211.0", 58552),
        (
            "Connection closed by authenticating user root 62.60.130.0 port 33112 [preauth]",
            "root",
            "62.60.130.0",
            33112,
        ),
        (
            "Timeout before authentication for 147.185.133.0 port 37836",
            None,
            "147.185.133.0",
            37836,
        ),
    ],
)
def test_openssh_98_preauth_wordings(message, username, ip, port):
    event = parse_line(message, TS)
    assert event.kind == "preauth_disconnect"
    assert event.username == username
    assert event.ip == ip
    assert event.port == port


def test_too_many_failures_is_max_auth_exceeded():
    event = parse_line(
        "Disconnecting authenticating user root 45.148.10.0 port 7480: "
        "Too many authentication failures [preauth]",
        TS,
    )
    assert event.kind == "max_auth_exceeded"
    assert event.username == "root"
    assert event.ip == "45.148.10.0"


def test_kex_exchange_identification_is_protocol_noise():
    event = parse_line(
        "error: kex_exchange_identification: Connection closed by remote host", TS
    )
    assert event.kind == "kex_failure"


def test_invalid_identification_string_is_banner_garbage():
    event = parse_line("Invalid SSH identification string from 147.185.133.0 port 37838", TS)
    assert event.kind == "banner_garbage"
    assert event.ip == "147.185.133.0"


@pytest.mark.parametrize(
    "message",
    [
        "pam_unix(sshd:session): session opened for user opc(uid=1000) by opc(uid=0)",
        "Starting OpenSSH server daemon...",
        "Started OpenSSH server daemon.",
        "Stopping OpenSSH server daemon...",
        "sshd.service: Deactivated successfully.",
        "Server listening on 0.0.0.0 port 2242.",
        "Server listening on :: port 22.",
        "Received signal 15; terminating.",
        "Set /proc/self/oom_score_adj to 0",
        "Disconnected from user opc 203.0.113.0 port 51234",
    ],
)
def test_lifecycle_lines_are_ignored_not_unparsed(message):
    assert parse_line(message, TS).kind in IGNORED_KINDS
    assert is_ignored(message)


def test_own_logout_is_not_counted_as_a_preauth_disconnect():
    assert parse_line("Disconnected from user opc 203.0.113.0 port 51234", TS).kind == "ignored"
    attacker = parse_line(
        "Disconnected from authenticating user root 62.60.130.0 port 1 [preauth]", TS
    )
    assert attacker.kind == "preauth_disconnect"


def test_attack_lines_are_never_ignored():
    for line in FIXTURE.read_text().splitlines():
        if "Connection reset by" in line or "Failed password" in line:
            assert parse_line(line, TS).kind != "ignored"


def test_oracle_linux_fixture_parse_rate():
    lines = [line for line in FIXTURE.read_text().splitlines() if line.strip()]
    events = [parse_line(line, TS) for line in lines]
    assert len(events) >= 40
    assert parse_rate(events) > 0.95
    assert [e.raw for e in events if e.kind == "other"] == []


def test_ignored_lines_still_keep_their_raw_text():
    event = parse_line("Started OpenSSH server daemon.", TS)
    assert event.raw == "Started OpenSSH server daemon."
    assert event.raw_hash


def test_unknown_line_still_counts_against_the_parse_rate():
    events = [parse_line("something genuinely new from sshd", TS)]
    assert events[0].kind == "other"
    assert parse_rate(events) == 0.0
