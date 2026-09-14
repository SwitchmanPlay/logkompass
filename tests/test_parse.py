from __future__ import annotations

from pathlib import Path

import pytest

from logkompass.parse import parse_line, parse_rate

TS = "2026-09-20T10:00:00Z"
FIXTURE = Path(__file__).parent / "fixtures" / "sshd_lines.txt"


@pytest.mark.parametrize(
    "message,kind,username,ip",
    [
        (
            "Failed password for invalid user admin from 203.0.113.9 port 54322 ssh2",
            "invalid_user",
            "admin",
            "203.0.113.9",
        ),
        (
            "Failed password for root from 198.51.100.7 port 41022 ssh2",
            "failed_password",
            "root",
            "198.51.100.7",
        ),
        ("Invalid user ubuntu from 203.0.113.9 port 54001", "invalid_user", "ubuntu", "203.0.113.9"),
        (
            "Accepted publickey for danya from 84.112.0.9 port 51000 ssh2: ED25519 SHA256:abc",
            "accepted_publickey",
            "danya",
            "84.112.0.9",
        ),
        (
            "Accepted password for danya from 84.112.0.9 port 51002 ssh2",
            "accepted_password",
            "danya",
            "84.112.0.9",
        ),
        (
            "error: maximum authentication attempts exceeded for root from 198.51.100.7 "
            "port 41022 ssh2 [preauth]",
            "max_auth_exceeded",
            "root",
            "198.51.100.7",
        ),
        (
            "Disconnected from authenticating user root 198.51.100.7 port 41022 [preauth]",
            "preauth_disconnect",
            "root",
            "198.51.100.7",
        ),
        (
            "Connection closed by 203.0.113.9 port 54322 [preauth]",
            "preauth_disconnect",
            None,
            "203.0.113.9",
        ),
        (
            "Unable to negotiate with 192.0.2.5 port 22: no matching key exchange method found",
            "kex_failure",
            None,
            "192.0.2.5",
        ),
        (
            "banner exchange: Connection from 192.0.2.5 port 22: invalid format",
            "banner_garbage",
            None,
            "192.0.2.5",
        ),
    ],
)
def test_parses_known_kinds(message, kind, username, ip):
    event = parse_line(message, TS)
    assert event.kind == kind
    assert event.username == username
    assert event.ip == ip
    assert event.raw_hash


def test_publickey_fingerprint_is_captured():
    event = parse_line(
        "Accepted publickey for danya from 84.112.0.9 port 51000 ssh2: "
        "ED25519 SHA256:6GEU0m0kCCBLQ7aBQ2sd",
        TS,
    )
    assert event.key_fp == "SHA256:6GEU0m0kCCBLQ7aBQ2sd"
    assert event.method == "publickey"


def test_ipv6_source_is_kept():
    event = parse_line(
        "Failed password for root from 2001:db8::dead:beef port 40000 ssh2", TS
    )
    assert event.ip == "2001:db8::dead:beef"
    assert event.kind == "failed_password"


def test_username_containing_a_space():
    event = parse_line(
        "Failed password for invalid user admin user from 203.0.113.9 port 1 ssh2", TS
    )
    assert event.username == "admin user"


def test_malformed_line_lands_in_other_bucket():
    event = parse_line("totally unrelated log line", TS)
    assert event.kind == "other"
    assert event.ip is None


def test_other_bucket_still_recovers_an_ip():
    event = parse_line("pam_unix(sshd:auth): authentication failure rhost=203.0.113.9", TS)
    assert event.kind == "other"
    assert event.ip == "203.0.113.9"


def test_parse_never_raises_on_empty_input():
    assert parse_line("", TS).kind == "other"


def test_fixture_parse_rate_above_95_percent():
    lines = [line for line in FIXTURE.read_text().splitlines() if line.strip()]
    events = [parse_line(line, TS) for line in lines]
    assert len(events) >= 55
    assert parse_rate(events) > 0.95


def test_parse_rate_of_empty_list_is_one():
    assert parse_rate([]) == 1.0
