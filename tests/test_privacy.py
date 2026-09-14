from __future__ import annotations

import pytest

from logkompass.util import in_quiet_hours, mask_ip, mask_text, parse_duration


@pytest.mark.parametrize(
    "raw,masked",
    [
        ("198.51.100.7", "198.51.100.x"),
        ("203.0.113.255", "203.0.113.x"),
        ("2001:db8::dead:beef", "2001:0db8:0000:0000::x"),
        ("not-an-ip", "not-an-ip"),
        (None, None),
    ],
)
def test_mask_ip(raw, masked):
    assert mask_ip(raw) == masked


def test_mask_text_rewrites_every_ipv4():
    text = "198.51.100.7 hit 203.0.113.9 twice"
    assert mask_text(text) == "198.51.100.x hit 203.0.113.x twice"


@pytest.mark.parametrize(
    "spec,seconds",
    [("45m", 2700), ("24h", 86400), ("7d", 604800), ("12", 43200)],
)
def test_parse_duration(spec, seconds):
    assert parse_duration(spec).total_seconds() == seconds


def test_parse_duration_rejects_nonsense():
    with pytest.raises(ValueError):
        parse_duration("3 weeks")


@pytest.mark.parametrize(
    "hour,expected",
    [(23, True), (2, True), (6, True), (7, False), (12, False), (22, False)],
)
def test_quiet_hours_wrap_around_midnight(hour, expected):
    assert in_quiet_hours(hour, (23, 7)) is expected


def test_quiet_hours_disabled():
    assert in_quiet_hours(3, None) is False
    assert in_quiet_hours(3, (0, 0)) is False
