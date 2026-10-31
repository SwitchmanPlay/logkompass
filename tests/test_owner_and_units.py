"""Owner allowlist, baseline confidence and the distro unit name.

The first live digest called the server owner the "top source" and quoted a
"25 percent below the 7-day average" figure built from three days of data.
Both were honest bugs in the aggregate, not model hallucinations.
"""

from __future__ import annotations

import tomllib

import pytest
from helpers import make_event, memory_store, minutes

from logkompass.aggregate import _owner_networks, build_aggregate, is_owner_ip
from logkompass.collect.journald import build_command
from logkompass.config import Collect, Config, ConfigError
from logkompass.digest import render_template
from logkompass.models import Finding


def seeded_store():
    store = memory_store()
    store.insert_events(
        minutes("2026-09-20T10:00:00Z", 8, ip="62.60.130.0", username="root"),
        geo=lambda ip: ("NL", 64475, "Example Hosting"),
    )
    store.insert_events(
        minutes("2026-09-20T11:00:00Z", 12, ip="78.104.125.0", username="opc"),
        geo=lambda ip: ("AT", 1853, "ACONET"),
    )
    store.insert_events(
        [make_event(ts="2026-09-20T12:00:00Z", kind="ignored", ip=None, username=None)]
    )
    return store


def test_owner_traffic_is_excluded_from_the_ranking():
    aggregate = build_aggregate(
        seeded_store(), "2026-09-20", host="canary-01", owner_ips=["78.104.125.0"]
    )
    assert aggregate["totals"]["owner_events_excluded"] == 12
    assert [item["ip"] for item in aggregate["top_ips"]] == ["62.60.130.0"]


def test_without_the_allowlist_the_owner_still_ranks_first():
    aggregate = build_aggregate(seeded_store(), "2026-09-20", host="canary-01")
    assert aggregate["top_ips"][0]["ip"] == "78.104.125.0"


def test_cidr_blocks_are_accepted():
    networks = _owner_networks(["78.104.0.0/16", "garbage", "203.0.113.5"])
    assert is_owner_ip("78.104.125.9", networks)
    assert is_owner_ip("203.0.113.5", networks)
    assert not is_owner_ip("62.60.130.0", networks)
    assert not is_owner_ip(None, networks)


def test_lifecycle_events_leave_the_aggregate_totals():
    aggregate = build_aggregate(seeded_store(), "2026-09-20", host="canary-01")
    assert aggregate["totals"]["ignored_lifecycle"] == 1
    assert aggregate["totals"]["events"] == 20
    assert "ignored" not in aggregate["kinds"]


def test_thin_history_refuses_to_state_a_comparison():
    aggregate = build_aggregate(
        seeded_store(), "2026-09-20", host="canary-01", baseline_min_days=5
    )
    assert aggregate["comparison"]["baseline_ready"] is False
    assert aggregate["comparison"]["events_vs_7day_avg"] is None
    line = render_template(aggregate)[0]
    assert "baseline still building" in line
    assert "percent" not in line


def test_full_history_states_the_comparison():
    aggregate = {
        "totals": {"events": 100, "distinct_ips": 4, "failed": 90, "accepted": 1},
        "comparison": {
            "events_vs_7day_avg": 1.5,
            "seven_day_avg_events": 66.7,
            "days_of_history": 7,
            "baseline_ready": True,
            "baseline_min_days": 5,
        },
    }
    assert "50 percent above" in render_template(aggregate)[0]


def test_unit_accepts_a_list_for_both_distro_families():
    cfg = Config.from_dict({"collect": {"unit": ["ssh", "sshd"]}}, env={})
    assert cfg.collect.units == ["ssh", "sshd"]
    assert build_command(cfg.collect.units, None, 10)[:5] == [
        "journalctl", "-u", "ssh", "-u", "sshd",
    ]


def test_unit_still_accepts_a_single_string():
    cfg = Config.from_dict({"collect": {"unit": "sshd"}}, env={})
    assert cfg.collect.units == ["sshd"]


def test_default_unit_covers_ssh_and_sshd():
    assert Collect().units == ["ssh", "sshd"]


@pytest.mark.parametrize("bad", ["", [], [""], 7])
def test_bad_unit_values_are_rejected(bad):
    with pytest.raises(ConfigError):
        Config.from_dict({"collect": {"unit": bad}}, env={})


def test_owner_ips_and_baseline_are_configurable():
    cfg = Config.from_dict(
        {"rules": {"owner_ips": ["78.104.0.0/16"], "baseline_min_days": 3}}, env={}
    )
    assert cfg.rules.owner_ips == ["78.104.0.0/16"]
    assert cfg.rules.baseline_min_days == 3


def test_baseline_history_is_filtered_like_today():
    # Lifecycle lines and owner traffic leave today's total, so they must leave
    # the 7-day history too, or the ratio compares two different things.
    store = memory_store()
    store.insert_events(minutes("2026-09-19T10:00:00Z", 10, ip="62.60.130.0"))
    store.insert_events(minutes("2026-09-19T11:00:00Z", 30, ip="78.104.125.0"))
    store.insert_events(minutes("2026-09-19T12:00:00Z", 50, kind="ignored", ip=None))
    store.insert_events(minutes("2026-09-20T10:00:00Z", 20, ip="62.60.130.0"))
    aggregate = build_aggregate(
        store, "2026-09-20", owner_ips=["78.104.0.0/16"], baseline_min_days=1
    )
    assert aggregate["comparison"]["seven_day_avg_events"] == 10.0
    assert aggregate["comparison"]["events_vs_7day_avg"] == 2.0


def test_owner_findings_are_kept_but_tagged():
    store = seeded_store()
    store.insert_findings(
        [
            Finding(
                rule_id="R04_success_after_failures",
                severity="high",
                ts="2026-09-20T11:30:00Z",
                window_from="2026-09-20T11:00:00Z",
                window_to="2026-09-20T11:30:00Z",
                ip="78.104.125.0",
                count=3,
            )
        ]
    )
    aggregate = build_aggregate(store, "2026-09-20", owner_ips=["78.104.125.0"])
    assert aggregate["findings"][0]["owner"] is True
    assert aggregate["findings_summary"]["total"] == 1
    assert "owner_ips" in render_template(aggregate)[4]

    untagged = build_aggregate(store, "2026-09-20")
    assert "owner" not in untagged["findings"][0]


@pytest.mark.parametrize("bad", [["not-an-ip"], "78.104.0.0/16"])
def test_bad_owner_ips_are_rejected(bad):
    with pytest.raises(ConfigError):
        Config.from_dict({"rules": {"owner_ips": bad}}, env={})


@pytest.mark.parametrize("bad", [-1, "5", True])
def test_bad_baseline_min_days_is_rejected(bad):
    with pytest.raises(ConfigError):
        Config.from_dict({"rules": {"baseline_min_days": bad}}, env={})


def test_canary_config_loads():
    data = tomllib.loads(
        """
        [collect]
        source = "journald"
        unit = ["ssh", "sshd"]

        [rules]
        owner_ips = ["84.112.0.0/16"]
        baseline_min_days = 5

        [notify]
        telegram_token = "env:LK_TOKEN"
        chat_id = "env:LK_CHAT"
        """
    )
    cfg = Config.from_dict(data, env={"LK_TOKEN": "t", "LK_CHAT": "1"})
    assert cfg.collect.units == ["ssh", "sshd"]
    assert cfg.rules.owner_ips == ["84.112.0.0/16"]
    assert cfg.rules.baseline_min_days == 5
