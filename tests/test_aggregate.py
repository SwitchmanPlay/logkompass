from __future__ import annotations

from helpers import make_event, memory_store, minutes

from logkompass.aggregate import build_aggregate
from logkompass.models import Finding


def seeded_store():
    store = memory_store()
    store.insert_events(
        minutes("2026-09-20T10:00:00Z", 10, step=1, ip="198.51.100.7", username="root"),
        geo=lambda ip: ("NL", 64475, "Example Hosting"),
    )
    store.insert_events(
        minutes("2026-09-20T11:00:00Z", 4, step=1, ip="203.0.113.9", username="admin"),
        geo=lambda ip: ("CN", 4134, "Example Telecom"),
    )
    store.insert_events(
        [
            make_event(
                ts="2026-09-20T12:00:00Z",
                kind="accepted_publickey",
                ip="84.112.0.9",
                username="danya",
                key_fp="SHA256:mine",
            )
        ],
        geo=lambda ip: ("AT", 8447, "Example ISP"),
    )
    return store


def test_totals_and_top_talkers():
    aggregate = build_aggregate(seeded_store(), "2026-09-20", host="canary-01")
    assert aggregate["totals"] == {
        "events": 15,
        "failed": 14,
        "accepted": 1,
        "distinct_ips": 3,
        "unparsed": 0,
        "ignored_lifecycle": 0,
        "owner_events_excluded": 0,
    }
    assert aggregate["top_ips"][0]["ip"] == "198.51.100.7"
    assert aggregate["top_ips"][0]["count"] == 10
    assert aggregate["top_ips"][0]["as_org"] == "Example Hosting"
    assert aggregate["top_users"][0] == {"username": "root", "count": 10}
    assert aggregate["countries"]["NL"] == 10


def test_findings_are_included_for_that_day_only():
    store = seeded_store()
    store.insert_findings(
        [
            Finding(
                rule_id="R01_burst",
                severity="medium",
                ts="2026-09-20T10:10:00Z",
                window_from="2026-09-20T10:00:00Z",
                window_to="2026-09-20T10:10:00Z",
                ip="198.51.100.7",
                count=10,
            ),
            Finding(
                rule_id="R01_burst",
                severity="medium",
                ts="2026-09-21T10:10:00Z",
                window_from="2026-09-21T10:00:00Z",
                window_to="2026-09-21T10:10:00Z",
                ip="198.51.100.7",
                count=11,
            ),
        ]
    )
    aggregate = build_aggregate(store, "2026-09-20")
    assert [f["rule_id"] for f in aggregate["findings"]] == ["R01_burst"]
    assert aggregate["findings"][0]["count"] == 10


def test_empty_day_produces_a_usable_aggregate():
    aggregate = build_aggregate(memory_store(), "2026-09-20")
    assert aggregate["totals"]["events"] == 0
    assert aggregate["top_ips"] == []
    assert aggregate["comparison"]["events_vs_7day_avg"] is None


def test_baseline_uses_only_days_with_data():
    store = memory_store()
    store.insert_events(minutes("2026-09-19T10:00:00Z", 10, step=1))
    store.insert_events(minutes("2026-09-20T10:00:00Z", 20, step=1))
    # baseline_min_days=1 so this test exercises the averaging itself, not the
    # confidence gate (which is tested in test_owner_and_units.py).
    aggregate = build_aggregate(store, "2026-09-20", baseline_min_days=1)
    assert aggregate["comparison"]["seven_day_avg_events"] == 10.0
    assert aggregate["comparison"]["events_vs_7day_avg"] == 2.0
    assert aggregate["comparison"]["days_of_history"] == 1


def test_mask_hides_the_last_octet_everywhere():
    store = seeded_store()
    aggregate = build_aggregate(store, "2026-09-20", mask=True)
    assert aggregate["top_ips"][0]["ip"] == "198.51.100.x"
    assert aggregate["privacy"]["ips_masked"] is True


def _finding(rule_id, severity, ip, count, minute):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        ts=f"2026-09-20T10:{minute:02d}:00Z",
        window_from=f"2026-09-20T09:{minute:02d}:00Z",
        window_to=f"2026-09-20T10:{minute:02d}:00Z",
        ip=ip,
        count=count,
    )


def test_findings_are_capped_with_a_per_rule_summary():
    # A busy honeypot produces tens of thousands of findings a day. Sending all
    # of them blew past every model's context window (HTTP 400 on every provider).
    store = seeded_store()
    noise = [
        _finding("R07_protocol_noise", "info", f"10.0.{n // 250}.{n % 250}", 5, n % 60)
        for n in range(500)
    ]
    bursts = [_finding("R01_burst", "medium", f"10.1.0.{n}", 20 + n, n) for n in range(30)]
    # one noisy high rule from a single IP, plus a rarer high rule
    repeats = [_finding("R04_success_after_failures", "high", "203.0.113.9", 50, n) for n in range(40)]
    rare = [_finding("R05_new_country_success", "high", "198.51.100.7", 1, 59)]
    store.insert_findings(noise + bursts + repeats + rare)

    aggregate = build_aggregate(store, "2026-09-20")

    findings = aggregate["findings"]
    assert len(findings) == 12  # 5 per rule cap, R04 and R05 deduped to one IP each
    rules = [f["rule_id"] for f in findings]
    assert rules[:2] == ["R04_success_after_failures", "R05_new_country_success"]
    assert rules.count("R01_burst") == 5 and rules.count("R07_protocol_noise") == 5
    assert findings[2]["ip"] == "10.1.0.29"  # biggest burst first
    summary = aggregate["findings_summary"]
    assert summary["total"] == 571
    assert summary["by_rule"]["R04_success_after_failures"] == {
        "severity": "high", "findings": 40, "distinct_ips": 1
    }
    assert summary["by_rule"]["R07_protocol_noise"]["distinct_ips"] == 500


def test_prompt_stays_small_on_a_very_busy_day():
    from logkompass.digest import build_user_prompt

    store = seeded_store()
    store.insert_findings(
        _finding("R03_high_value_user", "low", f"10.{n // 62500}.{n // 250 % 250}.{n % 250}", 9, n % 60)
        for n in range(20000)
    )
    aggregate = build_aggregate(store, "2026-09-20", mask=True)
    assert len(build_user_prompt(aggregate)) < 20_000
    assert all(f["ip"].endswith(".x") for f in aggregate["findings"])
