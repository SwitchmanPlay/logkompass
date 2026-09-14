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
    aggregate = build_aggregate(store, "2026-09-20")
    assert aggregate["comparison"]["seven_day_avg_events"] == 10.0
    assert aggregate["comparison"]["events_vs_7day_avg"] == 2.0
    assert aggregate["comparison"]["days_of_history"] == 1


def test_mask_hides_the_last_octet_everywhere():
    store = seeded_store()
    aggregate = build_aggregate(store, "2026-09-20", mask=True)
    assert aggregate["top_ips"][0]["ip"] == "198.51.100.x"
    assert aggregate["privacy"]["ips_masked"] is True
