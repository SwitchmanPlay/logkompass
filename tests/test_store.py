from __future__ import annotations

from helpers import make_event, memory_store, minutes

from logkompass.models import Finding


def test_replaying_the_same_lines_inserts_nothing_the_second_time():
    store = memory_store()
    events = minutes("2026-09-20T10:00:00Z", 5, step=1)
    first = store.insert_events(events)
    second = store.insert_events(events)
    assert first.inserted == 5
    assert second.inserted == 0
    assert second.duplicates == 5


def test_actor_counters_follow_the_events():
    store = memory_store()
    store.insert_events(
        [
            make_event(ts="2026-09-20T10:00:00Z"),
            make_event(ts="2026-09-20T10:01:00Z"),
            make_event(ts="2026-09-20T10:02:00Z", kind="accepted_password"),
        ]
    )
    actor = store.actor("198.51.100.7")
    assert actor.total_events == 3
    assert actor.total_failed == 2
    assert actor.ever_accepted == 1
    assert actor.first_seen == "2026-09-20T10:00:00Z"
    assert actor.last_seen == "2026-09-20T10:02:00Z"


def test_geo_lookup_is_applied_once_per_new_actor():
    store = memory_store()
    calls = []

    def geo(ip):
        calls.append(ip)
        return "NL", 64475, "Example Hosting"

    store.insert_events(minutes("2026-09-20T10:00:00Z", 3, step=1), geo=geo)
    assert calls == ["198.51.100.7"]
    assert store.actor("198.51.100.7").country == "NL"


def test_findings_are_idempotent_per_rule_ip_and_window():
    store = memory_store()
    finding = Finding(
        rule_id="R01_burst",
        severity="medium",
        ts="2026-09-20T10:10:00Z",
        window_from="2026-09-20T10:00:00Z",
        window_to="2026-09-20T10:10:00Z",
        ip="198.51.100.7",
        count=42,
    )
    assert store.insert_findings([finding]).inserted == 1
    assert store.insert_findings([finding]).inserted == 0


def test_state_round_trip():
    store = memory_store()
    assert store.get_state("journal_cursor") is None
    store.set_state("journal_cursor", "s=abc;i=1")
    store.set_state("journal_cursor", "s=abc;i=2")
    assert store.get_state("journal_cursor") == "s=abc;i=2"


def test_stats_reports_parse_rate():
    store = memory_store()
    store.insert_events(
        minutes("2026-09-20T10:00:00Z", 9, step=1)
        + [make_event(ts="2026-09-20T11:00:00Z", kind="other")]
    )
    stats = store.stats()
    assert stats["events"] == 10
    assert stats["unparsed"] == 1
    assert stats["parse_rate"] == 0.9


def test_new_ips_and_history_scoping():
    store = memory_store()
    store.insert_events(
        [make_event(ts="2026-09-19T10:00:00Z", kind="accepted_publickey", key_fp="SHA256:old")],
        geo=lambda ip: ("AT", 1, "ISP"),
    )
    assert store.new_ips_on_day("2026-09-19") == 1
    assert store.new_ips_on_day("2026-09-20") == 0
    assert store.accepted_countries_before("2026-09-20T00:00:00Z") == {"AT"}
    assert store.key_fingerprints_before("2026-09-20T00:00:00Z") == {"SHA256:old"}
    assert store.accepted_countries_before("2026-09-19T00:00:00Z") == set()


def test_prune_deletes_old_events():
    store = memory_store()
    store.insert_events([make_event(ts="2020-01-01T00:00:00Z")])
    store.insert_events(minutes("2026-09-20T10:00:00Z", 2, step=1))
    result = store.prune(days=36500)
    assert result["events"] == 0
    result = store.prune(days=1)
    assert result["events"] >= 1


def test_digest_record_is_upserted_per_day():
    store = memory_store()
    store.record_digest("2026-09-20", "a", "qwen3", "local_llm", 6400, "2026-09-21T06:00:00Z")
    store.record_digest(
        "2026-09-20", "b", "template", "template_fallback", None, "2026-09-21T07:00:00Z"
    )
    row = store.last_digest()
    assert row["text"] == "b"
    assert row["path"] == "template_fallback"
