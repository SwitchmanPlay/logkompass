from __future__ import annotations

from helpers import make_event, minutes

from logkompass.config import RuleSettings
from logkompass.enrich.history import StaticHistory
from logkompass.rules import evaluate

RC = RuleSettings()
W_FROM = "2026-09-20T00:00:00Z"
W_TO = "2026-09-21T00:00:00Z"


def run(events, history=None, rc=RC):
    return {f.rule_id: f for f in evaluate(events, rc, W_FROM, W_TO, history or StaticHistory())}


def test_r01_fires_on_twenty_failures_in_ten_minutes():
    events = minutes("2026-09-20T10:00:00Z", 20, step=0)
    findings = run(events)
    assert findings["R01_burst"].count == 20


def test_r01_does_not_fire_on_nineteen():
    events = minutes("2026-09-20T10:00:00Z", 19, step=0)
    assert "R01_burst" not in run(events)


def test_r01_does_not_fire_when_spread_beyond_the_window():
    events = minutes("2026-09-20T10:00:00Z", 30, step=5)
    assert "R01_burst" not in run(events)


def test_r02_fires_on_eight_distinct_usernames():
    events = [
        make_event(username=name)
        for name in ["a", "b", "c", "d", "e", "f", "g", "h"]
    ]
    assert run(events)["R02_user_spray"].count == 8


def test_r02_near_miss_with_seven_usernames():
    events = [make_event(username=name) for name in ["a", "b", "c", "d", "e", "f", "g"]]
    assert "R02_user_spray" not in run(events)


def test_r03_fires_for_privileged_usernames():
    finding = run([make_event(username="root")])["R03_high_value_user"]
    assert "root" in finding.detail


def test_r03_ignores_ordinary_usernames():
    assert "R03_high_value_user" not in run([make_event(username="tomcat9")])


def test_r04_fires_when_success_follows_failures():
    events = minutes("2026-09-20T10:00:00Z", 3, step=1, username="danya")
    events.append(
        make_event(
            ts="2026-09-20T10:05:00Z", kind="accepted_password", username="danya"
        )
    )
    finding = run(events)["R04_success_after_failures"]
    assert finding.severity == "high"
    assert finding.count == 3


def test_r04_near_miss_with_two_failures():
    events = minutes("2026-09-20T10:00:00Z", 2, step=1, username="danya")
    events.append(make_event(ts="2026-09-20T10:05:00Z", kind="accepted_password"))
    assert "R04_success_after_failures" not in run(events)


def test_r04_ignores_failures_older_than_the_lookback():
    events = minutes("2026-09-20T08:00:00Z", 5, step=1)
    events.append(make_event(ts="2026-09-20T10:05:00Z", kind="accepted_password"))
    assert "R04_success_after_failures" not in run(events)


def test_r05_fires_for_a_country_never_seen_succeeding():
    history = StaticHistory(countries={"AT"}, country_map={"203.0.113.9": "CN"})
    events = [make_event(kind="accepted_password", ip="203.0.113.9", username="danya")]
    assert run(events, history)["R05_new_country_success"].detail.startswith("CN")


def test_r05_quiet_for_a_known_country():
    history = StaticHistory(countries={"AT"}, country_map={"84.112.0.9": "AT"})
    events = [make_event(kind="accepted_password", ip="84.112.0.9")]
    assert "R05_new_country_success" not in run(events, history)


def test_r05_fires_only_once_per_country():
    history = StaticHistory(country_map={"203.0.113.9": "CN"})
    events = [
        make_event(ts="2026-09-20T10:00:00Z", kind="accepted_password", ip="203.0.113.9"),
        make_event(ts="2026-09-20T11:00:00Z", kind="accepted_password", ip="203.0.113.9"),
    ]
    findings = [f for f in evaluate(events, RC, W_FROM, W_TO, history) if f.rule_id.startswith("R05")]
    assert len(findings) == 1


def test_r06_fires_for_an_unknown_fingerprint():
    history = StaticHistory(fingerprints={"SHA256:known"})
    events = [
        make_event(kind="accepted_publickey", method="publickey", key_fp="SHA256:brand-new")
    ]
    assert "SHA256:brand-new" in run(events, history)["R06_new_key_fingerprint"].detail


def test_r06_quiet_for_a_known_fingerprint():
    history = StaticHistory(fingerprints={"SHA256:known"})
    events = [make_event(kind="accepted_publickey", key_fp="SHA256:known")]
    assert "R06_new_key_fingerprint" not in run(events, history)


def test_r06_honours_the_config_allowlist():
    rc = RuleSettings(known_key_fingerprints=["SHA256:mine"])
    history = StaticHistory(fingerprints=set(rc.known_key_fingerprints))
    events = [make_event(kind="accepted_publickey", key_fp="SHA256:mine")]
    assert "R06_new_key_fingerprint" not in run(events, history, rc)


def test_r07_fires_on_five_protocol_errors():
    events = [make_event(kind="kex_failure", username=None) for _ in range(5)]
    assert run(events)["R07_protocol_noise"].count == 5


def test_r07_near_miss_on_four():
    events = [make_event(kind="kex_failure", username=None) for _ in range(4)]
    assert "R07_protocol_noise" not in run(events)


def test_findings_are_sorted_high_severity_first():
    events = minutes("2026-09-20T10:00:00Z", 3, step=1, username="danya")
    events.append(make_event(ts="2026-09-20T10:05:00Z", kind="accepted_password", username="root"))
    findings = evaluate(events, RC, W_FROM, W_TO, StaticHistory())
    assert findings[0].severity == "high"


def test_no_events_means_no_findings():
    assert evaluate([], RC, W_FROM, W_TO, StaticHistory()) == []


def test_events_without_ip_are_ignored():
    events = [make_event(ip=None) for _ in range(30)]
    assert evaluate(events, RC, W_FROM, W_TO, StaticHistory()) == []
