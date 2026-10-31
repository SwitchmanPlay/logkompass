"""24 hour rollup. This dict is the only thing the model ever sees.

It is small, structured and already privacy reduced, which is what makes the local
model viable and the cloud fallback acceptable: no raw log lines leave the host.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from .models import ACCEPTED_KINDS, FAILED_KINDS, Event
from .util import day_bounds, iso, mask_ip, parse_iso

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _previous_day_counts(store, day: str, days: int = 7) -> list[int]:
    start = parse_iso(day_bounds(day)[0])
    counts = []
    for offset in range(1, days + 1):
        window_start = start - timedelta(days=offset)
        counts.append(
            store.count_events_between(iso(window_start), iso(window_start + timedelta(days=1)))
        )
    return counts


def build_aggregate(
    store,
    day: str,
    host: str = "localhost",
    top_n: int = 5,
    mask: bool = False,
    events: list[Event] | None = None,
    max_findings: int = 20,
    max_per_rule: int = 5,
) -> dict:
    start, end = day_bounds(day)
    events = events if events is not None else store.events_on_day(day)

    ip_counts: Counter[str] = Counter()
    ip_users: dict[str, set[str]] = defaultdict(set)
    user_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    for event in events:
        kind_counts[event.kind] += 1
        if event.ip:
            ip_counts[event.ip] += 1
            if event.username:
                ip_users[event.ip].add(event.username)
        if event.username:
            user_counts[event.username] += 1

    actors = store.actors(list(ip_counts))
    country_counts: Counter[str] = Counter()
    for ip, count in ip_counts.items():
        actor = actors.get(ip)
        if actor and actor.country:
            country_counts[actor.country] += count

    def show(ip: str) -> str:
        return (mask_ip(ip) or ip) if mask else ip

    top_ips = []
    for ip, count in ip_counts.most_common(top_n):
        actor = actors.get(ip)
        top_ips.append(
            {
                "ip": show(ip),
                "count": count,
                "country": actor.country if actor else None,
                "as_org": actor.as_org if actor else None,
                "first_seen": (actor.first_seen[:10] if actor and actor.first_seen else None),
                "users": len(ip_users.get(ip, ())),
            }
        )

    previous = _previous_day_counts(store, day)
    known_days = [count for count in previous if count > 0]
    average = sum(known_days) / len(known_days) if known_days else 0.0
    total = len(events)

    # A busy honeypot fires tens of thousands of findings a day. Sending them all
    # overflowed every model's context window, so the model gets the most severe
    # examples plus exact per-rule totals instead.
    all_findings = store.findings_between(start, end)
    by_rule: dict[str, dict] = {}
    rule_ips: dict[str, set[str]] = defaultdict(set)
    for finding in all_findings:
        entry = by_rule.setdefault(
            finding.rule_id, {"severity": finding.severity, "findings": 0, "distinct_ips": 0}
        )
        entry["findings"] += 1
        if finding.ip:
            rule_ips[finding.rule_id].add(finding.ip)
    for rule_id, ips in rule_ips.items():
        by_rule[rule_id]["distinct_ips"] = len(ips)
    findings_by_rule = dict(
        sorted(
            by_rule.items(),
            key=lambda kv: (SEVERITY_ORDER.get(kv[1]["severity"], 9), -kv[1]["findings"], kv[0]),
        )
    )

    ranked = sorted(
        all_findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -(f.count or 0), f.ts),
    )
    # One example per (rule, ip) and a few per rule, so one noisy rule cannot
    # crowd out a rarer high-severity one.
    seen: set[tuple[str, str | None]] = set()
    per_rule: Counter[str] = Counter()
    picked = []
    for finding in ranked:
        key = (finding.rule_id, finding.ip)
        if key in seen or per_rule[finding.rule_id] >= max_per_rule:
            continue
        seen.add(key)
        per_rule[finding.rule_id] += 1
        picked.append(finding)
        if len(picked) >= max_findings:
            break
    findings = []
    for finding in picked:
        item = finding.to_dict()
        if item.get("ip"):
            item["ip"] = show(item["ip"])
        findings.append(item)

    return {
        "day": day,
        "host": host,
        "totals": {
            "events": total,
            "failed": sum(1 for e in events if e.kind in FAILED_KINDS),
            "accepted": sum(1 for e in events if e.kind in ACCEPTED_KINDS),
            "distinct_ips": len(ip_counts),
            "unparsed": kind_counts.get("other", 0),
        },
        "kinds": dict(kind_counts.most_common()),
        "top_ips": top_ips,
        "top_users": [
            {"username": name, "count": count} for name, count in user_counts.most_common(top_n)
        ],
        "countries": dict(country_counts.most_common(10)),
        "findings": findings,
        "findings_summary": {"total": len(all_findings), "by_rule": findings_by_rule},
        "comparison": {
            "events_vs_7day_avg": round(total / average, 2) if average else None,
            "seven_day_avg_events": round(average, 1) if average else None,
            "days_of_history": len(known_days),
            "new_ips_today": store.new_ips_on_day(day),
        },
        "privacy": {"ips_masked": mask},
    }
