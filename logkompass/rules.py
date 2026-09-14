"""Deterministic detections. No model involved, one test per rule per outcome.

Rules 01 to 03 and 07 count noise. Rules 04 to 06 are the ones that matter: on a
properly configured canary they should only ever fire for the owner.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .config import RuleSettings
from .enrich.history import History, StaticHistory
from .models import ACCEPTED_KINDS, FAILED_KINDS, NOISE_KINDS, Event, Finding
from .util import iso, parse_iso

RULE_SEVERITY = {
    "R01_burst": "medium",
    "R02_user_spray": "medium",
    "R03_high_value_user": "low",
    "R04_success_after_failures": "high",
    "R05_new_country_success": "high",
    "R06_new_key_fingerprint": "high",
    "R07_protocol_noise": "info",
}

RULE_DESCRIPTIONS = {
    "R01_burst": "many failed attempts from one IP in a short window",
    "R02_user_spray": "one IP tried many different usernames",
    "R03_high_value_user": "attempts against privileged account names",
    "R04_success_after_failures": "a login succeeded from an IP that had just been failing",
    "R05_new_country_success": "first successful login from this country",
    "R06_new_key_fingerprint": "successful login with an unseen public key",
    "R07_protocol_noise": "key exchange failures or malformed banners",
}


def _by_ip(events: list[Event], kinds: frozenset[str] | None = None) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.ip is None:
            continue
        if kinds is not None and event.kind not in kinds:
            continue
        grouped[event.ip].append(event)
    return grouped


def r01_burst(events, rc: RuleSettings, w_from: str, w_to: str) -> list[Finding]:
    findings = []
    window = timedelta(minutes=rc.burst_window_minutes)
    for ip, group in _by_ip(events, FAILED_KINDS).items():
        times = sorted(parse_iso(e.ts) for e in group)
        best = 0
        best_span = (times[0], times[0]) if times else None
        left = 0
        for right, moment in enumerate(times):
            while moment - times[left] > window:
                left += 1
            size = right - left + 1
            if size > best:
                best = size
                best_span = (times[left], moment)
        if best >= rc.burst_threshold and best_span:
            findings.append(
                Finding(
                    rule_id="R01_burst",
                    severity=RULE_SEVERITY["R01_burst"],
                    ts=iso(best_span[1]),
                    window_from=iso(best_span[0]),
                    window_to=iso(best_span[1]),
                    ip=ip,
                    count=best,
                    detail=(
                        f"{best} failed attempts within "
                        f"{rc.burst_window_minutes} minutes"
                    ),
                )
            )
    return findings


def r02_user_spray(events, rc: RuleSettings, w_from: str, w_to: str) -> list[Finding]:
    findings = []
    for ip, group in _by_ip(events, FAILED_KINDS).items():
        users = {e.username for e in group if e.username}
        if len(users) >= rc.spray_distinct_users:
            sample = ", ".join(sorted(users)[:6])
            findings.append(
                Finding(
                    rule_id="R02_user_spray",
                    severity=RULE_SEVERITY["R02_user_spray"],
                    ts=w_to,
                    window_from=w_from,
                    window_to=w_to,
                    ip=ip,
                    count=len(users),
                    detail=f"{len(users)} distinct usernames, e.g. {sample}",
                )
            )
    return findings


def r03_high_value_user(events, rc: RuleSettings, w_from: str, w_to: str) -> list[Finding]:
    targets = {name.lower() for name in rc.high_value_users}
    findings = []
    for ip, group in _by_ip(events).items():
        hits = [e for e in group if e.username and e.username.lower() in targets]
        if not hits:
            continue
        names = sorted({e.username.lower() for e in hits if e.username})
        findings.append(
            Finding(
                rule_id="R03_high_value_user",
                severity=RULE_SEVERITY["R03_high_value_user"],
                ts=w_to,
                window_from=w_from,
                window_to=w_to,
                ip=ip,
                count=len(hits),
                detail="targeted " + ", ".join(names),
            )
        )
    return findings


def r04_success_after_failures(events, rc: RuleSettings, w_from: str, w_to: str) -> list[Finding]:
    findings = []
    lookback = timedelta(minutes=rc.success_lookback_minutes)
    failures = _by_ip(events, FAILED_KINDS)
    for event in events:
        if event.kind not in ACCEPTED_KINDS or not event.ip:
            continue
        moment = parse_iso(event.ts)
        recent = [
            e
            for e in failures.get(event.ip, [])
            if moment - lookback <= parse_iso(e.ts) < moment
        ]
        if len(recent) >= rc.success_after_failures:
            findings.append(
                Finding(
                    rule_id="R04_success_after_failures",
                    severity=RULE_SEVERITY["R04_success_after_failures"],
                    ts=event.ts,
                    window_from=iso(moment - lookback),
                    window_to=event.ts,
                    ip=event.ip,
                    username=event.username,
                    count=len(recent),
                    detail=(
                        f"accepted {event.method or 'login'} after {len(recent)} failures "
                        f"in the previous {rc.success_lookback_minutes} minutes"
                    ),
                )
            )
    return findings


def r05_new_country_success(
    events, rc: RuleSettings, w_from: str, w_to: str, history: History
) -> list[Finding]:
    seen = set(history.success_countries(w_from))
    findings = []
    for event in sorted(
        (e for e in events if e.kind in ACCEPTED_KINDS and e.ip), key=lambda e: e.ts
    ):
        country = history.country_of(event.ip)  # type: ignore[arg-type]
        if not country:
            continue
        if country in seen:
            continue
        seen.add(country)
        findings.append(
            Finding(
                rule_id="R05_new_country_success",
                severity=RULE_SEVERITY["R05_new_country_success"],
                ts=event.ts,
                window_from=w_from,
                window_to=w_to,
                ip=event.ip,
                username=event.username,
                count=1,
                detail=f"{country}, first successful login from this country",
            )
        )
    return findings


def r06_new_key_fingerprint(
    events, rc: RuleSettings, w_from: str, w_to: str, history: History
) -> list[Finding]:
    known = set(history.known_fingerprints(w_from))
    findings = []
    for event in sorted(
        (e for e in events if e.kind == "accepted_publickey" and e.key_fp), key=lambda e: e.ts
    ):
        if event.key_fp in known:
            continue
        known.add(event.key_fp)  # type: ignore[arg-type]
        findings.append(
            Finding(
                rule_id="R06_new_key_fingerprint",
                severity=RULE_SEVERITY["R06_new_key_fingerprint"],
                ts=event.ts,
                window_from=w_from,
                window_to=w_to,
                ip=event.ip,
                username=event.username,
                count=1,
                detail=f"unseen public key {event.key_fp}",
            )
        )
    return findings


def r07_protocol_noise(events, rc: RuleSettings, w_from: str, w_to: str) -> list[Finding]:
    findings = []
    for ip, group in _by_ip(events, NOISE_KINDS).items():
        if len(group) >= rc.protocol_noise_threshold:
            findings.append(
                Finding(
                    rule_id="R07_protocol_noise",
                    severity=RULE_SEVERITY["R07_protocol_noise"],
                    ts=w_to,
                    window_from=w_from,
                    window_to=w_to,
                    ip=ip,
                    count=len(group),
                    detail="key exchange failures or malformed banners",
                )
            )
    return findings


def evaluate(
    events: list[Event],
    rc: RuleSettings | None = None,
    w_from: str | None = None,
    w_to: str | None = None,
    history: History | None = None,
) -> list[Finding]:
    """Run every rule over one window. Pure function over events plus history."""
    rc = rc or RuleSettings()
    history = history or StaticHistory()
    if not events and (w_from is None or w_to is None):
        return []
    timestamps = sorted(e.ts for e in events) if events else []
    w_from = w_from or (timestamps[0] if timestamps else "")
    w_to = w_to or (timestamps[-1] if timestamps else "")

    findings: list[Finding] = []
    findings += r01_burst(events, rc, w_from, w_to)
    findings += r02_user_spray(events, rc, w_from, w_to)
    findings += r03_high_value_user(events, rc, w_from, w_to)
    findings += r04_success_after_failures(events, rc, w_from, w_to)
    findings += r05_new_country_success(events, rc, w_from, w_to, history)
    findings += r06_new_key_fingerprint(events, rc, w_from, w_to, history)
    findings += r07_protocol_noise(events, rc, w_from, w_to)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(findings, key=lambda f: (order.get(f.severity, 9), f.rule_id, f.ip or ""))
