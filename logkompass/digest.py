"""Aggregate -> five lines -> Telegram.

Three guards, in order:
  1. shape: exactly five usable lines, no markdown, no absurd line length.
  2. grounding: every IPv4 and every count in the output must appear in the input JSON.
     A model that invents an attacker is worse than no model.
  3. fallback: if the chain fails or a guard trips, a deterministic template writes the
     digest and the message says so. The `path` column makes that visible in the data.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .llm import LlmClient, LlmError
from .util import IPV4_RE, iso, mask_text, now_utc

SYSTEM_PROMPT = """You are a security analyst writing a daily SSH briefing for one server owner.
Input is a JSON summary of one day of sshd authentication events.

Write exactly five lines, plain text, no markdown, no bullets.
Line 1: volume and whether it is normal compared to the 7-day average.
Line 2: the single most active source, with country and network.
Line 3: what the attackers were trying, in terms of usernames and method.
Line 4: the highest severity finding and what it means, or "no high-severity findings".
Line 5: one concrete recommendation, or "no action needed".

Rules: use only numbers present in the JSON. Never invent an IP, country or count.
If a field is missing, say so. Maximum 30 words per line. No greetings, no sign-off.
Output only the five lines and nothing else: no title or header line, no markdown
headers, no code blocks, no bullet points. Do not restate this task, do not think out
loud, and do not echo the JSON field names. Begin your answer directly with line 1."""

MARKDOWN_PREFIX = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|#+\s+)")

# Signs the model leaked its reasoning or restated the task instead of just
# answering. A clean briefing never contains any of these.
_REASONING_MARKERS = re.compile(
    r"(here'?s a thinking|thinking process|the user wants|i need to write|"
    r"i'?ll write|i will write|let me (analyze|think|write|start)|as an ai|"
    r"chain of thought|analyz(e|ing) the (json|request|data|input)|the json summary|"
    r"to summar(ize|ise)|\bstep \d\b|based on the (json|provided|input)|"
    r"i'?m going to|i should (write|start|note))",
    re.IGNORECASE,
)
_JSON_ECHO = re.compile(r"^[a-z][\w]*(?:\.[a-z][\w]*)+\s*[:=]", re.IGNORECASE)
_MD_HEADER = re.compile(r"^\*\*.+\*\*:?\s*$")
FALLBACK_NOTICE = "[template fallback, model unreachable]"
GUARD_NOTICE = "[template fallback, model output failed validation]"


@dataclass
class DigestResult:
    day: str
    host: str
    lines: list[str]
    path: str  # local_llm | cloud_llm | template_fallback
    provider: str | None = None
    model: str = "template"
    latency_ms: int | None = None
    notice: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def used_model(self) -> bool:
        return self.path != "template_fallback"


def build_user_prompt(aggregate: dict) -> str:
    return json.dumps(aggregate, indent=2, sort_keys=True, ensure_ascii=False)


def five_lines(text: str) -> list[str] | None:
    lines = [MARKDOWN_PREFIX.sub("", line).strip() for line in (text or "").splitlines()]
    lines = [line for line in lines if line]
    if len(lines) < 5:
        return None
    return lines[:5]


def _numbers(text: str) -> set[str]:
    return set(re.findall(r"\d[\d.]*", text))


def looks_like_reasoning(lines: list[str]) -> bool:
    """True if the model leaked its reasoning or restated the task."""
    for line in lines:
        if (
            _REASONING_MARKERS.search(line)
            or _JSON_ECHO.match(line)
            or _MD_HEADER.match(line)
            or line.startswith("```")
        ):
            return True
    return False


def validate(aggregate: dict, lines: list[str]) -> tuple[bool, str]:
    """Grounding check: the model may only mention IPs that are in the input."""
    if looks_like_reasoning(lines):
        return False, "model leaked reasoning instead of a clean briefing"
    blob = json.dumps(aggregate, ensure_ascii=False)
    known_ips = set(IPV4_RE.findall(blob))
    for line in lines:
        if len(line.split()) > 45:
            return False, "a line is far longer than the 30 word limit"
        for found in IPV4_RE.findall(line):
            if found not in known_ips:
                return False, f"line mentions an IP that is not in the aggregate: {found}"
    return True, "ok"


def _pct(ratio: float | None) -> str:
    if ratio is None:
        return "no baseline yet"
    delta = (ratio - 1.0) * 100
    if abs(delta) < 5:
        return "in line with the 7-day average"
    direction = "above" if delta > 0 else "below"
    return f"{abs(delta):.0f} percent {direction} the 7-day average"


def render_template(aggregate: dict) -> list[str]:
    """Deterministic five lines from the same JSON. Never fails, never invents."""
    totals = aggregate.get("totals", {})
    comparison = aggregate.get("comparison", {})
    top_ips = aggregate.get("top_ips") or []
    top_users = aggregate.get("top_users") or []
    findings = aggregate.get("findings") or []

    line1 = (
        f"{totals.get('events', 0)} auth events from "
        f"{totals.get('distinct_ips', 0)} IPs, {_pct(comparison.get('events_vs_7day_avg'))}."
    )
    if top_ips:
        top = top_ips[0]
        line2 = (
            f"Loudest source {top.get('ip')}, {top.get('country') or 'country unknown'}, "
            f"{top.get('as_org') or 'network unknown'}, {top.get('count')} attempts, "
            f"first seen {top.get('first_seen') or 'unknown'}."
        )
    else:
        line2 = "No source IPs recorded today."
    if top_users:
        names = ", ".join(str(u.get("username")) for u in top_users[:3])
        line3 = (
            f"{totals.get('failed', 0)} failed attempts, most targeted usernames {names}; "
            f"{totals.get('accepted', 0)} accepted."
        )
    else:
        line3 = f"{totals.get('failed', 0)} failed and {totals.get('accepted', 0)} accepted attempts."

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ranked = sorted(findings, key=lambda f: order.get(str(f.get("severity")), 9))
    high = [f for f in ranked if f.get("severity") == "high"]
    if high:
        top_finding = high[0]
        line4 = (
            f"High: {top_finding.get('rule_id')} for {top_finding.get('ip') or 'unknown IP'} "
            f"({top_finding.get('detail') or 'see findings'})."
        )
        line5 = "Check that this login was you; if not, rotate keys and close password auth."
    elif ranked:
        top_finding = ranked[0]
        line4 = (
            f"No high-severity findings; highest is {top_finding.get('rule_id')} "
            f"({top_finding.get('severity')})."
        )
        line5 = "No action needed. Password auth stays open by design on this host."
    else:
        line4 = "No findings fired today."
        line5 = "No action needed."
    return [line1, line2, line3, line4, line5]


def make_digest(
    aggregate: dict,
    client: LlmClient | None = None,
    local_provider_names: tuple[str, ...] = ("local",),
) -> DigestResult:
    day = str(aggregate.get("day", ""))
    host = str(aggregate.get("host", "unknown"))
    errors: list[str] = []

    if client is not None:

        def _accept(text: str) -> bool:
            lines = five_lines(text)
            return lines is not None and validate(aggregate, lines)[0]

        try:
            result = client.complete(
                SYSTEM_PROMPT, build_user_prompt(aggregate), accept=_accept
            )
            lines = five_lines(result.text)
            if lines is not None:  # guaranteed by _accept, checked for safety
                is_local = any(
                    name in result.provider for name in local_provider_names
                )
                return DigestResult(
                    day=day,
                    host=host,
                    lines=lines,
                    path="local_llm" if is_local else "cloud_llm",
                    provider=result.provider,
                    model=result.model,
                    latency_ms=result.latency_ms,
                    errors=errors,
                )
        except LlmError as error:
            errors.append(str(error))
        except Exception as error:  # noqa: BLE001
            errors.append(f"{type(error).__name__}: {error}")

    notice = GUARD_NOTICE if errors and client is not None else FALLBACK_NOTICE
    if client is None:
        notice = "[template digest, no model configured]"
    return DigestResult(
        day=day,
        host=host,
        lines=render_template(aggregate),
        path="template_fallback",
        provider=None,
        model="template",
        latency_ms=None,
        notice=notice,
        errors=errors,
    )


def format_message(result: DigestResult, mask: bool = False) -> str:
    header = f"LogKompass {result.host}, {result.day}"
    parts = [header, ""]
    if result.notice:
        parts.append(result.notice)
    parts.extend(result.lines)
    parts.append("")
    if result.used_model:
        seconds = (result.latency_ms or 0) / 1000
        parts.append(f"model: {result.model} via {result.provider}, {seconds:.1f} s")
    else:
        parts.append(f"model: none, deterministic template, {iso(now_utc())}")
    text = "\n".join(parts)
    return mask_text(text) if mask else text
