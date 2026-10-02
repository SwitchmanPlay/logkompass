#!/usr/bin/env python3
"""Check which free OpenRouter models currently produce a valid LogKompass briefing.

Free models come and go, rate-limit, and some "reasoning" models leak their
thoughts into the answer. This lists the account's free models, sends each the
real briefing prompt, and reports which return a clean, grounded, five-line
answer — so the config's provider chain can be kept pointed at working models.

Run it on the sensor so it has the API key, e.g.:

    sudo systemd-run --pipe --wait --uid=logkompass \
        -p EnvironmentFile=/etc/logkompass/env --working-directory=/opt/logkompass \
        /opt/logkompass/.venv/bin/python tools/model_check.py --limit 25
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request

from logkompass.config import Provider
from logkompass.digest import (
    SYSTEM_PROMPT,
    build_user_prompt,
    five_lines,
    looks_like_reasoning,
    validate,
)
from logkompass.llm import LlmClient

SAMPLE = {
    "day": "2026-10-01",
    "host": "honeypot-01",
    "totals": {"events": 12000, "failed": 30, "accepted": 5000, "ips": 120},
    "comparison": {"events_vs_7day_avg": 1.2, "new_ips_today": 20},
    "top_sources": [
        {"ip": "109.160.32.176", "country": "BG", "as_org": "TechTies Inc.", "events": 9000}
    ],
    "usernames": ["root", "admin", "ubuntu", "support"],
    "findings": [{"rule_id": "R03_high_value_user", "severity": "low", "ip": "109.160.32.176"}],
}


def free_models(key: str) -> list[str]:
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/models", headers={"Authorization": f"Bearer {key}"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        data = json.loads(resp.read())
    free = []
    for m in data.get("data", []):
        pricing = m.get("pricing", {})
        if str(pricing.get("prompt", "1")) in ("0", "0.0") and str(
            pricing.get("completion", "1")
        ) in ("0", "0.0"):
            free.append(m["id"])
    return free


def check(model: str, key: str, pause: float) -> str:
    provider = Provider(
        name="check",
        base_url="https://openrouter.ai/api/v1",
        model=model,
        api_key=key,
        temperature=0.0,
        max_tokens=700,
        timeout_seconds=30,
    )
    client = LlmClient([provider], retries=0)
    try:
        result = client.complete(SYSTEM_PROMPT, build_user_prompt(SAMPLE))
    except Exception as error:  # noqa: BLE001
        return f"ERR {str(error)[-40:]}"
    finally:
        time.sleep(pause)
    lines = five_lines(result.text)
    if not lines:
        return "FAIL <5 lines"
    if looks_like_reasoning(lines):
        return "LEAK reasoning"
    ok, why = validate(SAMPLE, lines)
    return f"PASS ({result.latency_ms}ms)" if ok else f"FAIL {why}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--pause", type=float, default=6.0, help="seconds between models (avoid 429)")
    args = ap.parse_args()
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        raise SystemExit("OPENROUTER_API_KEY not set")
    models = free_models(key)
    print(f"{len(models)} free models available; testing up to {args.limit}\n")
    passed = []
    for model in models[: args.limit]:
        verdict = check(model, key, args.pause)
        print(f"{model:52s} {verdict}")
        if verdict.startswith("PASS"):
            passed.append(model)
    print("\nWORKING:", passed or "(none right now)")


if __name__ == "__main__":
    main()
