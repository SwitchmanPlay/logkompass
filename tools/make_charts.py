#!/usr/bin/env python3
"""Render the honeypot findings charts from docs/findings/stats.json.

Regenerate the data first (on the sensor) with tools/export_stats.py, then:

    python tools/make_charts.py

Writes PNGs next to the JSON, in docs/findings/.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent.parent
FINDINGS = HERE / "docs" / "findings"

INK = "#1f2933"
ACCENT = "#2f6f8f"
ACCENT2 = "#c1666b"
GRID = "#e4e7eb"

plt.rcParams.update(
    {
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK,
        "text.color": INK,
        "xtick.color": INK,
        "ytick.color": INK,
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "figure.dpi": 130,
    }
)


def _hbar(labels, values, title, fname, color=ACCENT, xlabel="events"):
    labels, values = labels[::-1], values[::-1]  # biggest at top
    fig, ax = plt.subplots(figsize=(8, max(2.4, 0.44 * len(labels) + 1)))
    bars = ax.barh(labels, values, color=color)
    ax.set_title(title, loc="left", pad=10)
    ax.set_xlabel(xlabel)
    ax.spines[["top", "right"]].set_visible(False)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for b, v in zip(bars, values):
        ax.text(v, b.get_y() + b.get_height() / 2, f" {v:,}", va="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(FINDINGS / fname, bbox_inches="tight")
    plt.close(fig)
    print("wrote", fname)


def main() -> None:
    data = json.loads((FINDINGS / "stats.json").read_text())
    t = data["totals"]
    print(f"{t['events']:,} events from {t['distinct_ips']} IPs")

    k = data["by_kind"]
    _hbar([r["kind"].replace("cowrie_", "") for r in k], [r["n"] for r in k],
          "What attackers did (event types)", "chart_kinds.png")

    ip = data["top_ips"]
    _hbar([r["ip"] for r in ip], [r["n"] for r in ip],
          "Loudest attacker IPs", "chart_ips.png", color=ACCENT2)

    cr = data["top_credentials"][:12]
    _hbar([r["cred"] for r in cr], [r["n"] for r in cr],
          "Most-tried username / password", "chart_creds.png", xlabel="attempts")

    cmd = [r for r in data["top_commands"] if r.get("cmd")][:10]
    if cmd:
        _hbar([r["cmd"] for r in cmd], [r["n"] for r in cmd],
              "Most-run commands in the fake shell", "chart_commands.png",
              color=ACCENT, xlabel="times run")


if __name__ == "__main__":
    main()
