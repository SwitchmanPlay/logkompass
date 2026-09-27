#!/usr/bin/env python3
"""Export honeypot attack stats from the LogKompass database to JSON.

Run this on the sensor (it reads the SQLite database directly), then copy the
output to docs/findings/stats.json and render charts with tools/make_charts.py:

    sudo -u logkompass /opt/logkompass/.venv/bin/python tools/export_stats.py \
        --db /var/lib/logkompass/logkompass.db > stats.json
"""

from __future__ import annotations

import argparse
import json
import sqlite3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="/var/lib/logkompass/logkompass.db")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    def rows(sql: str) -> list[dict]:
        return [dict(r) for r in conn.execute(sql)]

    events, ips = conn.execute(
        "select count(*), count(distinct ip) from events"
    ).fetchone()

    out = {
        "generated_from": "LogKompass Cowrie sensor",
        "totals": {"events": events, "distinct_ips": ips},
        "by_kind": rows(
            "select kind, count(*) n from events group by kind order by n desc"
        ),
        "top_ips": rows(
            "select ip, count(*) n from events where ip is not null "
            "group by ip order by n desc limit 12"
        ),
        "top_credentials": rows(
            'select username || "/" || coalesce(password, "") cred, count(*) n '
            "from events where password is not null group by cred "
            "order by n desc limit 15"
        ),
        "top_usernames": rows(
            "select username, count(*) n from events where username is not null "
            "group by username order by n desc limit 12"
        ),
        "top_commands": rows(
            "select substr(command, 1, 80) cmd, count(*) n from events "
            "where command is not null group by command order by n desc limit 12"
        ),
        "by_hour": rows(
            "select substr(ts, 1, 13) hour, count(*) n from events "
            "group by hour order by hour"
        ),
    }

    latest = conn.execute(
        "select day, text, created_at from digests order by created_at desc limit 1"
    ).fetchone()
    if latest:
        out["latest_digest"] = dict(latest)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
