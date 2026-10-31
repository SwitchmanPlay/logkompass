"""Reclassify events already stored in SQLite, in place, from their raw text.

Why this exists: the journald cursor has already moved past those lines, so a
plain `logkompass collect` will not re-emit them. After a parser fix you either
throw the history away or replay it from `events.raw`. This replays it.

    sudo -u logkompass /opt/logkompass/.venv/bin/python \\
        /opt/logkompass/tools/reparse.py --db /var/lib/logkompass/logkompass.db

Add --dry-run first to see what would change. Nothing is deleted: only the
kind, username, ip, port, method and key_fp columns are rewritten from raw.
"""

from __future__ import annotations

import argparse
import collections
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logkompass.parse import parse_line  # noqa: E402


def reparse(db_path: str, only_other: bool, dry_run: bool) -> dict[str, int]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Cowrie rows hold JSON, not sshd text; parse_line would turn every one of
    # them into "other". They are never reparsed.
    where = "WHERE kind = 'other'" if only_other else "WHERE substr(kind, 1, 7) != 'cowrie_'"
    rows = conn.execute(f"SELECT id, ts, host, raw, kind FROM events {where}").fetchall()

    moves: collections.Counter[str] = collections.Counter()
    changed = 0
    for row in rows:
        event = parse_line(row["raw"], row["ts"], host=row["host"] or "localhost")
        if event.kind == row["kind"]:
            continue
        changed += 1
        moves[f"{row['kind']} -> {event.kind}"] += 1
        if dry_run:
            continue
        conn.execute(
            "UPDATE events SET kind = ?, username = ?, ip = ?, port = ?, "
            "method = ?, key_fp = ? WHERE id = ?",
            (
                event.kind,
                event.username,
                event.ip,
                event.port,
                event.method,
                event.key_fp,
                row["id"],
            ),
        )
    if not dry_run:
        conn.commit()

    kinds = collections.Counter(
        r[0] for r in conn.execute("SELECT kind FROM events").fetchall()
    )
    conn.close()
    return {"scanned": len(rows), "changed": changed, "moves": dict(moves), "kinds": dict(kinds)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="/var/lib/logkompass/logkompass.db")
    parser.add_argument(
        "--all",
        action="store_true",
        help="rescan every row, not just the ones currently in the other bucket",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    result = reparse(args.db, only_other=not args.all, dry_run=args.dry_run)
    print(f"scanned {result['scanned']} rows, reclassified {result['changed']}")
    for move, count in sorted(result["moves"].items(), key=lambda kv: -kv[1]):
        print(f"  {move}: {count}")
    print("kinds now:")
    for kind, count in sorted(result["kinds"].items(), key=lambda kv: -kv[1]):
        print(f"  {kind}: {count}")
    if args.dry_run:
        print("(dry run, nothing written)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
