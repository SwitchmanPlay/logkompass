"""SQLite persistence: schema, idempotent writes, cursor state.

Every write path is idempotent. Replaying the same log twice must insert nothing
the second time, otherwise a retried timer run would invent an attack.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .models import ACCEPTED_KINDS, FAILED_KINDS, Actor, Event, Finding
from .util import day_bounds, parse_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY,
  ts            TEXT    NOT NULL,
  host          TEXT    NOT NULL,
  kind          TEXT    NOT NULL,
  username      TEXT,
  ip            TEXT,
  port          INTEGER,
  method        TEXT,
  key_fp        TEXT,
  raw_hash      TEXT    NOT NULL,
  raw           TEXT    NOT NULL,
  UNIQUE(raw_hash, ts)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

CREATE TABLE IF NOT EXISTS actors (
  ip            TEXT PRIMARY KEY,
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  country       TEXT,
  asn           INTEGER,
  as_org        TEXT,
  total_events  INTEGER NOT NULL DEFAULT 0,
  total_failed  INTEGER NOT NULL DEFAULT 0,
  ever_accepted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
  id          INTEGER PRIMARY KEY,
  ts          TEXT NOT NULL,
  rule_id     TEXT NOT NULL,
  severity    TEXT NOT NULL,
  ip          TEXT,
  username    TEXT,
  window_from TEXT,
  window_to   TEXT,
  count       INTEGER,
  detail      TEXT,
  UNIQUE(rule_id, ip, window_from)
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);

CREATE TABLE IF NOT EXISTS state (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS digests (
  day        TEXT PRIMARY KEY,
  text       TEXT NOT NULL,
  model      TEXT NOT NULL,
  path       TEXT NOT NULL,
  latency_ms INTEGER,
  created_at TEXT NOT NULL
);
"""

GeoLookup = Callable[[str], tuple[str | None, int | None, str | None]]


@dataclass
class InsertResult:
    seen: int = 0
    inserted: int = 0

    @property
    def duplicates(self) -> int:
        return self.seen - self.inserted


def _row_to_event(row: sqlite3.Row) -> Event:
    return Event(
        ts=row["ts"],
        host=row["host"],
        kind=row["kind"],
        raw=row["raw"],
        raw_hash=row["raw_hash"],
        username=row["username"],
        ip=row["ip"],
        port=row["port"],
        method=row["method"],
        key_fp=row["key_fp"],
    )


class Store:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.conn.row_factory = sqlite3.Row

    @classmethod
    def open(cls, path: str | Path) -> "Store":
        target = str(path)
        if target != ":memory:":
            Path(target).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(target)
        store = cls(conn)
        store.migrate()
        return store

    def migrate(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ---------- writes ----------

    def insert_events(self, events: Iterable[Event], geo: GeoLookup | None = None) -> InsertResult:
        result = InsertResult()
        for event in events:
            result.seen += 1
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO events"
                " (ts, host, kind, username, ip, port, method, key_fp, raw_hash, raw)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                event.as_row(),
            )
            if cur.rowcount:
                result.inserted += 1
                if event.ip:
                    self._touch_actor(event, geo)
        self.conn.commit()
        return result

    def _touch_actor(self, event: Event, geo: GeoLookup | None) -> None:
        assert event.ip is not None
        failed = 1 if event.kind in FAILED_KINDS else 0
        accepted = 1 if event.kind in ACCEPTED_KINDS else 0
        row = self.conn.execute("SELECT * FROM actors WHERE ip = ?", (event.ip,)).fetchone()
        if row is None:
            country = asn = as_org = None
            if geo is not None:
                country, asn, as_org = geo(event.ip)
            self.conn.execute(
                "INSERT INTO actors"
                " (ip, first_seen, last_seen, country, asn, as_org,"
                "  total_events, total_failed, ever_accepted)"
                " VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (event.ip, event.ts, event.ts, country, asn, as_org, failed, accepted),
            )
            return
        self.conn.execute(
            "UPDATE actors SET"
            "  first_seen = MIN(first_seen, ?),"
            "  last_seen = MAX(last_seen, ?),"
            "  total_events = total_events + 1,"
            "  total_failed = total_failed + ?,"
            "  ever_accepted = MAX(ever_accepted, ?)"
            " WHERE ip = ?",
            (event.ts, event.ts, failed, accepted, event.ip),
        )

    def set_actor_geo(
        self, ip: str, country: str | None, asn: int | None, as_org: str | None
    ) -> None:
        self.conn.execute(
            "UPDATE actors SET country = ?, asn = ?, as_org = ? WHERE ip = ?",
            (country, asn, as_org, ip),
        )
        self.conn.commit()

    def backfill_geo(self, geo: GeoLookup) -> int:
        rows = self.conn.execute(
            "SELECT ip FROM actors WHERE country IS NULL AND asn IS NULL"
        ).fetchall()
        updated = 0
        for row in rows:
            country, asn, as_org = geo(row["ip"])
            if country or asn:
                self.set_actor_geo(row["ip"], country, asn, as_org)
                updated += 1
        return updated

    def insert_findings(self, findings: Iterable[Finding]) -> InsertResult:
        result = InsertResult()
        for finding in findings:
            result.seen += 1
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO findings"
                " (ts, rule_id, severity, ip, username, window_from, window_to, count, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                finding.as_row(),
            )
            if cur.rowcount:
                result.inserted += 1
        self.conn.commit()
        return result

    def record_digest(
        self, day: str, text: str, model: str, path: str, latency_ms: int | None, created_at: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO digests (day, text, model, path, latency_ms, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(day) DO UPDATE SET text = excluded.text, model = excluded.model,"
            " path = excluded.path, latency_ms = excluded.latency_ms,"
            " created_at = excluded.created_at",
            (day, text, model, path, latency_ms, created_at),
        )
        self.conn.commit()

    def get_state(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_state(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO state (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        self.conn.commit()

    def prune(self, days: int) -> dict:
        from datetime import timedelta

        from .util import iso, now_utc

        cutoff = iso(now_utc() - timedelta(days=days))
        events = self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
        findings = self.conn.execute("DELETE FROM findings WHERE ts < ?", (cutoff,)).rowcount
        actors = self.conn.execute(
            "DELETE FROM actors WHERE ip NOT IN (SELECT DISTINCT ip FROM events WHERE ip IS NOT NULL)"
        ).rowcount
        self.conn.commit()
        return {"cutoff": cutoff, "events": events, "findings": findings, "actors": actors}

    # ---------- reads ----------

    def events_between(self, start: str, end: str) -> list[Event]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE ts >= ? AND ts < ? ORDER BY ts, id", (start, end)
        ).fetchall()
        return [_row_to_event(row) for row in rows]

    def events_on_day(self, day: str) -> list[Event]:
        start, end = day_bounds(day)
        return self.events_between(start, end)

    def count_events_between(self, start: str, end: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ?", (start, end)
        ).fetchone()
        return int(row["n"])

    def actor(self, ip: str) -> Actor | None:
        row = self.conn.execute("SELECT * FROM actors WHERE ip = ?", (ip,)).fetchone()
        if row is None:
            return None
        return Actor(**{key: row[key] for key in row.keys()})

    def actors(self, ips: Sequence[str] | None = None) -> dict[str, Actor]:
        if ips is None:
            rows = self.conn.execute("SELECT * FROM actors").fetchall()
        else:
            if not ips:
                return {}
            marks = ",".join("?" for _ in ips)
            rows = self.conn.execute(
                f"SELECT * FROM actors WHERE ip IN ({marks})", tuple(ips)
            ).fetchall()
        return {row["ip"]: Actor(**{key: row[key] for key in row.keys()}) for row in rows}

    def new_ips_on_day(self, day: str) -> int:
        start, end = day_bounds(day)
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM actors WHERE first_seen >= ? AND first_seen < ?",
            (start, end),
        ).fetchone()
        return int(row["n"])

    def accepted_countries_before(self, before: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT a.country AS country FROM events e"
            " JOIN actors a ON a.ip = e.ip"
            " WHERE e.kind IN ('accepted_password', 'accepted_publickey')"
            "   AND e.ts < ? AND a.country IS NOT NULL",
            (before,),
        ).fetchall()
        return {row["country"] for row in rows}

    def key_fingerprints_before(self, before: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT key_fp FROM events"
            " WHERE kind = 'accepted_publickey' AND key_fp IS NOT NULL AND ts < ?",
            (before,),
        ).fetchall()
        return {row["key_fp"] for row in rows}

    def findings_between(self, start: str, end: str) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE ts >= ? AND ts < ? ORDER BY ts, id", (start, end)
        ).fetchall()
        return [
            Finding(
                rule_id=row["rule_id"],
                severity=row["severity"],
                ts=row["ts"],
                window_from=row["window_from"],
                window_to=row["window_to"],
                ip=row["ip"],
                username=row["username"],
                count=row["count"],
                detail=row["detail"] or "",
            )
            for row in rows
        ]

    def last_digest(self) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM digests ORDER BY day DESC LIMIT 1"
        ).fetchone()

    def stats(self) -> dict:
        totals = self.conn.execute(
            "SELECT COUNT(*) AS events,"
            " SUM(CASE WHEN kind = 'other' THEN 1 ELSE 0 END) AS unparsed,"
            " MIN(ts) AS first_ts, MAX(ts) AS last_ts"
            " FROM events"
        ).fetchone()
        events = int(totals["events"] or 0)
        unparsed = int(totals["unparsed"] or 0)
        kinds = {
            row["kind"]: int(row["n"])
            for row in self.conn.execute(
                "SELECT kind, COUNT(*) AS n FROM events GROUP BY kind ORDER BY n DESC"
            ).fetchall()
        }
        top = [
            {"ip": row["ip"], "count": int(row["n"])}
            for row in self.conn.execute(
                "SELECT ip, COUNT(*) AS n FROM events WHERE ip IS NOT NULL"
                " GROUP BY ip ORDER BY n DESC LIMIT 5"
            ).fetchall()
        ]
        actors = int(
            self.conn.execute("SELECT COUNT(*) AS n FROM actors").fetchone()["n"]
        )
        findings = int(
            self.conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
        )
        page_count = int(self.conn.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(self.conn.execute("PRAGMA page_size").fetchone()[0])
        return {
            "events": events,
            "unparsed": unparsed,
            "parse_rate": round(1.0 - (unparsed / events), 4) if events else 1.0,
            "kinds": kinds,
            "actors": actors,
            "findings": findings,
            "top_ips": top,
            "first_event": totals["first_ts"],
            "last_event": totals["last_ts"],
            "db_bytes": page_count * page_size,
        }

    def days_with_events(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT substr(ts, 1, 10) AS day FROM events ORDER BY day"
        ).fetchall()
        return [row["day"] for row in rows]

    def latest_day(self) -> str | None:
        row = self.conn.execute("SELECT MAX(ts) AS ts FROM events").fetchone()
        return parse_iso(row["ts"]).date().isoformat() if row and row["ts"] else None
