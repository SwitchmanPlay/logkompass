"""Command line interface: collect | rules | aggregate | digest | probe | stats | prune."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__
from .aggregate import build_aggregate
from .collect import collect_once
from .config import Config, ConfigError
from .digest import format_message, make_digest
from .enrich.geoip import GeoIp
from .enrich.history import StoreHistory
from .llm import LlmClient
from .notify import stdout as stdout_sink
from .notify import telegram as telegram_sink
from .probe import run_probe
from .rules import evaluate
from .store import Store
from .util import in_quiet_hours, iso, now_utc, parse_duration

DEFAULT_CONFIG_PATHS = ("config.toml", "/etc/logkompass/config.toml")


def find_config(explicit: str | None) -> str:
    if explicit:
        return explicit
    for candidate in DEFAULT_CONFIG_PATHS:
        if Path(candidate).is_file():
            return candidate
    raise ConfigError(
        "no config file found; pass --config or create ./config.toml"
    )


def load(args) -> tuple[Config, Store]:
    cfg = Config.load(find_config(args.config))
    if args.db:
        cfg.paths.db = args.db
    return cfg, Store.open(cfg.paths.db)


def make_geo(cfg: Config) -> GeoIp:
    return GeoIp.from_paths(cfg.paths.geoip_country, cfg.paths.geoip_asn)


def make_client(cfg: Config) -> LlmClient | None:
    providers = cfg.available_providers()
    return LlmClient(providers) if providers else None


def emit(data: dict) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))


def cmd_collect(args) -> int:
    cfg, store = load(args)
    geo = make_geo(cfg)
    try:
        result = collect_once(store, cfg, geo=geo if geo.enabled else None)
        if geo.enabled:
            result["geo_backfilled"] = store.backfill_geo(geo)
    finally:
        geo.close()
        store.close()
    emit(result)
    return 0


def cmd_rules(args) -> int:
    cfg, store = load(args)
    try:
        until = now_utc()
        since = until - parse_duration(args.since)
        w_from, w_to = iso(since), iso(until)
        events = store.events_between(w_from, w_to)
        geo = make_geo(cfg)
        history = StoreHistory(
            store, geo=geo if geo.enabled else None,
            known_fingerprints=cfg.rules.known_key_fingerprints,
        )
        findings = evaluate(events, cfg.rules, w_from, w_to, history)
        inserted = store.insert_findings(findings)
        geo.close()
    finally:
        store.close()
    emit(
        {
            "window": {"from": w_from, "to": w_to},
            "events": len(events),
            "findings": [f.to_dict() for f in findings],
            "new_findings": inserted.inserted,
            "repeat_findings": inserted.duplicates,
        }
    )
    return 0


def resolve_day(store: Store, day: str | None) -> str:
    if day and day != "today":
        return day
    if day == "today" or day is None:
        return now_utc().date().isoformat() if day == "today" else (
            store.latest_day() or now_utc().date().isoformat()
        )
    return day


def cmd_aggregate(args) -> int:
    cfg, store = load(args)
    try:
        day = resolve_day(store, args.day)
        aggregate = build_aggregate(store, day, host=cfg.host, mask=args.mask)
    finally:
        store.close()
    text = json.dumps(aggregate, indent=2, sort_keys=True, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + "\n")
    else:
        print(text)
    return 0


def cmd_digest(args) -> int:
    cfg = Config.load(find_config(args.config))
    if args.db:
        cfg.paths.db = args.db
    store = None
    if args.input:
        aggregate = json.loads(Path(args.input).read_text())
    else:
        store = Store.open(cfg.paths.db)
        aggregate = build_aggregate(
            store, resolve_day(store, args.day), host=cfg.host, mask=args.mask
        )
    client = None if args.no_model else make_client(cfg)
    result = make_digest(aggregate, client=client)
    message = format_message(result, mask=args.mask or cfg.notify.mask_ips)

    sink_result: dict = {"ok": True, "sink": "none"}
    if args.notify == "telegram":
        silent = in_quiet_hours(now_utc().hour, cfg.quiet_hours)
        sink_result = telegram_sink.send(
            cfg.notify.telegram_token or "",
            cfg.notify.chat_id or "",
            message,
            disable_notification=silent,
        )
    elif args.notify == "stdout":
        sink_result = stdout_sink.send(message)

    if store is not None and not args.no_store:
        store.record_digest(
            day=result.day,
            text=message,
            model=result.model,
            path=result.path,
            latency_ms=result.latency_ms,
            created_at=iso(now_utc()),
        )
    if store is not None:
        store.close()

    if args.notify != "stdout":
        emit(
            {
                "day": result.day,
                "path": result.path,
                "provider": result.provider,
                "model": result.model,
                "latency_ms": result.latency_ms,
                "errors": result.errors,
                "notify": sink_result,
            }
        )
    return 0


def cmd_probe(args) -> int:
    cfg = Config.load(find_config(args.config))
    if args.db:
        cfg.paths.db = args.db
    checks = run_probe(cfg, skip_model=args.skip_model)
    for check in checks:
        print(check.line())
    return 0 if all(check.ok for check in checks) else 1


def cmd_stats(args) -> int:
    cfg, store = load(args)
    try:
        stats = store.stats()
        stats["days_with_events"] = len(store.days_with_events())
        last = store.last_digest()
        if last is not None:
            stats["last_digest"] = {
                "day": last["day"],
                "path": last["path"],
                "model": last["model"],
                "latency_ms": last["latency_ms"],
            }
        if args.mask:
            from .util import mask_ip

            stats["top_ips"] = [
                {"ip": mask_ip(item["ip"]), "count": item["count"]} for item in stats["top_ips"]
            ]
    finally:
        store.close()
    emit(stats)
    return 0


def cmd_prune(args) -> int:
    cfg, store = load(args)
    try:
        result = store.prune(args.days or cfg.retention_days)
    finally:
        store.close()
    emit(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logkompass", description="SSH log triage with a local LLM")
    parser.add_argument("--version", action="version", version=f"logkompass {__version__}")
    parser.add_argument("--config", help="path to config.toml")
    parser.add_argument("--db", help="override [paths] db")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("collect", help="pull new log lines into the database").set_defaults(
        func=cmd_collect
    )

    rules = sub.add_parser("rules", help="run detections over a time window")
    rules.add_argument("--since", default="24h", help="lookback window, e.g. 45m, 24h, 7d")
    rules.set_defaults(func=cmd_rules)

    aggregate = sub.add_parser("aggregate", help="build the daily rollup JSON")
    aggregate.add_argument("--day", help="YYYY-MM-DD or today")
    aggregate.add_argument("--out", help="write JSON to this file instead of stdout")
    aggregate.add_argument("--mask", action="store_true", help="mask IPs for publishing")
    aggregate.set_defaults(func=cmd_aggregate)

    digest = sub.add_parser("digest", help="turn the rollup into five lines")
    digest.add_argument("--day", help="YYYY-MM-DD or today")
    digest.add_argument("--input", help="read an aggregate JSON file instead of the database")
    digest.add_argument("--notify", choices=["stdout", "telegram", "none"], default="stdout")
    digest.add_argument("--mask", action="store_true")
    digest.add_argument("--no-model", action="store_true", help="force the template path")
    digest.add_argument("--no-store", action="store_true")
    digest.set_defaults(func=cmd_digest)

    probe = sub.add_parser("probe", help="health check")
    probe.add_argument("--skip-model", action="store_true")
    probe.set_defaults(func=cmd_probe)

    stats = sub.add_parser("stats", help="totals, parse rate, top talkers")
    stats.add_argument("--mask", action="store_true")
    stats.set_defaults(func=cmd_stats)

    prune = sub.add_parser("prune", help="delete events older than the retention window")
    prune.add_argument("--days", type=int)
    prune.set_defaults(func=cmd_prune)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as error:
        print(f"config error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
