"""Health check. Run it after deploy and before blaming the parser."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .llm import LlmClient, LlmError
from .store import Store


@dataclass
class Check:
    name: str
    ok: bool
    detail: str

    def line(self) -> str:
        return f"[{'ok' if self.ok else 'FAIL'}] {self.name}: {self.detail}"


def check_log_source(cfg: Config) -> Check:
    if cfg.collect.source == "journald":
        binary = shutil.which("journalctl")
        if not binary:
            return Check("log source", False, "journalctl not found in PATH")
        readable = os.access("/var/log/journal", os.R_OK) or os.access("/run/log/journal", os.R_OK)
        return Check(
            "log source",
            True,
            f"journalctl at {binary}, unit {cfg.collect.unit}"
            + ("" if readable else " (journal dir not directly readable, group membership needed)"),
        )
    path = Path(cfg.collect.authlog_path)
    if not path.is_file():
        return Check("log source", False, f"{path} does not exist (Ubuntu 24.04 may lack rsyslog)")
    if not os.access(path, os.R_OK):
        return Check("log source", False, f"{path} is not readable by this user")
    return Check("log source", True, f"{path}, {path.stat().st_size} bytes")


def check_database(cfg: Config) -> Check:
    try:
        store = Store.open(cfg.paths.db)
        store.set_state("probe", "ok")
        stats = store.stats()
        store.close()
    except Exception as error:  # noqa: BLE001
        return Check("database", False, f"{type(error).__name__}: {error}")
    return Check(
        "database",
        True,
        f"{cfg.paths.db}, {stats['events']} events, parse rate {stats['parse_rate']:.1%}",
    )


def check_geoip(cfg: Config) -> Check:
    missing = [
        path
        for path in (cfg.paths.geoip_country, cfg.paths.geoip_asn)
        if path and not Path(path).is_file()
    ]
    if not cfg.paths.geoip_country and not cfg.paths.geoip_asn:
        return Check("geoip", True, "not configured, country and ASN will be empty")
    if missing:
        return Check("geoip", False, f"missing mmdb files: {missing}")
    try:
        import geoip2.database  # noqa: F401
    except ImportError:
        return Check("geoip", False, "mmdb files present but geoip2 is not installed")
    return Check("geoip", True, "country and ASN databases readable")


def check_model(cfg: Config, client: LlmClient | None = None) -> Check:
    providers = cfg.available_providers()
    skipped = [f"{p.name} ({p.unavailable_reason})" for p in cfg.providers if not p.available]
    if not providers:
        return Check("model", False, f"no usable provider; skipped: {skipped or 'none configured'}")
    llm = client or LlmClient(providers, retries=0)
    try:
        result = llm.complete(
            "Reply with the single word ok.", "Say ok."
        )
    except LlmError as error:
        return Check("model", False, str(error)[:300])
    detail = f"{result.provider} answered in {result.latency_ms} ms with model {result.model}"
    if skipped:
        detail += f"; skipped: {skipped}"
    return Check("model", True, detail)


def check_notify(cfg: Config) -> Check:
    if not cfg.notify.telegram_token or not cfg.notify.chat_id:
        return Check("notify", True, "telegram not configured, digests print to stdout")
    return Check("notify", True, f"telegram configured, quiet hours {cfg.quiet_hours}")


def run_probe(cfg: Config, client: LlmClient | None = None, skip_model: bool = False) -> list[Check]:
    checks = [check_log_source(cfg), check_database(cfg), check_geoip(cfg), check_notify(cfg)]
    if not skip_model:
        checks.append(check_model(cfg, client))
    return checks
