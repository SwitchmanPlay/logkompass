"""TOML config with strict validation.

Two rules worth defending in an interview:
  1. Secrets are only ever referenced as "env:NAME". A value in the file is rejected.
  2. Unknown keys are an error, not a shrug. A typo in a threshold must not silently
     disable a detection rule.
"""

from __future__ import annotations

import os
import socket
import tomllib
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Mapping


class ConfigError(RuntimeError):
    pass


def _build(cls: type, data: Mapping[str, Any], section: str):
    if not isinstance(data, Mapping):
        raise ConfigError(f"[{section}] must be a table")
    known = {f.name for f in fields(cls) if is_dataclass(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{section}] has unknown keys: {sorted(unknown)}")
    return cls(**dict(data))


def resolve_secret(
    value: Any, *, env: Mapping[str, str] | None = None, label: str = "value", required: bool = True
) -> str | None:
    """Resolve "env:NAME" indirection. Plain secrets in the file are refused."""
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    environ = os.environ if env is None else env
    if not value.startswith("env:"):
        raise ConfigError(
            f"{label} must be written as \"env:VARIABLE_NAME\"; literal secrets are not allowed"
        )
    name = value[4:].strip()
    if not name:
        raise ConfigError(f"{label} is missing an environment variable name")
    resolved = environ.get(name)
    if resolved:
        return resolved
    if required:
        raise ConfigError(f"{label} refers to ${name}, which is not set")
    return None


@dataclass
class Paths:
    db: str = "/var/lib/logkompass/logkompass.db"
    geoip_country: str | None = None
    geoip_asn: str | None = None


@dataclass
class Collect:
    source: str = "journald"
    unit: str = "ssh"
    authlog_path: str = "/var/log/auth.log"
    max_lines_per_run: int = 50000

    def __post_init__(self) -> None:
        if self.source not in ("journald", "authlog"):
            raise ConfigError("[collect] source must be journald or authlog")


@dataclass
class RuleSettings:
    burst_window_minutes: int = 10
    burst_threshold: int = 20
    spray_distinct_users: int = 8
    high_value_users: list[str] = field(
        default_factory=lambda: ["root", "admin", "oracle", "postgres", "jenkins", "git"]
    )
    success_after_failures: int = 3
    success_lookback_minutes: int = 60
    protocol_noise_threshold: int = 5
    known_key_fingerprints: list[str] = field(default_factory=list)


@dataclass
class Provider:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    timeout_seconds: int = 90
    max_tokens: int = 700
    temperature: float = 0.0
    extra_body: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    available: bool = True
    unavailable_reason: str | None = None


@dataclass
class Notify:
    telegram_token: str | None = None
    chat_id: str | None = None
    quiet_hours: list[int] = field(default_factory=lambda: [23, 7])
    mask_ips: bool = False


DEFAULT_PROVIDER = Provider(
    name="local",
    base_url="http://127.0.0.1:8081/v1",
    model="local-model",
    extra_body={"chat_template_kwargs": {"enable_thinking": False}},
)


@dataclass
class Config:
    paths: Paths = field(default_factory=Paths)
    collect: Collect = field(default_factory=Collect)
    rules: RuleSettings = field(default_factory=RuleSettings)
    providers: list[Provider] = field(default_factory=lambda: [DEFAULT_PROVIDER])
    notify: Notify = field(default_factory=Notify)
    host: str = field(default_factory=socket.gethostname)
    retention_days: int = 90

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], env: Mapping[str, str] | None = None) -> "Config":
        allowed = {"paths", "collect", "rules", "llm", "notify", "host", "retention_days"}
        unknown = set(data) - allowed
        if unknown:
            raise ConfigError(f"unknown config sections: {sorted(unknown)}")

        paths = _build(Paths, data.get("paths", {}), "paths")
        collect = _build(Collect, data.get("collect", {}), "collect")
        rules = _build(RuleSettings, data.get("rules", {}), "rules")

        llm = data.get("llm", {}) or {}
        if set(llm) - {"providers"}:
            raise ConfigError(f"[llm] has unknown keys: {sorted(set(llm) - {'providers'})}")
        providers: list[Provider] = []
        for index, raw in enumerate(llm.get("providers", []) or []):
            provider = _build(Provider, raw, f"llm.providers[{index}]")
            if provider.api_key:
                key = resolve_secret(
                    provider.api_key,
                    env=env,
                    label=f"provider {provider.name} api_key",
                    required=False,
                )
                provider.api_key = key
                if not key:
                    provider.available = False
                    provider.unavailable_reason = "api key env var not set"
            providers.append(provider)
        if not providers:
            providers = [DEFAULT_PROVIDER]

        notify = _build(Notify, data.get("notify", {}), "notify")
        # Telegram secrets are strict: if you configured Telegram, it has to work.
        notify.telegram_token = resolve_secret(
            notify.telegram_token, env=env, label="[notify] telegram_token", required=True
        )
        notify.chat_id = resolve_secret(
            notify.chat_id, env=env, label="[notify] chat_id", required=True
        )

        return cls(
            paths=paths,
            collect=collect,
            rules=rules,
            providers=providers,
            notify=notify,
            host=str(data.get("host") or socket.gethostname()),
            retention_days=int(data.get("retention_days", 90)),
        )

    @classmethod
    def load(cls, path: str | Path, env: Mapping[str, str] | None = None) -> "Config":
        file_path = Path(path)
        if not file_path.is_file():
            raise ConfigError(f"config file not found: {file_path}")
        with file_path.open("rb") as handle:
            data = tomllib.load(handle)
        return cls.from_dict(data, env=env)

    @property
    def quiet_hours(self) -> tuple[int, int] | None:
        hours = self.notify.quiet_hours
        if not hours or len(hours) != 2:
            return None
        return int(hours[0]), int(hours[1])

    def available_providers(self) -> list[Provider]:
        return [p for p in self.providers if p.available]
