"""Core value objects. Deliberately dumb dataclasses, no behaviour beyond shaping."""

from __future__ import annotations

from dataclasses import dataclass

FAILED_KINDS = frozenset(
    {"failed_password", "invalid_user", "max_auth_exceeded", "cowrie_login_failed"}
)
ACCEPTED_KINDS = frozenset(
    {"accepted_password", "accepted_publickey", "cowrie_login_success"}
)
NOISE_KINDS = frozenset({"kex_failure", "banner_garbage"})
# Honeypot (Cowrie) events beyond the login attempts above.
COWRIE_KINDS = frozenset({"cowrie_connect", "cowrie_command", "cowrie_session"})
KINDS = frozenset(
    FAILED_KINDS
    | ACCEPTED_KINDS
    | NOISE_KINDS
    | COWRIE_KINDS
    | {"preauth_disconnect", "other"}
)
SEVERITIES = ("info", "low", "medium", "high")


@dataclass(frozen=True)
class Event:
    ts: str
    host: str
    kind: str
    raw: str
    raw_hash: str
    username: str | None = None
    ip: str | None = None
    port: int | None = None
    method: str | None = None
    key_fp: str | None = None
    password: str | None = None  # honeypot: the password an attacker tried
    command: str | None = None  # honeypot: a command run in the fake shell

    @property
    def is_failed(self) -> bool:
        return self.kind in FAILED_KINDS

    @property
    def is_accepted(self) -> bool:
        return self.kind in ACCEPTED_KINDS

    @property
    def is_noise(self) -> bool:
        return self.kind in NOISE_KINDS

    def as_row(self) -> tuple:
        return (
            self.ts,
            self.host,
            self.kind,
            self.username,
            self.ip,
            self.port,
            self.method,
            self.key_fp,
            self.raw_hash,
            self.raw,
            self.password,
            self.command,
        )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    ts: str
    window_from: str
    window_to: str
    ip: str | None = None
    username: str | None = None
    count: int | None = None
    detail: str = ""

    def as_row(self) -> tuple:
        return (
            self.ts,
            self.rule_id,
            self.severity,
            self.ip,
            self.username,
            self.window_from,
            self.window_to,
            self.count,
            self.detail,
        )

    def to_dict(self) -> dict:
        data = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "ip": self.ip,
            "username": self.username,
            "count": self.count,
            "detail": self.detail,
        }
        return {k: v for k, v in data.items() if v not in (None, "")}


@dataclass(frozen=True)
class Actor:
    ip: str
    first_seen: str
    last_seen: str
    country: str | None = None
    asn: int | None = None
    as_org: str | None = None
    total_events: int = 0
    total_failed: int = 0
    ever_accepted: int = 0
