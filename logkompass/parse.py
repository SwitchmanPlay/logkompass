"""sshd message -> Event.

One compiled pattern per kind, ordered from most specific to least.

Three buckets, and the difference matters for the metric:
  * a real auth kind, when a pattern matches;
  * ``ignored``, for daemon lifecycle and session bookkeeping that carries no
    authentication signal (systemd start/stop, ``Server listening on``, PAM
    session open/close). Understood, stored, but not a parser gap;
  * ``other``, for lines we genuinely failed to recognise.

The parse rate counts only the third bucket against us. Scoring ``Started
OpenSSH server daemon.`` as a failure made the metric lie: on Oracle Linux 9 it
pushed a healthy host down to 0.38.

Distro note: ``journalctl -u sshd`` on RHEL-family hosts also returns the
unit-level records emitted by systemd itself, not just sshd's own output, which
is where most of the lifecycle noise comes from. Debian-family hosts use
``ssh.service`` and see the same pattern.
"""

from __future__ import annotations

import re

from .models import Event
from .util import is_ip, sha1

# Understood, but not authentication. Checked before PATTERNS so that a normal
# logout is never mistaken for a preauth disconnect.
IGNORED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^pam_unix\(sshd:session\): session (?:opened|closed)"),
    # Session bookkeeping only. pam_unix(sshd:auth) is a real auth failure and
    # must never be swallowed here.
    re.compile(r"^pam_(?:systemd|env|loginuid|keyinit|selinux)\(sshd:"),
    re.compile(r"^(?:Starting|Started|Stopping|Stopped|Reloading|Reloaded) "),
    re.compile(r"^sshd(?:-session|-auth)?\.service:"),
    re.compile(r"^Server listening on "),
    re.compile(r"^Received signal \d+"),
    re.compile(r"^(?:Received|Got) SIGHUP"),
    # Owner logging out cleanly. OpenSSH 9.x wording.
    re.compile(r"^Disconnected from user \S+ "),
    re.compile(r"^Received disconnect from \S+ port \d+:\d+: disconnected by user"),
    re.compile(r"^Accepted key \S+ \S+ found at "),
    re.compile(r"^Postponed (?:publickey|keyboard-interactive)"),
    re.compile(r"^userauth_pubkey: "),
    re.compile(r"^Set /proc/self/oom_score_adj"),
    re.compile(r"^Transferred: sent \d+"),
    re.compile(r"^debug\d?: "),
]

# (kind, pattern, method)
PATTERNS: list[tuple[str, re.Pattern[str], str | None]] = [
    (
        "accepted_publickey",
        re.compile(
            r"^Accepted publickey for (?P<username>\S+) from (?P<ip>\S+) port "
            r"(?P<port>\d+) ssh2(?::\s*(?P<keytype>\S+)\s+(?P<key_fp>\S+))?"
        ),
        "publickey",
    ),
    (
        "accepted_password",
        re.compile(
            r"^Accepted password for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "password",
    ),
    (
        "invalid_user",
        re.compile(
            r"^Failed password for invalid user (?P<username>.+?) from (?P<ip>\S+) "
            r"port (?P<port>\d+)"
        ),
        "password",
    ),
    (
        "invalid_user",
        re.compile(
            r"^Failed (?:publickey|none) for invalid user (?P<username>.+?) from "
            r"(?P<ip>\S+) port (?P<port>\d+)"
        ),
        "publickey",
    ),
    (
        "invalid_user",
        re.compile(r"^Invalid user (?P<username>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
        None,
    ),
    (
        "failed_password",
        re.compile(r"^Failed password for (?P<username>.+?) from (?P<ip>\S+) port (?P<port>\d+)"),
        "password",
    ),
    (
        "failed_password",
        re.compile(
            r"^Failed (?:publickey|none) for (?P<username>.+?) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        "publickey",
    ),
    (
        "max_auth_exceeded",
        re.compile(
            r"^error: maximum authentication attempts exceeded for (?:invalid user )?"
            r"(?P<username>.+?) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        None,
    ),
    (
        # OpenSSH 9.x: "Disconnecting authenticating user root 1.2.3.4 port 5: Too
        # many authentication failures [preauth]"
        "max_auth_exceeded",
        re.compile(
            r"^Disconnecting (?:(?:authenticating|invalid) user (?P<username>\S+) )?"
            r"(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+): Too many authentication failures"
        ),
        None,
    ),
    (
        # Oracle Linux 9 / OpenSSH 9.8 adds "Connection reset" to the family that
        # older builds wrote as "Connection closed". Both forms appear with an
        # optional "authenticating user" / "invalid user" qualifier, or with a bare IP.
        "preauth_disconnect",
        re.compile(
            r"^(?:Disconnected|Connection closed|Connection reset)(?: (?:from|by))? "
            r"(?:(?:authenticating|invalid) user (?P<username>\S+) )?"
            r"(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
        ),
        None,
    ),
    (
        "preauth_disconnect",
        re.compile(r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        "preauth_disconnect",
        re.compile(
            r"^Timeout before authentication for (?:user \S+ )?"
            r"(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
        ),
        None,
    ),
    (
        "kex_failure",
        re.compile(r"^Unable to negotiate with (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        # Very common scanner signature on a public host. The IP is not always
        # present ("Connection closed by remote host"), so the fallback fills in.
        "kex_failure",
        re.compile(r"^error: kex_exchange_identification: "),
        None,
    ),
    (
        "kex_failure",
        re.compile(r"^fatal: .*? from (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        "banner_garbage",
        re.compile(r"^banner exchange: Connection from (?P<ip>\S+) port (?P<port>\d+)"),
        None,
    ),
    (
        "banner_garbage",
        re.compile(
            r"^Bad protocol version identification .*? from (?P<ip>\S+) port (?P<port>\d+)"
        ),
        None,
    ),
    (
        "banner_garbage",
        re.compile(
            r"^Invalid SSH identification string from (?P<ip>\S+)(?: port (?P<port>\d+))?"
        ),
        None,
    ),
]

ANY_IP_RE = re.compile(r"(?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7})")
ANY_PORT_RE = re.compile(r"\bport (\d{1,5})\b")


def _clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().strip(":")
    return candidate if is_ip(candidate) else None


def _fallback_ip(message: str) -> str | None:
    for match in ANY_IP_RE.finditer(message):
        if is_ip(match.group(0)):
            return match.group(0)
    return None


def _fallback_port(message: str) -> int | None:
    match = ANY_PORT_RE.search(message)
    if not match:
        return None
    value = int(match.group(1))
    return value if 0 < value <= 65535 else None


def is_ignored(message: str) -> bool:
    """True for daemon lifecycle and session bookkeeping lines."""
    text = message.strip()
    return any(pattern.match(text) for pattern in IGNORED_PATTERNS)


def parse_line(message: str, ts: str, host: str = "localhost") -> Event:
    """Parse one sshd log message. Never raises, never returns None."""
    text = message.strip()

    if is_ignored(text):
        return Event(
            ts=ts,
            host=host,
            kind="ignored",
            raw=text,
            raw_hash=sha1(text),
        )

    for kind, pattern, method in PATTERNS:
        match = pattern.match(text)
        if not match:
            continue
        groups = match.groupdict()
        port = groups.get("port")
        username = groups.get("username")
        return Event(
            ts=ts,
            host=host,
            kind=kind,
            raw=text,
            raw_hash=sha1(text),
            username=username.strip() if username else None,
            ip=_clean_ip(groups.get("ip")) or _fallback_ip(text),
            port=int(port) if port and port.isdigit() else _fallback_port(text),
            method=method,
            key_fp=groups.get("key_fp"),
        )

    return Event(
        ts=ts,
        host=host,
        kind="other",
        raw=text,
        raw_hash=sha1(text),
        ip=_fallback_ip(text),
    )


def parse_rate(events: list[Event]) -> float:
    """Share of lines we understood: matched a kind, or knowingly ignored.

    Only the ``other`` bucket counts as a miss, which is what makes the number
    worth putting in a README.
    """
    if not events:
        return 1.0
    understood = sum(1 for e in events if e.kind != "other")
    return understood / len(events)
