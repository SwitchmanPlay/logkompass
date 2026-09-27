# LogKompass

SSH authentication log triage for a single small server. Deterministic rules find the
signal, a local LLM writes five lines of English, systemd runs it every 15 minutes,
SQLite keeps 90 days of history. No agent, no cloud log pipeline, no dashboard.

## 🍯 Live SSH honeypot

LogKompass also runs as the front end of a real **SSH honeypot**: a public port 22
answered by [Cowrie](https://github.com/cowrie/cowrie), capturing the passwords and
commands attackers use. It geolocates them, writes a daily LLM briefing, and shows
it all on a self-refreshing dashboard.

**▶ [Live dashboard](https://switchmanplay.github.io/logkompass/)** ·
**📄 [Architecture & findings](docs/honeypot.md)**

[![LogKompass honeypot dashboard — loudest attacker IPs by country](docs/findings/chart_ips.png)](https://switchmanplay.github.io/logkompass/)

<sub>Live attacker traffic — click the chart for the full dashboard.</sub>

```
journald -> parse -> SQLite -> rules -> 24h aggregate (JSON) -> LLM -> 5 lines -> Telegram
```

Built around one rule: **the model never decides anything.** Detection is pure Python
with unit tests. The model only turns an already-computed summary into prose, and if it
is unreachable or invents an IP, a deterministic template writes the digest instead and
says so.

## Why this exists

A public SSH port collects a few thousand credential-stuffing attempts a day. Reading
`journalctl` is useless at that volume, and hosted SIEM tooling is absurd for one box.
This is the small version that actually gets read: one message a day that says whether
anything changed.

## What it does

- Reads sshd events from journald with a saved cursor, or from `auth.log` with byte
  offset and inode tracking. Re-running it inserts nothing new.
- Parses 9 event kinds. Unmatched lines are kept in an `other` bucket and counted, so
  the parse rate is a visible metric instead of a silent gap.
- Enriches IPs with country and ASN from local MaxMind GeoLite2 files. Offline, no API.
- Runs 7 rules, severity `info` to `high`, each with tests for the firing and the
  near-miss case.
- Aggregates a day into a small JSON object and asks the model for exactly five lines.
- Sends to Telegram, silent during quiet hours.

### Rules

| id | severity | fires when |
| --- | --- | --- |
| `R01_burst` | medium | >= 20 failures from one IP inside a 10 minute sliding window |
| `R02_user_spray` | medium | one IP tried >= 8 distinct usernames |
| `R03_high_value_user` | low | attempts against `root`, `admin`, `oracle`, `postgres`, `jenkins`, `git` |
| `R04_success_after_failures` | high | a login succeeded from an IP that failed >= 3 times in the previous hour |
| `R05_new_country_success` | high | first successful login ever from that country |
| `R06_new_key_fingerprint` | high | successful publickey login with a fingerprint never seen before |
| `R07_protocol_noise` | info | >= 5 key exchange failures or malformed banners from one IP |

R01 to R03 and R07 describe the background noise. R04 to R06 are the ones worth a
notification: on a correctly configured host they should only ever fire for the owner.
History for R05 and R06 is always queried with `ts < window_from`, so today's own
events cannot normalise today's detection and re-running the rules is stable.

## Example digest

```
LogKompass canary-01, 2026-09-20

4193 auth events from 212 IPs, 18 percent above the 7-day average.
Loudest source 198.51.100.x, NL, Example Hosting, 890 attempts, first seen 14 Sep.
Mostly password guessing against root, admin and ubuntu across 14 usernames.
High: accepted login from a new country, AT, user danya, key auth. Looks like you.
No action needed. Password auth stays open by design on this host.

model: qwen3-27b via local-qwen3, 6.4 s
```

IPs are masked in this README and in anything published. `--mask` does that for you.

## Install

```bash
git clone https://github.com/SwitchmanPlay/logkompass.git
cd logkompass
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp config.example.toml config.toml   # edit paths and providers
.venv/bin/logkompass --config config.toml probe
```

Runtime dependencies: none. Python 3.11+ standard library only, `geoip2` is an optional
extra. That is deliberate, the target is a 1 GB free-tier VM.

## Usage

```bash
logkompass collect                     # pull new lines from journald
logkompass rules --since 24h           # evaluate and store findings
logkompass aggregate --day today       # the JSON the model gets to see
logkompass digest --day today --notify telegram
logkompass probe                       # health check: logs, db, geoip, model, notify
logkompass stats --mask                # totals, parse rate, top talkers
logkompass prune --days 90             # retention
```

Deployment is `sudo bash scripts/deploy.sh`: service user, venv, systemd timer every 15
minutes, digest timer at 07:05. Server setup for a fresh Ubuntu host is
`scripts/bootstrap_canary.sh`. Both are idempotent.

- [docs/oracle-cloud.md](docs/oracle-cloud.md) for the Oracle Cloud Always Free walkthrough,
  including the iptables trap that silently drops traffic on Ubuntu images.
- [docs/model-providers.md](docs/model-providers.md) for local vs hosted models and the
  three deployment shapes.

## Model layer

Providers are an ordered list. The first one that answers wins, everything is
OpenAI-compatible, and which path ran is written into the `digests` table.

```toml
[[llm.providers]]
name = "local-qwen3"
base_url = "http://100.x.y.z:8081/v1"     # llama.cpp / vLLM on your own machine
model = "qwen3-27b"
extra_body = { chat_template_kwargs = { enable_thinking = false } }

[[llm.providers]]
name = "openrouter-free"
base_url = "https://openrouter.ai/api/v1"
model = "meta-llama/llama-3.3-70b-instruct:free"
api_key = "env:OPENROUTER_API_KEY"
```

Three guards around the model output:

1. **Shape.** Exactly five usable lines, markdown bullets stripped, absurd lengths rejected.
2. **Grounding.** Every IPv4 in the answer must appear in the aggregate. A model that
   invents an attacker is worse than no model, so the answer is discarded.
3. **Fallback.** On failure a deterministic template writes the same five lines from the
   same JSON, the message is labelled, and `digests.path` records `template_fallback`.

Only the aggregate is ever sent to a model: counts, top talkers, countries, findings.
No raw log lines, no usernames beyond the top few, and `mask_ips = true` truncates IPs
before they leave the host. With the local provider nothing leaves the network at all.

## Privacy and retention

IP addresses are personal data under GDPR. Therefore: 90 day retention enforced by
`prune`, last octet dropped in anything published, secrets only as `env:NAME`
references, and the database is in `.gitignore`.

## Tests

```bash
.venv/bin/pytest -q
```

Covers the parser against a 63 line fixture (>95 percent parse rate), every rule firing
and not firing, idempotent inserts, history scoping, config validation including typo
rejection, the provider fallback chain, the hallucination guard, a golden digest, and
the CLI end to end. No network, no real log files, no real model: transports, log
readers and GeoIP readers are injected.

## Limits

- Single host. Multi-host would need a collector protocol, not a bigger SQLite file.
- No blocking. It watches, it does not firewall. fail2ban would poison the dataset, and
  the point is measurement.
- GeoIP is country and ASN only, city data is noise at this resolution.
- The digest is best effort prose. The database is the source of truth.

MIT licensed.
