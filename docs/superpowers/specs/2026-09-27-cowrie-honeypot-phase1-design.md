# LogKompass → SSH Threat Sensor: Phase 1 Design

**Date:** 2026-09-27
**Status:** Draft for review
**Author:** Danya + Claude

## Why (intent)

LogKompass is a well-built SSH auth-log triage pipeline, but it is starved of
signal: the monitored box runs SSH on port 2242 with port 22 closed, so it
collects ~1 benign scanner event/day and never sees the credential-stuffing
flood its own README describes. The daily briefings are therefore empty and the
project "doesn't make sense."

**Goal:** turn LogKompass from a log summarizer for a quiet box into a real SSH
**honeypot + threat sensor** that captures genuine attack data, as the foundation
for a portfolio showpiece (a polished repo + write-up, then a live dashboard).

**Primary success criterion (CV framing):** within a week of going live, the
sensor has captured thousands of real login attempts from hundreds of distinct
IPs, with usernames, passwords, and post-login commands, feeding clean daily
LLM briefings and a growing dataset ready to visualize.

## Scope

Phase 1 only. Phases 2 (repo + data write-up) and 3 (live public dashboard) are
separate specs, both built on the dataset Phase 1 produces.

### In scope
- Provision a dedicated, isolated honeypot sensor VM (Oracle Always Free).
- Run Cowrie (medium-interaction SSH honeypot) on port 22.
- Extend LogKompass to ingest Cowrie's JSON event log as a new collector source.
- Add password + command capture to the event model.
- Fix the LLM digest reliability issues seen in production.
- Harden the sensor and keep the existing admin box out of the blast radius.

### Non-goals (Phase 1)
- No web dashboard/frontend (Phase 3).
- No data-analysis write-up/charts (Phase 2).
- No multi-sensor fleet or central aggregation.
- No changes to the existing admin box (92.5.164.90) beyond leaving it alone.

## Architecture

```
  attackers ──►  SENSOR VM (new, Oracle Always Free, Frankfurt)
                 ├─ Cowrie honeypot on :22  (emulated shell, never real OS)
                 │    └─ writes var/log/cowrie/cowrie.json  (JSON lines)
                 ├─ admin SSH on a high port, keys-only  (our access)
                 └─ LogKompass
                      ├─ collect source = "cowrie"  → Event objects
                      ├─ enrich (GeoIP, history)   [existing]
                      ├─ rules / aggregate / digest [existing]
                      ├─ digest → Telegram          [existing]
                      └─ SQLite = the dataset  → feeds Phases 2 & 3

  ADMIN BOX (existing, 92.5.164.90) — untouched, SSH stays on :2242
```

LogKompass runs **on the sensor** (mirrors the current deployment model:
collect locally, digest locally, notify). The sensor's SQLite DB is the dataset
later phases read.

## Components

### 1. Sensor VM (Oracle Always Free)
- Region: eu-frankfurt-1 (same tenancy/region as existing box).
- Shape: Always Free (VM.Standard.E2.1.Micro, or A1.Flex within remaining free
  allowance). Image: Ubuntu 24.04 or Oracle Linux 9 (match tooling to Cowrie).
- SSH keys: a **new dedicated keypair** for admin access to the sensor (not
  reused from the admin box). Admin SSH on a non-22 high port.
- Network: security list / NSG opens **TCP 22 to 0.0.0.0/0** (for Cowrie) and
  the admin port to 0.0.0.0/0 (or a narrower range). Oracle Ubuntu images ship
  iptables with a trailing REJECT — rules must be inserted, not just appended
  (the repo's `bootstrap_canary.sh` already documents this gotcha).

### 2. Cowrie
- Install per upstream (dedicated non-root user, Python venv).
- Cowrie listens on 2222 internally; redirect port 22 → 2222 via iptables (do
  not run Cowrie as root).
- Enable JSON logging (`output_jsonlog`) to a stable path.
- Keep it medium-interaction (emulated filesystem/shell). No real command
  execution, no outbound from the fake shell.
- Do **not** run fail2ban or rate-limiting on the sensor — we want the attacks.

### 3. Event-model changes (`logkompass/models.py`)
Additive and backward-compatible:
- Add optional fields to `Event`: `password: str | None = None`,
  `command: str | None = None`.
- Add kinds: `cowrie_connect`, `cowrie_login_failed`, `cowrie_login_success`,
  `cowrie_command`, `cowrie_session`.
- Extend `FAILED_KINDS` / `ACCEPTED_KINDS` so `is_failed` / `is_accepted` stay
  meaningful for Cowrie login events.
- `as_row()` and the store schema gain the two new columns (migration: additive
  `ALTER TABLE` guarded by a version check; existing rows get NULLs).

### 4. New collector (`logkompass/collect/cowrie.py`)
- Mirrors `authlog.py`: read `cowrie.json` from a byte offset + inode cursor
  (idempotent, resumable), map Cowrie event types → `Event`s.
- Mapping (Cowrie `eventid` → kind):
  - `cowrie.session.connect` → `cowrie_connect` (ip, port)
  - `cowrie.login.failed` → `cowrie_login_failed` (username, password)
  - `cowrie.login.success` → `cowrie_login_success` (username, password)
  - `cowrie.command.input` → `cowrie_command` (command)
  - `cowrie.session.closed` → `cowrie_session`
- Wire into `collect/__init__.py` under `cfg.collect.source == "cowrie"`.
- Config: add `[collect] source = "cowrie"` and a `cowrie_json_path`.

### 5. LLM digest reliability (`logkompass/llm.py`, `digest.py`)
Observed failures in production Telegram output:
- Reasoning models leak chain-of-thought ("Here's a thinking process:…") →
  validation fails → deterministic template fallback.
- One run numbered the 5 lines `2 3 4 5` (misread "5 lines").
Fixes:
- Pin the known-good model (`nvidia/nemotron-3-ultra-...:free`, clean + ~2s) and
  treat the lightning model as unsupported.
- Pre-validation cleanup: strip a leading reasoning preamble / `<think>…</think>`
  and any leading line-numbering before the 5-line check.
- On validation failure, retry once with a stricter instruction before falling
  back to the template.
- (Stretch) a tiny offline eval: a handful of recorded aggregate JSONs asserted
  to produce 5 valid lines. Optional in Phase 1.

## Data flow
attacker hits :22 → Cowrie logs JSON event → LogKompass `collect` (every ~15 min
timer) reads new lines → parses to `Event`s → GeoIP/history enrich → store in
SQLite → daily `aggregate` + `digest` → LLM → Telegram; SQLite accumulates the
full history for later phases.

## Error handling
- Collector is cursor-based and idempotent; a crashed run resumes at the last
  offset, duplicates are de-duped by `raw_hash`.
- Cowrie log rotation handled like authlog (inode change ⇒ re-read from 0).
- Digest degrades gracefully to the deterministic template (already present).

## Testing
- Unit: `collect/cowrie.py` against captured sample `cowrie.json` lines (fixture)
  → expected `Event`s, following the existing collector test pattern.
- Store migration: old DB opens, new columns added, old rows readable.
- LLM cleanup: preamble/line-number strings → 5 clean lines.
- Manual acceptance: sensor live, first real attacks visible in SQLite within
  hours, a clean digest delivered to Telegram.

## Security / risk
- Blast radius: honeypot is a separate VM with its own throwaway key; the admin
  box is untouched. Even a Cowrie escape (rare) reaches only a disposable free VM.
- Cowrie is an emulator — attackers never touch a real OS or real credentials.
- Egress from the sensor should be restricted so it can't be used to attack
  others (limit outbound; Cowrie's fake shell has no real network).
- Oracle Always Free idle-reclamation: the sensor is continuously active, so
  low reclamation risk; the SQLite dataset is what would hurt to lose — back it
  up (Phase 2 can rsync it off-box).

## Open questions for review
1. LogKompass on the sensor (recommended) vs. sensor-as-dumb-source + separate
   box? Spec assumes on-sensor.
2. Image preference: Ubuntu 24.04 vs. Oracle Linux 9 for the sensor?
3. Keep the existing admin box's LogKompass running as-is, or repoint everything
   to the sensor? Spec assumes existing box is left alone.
