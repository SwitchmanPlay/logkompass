# Case study: an SSH honeypot that reports on itself

**Live dashboard:** https://switchmanplay.github.io/logkompass/ ·
**Code:** https://github.com/SwitchmanPlay/logkompass

A small, end-to-end security project: put a fake SSH server on the public internet,
capture what attackers do, and turn it into a daily plain-English briefing and a
self-refreshing dashboard — all on free infrastructure.

---

## The problem

LogKompass began as a tool that summarised the SSH auth log of one hardened server.
On a properly locked-down box that log is nearly empty — SSH is on a non-standard
port, so almost nothing reaches it. The daily summary was, in effect, *"nothing
happened again."* Technically fine, but it demonstrated nothing and produced no
interesting data.

So I inverted it: instead of hiding, **expose an intentional port 22 on a disposable
machine and record the flood.**

## What I built

```
             ┌────────────────────────────────────────────────────┐
attackers ──▶│  Sensor VM (Oracle Always Free, isolated network)   │
   :22       │                                                     │
             │  Cowrie honeypot  ──cowrie.json──▶  LogKompass       │
             │  (fake shell)                      collect (15 min)  │
             │                                        │             │
             │  real admin SSH :62222                 ▼             │
             │  (attackers never see it)          SQLite ──▶ daily  │
             │                                    aggregate + GeoIP │
             │                                        │             │
             └────────────────────────────────────────┼────────────┘
                                                       ▼
                          resilient LLM chain ──▶ 5-line briefing ──▶ Telegram
                                                       │
                    GitHub Actions (every 6 h) ──▶ GitHub Pages dashboard
```

- **Cowrie** answers port 22 with an emulated shell; attackers "log in" and run
  commands, but never touch a real system. Real admin SSH lives on a separate high
  port, on a separate cloud network — the trap can't endanger anything.
- **LogKompass** ingests Cowrie's events every 15 minutes, capturing the usernames,
  **passwords**, and **commands** attackers use, and enriches each source IP with
  country and network (GeoIP).
- A **resilient multi-model LLM chain** turns the day's aggregate into five plain
  lines. Detection is pure Python with tests; the model only writes prose, and its
  output is validated — a model that leaks its reasoning or invents an IP is skipped
  to the next one, and a deterministic template is the final safety net.
- A **GitHub Actions** job refreshes the public dashboard every 6 hours, reaching the
  sensor through a **dedicated key locked to a single read-only command** — the
  honeypot holds no credentials of its own.

## Results (first ~3 days)

The premise held immediately: the first real attacker arrived within minutes.

| | |
|---|---|
| **Events captured** | **~39,700** |
| **Distinct attacker IPs** | **309** |
| **Commands run in the fake shell** | **~10,500** |
| **Time-to-first-attack** | minutes |

**What the data shows**

- **A botnet, not people.** Most traffic came from a tight cluster of Bulgarian IPs
  (`109.160.32.x`, ASN *TechTies Inc.*), each hitting the sensor thousands of times —
  the signature of a single automated campaign spread across a subnet. Other volume
  came from the US and the Philippines.
- **Credential stuffing from a dictionary.** The most-tried logins were classic
  defaults — `support/support`, `root/123456`, `admin/admin`, `root/111111` — the
  same lists baked into IoT/Linux botnet malware.
- **Automated infection attempts.** Once "inside", attackers ran reconnaissance
  (`uname -s -v -n -r -m`), manipulated `PATH`, and wrote and executed shell scripts
  to stage a next-stage payload — exactly the behaviour of a self-propagating worm.
- **A real anomaly, surfaced automatically.** Once a baseline built up, the briefing
  flagged the *first successful login from a new country* as high-severity — the kind
  of signal that matters on a real server.

## Engineering highlights

- **Cloud + networking:** provisioned an isolated VM, opened only the ports needed,
  moved admin SSH off 22 with an `iptables` redirect, and hardened the host.
- **Test-driven ingestion:** the new Cowrie collector and its data-model changes were
  written test-first, with an additive database migration.
- **Robust LLM use:** treated the model as untrusted — validated, grounded output
  with a multi-model fallback chain and a deterministic template, after observing a
  real reasoning-leak failure in production and fixing it.
- **Threat intel:** GeoIP enrichment (country + ASN) turns raw IPs into "who and
  where."
- **Security-conscious automation:** the CI refresh uses a throwaway key restricted
  to one forced command, so a public-facing honeypot never holds push credentials.
- **Shipped and self-maintaining:** live dashboard on GitHub Pages, data refreshed on
  a schedule, daily briefing to Telegram — zero ongoing effort.

## Stack

Python · SQLite · Cowrie · systemd · Oracle Cloud (Always Free) · GeoIP2 ·
OpenRouter LLMs · GitHub Actions · GitHub Pages · matplotlib

---

*Numbers are a rolling snapshot and keep growing; see the
[live dashboard](https://switchmanplay.github.io/logkompass/) for current figures and
[docs/honeypot.md](honeypot.md) for the technical detail.*
