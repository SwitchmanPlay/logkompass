# Deploying on Oracle Cloud Always Free

Written for an account that already exists. Roughly 30 minutes, including the two things
that usually waste an afternoon: the Ubuntu host firewall and idle reclamation.

## 0. Pick the shape first

Always Free gives you two options ([Oracle docs](https://docs.oracle.com/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)):

| shape | free allowance | verdict |
| --- | --- | --- |
| `VM.Standard.A1.Flex` (Ampere ARM) | 4 OCPU and 24 GB RAM to split across instances | take this, 1 OCPU / 6 GB is plenty and leaves room |
| `VM.Standard.E2.1.Micro` (AMD) | 2 instances, 1/8 OCPU, 1 GB RAM each | fallback when A1 capacity is unavailable |

A1 capacity is often exhausted in popular regions. If creation fails with an
out-of-capacity error, either retry later or create an E2.1.Micro. LogKompass runs fine
on 1 GB: no runtime dependencies, SQLite, a oneshot timer capped at 200 MB.

Your instance must be in your **home region** to stay free.

## 1. Network

Console > Networking > Virtual cloud networks > **Start VCN wizard** > *VCN with internet
connectivity*. Accept the defaults. That gives you a VCN, a public subnet, an internet
gateway and route table in one step.

## 2. Instance

Compute > Instances > **Create instance** ([docs](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/launchinginstance.htm)):

1. Name: `canary-01`.
2. Image: **Canonical Ubuntu 24.04**. Shape: change to `VM.Standard.A1.Flex`,
   1 OCPU, 6 GB.
3. Networking: the VCN and public subnet from step 1, **assign a public IPv4 address**.
4. SSH keys: paste your public key (`cat ~/.ssh/id_ed25519.pub`). Oracle never creates a
   password for you, key auth only, user `ubuntu`.
5. Boot volume: leave at 50 GB. Always Free covers 200 GB total across volumes, so do not
   create four 50 GB instances and expect them all to be free.
6. Create. Note the public IP.

```bash
ssh ubuntu@<public-ip>    # works immediately, port 22
```

## 3. Two firewalls, not one

This is the part that breaks people.

**Cloud side.** Networking > your VCN > the public subnet > its security list > Add
ingress rule: source `0.0.0.0/0`, IP protocol TCP, destination port range `2242`. Leave
the existing port 22 rule alone, port 22 is the bait that produces the data.

**Host side.** Oracle's Ubuntu images do **not** use UFW. The rules live in
`/etc/iptables/rules.v4` and the INPUT chain ends in a REJECT. A rule appended after that
REJECT never matches, and from outside you get a misleading "no route to host"
([Oracle blog](https://blogs.oracle.com/developers/enabling-network-traffic-to-ubuntu-images-in-oracle-cloud-infrastructure)).
The new rule must sit **above** the REJECT, next to the port 22 rule:

```
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 2242 -j ACCEPT
```

```bash
sudo nano /etc/iptables/rules.v4          # insert the line under the port 22 rule
sudo /sbin/iptables-restore < /etc/iptables/rules.v4
sudo iptables -L INPUT -n --line-numbers  # verify order: ACCEPTs before REJECT
```

`scripts/bootstrap_canary.sh` inserts the rule in the right position and persists it with
`netfilter-persistent save`, so you can skip the manual edit.

## 4. Make it a canary

From your laptop:

```bash
scp scripts/bootstrap_canary.sh ubuntu@<public-ip>:/tmp/
ssh ubuntu@<public-ip>
sudo ADMIN_USER=danya ADMIN_KEY="$(cat ~/.ssh/id_ed25519.pub)" bash /tmp/bootstrap_canary.sh
```

What you end up with:

- port 22 open with `PasswordAuthentication yes`, `PermitRootLogin no`,
  `AllowUsers danya`, `MaxAuthTries 4`, `LogLevel VERBOSE`. Bots can knock all day and
  cannot get in, because the only allowed user has no usable password.
- port 2242 key-only via `Match LocalPort 2242`. That is your real door.
- unattended security upgrades enabled.
- **no fail2ban.** Banning attackers destroys the dataset this tool exists to measure.

**Before closing your current session**, prove the new port works:

```bash
ssh -p 2242 danya@<public-ip>
```

If that fails, you still have the old session to fix it. This is the one step not to rush.

## 5. Install LogKompass

```bash
sudo apt-get update && sudo apt-get install -y git python3-venv rsync
git clone https://github.com/SwitchmanPlay/logkompass.git
cd logkompass
sudo bash scripts/deploy.sh
```

Then configure:

```bash
sudo nano /etc/logkompass/config.toml    # host name, provider base_url, thresholds
sudo nano /etc/logkompass/env            # LOGKOMPASS_TG_TOKEN, LOGKOMPASS_TG_CHAT, OPENROUTER_API_KEY
sudo -u logkompass /opt/logkompass/.venv/bin/logkompass --config /etc/logkompass/config.toml probe
```

Ubuntu 24.04 cloud images often ship without rsyslog, so `/var/log/auth.log` may not
exist. That is why `source = "journald"` is the default, and why the unit is called
`ssh`, not `sshd`. Check with `systemctl status ssh` and `journalctl -u ssh -n 5`.

Optional GeoIP (free MaxMind account, GeoLite2 Country and ASN in mmdb format):

```bash
sudo mv GeoLite2-*.mmdb /var/lib/logkompass/
sudo chown logkompass:logkompass /var/lib/logkompass/GeoLite2-*.mmdb
sudo /opt/logkompass/.venv/bin/pip install "geoip2"
```

Without them, country and ASN stay empty and R05 never fires. Everything else works.

## 6. Verify

```bash
systemctl list-timers | grep logkompass
journalctl -u logkompass-collect.service -n 50 --no-pager
sudo -u logkompass /opt/logkompass/.venv/bin/logkompass --config /etc/logkompass/config.toml stats
```

After an hour you should see a few hundred events and a parse rate above 0.95. If the
parse rate is low, paste a few `other` rows into an issue, that is exactly the case the
bucket exists for.

## 7. Two Always Free traps

**Idle reclamation.** Oracle may reclaim an Always Free compute instance when, over a
7-day window, CPU 95th percentile stays below 20 percent, network below 20 percent, and
(on A1) memory below 20 percent. A log triage box is idle by definition. Reclaimed
instances are stopped and can be removed, and people have reported A1 quota silently
dropping afterwards. Mitigations, in order of sanity:

1. Keep a backup of `/var/lib/logkompass/logkompass.db` and `/etc/logkompass/` off the
   box. Rebuilding takes 10 minutes with `deploy.sh`, the data is what hurts to lose.
2. Upgrade to a Pay As You Go account. Always Free resources stay free, the reclamation
   policy does not apply.
3. Give the box a second, genuinely useful job so it is not idle.

**Egress.** 10 TB per month outbound is included. Telegram messages and a nightly digest
are rounding errors against that.

## Alternative: any other VPS

Nothing here is Oracle-specific except sections 1 to 3. On Hetzner, Netcup or a Raspberry
Pi at home, skip to step 4, and on distributions that use UFW replace the iptables edit
with `ufw allow 2242/tcp`. Verify your provider allows running a deliberately exposed SSH
port before you start.
