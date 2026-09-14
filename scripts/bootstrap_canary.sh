#!/usr/bin/env bash
# Prepare a fresh Ubuntu 24.04 host as an SSH canary.
#
# What it does:
#   - creates an unprivileged admin user with your public key
#   - opens a second sshd port (2242) that is key-only, keeps 22 open as bait
#   - inserts the iptables ACCEPT rule ABOVE the trailing REJECT rule, which is the
#     one thing that silently breaks on Oracle Cloud Ubuntu images
#   - enables unattended security upgrades
#
# Usage (as root, on the server):
#   ADMIN_USER=danya ADMIN_KEY="ssh-ed25519 AAAA... you@laptop" bash bootstrap_canary.sh
set -euo pipefail

ADMIN_USER="${ADMIN_USER:?set ADMIN_USER}"
ADMIN_KEY="${ADMIN_KEY:?set ADMIN_KEY to your public key}"
ADMIN_PORT="${ADMIN_PORT:-2242}"

log() { printf "\n==> %s\n" "$*"; }

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-venv python3-pip iptables-persistent unattended-upgrades sqlite3

log "admin user ${ADMIN_USER}"
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$ADMIN_USER"
fi
usermod -aG sudo "$ADMIN_USER"
install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
echo "$ADMIN_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
chown "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh/authorized_keys"
# passwordless sudo keeps the admin port usable without a password on the box
echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$ADMIN_USER"
chmod 440 "/etc/sudoers.d/90-$ADMIN_USER"

log "sshd canary config"
cat > /etc/ssh/sshd_config.d/99-canary.conf <<EOF
# Port 22 stays open on purpose: it is the bait that produces the data.
Port 22
Port ${ADMIN_PORT}
PermitRootLogin no
AllowUsers ${ADMIN_USER}
PasswordAuthentication yes
KbdInteractiveAuthentication no
MaxAuthTries 4
LoginGraceTime 20
LogLevel VERBOSE

# Real access happens here and only with a key.
Match LocalPort ${ADMIN_PORT}
    PasswordAuthentication no
    PubkeyAuthentication yes
EOF
sshd -t
systemctl reload ssh

log "iptables rule for port ${ADMIN_PORT}"
# Oracle Cloud Ubuntu images ship iptables rules ending in a REJECT. A rule appended
# after it is dead weight and you get "no route to host" from the outside.
if ! iptables -C INPUT -p tcp -m state --state NEW -m tcp --dport "$ADMIN_PORT" -j ACCEPT 2>/dev/null; then
  line=$(iptables -L INPUT --line-numbers -n | awk -v p="dpt:22" '$0 ~ p {print $1; exit}')
  if [ -n "${line:-}" ]; then
    iptables -I INPUT "$((line + 1))" -p tcp -m state --state NEW -m tcp --dport "$ADMIN_PORT" -j ACCEPT
  else
    iptables -I INPUT 1 -p tcp -m state --state NEW -m tcp --dport "$ADMIN_PORT" -j ACCEPT
  fi
fi
netfilter-persistent save

log "unattended upgrades"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

log "done"
echo "Now open TCP ${ADMIN_PORT} in the Oracle security list, then test from your laptop:"
echo "  ssh -p ${ADMIN_PORT} ${ADMIN_USER}@<public-ip>"
echo "Keep this session open until that works."
