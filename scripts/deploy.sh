#!/usr/bin/env bash
# Install or update LogKompass on the server. Idempotent, safe to re-run.
#
# Usage, from the repository root on the server:
#   sudo bash scripts/deploy.sh
set -euo pipefail

APP_DIR=/opt/logkompass
DATA_DIR=/var/lib/logkompass
ETC_DIR=/etc/logkompass
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf "\n==> %s\n" "$*"; }

log "service user"
id -u logkompass >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin logkompass
# journald access without root:
usermod -aG systemd-journal logkompass

log "directories"
install -d -o logkompass -g logkompass -m 750 "$APP_DIR" "$DATA_DIR"
install -d -m 755 "$ETC_DIR"

log "code"
rsync -a --delete --exclude ".git" --exclude ".venv" --exclude "__pycache__" "$SRC_DIR/" "$APP_DIR/"
chown -R logkompass:logkompass "$APP_DIR"

log "virtualenv"
if [ ! -x "$APP_DIR/.venv/bin/python" ]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet "$APP_DIR"
chown -R logkompass:logkompass "$APP_DIR/.venv"

log "config"
if [ ! -f "$ETC_DIR/config.toml" ]; then
  cp "$APP_DIR/config.example.toml" "$ETC_DIR/config.toml"
  echo "edit $ETC_DIR/config.toml before the next timer run"
fi
if [ ! -f "$ETC_DIR/env" ]; then
  cat > "$ETC_DIR/env" <<EOF
# secrets live here, never in config.toml
LOGKOMPASS_TG_TOKEN=
LOGKOMPASS_TG_CHAT=
OPENROUTER_API_KEY=
EOF
fi
chmod 600 "$ETC_DIR/env"
chown root:logkompass "$ETC_DIR/env"
chmod 640 "$ETC_DIR/env"

log "systemd units"
install -m 644 "$APP_DIR/systemd/"logkompass-*.service "$APP_DIR/systemd/"logkompass-*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now logkompass-collect.timer
systemctl enable --now logkompass-digest.timer

log "probe"
sudo -u logkompass "$APP_DIR/.venv/bin/logkompass" --config "$ETC_DIR/config.toml" probe --skip-model || true

log "done"
echo "watch the first run:  journalctl -u logkompass-collect.service -f"
