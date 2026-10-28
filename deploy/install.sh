#!/usr/bin/env bash
# AI-UBA - Linux (systemd) installer. Can be run multiple times (for updates as well).
#   sudo ./deploy/install.sh
set -euo pipefail

APP_DIR=/opt/uba
ENV_DIR=/etc/uba
SERVICE_USER=uba
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "This script requires root privileges: sudo $0" >&2
  exit 1
fi
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }
python3 -c 'import venv, ensurepip' 2>/dev/null || {
  echo "python3-venv package not found (Debian/Ubuntu: apt install python3-venv)" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd not found" >&2; exit 1; }

echo "[1/6] Service user"
id -u "$SERVICE_USER" >/dev/null 2>&1 || \
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"

echo "[2/6] Copying code to $APP_DIR"
mkdir -p "$APP_DIR" "$ENV_DIR"
tar -C "$SRC_DIR" \
    --exclude=./venv --exclude=./.git --exclude=./data --exclude=./logs \
    --exclude='__pycache__' --exclude='*.pyc' --exclude=./.env \
    -cf - . | tar -C "$APP_DIR" -xf -
mkdir -p "$APP_DIR/data" "$APP_DIR/logs"

echo "[3/6] Python virtual environment and dependencies"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo "[4/6] Permissions (code owned by root, only data and logs can be written)"
chown -R root:root "$APP_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/data" "$APP_DIR/logs"

echo "[5/6] Configuration file"
if [[ ! -f "$ENV_DIR/uba.env" ]]; then
  install -m 600 -o root -g root "$APP_DIR/deploy/uba.env.example" "$ENV_DIR/uba.env"
  NEW_ENV=1
else
  NEW_ENV=0
fi

echo "[6/6] systemd unit"
install -m 644 "$APP_DIR/deploy/uba.service" /etc/systemd/system/uba.service
systemctl daemon-reload
systemctl enable uba >/dev/null

if [[ $NEW_ENV -eq 1 ]]; then
  cat <<MSG

Installation completed. Service NOT started yet.
  1) Set passwords:   sudo nano $ENV_DIR/uba.env
  2) Start service:                sudo systemctl start uba
  3) Check status:                sudo systemctl status uba ; journalctl -u uba -f
MSG
else
  systemctl restart uba
  echo "Installation completed and service restarted: systemctl status uba"
fi
