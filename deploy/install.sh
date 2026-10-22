#!/usr/bin/env bash
# AI-UBA - Linux (systemd) quraşdırıcısı. Təkrar işlədilə bilər (yeniləmə üçün də).
#   sudo ./deploy/install.sh
set -euo pipefail

APP_DIR=/opt/aiuba
ENV_DIR=/etc/aiuba
SERVICE_USER=aiuba
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Bu skript root icazəsi tələb edir: sudo $0" >&2
  exit 1
fi
command -v python3 >/dev/null || { echo "python3 tapılmadı" >&2; exit 1; }
python3 -c 'import venv, ensurepip' 2>/dev/null || {
  echo "python3-venv paketi yoxdur (Debian/Ubuntu: apt install python3-venv)" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd tapılmadı" >&2; exit 1; }

echo "[1/6] Servis istifadəçisi"
id -u "$SERVICE_USER" >/dev/null 2>&1 || \
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"

echo "[2/6] Kodun $APP_DIR qovluğuna kopyalanması"
mkdir -p "$APP_DIR" "$ENV_DIR"
tar -C "$SRC_DIR" \
    --exclude=./venv --exclude=./.git --exclude=./data --exclude=./logs \
    --exclude='__pycache__' --exclude='*.pyc' --exclude=./.env \
    -cf - . | tar -C "$APP_DIR" -xf -
mkdir -p "$APP_DIR/data" "$APP_DIR/logs"

echo "[3/6] Python virtual environment və asılılıqlar"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo "[4/6] İcazələr (kod root-a məxsus/oxunandır, yalnız data və logs yazıla bilir)"
chown -R root:root "$APP_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/data" "$APP_DIR/logs"

echo "[5/6] Konfiqurasiya faylı"
if [[ ! -f "$ENV_DIR/aiuba.env" ]]; then
  install -m 600 -o root -g root "$APP_DIR/deploy/aiuba.env.example" "$ENV_DIR/aiuba.env"
  NEW_ENV=1
else
  NEW_ENV=0
fi

echo "[6/6] systemd unit"
install -m 644 "$APP_DIR/deploy/aiuba.service" /etc/systemd/system/aiuba.service
systemctl daemon-reload
systemctl enable aiuba >/dev/null

if [[ $NEW_ENV -eq 1 ]]; then
  cat <<MSG

Quraşdırma tamamlandı. Servis HƏLƏ BAŞLADILMAYIB.
  1) Parolları təyin edin:   sudo nano $ENV_DIR/aiuba.env
  2) Başladın:                sudo systemctl start aiuba
  3) Yoxlayın:                sudo systemctl status aiuba ; journalctl -u aiuba -f
MSG
else
  systemctl restart aiuba
  echo "Yeniləndi və yenidən başladıldı: systemctl status aiuba"
fi
