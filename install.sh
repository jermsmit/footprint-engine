#!/usr/bin/env bash
#
# Bare-metal installer for Footprint Engine on Ubuntu Server.
# Installs system + Python dependencies, sets up a venv, and optionally
# registers a systemd service so it starts on boot.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="python3"
VENV_DIR="${APP_DIR}/.venv"
SERVICE_NAME="footprint-engine"
APP_PORT="${APP_PORT:-8000}"

echo "==> Footprint Engine bare-metal installer"
echo "    App directory: ${APP_DIR}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "==> Installing missing dependency: $1"
    sudo apt-get update -y
    sudo apt-get install -y "$2"
  fi
}

echo "==> Checking system packages"
require_cmd python3 python3
require_cmd pip3 python3-pip
require_cmd curl curl

if ! python3 -m venv --help >/dev/null 2>&1; then
  sudo apt-get install -y python3-venv
fi

echo "==> Creating virtual environment at ${VENV_DIR}"
"${PYTHON_BIN}" -m venv "${VENV_DIR}"

echo "==> Installing Python dependencies"
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt"

mkdir -p "${APP_DIR}/backend/data"

if [ ! -f "${APP_DIR}/backend/data/wmn-data.json" ]; then
  echo "==> Fetching username site list (WhatsMyName dataset)"
  curl -sL -o "${APP_DIR}/backend/data/wmn-data.json" \
    https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json
fi

if [ ! -f "${APP_DIR}/.env" ] && [ -f "${APP_DIR}/.env.example" ]; then
  cp "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi

echo ""
echo "==> Install complete."
echo ""
read -rp "Register a systemd service so this runs on boot? [y/N] " REGISTER_SVC
if [[ "${REGISTER_SVC}" =~ ^[Yy]$ ]]; then
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  RUN_USER="$(whoami)"
  echo "==> Writing ${SERVICE_FILE}"
  sudo tee "${SERVICE_FILE}" >/dev/null <<EOF
[Unit]
Description=Footprint Engine OSINT lookup tool
After=network.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=-${APP_DIR}/.env
Environment=APP_PORT=${APP_PORT}
ExecStart=${VENV_DIR}/bin/uvicorn backend.main:app --host 0.0.0.0 --port ${APP_PORT}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable "${SERVICE_NAME}"
  sudo systemctl restart "${SERVICE_NAME}"
  echo "==> Service '${SERVICE_NAME}' started. Check status with:"
  echo "    sudo systemctl status ${SERVICE_NAME}"
else
  echo "==> To run it manually:"
  echo "    source ${VENV_DIR}/bin/activate"
  echo "    uvicorn backend.main:app --host 0.0.0.0 --port ${APP_PORT}"
fi

echo ""
echo "==> Once running, open: http://<this-host-ip>:${APP_PORT}"
