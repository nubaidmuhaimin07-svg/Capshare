#!/usr/bin/env bash
# CapShare - one-time setup for Ubuntu 22.04 / 24.04 (desktop or VM).
#
# Every `sudo` command in this script is listed and explained below, and the script asks
# before running each one. Nothing here changes your system outside of: installing
# distribution packages, and (optionally) adding ONE firewall rule for your Wi-Fi subnet.
#
#   sudo apt update
#       Refresh the package index so apt knows the current package versions.
#   sudo apt install -y python3 python3-venv python3-pip acl <qt libraries>
#       python3*  : the interpreter + venv so pip packages stay inside ./.venv
#       acl       : provides the `setfacl` and `getfacl` commands (POSIX ACLs)
#       lib*      : shared libraries Qt (PySide6) needs to open a desktop window on Ubuntu
#   sudo ufw allow from <your Wi-Fi subnet> to any port 8765 proto tcp     (optional)
#       Opens the sharing port ONLY to your own local subnet, not to the whole internet.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${CAPSHARE_PORT:-8765}"

ask() { read -r -p "$1 [y/N] " reply; [[ "$reply" =~ ^[Yy]$ ]]; }

echo "== CapShare setup =="

PACKAGES="python3 python3-venv python3-pip acl libegl1 libgl1 libxkbcommon-x11-0 libxcb-cursor0 \
libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 libxcb-xinerama0 libxcb-image0 libxcb-render-util0 \
libxcb-xkb1 libdbus-1-3 libfontconfig1"

echo
echo "Step 1/4: system packages (needs sudo)"
echo "  sudo apt update && sudo apt install -y $PACKAGES"
if ask "Run it now?"; then
  sudo apt update
  # shellcheck disable=SC2086
  sudo apt install -y $PACKAGES
else
  echo "Skipped. If setfacl is missing, ACL integration will report 'disabled'."
fi

echo
echo "Step 2/4: Python virtual environment (no sudo)"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo
echo "Step 3/4: demo accounts (no sudo)"
python -m capshare seed

echo
echo "Step 4/4: firewall (optional, needs sudo)"
if command -v ufw >/dev/null; then
  CIDR=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -n1 || true)
  if [ -n "${CIDR:-}" ]; then
    SUBNET=$(python - "$CIDR" <<'PY'
import ipaddress, sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)
    echo "  Detected Wi-Fi/LAN subnet: $SUBNET"
    echo "  sudo ufw allow from $SUBNET to any port $PORT proto tcp"
    if ask "Add this rule (only if ufw is enabled and you want other devices to connect)?"; then
      sudo ufw allow from "$SUBNET" to any port "$PORT" proto tcp
    fi
  else
    echo "  No network address found - connect to Wi-Fi first, then re-run this script."
  fi
else
  echo "  ufw not installed: no firewall rule needed."
fi

echo
echo "Setup finished. Start CapShare with:   ./run.sh"
echo "Run the automated checks with:         ./run_checks.sh"
