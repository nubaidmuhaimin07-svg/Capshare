#!/usr/bin/env bash
# Launch CapShare.
#   ./run.sh                          desktop app + sharing service (the SENDER computer)
#   ./run.sh --client http://IP:8765  desktop app only, connected to another computer
#   ./run.sh serve                    sharing service only, no window (headless VM)
#   ./run.sh lab                      run the five challenge scenarios in the terminal
#   ./run.sh accounts | passwd USER | reset --yes | seed
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "No .venv found. Run ./setup_ubuntu.sh first." >&2
  exit 1
fi
# shellcheck disable=SC1091
source .venv/bin/activate

case "${1:-}" in
  gui|serve|seed|accounts|passwd|reset|lab) exec python -m capshare "$@" ;;
  *)                                        exec python -m capshare gui "$@" ;;
esac
