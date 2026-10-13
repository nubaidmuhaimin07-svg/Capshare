#!/usr/bin/env bash
# Run every automated check. Safe: each test uses its own temporary database, storage
# directory and sample files - your saved CapShare data (~/.capshare) is never touched.
set -euo pipefail
cd "$(dirname "$0")"
PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python
exec "$PY" -m unittest discover -s tests -v
