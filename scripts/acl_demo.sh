#!/usr/bin/env bash
# Real POSIX ACL demonstration (see scripts/acl_demo.py).
#
# sudo is used for exactly two things, both explained here:
#   1. `sudo useradd ...`  create two throw-away *system* users (no home, no login shell)
#                          so we can act "as" a second and third Linux user.
#   2. `sudo -u <user> ...` run `cat`/`sh -c "echo >>"` as those users to show what the
#                          KERNEL allows or denies. Nothing else runs as root.
# On exit the script deletes only the users it created itself (`sudo userdel`).
set -euo pipefail
cd "$(dirname "$0")/.."

ALICE=capshare_alice
BOB=capshare_bob
CREATED=()

cleanup() {
  for u in "${CREATED[@]:-}"; do
    [ -n "$u" ] && sudo userdel "$u" 2>/dev/null && echo "removed temporary user $u"
  done
}
trap cleanup EXIT

if ! command -v setfacl >/dev/null; then
  echo "setfacl not found. Install it first:  sudo apt install acl" >&2
  exit 2
fi

echo "Asking for your sudo password once (needed to create/delete two temporary users)..."
sudo -v

for u in "$ALICE" "$BOB"; do
  if id "$u" >/dev/null 2>&1; then
    echo "using existing Linux user $u"
  else
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
    CREATED+=("$u")
    echo "created temporary Linux user $u"
  fi
done

# Use the project's virtualenv when present.
PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python
"$PY" scripts/acl_demo.py --alice "$ALICE" --bob "$BOB"
