"""Linux POSIX ACL integration (setfacl / getfacl).

OS concept -> code
------------------
* "Discretionary access control list on an inode" -> PosixAclBackend.set_entry/remove_entry
  run `setfacl -m u:<user>:r-- <file>` / `setfacl -x u:<user> <file>`.
* "Directory search (x) permission"               -> AclManager._ensure_traversal gives the
  mapped user `--x` on the storage directory (and on parent directories we own) so the
  kernel lets them *reach* the file. Without `x` on every directory in the path, the file
  ACL alone would be useless.
* "Never remove access another path still supports" -> AclManager.apply_file receives the
  DESIRED permissions per Linux user (already computed over ALL independent grant paths by
  the engine) and only adds/removes the difference.

Backends
--------
PosixAclBackend  real commands (Linux only, needs the `acl` package)
FakeAclBackend   in-memory, records every operation; used by the Challenge Lab and tests
NullAclBackend   "ACL integration is off"; changes nothing and says so
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .db import utc_now
from .errors import AclError

LINUX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_ENTRY_RE = re.compile(r"^user:([^:\s]+):([rwx-]{3})(?:\s+#effective:([rwx-]{3}))?\s*$")


def perms_string(actions: set[str] | frozenset[str]) -> str:
    """{'READ'} -> 'r--', {'READ','WRITE'} -> 'rw-'. (CapShare never grants execute.)"""
    return ("r" if "READ" in actions else "-") + ("w" if "WRITE" in actions else "-") + "-"


def valid_linux_user(name: str) -> bool:
    return bool(LINUX_USER_RE.match(name or ""))


# =====================================================================================
# Backends
# =====================================================================================
class NullAclBackend:
    name = "disabled"
    real = False

    def available(self) -> bool:
        return False

    def detail(self) -> str:
        return "Linux ACL integration is switched off (CAPSHARE_ACL=off or setfacl not found)."

    def set_entry(self, path, linux_user, perms): ...
    def remove_entry(self, path, linux_user): ...
    def read_entry(self, path, linux_user): return None
    def getfacl_text(self, path): return "(ACL integration disabled)"
    def user_exists(self, linux_user): return False


class PosixAclBackend:
    name = "posix-acl"
    real = True

    def __init__(self, timeout_s: float = 10.0):
        self.timeout_s = timeout_s

    def available(self) -> bool:
        return bool(shutil.which("setfacl") and shutil.which("getfacl"))

    def detail(self) -> str:
        return "setfacl/getfacl found" if self.available() else \
            "setfacl/getfacl not found - install with: sudo apt install acl"

    def _run(self, argv: list[str]) -> str:
        # argv list + no shell: user names / paths can never be interpreted as shell syntax.
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout_s)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AclError(f"could not run {argv[0]}: {type(exc).__name__}") from exc
        if proc.returncode != 0:
            raise AclError(f"{argv[0]} failed: {proc.stderr.strip()[:200] or 'unknown error'}")
        return proc.stdout

    def set_entry(self, path: Path, linux_user: str, perms: str) -> None:
        if not valid_linux_user(linux_user):
            raise AclError("invalid Linux user name")
        self._run(["setfacl", "-m", f"u:{linux_user}:{perms}", "--", str(path)])

    def remove_entry(self, path: Path, linux_user: str) -> None:
        if not valid_linux_user(linux_user):
            raise AclError("invalid Linux user name")
        self._run(["setfacl", "-x", f"u:{linux_user}", "--", str(path)])

    def getfacl_text(self, path: Path) -> str:
        return self._run(["getfacl", "--absolute-names", "--", str(path)])

    def read_entry(self, path: Path, linux_user: str) -> str | None:
        """Return the *effective* permissions the kernel will apply (mask included)."""
        for line in self.getfacl_text(path).splitlines():
            match = _ENTRY_RE.match(line.strip())
            if match and match.group(1) == linux_user:
                return match.group(3) or match.group(2)
        return None

    def user_exists(self, linux_user: str) -> bool:
        try:
            import pwd                      # Linux/Unix only
            entry = pwd.getpwnam(linux_user)
            return entry.pw_uid != 0        # never map an app account to root
        except (ImportError, KeyError):
            return False


class FakeAclBackend:
    """Pretends to be a filesystem ACL. Records every call so tests/Lab can show them."""
    name = "simulated"
    real = False

    def __init__(self):
        self.entries: dict[tuple[str, str], str] = {}
        self.log: list[str] = []
        self.fail_on_user: set[str] = set()      # tests: make setfacl "fail" for these users
        self.known_users: set[str] | None = None  # None -> any valid name exists

    def available(self) -> bool:
        return True

    def detail(self) -> str:
        return "simulated ACLs (no real operating-system permission is changed)"

    def set_entry(self, path, linux_user, perms):
        if linux_user in self.fail_on_user:
            raise AclError(f"simulated setfacl failure for {linux_user}")
        self.entries[(str(path), linux_user)] = perms
        self.log.append(f"setfacl -m u:{linux_user}:{perms} {Path(str(path)).name}")

    def remove_entry(self, path, linux_user):
        if linux_user in self.fail_on_user:
            raise AclError(f"simulated setfacl failure for {linux_user}")
        self.entries.pop((str(path), linux_user), None)
        self.log.append(f"setfacl -x u:{linux_user} {Path(str(path)).name}")

    def read_entry(self, path, linux_user):
        return self.entries.get((str(path), linux_user))

    def getfacl_text(self, path):
        lines = [f"# file: {path}", "user::rw-", "group::---", "other::---"]
        for (p, user), perms in sorted(self.entries.items()):
            if p == str(path):
                lines.insert(1, f"user:{user}:{perms}")
        return "\n".join(lines) + "\n"

    def user_exists(self, linux_user):
        return self.known_users is None or linux_user in self.known_users


# =====================================================================================
# Manager: keeps the filesystem and the acl_entries bookkeeping table in step
# =====================================================================================
class AclManager:
    def __init__(self, backend, storage_dir: Path, home: Path):
        self.backend = backend
        self.storage_dir = Path(storage_dir)
        self.home = Path(home)

    @property
    def enabled(self) -> bool:
        return bool(self.backend.available())

    def status(self) -> dict:
        return {"backend": self.backend.name, "enabled": self.enabled,
                "real_os_acl": bool(self.backend.real and self.enabled),
                "detail": self.backend.detail()}

    # ---------------------------------------------------------------- per file
    def apply_file(self, conn, file_id: int, path: Path, desired: dict[str, str],
                   force: bool = False, probe: bool = False,
                   known_users: list[str] | None = None) -> list[str]:
        """Make the file's ACL entries equal `desired` ({linux_user: 'r--'|'rw-'}).

        Returns a list of human readable operations that REALLY happened.
        Raises AclError at the first failing command; entries already applied stay
        recorded in `acl_entries`, so the caller can report the exact inconsistency.

        probe=True  ignore our bookkeeping and READ the real ACL back for every mapped
                    user. Used to repair the filesystem after a failure/rollback.
        """
        if not self.enabled:
            return []
        ops: list[str] = []
        rows = conn.execute(
            "SELECT linux_user, perms FROM acl_entries WHERE kind='file' AND file_id=?",
            (file_id,)).fetchall()
        current = {r["linux_user"]: r["perms"] for r in rows}
        if probe:
            for linux_user in sorted(set(current) | set(desired) | set(known_users or ())):
                actual = self.backend.read_entry(path, linux_user)
                if actual is None:
                    current.pop(linux_user, None)
                    conn.execute("DELETE FROM acl_entries WHERE path=? AND linux_user=?",
                                 (str(path), linux_user))
                else:
                    current[linux_user] = actual
                    conn.execute(
                        "INSERT OR REPLACE INTO acl_entries(path, linux_user, perms, kind, file_id, applied_at) "
                        "VALUES (?,?,?,?,?,?)", (str(path), linux_user, actual, "file", file_id, utc_now()))

        for linux_user, want in sorted(desired.items()):
            if current.get(linux_user) == want and not force:
                continue
            self._ensure_traversal(conn, linux_user, ops)       # reach the file first
            self.backend.set_entry(path, linux_user, want)
            self._verify(path, linux_user, want)
            conn.execute(
                "INSERT OR REPLACE INTO acl_entries(path, linux_user, perms, kind, file_id, applied_at) "
                "VALUES (?,?,?,?,?,?)", (str(path), linux_user, want, "file", file_id, utc_now()))
            ops.append(f"setfacl -m u:{linux_user}:{want} {path.name}")

        for linux_user in sorted(set(current) - set(desired)):
            self.backend.remove_entry(path, linux_user)
            self._verify(path, linux_user, None)
            conn.execute("DELETE FROM acl_entries WHERE path=? AND linux_user=?",
                         (str(path), linux_user))
            ops.append(f"setfacl -x u:{linux_user} {path.name}")
            self._release_traversal_if_unused(conn, linux_user, ops)
        return ops

    def _verify(self, path: Path, linux_user: str, want: str | None) -> None:
        """Read the ACL back: never claim a change the kernel did not make."""
        got = self.backend.read_entry(path, linux_user)
        if got != want:
            raise AclError(
                f"ACL verification failed for {linux_user}: expected {want or 'no entry'}, "
                f"kernel reports {got or 'no entry'}")

    # ---------------------------------------------------------------- directories
    def traversal_dirs(self) -> list[Path]:
        """Directories a mapped user must be able to search (x) to reach the storage dir.

        We walk upward from the storage directory while we OWN the directory (we may only
        change ACLs on our own inodes). On a normal Ubuntu home this is
        ~/.capshare/storage, ~/.capshare and ~ itself.
        """
        dirs = [self.storage_dir]
        if not hasattr(os, "getuid"):        # non-POSIX (development on Windows)
            return dirs + ([self.home] if self.home != self.storage_dir else [])
        me = os.getuid()
        for parent in self.storage_dir.parents:
            try:
                if parent.stat().st_uid != me:
                    break
            except OSError:
                break
            dirs.append(parent)
        return dirs

    def _ensure_traversal(self, conn, linux_user: str, ops: list[str]) -> None:
        for directory in self.traversal_dirs():
            key = str(directory)
            if conn.execute("SELECT 1 FROM acl_entries WHERE path=? AND linux_user=?",
                            (key, linux_user)).fetchone():
                continue
            prior = self.backend.read_entry(directory, linux_user)
            if prior and prior[2] == "x":
                continue                      # already searchable; not ours to touch/remove
            new_perms = "--x" if not prior else prior[0] + prior[1] + "x"
            self.backend.set_entry(directory, linux_user, new_perms)
            self._verify(directory, linux_user, new_perms)
            conn.execute(
                "INSERT INTO acl_entries(path, linux_user, perms, kind, file_id, prior, applied_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (key, linux_user, new_perms, "dir", None, prior, utc_now()))
            ops.append(f"setfacl -m u:{linux_user}:{new_perms} {directory}")

    def _release_traversal_if_unused(self, conn, linux_user: str, ops: list[str]) -> None:
        still_used = conn.execute(
            "SELECT 1 FROM acl_entries WHERE kind='file' AND linux_user=?", (linux_user,)).fetchone()
        if still_used:
            return                            # another file still needs the directory path
        for row in conn.execute(
                "SELECT path, prior FROM acl_entries WHERE kind='dir' AND linux_user=?",
                (linux_user,)).fetchall():
            directory = Path(row["path"])
            if row["prior"]:
                self.backend.set_entry(directory, linux_user, row["prior"])
                ops.append(f"setfacl -m u:{linux_user}:{row['prior']} {directory}")
            else:
                self.backend.remove_entry(directory, linux_user)
                ops.append(f"setfacl -x u:{linux_user} {directory}")
            conn.execute("DELETE FROM acl_entries WHERE path=? AND linux_user=?",
                         (row["path"], linux_user))

    # ---------------------------------------------------------------- display
    def describe(self, path: Path) -> str:
        if not self.enabled:
            return self.backend.detail()
        try:
            return self.backend.getfacl_text(path)
        except AclError as exc:
            return f"(getfacl failed: {exc.message})"
