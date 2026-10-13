"""CapShare app accounts, passwords and login sessions.

IMPORTANT: a CapShare account is NOT a Linux user. A remote device logs in with a
CapShare username/password and is judged by the capability engine. Only an account that
the admin explicitly *maps* to a local Linux user (users.linux_user) also receives
POSIX ACL entries on the file system.

OS concept -> code
------------------
* "Credential storage"      -> PBKDF2-HMAC-SHA256 with a random salt (never plain text).
* "Session / process token" -> random 256-bit token in an HttpOnly cookie; only its
                               SHA-256 hash is stored, so a stolen database cannot be
                               replayed as sessions.
* "Anti-CSRF"               -> each session has a second random token that must be sent
                               in the X-CSRF-Token header for every state-changing call.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time

from .config import Config
from .db import Database, utc_now
from .errors import AuthRequired, BadRequest

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,31}$")
_DUMMY_HASH = None


def hash_password(password: str, iterations: int) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("not-a-real-password", 1_000)
    candidate = stored or _DUMMY_HASH        # unknown user: still do the work (timing)
    try:
        _, iterations, salt_hex, digest_hex = candidate.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        ok = hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False
    return ok and stored is not None


class LoginThrottle:
    """Tiny in-memory brake: 6 failures per username per 60 s -> temporary refusal."""

    def __init__(self, limit: int = 6, window_s: int = 60):
        self.limit, self.window_s = limit, window_s
        self._failures: dict[str, list[float]] = {}

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        recent = [t for t in self._failures.get(key, []) if now - t < self.window_s]
        self._failures[key] = recent
        return len(recent) >= self.limit

    def fail(self, key: str) -> None:
        self._failures.setdefault(key, []).append(time.monotonic())

    def clear(self, key: str) -> None:
        self._failures.pop(key, None)


class Accounts:
    def __init__(self, db: Database, config: Config):
        self.db = db
        self.config = config
        self.throttle = LoginThrottle()

    # ------------------------------------------------------------------ users
    def create_user(self, username: str, display_name: str, password: str | None,
                    is_admin: bool = False, linux_user: str | None = None) -> dict:
        username = (username or "").strip().lower()
        if not USERNAME_RE.match(username):
            raise BadRequest("username must be 2-32 chars: a-z, 0-9, _ . -  (starting with a letter)",
                             code="BAD_USERNAME")
        if password is not None and len(password) < 8:
            raise BadRequest("password must be at least 8 characters", code="WEAK_PASSWORD")
        display = (display_name or username).strip()[:60] or username
        pw_hash = hash_password(password, self.config.pbkdf2_iterations) if password else None
        with self.db.write() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise BadRequest("that username already exists", code="USER_EXISTS")
            cur = conn.execute(
                "INSERT INTO users(username, display_name, password_hash, is_admin, created_at, linux_user) "
                "VALUES (?,?,?,?,?,?)",
                (username, display, pw_hash, int(is_admin), utc_now(), linux_user))
            return {"id": cur.lastrowid, "username": username, "display_name": display}

    def get_user(self, user_id: int) -> dict | None:
        with self.db.read() as conn:
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            return dict(row) if row else None

    def by_username(self, username: str) -> dict | None:
        with self.db.read() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?",
                               ((username or "").strip().lower(),)).fetchone()
            return dict(row) if row else None

    def set_password(self, user_id: int, password: str) -> None:
        if len(password) < 8:
            raise BadRequest("password must be at least 8 characters", code="WEAK_PASSWORD")
        with self.db.write() as conn:
            conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                         (hash_password(password, self.config.pbkdf2_iterations), user_id))
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

    def set_linux_user(self, user_id: int, linux_user: str | None) -> None:
        with self.db.write() as conn:
            conn.execute("UPDATE users SET linux_user=? WHERE id=?", (linux_user, user_id))

    # ------------------------------------------------------------------ sessions
    def login(self, username: str, password: str) -> tuple[dict, str, str]:
        """Return (user, session_token, csrf_token) or raise AuthRequired."""
        key = (username or "").strip().lower()
        if self.throttle.blocked(key):
            raise AuthRequired("too many failed logins; wait a minute and try again",
                               code="LOGIN_THROTTLED")
        user = self.by_username(key)
        ok = verify_password(password or "", user["password_hash"] if user else None)
        if not (user and ok):
            self.throttle.fail(key)
            raise AuthRequired("wrong username or password", code="BAD_LOGIN")
        self.throttle.clear(key)
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        expires = time.time() + self.config.session_hours * 3600
        with self.db.write() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            conn.execute("INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at) "
                         "VALUES (?,?,?,?,?)",
                         (self._h(token), user["id"], csrf, utc_now(), expires))
        return user, token, csrf

    def session(self, token: str | None) -> dict | None:
        """Return {'user': row, 'csrf': str} for a valid token, else None."""
        if not token:
            return None
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT s.csrf_token, s.expires_at, u.* FROM sessions s JOIN users u ON u.id=s.user_id "
                "WHERE s.token_hash=?", (self._h(token),)).fetchone()
        if not row or row["expires_at"] < time.time():
            return None
        user = dict(row)
        csrf = user.pop("csrf_token")
        user.pop("expires_at", None)
        return {"user": user, "csrf": csrf}

    def logout(self, token: str | None) -> None:
        if token:
            with self.db.write() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (self._h(token),))

    @staticmethod
    def _h(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
