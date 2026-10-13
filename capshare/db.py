"""SQLite access: connections, serialized write transactions, safe migrations.

OS concept -> code
------------------
* "Critical section / mutual exclusion"  -> Database.write(): `BEGIN IMMEDIATE` takes
  SQLite's database write lock *before* any validation is done. Two writers can
  never interleave "check the parent grant" with "insert the child grant".
* "Never trust the caller's strings"     -> every statement uses `?` placeholders
  (prepared/parameterised statements). Values are never pasted into SQL text.
"""
from __future__ import annotations

import shutil
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

SCHEMA_VERSION = 3


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Database:
    def __init__(self, path: Path, busy_timeout_s: float = 30.0):
        self.path = Path(path)
        self.busy_timeout_s = busy_timeout_s

    # ------------------------------------------------------------------ connections
    def connect(self) -> sqlite3.Connection:
        # isolation_level=None -> we control BEGIN/COMMIT ourselves (no hidden transactions).
        conn = sqlite3.connect(str(self.path), timeout=self.busy_timeout_s,
                               isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """A serialized write transaction.

        BEGIN IMMEDIATE blocks until no other writer is active, then holds the write
        lock until COMMIT/ROLLBACK. Everything inside the `with` is atomic.
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    # ------------------------------------------------------------------ migrations
    def migrate(self, backup: bool = True) -> list[str]:
        """Bring the database up to SCHEMA_VERSION without discarding data.

        * Fresh file                      -> run all migrations.
        * Old CapShare file (tables exist, user_version = 0) -> treated as version 1.
        * Older version                   -> backed up first, then upgraded step by step.
        * Newer than this program         -> refuse (never downgrade or guess).
        Each step runs in its own transaction, so a crash leaves a consistent version.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        log: list[str] = []
        conn = self.connect()
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            has_tables = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='grants'").fetchone()
            if version == 0 and has_tables:
                version = 1
                log.append("legacy database without version marker: treating as v1")
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema v{version} is newer than this CapShare (v{SCHEMA_VERSION})")
            if version == SCHEMA_VERSION:
                return log
            if backup and version >= 1:
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                dest = self.path.with_name(f"{self.path.name}.bak-v{version}-{stamp}")
                bconn = sqlite3.connect(str(dest))
                try:
                    conn.backup(bconn)          # consistent copy even in WAL mode
                finally:
                    bconn.close()
                log.append(f"backup written: {dest.name}")
            if version == 0:
                conn.execute("PRAGMA journal_mode = WAL")   # persistent; readers never block writers
            for target in range(version + 1, SCHEMA_VERSION + 1):
                conn.execute("BEGIN IMMEDIATE")
                try:
                    MIGRATIONS[target](conn)
                    conn.execute(f"PRAGMA user_version = {int(target)}")
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                log.append(f"migrated to v{target}")
            return log
        finally:
            conn.close()


# ---------------------------------------------------------------------------------
# Migrations. NEVER edit an old one after release; add a new function instead.
# ---------------------------------------------------------------------------------

def _m1_base(conn: sqlite3.Connection) -> None:
    """v1: the original CapShare tables (no depth column, no parent index)."""
    _run_script(conn, """
    CREATE TABLE IF NOT EXISTS users(
        id            INTEGER PRIMARY KEY,
        username      TEXT NOT NULL UNIQUE,
        display_name  TEXT NOT NULL,
        password_hash TEXT,
        is_admin      INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files(
        id          INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        stored_name TEXT NOT NULL UNIQUE,
        owner_id    INTEGER NOT NULL REFERENCES users(id),
        size        INTEGER NOT NULL DEFAULT 0,
        sha256      TEXT,
        created_at  TEXT NOT NULL,
        updated_at  TEXT
    );
    CREATE TABLE IF NOT EXISTS grants(
        id           INTEGER PRIMARY KEY,
        file_id      INTEGER NOT NULL REFERENCES files(id),
        recipient_id INTEGER NOT NULL REFERENCES users(id),
        grantor_id   INTEGER NOT NULL REFERENCES users(id),
        actions      TEXT NOT NULL CHECK(actions IN ('READ','WRITE','READ,WRITE')),
        can_delegate INTEGER NOT NULL DEFAULT 0,
        parent_id    INTEGER REFERENCES grants(id),
        state        TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','revoked')),
        created_at   TEXT NOT NULL,
        revoked_at   TEXT,
        expires_at   INTEGER
    );
    CREATE TABLE IF NOT EXISTS audit(
        id       INTEGER PRIMARY KEY,
        ts       TEXT NOT NULL,
        actor_id INTEGER,
        action   TEXT NOT NULL,
        file_id  INTEGER,
        grant_id INTEGER,
        outcome  TEXT NOT NULL,
        detail   TEXT
    );
    """)


def _run_script(conn: sqlite3.Connection, script: str) -> None:
    """Run several statements INSIDE the current transaction.
    (sqlite3's executescript() would silently COMMIT first, breaking atomic migrations.)"""
    for statement in script.split(";"):
        if statement.strip():
            conn.execute(statement)


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _m2_depth_and_indexes(conn: sqlite3.Connection) -> None:
    """v2: lineage depth, revoke bookkeeping and the indexes the cascade relies on."""
    cols = _column_names(conn, "grants")
    if "depth" not in cols:
        conn.execute("ALTER TABLE grants ADD COLUMN depth INTEGER NOT NULL DEFAULT 0")
    if "revoked_by" not in cols:
        conn.execute("ALTER TABLE grants ADD COLUMN revoked_by INTEGER REFERENCES users(id)")
    if "revoke_reason" not in cols:
        conn.execute("ALTER TABLE grants ADD COLUMN revoke_reason TEXT")
    # Back-fill depth for rows that existed before this migration: roots are depth 1,
    # then repeatedly fill in the children of rows whose depth is known.
    conn.execute("UPDATE grants SET depth = 1 WHERE parent_id IS NULL AND depth = 0")
    for _ in range(1000):
        cur = conn.execute("""
            UPDATE grants
               SET depth = (SELECT p.depth + 1 FROM grants p WHERE p.id = grants.parent_id)
             WHERE depth = 0
               AND parent_id IN (SELECT id FROM grants WHERE depth > 0)""")
        if cur.rowcount == 0:
            break
    # KO-13 C3: the indexed parent link used by every lineage traversal.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_grants_parent_id ON grants(parent_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_grants_file_recipient ON grants(file_id, recipient_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(id DESC)")


def _m3_runtime_tables(conn: sqlite3.Connection) -> None:
    """v3: sessions, logical clocks, transfers, ACL bookkeeping, Linux user mapping."""
    if "linux_user" not in _column_names(conn, "users"):
        conn.execute("ALTER TABLE users ADD COLUMN linux_user TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_linux_user "
                 "ON users(linux_user) WHERE linux_user IS NOT NULL")
    _run_script(conn, """
    CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        csrf_token TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS logical_clocks(
        owner_id INTEGER PRIMARY KEY REFERENCES users(id),
        now      INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS transfers(
        id          INTEGER PRIMARY KEY,
        file_id     INTEGER NOT NULL REFERENCES files(id),
        user_id     INTEGER NOT NULL REFERENCES users(id),
        direction   TEXT NOT NULL CHECK(direction IN ('download','upload')),
        state       TEXT NOT NULL CHECK(state IN ('active','completed','denied','terminated','failed')),
        bytes_total INTEGER NOT NULL DEFAULT 0,
        bytes_done  INTEGER NOT NULL DEFAULT 0,
        grant_ids   TEXT,
        remote_addr TEXT,
        note        TEXT,
        started_at  TEXT NOT NULL,
        finished_at TEXT
    );
    CREATE TABLE IF NOT EXISTS acl_entries(
        path       TEXT NOT NULL,
        linux_user TEXT NOT NULL,
        perms      TEXT NOT NULL,
        kind       TEXT NOT NULL CHECK(kind IN ('file','dir')),
        file_id    INTEGER,
        prior      TEXT,
        applied_at TEXT NOT NULL,
        PRIMARY KEY(path, linux_user)
    );
    CREATE TABLE IF NOT EXISTS settings(
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)


MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _m1_base,
    2: _m2_depth_and_indexes,
    3: _m3_runtime_tables,
}

