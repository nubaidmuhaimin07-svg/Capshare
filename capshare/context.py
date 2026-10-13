"""AppContext: wires database, storage, ACL manager, engine, accounts and transfers.

The API server, the Challenge Lab, the CLI and the tests all build an AppContext, so
they all exercise exactly the same objects.
"""
from __future__ import annotations

import os
from pathlib import Path

from .accounts import Accounts
from .acl import AclManager, FakeAclBackend, NullAclBackend, PosixAclBackend
from .config import Config
from .db import Database
from .engine import CapabilityEngine
from .storage import Storage, safe_display_name
from .transfers import TransferRegistry


class AppContext:
    def __init__(self, config: Config, acl_backend=None):
        self.config = config
        config.home.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(config.home, 0o700)          # the data directory is private to the service user
        except OSError:
            pass
        self.db = Database(config.db_path)
        self.migration_log = self.db.migrate()
        self.storage = Storage(config.storage_dir)
        self.acl = AclManager(acl_backend or self._pick_backend(config.acl_mode),
                              config.storage_dir, config.home)
        self.engine = CapabilityEngine(self.db, config, self.storage, self.acl)
        self.accounts = Accounts(self.db, config)
        self.transfers = TransferRegistry(self.db)
        self.transfers.recover_after_restart()

    @staticmethod
    def _pick_backend(mode: str):
        if mode == "off":
            return NullAclBackend()
        real = PosixAclBackend()
        if real.available():
            return real
        return NullAclBackend()          # 'auto' (or 'on' without the tools): reported in the UI

    # ---------------------------------------------------------------- convenience
    def add_file_bytes(self, owner_id: int, name: str, data: bytes) -> dict:
        """Store bytes as a managed file (used by seed, Lab and tests)."""
        display = safe_display_name(name)
        tmp, size, digest = self.storage.write_stream([data], self.config.max_file_bytes)
        stored = self.storage.new_stored_name()
        self.storage.install_new(tmp, stored)
        return self.engine.register_file(owner_id, display, stored, size, digest)

    def get_setting(self, key: str, default: str = "") -> str:
        with self.db.read() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.db.write() as conn:
            conn.execute("INSERT INTO settings(key, value) VALUES (?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def make_test_context(home: Path, **config_overrides) -> AppContext:
    """Context for tests / Lab: temp directory, simulated ACLs, cheap password hashing."""
    cfg = Config.for_testing(home, **config_overrides)
    return AppContext(cfg, acl_backend=FakeAclBackend())
