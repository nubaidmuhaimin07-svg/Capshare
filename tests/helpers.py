"""Test helpers: every test gets its OWN temporary home (database + storage + sample files),
so the checks can never alter your real files or the saved demo database."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capshare.context import make_test_context  # noqa: E402


class EngineCase(unittest.TestCase):
    """setUp builds a fresh temp context with owner O and users A, B, C, D."""

    config_overrides: dict = {}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capshare-test-"))
        self.ctx = make_test_context(self.tmp / "home", **self.config_overrides)
        self.eng = self.ctx.engine
        self.acl = self.ctx.acl.backend            # FakeAclBackend
        self.O = self.mkuser("olivia", admin=True)
        self.A = self.mkuser("alice")
        self.B = self.mkuser("bob")
        self.C = self.mkuser("carol")
        self.D = self.mkuser("dave")
        self.file = self.ctx.add_file_bytes(self.O, "plan.txt", b"top secret plan\n" * 10)["id"]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def mkuser(self, name, linux=None, admin=False) -> int:
        return self.ctx.accounts.create_user(name, name.title(), "password-1", is_admin=admin,
                                             linux_user=linux)["id"]

    def grant(self, actor, recipient, actions="READ", file_id=None, **kw) -> dict:
        return self.eng.create_grant(actor_id=actor, file_id=file_id or self.file,
                                     recipient_id=recipient, actions=actions, **kw)["grant"]

    def allowed(self, user, action="READ", file_id=None) -> bool:
        return self.eng.check_access(user, file_id or self.file, action)["allowed"]

    def code(self, user, action="READ", file_id=None) -> str:
        return self.eng.check_access(user, file_id or self.file, action)["code"]

    def audit_actions(self, outcome=None) -> list[str]:
        rows = self.eng.list_activity(self.O, True, 1000)
        return [r["action"] for r in rows if outcome is None or r["outcome"] == outcome]
