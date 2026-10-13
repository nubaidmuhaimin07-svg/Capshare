"""REAL Linux POSIX ACL checks (skipped automatically on non-Linux or without `setfacl`).

These run the engine with the real PosixAclBackend against a temporary storage
directory and the system user `nobody`, then read the kernel's answer with getfacl.
The fuller demonstration with allowed/denied file operations as two Linux users is
scripts/acl_demo.sh (needs sudo to create throw-away users)."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import EngineCase  # noqa: F401

LINUX = sys.platform.startswith("linux")
HAVE_TOOLS = bool(shutil.which("setfacl") and shutil.which("getfacl"))


@unittest.skipUnless(LINUX and HAVE_TOOLS, "needs Linux with the 'acl' package")
class RealAcl(unittest.TestCase):
    def setUp(self):
        import pwd
        try:
            pwd.getpwnam("nobody")
        except KeyError:
            self.skipTest("no 'nobody' user")
        from capshare.acl import PosixAclBackend
        from capshare.config import Config
        from capshare.context import AppContext
        self.tmp = Path(tempfile.mkdtemp(prefix="capshare-acl-"))
        cfg = Config.for_testing(self.tmp / "home", acl_mode="on")
        self.ctx = AppContext(cfg, acl_backend=PosixAclBackend())
        if not self.ctx.acl.enabled:
            self.skipTest("setfacl unavailable")
        acc = self.ctx.accounts
        self.owner = acc.create_user("olivia", "Olivia", None)["id"]
        self.bob = acc.create_user("bob", "Bob", None, linux_user="nobody")["id"]
        self.file = self.ctx.add_file_bytes(self.owner, "real.txt", b"real bytes\n")
        self.path = self.ctx.storage.path_for(self.file["stored_name"])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def getfacl(self) -> str:
        return self.ctx.acl.backend.getfacl_text(self.path)

    def test_grant_then_revoke_changes_real_acl(self):
        try:
            res = self.ctx.engine.create_grant(actor_id=self.owner, file_id=self.file["id"],
                                               recipient_id=self.bob, actions="READ")
        except Exception as exc:
            self.skipTest(f"filesystem does not support ACLs here: {exc}")
        self.assertIn("user:nobody:r--", self.getfacl())
        self.assertNotIn("user:nobody:rw-", self.getfacl())
        # the storage directory must be searchable (x) for the mapped user
        dir_acl = self.ctx.acl.backend.getfacl_text(self.ctx.storage.root)
        self.assertIn("user:nobody:--x", dir_acl)
        self.assertEqual(self.path.stat().st_mode & 0o007, 0)       # "other" has no access
        self.ctx.engine.revoke_grant(actor_id=self.owner, grant_id=res["grant"]["id"])
        self.assertNotIn("user:nobody", self.getfacl())
        self.assertNotIn("user:nobody", self.ctx.acl.backend.getfacl_text(self.ctx.storage.root))

    def test_independent_path_keeps_real_acl(self):
        eng, f = self.ctx.engine, self.file["id"]
        a = self.ctx.accounts.create_user("alice", "Alice", None)["id"]
        try:
            g1 = eng.create_grant(actor_id=self.owner, file_id=f, recipient_id=a, actions="READ",
                                  can_delegate=True)["grant"]
        except Exception as exc:
            self.skipTest(f"filesystem does not support ACLs here: {exc}")
        eng.create_grant(actor_id=a, file_id=f, recipient_id=self.bob, actions="READ", parent_id=g1["id"])
        eng.create_grant(actor_id=self.owner, file_id=f, recipient_id=self.bob, actions="READ")
        eng.revoke_grant(actor_id=self.owner, grant_id=g1["id"])
        self.assertIn("user:nobody:r--", self.getfacl())


if __name__ == "__main__":
    unittest.main()
