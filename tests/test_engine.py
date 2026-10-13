"""Normal behaviour: upload/storage, access, denial, delegation, revocation, expiry,
ACL bookkeeping, migrations. Uses only temporary databases and files."""
import os
import sqlite3
import unittest

from helpers import EngineCase  # noqa: F401  (also puts the project on sys.path)

from capshare import db as dbmod
from capshare.errors import AclError, BadRequest, GrantRejected, TooLarge
from capshare.storage import Storage, safe_display_name


class AccessBasics(EngineCase):
    def test_owner_always_allowed(self):
        self.assertTrue(self.allowed(self.O, "READ"))
        self.assertTrue(self.allowed(self.O, "WRITE"))
        self.assertEqual(self.code(self.O), "OWNER")

    def test_no_capability_denied(self):
        d = self.eng.check_access(self.A, self.file, "READ")
        self.assertFalse(d["allowed"])
        self.assertEqual(d["code"], "NO_CAPABILITY")

    def test_read_grant_allows_read_denies_write(self):
        self.grant(self.O, self.A, "READ")
        self.assertTrue(self.allowed(self.A, "READ"))
        self.assertFalse(self.allowed(self.A, "WRITE"))
        self.assertEqual(self.code(self.A, "WRITE"), "ACTION_NOT_GRANTED")

    def test_capability_is_scoped_to_one_file_and_one_recipient(self):
        other = self.ctx.add_file_bytes(self.O, "other.txt", b"x")["id"]
        self.grant(self.O, self.A, "READ")
        self.assertFalse(self.allowed(self.A, "READ", other))   # other file
        self.assertFalse(self.allowed(self.B, "READ"))           # other recipient

    def test_write_only_grant_does_not_imply_read(self):
        self.grant(self.O, self.A, "WRITE")
        self.assertTrue(self.allowed(self.A, "WRITE"))
        self.assertFalse(self.allowed(self.A, "READ"))

    def test_bad_action_names_rejected(self):
        with self.assertRaises(BadRequest):
            self.eng.create_grant(actor_id=self.O, file_id=self.file, recipient_id=self.A,
                                  actions=["EXECUTE"])
        with self.assertRaises(BadRequest):
            self.eng.check_access(self.A, self.file, "DELETE")


class Delegation(EngineCase):
    def test_escalation_is_refused_and_audited(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.A, self.B, "WRITE", parent_id=p["id"])
        self.assertEqual(cm.exception.code, "ESCALATION")
        self.assertFalse(self.allowed(self.B, "WRITE"))
        self.assertIn("grant.create", self.audit_actions("denied"))

    def test_delegation_needs_permission_flag(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=False)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.A, self.B, "READ", parent_id=p["id"])
        self.assertEqual(cm.exception.code, "DELEGATION_NOT_PERMITTED")

    def test_cannot_use_someone_elses_grant_as_parent(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.B, self.C, "READ", parent_id=p["id"])
        self.assertEqual(cm.exception.code, "NOT_YOUR_GRANT")

    def test_stranger_without_grant_cannot_share(self):
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.B, self.C, "READ")
        self.assertEqual(cm.exception.code, "NO_AUTHORITY")

    def test_auto_parent_selection_picks_a_capable_grant(self):
        read_only = self.grant(self.O, self.A, "READ", can_delegate=False)     # useless parent
        rw = self.grant(self.O, self.A, "READ,WRITE", can_delegate=True)
        child = self.grant(self.A, self.B, "WRITE")                            # no parent_id given
        self.assertEqual(child["parent_id"], rw["id"])
        self.assertNotEqual(child["parent_id"], read_only["id"])

    def test_self_grant_and_grant_to_owner_rejected(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.A, self.A, "READ", parent_id=p["id"])
        self.assertEqual(cm.exception.code, "SELF_GRANT")
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.A, self.O, "READ", parent_id=p["id"])
        self.assertEqual(cm.exception.code, "GRANT_TO_OWNER")

    def test_delegated_access_works_for_delegate(self):
        p = self.grant(self.O, self.A, "READ,WRITE", can_delegate=True)
        self.grant(self.A, self.B, "READ", parent_id=p["id"])
        self.assertTrue(self.allowed(self.B, "READ"))
        self.assertFalse(self.allowed(self.B, "WRITE"))

    def test_depth_limit_is_four_edges(self):
        users = [self.A, self.B, self.C, self.D, self.mkuser("erin")]
        parent = None
        for i in range(4):
            actor = self.O if i == 0 else users[i - 1]
            parent = self.grant(actor, users[i], "READ", can_delegate=True,
                                parent_id=parent["id"] if parent else None)
            self.assertEqual(parent["depth"], i + 1)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(users[3], users[4], "READ", parent_id=parent["id"])
        self.assertEqual(cm.exception.code, "DEPTH_LIMIT")


class Revocation(EngineCase):
    def test_only_owner_or_grantor_may_revoke(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        c = self.grant(self.A, self.B, "READ", parent_id=p["id"])
        with self.assertRaises(GrantRejected):
            self.eng.revoke_grant(actor_id=self.B, grant_id=p["id"])      # recipient of a child
        with self.assertRaises(GrantRejected):
            self.eng.revoke_grant(actor_id=self.C, grant_id=c["id"])      # stranger
        rep = self.eng.revoke_grant(actor_id=self.A, grant_id=c["id"])    # grantor of the child
        self.assertEqual(rep["affected_grants"], 1)
        self.assertTrue(self.allowed(self.A))                             # A keeps own access
        self.assertFalse(self.allowed(self.B))

    def test_cascade_revokes_whole_subtree(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        c = self.grant(self.A, self.B, "READ", can_delegate=True, parent_id=p["id"])
        self.grant(self.B, self.C, "READ", parent_id=c["id"])
        rep = self.eng.revoke_grant(actor_id=self.O, grant_id=p["id"])
        self.assertEqual((rep["affected_grants"], rep["descendant_count"]), (3, 2))
        for user in (self.A, self.B, self.C):
            self.assertFalse(self.allowed(user))
        self.assertEqual(self.eng.find_orphan_children(), [])

    def test_revoked_grant_cannot_be_a_parent(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        self.eng.revoke_grant(actor_id=self.O, grant_id=p["id"])
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.A, self.B, "READ", parent_id=p["id"])
        self.assertEqual(cm.exception.code, "PARENT_REVOKED")

    def test_independent_path_survives(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        self.grant(self.A, self.B, "READ", parent_id=p["id"])
        direct = self.grant(self.O, self.B, "READ")
        self.eng.revoke_grant(actor_id=self.O, grant_id=p["id"])
        d = self.eng.check_access(self.B, self.file, "READ")
        self.assertTrue(d["allowed"])
        self.assertEqual(d["via_grants"], [direct["id"]])

    def test_revoke_is_idempotent(self):
        p = self.grant(self.O, self.A, "READ")
        self.eng.revoke_grant(actor_id=self.O, grant_id=p["id"])
        rep = self.eng.revoke_grant(actor_id=self.O, grant_id=p["id"])
        self.assertTrue(rep["already_revoked"])
        self.assertEqual(rep["affected_grants"], 0)

    def test_cascade_ceiling_is_enforced_atomically(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        for _ in range(6):
            self.grant(self.A, self.B, "READ", parent_id=p["id"])
        self.eng.config.cascade_ceiling = 3
        from capshare.errors import CascadeLimitExceeded
        with self.assertRaises(CascadeLimitExceeded):
            self.eng.revoke_grant(actor_id=self.O, grant_id=p["id"])
        self.assertTrue(self.allowed(self.A))          # nothing was half-revoked

    def test_parent_id_index_exists_and_is_used(self):
        with self.eng.db.read() as conn:
            names = {r["name"] for r in conn.execute("PRAGMA index_list(grants)")}
            plan = " ".join(r["detail"] for r in conn.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM grants WHERE parent_id IN (?,?)", (1, 2)))
        self.assertIn("idx_grants_parent_id", names)
        self.assertIn("idx_grants_parent_id", plan)


class Expiry(EngineCase):
    def test_expiry_boundary(self):
        self.grant(self.O, self.A, "READ", expires_at=10)
        self.eng.set_clock(self.O, self.O, 9)
        self.assertTrue(self.allowed(self.A))
        self.eng.set_clock(self.O, self.O, 10)
        self.assertEqual(self.code(self.A), "CAPABILITY_EXPIRED")
        self.eng.set_clock(self.O, self.O, 11)
        self.assertFalse(self.allowed(self.A))

    def test_only_owner_moves_clock_and_only_forward(self):
        with self.assertRaises(GrantRejected):
            self.eng.set_clock(self.A, self.O, 5)
        self.eng.set_clock(self.O, self.O, 7)
        with self.assertRaises(GrantRejected) as cm:
            self.eng.set_clock(self.O, self.O, 3)
        self.assertEqual(cm.exception.code, "CLOCK_BACKWARDS")

    def test_expiry_in_past_rejected(self):
        self.eng.set_clock(self.O, self.O, 5)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.O, self.A, "READ", expires_at=5)
        self.assertEqual(cm.exception.code, "EXPIRY_IN_PAST")

    def test_expired_ancestor_blocks_active_looking_child(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True, expires_at=10)
        self.grant(self.A, self.B, "READ", parent_id=p["id"], expires_at=10)
        self.eng.set_clock(self.O, self.O, 10)
        self.assertFalse(self.allowed(self.B))
        statuses = {g["id"]: g["status"] for g in self.eng.list_grants(self.O, self.file)}
        self.assertEqual(set(statuses.values()), {"expired"})

    def test_clock_advance_writes_expiry_audit(self):
        g = self.grant(self.O, self.A, "READ", expires_at=3)
        res = self.eng.set_clock(self.O, self.O, 4)
        self.assertEqual(res["expired_grants"], [g["id"]])
        self.assertIn("grant.expired", self.audit_actions("ok"))


class AclBookkeeping(EngineCase):
    def setUp(self):
        super().setUp()
        self.LA = self.mkuser("lina", linux="lx_lina")
        self.LB = self.mkuser("lonn", linux="lx_lonn")

    def file_entries(self):
        return {u: p for (path, u), p in self.acl.entries.items() if path.endswith(".bin")}

    def test_grant_applies_and_revoke_removes_entry(self):
        g = self.grant(self.O, self.LA, "READ")
        self.assertEqual(self.file_entries(), {"lx_lina": "r--"})
        self.eng.revoke_grant(actor_id=self.O, grant_id=g["id"])
        self.assertEqual(self.file_entries(), {})
        self.assertEqual([k for k in self.acl.entries], [])      # directory x entries released too

    def test_write_maps_to_rw(self):
        self.grant(self.O, self.LA, "READ,WRITE")
        self.assertEqual(self.file_entries(), {"lx_lina": "rw-"})

    def test_entry_kept_while_another_path_supports_it(self):
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        self.grant(self.A, self.LA, "READ", parent_id=p["id"])
        self.grant(self.O, self.LA, "READ")
        self.eng.revoke_grant(actor_id=self.O, grant_id=p["id"])
        self.assertEqual(self.file_entries(), {"lx_lina": "r--"})

    def test_entry_downgrades_when_only_read_path_remains(self):
        w = self.grant(self.O, self.LA, "WRITE")
        self.grant(self.O, self.LA, "READ")
        self.assertEqual(self.file_entries(), {"lx_lina": "rw-"})
        self.eng.revoke_grant(actor_id=self.O, grant_id=w["id"])
        self.assertEqual(self.file_entries(), {"lx_lina": "r--"})

    def test_expiry_removes_entry(self):
        self.grant(self.O, self.LA, "READ", expires_at=5)
        self.assertEqual(self.file_entries(), {"lx_lina": "r--"})
        self.eng.set_clock(self.O, self.O, 5)
        self.assertEqual(self.file_entries(), {})

    def test_acl_failure_on_grant_rolls_back(self):
        self.acl.fail_on_user = {"lx_lina"}
        with self.assertRaises(AclError):
            self.grant(self.O, self.LA, "READ")
        self.assertEqual(self.eng.list_grants(self.O, self.file), [])      # grant NOT created
        self.assertFalse(self.allowed(self.LA))
        self.assertIn("grant.create", self.audit_actions("error"))

    def test_acl_failure_on_revoke_is_reported_not_hidden(self):
        g = self.grant(self.O, self.LA, "READ")
        self.acl.fail_on_user = {"lx_lina"}
        rep = self.eng.revoke_grant(actor_id=self.O, grant_id=g["id"])
        self.assertFalse(self.allowed(self.LA))                  # the service already denies
        self.assertTrue(rep["acl"]["inconsistent"])
        self.assertIn("lx_lina", rep["acl"]["error"])
        self.assertEqual(self.file_entries(), {"lx_lina": "r--"})   # OS entry really is still there
        self.acl.fail_on_user = set()
        res = self.eng.sync_acl(self.file, force=True, probe=True)  # "Retry ACL sync"
        self.assertIsNone(res["error"])
        self.assertEqual(self.file_entries(), {})

    def test_acl_disabled_backend_changes_nothing(self):
        from capshare.acl import AclManager, NullAclBackend
        self.ctx.acl.backend = NullAclBackend()
        before = dict(self.acl.entries)
        res = self.grant(self.O, self.LB, "READ")
        self.assertEqual(self.acl.entries, before)
        self.assertTrue(res["id"])


class StorageAndLimits(EngineCase):
    def test_path_confinement(self):
        st: Storage = self.ctx.storage
        for bad in ("../x", "..", "a/b", "/etc/passwd", "a\\b", ""):
            with self.assertRaises(BadRequest):
                st.resolve(bad)
        ok = st.resolve("fine.bin")
        self.assertEqual(ok.parent, st.root.resolve())

    def test_symlink_escape_is_refused(self):
        st: Storage = self.ctx.storage
        target = self.tmp / "outside.txt"
        target.write_text("secret")
        link = st.root / "evil.bin"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        with self.assertRaises(BadRequest):
            st.resolve("evil.bin")

    def test_display_name_sanitised(self):
        self.assertEqual(safe_display_name("../../etc/passwd"), "passwd")
        self.assertEqual(safe_display_name('a<b>:"c".txt'), "a_b___c_.txt")
        with self.assertRaises(BadRequest):
            safe_display_name("   ")

    def test_upload_size_limit_and_cleanup(self):
        st: Storage = self.ctx.storage
        with self.assertRaises(TooLarge):
            st.write_stream([b"x" * 600, b"y" * 600], max_bytes=1000)
        leftovers = [p for p in st.root.iterdir() if p.name.startswith(".upload-")]
        self.assertEqual(leftovers, [])


class Migrations(unittest.TestCase):
    def test_old_database_is_upgraded_without_losing_data(self):
        import shutil
        import tempfile
        from pathlib import Path
        tmp = Path(tempfile.mkdtemp(prefix="capshare-mig-"))
        try:
            path = tmp / "old.db"
            conn = sqlite3.connect(path)
            dbmod._m1_base(conn)               # the ORIGINAL v1 layout: no depth, no index
            conn.executescript("""
              INSERT INTO users(id,username,display_name,is_admin,created_at) VALUES
                (1,'olivia','Olivia',1,'2026-01-01'),(2,'alice','Alice',0,'2026-01-01'),
                (3,'bob','Bob',0,'2026-01-01');
              INSERT INTO files(id,name,stored_name,owner_id,size,created_at) VALUES
                (1,'a.txt','a.bin',1,5,'2026-01-01');
              INSERT INTO grants(id,file_id,recipient_id,grantor_id,actions,can_delegate,parent_id,state,created_at)
                VALUES (1,1,2,1,'READ',1,NULL,'active','2026-01-01'),
                       (2,1,3,2,'READ',0,1,'active','2026-01-02');
            """)
            conn.commit()
            conn.close()
            database = dbmod.Database(path)
            log = database.migrate()
            self.assertTrue(any("backup written" in l for l in log))
            self.assertTrue(list(tmp.glob("old.db.bak-v1-*")))
            with database.read() as c:
                self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], dbmod.SCHEMA_VERSION)
                depths = {r["id"]: r["depth"] for r in c.execute("SELECT id, depth FROM grants")}
                self.assertEqual(depths, {1: 1, 2: 2})
                self.assertEqual(c.execute("SELECT name FROM files").fetchone()[0], "a.txt")
                idx = {r["name"] for r in c.execute("PRAGMA index_list(grants)")}
                self.assertIn("idx_grants_parent_id", idx)
            self.assertEqual(database.migrate(), [])         # second run is a no-op
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_newer_database_is_refused(self):
        import shutil
        import tempfile
        from pathlib import Path
        tmp = Path(tempfile.mkdtemp(prefix="capshare-mig-"))
        try:
            path = tmp / "future.db"
            c = sqlite3.connect(path)
            c.execute("PRAGMA user_version = 99")
            c.execute("CREATE TABLE x(a)")
            c.commit()
            c.close()
            with self.assertRaises(RuntimeError):
                dbmod.Database(path).migrate()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
