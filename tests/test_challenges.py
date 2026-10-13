"""KO-13 challenges C1..C5 as automated checks.

Each test runs the same scenario the Challenge Lab shows (capshare/lab.py) and then
asserts the key facts again independently, so a bug in the scenario narration cannot
hide a bug in the engine."""
import random
import threading
import unittest

from helpers import EngineCase  # noqa: F401

from capshare import lab
from capshare.errors import CascadeLimitExceeded, GrantRejected


def failed_steps(result):
    return [f"{s['n']}. {s['title']} -> {s['actual']}" for s in result["steps"] if not s["ok"]]


class C1_DelegationAndCascade(unittest.TestCase):
    def test_scenario(self):
        res = lab.run_c1()
        self.assertEqual(failed_steps(res), [])
        self.assertTrue(res["passed"])
        before, after = res["snapshots"]
        self.assertEqual(before["active"], 2)
        self.assertEqual(after["active"], 0)


class C1_Direct(EngineCase):
    def test_b_denied_write_and_loses_read_on_revoke(self):
        g1 = self.grant(self.O, self.A, "READ", can_delegate=True)
        g2 = self.grant(self.A, self.B, "READ", parent_id=g1["id"])
        self.assertTrue(self.allowed(self.B, "READ"))
        self.assertFalse(self.allowed(self.B, "WRITE"))
        with self.assertRaises(GrantRejected):
            self.grant(self.A, self.B, "WRITE", parent_id=g1["id"])
        self.eng.revoke_grant(actor_id=self.O, grant_id=g1["id"])
        self.assertFalse(self.allowed(self.B, "READ"))
        states = {g["id"]: g["status"] for g in self.eng.list_grants(self.O, self.file)}
        self.assertEqual(states, {g1["id"]: "revoked", g2["id"]: "revoked"})


class C2_IndependentPath(unittest.TestCase):
    def test_scenario(self):
        res = lab.run_c2()
        self.assertEqual(failed_steps(res), [])


class C2_Direct(EngineCase):
    def test_b_keeps_read_through_owner_grant(self):
        g1 = self.grant(self.O, self.A, "READ", can_delegate=True)
        g2 = self.grant(self.A, self.B, "READ", parent_id=g1["id"])
        g3 = self.grant(self.O, self.B, "READ")
        self.assertEqual(sorted(self.eng.check_access(self.B, self.file, "READ")["via_grants"]),
                         sorted([g2["id"], g3["id"]]))
        self.eng.revoke_grant(actor_id=self.O, grant_id=g1["id"])
        d = self.eng.check_access(self.B, self.file, "READ")
        self.assertTrue(d["allowed"])
        self.assertEqual(d["via_grants"], [g3["id"]])
        self.assertFalse(self.allowed(self.A))


class C3_BoundedLineage(unittest.TestCase):
    def test_scenario(self):
        res = lab.run_c3()
        self.assertEqual(failed_steps(res), [])
        m = res["metrics"]
        self.assertGreaterEqual(m["descendants"], 100)
        self.assertEqual(m["affected_grants"], m["descendants"] + 1)
        self.assertIn("idx_grants_parent_id", m["traversal_method"])
        self.assertGreaterEqual(m["elapsed_ms"], 0)


class C3_Direct(EngineCase):
    def test_fifth_edge_rejected(self):
        chain = [self.A, self.B, self.C, self.D, self.mkuser("erin")]
        parent = None
        for i in range(4):
            parent = self.grant(self.O if i == 0 else chain[i - 1], chain[i], "READ",
                                can_delegate=True, parent_id=parent["id"] if parent else None)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(chain[3], chain[4], "READ", parent_id=parent["id"])
        self.assertEqual(cm.exception.code, "DEPTH_LIMIT")

    def test_configurable_edge_limit(self):
        self.eng.config.max_delegation_edges = 2
        p = self.grant(self.O, self.A, "READ", can_delegate=True)
        c = self.grant(self.A, self.B, "READ", can_delegate=True, parent_id=p["id"])
        with self.assertRaises(GrantRejected):
            self.grant(self.B, self.C, "READ", parent_id=c["id"])


class C4_Concurrency(unittest.TestCase):
    def test_scenario(self):
        res = lab.run_c4()
        self.assertEqual(failed_steps(res), [])
        self.assertTrue(res["metrics"]["unsafe_race_reproduced"])
        self.assertEqual(res["metrics"]["orphans_after_safe_runs"], 0)
        self.assertEqual(res["metrics"]["revoker_first_error"], "PARENT_REVOKED")


class C4_Stress(EngineCase):
    """Many threads create and revoke at random; the invariant must hold at the end."""

    def test_no_active_child_under_inactive_parent(self):
        users = [self.A, self.B, self.C, self.D]
        roots = [self.grant(self.O, u, "READ", can_delegate=True) for u in users]
        rng_seed = 1234
        errors = []

        def worker(n):
            rng = random.Random(rng_seed + n)
            for _ in range(40):
                try:
                    if rng.random() < 0.7:
                        parent = rng.choice(roots)
                        actor = parent["recipient_id"]
                        target = rng.choice([u for u in users if u != actor])
                        self.eng.create_grant(actor_id=actor, file_id=self.file, recipient_id=target,
                                              actions="READ", parent_id=parent["id"])
                    else:
                        grants = self.eng.list_grants(self.O, self.file)
                        if grants:
                            self.eng.revoke_grant(actor_id=self.O, grant_id=rng.choice(grants)["id"])
                except GrantRejected:
                    pass                      # PARENT_REVOKED etc. is a legal outcome of the race
                except Exception as exc:      # anything else is a bug
                    errors.append(repr(exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(self.eng.find_orphan_children(), [])


class C5_Expiry(unittest.TestCase):
    def test_scenario(self):
        res = lab.run_c5()
        self.assertEqual(failed_steps(res), [])
        timeline = {(e["time"], e["user"]): e["decision"] for e in res["metrics"]["clock_timeline"]}
        self.assertEqual(timeline[(9, "A")], "ALLOWED")
        self.assertEqual(timeline[(10, "A")], "DENIED")
        self.assertEqual(timeline[(11, "A")], "DENIED")


class C5_Direct(EngineCase):
    def test_spec(self):
        g = self.grant(self.O, self.A, "READ", can_delegate=True, expires_at=10)
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.A, self.B, "READ", parent_id=g["id"], expires_at=20)
        self.assertEqual(cm.exception.code, "EXPIRY_OUTLIVES_PARENT")
        with self.assertRaises(GrantRejected) as cm:
            self.grant(self.A, self.B, "READ", parent_id=g["id"])
        self.assertEqual(cm.exception.code, "EXPIRY_PERMANENT_UNDER_EXPIRING_PARENT")
        self.eng.set_clock(self.O, self.O, 9)
        self.assertTrue(self.allowed(self.A))
        self.eng.set_clock(self.O, self.O, 10)
        self.assertFalse(self.allowed(self.A))
        self.eng.set_clock(self.O, self.O, 11)
        self.assertFalse(self.allowed(self.A))


class Lab_DoesNotTouchRealData(EngineCase):
    def test_lab_uses_its_own_database(self):
        before = self.eng.list_activity(self.O, True, 1000)
        lab.run_c1()
        after = self.eng.list_activity(self.O, True, 1000)
        self.assertEqual(len(before), len(after))
        self.assertEqual(self.eng.list_grants(self.O, self.file), [])


if __name__ == "__main__":
    unittest.main()
