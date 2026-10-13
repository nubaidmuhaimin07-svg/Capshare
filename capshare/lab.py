"""The five KO-13 challenge scenarios (C1 .. C5).

Each scenario runs the REAL permission engine against a throw-away database and a
sample file in a temporary directory, so it can never touch your saved demo data or
your real files. The Linux ACL backend is simulated here (every would-be `setfacl`
call is recorded and shown); the real `setfacl` demonstration is scripts/acl_demo.sh.

The same functions power the "Challenge Lab" page, `POST /api/lab/run/<key>` and the
automated checks in tests/test_challenges.py.
"""
from __future__ import annotations

import shutil
import tempfile
import threading
import time
from pathlib import Path

from .context import AppContext, make_test_context
from .db import utc_now
from .errors import AclError, CascadeLimitExceeded, GrantRejected

SAMPLE = b"CapShare sample file - KO-13 challenge\n" * 40


class LabRun:
    """Small helper that records numbered, human readable steps."""

    def __init__(self, key: str, title: str):
        self.key, self.title = key, title
        self.tmp = Path(tempfile.mkdtemp(prefix=f"capshare-lab-{key.lower()}-"))
        self.ctx: AppContext = make_test_context(self.tmp / "home")
        self.eng = self.ctx.engine
        self.steps: list[dict] = []
        self.snapshots: list[dict] = []
        self.users: dict[str, dict] = {}
        self.owner_id = 0
        self.file_id = 0
        self.metrics: dict = {}
        self._acl_mark = 0

    # ---------------------------------------------------------------- setup helpers
    def user(self, handle: str, display: str, linux: str | None = None) -> int:
        u = self.ctx.accounts.create_user(f"{handle}", display, None, linux_user=linux)
        self.users[handle] = u
        return u["id"]

    def name(self, user_id: int) -> str:
        for h, u in self.users.items():
            if u["id"] == user_id:
                return u["display_name"]
        return str(user_id)

    def setup_file(self, owner_id: int, name: str = "report.txt") -> int:
        self.owner_id = owner_id
        self.file_id = self.ctx.add_file_bytes(owner_id, name, SAMPLE)["id"]
        return self.file_id

    # ---------------------------------------------------------------- recording
    def step(self, title: str, expected: str, actual: str, ok: bool, data: dict | None = None):
        self.steps.append({"n": len(self.steps) + 1, "title": title, "expected": expected,
                           "actual": actual, "ok": bool(ok), "data": data or {}})

    def grant(self, title: str, **kw) -> int:
        res = self.eng.create_grant(file_id=self.file_id, **kw)
        g = res["grant"]
        self.step(title, "grant created", f"grant #{g['id']} created ({g['actions']}, "
                  f"delegable={bool(g['can_delegate'])}, depth {g['depth']}, "
                  f"expires {g['expires_at'] if g['expires_at'] is not None else 'never'})", True,
                  {"grant_id": g["id"], "acl_ops": res["acl"]["ops"]})
        return g["id"]

    def refuse(self, title: str, expect_code: str, **kw) -> None:
        try:
            res = self.eng.create_grant(file_id=self.file_id, **kw)
            self.step(title, f"rejected: {expect_code}",
                      f"UNEXPECTEDLY ACCEPTED as grant #{res['grant']['id']}", False)
        except GrantRejected as exc:
            self.step(title, f"rejected: {expect_code}", f"rejected: {exc.code} - {exc.message}",
                      exc.code == expect_code, {"code": exc.code})

    def check(self, title: str, user_id: int, action: str, expect_allowed: bool,
              expect_code: str | None = None) -> dict:
        d = self.eng.check_access(user_id, self.file_id, action, audit_actor=self.owner_id)
        ok = d["allowed"] == expect_allowed and (expect_code is None or d["code"] == expect_code)
        want = ("ALLOWED" if expect_allowed else "DENIED") + (f" ({expect_code})" if expect_code else "")
        self.step(title, want, f"{'ALLOWED' if d['allowed'] else 'DENIED'} ({d['code']}): {d['reason']}",
                  ok, {"clock": d["clock"], "via_grants": d["via_grants"], "paths": d["paths"]})
        return d

    def revoke(self, title: str, grant_id: int, actor_id: int | None = None) -> dict:
        rep = self.eng.revoke_grant(actor_id=actor_id or self.owner_id, grant_id=grant_id)
        self.step(title, "revoked with cascade",
                  f"{rep['affected_grants']} grant(s) revoked ({rep['descendants_revoked']} "
                  f"descendants) in {rep['elapsed_ms']} ms", True,
                  {k: rep[k] for k in ("affected_grants", "descendant_count", "traversal_method",
                                       "elapsed_ms", "revoked_ids")})
        return rep

    def snap(self, title: str, limit: int = 40) -> None:
        rows = self.eng.list_grants(self.owner_id, self.file_id)
        self.snapshots.append({
            "title": title, "total": len(rows),
            "active": sum(1 for g in rows if g["status"] == "active"),
            "clock": self.eng.get_clock(self.owner_id),
            "grants": [{"id": g["id"], "parent_id": g["parent_id"], "recipient": g["recipient_display"],
                        "grantor": g["grantor_name"], "actions": g["actions"],
                        "can_delegate": g["can_delegate"], "depth": g["depth"],
                        "expires_at": g["expires_at"], "status": g["status"],
                        "status_reason": g["status_reason"]} for g in rows[:limit]]})

    def acl_since_mark(self) -> list[str]:
        log = self.ctx.acl.backend.log
        out = log[self._acl_mark:]
        self._acl_mark = len(log)
        return out

    # ---------------------------------------------------------------- finish
    def result(self, summary: str) -> dict:
        activity = self.eng.list_activity(self.owner_id, True, limit=400)
        activity.reverse()                              # oldest first reads like a story
        out = {
            "key": self.key, "title": self.title, "summary": summary,
            "passed": all(s["ok"] for s in self.steps) and bool(self.steps),
            "steps": self.steps, "snapshots": self.snapshots, "metrics": self.metrics,
            "acl_log": [l.replace(str(self.tmp), "<tmp>") for l in self.ctx.acl.backend.log][-40:],
            "activity": [{"ts": a["ts"], "actor": a["actor_name"], "action": a["action"],
                          "outcome": a["outcome"], "grant_id": a["grant_id"],
                          "detail": a["detail"]} for a in activity[-120:]],
            "activity_total": len(activity),
            "finished_at": utc_now(),
        }
        shutil.rmtree(self.tmp, ignore_errors=True)
        return out


# =====================================================================================
# C1 - Delegation and cascade
# =====================================================================================
def run_c1() -> dict:
    r = LabRun("C1", "Delegation and cascade")
    o = r.user("owner_o", "O (owner)")
    a = r.user("alice_a", "A", linux="lab_alice")
    b = r.user("bob_b", "B", linux="lab_bob")
    r.setup_file(o)
    g1 = r.grant("O grants A a delegable READ capability", actor_id=o, recipient_id=a,
                 actions="READ", can_delegate=True)
    g2 = r.grant("A delegates READ to B (child of #%d)" % g1, actor_id=a, recipient_id=b,
                 actions="READ", parent_id=g1)
    r.check("B reads the file", b, "READ", True, "ALLOWED")
    r.check("B tries to WRITE", b, "WRITE", False, "ACTION_NOT_GRANTED")
    r.refuse("A tries to give B WRITE (A only holds READ)", "ESCALATION",
             actor_id=a, recipient_id=b, actions="WRITE", parent_id=g1)
    r.snap("BEFORE revocation")
    r.acl_since_mark()
    rep = r.revoke("O revokes A's grant #%d" % g1, g1)
    r.step("Cascade report", "A's grant and B's derived grant both revoked",
           f"affected={rep['affected_grants']} descendants={rep['descendant_count']}",
           rep["affected_grants"] == 2 and rep["descendant_count"] == 1)
    r.snap("AFTER revocation")
    r.check("A can no longer read", a, "READ", False, "CAPABILITY_REVOKED")
    r.check("B lost the delegated access", b, "READ", False, "CAPABILITY_REVOKED")
    ops = r.acl_since_mark()
    r.step("Linux ACL entries removed for the mapped users", "setfacl -x for lab_alice and lab_bob",
           "; ".join(ops) or "(no operations)",
           any("-x u:lab_alice" in o_ for o_ in ops) and any("-x u:lab_bob" in o_ for o_ in ops))
    r.metrics = {"state_change": f"#{g1}: active -> revoked, #{g2}: active -> revoked"}
    return r.result("O revoked A's grant; B's derived READ disappeared in the same transaction.")


# =====================================================================================
# C2 - Independent authority path
# =====================================================================================
def run_c2() -> dict:
    r = LabRun("C2", "Independent authority path")
    o = r.user("owner_o", "O (owner)")
    a = r.user("alice_a", "A", linux="lab_alice")
    b = r.user("bob_b", "B", linux="lab_bob")
    r.setup_file(o)
    g1 = r.grant("O grants A a delegable READ", actor_id=o, recipient_id=a, actions="READ",
                 can_delegate=True)
    g2 = r.grant("A delegates READ to B (path 1: O -> A -> B)", actor_id=a, recipient_id=b,
                 actions="READ", parent_id=g1)
    g3 = r.grant("O ALSO grants B a direct READ (path 2: O -> B)", actor_id=o, recipient_id=b,
                 actions="READ")
    d = r.check("B reads - two independent paths", b, "READ", True, "ALLOWED")
    r.step("Both paths are visible to the engine", f"via #{g2} and #{g3}",
           f"via {['#%d' % i for i in d['via_grants']]}", sorted(d["via_grants"]) == sorted([g2, g3]))
    r.snap("BEFORE: two lineages for B")
    r.acl_since_mark()
    r.revoke("O revokes ONLY A's delegated root #%d" % g1, g1)
    r.snap("AFTER: path 1 revoked, path 2 intact")
    d = r.check("B still reads through the direct grant", b, "READ", True, "ALLOWED")
    r.step("The surviving path is the owner-issued one", f"via #{g3}",
           f"via {['#%d' % i for i in d['via_grants']]}", d["via_grants"] == [g3])
    ops = r.acl_since_mark()
    r.step("B's Linux ACL entry was NOT removed (another path supports it)",
           "no 'setfacl -x u:lab_bob' on the file", "; ".join(ops) or "(no ACL changes for B)",
           not any("-x u:lab_bob" in o_ and ".bin" in o_ for o_ in ops))
    r.check("A lost access", a, "READ", False, "CAPABILITY_REVOKED")
    r.revoke("O revokes B's direct grant #%d" % g3, g3)
    r.check("Now B is denied", b, "READ", False)
    ops = r.acl_since_mark()
    r.step("Only now B's Linux ACL entry is removed", "setfacl -x u:lab_bob", "; ".join(ops),
           any("-x u:lab_bob" in o_ and ".bin" in o_ for o_ in ops))
    return r.result("Revoking one path preserved the access that another independent path supports.")


# =====================================================================================
# C3 - Bounded lineage and traversal
# =====================================================================================
def run_c3() -> dict:
    r = LabRun("C3", "Bounded lineage and traversal")
    eng = r.eng
    o = r.user("owner_o", "O (owner)")
    r.setup_file(o)

    # --- part 1: depth limit -------------------------------------------------------
    chain = [r.user(f"chain_{n}", f"Chain {n.upper()}") for n in "abcde"]
    prev = None
    for i in range(4):
        actor = o if i == 0 else chain[i - 1]
        prev = r.grant(f"Edge {i + 1}: {r.name(actor)} -> {r.name(chain[i])}", actor_id=actor,
                       recipient_id=chain[i], actions="READ", can_delegate=True,
                       parent_id=prev if i else None)
    r.refuse("Edge 5 is rejected (limit is 4 edges, owner's grant is edge 1)", "DEPTH_LIMIT",
             actor_id=chain[3], recipient_id=chain[4], actions="READ", parent_id=prev)

    # --- part 2: a subtree with 130 descendants -------------------------------------
    pool = [r.user(f"pool_{i:02d}", f"U{i:02d}") for i in range(1, 15)]
    root = r.grant("Subtree root: O -> U01 (edge 1)", actor_id=o, recipient_id=pool[0],
                   actions="READ", can_delegate=True)
    level2 = []
    for k in range(1, 11):                                  # 10 grants at edge 2
        res = eng.create_grant(actor_id=pool[0], file_id=r.file_id, recipient_id=pool[k],
                               actions="READ", can_delegate=True, parent_id=root)
        level2.append(res["grant"])
    level3 = []
    for g in level2:                                         # 4 each = 40 at edge 3
        grantor = g["recipient_id"]
        others = [p for p in pool if p != grantor]
        start = pool.index(grantor) % len(others)
        for j in range(4):
            res = eng.create_grant(actor_id=grantor, file_id=r.file_id,
                                   recipient_id=others[(start + j) % len(others)],
                                   actions="READ", can_delegate=True, parent_id=g["id"])
            level3.append(res["grant"])
    level4 = []
    for g in level3:                                         # 2 each = 80 at edge 4
        grantor = g["recipient_id"]
        others = [p for p in pool if p != grantor]
        start = pool.index(grantor) % len(others)
        for j in range(2):
            res = eng.create_grant(actor_id=grantor, file_id=r.file_id,
                                   recipient_id=others[(start + j) % len(others)],
                                   actions="READ", can_delegate=False, parent_id=g["id"])
            level4.append(res["grant"])
    total = len(level2) + len(level3) + len(level4)
    r.step("Built a delegation subtree", ">= 100 descendants",
           f"{len(level2)} + {len(level3)} + {len(level4)} = {total} descendants under grant #{root}",
           total >= 100, {"descendants": total})
    r.snap("Subtree before revoke (first 40 rows shown)", limit=40)

    with eng.db.read() as conn:
        plan = " | ".join(row["detail"] for row in conn.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM grants WHERE parent_id IN (?,?)", (1, 2)))
    r.step("Lineage traversal uses the parent_id index", "plan mentions idx_grants_parent_id", plan,
           "idx_grants_parent_id" in plan, {"query_plan": plan})

    # --- part 3: safety ceiling ------------------------------------------------------
    saved = eng.config.cascade_ceiling
    eng.config.cascade_ceiling = 50
    try:
        try:
            eng.revoke_grant(actor_id=o, grant_id=root)
            r.step("Revoke with ceiling = 50", "refused (130 > 50)", "UNEXPECTEDLY ACCEPTED", False)
        except CascadeLimitExceeded as exc:
            still = sum(1 for g in eng.list_grants(o, r.file_id)
                        if g["status"] == "active" and g["id"] >= root)
            r.step("Revoke with ceiling = 50 is refused and changes NOTHING", "error + 0 changes",
                   f"{exc.code}: {exc.message} Active grants unchanged: {still}", still == total + 1)
    finally:
        eng.config.cascade_ceiling = saved

    # --- part 4: the real revoke -----------------------------------------------------
    rep = r.revoke("O revokes the subtree root", root)
    r.step("Revocation report", f"affected = {total + 1}, descendants = {total}",
           f"affected={rep['affected_grants']}, descendants={rep['descendant_count']}, "
           f"method: {rep['traversal_method']}, elapsed={rep['elapsed_ms']} ms",
           rep["affected_grants"] == total + 1 and rep["descendant_count"] == total)
    r.snap("Subtree after revoke (first 40 rows shown)", limit=40)
    r.metrics = {"descendants": rep["descendant_count"], "affected_grants": rep["affected_grants"],
                 "traversal_method": rep["traversal_method"], "elapsed_ms": rep["elapsed_ms"],
                 "index_lookups": rep["index_lookups"], "levels": rep["traversal_levels"]}
    return r.result(f"Depth capped at 4 edges; {rep['affected_grants']} grants revoked "
                    f"via the parent_id index in {rep['elapsed_ms']} ms.")


# =====================================================================================
# C4 - Concurrent delegation and revoke
# =====================================================================================
def _naive_delegate(ctx: AppContext, file_id: int, grantor_id: int, recipient_id: int,
                    parent_id: int, window) -> int:
    """DEMONSTRATION ONLY - the vulnerable pattern CapShare does NOT use.

    "check" and "insert" are two separate transactions with a gap between them
    (`window()` is where the owner's revoke lands). This is the classic
    time-of-check / time-of-use (TOCTOU) race.
    """
    with ctx.db.read() as conn:                                  # 1) check
        parent = conn.execute("SELECT state FROM grants WHERE id=?", (parent_id,)).fetchone()
        assert parent and parent["state"] == "active"
    window()                                                     # ... the revoke happens here
    with ctx.db.write() as conn:                                 # 2) use (no re-check!)
        cur = conn.execute(
            "INSERT INTO grants(file_id, recipient_id, grantor_id, actions, can_delegate, parent_id, "
            "state, created_at, depth) VALUES (?,?,?,?,?,?,?,?,?)",
            (file_id, recipient_id, grantor_id, "READ", 0, parent_id, "active", utc_now(), 2))
        return cur.lastrowid


def run_c4() -> dict:
    r = LabRun("C4", "Concurrent delegation and revoke")
    eng = r.eng
    o = r.user("owner_o", "O (owner)")
    a = r.user("alice_a", "A")
    b = r.user("bob_b", "B")
    r.setup_file(o)

    # --- 0: reproduce the race with the unsafe pattern -------------------------------
    g0 = r.grant("O grants A a delegable READ (#1)", actor_id=o, recipient_id=a, actions="READ",
                 can_delegate=True)
    orphan = _naive_delegate(r.ctx, r.file_id, a, b, g0,
                             window=lambda: eng.revoke_grant(actor_id=o, grant_id=g0))
    orphans = eng.find_orphan_children()
    race_reproduced = bool(orphans)
    r.step("UNSAFE pattern (separate check and insert): race reproduced",
           "an ACTIVE child under a REVOKED parent",
           f"orphan child #{orphan} is active under revoked parent #{g0}" if orphans
           else "no orphan (race not reproduced)", race_reproduced,
           {"orphans": orphans})
    eng.revoke_grant(actor_id=o, grant_id=orphan, reason="lab cleanup of the demonstrated orphan")

    # --- 1: safe engine, creator wins -------------------------------------------------
    g1 = r.grant("O grants A another delegable READ", actor_id=o, recipient_id=a, actions="READ",
                 can_delegate=True)
    reached, release = threading.Event(), threading.Event()
    out: dict = {}

    def pause_creator(**_):
        reached.set()
        release.wait(10)

    def creator():
        try:
            out["child"] = eng.create_grant(actor_id=a, file_id=r.file_id, recipient_id=b,
                                            actions="READ", parent_id=g1)["grant"]["id"]
        except GrantRejected as exc:
            out["child_error"] = exc.code

    def revoker():
        out["report"] = eng.revoke_grant(actor_id=o, grant_id=g1)

    eng.hooks["create_grant.after_parent_check"] = pause_creator
    t_create = threading.Thread(target=creator)
    t_create.start()
    reached.wait(10)                                       # creator has CHECKED the parent
    t_revoke = threading.Thread(target=revoker)
    t_revoke.start()                                       # owner revokes while creator is paused
    time.sleep(0.4)
    blocked = t_revoke.is_alive()
    release.set()
    t_create.join(15)
    t_revoke.join(15)
    eng.hooks.pop("create_grant.after_parent_check", None)
    r.step("Ordering 1: revoker is BLOCKED while the creator holds the write lock",
           "revoke waits (serialized)", "revoke was waiting" if blocked else "revoke ran in parallel",
           blocked)
    child = out.get("child")
    rep = out.get("report", {})
    r.step("Ordering 1 outcome: child created first, then included in the cascade",
           "child created AND revoked by the cascade",
           f"child #{child} created; revoke affected {rep.get('affected_grants')} grant(s)",
           child is not None and child in rep.get("revoked_ids", []))
    r.step("Invariant after ordering 1", "no active child under an inactive parent",
           f"orphans: {eng.find_orphan_children()}", eng.find_orphan_children() == [])

    # --- 2: safe engine, revoker wins -------------------------------------------------
    g2 = r.grant("O grants A a third delegable READ", actor_id=o, recipient_id=a, actions="READ",
                 can_delegate=True)
    reached2, release2 = threading.Event(), threading.Event()
    out2: dict = {}

    def pause_revoker(**_):
        reached2.set()
        release2.wait(10)

    def creator2():
        try:
            out2["child"] = eng.create_grant(actor_id=a, file_id=r.file_id, recipient_id=b,
                                             actions="READ", parent_id=g2)["grant"]["id"]
        except GrantRejected as exc:
            out2["child_error"] = exc.code

    def revoker2():
        out2["report"] = eng.revoke_grant(actor_id=o, grant_id=g2)

    eng.hooks["revoke.after_lock"] = pause_revoker
    t_revoke2 = threading.Thread(target=revoker2)
    t_revoke2.start()
    reached2.wait(10)                                      # revoker holds the lock, not yet cascaded
    t_create2 = threading.Thread(target=creator2)
    t_create2.start()
    time.sleep(0.4)
    blocked2 = t_create2.is_alive()
    release2.set()
    t_revoke2.join(15)
    t_create2.join(15)
    eng.hooks.pop("revoke.after_lock", None)
    r.step("Ordering 2: creator is BLOCKED while the revoker holds the write lock",
           "create waits (serialized)", "create was waiting" if blocked2 else "create ran in parallel",
           blocked2)
    r.step("Ordering 2 outcome: revoke first, child creation rejected",
           "PARENT_REVOKED", str(out2.get("child_error") or f"child #{out2.get('child')} created"),
           out2.get("child_error") == "PARENT_REVOKED")
    orphans = eng.find_orphan_children()
    r.step("Invariant after ordering 2", "no active child under an inactive parent",
           f"orphans: {orphans}", orphans == [])
    r.snap("Final lineage")
    r.metrics = {"unsafe_race_reproduced": race_reproduced, "orphans_after_safe_runs": len(orphans),
                 "creator_first_child": child, "revoker_first_error": out2.get("child_error")}
    return r.result("Check+insert and revoke are serialized by BEGIN IMMEDIATE: either the child "
                    "is created and then revoked, or creation is rejected. No orphan survives.")


# =====================================================================================
# C5 - Temporary capability expiry (logical clock)
# =====================================================================================
def run_c5() -> dict:
    r = LabRun("C5", "Temporary capability expiry")
    eng = r.eng
    o = r.user("owner_o", "O (owner)")
    a = r.user("alice_a", "A", linux="lab_alice")
    b = r.user("bob_b", "B")
    r.setup_file(o)
    timeline: list[dict] = []

    g1 = r.grant("O grants A a delegable READ that expires at logical time 10", actor_id=o,
                 recipient_id=a, actions="READ", can_delegate=True, expires_at=10)
    r.refuse("A offers B a child expiring at 20 (outlives the parent)", "EXPIRY_OUTLIVES_PARENT",
             actor_id=a, recipient_id=b, actions="READ", parent_id=g1, expires_at=20)
    r.refuse("A offers B a PERMANENT child (parent expires)", "EXPIRY_PERMANENT_UNDER_EXPIRING_PARENT",
             actor_id=a, recipient_id=b, actions="READ", parent_id=g1)
    g2 = r.grant("A offers B a child expiring at 10 (allowed: not later than the parent)",
                 actor_id=a, recipient_id=b, actions="READ", parent_id=g1, expires_at=10)

    def set_clock(t: int):
        res = eng.set_clock(o, o, t)
        r.step(f"Owner sets the logical clock to {t}", "clock moved",
               f"clock {res['old']} -> {res['new']}; newly expired grants: {res['expired_grants']}", True,
               {"expired_grants": res["expired_grants"]})

    set_clock(9)
    d = r.check("t=9: A reads", a, "READ", True, "ALLOWED")
    timeline.append({"time": 9, "user": "A", "decision": "ALLOWED", "code": d["code"]})
    d = r.check("t=9: B reads", b, "READ", True, "ALLOWED")
    timeline.append({"time": 9, "user": "B", "decision": "ALLOWED", "code": d["code"]})
    r.snap("Lineage at t=9")
    set_clock(10)
    d = r.check("t=10: A reads (expiry reached)", a, "READ", False, "CAPABILITY_EXPIRED")
    timeline.append({"time": 10, "user": "A", "decision": "DENIED", "code": d["code"]})
    d = r.check("t=10: B reads (derived grant also expired)", b, "READ", False, "CAPABILITY_EXPIRED")
    timeline.append({"time": 10, "user": "B", "decision": "DENIED", "code": d["code"]})
    set_clock(11)
    d = r.check("t=11: A reads", a, "READ", False, "CAPABILITY_EXPIRED")
    timeline.append({"time": 11, "user": "A", "decision": "DENIED", "code": d["code"]})
    r.refuse("t=11: A tries to delegate from the expired grant", "PARENT_EXPIRED",
             actor_id=a, recipient_id=b, actions="READ", parent_id=g1, expires_at=None)
    try:
        eng.set_clock(o, o, 5)
        r.step("Clock rewind to 5", "refused (time only moves forward)", "UNEXPECTEDLY ACCEPTED", False)
    except GrantRejected as exc:
        r.step("Clock rewind to 5", "refused (time only moves forward)", f"{exc.code}: {exc.message}",
               exc.code == "CLOCK_BACKWARDS")
    r.snap("Lineage at t=11")
    ops = r.ctx.acl.backend.log
    r.step("Linux ACL for A followed the expiry", "setfacl -x u:lab_alice after the clock passed 10",
           "; ".join(o_ for o_ in ops if "lab_alice" in o_ and ".bin" in o_),
           any("-x u:lab_alice" in o_ and ".bin" in o_ for o_ in ops))
    r.metrics = {"clock_timeline": timeline, "parent_grant": g1, "child_grant": g2}
    return r.result("READ allowed at 9, denied at 10 and 11; children cannot outlive or "
                    "out-permanent an expiring parent.")


CHALLENGES = {
    "C1": {"title": "Delegation and cascade", "run": run_c1,
           "what": "Owner O grants A a delegable READ; A grants B READ. B is denied WRITE. "
                   "When O revokes A's grant, B's delegated access must disappear too.",
           "rules": ["a delegate can never exceed the parent's actions (no escalation)",
                     "revoking a grant revokes every descendant in the same transaction",
                     "the mapped Linux user's ACL entry is removed"]},
    "C2": {"title": "Independent authority path", "run": run_c2,
           "what": "O also gives B a direct READ. Revoking only A's delegated root must keep B's "
                   "READ because an independent, owner-issued path still supports it.",
           "rules": ["effective access = union over all independent active paths",
                     "a revoke removes only the subtree it roots",
                     "OS ACL entries are kept while any path still supports them"]},
    "C3": {"title": "Bounded lineage and traversal", "run": run_c3,
           "what": "At most four delegation edges (owner's grant = edge 1). A 130-descendant subtree "
                   "is revoked through the indexed parent_id link; the report shows counts, method "
                   "and elapsed time, and a safety ceiling refuses oversized cascades.",
           "rules": ["5th edge rejected", "index idx_grants_parent_id on grants(parent_id)",
                     "cascade ceiling: error and zero changes when exceeded"]},
    "C4": {"title": "Concurrent delegation and revoke", "run": run_c4,
           "what": "A delegation races with the owner's revoke. First the vulnerable check-then-insert "
                   "pattern is reproduced, then CapShare's serialized transactions are shown in both "
                   "possible orderings using pause hooks (deterministic).",
           "rules": ["BEGIN IMMEDIATE serializes grant creation and revocation",
                     "creator-first: child is created, then cascaded",
                     "revoker-first: child creation rejected (PARENT_REVOKED)"]},
    "C5": {"title": "Temporary capability expiry", "run": run_c5,
           "what": "An owner-controlled logical clock makes expiry deterministic. A grant expiring at "
                   "10 is readable at 9 and denied at 10 and 11; children cannot expire later or be "
                   "permanent.",
           "rules": ["valid while clock < expires_at", "child expiry <= parent expiry",
                     "no permanent child under an expiring parent", "clock never moves backward"]},
}


def describe() -> list[dict]:
    return [{"key": k, "title": v["title"], "what": v["what"], "rules": v["rules"]}
            for k, v in CHALLENGES.items()]


def run_challenge(key: str) -> dict:
    key = key.upper()
    if key not in CHALLENGES:
        raise KeyError(key)
    return CHALLENGES[key]["run"]()
