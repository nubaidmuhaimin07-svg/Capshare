"""THE PERMISSION ENGINE.

Everything that decides "may this user READ/WRITE this file?" lives here, so the
network service, the GUI, the Challenge Lab and the tests all share ONE implementation.

Vocabulary
----------
capability / grant  one row in `grants`: ONE file, ONE recipient, a set of actions
                    {READ, WRITE}, a delegation flag, an optional logical expiry and
                    an optional parent grant (the grant it was delegated from).
edge                one link of a delegation chain. The owner's own grant is edge 1.
logical clock       an integer the FILE OWNER controls (it only moves forward).
                    A grant with expires_at = T is valid while clock < T.

OS concept -> code
------------------
* Capability / least privilege   -> create_grant(): a delegate can never receive more
                                    than the grant it is derived from (ESCALATION).
* Mutual exclusion               -> create_grant() and revoke_grant() both run inside
                                    Database.write() (BEGIN IMMEDIATE). The parent check
                                    and the child INSERT are one atomic step, so a
                                    concurrent revoke cannot slip in between them (C4).
* Revocation / cascade           -> revoke_grant() walks the lineage with the indexed
                                    parent_id column and revokes every descendant (C1, C3).
* Independent authority paths    -> effective access is the UNION over every grant path;
                                    revoking one path keeps what another path supports (C2).
* Timeouts / leases              -> logical-clock expiry, checked on the grant and on
                                    EVERY ancestor (C5).
"""
from __future__ import annotations

import json
import time
from typing import Callable

from .acl import AclManager, perms_string
from .config import Config
from .db import Database, utc_now
from .errors import (AclError, BadRequest, CascadeLimitExceeded, Forbidden,
                     GrantRejected, NotFound)
from .storage import Storage

ACTIONS = ("READ", "WRITE")

# The order matters: when we try several candidate parents we report the error from the
# candidate that got *furthest* through these checks (most informative for the user).
VALIDATION_STAGES = [
    "NOT_YOUR_GRANT", "PARENT_REVOKED", "PARENT_EXPIRED", "DELEGATION_NOT_PERMITTED",
    "ESCALATION", "DEPTH_LIMIT", "EXPIRY_PERMANENT_UNDER_EXPIRING_PARENT",
    "EXPIRY_OUTLIVES_PARENT",
]


# ----------------------------------------------------------------------------- helpers
def normalize_actions(actions) -> str:
    """Accept 'READ', ['READ','WRITE'], 'read,write' ... -> canonical 'READ,WRITE'."""
    if isinstance(actions, str):
        actions = actions.split(",")
    wanted = {str(a).strip().upper() for a in actions if str(a).strip()}
    if not wanted or not wanted <= set(ACTIONS):
        raise BadRequest("actions must be READ and/or WRITE", code="BAD_ACTIONS")
    return ",".join(a for a in ACTIONS if a in wanted)


def action_set(text: str) -> frozenset[str]:
    return frozenset(text.split(","))


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


class CapabilityEngine:
    def __init__(self, db: Database, config: Config, storage: Storage, acl: AclManager):
        self.db = db
        self.config = config
        self.storage = storage
        self.acl = acl
        # Test/Lab hooks: name -> callable(**context). Used to pause a thread at an exact
        # point inside a transaction so the C4 race can be reproduced deterministically.
        self.hooks: dict[str, Callable[..., None]] = {}

    def _hook(self, name: str, **context) -> None:
        fn = self.hooks.get(name)
        if fn:
            fn(**context)

    # ================================================================== audit trail
    def _audit(self, conn, *, actor_id, action, outcome, file_id=None, grant_id=None,
               detail: dict | None = None) -> None:
        conn.execute(
            "INSERT INTO audit(ts, actor_id, action, file_id, grant_id, outcome, detail) "
            "VALUES (?,?,?,?,?,?,?)",
            (utc_now(), actor_id, action, file_id, grant_id, outcome,
             json.dumps(detail or {}, sort_keys=True)))

    def audit(self, *, actor_id, action, outcome, file_id=None, grant_id=None, detail=None) -> None:
        """Public: write one audit row in its own transaction (used by the API layer)."""
        with self.db.write() as conn:
            self._audit(conn, actor_id=actor_id, action=action, outcome=outcome,
                        file_id=file_id, grant_id=grant_id, detail=detail)

    def _audit_denied(self, actor_id, action, file_id, grant_id, exc: GrantRejected,
                      extra: dict | None = None) -> None:
        """Denied operations roll back, so their audit row is written in a NEW transaction."""
        detail = {"code": exc.code, "reason": exc.message}
        detail.update(extra or {})
        self.audit(actor_id=actor_id, action=action, outcome="denied",
                   file_id=file_id, grant_id=grant_id, detail=detail)

    # ================================================================== small readers
    def _user(self, conn, user_id: int):
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise NotFound("user not found", code="USER_NOT_FOUND")
        return row

    def _file(self, conn, file_id: int):
        row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            raise NotFound("file not found", code="FILE_NOT_FOUND")
        return row

    def _clock(self, conn, owner_id: int) -> int:
        row = conn.execute("SELECT now FROM logical_clocks WHERE owner_id=?", (owner_id,)).fetchone()
        return int(row["now"]) if row else 0

    @staticmethod
    def _lookup(conn, cache: dict | None = None) -> Callable[[int], dict | None]:
        cache = {} if cache is None else cache

        def get(grant_id: int | None):
            if grant_id is None:
                return None
            if grant_id not in cache:
                row = conn.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
                cache[grant_id] = dict(row) if row else None
            return cache[grant_id]
        return get

    # ================================================================== chain status
    @staticmethod
    def _path_status(grant: dict, lookup: Callable[[int | None], dict | None], now: int):
        """Walk from `grant` up to its root and judge the WHOLE path.

        Returns (status, culprit_grant_id, earliest_expiry)
          status  'active' | 'revoked' | 'expired'
          culprit the grant on the path that is revoked/expired (None if active)
          earliest_expiry  the soonest expiry on the path (None = permanent)
        The rule from the spec: access needs the grant AND every ancestor to be
        active and unexpired.
        """
        node, hops, earliest = grant, 0, None
        while node is not None:
            if node["state"] != "active":
                return "revoked", node["id"], earliest
            exp = node["expires_at"]
            if exp is not None:
                earliest = exp if earliest is None else min(earliest, exp)
                if exp <= now:
                    return "expired", node["id"], earliest
            node = lookup(node["parent_id"])
            hops += 1
            if hops > 64:                       # cycles are impossible; this is a seatbelt
                raise RuntimeError("grant lineage is corrupt (cycle)")
        return "active", None, earliest

    # ================================================================== files
    def register_file(self, owner_id: int, display_name: str, stored_name: str,
                      size: int, sha256: str) -> dict:
        with self.db.write() as conn:
            self._user(conn, owner_id)
            now = utc_now()
            cur = conn.execute(
                "INSERT INTO files(name, stored_name, owner_id, size, sha256, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?)", (display_name, stored_name, owner_id, size, sha256, now, now))
            file_id = cur.lastrowid
            self._audit(conn, actor_id=owner_id, action="file.add", outcome="ok", file_id=file_id,
                        detail={"name": display_name, "size": size})
            return dict(self._file(conn, file_id))

    def update_file_content(self, file_id: int, actor_id: int, size: int, sha256: str) -> None:
        with self.db.write() as conn:
            conn.execute("UPDATE files SET size=?, sha256=?, updated_at=? WHERE id=?",
                         (size, sha256, utc_now(), file_id))

    def get_file(self, file_id: int) -> dict:
        with self.db.read() as conn:
            return dict(self._file(conn, file_id))

    # ================================================================== logical clock
    def get_clock(self, owner_id: int) -> int:
        with self.db.read() as conn:
            return self._clock(conn, owner_id)

    def set_clock(self, actor_id: int, owner_id: int, value: int) -> dict:
        """The owner moves their logical clock FORWARD. Grants whose expiry is crossed
        become expired immediately for every ancestor/descendant check (C5)."""
        if actor_id != owner_id:
            exc = GrantRejected("Only the file owner controls the logical clock for their files.",
                                code="NOT_CLOCK_OWNER")
            self._audit_denied(actor_id, "clock.set", None, None, exc, {"requested": value})
            raise exc
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BadRequest("clock value must be a whole number >= 0", code="BAD_CLOCK")
        acl_result: dict = {"enabled": self.acl.enabled, "ops": [], "error": None}
        try:
            with self.db.write() as conn:
                old = self._clock(conn, owner_id)
                if value < old:
                    raise GrantRejected(
                        f"The logical clock only moves forward (now {old}, requested {value}). "
                        "Otherwise an expired capability could be revived.", code="CLOCK_BACKWARDS")
                conn.execute("INSERT INTO logical_clocks(owner_id, now) VALUES (?,?) "
                             "ON CONFLICT(owner_id) DO UPDATE SET now=excluded.now", (owner_id, value))
                newly = conn.execute(
                    "SELECT g.* FROM grants g JOIN files f ON f.id = g.file_id "
                    "WHERE f.owner_id=? AND g.state='active' AND g.expires_at IS NOT NULL "
                    "AND g.expires_at > ? AND g.expires_at <= ?", (owner_id, old, value)).fetchall()
                for g in newly:
                    self._audit(conn, actor_id=owner_id, action="grant.expired", outcome="ok",
                                file_id=g["file_id"], grant_id=g["id"],
                                detail={"expires_at": g["expires_at"], "clock": value})
                self._audit(conn, actor_id=owner_id, action="clock.set", outcome="ok",
                            detail={"old": old, "new": value, "expired_grants": [g["id"] for g in newly]})
                # Expiry changes effective permissions, so the OS-level ACLs must follow.
                for file_id in sorted({g["file_id"] for g in newly}):
                    self._sync_acl_collect(conn, self._file(conn, file_id), acl_result, actor_id)
        except GrantRejected as exc:
            if exc.code == "CLOCK_BACKWARDS":
                self._audit_denied(actor_id, "clock.set", None, None, exc, {"requested": value})
            raise
        return {"old": old, "new": value, "expired_grants": [g["id"] for g in newly],
                "affected_files": sorted({g["file_id"] for g in newly}), "acl": acl_result}

    # ================================================================== effective access
    def _effective(self, conn, file_row) -> dict[int, dict]:
        """Union of every independent active grant path, per recipient.

        {user_id: {"actions": set, "grant_ids": [...], "expiry_by_action": {...}}}
        expiry_by_action: None = permanent through at least one supporting path.
        """
        now = self._clock(conn, file_row["owner_id"])
        by_id = {r["id"]: dict(r) for r in
                 conn.execute("SELECT * FROM grants WHERE file_id=?", (file_row["id"],))}
        result: dict[int, dict] = {}
        for grant in by_id.values():
            status, _, earliest = self._path_status(grant, by_id.get, now)
            if status != "active":
                continue
            entry = result.setdefault(grant["recipient_id"],
                                      {"actions": set(), "grant_ids": [], "expiry_by_action": {}})
            entry["grant_ids"].append(grant["id"])
            for action in action_set(grant["actions"]):
                entry["actions"].add(action)
                if action not in entry["expiry_by_action"]:
                    entry["expiry_by_action"][action] = earliest
                else:
                    prev = entry["expiry_by_action"][action]
                    entry["expiry_by_action"][action] = (
                        None if (prev is None or earliest is None) else max(prev, earliest))
        return result

    def effective_access(self, file_id: int) -> dict[int, dict]:
        with self.db.read() as conn:
            return self._effective(conn, self._file(conn, file_id))

    # ================================================================== access check
    def check_access(self, user_id: int, file_id: int, action: str, *,
                     audit_actor: int | None = None) -> dict:
        """The one decision function. Returns a dict with allowed + a reason.

        Pass `audit_actor` to also write an audit row (used by the Access-check page).
        Transfers re-run this per chunk WITHOUT auditing every chunk.
        """
        action = action.upper()
        if action not in ACTIONS:
            raise BadRequest("action must be READ or WRITE", code="BAD_ACTION")
        with self.db.read() as conn:
            file_row = self._file(conn, file_id)
            decision = self._decide(conn, file_row, user_id, action)
        if audit_actor is not None:
            self.audit(actor_id=audit_actor, action="access.check",
                       outcome="ok" if decision["allowed"] else "denied",
                       file_id=file_id,
                       detail={"user_id": user_id, "action": action, "code": decision["code"],
                               "reason": decision["reason"], "via_grants": decision["via_grants"],
                               "clock": decision["clock"]})
        return decision

    def _decide(self, conn, file_row, user_id: int, action: str) -> dict:
        now = self._clock(conn, file_row["owner_id"])
        base = {"allowed": False, "action": action, "user_id": user_id, "file_id": file_row["id"],
                "clock": now, "via_grants": [], "paths": []}
        if user_id == file_row["owner_id"]:
            return {**base, "allowed": True, "code": "OWNER",
                    "reason": "The user owns this file, so holds every right."}
        lookup = self._lookup(conn)
        grants = [dict(r) for r in conn.execute(
            "SELECT * FROM grants WHERE file_id=? AND recipient_id=? ORDER BY id",
            (file_row["id"], user_id))]
        if not grants:
            return {**base, "code": "NO_CAPABILITY",
                    "reason": "No capability has been granted to this user for this file."}
        paths = []
        for g in grants:
            status, culprit, earliest = self._path_status(g, lookup, now)
            paths.append({"grant_id": g["id"], "actions": sorted(action_set(g["actions"])),
                          "status": status, "culprit": culprit, "expires_at": g["expires_at"],
                          "path_expiry": earliest})
        base["paths"] = paths
        allowing = [p for p in paths if p["status"] == "active" and action in p["actions"]]
        if allowing:
            ids = [p["grant_id"] for p in allowing]
            extra = f" (independent paths: {', '.join('#' + str(i) for i in ids)})" if len(ids) > 1 else ""
            return {**base, "allowed": True, "via_grants": ids, "code": "ALLOWED",
                    "reason": f"{action} allowed by active capability #{ids[0]}{extra}; "
                              f"it and every ancestor are active and unexpired at clock {now}."}
        active_wrong = [p for p in paths if p["status"] == "active"]
        if active_wrong:
            held = sorted({a for p in active_wrong for a in p["actions"]})
            return {**base, "code": "ACTION_NOT_GRANTED",
                    "reason": f"{action} denied: the user's active capabilities only allow "
                              f"{' and '.join(held)}."}
        expired = [p for p in paths if p["status"] == "expired"]
        if expired:
            p = expired[0]
            culprit = lookup(p["culprit"])
            where = "capability" if p["culprit"] == p["grant_id"] else "ancestor capability"
            return {**base, "code": "CAPABILITY_EXPIRED",
                    "reason": f"{action} denied: {where} #{p['culprit']} expired at logical time "
                              f"{culprit['expires_at']} (the owner's clock is {now})."}
        p = paths[0]
        who = "capability" if p["culprit"] == p["grant_id"] else "ancestor capability"
        return {**base, "code": "CAPABILITY_REVOKED",
                "reason": f"{action} denied: {who} #{p['culprit']} has been revoked."}

    # ================================================================== create grant
    def create_grant(self, *, actor_id: int, file_id: int, recipient_id: int, actions,
                     can_delegate: bool = False, expires_at: int | None = None,
                     parent_id: int | None = None) -> dict:
        """Create ONE capability. The owner issues root grants; everybody else delegates
        from a grant they hold. Every rule is enforced here, inside one transaction."""
        acl_result: dict = {"enabled": self.acl.enabled, "ops": [], "error": None}
        acl_touched = False
        try:
            with self.db.write() as conn:        # <- BEGIN IMMEDIATE: serialized with revoke
                file_row = self._file(conn, file_id)
                actor = self._user(conn, actor_id)
                recipient = self._user(conn, recipient_id)
                actions_text = normalize_actions(actions)
                wanted = action_set(actions_text)
                can_delegate = bool(can_delegate)
                now = self._clock(conn, file_row["owner_id"])
                if expires_at is not None:
                    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at < 0:
                        raise BadRequest("expiry must be a logical time (whole number)", code="BAD_EXPIRY")
                    if expires_at <= now:
                        raise GrantRejected(
                            f"Expiry {expires_at} is not in the future (owner's clock is {now}).",
                            code="EXPIRY_IN_PAST")
                if recipient_id == actor_id:
                    raise GrantRejected("You cannot grant a capability to yourself.", code="SELF_GRANT")
                if recipient_id == file_row["owner_id"]:
                    raise GrantRejected("The owner already holds every right on this file.",
                                        code="GRANT_TO_OWNER")

                if actor_id == file_row["owner_id"]:
                    if parent_id is not None:
                        raise GrantRejected("The owner issues root capabilities; no parent applies.",
                                            code="OWNER_HAS_NO_PARENT")
                    parent, depth = None, 1                   # the owner's grant is edge 1
                else:
                    parent = self._choose_parent(conn, actor_id, file_row, parent_id, wanted,
                                                 can_delegate, expires_at, now)
                    depth = parent["depth"] + 1

                # ---- the check is finished; the INSERT follows in the SAME transaction.
                # A concurrent revoke of `parent` cannot run between these two steps.
                self._hook("create_grant.after_parent_check", parent_id=parent["id"] if parent else None)

                cur = conn.execute(
                    "INSERT INTO grants(file_id, recipient_id, grantor_id, actions, can_delegate, "
                    "parent_id, state, created_at, expires_at, depth) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (file_id, recipient_id, actor_id, actions_text, int(can_delegate),
                     parent["id"] if parent else None, "active", utc_now(), expires_at, depth))
                grant_id = cur.lastrowid
                self._audit(conn, actor_id=actor_id, action="grant.create", outcome="ok",
                            file_id=file_id, grant_id=grant_id,
                            detail={"recipient": recipient["username"], "actions": actions_text,
                                    "can_delegate": can_delegate, "expires_at": expires_at,
                                    "parent_id": parent["id"] if parent else None, "depth": depth})
                # OS permissions follow. If setfacl fails we ROLL BACK: the grant is not
                # created and we never claim an OS permission that was not applied.
                acl_touched = True
                acl_result["ops"] = self._sync_acl(conn, file_row)
                grant = dict(conn.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone())
        except GrantRejected as exc:
            self._audit_denied(actor_id, "grant.create", file_id, parent_id, exc,
                               {"recipient_id": recipient_id, "actions": str(actions),
                                "can_delegate": bool(can_delegate), "expires_at": expires_at})
            raise
        except AclError as exc:
            self._repair_acl_after_failure(file_id)
            self.audit(actor_id=actor_id, action="grant.create", outcome="error", file_id=file_id,
                       detail={"code": exc.code, "reason": exc.message, "rolled_back": True})
            raise AclError(f"Grant NOT created - the Linux ACL could not be applied: {exc.message}",
                           code="ACL_ERROR") from exc
        except BaseException:
            if acl_touched:
                self._repair_acl_after_failure(file_id)
            raise
        return {"grant": grant, "acl": acl_result}

    def _choose_parent(self, conn, actor_id, file_row, parent_id, wanted, can_delegate,
                       expires_at, now) -> dict:
        """Pick (or validate) the grant the delegate is derived from."""
        lookup = self._lookup(conn)
        if parent_id is not None:
            parent = lookup(parent_id)
            if not parent or parent["file_id"] != file_row["id"]:
                raise GrantRejected("That parent capability does not exist for this file.",
                                    code="NOT_YOUR_GRANT")
            self._validate_parent(parent, lookup, actor_id, wanted, can_delegate, expires_at, now)
            return parent
        candidates = [dict(r) for r in conn.execute(
            "SELECT * FROM grants WHERE file_id=? AND recipient_id=? ORDER BY id",
            (file_row["id"], actor_id))]
        if not candidates:
            raise GrantRejected("You hold no capability on this file, so you cannot share it.",
                                code="NO_AUTHORITY")
        best_error: GrantRejected | None = None
        for candidate in candidates:
            try:
                self._validate_parent(candidate, lookup, actor_id, wanted, can_delegate, expires_at, now)
                return candidate
            except GrantRejected as exc:
                if (best_error is None or VALIDATION_STAGES.index(exc.code)
                        > VALIDATION_STAGES.index(best_error.code)):
                    best_error = exc
        assert best_error is not None
        raise best_error

    def _validate_parent(self, parent: dict, lookup, actor_id: int, wanted: frozenset,
                         can_delegate: bool, expires_at: int | None, now: int) -> None:
        """Authority validation. Each failure has a distinct, explainable code."""
        pid = parent["id"]
        if parent["recipient_id"] != actor_id:
            raise GrantRejected(f"Capability #{pid} was not issued to you.", code="NOT_YOUR_GRANT")
        status, culprit, earliest = self._path_status(parent, lookup, now)
        if status == "revoked":
            raise GrantRejected(
                f"Capability #{culprit} on the path to #{pid} is revoked; nothing can be delegated from it.",
                code="PARENT_REVOKED")
        if status == "expired":
            raise GrantRejected(
                f"Capability #{culprit} on the path to #{pid} has expired (owner's clock is {now}).",
                code="PARENT_EXPIRED")
        if not parent["can_delegate"]:
            raise GrantRejected(f"Capability #{pid} does not permit delegation.",
                                code="DELEGATION_NOT_PERMITTED")
        held = action_set(parent["actions"])
        if not wanted <= held:
            raise GrantRejected(
                f"Privilege escalation refused: capability #{pid} holds only "
                f"{' and '.join(sorted(held))}; you asked to share {' and '.join(sorted(wanted))}.",
                code="ESCALATION")
        if parent["depth"] + 1 > self.config.max_delegation_edges:
            raise GrantRejected(
                f"Delegation depth limit: at most {self.config.max_delegation_edges} edges "
                f"(the owner's grant is edge 1). Capability #{pid} is already edge {parent['depth']}.",
                code="DEPTH_LIMIT")
        if earliest is not None:          # some ancestor (or the parent) expires
            if expires_at is None:
                raise GrantRejected(
                    f"A child of an expiring capability cannot be permanent "
                    f"(the path expires at logical time {earliest}).",
                    code="EXPIRY_PERMANENT_UNDER_EXPIRING_PARENT")
            if expires_at > earliest:
                raise GrantRejected(
                    f"A child capability cannot outlive its parent: parent path expires at "
                    f"logical time {earliest}, requested {expires_at}.",
                    code="EXPIRY_OUTLIVES_PARENT")

    # ================================================================== revoke + cascade
    def revoke_grant(self, *, actor_id: int, grant_id: int, reason: str = "manual") -> dict:
        """Revoke a grant and, atomically, everything derived from it.

        Allowed for the file owner and for the grantor of that grant.
        Returns a report: affected grant count, descendant count, traversal method, time.
        Revocation stops FUTURE reads/writes. It cannot erase bytes a device already
        downloaded - the report says so explicitly.
        """
        acl_result: dict = {"enabled": self.acl.enabled, "ops": [], "error": None}
        file_id = None
        try:
            with self.db.write() as conn:        # <- serialized with create_grant
                row = conn.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
                if not row:
                    raise NotFound("capability not found", code="GRANT_NOT_FOUND")
                grant = dict(row)
                file_id = grant["file_id"]
                file_row = self._file(conn, file_id)
                if actor_id not in (file_row["owner_id"], grant["grantor_id"]):
                    raise GrantRejected(
                        "Only the file owner or the person who issued this capability can revoke it.",
                        code="NOT_AUTHORIZED_TO_REVOKE")
                self._hook("revoke.after_lock", grant_id=grant_id)

                started = time.perf_counter()
                descendants, stats = self._collect_descendants(conn, grant_id)
                ids_to_revoke = [grant_id] + descendants
                revoked_at = utc_now()
                revoked_ids: list[int] = []
                for chunk in _chunks(ids_to_revoke, 400):
                    marks = ",".join("?" * len(chunk))        # only '?' placeholders are formatted
                    active = [r["id"] for r in conn.execute(
                        f"SELECT id FROM grants WHERE state='active' AND id IN ({marks})", chunk)]
                    for gid in active:
                        why = reason if gid == grant_id else f"cascade from #{grant_id}"
                        conn.execute(
                            "UPDATE grants SET state='revoked', revoked_at=?, revoked_by=?, "
                            "revoke_reason=? WHERE id=? AND state='active'",
                            (revoked_at, actor_id, why, gid))
                        revoked_ids.append(gid)
                elapsed_ms = (time.perf_counter() - started) * 1000.0

                already = grant["state"] != "active"
                report = {
                    "grant_id": grant_id, "file_id": file_id,
                    "already_revoked": already,
                    "affected_grants": len(revoked_ids),
                    "descendant_count": len(descendants),
                    "descendants_revoked": len([g for g in revoked_ids if g != grant_id]),
                    "revoked_ids": revoked_ids,
                    "traversal_method": (
                        "level-by-level breadth-first search over the indexed grants.parent_id "
                        f"column (idx_grants_parent_id): {stats['index_lookups']} index lookups, "
                        f"{stats['levels']} levels"),
                    "traversal_levels": stats["levels"],
                    "index_lookups": stats["index_lookups"],
                    "elapsed_ms": round(elapsed_ms, 3),
                    "cascade_ceiling": self.config.cascade_ceiling,
                    "copy_notice": ("Revocation blocks future access and stops transfers in "
                                    "progress. It cannot erase a copy another device already "
                                    "downloaded."),
                }
                self._audit(conn, actor_id=actor_id, action="grant.revoke",
                            outcome="ok" if revoked_ids else "noop",
                            file_id=file_id, grant_id=grant_id,
                            detail={"affected": len(revoked_ids), "descendants": len(descendants),
                                    "elapsed_ms": report["elapsed_ms"], "reason": reason})
                for gid in revoked_ids:
                    if gid != grant_id:
                        self._audit(conn, actor_id=actor_id, action="grant.cascade_revoke",
                                    outcome="ok", file_id=file_id, grant_id=gid,
                                    detail={"root": grant_id})
                # Re-derive OS permissions from what STILL holds (other paths survive).
                self._sync_acl_collect(conn, file_row, acl_result, actor_id)
                report["acl"] = acl_result
                return report
        except GrantRejected as exc:
            self._audit_denied(actor_id, "grant.revoke", file_id, grant_id, exc)
            raise
        except CascadeLimitExceeded as exc:
            self.audit(actor_id=actor_id, action="grant.revoke", outcome="denied", file_id=file_id,
                       grant_id=grant_id, detail={"code": exc.code, "reason": exc.message})
            raise

    def _collect_descendants(self, conn, root_id: int) -> tuple[list[int], dict]:
        """Breadth-first walk down the lineage using the INDEXED parent_id column.

        Each level is one query `WHERE parent_id IN (...)` which SQLite answers from
        idx_grants_parent_id - no full table scan. Bounded by cascade_ceiling: if the
        subtree is bigger we raise BEFORE changing anything (the caller's transaction
        rolls back, so a revoke is never half-applied).
        """
        ceiling = self.config.cascade_ceiling
        found: list[int] = []
        seen = {root_id}
        frontier = [root_id]
        levels = lookups = 0
        while frontier:
            nxt: list[int] = []
            for chunk in _chunks(frontier, 400):
                marks = ",".join("?" * len(chunk))
                lookups += 1
                for r in conn.execute(f"SELECT id FROM grants WHERE parent_id IN ({marks})", chunk):
                    if r["id"] not in seen:
                        seen.add(r["id"])
                        nxt.append(r["id"])
            if nxt:
                levels += 1
            found.extend(nxt)
            if len(found) > ceiling:
                raise CascadeLimitExceeded(
                    f"Revoking this capability would touch more than {ceiling} derived grants "
                    f"(safety ceiling). Nothing was changed.", code="CASCADE_LIMIT_EXCEEDED",
                    details={"ceiling": ceiling})
            frontier = nxt
        return found, {"levels": levels, "index_lookups": lookups}

    # ================================================================== ACL synchronisation
    def _desired_acl(self, conn, file_row) -> dict[str, str]:
        out: dict[str, str] = {}
        for user_id, info in self._effective(conn, file_row).items():
            user = conn.execute("SELECT linux_user FROM users WHERE id=?", (user_id,)).fetchone()
            if user and user["linux_user"]:
                out[user["linux_user"]] = perms_string(info["actions"])
        return out

    def _sync_acl(self, conn, file_row, force: bool = False, probe: bool = False) -> list[str]:
        if not self.acl.enabled:
            return []
        known = [r["linux_user"] for r in conn.execute(
            "SELECT linux_user FROM users WHERE linux_user IS NOT NULL")]
        return self.acl.apply_file(conn, file_row["id"], self.storage.path_for(file_row["stored_name"]),
                                   self._desired_acl(conn, file_row), force=force, probe=probe,
                                   known_users=known)

    def _sync_acl_collect(self, conn, file_row, result: dict, actor_id: int | None) -> None:
        """Like _sync_acl, but a failure is REPORTED instead of raised (used where the
        database change is authoritative and must not be undone, e.g. revoke)."""
        try:
            result["ops"] = result.get("ops", []) + self._sync_acl(conn, file_row)
        except AclError as exc:
            result["error"] = exc.message
            result["inconsistent"] = True
            result["note"] = ("The database change is committed and the network service already "
                              "denies access, but the Linux ACL on the file could NOT be updated "
                              "and may still grant the mapped Linux user access. "
                              "Use 'Retry ACL sync' after fixing the problem.")
            self._audit(conn, actor_id=actor_id, action="acl.sync", outcome="error",
                        file_id=file_row["id"], detail={"error": exc.message})

    def _repair_acl_after_failure(self, file_id: int) -> None:
        """After a rollback, make the real filesystem match the (rolled back) database."""
        try:
            self.sync_acl(file_id, probe=True)
        except Exception:                      # best effort; the audit row records the error
            pass

    def sync_acl(self, file_id: int, force: bool = False, probe: bool = False,
                 actor_id: int | None = None) -> dict:
        """Recompute and apply the OS ACLs for one file ('Retry ACL sync')."""
        result: dict = {"enabled": self.acl.enabled, "ops": [], "error": None}
        with self.db.write() as conn:
            file_row = self._file(conn, file_id)
            try:
                result["ops"] = self._sync_acl(conn, file_row, force=force, probe=probe)
            except AclError as exc:
                # Entries applied before the failure are still recorded (we commit).
                result["error"] = exc.message
                result["inconsistent"] = True
                self._audit(conn, actor_id=actor_id, action="acl.sync", outcome="error",
                            file_id=file_id, detail={"error": exc.message})
            else:
                self._audit(conn, actor_id=actor_id, action="acl.sync", outcome="ok",
                            file_id=file_id, detail={"ops": result["ops"], "force": force})
        return result

    def sync_all_acls(self, actor_id: int | None = None) -> dict:
        """Used after a Linux-user mapping changes."""
        out = {"files": 0, "ops": [], "errors": []}
        with self.db.read() as conn:
            ids = [r["id"] for r in conn.execute("SELECT id FROM files")]
        for file_id in ids:
            res = self.sync_acl(file_id, probe=True, actor_id=actor_id)
            out["files"] += 1
            out["ops"] += res["ops"]
            if res["error"]:
                out["errors"].append({"file_id": file_id, "error": res["error"]})
        return out

    # ================================================================== views for the UI
    def _status_of(self, grant: dict, lookup, now: int) -> tuple[str, str]:
        status, culprit, _ = self._path_status(grant, lookup, now)
        if status == "active":
            return "active", "valid; it and every ancestor are active and unexpired"
        if culprit == grant["id"]:
            if status == "expired":
                return "expired", f"expired at logical time {grant['expires_at']}"
            return "revoked", grant.get("revoke_reason") or "revoked"
        return status, f"ancestor #{culprit} is {status}"

    def list_grants(self, viewer_id: int, file_id: int | None = None) -> list[dict]:
        """Lineage rows the viewer may see: the file owner sees every grant on the file;
        others see grants they received or issued."""
        with self.db.read() as conn:
            sql = ("SELECT g.*, f.name AS file_name, f.owner_id AS file_owner_id, "
                   "r.username AS recipient_name, r.display_name AS recipient_display, "
                   "gr.username AS grantor_name, rb.username AS revoked_by_name, "
                   "(SELECT COUNT(*) FROM grants c WHERE c.parent_id = g.id) AS child_count "
                   "FROM grants g JOIN files f ON f.id=g.file_id "
                   "JOIN users r ON r.id=g.recipient_id JOIN users gr ON gr.id=g.grantor_id "
                   "LEFT JOIN users rb ON rb.id=g.revoked_by "
                   "WHERE (f.owner_id=? OR g.recipient_id=? OR g.grantor_id=?)")
            params: list = [viewer_id, viewer_id, viewer_id]
            if file_id is not None:
                sql += " AND g.file_id=?"
                params.append(file_id)
            sql += " ORDER BY g.file_id, g.depth, g.id"
            rows = [dict(r) for r in conn.execute(sql, params)]
            lookup = self._lookup(conn)
            clocks: dict[int, int] = {}
            for g in rows:
                owner = g["file_owner_id"]
                if owner not in clocks:
                    clocks[owner] = self._clock(conn, owner)
                g["status"], g["status_reason"] = self._status_of(g, lookup, clocks[owner])
                g["actions"] = sorted(action_set(g["actions"]))
                g["can_delegate"] = bool(g["can_delegate"])
                g["clock"] = clocks[owner]
            return rows

    def delegable_grants(self, user_id: int, file_id: int) -> list[dict]:
        """Grants this user could delegate FROM right now (drives the Share form)."""
        return [g for g in self.list_grants(user_id, file_id)
                if g["recipient_id"] == user_id and g["status"] == "active" and g["can_delegate"]
                and g["depth"] < self.config.max_delegation_edges]

    def list_files(self, viewer_id: int) -> list[dict]:
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT f.*, u.username AS owner_name, u.display_name AS owner_display "
                "FROM files f JOIN users u ON u.id=f.owner_id "
                "WHERE f.owner_id=? OR f.id IN (SELECT file_id FROM grants WHERE recipient_id=? "
                "AND state='active') ORDER BY f.id", (viewer_id, viewer_id)).fetchall()
            out = []
            users = {r["id"]: r for r in conn.execute(
                "SELECT id, username, display_name, linux_user FROM users")}
            for row in rows:
                f = dict(row)
                eff = self._effective(conn, row)
                clock = self._clock(conn, row["owner_id"])
                is_owner = row["owner_id"] == viewer_id
                mine = eff.get(viewer_id)
                f["is_owner"] = is_owner
                f["clock"] = clock
                f["my_actions"] = list(ACTIONS) if is_owner else sorted(mine["actions"]) if mine else []
                f["my_expiry"] = {} if is_owner or not mine else mine["expiry_by_action"]
                actual = self.storage.size_of(row["stored_name"])
                f["size"] = actual if actual is not None else f["size"]
                access = []
                for uid, info in eff.items():
                    if not is_owner and uid != viewer_id:
                        continue                   # recipients only see their own entry
                    access.append({"user_id": uid, "username": users[uid]["username"],
                                   "display_name": users[uid]["display_name"],
                                   "linux_user": users[uid]["linux_user"] if is_owner else None,
                                   "actions": sorted(info["actions"]), "grant_ids": info["grant_ids"],
                                   "expiry_by_action": info["expiry_by_action"]})
                f["access"] = access
                f["grant_count"] = conn.execute(
                    "SELECT COUNT(*) FROM grants WHERE file_id=? AND state='active'",
                    (row["id"],)).fetchone()[0]
                if not is_owner:
                    f.pop("stored_name", None)
                    f.pop("sha256", None)
                out.append(f)
            return out

    def list_users(self, include_linux: bool) -> list[dict]:
        with self.db.read() as conn:
            rows = conn.execute("SELECT id, username, display_name, is_admin, linux_user, "
                                "(password_hash IS NOT NULL) AS can_login FROM users ORDER BY id").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["is_admin"] = bool(d["is_admin"])
                d["can_login"] = bool(d["can_login"])
                if not include_linux:
                    d["linux_user"] = None
                out.append(d)
            return out

    def list_activity(self, viewer_id: int, is_admin: bool, limit: int = 200,
                      after_id: int = 0) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self.db.read() as conn:
            where = "a.id > ?"
            params: list = [after_id]
            if not is_admin:
                where += " AND (a.actor_id=? OR f.owner_id=?)"
                params += [viewer_id, viewer_id]
            rows = conn.execute(
                "SELECT a.*, u.username AS actor_name, f.name AS file_name FROM audit a "
                "LEFT JOIN users u ON u.id=a.actor_id LEFT JOIN files f ON f.id=a.file_id "
                f"WHERE {where} ORDER BY a.id DESC LIMIT ?", params + [limit]).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["detail"] = json.loads(d["detail"] or "{}")
                except ValueError:
                    d["detail"] = {}
                out.append(d)
            return out

    # ================================================================== invariants (C4)
    def find_orphan_children(self) -> list[dict]:
        """Active grants whose parent is NOT active. Must always be empty."""
        with self.db.read() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT c.id AS child_id, c.parent_id, p.state AS parent_state "
                "FROM grants c JOIN grants p ON p.id = c.parent_id "
                "WHERE c.state='active' AND p.state <> 'active'")]
