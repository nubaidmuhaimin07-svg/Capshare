# CapShare architecture

## Diagram

```
 SENDER COMPUTER (normal Linux user, e.g. "olivia")                  RECIPIENT DEVICE (same Wi-Fi)
┌──────────────────────────────────────────────────────────┐        ┌───────────────────────────┐
│  PySide6 desktop app  (capshare/gui)                     │        │ Browser transfer page     │
│    pages: Files · Share · Lineage · Access · Transfers · │        │   (capshare/static)       │
│           Lab · Activity                                 │        │   or `run.sh --client`    │
│        │  HTTP (loopback)                                │        └─────────────┬─────────────┘
│        ▼                                                 │   TCP / HTTP over Wi-Fi (LAN only)
│  ┌────────────────────────────────────────────────────┐  │◄───────────────────────┘
│  │ FastAPI service  capshare/api.py + server.py       │  │
│  │  LAN-only guard · session cookie · CSRF · limits   │  │
│  └───────┬──────────────────────────┬─────────────────┘  │
│          ▼                          ▼                    │
│  ┌────────────────┐        ┌─────────────────────┐       │
│  │ PERMISSION     │        │ TransferRegistry     │       │
│  │ ENGINE         │◄───────│ per-chunk re-check,  │       │
│  │ engine.py      │ enforce│ terminate on revoke  │       │
│  └──┬──────────┬──┘        └─────────────────────┘       │
│     ▼          ▼                                         │
│  SQLite     AclManager ──► setfacl/getfacl ──► Linux kernel ACLs on
│  capshare.db  (acl.py)                         ~/.capshare/storage/<uuid>.bin
└──────────────────────────────────────────────────────────┘
```

* The **desktop frontend never touches the engine or the database** — it is an HTTP client, just
  like a recipient's browser. Frontend and backend are separate packages.
* **Only the engine decides** access. The API, the Lab and the tests all call the same
  `CapabilityEngine`.

## OS concept → code

| OS / systems concept | Where it lives |
|---|---|
| **Capability** (unforgeable token naming object + rights) | a row in `grants`; created only by `CapabilityEngine.create_grant` (`engine.py`) |
| **Least privilege / no privilege escalation** | `_validate_parent` → `ESCALATION`, `DELEGATION_NOT_PERMITTED` (`engine.py`) |
| **Delegation depth bound** | `Config.max_delegation_edges` (=4), `DEPTH_LIMIT`, `grants.depth` |
| **Revocation with cascade** | `revoke_grant` + `_collect_descendants` (BFS over indexed `parent_id`) |
| **Independent authority paths** | `_effective` / `_decide`: union over all grants, each path judged alone |
| **Mutual exclusion / critical section** | `Database.write()` = `BEGIN IMMEDIATE` (`db.py`); used by create + revoke |
| **TOCTOU race** | reproduced in `lab._naive_delegate`, fixed because check+insert share one transaction |
| **Leases / timeouts** | `grants.expires_at` vs `logical_clocks.now`; checked on grant **and every ancestor** |
| **File permission bits / ACL** | `acl.PosixAclBackend` runs `setfacl -m u:NAME:r--` / `-x`; `getfacl` reads back |
| **Directory search permission (x)** | `AclManager._ensure_traversal` / `_release_traversal_if_unused` |
| **Reconcile desired vs actual state** | `AclManager.apply_file(..., probe=True)`; "Retry ACL sync" |
| **Confinement / canonical paths** | `Storage.resolve()` (`storage.py`) |
| **Resource limits** | `max_file_bytes`, `cascade_ceiling`, chunked streaming |
| **Authentication / session / CSRF** | `accounts.py`, `api.require_session_csrf` |
| **Network interface binding** | `server.open_sockets`: loopback + one RFC1918 address, never `0.0.0.0` |
| **Peer address filtering** | `server.GuardMiddleware` + `netinfo.is_lan_address` |
| **In-flight I/O cancellation** | `TransferRegistry.enforce` + per-chunk `check_access` in `api.download` |
| **Schema evolution** | `db.Database.migrate` (versioned, transactional, backed up, never downgrades) |
| **Audit log** | `audit` table; `engine._audit`, `_audit_denied` |

## Data model

```
users(id, username, display_name, password_hash, is_admin, linux_user (UNIQUE when set), created_at)
files(id, name, stored_name UNIQUE, owner_id, size, sha256, created_at, updated_at)
grants(id, file_id, recipient_id, grantor_id, actions, can_delegate, parent_id → grants.id,
       state active|revoked, created_at, revoked_at, revoked_by, revoke_reason,
       expires_at (logical), depth)               INDEX idx_grants_parent_id(parent_id)
logical_clocks(owner_id, now)         sessions(token_hash, user_id, csrf_token, expires_at)
transfers(id, file_id, user_id, direction, state, bytes_total, bytes_done, grant_ids, ...)
acl_entries(path, linux_user, perms, kind file|dir, file_id, prior, applied_at)
audit(id, ts, actor_id, action, file_id, grant_id, outcome ok|denied|error|noop, detail JSON)
```

`PRAGMA user_version` holds the schema version (currently 3). v1 = original tables, v2 = `depth`,
revoke bookkeeping and the indexes, v3 = sessions, clocks, transfers, ACL bookkeeping, Linux mapping.
An old database is copied to `capshare.db.bak-v<N>-<time>` and upgraded step by step.

## Decision rules (all enforced in `engine.py`)

1. **Access** to action *X* by user *U* on file *F*: *U* is the owner, **or** some grant to *U* on *F*
   contains *X* and the grant **and every ancestor** is `active` and `now < expires_at`
   (NULL = never). Computed across *all* grants (independent paths).
2. **Create** (owner): any actions, `expires_at > now`, depth 1.
   **Create** (delegate from parent *P*): *P* is the actor's, path active, `P.can_delegate`,
   `actions ⊆ P.actions`, `P.depth + 1 ≤ 4`, and if the path expires: child must expire, and not
   later than the path's earliest expiry.
3. **Revoke** by the file owner or the grantor: the grant and **all descendants** become `revoked`
   in one transaction; ceiling exceeded → nothing changes.
4. **Clock**: only the file owner moves it, only forward.
5. After every authority change the engine recomputes the **desired OS ACL** per mapped Linux user
   from rule 1 and applies only the difference.

## Concurrency (C4)

```
create_grant:  BEGIN IMMEDIATE ─ read parent ─ validate ─ [hook] ─ INSERT child ─ COMMIT
revoke_grant:  BEGIN IMMEDIATE ─ [hook] ─ BFS descendants ─ UPDATE state ─ COMMIT
```

SQLite allows one writer at a time, so whichever transaction obtains the lock first completes
before the other starts. Either the child commits first (the revoker's BFS then sees it and revokes
it) or the revoke commits first (the creator then reads `state='revoked'` and is rejected).
`engine.hooks` lets tests/Lab pause a thread *inside* the critical section to force each order.

## ACL consistency policy

| Operation | If `setfacl` fails |
|---|---|
| create grant | **roll back** — the grant is not created; the OS is re-probed and repaired; the API returns `ACL_ERROR` |
| revoke / expiry | the DB change is **authoritative and kept** (the service already denies); the response and the audit log say `inconsistent`, and *Retry ACL sync* re-applies. We never report an OS change that was not verified by reading the ACL back |

## HTTP API (all under `/api`, JSON; state-changing calls need `X-CSRF-Token`)

| Route | Purpose |
|---|---|
| `POST /login`, `POST /logout`, `GET /me` | session |
| `GET /users`, `POST /users`, `PUT /users/{id}/linux-user` | accounts, Linux mapping (admin) |
| `GET /files`, `GET /files/{id}`, `POST /files?name=` | list / detail / upload new (raw body) |
| `PUT /files/{id}/content` | replace content (WRITE) |
| `GET /files/{id}/download` | stream (READ), re-checked per chunk |
| `GET /files/{id}/acl`, `POST /files/{id}/acl/resync` | getfacl view / retry (owner) |
| `GET /storage/unmanaged`, `POST /files/adopt` | register a file placed in storage (admin) |
| `GET /grants`, `GET /grants/delegable`, `POST /grants`, `POST /grants/{id}/revoke` | lineage, share, revoke |
| `GET /clock`, `POST /clock` | logical clock |
| `POST /access/check` | the backend decision with reason |
| `GET /transfers`, `GET /activity` | transfers, audit trail |
| `GET /connect`, `GET /connect/qr.svg` | Wi-Fi address, port, QR |
| `GET/POST /settings`, `GET /acl/status` | limits, slow mode, ACL backend status |
| `GET /lab/challenges`, `POST /lab/run/{C1..C5}` | challenge lab |
