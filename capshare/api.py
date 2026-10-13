"""HTTP API: the only door remote devices have into CapShare.

Every route that touches a file goes through the capability engine first - there is no
code path that reads or writes managed file data without a positive access decision.

Which checks are enforced by WHOM
---------------------------------
* CapShare network service (this module + engine.py): login, session, CSRF, the
  capability/lineage/expiry decision, size limit, per-chunk re-check, audit.
* Linux kernel: the file-system permission bits and POSIX ACLs on files in the storage
  directory. They matter for *local* Linux users that an admin mapped to an app account.
  A remote device never gets an OS account; it only receives bytes this service sends.
"""
from __future__ import annotations

import asyncio
import hmac
import io
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import __version__, lab
from .acl import valid_linux_user
from .context import AppContext
from .errors import (AuthRequired, BadRequest, CapShareError, Forbidden, NotFound,
                     TooLarge, TransferTerminated)
from .netinfo import is_lan_address
from .storage import safe_display_name

COOKIE = "capshare_session"
router = APIRouter()
_lab_lock = threading.Lock()


# ================================================================== dependencies
@dataclass
class Session:
    user: dict
    csrf: str

    @property
    def id(self) -> int:
        return self.user["id"]

    @property
    def is_admin(self) -> bool:
        return bool(self.user["is_admin"])


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def require_session(request: Request) -> Session:
    ctx = get_ctx(request)
    found = ctx.accounts.session(request.cookies.get(COOKIE))
    if not found:
        raise AuthRequired("please sign in", code="AUTH_REQUIRED")
    return Session(user=found["user"], csrf=found["csrf"])


def require_session_csrf(request: Request) -> Session:
    """Authenticated AND CSRF-protected. Used by every state-changing route."""
    sess = require_session(request)
    sent = request.headers.get("x-csrf-token", "")
    if not sent or not hmac.compare_digest(sent, sess.csrf):
        raise Forbidden("missing or wrong CSRF token", code="CSRF")
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc != request.headers.get("host", ""):
        raise Forbidden("cross-site request refused", code="CSRF_ORIGIN")
    return sess


def require_admin(sess: Session = Depends(require_session_csrf)) -> Session:
    if not sess.is_admin:
        raise Forbidden("administrator only", code="ADMIN_ONLY")
    return sess


def public_user(user: dict, include_linux: bool = False) -> dict:
    return {"id": user["id"], "username": user["username"], "display_name": user["display_name"],
            "is_admin": bool(user["is_admin"]),
            "linux_user": user.get("linux_user") if include_linux else None}


def remote_of(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ================================================================== request bodies
class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class GrantBody(BaseModel):
    file_id: int
    recipient_id: int
    actions: list[str] = Field(min_length=1, max_length=2)
    can_delegate: bool = False
    expires_at: int | None = None
    parent_id: int | None = None


class RevokeBody(BaseModel):
    reason: str = Field(default="manual", max_length=200)


class ClockBody(BaseModel):
    value: int = Field(ge=0, le=10**9)


class CheckBody(BaseModel):
    file_id: int
    user_id: int
    action: str


class NewUserBody(BaseModel):
    username: str = Field(max_length=32)
    display_name: str = Field(default="", max_length=60)
    password: str = Field(min_length=8, max_length=256)
    linux_user: str | None = Field(default=None, max_length=32)


class LinuxUserBody(BaseModel):
    linux_user: str | None = Field(default=None, max_length=32)


class AdoptBody(BaseModel):
    name: str = Field(max_length=200)


class SettingsBody(BaseModel):
    transfer_delay_ms: int = Field(ge=0, le=2000)


# ================================================================== helpers
def _enforce_transfers(ctx: AppContext, file_id: int | None = None) -> int:
    """Cancel in-flight transfers whose user no longer holds the needed action."""
    def still_allowed(handle) -> bool:
        action = "READ" if handle.direction == "download" else "WRITE"
        return ctx.engine.check_access(handle.user_id, handle.file_id, action)["allowed"]
    if file_id is None:
        return ctx.transfers.enforce_all(still_allowed)
    return ctx.transfers.enforce(file_id, still_allowed)


def _service_account_name() -> str | None:
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, AttributeError):
        return None


def _validate_linux_user(ctx: AppContext, linux_user: str | None) -> str | None:
    if linux_user in (None, ""):
        return None
    if not valid_linux_user(linux_user):
        raise BadRequest("not a valid Linux user name", code="BAD_LINUX_USER")
    if not ctx.acl.enabled:
        raise BadRequest("Linux ACL integration is not active on this machine "
                         "(install the 'acl' package and run on Linux)", code="ACL_DISABLED")
    if not ctx.acl.backend.user_exists(linux_user):
        raise BadRequest("that Linux user does not exist on this machine (or is root)",
                         code="NO_SUCH_LINUX_USER")
    if linux_user == _service_account_name():
        raise BadRequest("that is the account CapShare itself runs as; it already owns the files",
                         code="SERVICE_ACCOUNT")
    return linux_user


# ================================================================== health + auth
@router.get("/api/health")
def health(request: Request):
    return {"app": "CapShare", "version": __version__}


@router.post("/api/login")
def login(body: LoginBody, request: Request, response: Response):
    ctx = get_ctx(request)
    try:
        user, token, csrf = ctx.accounts.login(body.username, body.password)
    except AuthRequired as exc:
        ctx.engine.audit(actor_id=None, action="auth.login", outcome="denied",
                         detail={"username": body.username[:32], "reason": exc.code,
                                 "remote": remote_of(request)})
        raise
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/",
                        max_age=ctx.config.session_hours * 3600)
    ctx.engine.audit(actor_id=user["id"], action="auth.login", outcome="ok",
                     detail={"remote": remote_of(request)})
    return {"user": public_user(user, include_linux=True), "csrf_token": csrf}


@router.post("/api/logout")
def logout(request: Request, response: Response, sess: Session = Depends(require_session_csrf)):
    get_ctx(request).accounts.logout(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/api/me")
def me(request: Request):
    """Who am I? Answers 200 with user=null when signed out (no 401 noise in browsers)."""
    found = get_ctx(request).accounts.session(request.cookies.get(COOKIE))
    if not found:
        return {"user": None, "csrf_token": None}
    return {"user": public_user(found["user"], include_linux=True), "csrf_token": found["csrf"]}


# ================================================================== users
@router.get("/api/users")
def users(request: Request, sess: Session = Depends(require_session)):
    return {"users": get_ctx(request).engine.list_users(include_linux=sess.is_admin)}


@router.post("/api/users")
def create_user(body: NewUserBody, request: Request, sess: Session = Depends(require_admin)):
    ctx = get_ctx(request)
    linux = _validate_linux_user(ctx, body.linux_user)
    created = ctx.accounts.create_user(body.username, body.display_name, body.password,
                                       linux_user=linux)
    ctx.engine.audit(actor_id=sess.id, action="user.create", outcome="ok",
                     detail={"username": created["username"], "linux_user": linux})
    return {"user": created}


@router.put("/api/users/{user_id}/linux-user")
def set_linux_user(user_id: int, body: LinuxUserBody, request: Request,
                   sess: Session = Depends(require_admin)):
    ctx = get_ctx(request)
    if not ctx.accounts.get_user(user_id):
        raise NotFound("user not found", code="USER_NOT_FOUND")
    linux = _validate_linux_user(ctx, body.linux_user)
    try:
        ctx.accounts.set_linux_user(user_id, linux)
    except Exception as exc:                       # UNIQUE index violation
        raise BadRequest("that Linux user is already mapped to another account",
                         code="LINUX_USER_TAKEN") from exc
    ctx.engine.audit(actor_id=sess.id, action="user.map_linux", outcome="ok",
                     detail={"user_id": user_id, "linux_user": linux})
    result = ctx.engine.sync_all_acls(actor_id=sess.id)
    return {"linux_user": linux, "acl": result}


# ================================================================== files
@router.get("/api/files")
def list_files(request: Request, sess: Session = Depends(require_session)):
    return {"files": get_ctx(request).engine.list_files(sess.id)}


@router.get("/api/files/{file_id}")
def file_detail(file_id: int, request: Request, sess: Session = Depends(require_session)):
    for f in get_ctx(request).engine.list_files(sess.id):
        if f["id"] == file_id:
            return {"file": f}
    raise NotFound("file not found", code="FILE_NOT_FOUND")


@router.post("/api/files")
async def upload_new_file(name: str, request: Request,
                          sess: Session = Depends(require_session_csrf)):
    """Upload a NEW file; the uploader becomes its owner. Body = raw bytes."""
    ctx = get_ctx(request)
    limit = ctx.config.max_file_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise TooLarge(f"file is larger than the {limit // (1024 * 1024)} MiB limit")
    display = safe_display_name(name)
    staged = ctx.storage.begin_upload(limit)
    try:
        async for chunk in request.stream():
            staged.write(chunk)
            if ctx.config.transfer_delay_ms:
                await asyncio.sleep(ctx.config.transfer_delay_ms / 1000)
        tmp, size, digest = staged.finish()
    except BaseException:
        staged.abort()
        raise
    stored = ctx.storage.new_stored_name()
    ctx.storage.install_new(tmp, stored)
    row = ctx.engine.register_file(sess.id, display, stored, size, digest)
    handle = ctx.transfers.start(file_id=row["id"], user_id=sess.id, direction="upload", total=size,
                                 grant_ids=[], remote=remote_of(request))
    handle.progress(size)
    handle.finish("completed", "new file")
    return {"file": {"id": row["id"], "name": row["name"], "size": size}}


@router.put("/api/files/{file_id}/content")
async def replace_content(file_id: int, request: Request,
                          sess: Session = Depends(require_session_csrf)):
    """Overwrite an existing file. Requires an active WRITE capability (or ownership)."""
    ctx = get_ctx(request)
    eng = ctx.engine
    remote = remote_of(request)
    decision = await run_in_threadpool(eng.check_access, sess.id, file_id, "WRITE")
    if not decision["allowed"]:
        await run_in_threadpool(ctx.transfers.record_denied, file_id=file_id, user_id=sess.id,
                                direction="upload", reason=decision["reason"], remote=remote)
        await run_in_threadpool(eng.audit, actor_id=sess.id, action="transfer.denied",
                                outcome="denied", file_id=file_id,
                                detail={"direction": "upload", "code": decision["code"],
                                        "reason": decision["reason"]})
        raise Forbidden(decision["reason"], code=decision["code"])
    file_row = eng.get_file(file_id)
    declared = request.headers.get("content-length", "0")
    handle = ctx.transfers.start(file_id=file_id, user_id=sess.id, direction="upload",
                                 total=int(declared) if declared.isdigit() else 0,
                                 grant_ids=decision["via_grants"], remote=remote)
    staged = ctx.storage.begin_upload(ctx.config.max_file_bytes)
    try:
        async for chunk in request.stream():
            size = staged.write(chunk)
            # Re-check authority for EVERY chunk: a revoke mid-upload stops the write.
            again = await run_in_threadpool(eng.check_access, sess.id, file_id, "WRITE")
            if handle.cancelled.is_set() or not again["allowed"]:
                raise TransferTerminated(again["reason"], code="TRANSFER_TERMINATED")
            handle.progress(size)
            if ctx.config.transfer_delay_ms:
                await asyncio.sleep(ctx.config.transfer_delay_ms / 1000)
        tmp, size, digest = staged.finish()
        final = await run_in_threadpool(eng.check_access, sess.id, file_id, "WRITE")
        if not final["allowed"]:                    # last look before the data becomes visible
            raise TransferTerminated(final["reason"], code="TRANSFER_TERMINATED")
        ctx.storage.replace_content(tmp, file_row["stored_name"])
        eng.update_file_content(file_id, sess.id, size, digest)
        acl_result = await run_in_threadpool(eng.sync_acl, file_id, True, False, sess.id)
        handle.progress(size)
        handle.finish("completed", "content replaced")
        await run_in_threadpool(eng.audit, actor_id=sess.id, action="transfer.upload", outcome="ok",
                                file_id=file_id, detail={"bytes": size, "remote": remote})
        return {"file_id": file_id, "size": size, "acl": acl_result}
    except TransferTerminated as exc:
        staged.abort()
        handle.finish("terminated", exc.message)
        await run_in_threadpool(eng.audit, actor_id=sess.id, action="transfer.terminated",
                                outcome="denied", file_id=file_id,
                                detail={"direction": "upload", "reason": exc.message})
        raise
    except CapShareError as exc:
        staged.abort()
        handle.finish("failed", exc.message)
        raise
    except BaseException:
        staged.abort()
        handle.finish("failed", "upload interrupted")
        raise


@router.get("/api/files/{file_id}/download")
def download(file_id: int, request: Request, sess: Session = Depends(require_session)):
    ctx = get_ctx(request)
    eng = ctx.engine
    remote = remote_of(request)
    decision = eng.check_access(sess.id, file_id, "READ")
    if not decision["allowed"]:
        ctx.transfers.record_denied(file_id=file_id, user_id=sess.id, direction="download",
                                    reason=decision["reason"], remote=remote)
        eng.audit(actor_id=sess.id, action="transfer.denied", outcome="denied", file_id=file_id,
                  detail={"direction": "download", "code": decision["code"],
                          "reason": decision["reason"]})
        raise Forbidden(decision["reason"], code=decision["code"])
    file_row = eng.get_file(file_id)
    path = ctx.storage.path_for(file_row["stored_name"])
    try:
        total = path.stat().st_size
    except OSError:
        raise NotFound("the stored file is missing", code="STORAGE_MISSING")
    handle = ctx.transfers.start(file_id=file_id, user_id=sess.id, direction="download",
                                 total=total, grant_ids=decision["via_grants"], remote=remote)
    chunk_size = ctx.config.chunk_size

    def stream():
        sent = 0
        try:
            with open(path, "rb") as handle_fd:
                while True:
                    # Authority is re-evaluated before EVERY chunk (revoke/expiry stops us).
                    now = eng.check_access(sess.id, file_id, "READ")
                    if handle.cancelled.is_set() or not now["allowed"]:
                        raise TransferTerminated(now["reason"], code="TRANSFER_TERMINATED")
                    block = handle_fd.read(chunk_size)
                    if not block:
                        break
                    yield block
                    sent += len(block)
                    handle.progress(sent)
                    if ctx.config.transfer_delay_ms:
                        threading.Event().wait(ctx.config.transfer_delay_ms / 1000)
            handle.finish("completed")
            eng.audit(actor_id=sess.id, action="transfer.download", outcome="ok", file_id=file_id,
                      detail={"bytes": sent, "remote": remote})
        except TransferTerminated as exc:
            handle.finish("terminated", exc.message)
            eng.audit(actor_id=sess.id, action="transfer.terminated", outcome="denied",
                      file_id=file_id, detail={"direction": "download", "bytes_sent": sent,
                                               "reason": exc.message})
            # Returning now leaves the body shorter than Content-Length, so the client
            # sees an incomplete download instead of a "successful" truncated file.
        except GeneratorExit:
            handle.finish("failed", "client disconnected")
            raise
        except Exception:
            handle.finish("failed", "server error")
            raise

    disposition = "attachment; filename*=UTF-8''" + quote(file_row["name"])
    return StreamingResponse(stream(), media_type="application/octet-stream",
                             headers={"Content-Length": str(total),
                                      "Content-Disposition": disposition})


@router.get("/api/files/{file_id}/acl")
def file_acl(file_id: int, request: Request, sess: Session = Depends(require_session)):
    """Owner only: the real getfacl output plus what CapShare believes it applied."""
    ctx = get_ctx(request)
    file_row = ctx.engine.get_file(file_id)
    if file_row["owner_id"] != sess.id:
        raise Forbidden("only the file owner can inspect OS permissions", code="OWNER_ONLY")
    path = ctx.storage.path_for(file_row["stored_name"])
    with ctx.db.read() as conn:
        entries = [dict(r) for r in conn.execute(
            "SELECT path, linux_user, perms, kind, applied_at FROM acl_entries "
            "WHERE file_id=? OR kind='dir' ORDER BY kind DESC, linux_user", (file_id,))]
    for e in entries:
        e["path"] = Path(e["path"]).name if e["kind"] == "file" else e["path"]
    return {"status": ctx.acl.status(), "stored_as": path.name, "getfacl": ctx.acl.describe(path),
            "entries": entries}


@router.post("/api/files/{file_id}/acl/resync")
def resync_acl(file_id: int, request: Request, sess: Session = Depends(require_session_csrf)):
    ctx = get_ctx(request)
    if ctx.engine.get_file(file_id)["owner_id"] != sess.id:
        raise Forbidden("only the file owner can re-apply OS permissions", code="OWNER_ONLY")
    return ctx.engine.sync_acl(file_id, force=True, probe=True, actor_id=sess.id)


@router.get("/api/storage/unmanaged")
def unmanaged(request: Request, sess: Session = Depends(require_session)):
    if not sess.is_admin:
        raise Forbidden("administrator only", code="ADMIN_ONLY")
    ctx = get_ctx(request)
    with ctx.db.read() as conn:
        known = {r["stored_name"] for r in conn.execute("SELECT stored_name FROM files")}
    return {"files": ctx.storage.list_unmanaged(known)}


@router.post("/api/files/adopt")
def adopt(body: AdoptBody, request: Request, sess: Session = Depends(require_admin)):
    """Register a file that was copied straight into the storage directory."""
    ctx = get_ctx(request)
    path = ctx.storage.resolve(body.name)             # canonicalization / confinement
    if path.is_symlink() or not path.is_file():
        raise BadRequest("that is not a regular file inside the CapShare storage directory",
                         code="NOT_A_FILE")
    with ctx.db.read() as conn:
        if conn.execute("SELECT 1 FROM files WHERE stored_name=?", (path.name,)).fetchone():
            raise BadRequest("that file is already managed", code="ALREADY_MANAGED")
    size = path.stat().st_size
    if size > ctx.config.max_file_bytes:
        raise TooLarge("file is larger than the configured limit")
    os.chmod(path, 0o600)
    row = ctx.engine.register_file(sess.id, safe_display_name(path.name), path.name, size,
                                   ctx.storage.sha256_of(path))
    return {"file": {"id": row["id"], "name": row["name"], "size": size}}


# ================================================================== grants / delegation
@router.get("/api/grants")
def grants(request: Request, file_id: int | None = None, sess: Session = Depends(require_session)):
    return {"grants": get_ctx(request).engine.list_grants(sess.id, file_id)}


@router.get("/api/grants/delegable")
def delegable(file_id: int, request: Request, sess: Session = Depends(require_session)):
    return {"grants": get_ctx(request).engine.delegable_grants(sess.id, file_id)}


@router.post("/api/grants")
def create_grant(body: GrantBody, request: Request, sess: Session = Depends(require_session_csrf)):
    ctx = get_ctx(request)
    return ctx.engine.create_grant(actor_id=sess.id, file_id=body.file_id,
                                   recipient_id=body.recipient_id, actions=body.actions,
                                   can_delegate=body.can_delegate, expires_at=body.expires_at,
                                   parent_id=body.parent_id)


@router.post("/api/grants/{grant_id}/revoke")
def revoke(grant_id: int, request: Request, body: RevokeBody | None = None,
           sess: Session = Depends(require_session_csrf)):
    ctx = get_ctx(request)
    report = ctx.engine.revoke_grant(actor_id=sess.id, grant_id=grant_id,
                                     reason=(body.reason if body else "manual"))
    report["transfers_terminated"] = _enforce_transfers(ctx, report["file_id"])
    return report


# ================================================================== clock, access, activity
@router.get("/api/clock")
def clock(request: Request, sess: Session = Depends(require_session)):
    ctx = get_ctx(request)
    owners = {sess.id: sess.user["display_name"]}
    for f in ctx.engine.list_files(sess.id):
        owners[f["owner_id"]] = f["owner_display"]
    return {"my_clock": ctx.engine.get_clock(sess.id),
            "clocks": [{"owner_id": oid, "owner": name, "clock": ctx.engine.get_clock(oid)}
                       for oid, name in owners.items()]}


@router.post("/api/clock")
def set_clock(body: ClockBody, request: Request, sess: Session = Depends(require_session_csrf)):
    ctx = get_ctx(request)
    result = ctx.engine.set_clock(sess.id, sess.id, body.value)
    result["transfers_terminated"] = _enforce_transfers(ctx)
    return result


@router.post("/api/access/check")
def access_check(body: CheckBody, request: Request, sess: Session = Depends(require_session_csrf)):
    """Run the SAME decision function the transfer routes use, for a chosen user."""
    ctx = get_ctx(request)
    file_row = ctx.engine.get_file(body.file_id)
    if body.user_id != sess.id and sess.id != file_row["owner_id"] and not sess.is_admin:
        raise Forbidden("only the file owner can check access for another user", code="OWNER_ONLY")
    decision = ctx.engine.check_access(body.user_id, body.file_id, body.action,
                                       audit_actor=sess.id)
    decision["enforced_by"] = {
        "capability_decision": "CapShare network service (this check)",
        "os_file_permissions": "Linux kernel - applies only to Linux users mapped to app accounts",
    }
    return decision


@router.get("/api/activity")
def activity(request: Request, limit: int = 200, after_id: int = 0,
             sess: Session = Depends(require_session)):
    rows = get_ctx(request).engine.list_activity(sess.id, sess.is_admin, limit, after_id)
    return {"events": rows}


@router.get("/api/transfers")
def transfers(request: Request, sess: Session = Depends(require_session)):
    return {"transfers": get_ctx(request).transfers.list(sess.id, sess.is_admin)}


# ================================================================== connect info
@router.get("/api/connect")
def connect(request: Request, sess: Session = Depends(require_session)):
    ctx = get_ctx(request)
    bound = getattr(request.app.state, "bound", [])
    lan = [h for h, _ in bound if h not in ("127.0.0.1", "::1")]
    port = bound[0][1] if bound else ctx.config.port
    return {"port": port, "lan_addresses": lan,
            "urls": [f"http://{h}:{port}/" for h in lan],
            "local_url": f"http://127.0.0.1:{port}/",
            "lan_only": ctx.config.lan_only,
            "note": "Only devices on the same private network can reach this address."}


@router.get("/api/connect/qr.svg")
def connect_qr(request: Request, sess: Session = Depends(require_session)):
    try:
        import segno
    except ImportError:
        raise CapShareError("QR support not installed (pip install segno)", code="NO_QR")
    info = connect(request, sess)
    if not info["urls"]:
        raise NotFound("no LAN address detected", code="NO_LAN")
    buf = io.BytesIO()
    segno.make(info["urls"][0], error="m").save(buf, kind="svg", scale=6, border=2, dark="#111827")
    return Response(buf.getvalue(), media_type="image/svg+xml")


# ================================================================== settings / ACL status
@router.get("/api/acl/status")
def acl_status(request: Request, sess: Session = Depends(require_session)):
    ctx = get_ctx(request)
    st = ctx.acl.status()
    st["storage_dir"] = str(ctx.config.storage_dir) if sess.is_admin else None
    return st


@router.get("/api/settings")
def get_settings(request: Request, sess: Session = Depends(require_session)):
    ctx = get_ctx(request)
    return {"transfer_delay_ms": ctx.config.transfer_delay_ms,
            "max_file_mb": ctx.config.max_file_bytes // (1024 * 1024),
            "max_delegation_edges": ctx.config.max_delegation_edges,
            "cascade_ceiling": ctx.config.cascade_ceiling}


@router.post("/api/settings")
def set_settings(body: SettingsBody, request: Request, sess: Session = Depends(require_admin)):
    ctx = get_ctx(request)
    ctx.config.transfer_delay_ms = body.transfer_delay_ms
    ctx.set_setting("transfer_delay_ms", str(body.transfer_delay_ms))
    ctx.engine.audit(actor_id=sess.id, action="settings.update", outcome="ok",
                     detail={"transfer_delay_ms": body.transfer_delay_ms})
    return {"transfer_delay_ms": body.transfer_delay_ms}


# ================================================================== challenge lab
@router.get("/api/lab/challenges")
def lab_challenges(sess: Session = Depends(require_session)):
    return {"challenges": lab.describe()}


@router.post("/api/lab/run/{key}")
def lab_run(key: str, request: Request, sess: Session = Depends(require_session_csrf)):
    ctx = get_ctx(request)
    if key.upper() not in lab.CHALLENGES:
        raise NotFound("unknown challenge", code="NO_SUCH_CHALLENGE")
    with _lab_lock:
        result = lab.run_challenge(key)
    ctx.engine.audit(actor_id=sess.id, action="lab.run",
                     outcome="ok" if result["passed"] else "error",
                     detail={"challenge": key.upper(), "title": result["title"],
                             "steps": len(result["steps"]),
                             "failed_steps": [s["n"] for s in result["steps"] if not s["ok"]],
                             "summary": result["summary"]})
    return result
