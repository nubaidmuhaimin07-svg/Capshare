"""FastAPI application factory and the LAN-only server runner.

OS concept -> code
------------------
* "Bind to an interface"  -> run_server() opens listening TCP sockets ONLY on loopback and on
  this machine's private (RFC1918) address. It never binds 0.0.0.0, so the service is not
  reachable through a public interface even if the machine has one.
* "Peer address filter"   -> GuardMiddleware refuses any client IP that is not private,
  loopback or link-local (defence in depth if the firewall is misconfigured).
"""
from __future__ import annotations

import logging
import socket
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders

from . import api
from .context import AppContext
from .errors import CapShareError
from .netinfo import is_lan_address, private_ipv4_addresses

log = logging.getLogger("capshare")
STATIC_DIR = Path(__file__).parent / "static"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; "
                                "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"),
}


class GuardMiddleware:
    """Pure ASGI middleware: LAN-only filter + security headers (streaming safe)."""

    def __init__(self, app, lan_only: bool):
        self.app = app
        self.lan_only = lan_only

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client = (scope.get("client") or ("", 0))[0]
        if self.lan_only and not is_lan_address(client):
            response = JSONResponse({"error": {"code": "LAN_ONLY",
                                               "message": "CapShare only serves the local network."}},
                                    status_code=403)
            await response(scope, receive, send)
            return
        is_api = scope["path"].startswith("/api/")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in SECURITY_HEADERS.items():
                    headers[key] = value
                if is_api:
                    headers["Cache-Control"] = "no-store"
                elif "cache-control" not in headers:
                    headers["Cache-Control"] = "no-cache"      # revalidate (ETag) so updates show
            await send(message)

        await self.app(scope, receive, send_with_headers)


_SHORT_BODY = "Too little data for declared Content-Length"


def _is_terminated_transfer(exc: BaseException | None) -> bool:
    """When a transfer is terminated on purpose (revoke/expiry) the response body ends
    shorter than its Content-Length - exactly how the client learns the file is
    incomplete. The HTTP stack reports that as an error; it is expected, so we recognise
    it (also inside exception groups) and keep it out of the logs."""
    while exc is not None:
        if _SHORT_BODY in str(exc):
            return True
        for sub in getattr(exc, "exceptions", ()):
            if _is_terminated_transfer(sub):
                return True
        exc = exc.__cause__ or exc.__context__
    return False


class _QuietTerminatedTransfers(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not (record.exc_info and _is_terminated_transfer(record.exc_info[1]))


logging.getLogger("uvicorn.error").addFilter(_QuietTerminatedTransfers())


def create_app(ctx: AppContext) -> FastAPI:
    app = FastAPI(title="CapShare", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.ctx = ctx
    app.state.bound = [(ctx.config.host or "127.0.0.1", ctx.config.port)]
    try:
        ctx.config.transfer_delay_ms = int(ctx.get_setting("transfer_delay_ms", "0"))
    except ValueError:
        ctx.config.transfer_delay_ms = 0
    app.add_middleware(GuardMiddleware, lan_only=ctx.config.lan_only)

    @app.exception_handler(CapShareError)
    async def known_error(request: Request, exc: CapShareError):
        return JSONResponse({"error": {"code": exc.code, "message": exc.message,
                                       "details": exc.details}}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def bad_input(request: Request, exc: RequestValidationError):
        fields = sorted({str(e["loc"][-1]) for e in exc.errors() if e.get("loc")})
        return JSONResponse({"error": {"code": "BAD_REQUEST",
                                       "message": "invalid request: check " + ", ".join(fields)}},
                            status_code=422)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        if _is_terminated_transfer(exc):                # deliberate abort, not a bug
            return JSONResponse({"error": {"code": "TRANSFER_TERMINATED"}}, status_code=500)
        ref = uuid.uuid4().hex[:8]
        log.exception("unhandled error ref=%s path=%s", ref, request.url.path)   # details stay in the log
        return JSONResponse({"error": {"code": "INTERNAL",
                                       "message": f"internal error (ref {ref})"}}, status_code=500)

    app.include_router(api.router)

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


# ====================================================================================
# Runner
# ====================================================================================
def open_sockets(config) -> tuple[list[socket.socket], list[tuple[str, int]]]:
    """Open listening sockets on loopback + the chosen private LAN address.

    If the preferred port is busy we try the next 10, so a second demo instance still starts.
    """
    hosts = ["127.0.0.1"]
    if config.host:
        if not is_lan_address(config.host):
            raise SystemExit(f"CAPSHARE_HOST={config.host} is not a private/loopback address; "
                             "CapShare refuses to bind to a public interface.")
        if config.host not in hosts:
            hosts.append(config.host)
    else:
        for addr in private_ipv4_addresses()[:4]:      # every private address, never 0.0.0.0
            hosts.append(addr)
    last_error = None
    for port in range(config.port, config.port + 11):
        socks: list[socket.socket] = []
        try:
            actual_port = port
            for host in hosts:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, actual_port))
                s.listen(100)
                actual_port = s.getsockname()[1]      # port 0 -> every socket shares the first one
                socks.append(s)
            return socks, [(h, actual_port) for h in hosts]
        except OSError as exc:
            last_error = exc
            for s in socks:
                s.close()
    raise SystemExit(f"could not open a listening port near {config.port}: {last_error}")


class ServerThread:
    """Runs uvicorn on LAN-only sockets in a background thread (used by the desktop app,
    the CLI and the tests)."""

    def __init__(self, ctx: AppContext):
        import uvicorn
        self.ctx = ctx
        self.app = create_app(ctx)
        self.sockets, self.bound = open_sockets(ctx.config)
        self.app.state.bound = self.bound
        self.port = self.bound[0][1]
        cfg = uvicorn.Config(self.app, log_level="warning", access_log=False)
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(target=self._run, name="capshare-server", daemon=True)

    def _run(self) -> None:
        self.server.run(sockets=self.sockets)

    def start(self, timeout: float = 15.0) -> "ServerThread":
        self.thread.start()
        deadline = time.time() + timeout
        while not self.server.started and time.time() < deadline:
            time.sleep(0.05)
        if not self.server.started:
            raise RuntimeError("the sharing service did not start")
        return self

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(5)
        for s in self.sockets:
            try:
                s.close()
            except OSError:
                pass

    @property
    def local_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def lan_urls(self) -> list[str]:
        return [f"http://{h}:{self.port}" for h, _ in self.bound if h != "127.0.0.1"]
