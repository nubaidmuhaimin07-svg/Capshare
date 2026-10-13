"""Live and historic LAN transfers.

OS concept -> code
------------------
* "Open file description / in-flight I/O"  -> TransferHandle: one per active stream.
* "Signal to a running process"            -> TransferRegistry.enforce(): when authority
  disappears (revoke, expiry) active handles for that file are re-checked and cancelled.
  The streaming loops ALSO re-check authority before every chunk, so even a missed
  signal cannot let a revoked reader keep pulling data.
* The data really flows over a TCP connection (uvicorn -> kernel TCP/IP -> Wi-Fi).
"""
from __future__ import annotations

import threading
import time
from typing import Callable

from .db import Database, utc_now


class TransferHandle:
    def __init__(self, registry: "TransferRegistry", transfer_id: int, file_id: int,
                 user_id: int, direction: str, total: int):
        self.registry = registry
        self.id = transfer_id
        self.file_id = file_id
        self.user_id = user_id
        self.direction = direction
        self.total = total
        self.done = 0
        self.cancelled = threading.Event()
        self.reason = ""
        self._last_write = 0.0
        self._finished = False

    def progress(self, done: int) -> None:
        self.done = done
        now = time.monotonic()
        if now - self._last_write >= 0.25:          # throttle DB writes
            self._last_write = now
            self.registry._write_progress(self.id, done)

    def cancel(self, reason: str) -> None:
        self.reason = reason
        self.cancelled.set()

    def finish(self, state: str, note: str = "") -> None:
        if self._finished:
            return
        self._finished = True
        self.registry._finish(self, state, note)


class TransferRegistry:
    def __init__(self, db: Database):
        self.db = db
        self._lock = threading.Lock()
        self._active: dict[int, TransferHandle] = {}

    def recover_after_restart(self) -> None:
        """Transfers that were 'active' when the previous process died did not finish."""
        with self.db.write() as conn:
            conn.execute("UPDATE transfers SET state='failed', note='service restarted', finished_at=? "
                         "WHERE state='active'", (utc_now(),))

    # ------------------------------------------------------------------ lifecycle
    def start(self, *, file_id: int, user_id: int, direction: str, total: int,
              grant_ids: list[int], remote: str) -> TransferHandle:
        with self.db.write() as conn:
            cur = conn.execute(
                "INSERT INTO transfers(file_id, user_id, direction, state, bytes_total, bytes_done, "
                "grant_ids, remote_addr, started_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (file_id, user_id, direction, "active", total, 0,
                 ",".join(str(g) for g in grant_ids), remote, utc_now()))
            handle = TransferHandle(self, cur.lastrowid, file_id, user_id, direction, total)
        with self._lock:
            self._active[handle.id] = handle
        return handle

    def record_denied(self, *, file_id: int, user_id: int, direction: str, reason: str,
                      remote: str) -> None:
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO transfers(file_id, user_id, direction, state, bytes_total, bytes_done, "
                "remote_addr, note, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (file_id, user_id, direction, "denied", 0, 0, remote, reason[:300],
                 utc_now(), utc_now()))

    def _write_progress(self, transfer_id: int, done: int) -> None:
        with self.db.write() as conn:
            conn.execute("UPDATE transfers SET bytes_done=? WHERE id=? AND state='active'",
                         (done, transfer_id))

    def _finish(self, handle: TransferHandle, state: str, note: str) -> None:
        with self._lock:
            self._active.pop(handle.id, None)
        with self.db.write() as conn:
            conn.execute("UPDATE transfers SET state=?, bytes_done=?, note=?, finished_at=? WHERE id=?",
                         (state, handle.done, note[:300], utc_now(), handle.id))

    # ------------------------------------------------------------------ enforcement
    def enforce(self, file_id: int, still_allowed: Callable[[TransferHandle], bool]) -> int:
        """Cancel active transfers of `file_id` whose user lost the needed right."""
        with self._lock:
            handles = [h for h in self._active.values() if h.file_id == file_id]
        cancelled = 0
        for handle in handles:
            if not still_allowed(handle):
                handle.cancel("capability revoked or expired while the transfer was running")
                cancelled += 1
        return cancelled

    def enforce_all(self, still_allowed: Callable[[TransferHandle], bool]) -> int:
        with self._lock:
            file_ids = {h.file_id for h in self._active.values()}
        return sum(self.enforce(f, still_allowed) for f in file_ids)

    # ------------------------------------------------------------------ views
    def list(self, viewer_id: int, is_admin: bool, limit: int = 100) -> list[dict]:
        with self.db.read() as conn:
            where, params = "", []
            if not is_admin:
                where = "WHERE t.user_id=? OR f.owner_id=?"
                params = [viewer_id, viewer_id]
            rows = conn.execute(
                "SELECT t.*, u.username AS user_name, f.name AS file_name, f.owner_id AS owner_id, "
                "o.username AS owner_name FROM transfers t JOIN users u ON u.id=t.user_id "
                "JOIN files f ON f.id=t.file_id JOIN users o ON o.id=f.owner_id "
                f"{where} ORDER BY t.id DESC LIMIT ?", params + [limit]).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            with self._lock:
                live = self._active.get(d["id"])
            if live and d["state"] == "active":
                d["bytes_done"] = live.done          # fresher than the throttled DB value
            # From the SENDER's point of view: a download by a remote is "outgoing".
            d["perspective"] = "outgoing" if d["direction"] == "download" else "incoming"
            out.append(d)
        return out
