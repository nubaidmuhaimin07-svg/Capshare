"""HTTP client used by the desktop frontend (and usable as a tiny recipient client).

It keeps the session cookie and CSRF token the backend issued at login, so every
state-changing call carries the X-CSRF-Token header the server requires.
"""
from __future__ import annotations

import os
from typing import Callable

import requests


class ApiError(Exception):
    def __init__(self, message: str, code: str = "", status: int = 0):
        super().__init__(message)
        self.message, self.code, self.status = message, code, status


class _ProgressReader:
    """File-like body with a length, so `requests` sends a Content-Length and we can report progress."""

    def __init__(self, path: str, callback: Callable[[int, int], None] | None):
        self._f = open(path, "rb")
        self._total = os.path.getsize(path)
        self._sent = 0
        self._cb = callback

    def __len__(self) -> int:
        return self._total

    def read(self, n: int = -1) -> bytes:
        block = self._f.read(n if n and n > 0 else 65536)
        self._sent += len(block)
        if self._cb:
            self._cb(self._sent, self._total)
        if not block:
            self._f.close()
        return block


class ApiClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.http = requests.Session()
        self.csrf: str | None = None
        self.user: dict | None = None

    # ------------------------------------------------------------------ core
    def request(self, method: str, path: str, *, json=None, params=None, data=None,
                timeout: float = 30, stream: bool = False, extra_headers: dict | None = None):
        headers = dict(extra_headers or {})
        if method != "GET" and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        try:
            res = self.http.request(method, self.base + path, json=json, params=params, data=data,
                                    headers=headers, timeout=timeout, stream=stream)
        except requests.RequestException as exc:
            raise ApiError(f"Cannot reach the CapShare service at {self.base} "
                           f"({type(exc).__name__}). Is it running and on the same network?") from exc
        if res.status_code >= 400:
            code, msg = "", f"request failed ({res.status_code})"
            try:
                err = res.json()["error"]
                code, msg = err.get("code", ""), err.get("message", msg)
            except (ValueError, KeyError, TypeError):
                pass
            raise ApiError(msg, code, res.status_code)
        return res

    def get(self, path: str, **params):
        return self.request("GET", path, params=params or None).json()

    def post(self, path: str, json=None):
        return self.request("POST", path, json=json if json is not None else {}).json()

    def put(self, path: str, json=None):
        return self.request("PUT", path, json=json if json is not None else {}).json()

    # ------------------------------------------------------------------ session
    def login(self, username: str, password: str) -> dict:
        data = self.post("/api/login", {"username": username, "password": password})
        self.csrf = data["csrf_token"]
        self.user = data["user"]
        return self.user

    def logout(self) -> None:
        try:
            self.post("/api/logout")
        except ApiError:
            pass
        self.csrf = None
        self.user = None

    # ------------------------------------------------------------------ transfers
    def upload_new(self, local_path: str, progress=None) -> dict:
        name = os.path.basename(local_path)
        res = self.request("POST", "/api/files", params={"name": name},
                           data=_ProgressReader(local_path, progress), timeout=3600,
                           extra_headers={"Content-Type": "application/octet-stream"})
        return res.json()

    def replace_content(self, file_id: int, local_path: str, progress=None) -> dict:
        res = self.request("PUT", f"/api/files/{file_id}/content",
                           data=_ProgressReader(local_path, progress), timeout=3600,
                           extra_headers={"Content-Type": "application/octet-stream"})
        return res.json()

    def download(self, file_id: int, dest_path: str, progress=None) -> int:
        res = self.request("GET", f"/api/files/{file_id}/download", stream=True, timeout=3600)
        total = int(res.headers.get("Content-Length", "0"))
        got = 0
        tmp = dest_path + ".part"
        try:
            with open(tmp, "wb") as out:
                for block in res.iter_content(65536):
                    out.write(block)
                    got += len(block)
                    if progress:
                        progress(got, total)
            if total and got != total:
                raise ApiError("Download was cut short - the capability may have been revoked "
                               "or expired during the transfer.", "TRANSFER_TERMINATED")
            os.replace(tmp, dest_path)
        except (requests.RequestException, ApiError) as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            if isinstance(exc, ApiError):
                raise
            raise ApiError("Download interrupted - the capability may have been revoked "
                           "or expired during the transfer.", "TRANSFER_TERMINATED") from exc
        return got
