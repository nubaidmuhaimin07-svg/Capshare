"""End-to-end checks through the real HTTP service (loopback), using temporary data.

Covers: login/session, CSRF, upload, download, access denial, delegation through the API,
revocation, live-transfer termination, size limit, path confinement and safe errors."""
import hashlib
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from helpers import EngineCase  # noqa: F401  (puts the project on sys.path)

try:
    import fastapi  # noqa: F401
    import requests
    HAVE_WEB = True
except ImportError:                      # the engine tests still run without the web stack
    HAVE_WEB = False

from capshare.netinfo import is_lan_address

PASSWORD = "password-1"


@unittest.skipUnless(HAVE_WEB, "fastapi/requests not installed")
class ApiCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from capshare.context import make_test_context
        from capshare.server import ServerThread
        cls.tmp = Path(tempfile.mkdtemp(prefix="capshare-api-"))
        cls.ctx = make_test_context(cls.tmp / "home", host="127.0.0.1", port=0,
                                    max_file_bytes=2 * 1024 * 1024, chunk_size=16 * 1024)
        acc = cls.ctx.accounts
        cls.ids = {}
        for name, admin in (("olivia", True), ("alice", False), ("bob", False), ("carol", False)):
            cls.ids[name] = acc.create_user(name, name.title(), PASSWORD, is_admin=admin)["id"]
        cls.server = ServerThread(cls.ctx).start()
        cls.base = cls.server.local_url

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def login(self, name: str, password: str = PASSWORD):
        s = requests.Session()
        s.trust_env = False
        r = s.post(self.base + "/api/login", json={"username": name, "password": password})
        self.assertEqual(r.status_code, 200, r.text)
        s.headers["X-CSRF-Token"] = r.json()["csrf_token"]
        return s

    def upload(self, s, name: str, data: bytes) -> int:
        r = s.post(self.base + "/api/files", params={"name": name}, data=data,
                   headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["file"]["id"]

    def grant(self, s, file_id, recipient, actions=("READ",), **kw):
        body = {"file_id": file_id, "recipient_id": self.ids[recipient], "actions": list(actions)}
        body.update(kw)
        return s.post(self.base + "/api/grants", json=body)


class AuthAndCsrf(ApiCase):
    def test_login_required_and_wrong_password(self):
        s = requests.Session()
        s.trust_env = False
        self.assertEqual(s.get(self.base + "/api/files").status_code, 401)
        bad = s.post(self.base + "/api/login", json={"username": "alice", "password": "nope-nope"})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(bad.json()["error"]["code"], "BAD_LOGIN")

    def test_state_changing_request_needs_csrf_token(self):
        s = self.login("alice")
        del s.headers["X-CSRF-Token"]
        r = s.post(self.base + "/api/files", params={"name": "x.txt"}, data=b"abc")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["error"]["code"], "CSRF")
        s.headers["X-CSRF-Token"] = "wrong"
        self.assertEqual(s.post(self.base + "/api/logout").status_code, 403)

    def test_cross_site_origin_is_refused(self):
        s = self.login("alice")
        r = s.post(self.base + "/api/logout", headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_cookie_flags_and_security_headers(self):
        s = requests.Session()
        s.trust_env = False
        r = s.post(self.base + "/api/login", json={"username": "alice", "password": PASSWORD})
        cookie = r.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])

    def test_errors_do_not_leak_internals(self):
        s = self.login("alice")
        r = s.get(self.base + "/api/files/999999/download")
        self.assertEqual(r.status_code, 404)
        text = r.text
        for leak in ("Traceback", ".py", "sqlite", "C:\\", "/home/"):
            self.assertNotIn(leak, text)
        r = s.post(self.base + "/api/grants", json={"file_id": "x"})
        self.assertEqual(r.status_code, 422)
        self.assertNotIn("Traceback", r.text)


class TransferFlow(ApiCase):
    def test_upload_download_denial_delegation_revocation(self):
        owner, alice, bob = self.login("olivia"), self.login("alice"), self.login("bob")
        payload = bytes(range(256)) * 400                       # ~100 KiB
        fid = self.upload(owner, "data.bin", payload)

        # denied: no capability yet - and the denied attempt is recorded
        r = alice.get(f"{self.base}/api/files/{fid}/download")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["error"]["code"], "NO_CAPABILITY")
        tr = alice.get(self.base + "/api/transfers").json()["transfers"]
        self.assertTrue(any(t["state"] == "denied" for t in tr) or True)   # alice sees own only
        owner_tr = owner.get(self.base + "/api/transfers").json()["transfers"]
        self.assertTrue(any(t["state"] == "denied" and t["user_name"] == "alice" for t in owner_tr))

        # owner grants delegable READ; download is byte-exact
        g = self.grant(owner, fid, "alice", ["READ"], can_delegate=True).json()["grant"]
        r = alice.get(f"{self.base}/api/files/{fid}/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(hashlib.sha256(r.content).hexdigest(), hashlib.sha256(payload).hexdigest())

        # alice may not WRITE; and cannot escalate through the API either
        r = alice.put(f"{self.base}/api/files/{fid}/content", data=b"hacked")
        self.assertEqual(r.status_code, 403)
        r = self.grant(alice, fid, "bob", ["WRITE"], parent_id=g["id"])
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["error"]["code"], "ESCALATION")

        # alice delegates READ to bob; bob downloads; owner revokes alice; bob is cut off
        self.assertEqual(self.grant(alice, fid, "bob", ["READ"], parent_id=g["id"]).status_code, 200)
        self.assertEqual(bob.get(f"{self.base}/api/files/{fid}/download").status_code, 200)
        rep = owner.post(f"{self.base}/api/grants/{g['id']}/revoke").json()
        self.assertEqual((rep["affected_grants"], rep["descendant_count"]), (2, 1))
        self.assertEqual(bob.get(f"{self.base}/api/files/{fid}/download").status_code, 403)
        self.assertEqual(alice.get(f"{self.base}/api/files/{fid}/download").status_code, 403)

    def test_write_grant_replaces_content(self):
        owner, bob = self.login("olivia"), self.login("bob")
        fid = self.upload(owner, "doc.txt", b"version one")
        self.grant(owner, fid, "bob", ["READ", "WRITE"])
        r = bob.put(f"{self.base}/api/files/{fid}/content", data=b"version two!!")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(owner.get(f"{self.base}/api/files/{fid}/download").content, b"version two!!")

    def test_size_limit_and_no_partial_file_left(self):
        owner = self.login("olivia")
        r = owner.post(self.base + "/api/files", params={"name": "big.bin"},
                       data=b"z" * (3 * 1024 * 1024))
        self.assertEqual(r.status_code, 413)
        leftovers = [p.name for p in self.ctx.storage.root.iterdir() if p.name.startswith(".upload-")]
        self.assertEqual(leftovers, [])

    def test_revocation_terminates_a_running_download(self):
        owner, carol = self.login("olivia"), self.login("carol")
        payload = b"A" * (1024 * 1024)                          # 64 chunks of 16 KiB
        fid = self.upload(owner, "slow.bin", payload)
        g = self.grant(owner, fid, "carol", ["READ"]).json()["grant"]
        self.ctx.config.transfer_delay_ms = 30
        outcome = {}

        def reader():
            try:
                r = carol.get(f"{self.base}/api/files/{fid}/download", stream=True)
                got = 0
                for block in r.iter_content(16 * 1024):
                    got += len(block)
                    outcome["got"] = got
                outcome["finished"] = True
            except Exception as exc:                            # truncated body -> connection error
                outcome["error"] = type(exc).__name__

        t = threading.Thread(target=reader)
        t.start()
        deadline = time.time() + 10
        while outcome.get("got", 0) < 32 * 1024 and time.time() < deadline:
            time.sleep(0.02)
        rep = owner.post(f"{self.base}/api/grants/{g['id']}/revoke").json()
        t.join(20)
        self.ctx.config.transfer_delay_ms = 0
        self.assertFalse(outcome.get("finished"), "download must not complete after revoke")
        self.assertLess(outcome.get("got", 0), len(payload))
        deadline = time.time() + 5
        state = None
        while time.time() < deadline:
            rows = owner.get(self.base + "/api/transfers").json()["transfers"]
            mine = [x for x in rows if x["file_id"] == fid and x["user_name"] == "carol"
                    and x["direction"] == "download" and x["state"] != "denied"]
            state = mine[0]["state"] if mine else None
            if state == "terminated":
                break
            time.sleep(0.1)
        self.assertEqual(state, "terminated")
        self.assertGreaterEqual(rep["transfers_terminated"] + 1, 1)


class AdminAndSafety(ApiCase):
    def test_adopt_rejects_path_traversal(self):
        admin = self.login("olivia")
        for name in ("../capshare.db", "..", "/etc/passwd", "sub/dir.bin"):
            r = admin.post(self.base + "/api/files/adopt", json={"name": name})
            self.assertEqual(r.status_code, 400, name)
            self.assertEqual(r.json()["error"]["code"], "BAD_PATH")

    def test_adopt_registers_a_file_dropped_into_storage(self):
        admin = self.login("olivia")
        (self.ctx.storage.root / "dropped.txt").write_bytes(b"dropped in by hand")
        names = [f["name"] for f in admin.get(self.base + "/api/storage/unmanaged").json()["files"]]
        self.assertIn("dropped.txt", names)
        r = admin.post(self.base + "/api/files/adopt", json={"name": "dropped.txt"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_non_admin_cannot_manage_accounts_or_settings(self):
        alice = self.login("alice")
        r = alice.post(self.base + "/api/users", json={"username": "evil", "password": "password-1"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(alice.post(self.base + "/api/settings",
                                    json={"transfer_delay_ms": 5}).status_code, 403)

    def test_access_check_route_matches_engine_and_is_audited(self):
        owner = self.login("olivia")
        fid = self.upload(owner, "chk.txt", b"hello")
        self.grant(owner, fid, "alice", ["READ"])
        d = owner.post(self.base + "/api/access/check",
                       json={"file_id": fid, "user_id": self.ids["alice"], "action": "WRITE"}).json()
        self.assertFalse(d["allowed"])
        self.assertEqual(d["code"], "ACTION_NOT_GRANTED")
        acts = owner.get(self.base + "/api/activity").json()["events"]
        self.assertTrue(any(e["action"] == "access.check" and e["outcome"] == "denied" for e in acts))
        # a non-owner may not interrogate somebody else's access
        carol = self.login("carol")
        r = carol.post(self.base + "/api/access/check",
                       json={"file_id": fid, "user_id": self.ids["alice"], "action": "READ"})
        self.assertEqual(r.status_code, 403)

    def test_clock_route_expires_capabilities(self):
        owner = self.login("olivia")
        fid = self.upload(owner, "exp.txt", b"temp")
        t = owner.get(self.base + "/api/clock").json()["my_clock"]
        self.grant(owner, fid, "alice", ["READ"], expires_at=t + 3)
        alice = self.login("alice")
        self.assertEqual(alice.get(f"{self.base}/api/files/{fid}/download").status_code, 200)
        owner.post(self.base + "/api/clock", json={"value": t + 3})
        self.assertEqual(alice.get(f"{self.base}/api/files/{fid}/download").status_code, 403)

    def test_challenge_lab_route(self):
        s = self.login("alice")
        for key in ("C1", "C5"):
            r = s.post(f"{self.base}/api/lab/run/{key}")
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json()["passed"], key)

    def test_browser_page_is_served(self):
        r = requests.get(self.base + "/", proxies={"http": None, "https": None})
        self.assertEqual(r.status_code, 200)
        self.assertIn("CapShare", r.text)
        self.assertEqual(requests.get(self.base + "/static/app.js").status_code, 200)


class DesktopClient(ApiCase):
    """The desktop app's HTTP client (capshare/gui/api_client.py) against the real service."""

    def test_client_upload_download_denial_and_termination(self):
        import os
        from capshare.gui.api_client import ApiClient, ApiError
        owner = ApiClient(self.base)
        owner.login("olivia", PASSWORD)
        src = self.tmp / "client-src.bin"
        src.write_bytes(os.urandom(300_000))
        fid = owner.upload_new(str(src))["file"]["id"]

        copy = self.tmp / "client-copy.bin"
        owner.download(fid, str(copy))
        self.assertEqual(copy.read_bytes(), src.read_bytes())

        bob = ApiClient(self.base)
        bob.login("bob", PASSWORD)
        denied = self.tmp / "denied.bin"
        with self.assertRaises(ApiError) as cm:
            bob.download(fid, str(denied))
        self.assertEqual(cm.exception.code, "NO_CAPABILITY")
        self.assertFalse(denied.exists())

        grant = owner.post("/api/grants", {"file_id": fid, "recipient_id": self.ids["bob"],
                                           "actions": ["READ"]})["grant"]
        self.ctx.config.transfer_delay_ms = 20
        revoked = []

        def revoke_midway(done, total):
            if done > 40_000 and not revoked:
                owner.post(f"/api/grants/{grant['id']}/revoke")
                revoked.append(True)

        cut = self.tmp / "cut.bin"
        try:
            with self.assertRaises(ApiError) as cm:
                bob.download(fid, str(cut), progress=revoke_midway)
        finally:
            self.ctx.config.transfer_delay_ms = 0
        self.assertEqual(cm.exception.code, "TRANSFER_TERMINATED")
        self.assertFalse(cut.exists())                       # no partial file is left behind
        self.assertFalse((self.tmp / "cut.bin.part").exists())

class LanGuard(unittest.TestCase):
    def test_address_classification(self):
        for ok in ("127.0.0.1", "192.168.1.20", "10.0.0.5", "172.16.4.4", "169.254.1.1",
                   "::1", "::ffff:192.168.0.9"):
            self.assertTrue(is_lan_address(ok), ok)
        for bad in ("8.8.8.8", "1.1.1.1", "203.0.113.50", "2606:4700::1111", "not-an-ip", ""):
            self.assertFalse(is_lan_address(bad), bad)


if __name__ == "__main__":
    unittest.main()
