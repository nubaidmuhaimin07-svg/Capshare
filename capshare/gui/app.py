"""Desktop application: login dialog + main window.

Two modes
---------
sender (default)   starts the sharing service inside this app (LAN-only) and signs in to it
client             `--client http://<sender-ip>:8765` : only a window, talks to another
                   computer's CapShare exactly like the browser page does
"""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QApplication, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QMainWindow, QMessageBox, QPushButton, QStackedWidget,
                               QStatusBar, QVBoxLayout, QWidget)

from .api_client import ApiClient, ApiError
from .pages_files import FilesPage, SharePage
from .pages_ops import ActivityPage, LabPage, TransfersPage
from .pages_perm import AccessPage, LineagePage
from .theme import STYLE
from .widgets import label


class LoginDialog(QDialog):
    def __init__(self, api: ApiClient, embedded: bool):
        super().__init__()
        self.api = api
        self.setWindowTitle("CapShare — sign in")
        self.setMinimumWidth(420)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 20)
        lay.setSpacing(12)
        lay.addWidget(label("CapShare", "h1"))
        where = ("Sharing service started on this computer." if embedded
                 else f"Connecting to {api.base}")
        lay.addWidget(label(where, "muted", wrap=True))
        form = QFormLayout()
        self.user = QLineEdit("olivia" if embedded else "")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        form.addRow("Username", self.user)
        form.addRow("Password", self.password)
        lay.addLayout(form)
        self.error = QLabel("")
        self.error.setStyleSheet("color:#c62828;")
        self.error.setWordWrap(True)
        lay.addWidget(self.error)
        lay.addWidget(label("Demo accounts: olivia (owner/admin), alice, bob, carol, dave — "
                            "password: capshare-demo", "muted", wrap=True))
        self.btn = QPushButton("Sign in")
        self.btn.setObjectName("primary")
        self.btn.setDefault(True)
        self.btn.clicked.connect(self.attempt)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(self.btn)
        lay.addLayout(row)
        (self.password if embedded else self.user).setFocus()

    def attempt(self) -> None:
        try:
            self.api.login(self.user.text().strip(), self.password.text())
        except ApiError as e:
            self.error.setText(e.message)
            return
        self.accept()


class MainWindow(QMainWindow):
    NAV = [("Files", FilesPage), ("Share", SharePage), ("Permission lineage", LineagePage),
           ("Access check", AccessPage), ("Transfers", TransfersPage),
           ("Challenge Lab", LabPage), ("Activity", ActivityPage)]

    def __init__(self, api: ApiClient, server=None):
        super().__init__()
        self.api, self.server = api, server
        self.user = api.user
        self.users: list[dict] = []
        self.files: list[dict] = []
        self.setWindowTitle("CapShare — revocable file sharing over Wi-Fi")
        self.resize(1280, 800)

        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(220)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(10, 14, 10, 12)
        sl.addWidget(label("◆ CapShare", "brand"))
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        sl.addWidget(self.nav, 1)
        sl.addWidget(label(f"Signed in as\n{self.user['display_name']}", "muted"))
        btn_out = QPushButton("Sign out")
        btn_out.clicked.connect(self.sign_out)
        sl.addWidget(btn_out)
        h.addWidget(side)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        self.header = QLabel("")
        self.header.setStyleSheet("background:#ffffff;border-bottom:1px solid #e1e6ef;padding:8px 24px;color:#5b6678;")
        rl.addWidget(self.header)
        self.stack = QStackedWidget()
        rl.addWidget(self.stack, 1)
        h.addWidget(right, 1)
        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.set_connect_label(None)

        self.pages = []
        for title, cls in self.NAV:
            page = cls(self)
            self.pages.append(page)
            self.stack.addWidget(page)
            self.nav.addItem(title)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.currentRowChanged.connect(lambda i: self.pages[i].refresh())
        self.nav.setCurrentRow(0)

        self.reload_shared()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(2000)

    # ---------------------------------------------------------------- shared state
    @property
    def is_admin(self) -> bool:
        return bool(self.user.get("is_admin"))

    def reload_shared(self) -> None:
        try:
            self.users = self.api.get("/api/users")["users"]
            self.files = self.api.get("/api/files")["files"]
        except ApiError as e:
            if e.status == 401:
                self.timer.stop()
                QMessageBox.information(self, "Signed out", "Your session ended. Please sign in again.")
                self.close()
                return
            self.status(e.message, 6000)
            return
        for page in self.pages:
            page.on_shared()

    def tick(self) -> None:
        page = self.pages[self.stack.currentIndex()]
        if page.auto_refresh and not isinstance(page, FilesPage):
            page.refresh()
        elif isinstance(page, FilesPage):
            self.reload_shared()

    def status(self, message: str, ms: int = 0) -> None:
        self.statusBar().showMessage(message, ms)

    def acl_note(self) -> str:
        """One honest line about the Linux ACL feature on THIS machine."""
        try:
            st = self.api.get("/api/acl/status")
        except ApiError:
            return ""
        if st.get("real_os_acl"):
            return "Linux ACLs: active (real setfacl)"
        if sys.platform.startswith("win"):
            return "Linux ACLs: not available on Windows (permissions are enforced by the CapShare service)"
        return "Linux ACLs: off (" + st.get("detail", "") + ")"

    def set_connect_label(self, url: str | None) -> None:
        mode = "Sharing service at" if self.server else "Connected to"
        if not hasattr(self, "_acl_note"):
            self._acl_note = self.acl_note()
        extra = f"   ·   {self._acl_note}" if self._acl_note else ""
        self.header.setText(f"{mode}  {url or self.api.base}   ·   LAN only{extra}")

    def sign_out(self) -> None:
        self.timer.stop()
        self.api.logout()
        self.close()


def main(client_url: str | None = None, port: int | None = None, host: str | None = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    server = None
    if client_url:
        base = client_url
    else:
        from ..config import Config
        from ..context import AppContext
        from ..seed import seed_demo
        from ..server import ServerThread
        cfg = Config.from_env()
        if port:
            cfg.port = port
        if host:
            cfg.host = host
        ctx = AppContext(cfg)
        seed_demo(ctx)
        server = ServerThread(ctx).start()
        base = server.local_url
        print("CapShare service:", server.local_url, " LAN:", ", ".join(server.lan_urls) or "(none)")
    api = ApiClient(base)
    try:
        if LoginDialog(api, embedded=server is not None).exec() != QDialog.Accepted:
            return 0
        win = MainWindow(api, server)
        win.show()
        return app.exec()
    finally:
        if server:
            server.stop()
