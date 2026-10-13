"""Files page and Share page."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGridLayout, QHBoxLayout,
                               QInputDialog, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox,
                               QSplitter, QVBoxLayout, QWidget)

from .api_client import ApiError
from .widgets import (card, error_box, fmt_expiry, fmt_size, fmt_ts, hbox, label, make_table,
                      page_header, run_async, selected_data, set_row)


class Page(QWidget):
    """Base class: every page knows the main window (shared state + API client)."""
    auto_refresh = False

    def __init__(self, win):
        super().__init__()
        self.setObjectName("page")
        self.win = win
        self.api = win.api

    def refresh(self) -> None: ...
    def on_shared(self) -> None: ...


def expiry_summary(expiry_by_action: dict) -> str:
    if not expiry_by_action:
        return ""
    return ", ".join(f"{a}: {fmt_expiry(t)}" for a, t in sorted(expiry_by_action.items()))


# =====================================================================================
class FilesPage(Page):
    auto_refresh = True

    def __init__(self, win):
        super().__init__(win)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(12)
        outer.addWidget(page_header(
            "Files", "Files stored in the CapShare directory, who owns them and who can reach them. "
                     "Add a file, then use Share to create a capability for another person."))

        self.btn_add = QPushButton("Add file…")
        self.btn_add.setObjectName("primary")
        self.btn_add.clicked.connect(self.add_file)
        self.btn_download = QPushButton("Download…")
        self.btn_download.clicked.connect(self.download_selected)
        self.btn_replace = QPushButton("Upload new version…")
        self.btn_replace.clicked.connect(self.replace_selected)
        self.btn_adopt = QPushButton("Adopt from storage…")
        self.btn_adopt.clicked.connect(self.adopt)
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.win.reload_shared)
        outer.addWidget(hbox(self.btn_add, self.btn_download, self.btn_replace, self.btn_adopt,
                             None, self.btn_refresh))

        self.table = make_table(["Name", "Owner", "Size", "My access", "Expiry", "Who has access",
                                 "Owner clock", "Updated"], stretch_col=5)
        self.table.itemSelectionChanged.connect(self.on_select)
        outer.addWidget(self.table, 3)

        box, lay = card("Selected file")
        self.detail_title = label("Select a file above.", "muted")
        lay.addWidget(self.detail_title)
        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(label("Effective access (all independent grant paths)", "muted"))
        self.access_table = make_table(["User", "Actions", "Via capabilities", "Expiry", "Linux user"],
                                       stretch_col=2)
        ll.addWidget(self.access_table)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(label("Operating-system permissions (getfacl)", "muted"))
        row.addStretch(1)
        self.btn_acl = QPushButton("Show getfacl")
        self.btn_acl.clicked.connect(self.show_acl)
        self.btn_resync = QPushButton("Retry ACL sync")
        self.btn_resync.clicked.connect(self.resync_acl)
        row.addWidget(self.btn_acl)
        row.addWidget(self.btn_resync)
        rl.addLayout(row)
        self.acl_text = QPlainTextEdit()
        self.acl_text.setReadOnly(True)
        self.acl_text.setPlaceholderText("Owner only. Shows the real `getfacl` output for the stored file.")
        rl.addWidget(self.acl_text)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([620, 480])
        lay.addWidget(split, 1)
        outer.addWidget(box, 2)
        self._files: list[dict] = []
        self.on_shared()

    # ------------------------------------------------------------ data
    def on_shared(self) -> None:
        self._files = self.win.files
        keep = self.current_id()
        t = self.table
        t.setRowCount(len(self._files))
        for row, f in enumerate(self._files):
            who = ", ".join(f"{a['username']} ({'+'.join(x[0] for x in a['actions'])})"
                            for a in f["access"]) or "only the owner"
            mine = ", ".join(f["my_actions"]) or "—"
            set_row(t, row, [f["name"], f["owner_display"], fmt_size(f["size"]), mine,
                             expiry_summary(f.get("my_expiry", {})) or ("owner" if f["is_owner"] else ""),
                             who, f"t={f['clock']}", fmt_ts(f.get("updated_at"))], data=f["id"])
        if keep is not None:
            for row, f in enumerate(self._files):
                if f["id"] == keep:
                    t.selectRow(row)
        has = self.selected_file() is not None
        self.btn_download.setEnabled(has)
        self.btn_adopt.setVisible(bool(self.win.is_admin))
        self.on_select()

    def refresh(self) -> None:
        self.win.reload_shared()

    def current_id(self):
        return selected_data(self.table)

    def selected_file(self) -> dict | None:
        fid = self.current_id()
        return next((f for f in self._files if f["id"] == fid), None)

    def on_select(self) -> None:
        f = self.selected_file()
        self.btn_download.setEnabled(bool(f and "READ" in f["my_actions"]))
        self.btn_replace.setEnabled(bool(f and "WRITE" in f["my_actions"]))
        self.btn_acl.setEnabled(bool(f and f["is_owner"]))
        self.btn_resync.setEnabled(bool(f and f["is_owner"]))
        t = self.access_table
        if not f:
            self.detail_title.setText("Select a file above.")
            t.setRowCount(0)
            return
        self.detail_title.setText(
            f"{f['name']} — owner {f['owner_display']}, {fmt_size(f['size'])}, "
            f"{f['grant_count']} active capability row(s)")
        t.setRowCount(len(f["access"]))
        for row, a in enumerate(f["access"]):
            set_row(t, row, [a["display_name"], " + ".join(a["actions"]),
                             ", ".join(f"#{i}" for i in a["grant_ids"]),
                             expiry_summary(a["expiry_by_action"]), a.get("linux_user") or ""])

    # ------------------------------------------------------------ actions
    def add_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to store in CapShare")
        if not path:
            return
        self.win.status(f"Uploading {os.path.basename(path)} …")
        run_async(lambda progress: self.api.upload_new(path, progress),
                  lambda r: (self.win.status(f"Added {r['file']['name']}", 4000), self.win.reload_shared()),
                  lambda e: error_box(self, "Could not add the file", e),
                  on_progress=lambda a, b: self.win.status(f"Uploading… {fmt_size(a)} / {fmt_size(b)}"))

    def download_selected(self) -> None:
        f = self.selected_file()
        if not f:
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Save a copy as", f["name"])
        if not dest:
            return
        self.win.status(f"Downloading {f['name']} …")

        def ok(n):
            self.win.status(f"Saved {fmt_size(n)} to {dest}", 6000)
            self.win.reload_shared()

        def fail(e):
            self.win.status("Download failed", 4000)
            error_box(self, "Download failed", e)
            self.win.reload_shared()
        run_async(lambda progress: self.api.download(f["id"], dest, progress), ok, fail,
                  on_progress=lambda a, b: self.win.status(f"Downloading… {fmt_size(a)} / {fmt_size(b)}"))

    def replace_selected(self) -> None:
        f = self.selected_file()
        if not f:
            return
        path, _ = QFileDialog.getOpenFileName(self, f"New content for {f['name']}")
        if not path:
            return
        run_async(lambda progress: self.api.replace_content(f["id"], path, progress),
                  lambda r: (self.win.status("Content replaced", 4000), self.win.reload_shared()),
                  lambda e: (error_box(self, "Upload refused", e), self.win.reload_shared()),
                  on_progress=lambda a, b: self.win.status(f"Uploading… {fmt_size(a)} / {fmt_size(b)}"))

    def adopt(self) -> None:
        try:
            names = [x["name"] for x in self.api.get("/api/storage/unmanaged")["files"]]
        except ApiError as e:
            return error_box(self, "Cannot list storage", e)
        if not names:
            self.win.status("No unmanaged files in the CapShare storage directory.", 5000)
            return
        name, ok = QInputDialog.getItem(self, "Adopt a file", "Files found in the storage directory:",
                                        names, 0, False)
        if ok:
            try:
                self.api.post("/api/files/adopt", {"name": name})
                self.win.reload_shared()
            except ApiError as e:
                error_box(self, "Could not adopt the file", e)

    def show_acl(self) -> None:
        fid = self.current_id()
        if fid is None:
            return
        try:
            d = self.api.get(f"/api/files/{fid}/acl")
        except ApiError as e:
            return error_box(self, "ACL", e)
        text = [f"# ACL backend: {d['status']['backend']} - {d['status']['detail']}",
                f"# stored as: {d['stored_as']}", "", d["getfacl"].rstrip(), "",
                "# CapShare bookkeeping (entries it applied):"]
        text += [f"  {e['kind']:<4} {e['linux_user']:<16} {e['perms']}  {e['path']}" for e in d["entries"]] \
            or ["  (none)"]
        self.acl_text.setPlainText("\n".join(text))

    def resync_acl(self) -> None:
        fid = self.current_id()
        if fid is None:
            return
        try:
            res = self.api.post(f"/api/files/{fid}/acl/resync")
        except ApiError as e:
            return error_box(self, "ACL sync", e)
        msg = res.get("error") or ("ACL integration disabled" if not res.get("enabled")
                                   else f"ACL in sync ({len(res.get('ops', []))} change(s))")
        self.win.status(msg, 6000)
        self.show_acl()


# =====================================================================================
class SharePage(Page):
    def __init__(self, win):
        super().__init__(win)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(12)
        outer.addWidget(page_header(
            "Share", "Create ONE capability: one file, one recipient, chosen actions. "
                     "Delegate only what you hold - the backend refuses escalation and records the attempt."))

        box, lay = card("New capability")
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)
        self.file_combo = QComboBox()
        self.file_combo.currentIndexChanged.connect(self.load_sources)
        self.source_combo = QComboBox()
        self.recipient_combo = QComboBox()
        self.cb_read = QCheckBox("READ")
        self.cb_read.setChecked(True)
        self.cb_write = QCheckBox("WRITE")
        self.cb_delegate = QCheckBox("Allow the recipient to delegate further")
        self.cb_expiry = QCheckBox("Expires at logical time")
        self.sp_expiry = QSpinBox()
        self.sp_expiry.setRange(1, 1_000_000)
        self.sp_expiry.setValue(10)
        self.sp_expiry.setEnabled(False)
        self.cb_expiry.toggled.connect(self.sp_expiry.setEnabled)
        grid.addWidget(label("File"), 0, 0)
        grid.addWidget(self.file_combo, 0, 1, 1, 3)
        grid.addWidget(label("Authority"), 1, 0)
        grid.addWidget(self.source_combo, 1, 1, 1, 3)
        grid.addWidget(label("Recipient"), 2, 0)
        grid.addWidget(self.recipient_combo, 2, 1, 1, 3)
        grid.addWidget(label("Actions"), 3, 0)
        grid.addWidget(hbox(self.cb_read, self.cb_write, None), 3, 1, 1, 3)
        grid.addWidget(self.cb_delegate, 4, 1, 1, 3)
        grid.addWidget(self.cb_expiry, 5, 1)
        grid.addWidget(self.sp_expiry, 5, 2)
        lay.addLayout(grid)
        self.btn_create = QPushButton("Create capability")
        self.btn_create.setObjectName("primary")
        self.btn_create.clicked.connect(self.create)
        lay.addWidget(hbox(self.btn_create, None))
        self.result = label("", "", wrap=True)
        lay.addWidget(self.result)
        outer.addWidget(box)

        self.people_box, pl = card("People (administrator)")
        pl.addWidget(label("Accounts are CapShare accounts, NOT Linux users. Only an account you map to an "
                           "existing local Linux user also receives POSIX ACL entries.", "muted", wrap=True))
        self.people = make_table(["Account", "Name", "Role", "Linux user"], stretch_col=1)
        pl.addWidget(self.people)
        self.new_user = QLineEdit()
        self.new_user.setPlaceholderText("new username")
        self.new_pw = QLineEdit()
        self.new_pw.setPlaceholderText("password (8+)")
        self.new_pw.setEchoMode(QLineEdit.Password)
        btn_add = QPushButton("Create account")
        btn_add.clicked.connect(self.create_account)
        btn_map = QPushButton("Map selected to Linux user…")
        btn_map.clicked.connect(self.map_linux)
        pl.addWidget(hbox(self.new_user, self.new_pw, btn_add, None, btn_map))
        outer.addWidget(self.people_box, 1)
        self.on_shared()

    def on_shared(self) -> None:
        keep_file = self.file_combo.currentData()
        self.file_combo.blockSignals(True)
        self.file_combo.clear()
        for f in self.win.files:
            if f["is_owner"] or "READ" in f["my_actions"] or "WRITE" in f["my_actions"]:
                self.file_combo.addItem(f"{f['name']}  (owner: {f['owner_display']})", f["id"])
        idx = self.file_combo.findData(keep_file)
        self.file_combo.setCurrentIndex(max(idx, 0))
        self.file_combo.blockSignals(False)
        keep_user = self.recipient_combo.currentData()
        self.recipient_combo.clear()
        for u in self.win.users:
            if u["id"] != self.win.user["id"]:
                self.recipient_combo.addItem(f"{u['display_name']}  ({u['username']})", u["id"])
        idx = self.recipient_combo.findData(keep_user)
        if idx >= 0:
            self.recipient_combo.setCurrentIndex(idx)
        self.load_sources()
        self.people_box.setVisible(bool(self.win.is_admin))
        t = self.people
        t.setRowCount(len(self.win.users))
        for row, u in enumerate(self.win.users):
            set_row(t, row, [u["username"], u["display_name"], "admin" if u["is_admin"] else "user",
                             u.get("linux_user") or "—"], data=u["id"])

    def load_sources(self) -> None:
        self.source_combo.clear()
        fid = self.file_combo.currentData()
        f = next((x for x in self.win.files if x["id"] == fid), None)
        if not f:
            return
        if f["is_owner"]:
            self.source_combo.addItem("As owner (root capability, edge 1)", None)
            return
        self.source_combo.addItem("Automatic - let the engine pick a capability I hold", None)
        try:
            for g in self.api.get("/api/grants/delegable", file_id=fid)["grants"]:
                self.source_combo.addItem(
                    f"Delegate from #{g['id']} ({' + '.join(g['actions'])}, edge {g['depth']}, "
                    f"expires {fmt_expiry(g['expires_at'])})", g["id"])
        except ApiError:
            pass

    def create(self) -> None:
        actions = [a for a, cb in (("READ", self.cb_read), ("WRITE", self.cb_write)) if cb.isChecked()]
        body = {"file_id": self.file_combo.currentData(), "recipient_id": self.recipient_combo.currentData(),
                "actions": actions, "can_delegate": self.cb_delegate.isChecked(),
                "expires_at": self.sp_expiry.value() if self.cb_expiry.isChecked() else None,
                "parent_id": self.source_combo.currentData()}
        if body["file_id"] is None or body["recipient_id"] is None or not actions:
            self.show_result("Choose a file, a recipient and at least one action.", False)
            return
        try:
            res = self.api.post("/api/grants", body)
        except ApiError as e:
            self.show_result(f"REFUSED ({e.code}): {e.message}", False)
            self.win.reload_shared()
            return
        g, acl = res["grant"], res["acl"]
        extra = ""
        if acl.get("ops"):
            extra = "\nLinux ACL: " + "; ".join(acl["ops"])
        elif acl.get("enabled"):
            extra = "\nLinux ACL: no change needed."
        self.show_result(f"Capability #{g['id']} created: {g['actions'].replace(',', ' + ')}, edge {g['depth']}, "
                         f"delegation {'allowed' if g['can_delegate'] else 'denied'}, "
                         f"expires {fmt_expiry(g['expires_at'])}.{extra}", True)
        self.win.reload_shared()

    def show_result(self, text: str, ok: bool) -> None:
        color = "#0f9d58" if ok else "#c62828"
        self.result.setText(f"<span style='color:{color};font-weight:600'>{text}</span>".replace("\n", "<br>"))

    # ------------------------------------------------------------ admin
    def create_account(self) -> None:
        try:
            self.api.post("/api/users", {"username": self.new_user.text(), "display_name": self.new_user.text(),
                                         "password": self.new_pw.text()})
        except ApiError as e:
            return error_box(self, "Could not create the account", e)
        self.new_user.clear()
        self.new_pw.clear()
        self.win.reload_shared()

    def map_linux(self) -> None:
        uid = selected_data(self.people)
        if uid is None:
            return
        name, ok = QInputDialog.getText(self, "Map to Linux user",
                                        "Existing local Linux user name (empty = remove mapping):")
        if not ok:
            return
        try:
            res = self.api.put(f"/api/users/{uid}/linux-user", {"linux_user": name.strip() or None})
        except ApiError as e:
            return error_box(self, "Mapping refused", e)
        errs = res["acl"]["errors"]
        self.win.status("Mapped. " + (f"ACL problems: {errs}" if errs else
                                      f"{len(res['acl']['ops'])} ACL change(s) applied."), 7000)
        self.win.reload_shared()
