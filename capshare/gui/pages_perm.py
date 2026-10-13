"""Permission lineage page and Access check page (with the logical clock)."""
from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QMessageBox, QPushButton, QSpinBox, QVBoxLayout)

from .api_client import ApiError
from .pages_files import Page
from .widgets import (card, error_box, fmt_expiry, fmt_ts, hbox, label, make_table, page_header,
                      pill, selected_data, set_row)


# =====================================================================================
class LineagePage(Page):
    auto_refresh = True

    def __init__(self, win):
        super().__init__(win)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(12)
        outer.addWidget(page_header(
            "Permission lineage", "Every capability with its parent, depth and live status. "
                                  "Indented rows were delegated from the row above. Revoking a row "
                                  "revokes everything derived from it."))
        self.file_filter = QComboBox()
        self.file_filter.currentIndexChanged.connect(self.refresh)
        self.btn_revoke = QPushButton("Revoke selected…")
        self.btn_revoke.setObjectName("danger")
        self.btn_revoke.clicked.connect(self.revoke)
        self.summary = label("", "muted")
        outer.addWidget(hbox(label("File:"), self.file_filter, self.summary, None, self.btn_revoke))
        self.table = make_table(["Capability", "Parent", "File", "Recipient", "Granted by", "Actions",
                                 "Delegate", "Depth", "Expires", "Status", "Why / reason", "Created"],
                                stretch_col=10)
        outer.addWidget(self.table, 1)
        self.report_label = label("", "muted", wrap=True)
        box, lay = card("Last revocation report")
        lay.addWidget(self.report_label)
        outer.addWidget(box)
        self._rows: list[dict] = []

    def on_shared(self) -> None:
        keep = self.file_filter.currentData()
        self.file_filter.blockSignals(True)
        self.file_filter.clear()
        self.file_filter.addItem("All files", None)
        for f in self.win.files:
            self.file_filter.addItem(f["name"], f["id"])
        idx = self.file_filter.findData(keep)
        self.file_filter.setCurrentIndex(max(idx, 0))
        self.file_filter.blockSignals(False)
        self.refresh()

    def refresh(self) -> None:
        fid = self.file_filter.currentData()
        try:
            rows = self.api.get("/api/grants", **({"file_id": fid} if fid else {}))["grants"]
        except ApiError:
            return
        self._rows = rows
        keep = selected_data(self.table)
        t = self.table
        t.setRowCount(len(rows))
        for r, g in enumerate(rows):
            indent = "    " * max(g["depth"] - 1, 0) + ("↳ " if g["parent_id"] else "")
            set_row(t, r, [f"{indent}#{g['id']}", f"#{g['parent_id']}" if g["parent_id"] else "owner",
                           g["file_name"], g["recipient_display"], g["grantor_name"],
                           " + ".join(g["actions"]), "yes" if g["can_delegate"] else "no", g["depth"],
                           fmt_expiry(g["expires_at"]), g["status"], g["status_reason"],
                           fmt_ts(g["created_at"])], colored={9: "status"}, data=g["id"])
            if keep == g["id"]:
                t.selectRow(r)
        active = sum(1 for g in rows if g["status"] == "active")
        self.summary.setText(f"{len(rows)} capabilities, {active} active")

    def revoke(self) -> None:
        gid = selected_data(self.table)
        g = next((x for x in self._rows if x["id"] == gid), None)
        if not g:
            QMessageBox.information(self, "Revoke", "Select a capability row first.")
            return
        if g["child_count"]:
            note = f"\n\nThis also revokes every capability derived from it ({g['child_count']} direct child(ren) and below)."
        else:
            note = ""
        ok = QMessageBox.question(
            self, "Revoke capability",
            f"Revoke capability #{g['id']} ({' + '.join(g['actions'])} for {g['recipient_display']}"
            f" on {g['file_name']})?{note}\n\nRevocation stops FUTURE access and running transfers. "
            "It cannot erase a copy that was already downloaded.")
        if ok != QMessageBox.Yes:
            return
        try:
            rep = self.api.post(f"/api/grants/{gid}/revoke")
        except ApiError as e:
            return error_box(self, "Revoke refused", e)
        acl = rep.get("acl", {})
        acl_line = ("Linux ACL: " + ("; ".join(acl["ops"]) if acl.get("ops") else "no change")
                    if acl.get("enabled") else "Linux ACL integration is off on this machine.")
        if acl.get("error"):
            acl_line = f"⚠ ACL INCONSISTENCY: {acl['error']}"
        self.report_label.setText(
            f"Grant #{rep['grant_id']}: affected grants = {rep['affected_grants']}, descendants = "
            f"{rep['descendant_count']}, transfers terminated = {rep.get('transfers_terminated', 0)}\n"
            f"Traversal: {rep['traversal_method']}\n"
            f"Elapsed: {rep['elapsed_ms']} ms   |   {acl_line}\n{rep['copy_notice']}")
        self.win.reload_shared()


# =====================================================================================
class AccessPage(Page):
    def __init__(self, win):
        super().__init__(win)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(12)
        outer.addWidget(page_header(
            "Access check", "Ask the backend whether a user may READ or WRITE a file right now. "
                            "This calls the exact decision function the transfer routes use."))
        box, lay = card("Check")
        self.file_combo = QComboBox()
        self.user_combo = QComboBox()
        self.action_combo = QComboBox()
        self.action_combo.addItems(["READ", "WRITE"])
        btn = QPushButton("Check access")
        btn.setObjectName("primary")
        btn.clicked.connect(self.check)
        lay.addWidget(hbox(label("File"), self.file_combo, label("User"), self.user_combo,
                           label("Action"), self.action_combo, btn))
        outer.addWidget(box)

        rbox, rl = card("Backend decision")
        self.verdict = label("—", "h1")
        self.reason = label("", "", wrap=True)
        self.enforced = label("", "muted", wrap=True)
        rl.addWidget(self.verdict)
        rl.addWidget(self.reason)
        self.paths = make_table(["Capability", "Actions", "Path status", "Blocked by", "Own expiry",
                                 "Path expires"], stretch_col=2)
        self.paths.setMaximumHeight(170)
        rl.addWidget(self.paths)
        rl.addWidget(self.enforced)
        outer.addWidget(rbox)

        cbox, cl = card("Logical clock (owner controlled)")
        cl.addWidget(label("Expiry uses this deterministic counter instead of wall-clock time. "
                           "A capability with expiry T is valid while clock < T. "
                           "The clock only moves forward, so an expired capability can never be revived.",
                           "muted", wrap=True))
        self.clock_info = label("", "")
        self.clock_spin = QSpinBox()
        self.clock_spin.setRange(0, 1_000_000)
        btn_set = QPushButton("Set my clock")
        btn_set.setObjectName("primary")
        btn_set.clicked.connect(self.set_clock)
        btn_plus = QPushButton("+1")
        btn_plus.clicked.connect(lambda: self.set_clock(delta=1))
        cl.addWidget(self.clock_info)
        cl.addWidget(hbox(label("Set to"), self.clock_spin, btn_set, btn_plus, None))
        self.clock_result = label("", "muted", wrap=True)
        cl.addWidget(self.clock_result)
        outer.addWidget(cbox)
        outer.addStretch(1)
        self.on_shared()

    def on_shared(self) -> None:
        kf, ku = self.file_combo.currentData(), self.user_combo.currentData()
        self.file_combo.clear()
        for f in self.win.files:
            self.file_combo.addItem(f"{f['name']} (owner: {f['owner_display']})", f["id"])
        self.user_combo.clear()
        for u in self.win.users:
            self.user_combo.addItem(f"{u['display_name']} ({u['username']})", u["id"])
        for combo, key in ((self.file_combo, kf), (self.user_combo, ku)):
            idx = combo.findData(key)
            if idx >= 0:
                combo.setCurrentIndex(idx)
        self.load_clock()

    def load_clock(self) -> None:
        try:
            d = self.api.get("/api/clock")
        except ApiError:
            return
        others = ", ".join(f"{c['owner']}: t={c['clock']}" for c in d["clocks"] if c["owner_id"] != self.win.user["id"])
        self.clock_info.setText(f"<b>My clock: t={d['my_clock']}</b>" + (f"   |   other owners — {others}" if others else ""))
        self.clock_spin.setMinimum(d["my_clock"])
        self.clock_spin.setValue(d["my_clock"])

    def check(self) -> None:
        fid, uid = self.file_combo.currentData(), self.user_combo.currentData()
        if fid is None or uid is None:
            return
        try:
            d = self.api.post("/api/access/check", {"file_id": fid, "user_id": uid,
                                                    "action": self.action_combo.currentText()})
        except ApiError as e:
            return error_box(self, "Access check refused", e)
        self.verdict.setObjectName("verdictOk" if d["allowed"] else "verdictBad")
        self.verdict.setStyleSheet("")                      # force re-polish with the new object name
        self.verdict.style().unpolish(self.verdict)
        self.verdict.style().polish(self.verdict)
        self.verdict.setText(f"{'ALLOWED' if d['allowed'] else 'DENIED'}  ·  {d['action']}  ·  {d['code']}")
        self.reason.setText(d["reason"] + f"   (owner's logical clock: t={d['clock']})")
        t = self.paths
        t.setRowCount(len(d["paths"]))
        for r, p in enumerate(d["paths"]):
            set_row(t, r, [f"#{p['grant_id']}", " + ".join(p["actions"]), p["status"],
                           f"#{p['culprit']}" if p["culprit"] else "", fmt_expiry(p["expires_at"]),
                           fmt_expiry(p["path_expiry"])], colored={2: "status"})
        self.enforced.setText("Capability decision: enforced by the CapShare network service.   "
                              "File-system permissions: enforced by the Linux kernel, and only for "
                              "Linux users mapped to app accounts.")
        self.win.status("Access check recorded in Activity.", 3000)

    def set_clock(self, delta: int | None = None) -> None:
        value = self.clock_spin.minimum() + delta if delta else self.clock_spin.value()
        try:
            res = self.api.post("/api/clock", {"value": value})
        except ApiError as e:
            return error_box(self, "Clock", e)
        exp = res["expired_grants"]
        self.clock_result.setText(
            f"Clock moved {res['old']} → {res['new']}. "
            + (f"Capabilities that just expired: {', '.join('#' + str(i) for i in exp)}. "
               if exp else "No capability expired. ")
            + f"Transfers terminated: {res.get('transfers_terminated', 0)}.")
        self.win.reload_shared()
