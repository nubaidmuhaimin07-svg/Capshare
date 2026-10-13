"""Transfers page (with connect info), Challenge Lab page, Activity page."""
from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QHeaderView, QLineEdit, QListWidget, QPlainTextEdit,
                               QPushButton, QScrollArea, QSpinBox, QSplitter, QTabWidget,
                               QVBoxLayout, QWidget)

from .api_client import ApiError
from .pages_files import Page
from .widgets import (card, error_box, fmt_size, fmt_ts, hbox, label, make_table, page_header,
                      pill, progress_cell, qr_pixmap, run_async, selected_data, set_row, fmt_expiry)


# =====================================================================================
class TransfersPage(Page):
    auto_refresh = True

    def __init__(self, win):
        super().__init__(win)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(12)
        outer.addWidget(page_header(
            "Transfers", "Files move directly between devices over your local network (TCP). "
                         "Every chunk is re-checked against the capability, so a revoke stops a transfer."))

        self.connect_box, cl = card("Connect a recipient device")
        row = QHBoxLayout()
        text = QVBoxLayout()
        self.url_label = label("…", "h2")
        self.url_hint = label("", "muted", wrap=True)
        text.addWidget(self.url_label)
        text.addWidget(self.url_hint)
        btns = QHBoxLayout()
        self.btn_copy = QPushButton("Copy link")
        self.btn_copy.clicked.connect(self.copy_link)
        btns.addWidget(self.btn_copy)
        btns.addStretch(1)
        text.addLayout(btns)
        row.addLayout(text, 1)
        self.qr = label("")
        self.qr.setFixedSize(150, 150)
        self.qr.setScaledContents(True)
        row.addWidget(self.qr)
        cl.addLayout(row)
        outer.addWidget(self.connect_box)

        self.admin_row = QWidget()
        al = QHBoxLayout(self.admin_row)
        al.setContentsMargins(0, 0, 0, 0)
        self.delay = QSpinBox()
        self.delay.setRange(0, 2000)
        self.delay.setSuffix(" ms per 64 KiB")
        btn_delay = QPushButton("Apply slow mode")
        btn_delay.clicked.connect(self.apply_delay)
        al.addWidget(label("Demo slow mode (makes a transfer long enough to revoke it mid-way):", "muted"))
        al.addWidget(self.delay)
        al.addWidget(btn_delay)
        al.addStretch(1)
        outer.addWidget(self.admin_row)

        self.table = make_table(["File", "Direction", "User", "State", "Progress", "Size", "Remote",
                                 "Note", "Started"], stretch_col=7)
        outer.addWidget(self.table, 1)
        self.urls: list[str] = []
        self._loaded_connect = False

    def on_shared(self) -> None:
        self.admin_row.setVisible(bool(self.win.is_admin))
        if not self._loaded_connect:
            self.load_connect()

    def load_connect(self) -> None:
        try:
            d = self.api.get("/api/connect")
            s = self.api.get("/api/settings")
        except ApiError:
            return
        self._loaded_connect = True
        self.delay.setValue(s["transfer_delay_ms"])
        self.urls = d["urls"]
        if d["urls"]:
            self.url_label.setText(d["urls"][0])
            more = (" Other addresses: " + ", ".join(d["urls"][1:]) + ".") if len(d["urls"]) > 1 else ""
            self.url_hint.setText(
                f"Wi-Fi address {d['lan_addresses'][0]}, port {d['port']}.{more} On the other device open this link "
                f"in a browser, or run the CapShare client: ./run.sh --client {d['urls'][0].rstrip('/')}. "
                "Only devices on the same private network can connect.")
            pix = qr_pixmap(d["urls"][0])
            if pix:
                self.qr.setPixmap(pix)
        else:
            self.url_label.setText(d["local_url"])
            self.urls = [d["local_url"]]
            self.url_hint.setText("No private Wi-Fi/LAN address was detected, so the service is only "
                                  "reachable from this computer. Connect to Wi-Fi and restart CapShare.")
            self.qr.clear()
        self.win.set_connect_label(self.urls[0])

    def copy_link(self) -> None:
        if self.urls:
            QGuiApplication.clipboard().setText(self.urls[0])
            self.win.status("Link copied to the clipboard.", 3000)

    def apply_delay(self) -> None:
        try:
            self.api.post("/api/settings", {"transfer_delay_ms": self.delay.value()})
            self.win.status("Slow mode updated.", 3000)
        except ApiError as e:
            error_box(self, "Settings", e)

    def refresh(self) -> None:
        try:
            rows = self.api.get("/api/transfers")["transfers"]
        except ApiError:
            return
        t = self.table
        t.setRowCount(len(rows))
        for r, x in enumerate(rows):
            direction = "Outgoing ↑" if x["perspective"] == "outgoing" else "Incoming ↓"
            set_row(t, r, [x["file_name"], direction, x["user_name"], x["state"], "",
                           fmt_size(x["bytes_total"]), x["remote_addr"], x["note"] or "",
                           fmt_ts(x["started_at"])], colored={3: "state"})
            progress_cell(t, r, 4, x["bytes_done"], x["bytes_total"], x["state"])


# =====================================================================================
class LabPage(Page):
    def __init__(self, win):
        super().__init__(win)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(12)
        outer.addWidget(page_header(
            "Challenge Lab", "The five KO-13 challenges. Each run executes the real permission engine "
                             "on a throw-away database and sample file - your saved data is never touched."))
        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.setObjectName("nav")
        self.list.currentRowChanged.connect(self.show_description)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        ll.addWidget(self.list, 1)
        self.desc = label("", "", wrap=True)
        self.rules = label("", "muted", wrap=True)
        ll.addWidget(self.desc)
        ll.addWidget(self.rules)
        self.btn_run = QPushButton("Run this challenge")
        self.btn_run.setObjectName("primary")
        self.btn_run.clicked.connect(self.run)
        self.btn_all = QPushButton("Run all five")
        self.btn_all.clicked.connect(self.run_all)
        ll.addWidget(hbox(self.btn_run, self.btn_all))
        split.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.verdict = QHBoxLayout()
        self.verdict_box = QWidget()
        self.verdict_box.setLayout(self.verdict)
        self.summary = label("Pick a challenge and press Run.", "", wrap=True)
        rl.addWidget(self.verdict_box)
        rl.addWidget(self.summary)
        self.metrics = label("", "muted", wrap=True)
        rl.addWidget(self.metrics)
        self.tabs = QTabWidget()
        self.steps = make_table(["#", "", "Step", "Expected", "Actual backend result"], stretch_col=4)
        self.steps.setWordWrap(True)
        self.steps.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.steps.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
        self.steps.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.steps.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.steps.setColumnWidth(0, 34)
        self.steps.setColumnWidth(1, 28)
        self.steps.setColumnWidth(2, 230)
        self.steps.setColumnWidth(3, 150)
        self.snap_area = QScrollArea()
        self.snap_area.setWidgetResizable(True)
        self.snap_host = QWidget()
        self.snap_lay = QVBoxLayout(self.snap_host)
        self.snap_area.setWidget(self.snap_host)
        self.acl_log = QPlainTextEdit()
        self.acl_log.setReadOnly(True)
        self.act = make_table(["Time", "Actor", "Action", "Outcome", "Grant", "Detail"], stretch_col=5)
        self.tabs.addTab(self.steps, "Steps")
        self.tabs.addTab(self.snap_area, "Lineage snapshots")
        self.tabs.addTab(self.acl_log, "Linux ACL operations")
        self.tabs.addTab(self.act, "Activity recorded")
        rl.addWidget(self.tabs, 1)
        split.addWidget(right)
        left.setMaximumWidth(340)
        split.setSizes([320, 900])
        split.setStretchFactor(1, 3)
        outer.addWidget(split, 1)

        self.defs: list[dict] = []
        self._queue: list[str] = []
        try:
            self.defs = self.api.get("/api/lab/challenges")["challenges"]
        except ApiError:
            pass
        for d in self.defs:
            self.list.addItem(f"{d['key']}  ·  {d['title']}")
        if self.defs:
            self.list.setCurrentRow(0)

    def show_description(self, row: int) -> None:
        if 0 <= row < len(self.defs):
            d = self.defs[row]
            self.desc.setText(d["what"])
            self.rules.setText("Rules shown:\n• " + "\n• ".join(d["rules"]))

    def run(self) -> None:
        row = self.list.currentRow()
        if row < 0:
            return
        self._execute(self.defs[row]["key"])

    def run_all(self) -> None:
        self._queue = [d["key"] for d in self.defs]
        self._next_queued()

    def _next_queued(self) -> None:
        if self._queue:
            self._execute(self._queue.pop(0), then=self._next_queued)

    def _execute(self, key: str, then=None) -> None:
        self.btn_run.setEnabled(False)
        self.btn_all.setEnabled(False)
        self.steps.setRowCount(0)                       # do not mix old results with the new run
        self.metrics.setText("")
        self.summary.setText(f"Running {key} …")

        def done(res):
            self.btn_run.setEnabled(True)
            self.btn_all.setEnabled(True)
            self.render(res)
            self.win.reload_shared()
            if then:
                then()

        def fail(e):
            self.btn_run.setEnabled(True)
            self.btn_all.setEnabled(True)
            self._queue.clear()
            self.summary.setText("The run failed.")
            error_box(self, "Challenge run failed", e)
        run_async(lambda: self.api.post(f"/api/lab/run/{key}"), done, fail)

    # ------------------------------------------------------------ rendering
    def render(self, res: dict) -> None:
        while self.verdict.count():
            w = self.verdict.takeAt(0).widget()
            if w:
                w.deleteLater()
        self.verdict.addWidget(label(f"{res['key']} · {res['title']}", "h2"))
        self.verdict.addWidget(pill("PASSED" if res["passed"] else "FAILED", "ok" if res["passed"] else "bad"))
        self.verdict.addStretch(1)
        self.summary.setText(res["summary"])
        m = res.get("metrics", {})
        lines = []
        for k, v in m.items():
            if k == "clock_timeline":
                lines.append("clock timeline: " + "; ".join(
                    f"t={e['time']} {e['user']}→{e['decision']}" for e in v))
            else:
                lines.append(f"{k.replace('_', ' ')}: {v}")
        self.metrics.setText("   |   ".join(lines))

        t = self.steps
        t.setRowCount(len(res["steps"]))
        for r, s in enumerate(res["steps"]):
            set_row(t, r, [s["n"], "✔" if s["ok"] else "✘", s["title"], s["expected"], s["actual"]])
            mark = t.item(r, 1)
            mark.setForeground(QColor("#0f9d58") if s["ok"] else QColor("#c62828"))
        t.resizeRowsToContents()

        while self.snap_lay.count():
            w = self.snap_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        for snap in res["snapshots"]:
            self.snap_lay.addWidget(label(
                f"{snap['title']} — clock t={snap['clock']}, {snap['active']} active of {snap['total']}", "h2"))
            tb = make_table(["#", "Parent", "Recipient", "Granted by", "Actions", "Delegate", "Depth",
                             "Expires", "Status", "Why"], stretch_col=9)
            tb.setMinimumHeight(min(60 + 28 * len(snap["grants"]), 330))
            tb.setRowCount(len(snap["grants"]))
            for r, g in enumerate(snap["grants"]):
                set_row(tb, r, [f"#{g['id']}", f"#{g['parent_id']}" if g["parent_id"] else "owner",
                                g["recipient"], g["grantor"], " + ".join(g["actions"]),
                                "yes" if g["can_delegate"] else "no", g["depth"], fmt_expiry(g["expires_at"]),
                                g["status"], g["status_reason"]], colored={8: "status"})
            self.snap_lay.addWidget(tb)
        self.snap_lay.addStretch(1)

        self.acl_log.setPlainText(
            "These are the setfacl operations the engine issued against the SIMULATED ACL backend\n"
            "(the real `setfacl` demo is scripts/acl_demo.sh):\n\n" + "\n".join(res["acl_log"]))
        a = self.act
        a.setRowCount(len(res["activity"]))
        for r, e in enumerate(res["activity"]):
            set_row(a, r, [fmt_ts(e["ts"]), e["actor"] or "", e["action"], e["outcome"],
                           f"#{e['grant_id']}" if e["grant_id"] else "",
                           json.dumps(e["detail"], ensure_ascii=False)], colored={3: "outcome"})


# =====================================================================================
class ActivityPage(Page):
    auto_refresh = True

    def __init__(self, win):
        super().__init__(win)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(12)
        outer.addWidget(page_header(
            "Activity", "Audit trail: grants, denied escalation attempts, access checks, transfers, "
                        "expiry, revocation and cascade work."))
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText("Filter text (e.g. grant, denied, cascade, transfer)")
        self.filter_text.textChanged.connect(self.refresh)
        self.outcome = QComboBox()
        self.outcome.addItems(["all outcomes", "ok", "denied", "error", "noop"])
        self.outcome.currentIndexChanged.connect(self.refresh)
        outer.addWidget(hbox(self.filter_text, self.outcome))
        self.table = make_table(["Time", "Actor", "Action", "Outcome", "File", "Grant", "Details"],
                                stretch_col=6)
        outer.addWidget(self.table, 1)

    def refresh(self) -> None:
        try:
            events = self.api.get("/api/activity", limit=400)["events"]
        except ApiError:
            return
        needle = self.filter_text.text().strip().lower()
        want = self.outcome.currentText()
        rows = []
        for e in events:
            if want != "all outcomes" and e["outcome"] != want:
                continue
            detail = json.dumps(e["detail"], ensure_ascii=False)
            line = f"{e['action']} {e['actor_name']} {e['file_name']} {detail}".lower()
            if needle and needle not in line:
                continue
            rows.append((e, detail))
        t = self.table
        t.setRowCount(len(rows))
        for r, (e, detail) in enumerate(rows):
            set_row(t, r, [fmt_ts(e["ts"]), e["actor_name"] or "—", e["action"], e["outcome"],
                           e["file_name"] or "", f"#{e['grant_id']}" if e["grant_id"] else "", detail],
                    colored={3: "outcome"})
