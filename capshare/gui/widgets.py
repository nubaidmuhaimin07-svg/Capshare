"""Small reusable Qt helpers: cards, tables, background tasks, QR rendering."""
from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QColor, QImage, QPainter, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel,
                               QMessageBox, QProgressBar, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from . import theme
from .api_client import ApiError


# ---------------------------------------------------------------- layout helpers
def label(text: str, kind: str = "", wrap: bool = False) -> QLabel:
    lab = QLabel(text)
    if kind:
        lab.setObjectName(kind)
    lab.setWordWrap(wrap)
    lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lab


def card(title: str | None = None) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(16, 14, 16, 14)
    lay.setSpacing(10)
    if title:
        lay.addWidget(label(title, "h2"))
    return frame, lay


def page_header(title: str, subtitle: str) -> QWidget:
    box = QWidget()
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 4)
    lay.setSpacing(2)
    lay.addWidget(label(title, "h1"))
    lay.addWidget(label(subtitle, "muted", wrap=True))
    return box


def hbox(*widgets, stretch_last: bool = False, margins=(0, 0, 0, 0)) -> QWidget:
    box = QWidget()
    lay = QHBoxLayout(box)
    lay.setContentsMargins(*margins)
    lay.setSpacing(8)
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        else:
            lay.addWidget(w)
    return box


def pill(text: str, kind: str) -> QLabel:
    """kind: ok | bad | warn"""
    lab = QLabel(text)
    lab.setObjectName({"ok": "pillOk", "bad": "pillBad", "warn": "pillWarn"}[kind])
    return lab


# ---------------------------------------------------------------- tables
def make_table(headers: list[str], stretch_col: int | None = None) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.setWordWrap(False)
    t.horizontalHeader().setStretchLastSection(stretch_col is None)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    if stretch_col is not None:
        t.horizontalHeader().setSectionResizeMode(stretch_col, QHeaderView.Stretch)
    return t


STATUS_COLORS = {"active": theme.OK, "ok": theme.OK, "completed": theme.OK, "allowed": theme.OK,
                 "revoked": theme.BAD, "denied": theme.BAD, "terminated": theme.BAD,
                 "failed": theme.BAD, "error": theme.BAD, "expired": theme.WARN,
                 "noop": theme.MUTED}


def set_row(table: QTableWidget, row: int, values: list[Any], colored: dict[int, str] | None = None,
            data=None) -> None:
    for col, value in enumerate(values):
        item = QTableWidgetItem("" if value is None else str(value))
        item.setToolTip(item.text())
        if colored and col in colored:
            color = STATUS_COLORS.get(str(value).lower())
            if color:
                item.setForeground(QColor(color))
                font = item.font()
                font.setBold(True)
                item.setFont(font)
        if col == 0 and data is not None:
            item.setData(Qt.UserRole, data)
        table.setItem(row, col, item)


def selected_data(table: QTableWidget):
    rows = table.selectionModel().selectedRows()
    if not rows:
        return None
    item = table.item(rows[0].row(), 0)
    return item.data(Qt.UserRole) if item else None


def progress_cell(table: QTableWidget, row: int, col: int, done: int, total: int, state: str) -> None:
    bar = QProgressBar()
    pct = 100 if (state == "completed" and not total) else (int(100 * done / total) if total else 0)
    bar.setRange(0, 100)
    bar.setValue(min(100, pct))
    bar.setFormat(f"{pct}%")
    if state in ("terminated", "failed", "denied"):
        bar.setStyleSheet(f"QProgressBar::chunk {{ background: {theme.BAD}; }}")
    table.setCellWidget(row, col, bar)


# ---------------------------------------------------------------- formatting
def fmt_size(n: int | None) -> str:
    n = n or 0
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n / 1024 / 1024:.1f} MiB"


def fmt_ts(iso: str | None) -> str:
    return (iso or "")[:19].replace("T", " ")


def fmt_expiry(t) -> str:
    return "never" if t is None else f"t={t}"


# ---------------------------------------------------------------- messages
def error_box(parent, title: str, exc: Exception) -> None:
    message = exc.message if isinstance(exc, ApiError) else str(exc)
    code = f"\n\nCode: {exc.code}" if isinstance(exc, ApiError) and exc.code else ""
    QMessageBox.warning(parent, title, message + code)


# ---------------------------------------------------------------- background tasks
class _Signals(QObject):
    done = Signal(object)
    failed = Signal(object)
    progress = Signal(int, int)


class _Task(QRunnable):
    def __init__(self, fn: Callable, signals: _Signals, pass_progress: bool):
        super().__init__()
        self.fn, self.signals, self.pass_progress = fn, signals, pass_progress

    def run(self) -> None:
        try:
            if self.pass_progress:
                result = self.fn(lambda a, b: self.signals.progress.emit(int(a), int(b)))
            else:
                result = self.fn()
            self.signals.done.emit(result)
        except Exception as exc:                      # shown to the user, never swallowed
            self.signals.failed.emit(exc)


_live_signals: set[_Signals] = set()


def run_async(fn: Callable, on_done: Callable, on_error: Callable, on_progress=None) -> None:
    """Run `fn` on a worker thread; callbacks run on the UI thread."""
    signals = _Signals()
    _live_signals.add(signals)

    def finish(cb):
        def wrapper(value):
            _live_signals.discard(signals)
            cb(value)
        return wrapper
    signals.done.connect(finish(on_done))
    signals.failed.connect(finish(on_error))
    if on_progress:
        signals.progress.connect(on_progress)
    QThreadPool.globalInstance().start(_Task(fn, signals, on_progress is not None))


# ---------------------------------------------------------------- QR code
def qr_pixmap(text: str, scale: int = 6) -> QPixmap | None:
    try:
        import segno
    except ImportError:
        return None
    matrix = segno.make(text, error="m").matrix
    border = 2
    size = (len(matrix) + 2 * border) * scale
    image = QImage(size, size, QImage.Format_RGB32)
    image.fill(QColor("white"))
    painter = QPainter(image)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor("#111827"))
    for y, row in enumerate(matrix):
        for x, bit in enumerate(row):
            if bit:
                painter.drawRect((x + border) * scale, (y + border) * scale, scale, scale)
    painter.end()
    return QPixmap.fromImage(image)
