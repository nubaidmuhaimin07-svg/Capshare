"""One place for colours and the Qt style sheet, so every page looks the same."""

INK = "#14213d"
MUTED = "#5b6678"
LINE = "#e1e6ef"
BG = "#f4f6fb"
CARD = "#ffffff"
ACCENT = "#4f46e5"
ACCENT_DARK = "#4338ca"
OK = "#0f9d58"
BAD = "#c62828"
WARN = "#b45309"
CHIP = "#eef2ff"

STYLE = f"""
* {{ font-family: "Segoe UI", "Ubuntu", "Noto Sans", sans-serif; font-size: 13px; color: {INK}; }}
QMainWindow, QDialog, QWidget#page {{ background: {BG}; }}
QWidget#sidebar {{ background: {CARD}; border-right: 1px solid {LINE}; }}
QLabel#brand {{ font-size: 18px; font-weight: 700; padding: 6px 4px; }}
QLabel#h1 {{ font-size: 20px; font-weight: 700; }}
QLabel#h2 {{ font-size: 14px; font-weight: 700; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#pillOk {{ background: #e6f6ee; color: {OK}; border-radius: 10px; padding: 3px 10px; font-weight: 700; }}
QLabel#pillBad {{ background: #fdecec; color: {BAD}; border-radius: 10px; padding: 3px 10px; font-weight: 700; }}
QLabel#pillWarn {{ background: #fff4e0; color: {WARN}; border-radius: 10px; padding: 3px 10px; font-weight: 700; }}
QLabel#verdictOk {{ background: #e6f6ee; color: {OK}; border-radius: 10px; padding: 10px 16px; font-size: 18px; font-weight: 800; }}
QLabel#verdictBad {{ background: #fdecec; color: {BAD}; border-radius: 10px; padding: 10px 16px; font-size: 18px; font-weight: 800; }}
QFrame#card {{ background: {CARD}; border: 1px solid {LINE}; border-radius: 12px; }}
QListWidget#nav {{ background: transparent; border: none; outline: none; }}
QListWidget#nav::item {{ padding: 10px 12px; border-radius: 8px; margin: 2px 4px; }}
QListWidget#nav::item:selected {{ background: {CHIP}; color: {ACCENT}; font-weight: 700; }}
QListWidget#nav::item:hover {{ background: #f1f4fb; }}
QPushButton {{ background: {CARD}; border: 1px solid {LINE}; border-radius: 8px; padding: 7px 14px; font-weight: 600; }}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: #9aa3b5; background: #f1f3f8; }}
QPushButton#primary {{ background: {ACCENT}; color: white; border-color: {ACCENT}; }}
QPushButton#primary:hover {{ background: {ACCENT_DARK}; }}
QPushButton#primary:disabled {{ background: #b9b6f5; color: white; }}
QPushButton#danger {{ background: {BAD}; color: white; border-color: {BAD}; }}
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
  background: {CARD}; border: 1px solid {LINE}; border-radius: 8px; padding: 6px 8px; selection-background-color: {ACCENT}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QTableWidget {{ background: {CARD}; border: 1px solid {LINE}; border-radius: 10px; gridline-color: {LINE};
  alternate-background-color: #f8f9fd; selection-background-color: {CHIP}; selection-color: {INK}; }}
QHeaderView::section {{ background: #f1f4fb; border: none; border-bottom: 1px solid {LINE}; padding: 7px 8px; font-weight: 700; color: {MUTED}; }}
QProgressBar {{ border: 1px solid {LINE}; border-radius: 6px; background: {CHIP}; text-align: center; height: 16px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}
QTabWidget::pane {{ border: 1px solid {LINE}; border-radius: 10px; background: {CARD}; top: -1px; }}
QTabBar::tab {{ padding: 8px 14px; border: none; color: {MUTED}; font-weight: 600; }}
QTabBar::tab:selected {{ color: {ACCENT}; border-bottom: 2px solid {ACCENT}; }}
QStatusBar {{ background: {CARD}; border-top: 1px solid {LINE}; }}
QCheckBox {{ spacing: 8px; }}
QScrollArea {{ border: none; background: transparent; }}
"""
