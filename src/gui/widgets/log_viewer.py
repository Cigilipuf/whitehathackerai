"""
WhiteHatHacker AI — Log Viewer Widget (v2.1)

Real-time log viewer with:
  - Multiple log source tabs (Brain, Tools, Debug, Errors, Scan stdout)
  - Colour-coded log levels
  - JSON log parsing (loguru structured output)
  - Auto-scroll
  - Search / filter
  - Clear / export
  - Auto-tailing of active log files
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from loguru import logger
from PySide6.QtCore import Qt, Signal, Slot, QTimer
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTextEdit,
    QLabel,
    QPushButton,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QFileDialog,
    QTabWidget,
)


_LEVEL_COLORS: dict[str, str] = {
    "TRACE": "#555555",
    "DEBUG": "#6c757d",
    "INFO": "#17a2b8",
    "SUCCESS": "#28a745",
    "WARNING": "#ffc107",
    "ERROR": "#dc3545",
    "CRITICAL": "#ff0040",
}


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _parse_json_log_line(raw: str) -> tuple[str, str, str]:
    """Parse a loguru JSON-serialized log line.

    Returns (level, formatted_text, raw_message).
    """
    try:
        data = json.loads(raw)
        # loguru JSON format has "text" and "record" keys
        if "record" in data:
            rec = data["record"]
            level = rec.get("level", {}).get("name", "INFO")
            msg = rec.get("message", "")
            time_str = ""
            time_obj = rec.get("time", {})
            if isinstance(time_obj, dict):
                time_str = time_obj.get("repr", "")[:19]
            module = rec.get("name", "")
            func = rec.get("function", "")
            session = rec.get("extra", {}).get("session_id", "")

            formatted = f"{time_str} | {level:8s} | [{session[:8]}] {module}:{func} | {msg}"
            return level, formatted, msg
        elif "text" in data:
            text = data["text"].rstrip("\n")
            # Extract level from text
            for lvl in _LEVEL_COLORS:
                if f"| {lvl}" in text:
                    return lvl, text, text
            return "INFO", text, text
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    # Plain text fallback
    level = "INFO"
    for lvl in _LEVEL_COLORS:
        if lvl in raw.upper()[:60]:
            level = lvl
            break
    return level, raw.rstrip("\n"), raw.rstrip("\n")


class _LogPane(QWidget):
    """A single log viewer pane with text display and tail capabilities."""

    log_appended = Signal(str)

    def __init__(
        self,
        name: str,
        log_paths: list[str],
        is_json: bool = True,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._name = name
        self._log_paths = log_paths  # can use {date} placeholder
        self._is_json = is_json
        self._max_lines = 15_000
        self._auto_scroll = True
        self._line_count = 0
        self._tail_positions: dict[str, int] = {}
        self._level_filter: str = ""
        self._search_filter: str = ""

        self._build_ui()
        self.log_appended.connect(self._do_append, Qt.ConnectionType.QueuedConnection)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFont(QFont("Fira Code", 9))
        self._log_view.setStyleSheet(
            "QTextEdit { background: #0a0a0a; color: #b0b0b0; "
            "border: 1px solid #222; }"
        )
        self._log_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self._log_view, 1)

        self._status = QLabel("0 lines")
        self._status.setStyleSheet("color: #555; font-size: 9px;")
        layout.addWidget(self._status)

    def tail(self) -> None:
        """Read new lines from all configured log files."""
        today = datetime.now().strftime("%Y-%m-%d")

        for pattern in self._log_paths:
            log_path = Path(pattern.replace("{date}", today))
            if not log_path.exists():
                continue

            key = str(log_path)
            pos = self._tail_positions.get(key, 0)

            try:
                with open(log_path, "r", errors="replace") as f:
                    f.seek(pos)
                    new_data = f.read()
                    self._tail_positions[key] = f.tell()

                if new_data:
                    for line in new_data.splitlines():
                        stripped = line.strip()
                        if not stripped:
                            continue
                        if self._is_json:
                            level, formatted, raw_msg = _parse_json_log_line(stripped)
                        else:
                            level = "INFO"
                            for lvl in _LEVEL_COLORS:
                                if lvl in stripped.upper()[:60]:
                                    level = lvl
                                    break
                            formatted = stripped
                        # Apply filters
                        if self._level_filter and level != self._level_filter:
                            continue
                        if self._search_filter and self._search_filter not in formatted.lower():
                            continue
                        self._append_colored(level, formatted)
            except Exception as _exc:
                logger.debug(f"log viewer error: {_exc}")

    def _append_colored(self, level: str, text: str) -> None:
        """Append a line with level-based coloring."""
        color = _LEVEL_COLORS.get(level, "#b0b0b0")

        # Special highlights
        if "[FINDING]" in text:
            color = "#ff6d00"
        elif "CRITICAL" in text[:30]:
            color = "#ff0040"

        self._log_view.append(
            f'<span style="color:{color}">{_html_escape(text)}</span>'
        )
        self._line_count += 1

        # Auto trim
        if self._line_count > self._max_lines:
            cursor = self._log_view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(
                QTextCursor.MoveOperation.Down,
                QTextCursor.MoveMode.KeepAnchor,
                self._line_count - self._max_lines,
            )
            cursor.removeSelectedText()
            self._line_count = self._max_lines

        if self._auto_scroll:
            sb = self._log_view.verticalScrollBar()
            sb.setValue(sb.maximum())

        self._status.setText(f"{self._line_count} lines")

    @Slot(str)
    def _do_append(self, message: str) -> None:
        """Thread-safe append."""
        level, formatted, _ = _parse_json_log_line(message) if self._is_json else ("INFO", message, message)
        self._append_colored(level, formatted)

    def append_log(self, message: str) -> None:
        """Thread-safe log append — can be called from any thread."""
        self.log_appended.emit(message)

    def set_auto_scroll(self, enabled: bool) -> None:
        self._auto_scroll = enabled

    def clear(self) -> None:
        self._log_view.clear()
        self._line_count = 0
        self._status.setText("0 lines")

    def get_text(self) -> str:
        return self._log_view.toPlainText()

    def apply_filter(self, level_filter: str, search_text: str) -> None:
        """Apply level/text filter. Affects new tailed lines only."""
        self._level_filter = level_filter.upper() if level_filter and level_filter != "All Levels" else ""
        self._search_filter = search_text.lower() if search_text else ""


class LogViewerWidget(QWidget):
    """Multi-source log viewer with tabs for different log categories."""

    log_appended = Signal(str)  # backward compat for thread-safe append

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._panes: dict[str, _LogPane] = {}

        self._build_ui()

        # Connect the thread-safe signal to main log pane
        self.log_appended.connect(self._on_external_log, Qt.ConnectionType.QueuedConnection)

        # Tail timer — check for new log data every 2 seconds
        self._tail_timer = QTimer(self)
        self._tail_timer.timeout.connect(self._tail_all)
        self._tail_timer.start(2_000)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        # ── Header ────────────────────────────────────
        header = QLabel("📝 Log Viewer")
        header.setFont(QFont("", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff; padding: 4px;")
        layout.addWidget(header)

        # ── Toolbar ───────────────────────────────────
        toolbar = QHBoxLayout()

        self._level_combo = QComboBox()
        self._level_combo.addItems(
            ["All Levels", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        )
        self._level_combo.setCurrentIndex(0)
        toolbar.addWidget(self._level_combo)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("🔎 Filter logs...")
        toolbar.addWidget(self._search_input, 1)

        self._auto_scroll_cb = QCheckBox("Auto-scroll")
        self._auto_scroll_cb.setChecked(True)
        self._auto_scroll_cb.toggled.connect(self._on_auto_scroll_toggle)
        toolbar.addWidget(self._auto_scroll_cb)

        self._clear_btn = QPushButton("🗑 Clear")
        self._clear_btn.clicked.connect(self._on_clear)
        toolbar.addWidget(self._clear_btn)

        self._export_btn = QPushButton("💾 Save")
        self._export_btn.clicked.connect(self._on_export)
        toolbar.addWidget(self._export_btn)

        layout.addLayout(toolbar)

        # ── Log Tabs ─────────────────────────────────
        self._tab_widget = QTabWidget()
        self._tab_widget.setDocumentMode(True)

        # Create log panes for each log category
        log_sources = [
            ("🧠 Brain", "brain", ["output/logs/brain_{date}.log"], True),
            ("🔧 Tools", "tools", ["output/logs/tools_{date}.log"], True),
            ("⚠ Errors", "errors", ["output/logs/errors_{date}.log"], True),
            ("🐛 Debug", "debug", ["output/logs/debug_{date}.log"], True),
            ("📺 Scan Stdout", "stdout", self._discover_stdout_logs(), False),
            ("📋 All", "all", ["output/logs/whai_{date}.log"], True),
        ]

        for label, key, paths, is_json in log_sources:
            pane = _LogPane(key, paths, is_json)
            self._panes[key] = pane
            self._tab_widget.addTab(pane, label)

        layout.addWidget(self._tab_widget, 1)

        # Wire filter controls
        self._level_combo.currentTextChanged.connect(self._on_filter_changed)
        self._search_input.textChanged.connect(self._on_filter_changed)

    def _on_filter_changed(self) -> None:
        """Push filter state to all panes."""
        level = self._level_combo.currentText()
        search = self._search_input.text()
        for pane in self._panes.values():
            pane.apply_filter(level, search)

    @staticmethod
    def _discover_stdout_logs() -> list[str]:
        """Find all scan stdout/console log files."""
        log_dir = Path("output/logs")
        if not log_dir.exists():
            return []
        # Match both scan*_stdout.log and scan*_console.log patterns
        results: list[Path] = []
        for pattern in ("scan*_stdout.log", "scan*_console.log", "scan_*_console.log"):
            results.extend(log_dir.glob(pattern))
        # Deduplicate and sort newest first
        seen: set[str] = set()
        unique: list[str] = []
        for p in sorted(results, key=lambda f: f.stat().st_mtime, reverse=True):
            s = str(p)
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique

    # ─────────────────────────────────────────────────────
    # Public API (thread-safe, backward compatible)
    # ─────────────────────────────────────────────────────

    def append_log(self, message: str) -> None:
        """Thread-safe log append — can be called from any thread."""
        self.log_appended.emit(message)

    @Slot(str)
    def _on_external_log(self, message: str) -> None:
        """Handle externally appended log (from ScanWorker etc.)."""
        # Append to "All" pane
        all_pane = self._panes.get("all")
        if all_pane:
            all_pane._append_colored("INFO", message)

    # ─────────────────────────────────────────────────────
    # Tailing
    # ─────────────────────────────────────────────────────

    def _tail_all(self) -> None:
        """Tail all log files across all panes."""
        for pane in self._panes.values():
            try:
                pane.tail()
            except Exception as _exc:
                logger.debug(f"log viewer error: {_exc}")

        # Also refresh stdout log discovery (new scans may have started)
        stdout_pane = self._panes.get("stdout")
        if stdout_pane:
            new_paths = self._discover_stdout_logs()
            if set(new_paths) != set(stdout_pane._log_paths):
                stdout_pane._log_paths = new_paths

    # ─────────────────────────────────────────────────────
    # Slots
    # ─────────────────────────────────────────────────────

    def _on_auto_scroll_toggle(self, checked: bool) -> None:
        for pane in self._panes.values():
            pane.set_auto_scroll(checked)

    def _on_clear(self) -> None:
        idx = self._tab_widget.currentIndex()
        pane = list(self._panes.values())[idx] if idx < len(self._panes) else None
        if pane:
            pane.clear()

    def _on_export(self) -> None:
        idx = self._tab_widget.currentIndex()
        pane = list(self._panes.values())[idx] if idx < len(self._panes) else None
        if not pane:
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Logs",
            f"whai_logs_{datetime.now():%Y%m%d_%H%M%S}.txt",
            "Text Files (*.txt)"
        )
        if path:
            Path(path).write_text(pane.get_text())
