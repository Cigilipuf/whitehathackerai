"""
WhiteHatHacker AI — Live Process Viewer Widget (v2.1)

Real-time view of bot operations:
  - Brain LLM calls (prompts, responses, model used, duration)
  - Tool executions (command, args, exit code, duration)
  - Stage transitions (workflow progress)
  - Findings discovered in real-time
  - All data parsed from JSON log files
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from loguru import logger
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor, QBrush
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
)


# ── Helpers ──────────────────────────────────────────────────

def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _extract_brain_calls(log_path: Path, after_pos: int = 0) -> tuple[list[dict], int]:
    """Extract brain LLM call records from a JSON log file."""
    calls = []
    new_pos = after_pos
    if not log_path.exists():
        return calls, new_pos

    try:
        with open(log_path, "r", errors="replace") as f:
            f.seek(after_pos)
            data = f.read()
            new_pos = f.tell()

        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                rec = entry.get("record", {})
                msg = rec.get("message", "")
                extra = rec.get("extra", {})
                time_obj = rec.get("time", {})
                timestamp = time_obj.get("repr", "")[:19] if isinstance(time_obj, dict) else ""

                # Brain call patterns
                if any(kw in msg.lower() for kw in ("brain", "inference", "llm", "model")):
                    calls.append({
                        "time": timestamp,
                        "message": msg,
                        "model": extra.get("model", ""),
                        "duration": extra.get("duration_ms", ""),
                        "function": rec.get("function", ""),
                        "module": rec.get("name", ""),
                        "level": rec.get("level", {}).get("name", "INFO"),
                    })
            except (json.JSONDecodeError, KeyError):
                pass
    except Exception as _exc:
        logger.debug(f"process viewer error: {_exc}")

    return calls, new_pos


def _extract_tool_runs(log_path: Path, after_pos: int = 0) -> tuple[list[dict], int]:
    """Extract tool execution records from a JSON log file."""
    runs = []
    new_pos = after_pos
    if not log_path.exists():
        return runs, new_pos

    try:
        with open(log_path, "r", errors="replace") as f:
            f.seek(after_pos)
            data = f.read()
            new_pos = f.tell()

        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                rec = entry.get("record", {})
                msg = rec.get("message", "")
                extra = rec.get("extra", {})
                time_obj = rec.get("time", {})
                timestamp = time_obj.get("repr", "")[:19] if isinstance(time_obj, dict) else ""

                # Tool execution patterns
                if any(kw in msg.lower() for kw in (
                    "running", "completed", "tool", "execute", "command",
                    "nuclei", "nmap", "sqlmap", "dalfox", "httpx",
                    "subfinder", "katana", "gospider", "ffuf", "nikto",
                )):
                    runs.append({
                        "time": timestamp,
                        "message": msg,
                        "tool": extra.get("tool_name", ""),
                        "duration": extra.get("duration_ms", ""),
                        "exit_code": extra.get("exit_code", ""),
                        "function": rec.get("function", ""),
                        "level": rec.get("level", {}).get("name", "INFO"),
                    })
            except (json.JSONDecodeError, KeyError):
                pass
    except Exception as _exc:
        logger.debug(f"process viewer error: {_exc}")

    return runs, new_pos


# ────────────────────────────────────────────────────────────
# Brain Activity Panel
# ────────────────────────────────────────────────────────────


class BrainActivityPanel(QWidget):
    """Shows LLM brain calls with prompts, responses, timing."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._calls: list[dict] = []
        self._tail_pos: int = 0
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        # Stats bar
        stats_row = QHBoxLayout()
        self._call_count_label = QLabel("Brain Calls: 0")
        self._call_count_label.setStyleSheet("color: #6c63ff; font-weight: bold;")
        stats_row.addWidget(self._call_count_label)
        stats_row.addStretch()

        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self._clear)
        stats_row.addWidget(clear_btn)
        layout.addLayout(stats_row)

        # Splitter: table + detail
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Time", "Level", "Module", "Message", "Duration"]
        )
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(0, 140)
        self._table.setColumnWidth(1, 70)
        self._table.setColumnWidth(2, 150)
        self._table.setColumnWidth(4, 80)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.currentCellChanged.connect(self._on_row_selected)
        splitter.addWidget(self._table)

        # Detail
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setFont(QFont("Fira Code", 9))
        self._detail.setStyleSheet("background: #0a0a0a; color: #ccc;")
        self._detail.setPlaceholderText("Select a brain call to see details...")
        splitter.addWidget(self._detail)

        splitter.setSizes([400, 200])
        layout.addWidget(splitter, 1)

    def tail(self) -> None:
        """Read new brain calls from log file."""
        today = datetime.now().strftime("%Y-%m-%d")
        log_path = Path(f"output/logs/brain_{today}.log")

        new_calls, self._tail_pos = _extract_brain_calls(log_path, self._tail_pos)
        if new_calls:
            self._calls.extend(new_calls)
            self._update_table(new_calls)
            self._call_count_label.setText(f"Brain Calls: {len(self._calls)}")

    def _update_table(self, new_calls: list[dict]) -> None:
        """Append new rows to table."""
        for call in new_calls:
            row = self._table.rowCount()
            self._table.insertRow(row)

            level = call.get("level", "INFO")
            level_colors = {"WARNING": "#ffc107", "ERROR": "#dc3545", "DEBUG": "#6c757d"}

            self._table.setItem(row, 0, QTableWidgetItem(call.get("time", "")))

            lvl_item = QTableWidgetItem(level)
            if level in level_colors:
                lvl_item.setForeground(QBrush(QColor(level_colors[level])))
            else:
                lvl_item.setForeground(QBrush(QColor("#6c63ff")))
            self._table.setItem(row, 1, lvl_item)

            self._table.setItem(row, 2, QTableWidgetItem(call.get("module", "")))

            msg_item = QTableWidgetItem(call.get("message", "")[:200])
            self._table.setItem(row, 3, msg_item)

            dur = call.get("duration", "")
            dur_text = f"{dur}ms" if dur else ""
            self._table.setItem(row, 4, QTableWidgetItem(dur_text))

            # Store full data
            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, call)

        # Auto-scroll to bottom
        self._table.scrollToBottom()

    def _on_row_selected(self, row: int, *_args) -> None:
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        call = item.data(Qt.ItemDataRole.UserRole)
        if call:
            self._detail.setHtml(
                f"<h4 style='color:#6c63ff'>Brain Call</h4>"
                f"<b>Time:</b> {call.get('time', '')}<br>"
                f"<b>Module:</b> {call.get('module', '')}<br>"
                f"<b>Function:</b> {call.get('function', '')}<br>"
                f"<b>Model:</b> {call.get('model', 'N/A')}<br>"
                f"<b>Duration:</b> {call.get('duration', 'N/A')}ms<br>"
                f"<br><b>Message:</b><br>"
                f"<pre>{_html_escape(call.get('message', ''))}</pre>"
            )

    def _clear(self) -> None:
        self._calls.clear()
        self._table.setRowCount(0)
        self._detail.clear()
        self._call_count_label.setText("Brain Calls: 0")


# ────────────────────────────────────────────────────────────
# Tool Execution Panel
# ────────────────────────────────────────────────────────────


class ToolExecutionPanel(QWidget):
    """Shows tool/command executions with timing and results."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._runs: list[dict] = []
        self._tail_positions: dict[str, int] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        stats_row = QHBoxLayout()
        self._tool_count_label = QLabel("Tool Executions: 0")
        self._tool_count_label.setStyleSheet("color: #00d4ff; font-weight: bold;")
        stats_row.addWidget(self._tool_count_label)
        stats_row.addStretch()

        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self._clear)
        stats_row.addWidget(clear_btn)
        layout.addLayout(stats_row)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Time", "Level", "Tool", "Message", "Duration"]
        )
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(0, 140)
        self._table.setColumnWidth(1, 70)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(4, 80)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.currentCellChanged.connect(self._on_row_selected)
        splitter.addWidget(self._table)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setFont(QFont("Fira Code", 9))
        self._detail.setStyleSheet("background: #0a0a0a; color: #ccc;")
        self._detail.setPlaceholderText("Select a tool execution to see details...")
        splitter.addWidget(self._detail)

        splitter.setSizes([400, 200])
        layout.addWidget(splitter, 1)

    def tail(self) -> None:
        """Read new tool execution records from log files."""
        today = datetime.now().strftime("%Y-%m-%d")
        # Check both tools log and brain log (tools are logged in both)
        for log_name in (f"output/logs/tools_{today}.log", f"output/logs/brain_{today}.log"):
            log_path = Path(log_name)
            prev_pos = self._tail_positions.get(log_name, 0)
            new_runs, pos = _extract_tool_runs(log_path, prev_pos)
            self._tail_positions[log_name] = pos
            if new_runs:
                self._runs.extend(new_runs)
                self._update_table(new_runs)
                self._tool_count_label.setText(f"Tool Executions: {len(self._runs)}")

    def _update_table(self, new_runs: list[dict]) -> None:
        for run in new_runs:
            row = self._table.rowCount()
            self._table.insertRow(row)

            self._table.setItem(row, 0, QTableWidgetItem(run.get("time", "")))

            level = run.get("level", "INFO")
            lvl_item = QTableWidgetItem(level)
            if level == "ERROR":
                lvl_item.setForeground(QBrush(QColor("#dc3545")))
            elif level == "WARNING":
                lvl_item.setForeground(QBrush(QColor("#ffc107")))
            else:
                lvl_item.setForeground(QBrush(QColor("#00d4ff")))
            self._table.setItem(row, 1, lvl_item)

            tool = run.get("tool", "") or run.get("function", "")
            self._table.setItem(row, 2, QTableWidgetItem(tool))

            self._table.setItem(row, 3, QTableWidgetItem(run.get("message", "")[:200]))

            dur = run.get("duration", "")
            dur_text = f"{dur}ms" if dur else ""
            self._table.setItem(row, 4, QTableWidgetItem(dur_text))

            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, run)

        self._table.scrollToBottom()

    def _on_row_selected(self, row: int, *_args) -> None:
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        run = item.data(Qt.ItemDataRole.UserRole)
        if run:
            exit_code = run.get("exit_code", "")
            self._detail.setHtml(
                f"<h4 style='color:#00d4ff'>Tool Execution</h4>"
                f"<b>Time:</b> {run.get('time', '')}<br>"
                f"<b>Tool:</b> {run.get('tool', 'N/A')}<br>"
                f"<b>Function:</b> {run.get('function', '')}<br>"
                f"<b>Exit Code:</b> {exit_code if exit_code != '' else 'N/A'}<br>"
                f"<b>Duration:</b> {run.get('duration', 'N/A')}ms<br>"
                f"<br><b>Message:</b><br>"
                f"<pre>{_html_escape(run.get('message', ''))}</pre>"
            )

    def _clear(self) -> None:
        self._runs.clear()
        self._table.setRowCount(0)
        self._detail.clear()
        self._tool_count_label.setText("Tool Executions: 0")


# ────────────────────────────────────────────────────────────
# Stdout Live Feed
# ────────────────────────────────────────────────────────────


class StdoutFeedPanel(QWidget):
    """Live feed of the latest scan's stdout output."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._tail_pos: int = 0
        self._current_log: str = ""
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        stats_row = QHBoxLayout()
        self._log_name_label = QLabel("No active scan log")
        self._log_name_label.setStyleSheet("color: #00c853; font-weight: bold;")
        stats_row.addWidget(self._log_name_label)
        stats_row.addStretch()

        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(lambda: (self._output.clear(), None))
        stats_row.addWidget(clear_btn)
        layout.addLayout(stats_row)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Fira Code", 9))
        self._output.setStyleSheet("background: #0a0a0a; color: #b0b0b0;")
        layout.addWidget(self._output, 1)

    def tail(self) -> None:
        """Find and tail the most recent scan stdout log."""
        log_dir = Path("output/logs")
        if not log_dir.exists():
            return

        # Find latest scan stdout log
        stdout_logs = sorted(log_dir.glob("scan*_stdout.log"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not stdout_logs:
            return

        latest = str(stdout_logs[0])
        if latest != self._current_log:
            # New log file detected
            self._current_log = latest
            self._tail_pos = 0
            self._output.clear()
            self._log_name_label.setText(f"📺 {stdout_logs[0].name}")

        try:
            with open(latest, "r", errors="replace") as f:
                f.seek(self._tail_pos)
                new_data = f.read()
                self._tail_pos = f.tell()

            if new_data:
                for line in new_data.splitlines():
                    stripped = line.strip()
                    if not stripped:
                        continue

                    # Color based on content
                    color = "#b0b0b0"
                    upper = stripped.upper()
                    if "ERROR" in upper[:30] or "FAILED" in upper:
                        color = "#dc3545"
                    elif "WARNING" in upper[:30]:
                        color = "#ffc107"
                    elif "CRITICAL" in upper or "HIGH" in upper:
                        color = "#ff6d00"
                    elif "[FINDING]" in stripped:
                        color = "#ff6d00"
                    elif "✅" in stripped or "COMPLETED" in upper or "SUCCESS" in upper:
                        color = "#00c853"
                    elif "STAGE" in upper or "PHASE" in upper:
                        color = "#6c63ff"
                    elif "BRAIN" in upper or "LLM" in upper:
                        color = "#6c63ff"

                    self._output.append(
                        f'<span style="color:{color}">{_html_escape(stripped)}</span>'
                    )

                # Auto-scroll
                sb = self._output.verticalScrollBar()
                sb.setValue(sb.maximum())
        except Exception as _exc:
            logger.debug(f"process viewer error: {_exc}")


# ────────────────────────────────────────────────────────────
# Main Process Viewer Widget
# ────────────────────────────────────────────────────────────


class ProcessViewerWidget(QWidget):
    """Combined live process viewer with tabs for brain, tools, and stdout."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._build_ui()

        # Tail timer
        self._tail_timer = QTimer(self)
        self._tail_timer.timeout.connect(self._tail_all)
        self._tail_timer.start(3_000)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        header = QLabel("⚡ Live Process Viewer")
        header.setFont(QFont("", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff; padding: 4px;")
        layout.addWidget(header)

        # Description
        desc = QLabel(
            "Real-time view of bot operations: Brain LLM calls, tool executions, "
            "and scan output. Data is parsed from log files and updates every 3 seconds."
        )
        desc.setStyleSheet("color: #8b949e; font-size: 10px; padding: 2px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Tabs
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        self._stdout_panel = StdoutFeedPanel()
        self._brain_panel = BrainActivityPanel()
        self._tool_panel = ToolExecutionPanel()

        self._tabs.addTab(self._stdout_panel, "📺 Live Scan Output")
        self._tabs.addTab(self._brain_panel, "🧠 Brain Activity")
        self._tabs.addTab(self._tool_panel, "🔧 Tool Executions")

        layout.addWidget(self._tabs, 1)

    def _tail_all(self) -> None:
        """Tail all panels."""
        try:
            self._stdout_panel.tail()
        except Exception as _exc:
            logger.debug(f"process viewer error: {_exc}")
        try:
            self._brain_panel.tail()
        except Exception as _exc:
            logger.debug(f"process viewer error: {_exc}")
        try:
            self._tool_panel.tail()
        except Exception as _exc:
            logger.debug(f"process viewer error: {_exc}")
