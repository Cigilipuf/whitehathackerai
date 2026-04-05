"""
WhiteHatHacker AI — Dashboard Widget (v2.1)

Overview panel showing:
  - Quick stats (total scans, findings by severity, programs scanned)
  - Recent scans table loaded from output/scans/*_state.json
  - Severity distribution bar
  - Disk usage meter
  - System health indicators
  - Click-to-view scan detail & findings
"""

from __future__ import annotations

import json
from pathlib import Path

from loguru import logger
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QColor, QBrush
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QFrame,
    QGroupBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QMessageBox,
)


# ── Severity colors ─────────────────────────────────────────

_SEV_COLORS = {
    "critical": "#ff1744",
    "high": "#ff6d00",
    "medium": "#ffd600",
    "low": "#00c853",
    "info": "#2979ff",
}


# ────────────────────────────────────────────────────────────
# Stat Card
# ────────────────────────────────────────────────────────────


class StatCard(QFrame):
    """Small metrics card for the dashboard grid."""

    def __init__(
        self,
        label: str,
        value: str = "0",
        color: str = "#00d4ff",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFixedHeight(90)
        self.setMinimumWidth(120)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        self._value_label = QLabel(value)
        self._value_label.setFont(QFont("", 24, QFont.Weight.Bold))
        self._value_label.setStyleSheet(f"color: {color};")
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._value_label)

        self._label = QLabel(label)
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(self._label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)


# ────────────────────────────────────────────────────────────
# Severity Distribution Bar
# ────────────────────────────────────────────────────────────


class SeverityBar(QWidget):
    """Horizontal stacked bar showing severity distribution."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setFixedHeight(40)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 4, 0, 4)
        self._layout.setSpacing(2)
        self._segments: list[QFrame] = []

    def set_counts(self, counts: dict[str, int]) -> None:
        """Update bar with severity counts."""
        # Clear existing
        for seg in self._segments:
            self._layout.removeWidget(seg)
            seg.deleteLater()
        self._segments.clear()

        total = sum(counts.values())
        if total == 0:
            return

        for sev_name in ("critical", "high", "medium", "low", "info"):
            count = counts.get(sev_name, 0)
            if count == 0:
                continue
            color = _SEV_COLORS.get(sev_name, "#555")
            seg = QFrame()
            seg.setStyleSheet(
                f"background: {color}; border-radius: 3px; min-width: 8px;"
            )
            seg.setToolTip(f"{sev_name.title()}: {count}")
            self._layout.addWidget(seg, count)
            self._segments.append(seg)


# ────────────────────────────────────────────────────────────
# Dashboard Widget
# ────────────────────────────────────────────────────────────


class DashboardWidget(QWidget):
    """Main dashboard with stats and recent scans."""

    # Signal emitted when user clicks a scan row (sends full state data)
    scan_selected = Signal(dict)
    disk_info_ready = Signal(dict)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._scan_states: list[dict] = []
        self.disk_info_ready.connect(self._apply_disk_info)

        self._build_ui()

        # Auto-refresh every 15 seconds
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start(15_000)

        QTimer.singleShot(500, self.refresh)

    def _build_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(12)

        # ── Welcome Header ────────────────────────────
        header_row = QHBoxLayout()
        header = QLabel("📊 Dashboard — WhiteHatHacker AI v2.1")
        header.setFont(QFont("", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff; padding: 4px;")
        header_row.addWidget(header)
        header_row.addStretch()

        self._refresh_btn = QPushButton("⟳ Refresh")
        self._refresh_btn.setStyleSheet(
            "QPushButton { background: #1a3a5c; color: #00d4ff; "
            "padding: 6px 14px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background: #1d4e7a; }"
        )
        self._refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self._refresh_btn)
        layout.addLayout(header_row)

        # ── Stats Row ─────────────────────────────────
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)

        self._card_targets = StatCard("Targets", "0", "#6c63ff")
        self._card_scans = StatCard("Total Scans", "0", "#00d4ff")
        self._card_findings = StatCard("Total Findings", "0", "#ff6d00")
        self._card_verified = StatCard("Verified", "0", "#00c853")
        self._card_critical = StatCard("Critical", "0", "#ff1744")
        self._card_high = StatCard("High", "0", "#ff6d00")
        self._card_medium = StatCard("Medium", "0", "#ffd600")
        self._card_fp_rate = StatCard("FP Rate", "0%", "#8b949e")

        for card in (
            self._card_targets, self._card_scans, self._card_findings,
            self._card_verified, self._card_critical, self._card_high,
            self._card_medium, self._card_fp_rate,
        ):
            stats_layout.addWidget(card)

        layout.addLayout(stats_layout)

        # ── Severity Distribution ─────────────────────
        sev_group = QGroupBox("Severity Distribution")
        sev_layout = QVBoxLayout(sev_group)
        self._severity_bar = SeverityBar()
        sev_layout.addWidget(self._severity_bar)
        self._sev_legend = QLabel("")
        self._sev_legend.setStyleSheet("color: #8b949e; font-size: 9px;")
        sev_layout.addWidget(self._sev_legend)
        layout.addWidget(sev_group)

        # ── Recent Scans ─────────────────────────────
        scans_group = QGroupBox("Scan History (click a row to preview, double-click to load findings)")
        scans_layout = QVBoxLayout(scans_group)

        self._scans_table = QTableWidget(0, 8)
        self._scans_table.setHorizontalHeaderLabels(
            ["#", "Target", "Duration", "Subdomains", "Raw", "Verified", "FP", "Session ID"]
        )
        header_obj = self._scans_table.horizontalHeader()
        header_obj.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header_obj.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self._scans_table.setColumnWidth(0, 35)
        self._scans_table.setColumnWidth(2, 80)
        self._scans_table.setColumnWidth(3, 90)
        self._scans_table.setColumnWidth(4, 55)
        self._scans_table.setColumnWidth(5, 70)
        self._scans_table.setColumnWidth(6, 45)
        self._scans_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._scans_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._scans_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self._scans_table.cellDoubleClicked.connect(self._on_scan_double_click)
        self._scans_table.currentCellChanged.connect(self._on_scan_row_changed)
        scans_layout.addWidget(self._scans_table)

        # Scan detail preview
        self._scan_detail = QTextEdit()
        self._scan_detail.setReadOnly(True)
        self._scan_detail.setFont(QFont("Fira Code", 9))
        self._scan_detail.setStyleSheet("background: #0a0a0a; color: #b0b0b0;")
        self._scan_detail.setMaximumHeight(160)
        self._scan_detail.setPlaceholderText("Select a scan to preview details...")
        scans_layout.addWidget(self._scan_detail)

        # Buttons
        btn_row = QHBoxLayout()
        self._view_findings_btn = QPushButton("🐛 View Findings")
        self._view_findings_btn.setStyleSheet(
            "QPushButton { background: #1a3a5c; color: #00d4ff; "
            "padding: 6px 14px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background: #1d4e7a; }"
        )
        self._view_findings_btn.clicked.connect(self._on_view_findings_click)
        self._view_findings_btn.setEnabled(False)
        btn_row.addWidget(self._view_findings_btn)

        self._view_report_btn = QPushButton("📄 View Report")
        self._view_report_btn.setStyleSheet(
            "QPushButton { background: #1a3a5c; color: #00d4ff; "
            "padding: 6px 14px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background: #1d4e7a; }"
        )
        self._view_report_btn.clicked.connect(self._on_view_report_click)
        self._view_report_btn.setEnabled(False)
        btn_row.addWidget(self._view_report_btn)

        btn_row.addStretch()

        self._total_duration_label = QLabel("")
        self._total_duration_label.setStyleSheet("color: #8b949e; font-size: 10px;")
        btn_row.addWidget(self._total_duration_label)

        scans_layout.addLayout(btn_row)
        layout.addWidget(scans_group)

        # ── System Info Row ───────────────────────────
        sys_group = QGroupBox("System")
        sys_layout = QGridLayout(sys_group)

        sys_layout.addWidget(QLabel("Output Disk Usage:"), 0, 0)
        self._disk_bar = QProgressBar()
        self._disk_bar.setRange(0, 100)
        self._disk_bar.setTextVisible(True)
        sys_layout.addWidget(self._disk_bar, 0, 1)

        sys_layout.addWidget(QLabel("Log Files:"), 1, 0)
        self._log_label = QLabel("-")
        self._log_label.setStyleSheet("color: #888;")
        sys_layout.addWidget(self._log_label, 1, 1)

        sys_layout.addWidget(QLabel("Reports:"), 2, 0)
        self._report_count_label = QLabel("-")
        self._report_count_label.setStyleSheet("color: #888;")
        sys_layout.addWidget(self._report_count_label, 2, 1)

        sys_layout.addWidget(QLabel("Output Dir:"), 3, 0)
        self._output_label = QLabel(str(Path("output").resolve()))
        self._output_label.setStyleSheet("color: #666; font-size: 9px;")
        sys_layout.addWidget(self._output_label, 3, 1)

        layout.addWidget(sys_group)
        layout.addStretch()

        scroll.setWidget(content)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ─────────────────────────────────────────────────────
    # Refresh
    # ─────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Reload stats from disk."""
        try:
            self._load_scan_states()
            self._refresh_stats()
            self._refresh_scans_table()
            self._refresh_disk()
        except Exception as exc:
            from loguru import logger as _log
            _log.debug(f"Dashboard refresh error: {exc}")

    def _load_scan_states(self) -> None:
        """Load all scan state JSON files from output/scans/."""
        scans_dir = Path("output/scans")
        if not scans_dir.exists():
            self._scan_states = []
            return

        states: list[dict] = []
        for f in scans_dir.iterdir():
            if f.name.endswith("_state.json") and f.is_file():
                try:
                    data = json.loads(f.read_text())
                    data["_file"] = str(f)
                    data.setdefault("_mtime", f.stat().st_mtime)
                    states.append(data)
                except Exception as _exc:
                    logger.debug(f"dashboard error: {_exc}")

        # Also load partial scans
        for f in scans_dir.iterdir():
            if f.name.startswith("partial_") and f.name.endswith(".json") and f.is_file():
                try:
                    data = json.loads(f.read_text())
                    data["_file"] = str(f)
                    data["_partial"] = True
                    data.setdefault("_mtime", f.stat().st_mtime)
                    states.append(data)
                except Exception as _exc:
                    logger.debug(f"dashboard error: {_exc}")

        # Sort by modification time (newest first)
        states.sort(key=lambda x: x.get("_mtime", 0), reverse=True)
        self._scan_states = states

    def _refresh_stats(self) -> None:
        """Update stat cards from loaded scan states."""
        targets: set[str] = set()
        total_scans = len(self._scan_states)
        total_findings = 0
        verified = 0
        critical = 0
        high = 0
        medium = 0
        total_fp = 0
        total_raw = 0

        sev_counts: dict[str, int] = {}

        for state in self._scan_states:
            target = state.get("target", "")
            if target:
                targets.add(target)

            raw = state.get("raw_findings", 0)
            ver = state.get("verified_findings", 0)
            fp = state.get("false_positives", 0)
            # Handle both int (legacy) and list (v2.1+) formats
            if isinstance(raw, list): raw = len(raw)
            if isinstance(ver, list): ver = len(ver)
            if isinstance(fp, list): fp = len(fp)
            total_raw += raw
            verified += ver
            total_fp += fp

            # Count by severity from findings list
            for finding in state.get("findings", []):
                total_findings += 1
                sev = (finding.get("severity") or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                if sev == "critical":
                    critical += 1
                elif sev == "high":
                    high += 1
                elif sev == "medium":
                    medium += 1

        self._card_targets.set_value(str(len(targets)))
        self._card_scans.set_value(str(total_scans))
        self._card_findings.set_value(str(total_findings))
        self._card_verified.set_value(str(verified))
        self._card_critical.set_value(str(critical))
        self._card_high.set_value(str(high))
        self._card_medium.set_value(str(medium))

        # FP rate
        if total_raw > 0:
            fp_pct = round(total_fp / total_raw * 100, 1)
            self._card_fp_rate.set_value(f"{fp_pct}%")
        else:
            self._card_fp_rate.set_value("N/A")

        # Severity bar
        self._severity_bar.set_counts(sev_counts)
        legend_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            c = sev_counts.get(sev, 0)
            if c > 0:
                legend_parts.append(f"{sev.title()}: {c}")
        self._sev_legend.setText(
            "  |  ".join(legend_parts) if legend_parts else "No findings yet"
        )

    def _refresh_scans_table(self) -> None:
        """Populate the scans table from loaded state data."""
        self._scans_table.setRowCount(len(self._scan_states))

        total_duration = 0.0
        for i, state in enumerate(self._scan_states):
            is_partial = state.get("_partial", False)
            scan_num = len(self._scan_states) - i  # reverse numbering

            # # column
            num_item = QTableWidgetItem(str(scan_num))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if is_partial:
                num_item.setForeground(QBrush(QColor("#ffc107")))
            self._scans_table.setItem(i, 0, num_item)

            # Target
            target = state.get("target", "?")
            target_item = QTableWidgetItem(target)
            target_item.setFont(QFont("", 10, QFont.Weight.Bold))
            target_item.setForeground(QBrush(QColor("#00d4ff")))
            self._scans_table.setItem(i, 1, target_item)

            # Duration
            duration = state.get("duration", 0)
            total_duration += duration
            mins = int(duration / 60)
            dur_text = f"{mins}m" if mins > 0 else ("partial" if is_partial else "running...")
            self._scans_table.setItem(i, 2, QTableWidgetItem(dur_text))

            # Subdomains
            subs = state.get("subdomains", 0)
            self._scans_table.setItem(i, 3, QTableWidgetItem(str(subs)))

            # Raw findings
            raw = state.get("raw_findings", 0)
            if isinstance(raw, list): raw = len(raw)
            raw_item = QTableWidgetItem(str(raw))
            self._scans_table.setItem(i, 4, raw_item)

            # Verified
            ver = state.get("verified_findings", 0)
            if isinstance(ver, list): ver = len(ver)
            ver_item = QTableWidgetItem(str(ver))
            if ver > 0:
                ver_item.setForeground(QBrush(QColor("#00c853")))
                ver_item.setFont(QFont("", 10, QFont.Weight.Bold))
            self._scans_table.setItem(i, 5, ver_item)

            # FP
            fp = state.get("false_positives", 0)
            if isinstance(fp, list): fp = len(fp)
            fp_item = QTableWidgetItem(str(fp))
            if fp > 0:
                fp_item.setForeground(QBrush(QColor("#ff6d00")))
            self._scans_table.setItem(i, 6, fp_item)

            # Session ID
            sid = state.get("session_id", "?")
            sid_item = QTableWidgetItem(sid)
            sid_item.setForeground(QBrush(QColor("#666")))
            self._scans_table.setItem(i, 7, sid_item)

            # Store full state data in first column
            self._scans_table.item(i, 0).setData(Qt.ItemDataRole.UserRole, state)

        # Total duration
        total_hrs = total_duration / 3600
        self._total_duration_label.setText(
            f"Total scan time: {total_hrs:.1f}h across {len(self._scan_states)} scans"
        )

    def _refresh_disk(self) -> None:
        """Update disk usage and file counts in a background thread."""
        import threading

        def _calc_disk() -> dict:
            output_dir = Path("output")
            result = {"total_bytes": 0, "log_count": 0, "report_sessions": 0, "report_files": 0}
            if not output_dir.exists():
                return result
            try:
                result["total_bytes"] = sum(
                    f.stat().st_size for f in output_dir.rglob("*") if f.is_file()
                )
            except Exception as _exc:
                logger.debug(f"dashboard error: {_exc}")
            log_dir = Path("output/logs")
            if log_dir.exists():
                try:
                    result["log_count"] = len(list(log_dir.glob("*.log")))
                except Exception as _exc:
                    logger.debug(f"dashboard error: {_exc}")
            report_dir = Path("output/reports")
            if report_dir.exists():
                try:
                    report_dirs = [d for d in report_dir.iterdir() if d.is_dir()]
                    result["report_sessions"] = len(report_dirs)
                    result["report_files"] = sum(len(list(d.glob("*.md"))) for d in report_dirs)
                except Exception as _exc:
                    logger.debug(f"dashboard error: {_exc}")
            return result

        def _bg():
            info = _calc_disk()
            self.disk_info_ready.emit(info)

        # Guard against overlapping disk calculations
        if getattr(self, "_disk_calc_running", False):
            return
        self._disk_calc_running = True
        threading.Thread(target=_bg, daemon=True).start()

    def _apply_disk_info(self, info: dict) -> None:
        """Apply disk usage metrics on the GUI thread."""
        total_bytes = info.get("total_bytes", 0)
        mb = total_bytes / (1024 * 1024)
        gb = mb / 1024
        if gb > 1:
            self._disk_bar.setFormat(f"{gb:.1f} GB")
        else:
            self._disk_bar.setFormat(f"{mb:.0f} MB")
        pct = min(int(gb / 10 * 100), 100)
        self._disk_bar.setValue(pct)
        log_count = info.get("log_count", 0)
        self._log_label.setText(f"{log_count} log files" if log_count else "No logs")
        rs = info.get("report_sessions", 0)
        rf = info.get("report_files", 0)
        self._report_count_label.setText(
            f"{rs} sessions, {rf} report files" if rs else "No reports"
        )

        self._disk_calc_running = False

    # ─────────────────────────────────────────────────────
    # Scan Selection Handlers
    # ─────────────────────────────────────────────────────

    def _get_selected_state(self) -> dict | None:
        """Get the state dict for the currently selected scan row."""
        row = self._scans_table.currentRow()
        if row < 0:
            return None
        item = self._scans_table.item(row, 0)
        if not item:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _on_scan_row_changed(self, row: int, *_args) -> None:
        """Show preview of selected scan."""
        state = self._get_selected_state()
        if not state:
            self._scan_detail.clear()
            self._view_findings_btn.setEnabled(False)
            self._view_report_btn.setEnabled(False)
            return

        self._view_findings_btn.setEnabled(True)
        self._view_report_btn.setEnabled(True)

        # Build preview HTML
        sid = state.get("session_id", "?")
        target = state.get("target", "?")
        profile = state.get("profile", "?")
        mode = state.get("mode", "?")
        duration = state.get("duration", 0)
        stages = state.get("completed_stages", [])
        live_hosts = state.get("live_hosts", [])
        subdomains = state.get("subdomains", 0)
        raw = state.get("raw_findings", 0)
        verified = state.get("verified_findings", 0)
        fp = state.get("false_positives", 0)
        if isinstance(raw, list): raw = len(raw)
        if isinstance(verified, list): verified = len(verified)
        if isinstance(fp, list): fp = len(fp)

        # Count severity from findings
        sev_counts: dict[str, int] = {}
        for f in state.get("findings", []):
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        mins = int(duration / 60)
        secs = int(duration % 60)

        sev_parts = []
        for s in ("critical", "high", "medium", "low", "info"):
            c = sev_counts.get(s, 0)
            if c > 0:
                color = _SEV_COLORS.get(s, "#888")
                sev_parts.append(
                    f"<span style='color:{color};font-weight:bold'>"
                    f"{s.upper()}: {c}</span>"
                )

        host_count = len(live_hosts) if isinstance(live_hosts, list) else live_hosts

        html = (
            f"<h3 style='color:#00d4ff'>Scan: {target}</h3>"
            f"<b>Session:</b> {sid}<br>"
            f"<b>Profile:</b> {profile} | <b>Mode:</b> {mode}<br>"
            f"<b>Duration:</b> {mins}m {secs}s<br>"
            f"<b>Subdomains:</b> {subdomains} | "
            f"<b>Live Hosts:</b> {host_count}<br>"
            f"<b>Findings:</b> {raw} raw &rarr; {verified} verified | "
            f"{fp} FP<br>"
            f"<b>Severity:</b> {'  '.join(sev_parts) if sev_parts else 'None'}<br>"
            f"<b>Stages:</b> {', '.join(stages) if stages else 'Unknown'}"
        )
        self._scan_detail.setHtml(html)

    def _on_scan_double_click(self, row: int, col: int) -> None:
        """Double-click a scan row -> emit scan_selected signal."""
        state = self._get_selected_state()
        if state:
            self.scan_selected.emit(state)

    def _on_view_findings_click(self) -> None:
        """View Findings button clicked -> emit scan_selected signal."""
        state = self._get_selected_state()
        if state:
            self.scan_selected.emit(state)

    def _on_view_report_click(self) -> None:
        """Open the report file for the selected scan."""
        state = self._get_selected_state()
        if not state:
            return

        sid = state.get("session_id", "")
        report_dir = Path("output/reports") / sid
        if not report_dir.exists():
            QMessageBox.information(
                self, "No Report",
                f"No report directory found for session {sid}"
            )
            return

        md_files = list(report_dir.glob("*.md"))
        if not md_files:
            QMessageBox.information(
                self, "No Report",
                f"No markdown report found in {report_dir}"
            )
            return

        # Read and display the first report
        report_text = md_files[0].read_text(errors="replace")
        self._scan_detail.setPlainText(report_text)
