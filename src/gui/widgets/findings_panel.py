"""
WhiteHatHacker AI — Findings Panel

Displays vulnerability findings in a sortable/filterable table:
  - Severity colour coding (Critical=red, High=orange, …)
  - Status column (raw / verified / false_positive)
  - Click to expand full finding detail
  - Export selected findings
  - Load from scan workspace
"""

from __future__ import annotations

import json
from pathlib import Path

from loguru import logger
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QBrush
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
    QGroupBox,
    QSplitter,
    QFileDialog,
    QMessageBox,
)


_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff1744",
    "high": "#ff6d00",
    "medium": "#ffd600",
    "low": "#00c853",
    "info": "#2979ff",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class FindingsPanel(QWidget):
    """Findings table with detail expansion."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._findings: list[dict] = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # ── Filters Row ───────────────────────────────
        filter_row = QHBoxLayout()

        self._severity_combo = QComboBox()
        self._severity_combo.addItems(
            ["All Severities", "Critical", "High", "Medium", "Low", "Info"]
        )
        self._severity_combo.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self._severity_combo)

        self._status_combo = QComboBox()
        self._status_combo.addItems(
            ["All Statuses", "Raw", "Verified", "False Positive"]
        )
        self._status_combo.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self._status_combo)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("🔎 Search findings...")
        self._search_input.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self._search_input, 1)

        self._load_btn = QPushButton("📂 Load Workspace")
        self._load_btn.clicked.connect(self._on_load_workspace)
        filter_row.addWidget(self._load_btn)

        self._export_btn = QPushButton("💾 Export")
        self._export_btn.clicked.connect(self._on_export)
        filter_row.addWidget(self._export_btn)

        layout.addLayout(filter_row)

        # ── Stats Bar ─────────────────────────────────
        self._stats_label = QLabel("No findings loaded")
        self._stats_label.setStyleSheet("color: #888; font-size: 10px; padding: 2px;")
        layout.addWidget(self._stats_label)

        # ── Splitter: Table + Detail ──────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Severity", "Title", "Tool", "Status", "Confidence", "Target"]
        )
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 80)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(3, 100)
        self._table.setColumnWidth(4, 80)
        self._table.setColumnWidth(5, 180)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.currentCellChanged.connect(self._on_row_selected)
        self._table.setSortingEnabled(True)
        splitter.addWidget(self._table)

        # Detail pane
        detail_group = QGroupBox("Finding Details")
        detail_layout = QVBoxLayout(detail_group)
        self._detail_view = QTextEdit()
        self._detail_view.setReadOnly(True)
        self._detail_view.setFont(QFont("Fira Code", 9))
        self._detail_view.setStyleSheet("background: #0d0d0d; color: #ccc;")
        detail_layout.addWidget(self._detail_view)
        splitter.addWidget(detail_group)

        splitter.setSizes([500, 250])
        layout.addWidget(splitter, 1)

    # ─────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────

    def add_finding(self, finding: dict) -> None:
        self._findings.append(finding)
        self._apply_filter()

    def set_findings(self, findings: list[dict]) -> None:
        self._findings = list(findings)
        self._apply_filter()

    def load_from_workspace(self, workspace_path: str) -> None:
        """Load findings from a scan workspace directory."""
        ws = Path(workspace_path)
        findings: list[dict] = []

        for category in ("raw", "verified", "false_positives"):
            d = ws / "04_findings" / category
            if not d.exists():
                continue
            for f in d.glob("*.json"):
                try:
                    data = json.loads(f.read_text())
                    data.setdefault("status", category)
                    findings.append(data)
                except Exception as _exc:
                    logger.debug(f"findings panel error: {_exc}")

        self._findings = findings
        self._apply_filter()

    def load_from_scan_state(self, state: dict) -> None:
        """Load findings from a scan state dict (output/scans/*_state.json).

        Classification mirrors the pipeline logic in full_scan.py:
        1. fp_reason → false_positive
        2. confidence_score >= 50 → verified
        3. Everything else → raw (low confidence or unscored)

        Also deduplicates by (norm_title, tool), keeping highest confidence,
        just like the pipeline does after brain verification.
        """
        findings: list[dict] = []
        raw_findings_list = state.get("findings", [])

        # Separate verified list if the state stores it (future scans)
        verified_list = state.get("verified_findings_list")

        # If we have an explicit verified list, use it to tag findings
        verified_keys: set[str] | None = None
        if isinstance(verified_list, list) and verified_list:
            verified_keys = set()
            for vf in verified_list:
                k = f"{(vf.get('title') or '')[:60].lower()}||{vf.get('tool', '')}"
                verified_keys.add(k)

        for f in raw_findings_list:
            entry = dict(f)  # shallow copy

            # Classify
            if entry.get("fp_reason"):
                entry["status"] = "false_positive"
            elif verified_keys is not None:
                # Use explicit verified list for matching
                k = f"{(entry.get('title') or '')[:60].lower()}||{entry.get('tool', '')}"
                entry["status"] = "verified" if k in verified_keys else "raw"
            elif (entry.get("confidence_score") or 0) >= 50:
                entry["status"] = "verified"
            elif (entry.get("confidence_score") or 0) < 30:
                entry["status"] = "false_positive"
            else:
                entry["status"] = "raw"

            # Normalize field names for display
            entry.setdefault("tool_name", entry.get("tool", "-"))
            entry.setdefault("confidence",
                             entry.get("confidence_score",
                                       entry.get("brain_confidence", "-")))
            entry.setdefault("target", entry.get("url", "-"))

            findings.append(entry)

        # ─── Dedup by (norm_title, tool) — keep highest confidence ───
        seen: dict[str, dict] = {}
        for f in findings:
            raw_title = (f.get("title") or "").strip()
            norm_title = raw_title[:60].lower()
            tool = f.get("tool", f.get("tool_name", ""))
            key = f"{norm_title}||{tool}"
            existing = seen.get(key)
            if existing is None:
                seen[key] = f
            else:
                if (f.get("confidence_score") or 0) > (existing.get("confidence_score") or 0):
                    seen[key] = f
        deduped = list(seen.values())

        self._findings = deduped
        self._apply_filter()

        # Stats from state-level counts (authoritative)
        verified_count = state.get("verified_findings", 0)
        if isinstance(verified_count, list):
            verified_count = len(verified_count)
        fp_count = state.get("false_positives", 0)
        if isinstance(fp_count, list):
            fp_count = len(fp_count)

        target = state.get("target", "?")
        sid = state.get("session_id", "?")[:8]
        dup_count = len(findings) - len(deduped)
        self._stats_label.setText(
            f"Scan: {target} [{sid}] | "
            f"{len(deduped)} unique findings ({dup_count} dupes removed) | "
            f"{verified_count} pipeline-verified | {fp_count} FP"
        )

    # ─────────────────────────────────────────────────────
    # Filter & Refresh
    # ─────────────────────────────────────────────────────

    def _apply_filter(self) -> None:
        sev_filter = self._severity_combo.currentText().lower()
        status_filter = self._status_combo.currentText().lower()
        search = self._search_input.text().lower().strip()

        filtered = []
        for f in self._findings:
            sev = (f.get("severity") or "info").lower()
            status = (f.get("status") or "raw").lower()

            if sev_filter != "all severities" and sev != sev_filter:
                continue
            if status_filter != "all statuses" and status.replace("_", " ") != status_filter:
                continue
            if search:
                haystack = json.dumps(f).lower()
                if search not in haystack:
                    continue
            filtered.append(f)

        # Sort by severity
        filtered.sort(key=lambda x: _SEVERITY_ORDER.get(
            (x.get("severity") or "info").lower(), 9
        ))

        self._rebuild_table(filtered)
        self._update_stats()

    def _rebuild_table(self, findings: list[dict]) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(findings))

        for i, f in enumerate(findings):
            sev = (f.get("severity") or "info").lower()
            color = _SEVERITY_COLORS.get(sev, "#808080")

            sev_item = QTableWidgetItem(sev.upper())
            sev_item.setForeground(QBrush(QColor(color)))
            sev_item.setFont(QFont("", 9, QFont.Weight.Bold))
            self._table.setItem(i, 0, sev_item)

            self._table.setItem(i, 1, QTableWidgetItem(
                f.get("title") or f.get("name", "Untitled")
            ))
            self._table.setItem(i, 2, QTableWidgetItem(
                f.get("tool_name") or f.get("tool", "-")
            ))

            status = (f.get("status") or "raw").replace("_", " ").title()
            self._table.setItem(i, 3, QTableWidgetItem(status))

            conf = f.get("confidence", f.get("confidence_score", ""))
            self._table.setItem(i, 4, QTableWidgetItem(str(conf)))

            self._table.setItem(i, 5, QTableWidgetItem(
                f.get("target") or f.get("url", "-")
            ))

            # Store full data
            self._table.item(i, 0).setData(Qt.ItemDataRole.UserRole, f)

        self._table.setSortingEnabled(True)

    def _update_stats(self) -> None:
        total = len(self._findings)
        counts: dict[str, int] = {}
        for f in self._findings:
            sev = (f.get("severity") or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        parts = [f"Total: {total}"]
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in counts:
                parts.append(f"{sev.title()}: {counts[sev]}")
        self._stats_label.setText("  |  ".join(parts))

    def _on_row_selected(self, row: int, *_args) -> None:
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        finding = item.data(Qt.ItemDataRole.UserRole)
        if not finding:
            return

        # Render detail
        html = self._format_finding_html(finding)
        self._detail_view.setHtml(html)

    def _format_finding_html(self, f: dict) -> str:
        import html as _html
        _e = _html.escape  # shorthand for HTML-escaping user-controlled data
        sev = (f.get("severity") or "info").lower()
        color = _SEVERITY_COLORS.get(sev, "#888")
        status = (f.get("status") or "raw").replace("_", " ").title()
        conf = f.get("confidence", f.get("confidence_score", "-"))
        status_color_map = {'verified': '#00c853', 'false_positive': '#ff6d00', 'raw': '#ffd600'}
        status_color = status_color_map.get(f.get('status', 'raw'), '#888')
        lines = [
            f"<h3 style='color:{color}'>[{sev.upper()}] {_e(str(f.get('title', 'Untitled')))}</h3>",
            f"<b>Tool:</b> {_e(str(f.get('tool_name', f.get('tool', '-'))))}<br>",
            f"<b>Target:</b> {_e(str(f.get('target', f.get('url', '-'))))}<br>",
            f"<b>Status:</b> <span style='color:{status_color}'>{_e(status)}</span><br>",
            f"<b>Confidence Score:</b> {_e(str(conf))}<br>",
        ]

        # Parameter / Payload
        if f.get("parameter"):
            lines.append(f"<b>Parameter:</b> {_e(str(f['parameter']))}<br>")
        if f.get("payload"):
            lines.append(f"<b>Payload:</b> <code>{_e(str(f['payload']))}</code><br>")

        # CVSS
        if f.get("cvss_score"):
            lines.append(f"<b>CVSS:</b> {_e(str(f['cvss_score']))}<br>")

        # Brain Verification Details
        if f.get("brain_verified") is not None:
            bc = _e(str(f.get("brain_confidence", "-")))
            lines.append("<br><b style='color:#64b5f6'>🧠 Brain Verification:</b><br>")
            lines.append(f"&nbsp;&nbsp;Brain Verified: {'✅ Yes' if f.get('brain_verified') else '❌ No'}<br>")
            lines.append(f"&nbsp;&nbsp;Brain Confidence: {bc}<br>")
            if f.get("exploit_feasibility"):
                lines.append(f"&nbsp;&nbsp;Exploit Feasibility: {_e(str(f['exploit_feasibility']))}<br>")
            if f.get("brain_reasoning"):
                lines.append(f"&nbsp;&nbsp;Reasoning: <i>{_e(str(f['brain_reasoning']))}</i><br>")
            if f.get("brain_fp_warning"):
                lines.append(f"&nbsp;&nbsp;<span style='color:#ff6d00'>⚠ FP Warning: {_e(str(f['brain_fp_warning']))}</span><br>")
            if f.get("brain_poc_steps"):
                steps = f["brain_poc_steps"]
                if isinstance(steps, list):
                    steps = "<br>".join(f"&nbsp;&nbsp;{i+1}. {_e(str(s))}" for i, s in enumerate(steps))
                else:
                    steps = _e(str(steps))
                lines.append(f"&nbsp;&nbsp;PoC Steps:<br>{steps}<br>")

        # FP Reason
        if f.get("fp_reason"):
            lines.append(f"<br><span style='color:#ff6d00'><b>FP Reason:</b> {_e(str(f['fp_reason']))}</span><br>")

        # Description
        if f.get("description"):
            lines.append(f"<br><b>Description:</b><br>{_e(str(f['description']))}<br>")

        # Evidence
        if f.get("evidence"):
            lines.append(f"<br><b>Evidence:</b><br><pre>{_e(str(f['evidence']))}</pre>")

        # HTTP Request/Response
        if f.get("http_request") or f.get("request"):
            req = f.get("http_request") or f.get("request", "")
            lines.append(f"<br><b>HTTP Request:</b><br><pre>{_e(str(req)[:3000])}</pre>")
        if f.get("http_response") or f.get("response"):
            resp = str(f.get("http_response") or f.get("response", ""))[:3000]
            lines.append(f"<br><b>HTTP Response (truncated):</b><br><pre>{_e(resp)}</pre>")

        # Tags
        if f.get("tags"):
            tags = f["tags"]
            if isinstance(tags, list):
                tags = ", ".join(str(t) for t in tags)
            lines.append(f"<br><b>Tags:</b> {_e(str(tags))}")

        # Remediation
        if f.get("remediation"):
            lines.append(f"<br><b>Remediation:</b><br>{_e(str(f['remediation']))}")

        return "\n".join(lines)

    # ─────────────────────────────────────────────────────
    # Load / Export
    # ─────────────────────────────────────────────────────

    def _on_load_workspace(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Select Scan Workspace", "output/scans"
        )
        if folder:
            self.load_from_workspace(folder)

    def _on_export(self) -> None:
        if not self._findings:
            QMessageBox.information(self, "Export", "No findings to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Findings", "findings.json", "JSON Files (*.json)"
        )
        if path:
            Path(path).write_text(
                json.dumps(self._findings, indent=2, ensure_ascii=False)
            )
            QMessageBox.information(
                self, "Export", f"Exported {len(self._findings)} findings."
            )
