"""
WhiteHatHacker AI — Main Window (v2.1)

Central application window that hosts all panels:
  - Left  : Program browser (HackerOne / Bugcrowd)
  - Right : Tabbed area (Dashboard, Scan, Findings, Process Viewer, Logs, Settings)
  - Bottom: Status bar with brain connection + scan count
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import httpx
from loguru import logger
from PySide6.QtCore import Qt, QTimer, QSize, QSettings
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QSplitter,
    QTabWidget,
    QStatusBar,
    QToolBar,
    QLabel,
    QMessageBox,
)

from src.gui.widgets.program_browser import ProgramBrowserWidget
from src.gui.widgets.dashboard import DashboardWidget
from src.gui.widgets.scan_control import ScanControlWidget
from src.gui.widgets.findings_panel import FindingsPanel
from src.gui.widgets.process_viewer import ProcessViewerWidget
from src.gui.widgets.log_viewer import LogViewerWidget
from src.gui.widgets.settings_panel import SettingsPanel


class MainWindow(QMainWindow):
    """Top-level application window."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("WhiteHatHacker AI v2.1 — Bug Bounty Hunter")
        self.setMinimumSize(1280, 800)
        self.resize(1600, 950)

        # ── Internal state ────────────────────────────────
        self._active_scans: int = 0
        self._total_findings: int = 0

        # ── Build UI ──────────────────────────────────────
        self._build_menubar()
        self._build_toolbar()
        self._build_central()
        self._build_statusbar()

        # ── Wire signals ──────────────────────────────────
        self._wire_signals()

        # Periodic status refresh
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._update_status)
        self._status_timer.start(5_000)

        self._update_status()

        # Restore saved window geometry
        settings = QSettings("WhiteHatHackerAI", "MainWindow")
        geo = settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)
        state = settings.value("windowState")
        if state:
            self.restoreState(state)

    # ─────────────────────────────────────────────────────
    # Menu Bar
    # ─────────────────────────────────────────────────────

    def _build_menubar(self) -> None:
        mb = self.menuBar()

        # ── File ──
        file_menu = mb.addMenu("&File")
        file_menu.addAction(self._action("&New Scan", "Ctrl+N", self._on_new_scan))
        file_menu.addSeparator()
        file_menu.addAction(self._action("&Refresh Programs", "F5", self._on_refresh_programs))
        file_menu.addSeparator()
        file_menu.addAction(self._action("E&xit", "Ctrl+Q", self.close))

        # ── View ──
        view_menu = mb.addMenu("&View")
        view_menu.addAction(self._action("&Dashboard", "Ctrl+1", lambda: self._tabs.setCurrentIndex(0)))
        view_menu.addAction(self._action("&Scan", "Ctrl+2", lambda: self._tabs.setCurrentIndex(1)))
        view_menu.addAction(self._action("&Findings", "Ctrl+3", lambda: self._tabs.setCurrentIndex(2)))
        view_menu.addAction(self._action("&Process Viewer", "Ctrl+4", lambda: self._tabs.setCurrentIndex(3)))
        view_menu.addAction(self._action("&Logs", "Ctrl+5", lambda: self._tabs.setCurrentIndex(4)))
        view_menu.addAction(self._action("S&ettings", "Ctrl+,", lambda: self._tabs.setCurrentIndex(5)))

        # ── Help ──
        help_menu = mb.addMenu("&Help")
        help_menu.addAction(self._action("&About", "", self._on_about))

    def _action(self, text: str, shortcut: str, slot) -> QAction:
        act = QAction(text, self)
        if shortcut:
            act.setShortcut(shortcut)
        act.triggered.connect(slot)
        return act

    # ─────────────────────────────────────────────────────
    # Toolbar
    # ─────────────────────────────────────────────────────

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main Toolbar")
        tb.setMovable(False)
        tb.setIconSize(QSize(20, 20))
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(tb)

        tb.addAction(self._action("⟳ Refresh Programs", "", self._on_refresh_programs))
        tb.addSeparator()
        tb.addAction(self._action("▶ New Scan", "", self._on_new_scan))
        tb.addAction(self._action("⏹ Stop All", "", self._on_stop_scans))
        tb.addSeparator()

        # Quick nav buttons
        tb.addAction(self._action("📊 Dashboard", "", lambda: self._tabs.setCurrentIndex(0)))
        tb.addAction(self._action("🐛 Findings", "", lambda: self._tabs.setCurrentIndex(2)))
        tb.addAction(self._action("⚡ Processes", "", lambda: self._tabs.setCurrentIndex(3)))
        tb.addSeparator()

        # Mode indicator label (will be updated dynamically)
        self._mode_label = QLabel("  Mode: semi-autonomous  ")
        self._mode_label.setStyleSheet(
            "QLabel { background: #1a3a1a; color: #66ff66; "
            "border-radius: 4px; padding: 2px 8px; font-weight: bold; }"
        )
        tb.addWidget(self._mode_label)

        # Brain connection indicator
        self._brain_status_label = QLabel("  Brain: checking...  ")
        self._brain_status_label.setStyleSheet(
            "QLabel { background: #2a2a2a; color: #888; "
            "border-radius: 4px; padding: 2px 8px; }"
        )
        tb.addWidget(self._brain_status_label)

    # ─────────────────────────────────────────────────────
    # Central Widget (Splitter: ProgramBrowser | Tabs)
    # ─────────────────────────────────────────────────────

    def _build_central(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left — Program Browser
        self._program_browser = ProgramBrowserWidget()
        self._program_browser.setMinimumWidth(280)
        self._program_browser.setMaximumWidth(500)
        self._program_browser.program_selected.connect(self._on_program_selected)
        splitter.addWidget(self._program_browser)

        # Right — Tab Area
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        self._dashboard = DashboardWidget()
        self._scan_control = ScanControlWidget()
        self._findings_panel = FindingsPanel()
        self._process_viewer = ProcessViewerWidget()
        self._log_viewer = LogViewerWidget()
        self._settings_panel = SettingsPanel()

        self._tabs.addTab(self._dashboard, "📊 Dashboard")
        self._tabs.addTab(self._scan_control, "🔍 Scan")
        self._tabs.addTab(self._findings_panel, "🐛 Findings")
        self._tabs.addTab(self._process_viewer, "⚡ Processes")
        self._tabs.addTab(self._log_viewer, "📝 Logs")
        self._tabs.addTab(self._settings_panel, "⚙ Settings")

        splitter.addWidget(self._tabs)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([320, 1280])

        self.setCentralWidget(splitter)

    # ─────────────────────────────────────────────────────
    # Signal Wiring
    # ─────────────────────────────────────────────────────

    def _wire_signals(self) -> None:
        """Connect cross-widget signals."""
        # Dashboard scan_selected → load findings into Findings panel & switch tab
        self._dashboard.scan_selected.connect(self._on_dashboard_scan_selected)

    def _on_dashboard_scan_selected(self, state: dict) -> None:
        """User selected a scan in the dashboard → load its findings."""
        self._findings_panel.load_from_scan_state(state)
        self._tabs.setCurrentIndex(2)  # Switch to Findings tab
        self._total_findings = len(state.get("findings", []))
        self._update_status()
        target = state.get("target", "?")
        sid = state.get("session_id", "?")[:8]
        self.statusBar().showMessage(
            f"Loaded findings from scan: {target} [{sid}]", 5000
        )

    # ─────────────────────────────────────────────────────
    # Status Bar
    # ─────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)

        self._status_scans = QLabel("Scans: 0 active")
        self._status_findings = QLabel("Findings: 0")
        self._status_brain = QLabel("Brain: checking...")
        self._status_brain.setStyleSheet("color: #888;")
        self._status_time = QLabel("")

        sb.addPermanentWidget(self._status_brain)
        sb.addPermanentWidget(self._status_scans)
        sb.addPermanentWidget(self._status_findings)
        sb.addPermanentWidget(self._status_time)

        sb.showMessage("Ready — WhiteHatHacker AI v2.1", 5000)

    def _update_status(self) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        self._status_scans.setText(f"  Scans: {self._active_scans} active  ")
        self._status_findings.setText(f"  Findings: {self._total_findings}  ")
        self._status_time.setText(f"  {now}  ")

        # Update mode from cached config (re-read only if file changed)
        if not hasattr(self, "_cached_mode"):
            self._cached_mode = "semi-autonomous"
            self._cached_api_url = "http://127.0.0.1:1239"
            self._config_mtime = 0.0
        try:
            config_path = Path("config/settings.yaml")
            if config_path.exists():
                mtime = config_path.stat().st_mtime
                if mtime != self._config_mtime:
                    self._config_mtime = mtime
                    import yaml
                    with open(config_path) as f:
                        cfg = yaml.safe_load(f) or {}
                    self._cached_mode = cfg.get("mode", "semi-autonomous")
                    primary = cfg.get("brain", {}).get("primary", {})
                    self._cached_api_url = primary.get("api_url", "http://127.0.0.1:1239")
            self._mode_label.setText(f"  Mode: {self._cached_mode}  ")
        except Exception as _exc:
            logger.debug(f"main window error: {_exc}")

        # Check brain connection via actual LM Studio API call
        self._check_brain_health()

    def _check_brain_health(self) -> None:
        """Check brain health via actual API endpoint (non-blocking)."""
        # Guard against overlapping health checks
        if getattr(self, "_brain_check_running", False):
            return
        self._brain_check_running = True

        import threading

        def _probe():
            try:
                api_url = getattr(self, "_cached_api_url", "http://127.0.0.1:1239")
                resp = httpx.get(f"{api_url}/v1/models", timeout=3)
                if resp.status_code == 200:
                    models = resp.json().get("data", [])
                    model_name = models[0].get("id", "?") if models else "?"
                    QTimer.singleShot(0, lambda: self._set_brain_status(True, model_name))
                else:
                    QTimer.singleShot(0, lambda: self._set_brain_status(False))
            except Exception as _exc:
                QTimer.singleShot(0, lambda: self._set_brain_status(False))
            finally:
                self._brain_check_running = False

        threading.Thread(target=_probe, daemon=True).start()

    def _set_brain_status(self, connected: bool, model: str = "") -> None:
        if connected:
            short = model[:30] + "..." if len(model) > 30 else model
            self._status_brain.setText(f"  🟢 Brain: {short}  ")
            self._status_brain.setStyleSheet("color: #00c853;")
            self._brain_status_label.setText("  🟢 Brain  ")
            self._brain_status_label.setStyleSheet(
                "QLabel { background: #1a3a1a; color: #00c853; "
                "border-radius: 4px; padding: 2px 8px; }"
            )
        else:
            self._status_brain.setText("  🔴 Brain: disconnected  ")
            self._status_brain.setStyleSheet("color: #ff4444;")
            self._brain_status_label.setText("  🔴 Brain  ")
            self._brain_status_label.setStyleSheet(
                "QLabel { background: #3a1a1a; color: #ff4444; "
                "border-radius: 4px; padding: 2px 8px; }"
            )

    # ─────────────────────────────────────────────────────
    # Slots
    # ─────────────────────────────────────────────────────

    def _on_program_selected(self, program_data: dict) -> None:
        """User selected a program in the browser → load into scan tab."""
        self._scan_control.load_program(program_data)
        self._tabs.setCurrentIndex(1)  # Switch to Scan tab
        self.statusBar().showMessage(
            f"Program loaded: {program_data.get('name', '?')}", 5000
        )

    def _on_new_scan(self) -> None:
        self._tabs.setCurrentIndex(1)

    def _on_refresh_programs(self) -> None:
        self._program_browser.refresh_programs()

    def _on_stop_scans(self) -> None:
        self._scan_control.stop_scan()

    def _on_about(self) -> None:
        QMessageBox.about(
            self,
            "About WhiteHatHacker AI",
            "<h2>WhiteHatHacker AI v2.1</h2>"
            "<p>Autonomous Bug Bounty Hunter Bot</p>"
            "<p><b>HUNTER MODE Active</b></p>"
            "<p>Dual-Brain Architecture:<br>"
            "• BaronLLM v2 — Offensive Security (Primary /think)<br>"
            "• BaronLLM v2 — Offensive Security (Secondary /no_think)</p>"
            "<p>Scan History: All scans auto-discovered from output/scans/</p>"
            "<p><b>WARNING:</b> Use only on authorized targets.</p>",
        )

    # ─────────────────────────────────────────────────────
    # Public API (for worker threads)
    # ─────────────────────────────────────────────────────

    def increment_findings(self, count: int = 1) -> None:
        self._total_findings += count
        self._update_status()

    def set_active_scans(self, count: int) -> None:
        self._active_scans = count
        self._update_status()

    def append_log(self, message: str) -> None:
        self._log_viewer.append_log(message)

    # ─────────────────────────────────────────────────────
    # Close
    # ─────────────────────────────────────────────────────

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._active_scans > 0:
            reply = QMessageBox.question(
                self,
                "Confirm Exit",
                f"There are {self._active_scans} active scan(s).\n"
                "Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return

        # Save window geometry
        settings = QSettings("WhiteHatHackerAI", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState())

        event.accept()
