"""
WhiteHatHacker AI — Scan Control Widget

Central scan management panel:
  - Selected program info display
  - Scan profile selection (stealth / balanced / aggressive)
  - Mode selection (autonomous / semi-autonomous)
  - Scope display with checkbox toggles per asset
  - Start / Pause / Stop buttons
  - Live progress per stage
  - Worker thread running the orchestrator
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from loguru import logger
from PySide6.QtCore import Qt, Signal, QThread, QObject, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QGroupBox,
    QTextEdit,
    QProgressBar,
    QCheckBox,
    QSpinBox,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
)

# ────────────────────────────────────────────────────────────
# Scope identifier normalisation helpers
# ────────────────────────────────────────────────────────────

# Characters that must never appear in a domain / wildcard / IP
_VALID_TARGET_RE = re.compile(
    r'^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)
_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def normalize_scope_identifier(identifier: str, asset_type: str = "") -> str | None:
    """Convert a raw scope identifier into a clean domain/wildcard/IP.

    Returns ``None`` when the identifier is clearly not a scan target
    (e.g. a text note, an e-mail address, an empty string, etc.).

    Examples:
        https://support.1password.com  →  support.1password.com
        http://github.com/cloudflare   →  github.com
        *.agilebits.com                →  *.agilebits.com
        192.168.1.0/24                 →  192.168.1.0/24
        "All other domains …"          →  None   (filtered out)
    """
    raw = identifier.strip()
    if not raw:
        return None

    # Step 1 – discard obvious text / description entries
    #   • Longer than 120 chars → definitely a note
    #   • Contains spaces after stripping scheme → note
    #   • asset_type hints that it's not a real target
    lower_type = asset_type.lower()
    if lower_type in ("other", "hardware", "downloadable_executables",
                       "source_code", "smart_contract", "ai_model"):
        return None
    if len(raw) > 120:
        return None

    # Step 2 – extract hostname from URL-like identifiers
    if "://" in raw:
        parsed = urlparse(raw)
        hostname = (parsed.hostname or "").lower().strip(".")
        if not hostname:
            return None
        return hostname

    # Step 3 – CIDR notation (must check before splitting on "/")
    if "/" in raw:
        try:
            import ipaddress
            ipaddress.ip_network(raw, strict=False)
            return raw.lower()
        except ValueError:
            pass

    # Step 4 – handle bare identifiers
    candidate = raw.split("/")[0].split(":")[0].strip(".").lower()

    # Discard if it contains spaces (plain-text note) or looks like email
    if " " in candidate or "@" in candidate:
        return None

    # Must look like a domain, wildcard or IP
    if _VALID_TARGET_RE.match(candidate) or _IP_RE.match(candidate):
        return candidate

    return None


def detect_scope_type(target: str) -> str:
    """Return the scope type string for ScopeValidator."""
    if target.startswith("*."):
        return "wildcard"
    if _IP_RE.match(target):
        return "ip"
    if "/" in target:
        return "cidr"
    return "domain"


# ────────────────────────────────────────────────────────────
# Scope Fetch Worker (lazy-loads scopes from platform API)
# ────────────────────────────────────────────────────────────


class ScopeFetchWorker(QObject):
    """Fetches program scopes from the platform API in a background thread."""

    finished = Signal(list)   # list of scope dicts
    error = Signal(str)

    def __init__(self, platform: str, handle: str) -> None:
        super().__init__()
        self._platform = platform
        self._handle = handle

    @Slot()
    def run(self) -> None:
        try:
            loop = asyncio.new_event_loop()
            try:
                scopes = loop.run_until_complete(self._fetch())
            finally:
                loop.close()
            self.finished.emit(scopes)
        except Exception as e:
            self.error.emit(str(e))

    async def _fetch(self) -> list[dict]:
        from src.platforms.program_manager import ProgramManager

        manager = ProgramManager()
        scope_objs = await manager.fetch_and_update_scopes(
            self._platform, self._handle,
        )
        return [
            {
                "asset_type": s.asset_type,
                "identifier": s.identifier,
                "eligible_for_bounty": s.eligible_for_bounty,
                "notes": s.notes,
            }
            for s in scope_objs
        ]


# ────────────────────────────────────────────────────────────
# Scan Worker (runs orchestrator in background)
# ────────────────────────────────────────────────────────────


class ScanWorker(QObject):
    """Runs a scan via the orchestrator in a background thread."""

    progress = Signal(str, int)   # (stage_name, percent)
    log_line = Signal(str)        # log message
    finding = Signal(dict)        # single finding dict
    finished = Signal(dict)       # final summary
    error = Signal(str)
    approval_needed = Signal(str) # prompt for human approval (main thread)

    def __init__(
        self,
        target_domains: list[str],
        scan_profile: str = "balanced",
        mode: str = "semi-autonomous",
        program_data: dict | None = None,
    ):
        super().__init__()
        self._targets = target_domains
        self._profile = scan_profile
        self._mode = mode
        self._program = program_data or {}
        self._stop_requested = False
        self._orchestrator_ref = None  # Set during run() for graceful stop

        # Cross-thread approval mechanism
        import threading
        self._approval_event = threading.Event()
        self._approval_result = False

    def set_approval_result(self, approved: bool) -> None:
        """Called from main thread after user responds to approval dialog."""
        self._approval_result = approved
        self._approval_event.set()

    def request_stop(self) -> None:
        self._stop_requested = True
        # Also signal the orchestrator to stop after current stage
        if self._orchestrator_ref is not None:
            try:
                self._orchestrator_ref.request_shutdown()
            except Exception as _exc:
                logger.debug(f"scan control error: {_exc}")

    @Slot()
    def run(self) -> None:
        try:
            self.log_line.emit(f"[*] Starting scan — targets: {', '.join(self._targets)}")
            self.log_line.emit(f"[*] Profile: {self._profile} | Mode: {self._mode}")

            # Create workspace
            from src.file_manager.output_organizer import OutputOrganizer

            organizer = OutputOrganizer()
            platform = self._program.get("platform", "manual")
            handle = self._program.get("handle", "custom_target")

            ws = organizer.create_workspace(
                platform=platform,
                program_handle=handle,
                config={
                    "targets": self._targets,
                    "profile": self._profile,
                    "mode": self._mode,
                    "program": self._program.get("name", ""),
                    "started_at": datetime.now(timezone.utc).isoformat(),
                },
            )

            self.log_line.emit(f"[*] Workspace: {ws.root}")
            self.progress.emit("Initializing", 5)

            # Initialize app components
            from src.main import load_config, initialize_app

            config = load_config()
            config["mode"] = self._mode
            config["scan_profile"] = self._profile

            loop = asyncio.new_event_loop()
            brain = None
            try:
                components = loop.run_until_complete(initialize_app(config))
                orchestrator = components["orchestrator"]
                brain = components["brain_engine"]

                # Wire stop button → orchestrator's graceful shutdown
                self._orchestrator_ref = orchestrator

                # Wire GUI approval callback for semi-autonomous mode
                worker_ref = self

                async def _gui_approval_callback(prompt: str) -> bool:
                    """Bridge approval request to main thread via Qt signal."""
                    worker_ref._approval_event.clear()
                    worker_ref._approval_result = False
                    worker_ref.approval_needed.emit(prompt)
                    # Wait in executor to avoid blocking the event loop
                    await asyncio.get_event_loop().run_in_executor(
                        None, worker_ref._approval_event.wait, 300,
                    )
                    return worker_ref._approval_result

                orchestrator.human_approval_callback = _gui_approval_callback

                # ── Brain lifecycle (mirrors run_scan() in main.py) ──
                self.log_line.emit("[*] Initializing Brain Engine (LLM connection)...")
                self.progress.emit("Connecting to Brain", 6)
                try:
                    loop.run_until_complete(brain.initialize())
                except Exception as e:
                    self.log_line.emit(f"[!] Brain initialization failed: {e}")
                    self.log_line.emit("[!] Scan will continue without AI brain — quality will be reduced.")
                    # Don't abort — let pipeline run degraded (like --no-brain)

                # ── Pre-scan brain health check ──
                self.log_line.emit("[*] Running pre-scan brain health check...")
                self.progress.emit("Brain health check", 7)
                health = loop.run_until_complete(brain.verify_brain_ready())
                if health["ready"]:
                    primary_s = "OK" if health["primary_ok"] else "FAIL"
                    secondary_s = "OK" if health["secondary_ok"] else "FAIL"
                    tunnel_s = health.get("tunnel_status", "n/a")
                    models = health.get("models", [])
                    self.log_line.emit(
                        f"[+] Brain check PASSED | tunnel={tunnel_s} | "
                        f"primary={primary_s} | secondary={secondary_s} | "
                        f"models={models}"
                    )
                    # Start background tunnel watchdog for auto-reconnect
                    loop.run_until_complete(brain.start_tunnel_watchdog(interval=60.0))
                else:
                    err = health.get("error", "Unknown")
                    tunnel_s = health.get("tunnel_status", "unknown")
                    self.log_line.emit(f"[!] Brain check FAILED: {err}")
                    self.log_line.emit(f"[!] Tunnel: {tunnel_s} | Primary: {health['primary_ok']} | Secondary: {health['secondary_ok']}")
                    if tunnel_s == "failed":
                        self.log_line.emit("[!] SSH tunnel is DOWN — run: bash scripts/ssh_tunnel.sh start")
                    self.log_line.emit("[!] Continuing without AI brain — findings quality will be reduced.")

                # Build scope — must match ScopeValidator.from_dict() format (HIGH-1 fix)
                scope = {
                    "targets": [
                        {"value": d, "type": detect_scope_type(d), "include": True}
                        for d in self._targets
                    ],
                    "excluded": [],
                }

                self.progress.emit("Running scan", 10)

                # Scan ALL targets, not just the first
                total = len(self._targets)
                for idx, target in enumerate(self._targets, 1):
                    if self._stop_requested:
                        self.log_line.emit(f"[!] Stop requested — skipping remaining targets ({total - idx + 1} left)")
                        break

                    self.log_line.emit(f"[*] Scanning target {idx}/{total}: {target}")
                    pct_base = 10 + int(80 * (idx - 1) / total)
                    self.progress.emit(f"Target {idx}/{total}: {target}", pct_base)

                    loop.run_until_complete(
                        orchestrator.run(target=target, scope=scope)
                    )

                    # Reset shutdown flag for next target
                    orchestrator.clear_shutdown_request()

                self.progress.emit("Complete", 100)
                summary = {
                    "workspace": str(ws.root),
                    "session_id": ws.info.session_id,
                    "status": "stopped" if self._stop_requested else "completed",
                    "targets_scanned": min(idx, total) if self._targets else 0,
                    "targets_total": total,
                }
                self.finished.emit(summary)

            except Exception as e:
                self.error.emit(f"Scan error: {e}")
            finally:
                # ── Brain cleanup (mirrors run_scan() in main.py) ──
                if brain is not None:
                    try:
                        loop.run_until_complete(brain.stop_tunnel_watchdog())
                    except Exception as _wtd_err:
                        logger.warning("Brain watchdog stop failed: %s", _wtd_err)
                    try:
                        loop.run_until_complete(brain.shutdown())
                    except Exception as _bsd_err:
                        logger.warning("Brain shutdown failed: %s", _bsd_err)
                self._orchestrator_ref = None
                loop.close()

        except Exception as e:
            self.error.emit(f"Worker error: {e}")


# ────────────────────────────────────────────────────────────
# Scan Control Widget
# ────────────────────────────────────────────────────────────


class ScanControlWidget(QWidget):
    """Scan configuration and execution panel."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._program_data: dict = {}
        self._worker_thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._is_running = False

        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # ── Program Info ──────────────────────────────
        info_group = QGroupBox("Selected Program")
        info_layout = QFormLayout(info_group)

        self._prog_name = QLabel("No program selected")
        self._prog_name.setFont(QFont("", 12, QFont.Weight.Bold))
        self._prog_name.setStyleSheet("color: #00d4ff;")
        info_layout.addRow("Program:", self._prog_name)

        self._prog_platform = QLabel("-")
        info_layout.addRow("Platform:", self._prog_platform)

        self._prog_bounty = QLabel("-")
        self._prog_bounty.setStyleSheet("color: #66ff66;")
        info_layout.addRow("Bounty:", self._prog_bounty)

        self._prog_url = QLabel("-")
        self._prog_url.setOpenExternalLinks(True)
        info_layout.addRow("URL:", self._prog_url)

        layout.addWidget(info_group)

        # ── Scan Configuration ────────────────────────
        config_group = QGroupBox("Scan Configuration")
        config_layout = QGridLayout(config_group)

        # Profile
        config_layout.addWidget(QLabel("Profile:"), 0, 0)
        self._profile_combo = QComboBox()
        self._profile_combo.addItems(["stealth", "balanced", "aggressive"])
        self._profile_combo.setCurrentIndex(1)
        config_layout.addWidget(self._profile_combo, 0, 1)

        # Mode
        config_layout.addWidget(QLabel("Mode:"), 0, 2)
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(["semi-autonomous", "autonomous"])
        config_layout.addWidget(self._mode_combo, 0, 3)

        # Max parallel tools
        config_layout.addWidget(QLabel("Parallel tools:"), 1, 0)
        self._parallel_spin = QSpinBox()
        self._parallel_spin.setRange(1, 20)
        self._parallel_spin.setValue(5)
        config_layout.addWidget(self._parallel_spin, 1, 1)

        # Rate limit
        config_layout.addWidget(QLabel("Req/sec limit:"), 1, 2)
        self._rate_spin = QSpinBox()
        self._rate_spin.setRange(1, 100)
        self._rate_spin.setValue(10)
        config_layout.addWidget(self._rate_spin, 1, 3)

        layout.addWidget(config_group)

        # ── Scope / Targets ───────────────────────────
        scope_group = QGroupBox("Targets / Scope")
        scope_layout = QVBoxLayout(scope_group)

        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText(
            "Enter targets (comma-separated domains/IPs) or select from program scope..."
        )
        scope_layout.addWidget(self._target_input)

        self._scope_table = QTableWidget(0, 3)
        self._scope_table.setHorizontalHeaderLabels(["✓", "Type", "Asset"])
        self._scope_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self._scope_table.setColumnWidth(0, 30)
        self._scope_table.setColumnWidth(1, 80)
        self._scope_table.setMaximumHeight(150)
        scope_layout.addWidget(self._scope_table)

        layout.addWidget(scope_group)

        # ── Action Buttons ────────────────────────────
        btn_row = QHBoxLayout()

        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setStyleSheet(
            "QPushButton { background: #1a6b1a; color: white; font-weight: bold; "
            "padding: 10px 24px; border-radius: 6px; font-size: 13px; }"
            "QPushButton:hover { background: #228b22; }"
            "QPushButton:disabled { background: #333; color: #666; }"
        )
        self._start_btn.clicked.connect(self._on_start)
        btn_row.addWidget(self._start_btn)

        self._stop_btn = QPushButton("⏹  Stop")
        self._stop_btn.setStyleSheet(
            "QPushButton { background: #6b1a1a; color: white; font-weight: bold; "
            "padding: 10px 24px; border-radius: 6px; font-size: 13px; }"
            "QPushButton:hover { background: #8b2222; }"
            "QPushButton:disabled { background: #333; color: #666; }"
        )
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop)
        btn_row.addWidget(self._stop_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # ── Progress ──────────────────────────────────
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout(progress_group)

        self._stage_label = QLabel("Idle")
        self._stage_label.setFont(QFont("", 10, QFont.Weight.Bold))
        progress_layout.addWidget(self._stage_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        progress_layout.addWidget(self._progress_bar)

        # Stage timeline
        stages = [
            "Scope Analysis", "Passive Recon", "Active Recon",
            "Enumeration", "Attack Surface", "Vuln Scan",
            "FP Elimination", "Reporting",
        ]
        self._stage_labels: list[QLabel] = []
        stage_row = QHBoxLayout()
        for s in stages:
            lbl = QLabel(s)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(
                "font-size: 8px; color: #555; padding: 2px;"
                "border: 1px solid #333; border-radius: 3px;"
            )
            self._stage_labels.append(lbl)
            stage_row.addWidget(lbl)
        progress_layout.addLayout(stage_row)

        layout.addWidget(progress_group)

        # ── Live Output ───────────────────────────────
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Fira Code", 9))
        self._output.setStyleSheet("background: #0a0a0a; color: #b0b0b0;")
        self._output.setMaximumHeight(200)
        layout.addWidget(self._output)

        layout.addStretch()

    # ─────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────

    def load_program(self, data: dict) -> None:
        """Load program details from browser selection."""
        self._program_data = data
        self._prog_name.setText(data.get("name", "Unknown"))
        self._prog_platform.setText(data.get("platform", "-").title())

        bmin = data.get("min_bounty", 0)
        bmax = data.get("max_bounty", 0)
        self._prog_bounty.setText(f"${bmin:,} — ${bmax:,}")

        url = data.get("url", "")
        self._prog_url.setText(f"<a href='{url}'>{url}</a>")

        # Populate scope table
        scopes = data.get("scopes", [])
        self._populate_scopes(scopes)

        # If scopes are empty, lazy-fetch from platform API
        if not scopes and data.get("handle"):
            self._lazy_fetch_scopes(data)

    def _populate_scopes(self, scopes: list[dict]) -> None:
        """Fill the scope table and target input from a scope list."""
        self._scope_table.setRowCount(len(scopes))

        target_domains: list[str] = []
        seen: set[str] = set()

        for i, s in enumerate(scopes):
            asset_type = s.get("asset_type", "")
            identifier = s.get("identifier", "")
            eligible = bool(s.get("eligible_for_bounty", False))

            # Checkbox
            cb = QCheckBox()
            cb.setChecked(eligible)
            self._scope_table.setCellWidget(i, 0, cb)

            self._scope_table.setItem(
                i, 1, QTableWidgetItem(asset_type)
            )
            self._scope_table.setItem(i, 2, QTableWidgetItem(identifier))

            # Only auto-add eligible, scannable targets
            if not eligible:
                continue

            normalised = normalize_scope_identifier(identifier, asset_type)
            if normalised and normalised not in seen:
                seen.add(normalised)
                target_domains.append(normalised)

        self._target_input.setText(", ".join(target_domains[:20]))

    def _lazy_fetch_scopes(self, data: dict) -> None:
        """Fetch scopes from the platform API in a background thread."""
        platform = data.get("platform", "")
        handle = data.get("handle", "")
        if not handle or not platform:
            return

        self._target_input.setPlaceholderText("Fetching scopes from API...")
        self._target_input.setText("")
        self._start_btn.setEnabled(False)
        self._start_btn.setText("⏳ Fetching Scopes...")

        self._scope_thread = QThread()
        self._scope_worker = ScopeFetchWorker(platform, handle)
        self._scope_worker.moveToThread(self._scope_thread)

        self._scope_thread.started.connect(self._scope_worker.run)
        self._scope_worker.finished.connect(self._on_scopes_fetched)
        self._scope_worker.error.connect(self._on_scopes_error)
        self._scope_worker.finished.connect(self._scope_thread.quit)
        self._scope_worker.error.connect(self._scope_thread.quit)

        self._scope_thread.start()

    def _on_scopes_fetched(self, scopes: list[dict]) -> None:
        """Callback when lazy scope fetch completes."""
        self._start_btn.setEnabled(True)
        self._start_btn.setText("▶  Start Scan")
        self._target_input.setPlaceholderText(
            "Target domains / IPs (comma-separated)"
        )
        if not scopes:
            logger.info("No scopes returned from API — user can enter targets manually")
            return

        # Update in-memory program data
        self._program_data["scopes"] = scopes
        self._program_data["scope_count"] = len(scopes)

        # Re-populate UI
        self._populate_scopes(scopes)
        logger.info(f"Lazy-fetched {len(scopes)} scopes for program")

    def _on_scopes_error(self, msg: str) -> None:
        """Callback when lazy scope fetch fails."""
        self._start_btn.setEnabled(True)
        self._start_btn.setText("▶  Start Scan")
        self._target_input.setPlaceholderText(
            "Scope fetch failed — enter targets manually"
        )
        logger.warning(f"Scope lazy-fetch failed: {msg}")

    def stop_scan(self) -> None:
        """Stop the running scan."""
        self._on_stop()

    # ─────────────────────────────────────────────────────
    # Scan lifecycle
    # ─────────────────────────────────────────────────────

    def _on_start(self) -> None:
        targets_raw = self._target_input.text().strip()
        if not targets_raw:
            QMessageBox.warning(
                self, "No Targets",
                "Please select a program or enter target domains."
            )
            return

        targets = [t.strip() for t in targets_raw.split(",") if t.strip()]

        # ── Pre-flight validation ──
        # Normalise any raw input the user may have typed/pasted
        clean_targets: list[str] = []
        bad_targets: list[str] = []
        for t in targets:
            n = normalize_scope_identifier(t)
            if n:
                clean_targets.append(n)
            else:
                bad_targets.append(t)

        if bad_targets:
            QMessageBox.warning(
                self, "Invalid Targets",
                f"The following targets don't look like valid domains or IPs:\n\n"
                f"{', '.join(bad_targets[:5])}\n\n"
                f"Please fix them before starting the scan."
            )
            return

        if not clean_targets:
            QMessageBox.warning(
                self, "No Targets",
                "No valid scan targets after normalisation."
            )
            return

        targets = clean_targets

        # 2. Try loading config
        try:
            from src.main import load_config
            _cfg = load_config()
        except Exception as exc:
            QMessageBox.critical(
                self, "Configuration Error",
                f"Failed to load configuration:\n\n{exc}\n\n"
                f"Check config/settings.yaml and .env files."
            )
            return

        # 3. Quick brain connectivity check (with proper auth headers)
        try:
            import httpx

            brain_cfg = _cfg.get("brain", {}).get("primary", {})
            brain_url = brain_cfg.get("api_url", "")
            brain_key = brain_cfg.get("api_key", "")
            if not brain_url:
                import os
                brain_url = os.environ.get("WHAI_PRIMARY_API_URL", "http://127.0.0.1:1239")
            if not brain_key:
                import os
                brain_key = os.environ.get("WHAI_PRIMARY_API_KEY", "")

            headers: dict[str, str] = {}
            if brain_key:
                headers["Authorization"] = f"Bearer {brain_key}"

            resp = httpx.get(
                f"{brain_url.rstrip('/')}/v1/models",
                headers=headers,
                timeout=5.0,
            )

            if resp.status_code == 200:
                # Brain OK — check if models are loaded
                try:
                    data = resp.json()
                    model_ids = [m.get("id", "?") for m in data.get("data", [])]
                    if not model_ids:
                        answer = QMessageBox.question(
                            self, "No Model Loaded",
                            "Brain API is reachable but no models are loaded in LM Studio.\n\n"
                            "Load a model first for AI-powered analysis.\n"
                            "Continue without LLM? (reduced quality)",
                            QMessageBox.Yes | QMessageBox.No,
                        )
                        if answer == QMessageBox.No:
                            return
                except Exception:
                    pass  # JSON parse failed — proceed anyway
            elif resp.status_code == 401:
                # Auth failure — try without auth in case LM Studio config changed
                resp_noauth = httpx.get(
                    f"{brain_url.rstrip('/')}/v1/models", timeout=5.0,
                )
                if resp_noauth.status_code == 200:
                    # Server doesn't need auth anymore — proceed (BrainEngine
                    # will also succeed because _init_model tolerates non-200)
                    pass
                else:
                    answer = QMessageBox.question(
                        self, "Brain Authentication Failed",
                        "Brain API returned 401 Unauthorized.\n\n"
                        "The API key in .env (WHAI_PRIMARY_API_KEY) does not match\n"
                        "the key configured in LM Studio.\n\n"
                        "Fix: Open LM Studio → Server → copy the API key → update .env\n\n"
                        "Continue without LLM? (reduced quality)",
                        QMessageBox.Yes | QMessageBox.No,
                    )
                    if answer == QMessageBox.No:
                        return
            else:
                answer = QMessageBox.question(
                    self, "Brain Unreachable",
                    f"Brain API returned status {resp.status_code}.\n\n"
                    f"Scan will run without LLM analysis (reduced quality).\n"
                    f"Continue anyway?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if answer == QMessageBox.No:
                    return
        except httpx.ConnectError:
            answer = QMessageBox.question(
                self, "Brain Unreachable",
                f"Cannot connect to Brain LLM at:\n{brain_url}\n\n"
                "Check:\n"
                "  1. SSH tunnel: bash scripts/ssh_tunnel.sh status\n"
                "  2. LM Studio is running on the Mac\n"
                "  3. Model is loaded in LM Studio\n\n"
                "Continue without LLM? (reduced quality)",
                QMessageBox.Yes | QMessageBox.No,
            )
            if answer == QMessageBox.No:
                return
        except Exception:
            pass  # Don't block scan start on unexpected pre-check errors

        profile = self._profile_combo.currentText()
        mode = self._mode_combo.currentText()

        self._output.clear()
        self._progress_bar.setValue(0)
        self._stage_label.setText("Starting…")
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._is_running = True

        # Create worker
        self._worker_thread = QThread()
        self._worker = ScanWorker(
            target_domains=targets,
            scan_profile=profile,
            mode=mode,
            program_data=self._program_data,
        )
        self._worker.moveToThread(self._worker_thread)

        self._worker_thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.log_line.connect(self._on_log)
        self._worker.finding.connect(self._on_finding)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.approval_needed.connect(self._on_approval_needed)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.error.connect(self._worker_thread.quit)

        self._worker_thread.start()

    def _on_stop(self) -> None:
        if self._worker:
            self._worker.request_stop()
        self._on_log("[!] Stop requested — waiting for current tool to finish...")

    def _on_approval_needed(self, prompt: str) -> None:
        """Show approval dialog on main thread, return result to worker."""
        result = QMessageBox.question(
            self,
            "Stage Approval Required",
            prompt,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        approved = result == QMessageBox.Yes
        self._on_log(f"[APPROVAL] {prompt} → {'APPROVED' if approved else 'REJECTED'}")
        if self._worker:
            self._worker.set_approval_result(approved)

    def _on_progress(self, stage: str, percent: int) -> None:
        self._stage_label.setText(stage)
        self._progress_bar.setValue(percent)

        # Highlight active stage label
        stage_lower = stage.lower()
        for lbl in self._stage_labels:
            if lbl.text().lower().replace(" ", "") in stage_lower.replace(" ", ""):
                lbl.setStyleSheet(
                    "font-size: 8px; color: #00ff88; padding: 2px; "
                    "border: 1px solid #00ff88; border-radius: 3px; font-weight: bold;"
                )
            else:
                lbl.setStyleSheet(
                    "font-size: 8px; color: #555; padding: 2px; "
                    "border: 1px solid #333; border-radius: 3px;"
                )

    def _on_log(self, msg: str) -> None:
        self._output.append(msg)
        sb = self._output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_finding(self, finding: dict) -> None:
        severity = str(finding.get("severity") or "info")
        title = finding.get("title", "Untitled")
        self._on_log(f"[FINDING] [{severity.upper()}] {title}")

    def _on_finished(self, summary: dict) -> None:
        self._is_running = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        status = summary.get("status", "completed")
        scanned = summary.get("targets_scanned", "?")
        total = summary.get("targets_total", "?")
        icon = "✅" if status == "completed" else "⏹"
        self._stage_label.setText(f"{icon} {status.title()} ({scanned}/{total} targets)")
        self._progress_bar.setValue(100)
        ws = summary.get("workspace", "")
        self._on_log(f"\n[✓] Scan {status}. Output: {ws}")
        self._cleanup_worker()

    def _on_error(self, error: str) -> None:
        self._is_running = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._stage_label.setText("❌ Error")
        self._on_log(f"\n[ERROR] {error}")
        self._cleanup_worker()

    def _cleanup_worker(self) -> None:
        """Clean up worker and thread to prevent memory leaks."""
        if self._worker:
            self._worker.deleteLater()
            self._worker = None
        if self._worker_thread:
            self._worker_thread.quit()
            self._worker_thread.wait(5000)
            self._worker_thread.deleteLater()
            self._worker_thread = None
