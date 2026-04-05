"""
WhiteHatHacker AI — Settings Panel

Configuration GUI for:
  - API credentials (HackerOne, Bugcrowd, Shodan, Censys, GitHub, etc.)
  - Brain engine settings (LM Studio URLs, model paths, GPU, threads)
  - Scan defaults (profile, mode, rate limit)
  - Output directory & cache
  - Notification settings (Slack, Telegram, Discord)
  - Interactsh OOB server
"""

from __future__ import annotations

import os
from collections import OrderedDict
from pathlib import Path

import yaml
try:
    from ruamel.yaml import YAML as RuamelYAML
except ImportError:
    RuamelYAML = None  # type: ignore[assignment,misc]
from PySide6.QtCore import Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QSpinBox,
    QCheckBox,
    QTabWidget,
    QScrollArea,
    QMessageBox,
    QFileDialog,
)

from loguru import logger


# ── .env file helpers ─────────────────────────────────────────

def _read_dotenv(path: Path) -> OrderedDict[str, str]:
    """Read .env file preserving order. Returns key→value map."""
    data: OrderedDict[str, str] = OrderedDict()
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            data[key.strip()] = value.strip()
    return data


def _write_dotenv(path: Path, data: OrderedDict[str, str]) -> None:
    """
    Write .env preserving existing comments & structure.
    Updates existing keys in-place and appends new keys at the end.
    """
    if not path.exists():
        # Fresh write
        lines = [f"{k}={v}" for k, v in data.items()]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return

    original = path.read_text(encoding="utf-8")
    result_lines: list[str] = []
    handled_keys: set[str] = set()

    for line in original.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.partition("=")[0].strip()
            if key in data:
                result_lines.append(f"{key}={data[key]}")
                handled_keys.add(key)
            else:
                result_lines.append(line)
        else:
            result_lines.append(line)

    # Append new keys that weren't in the original file
    new_keys = [k for k in data if k not in handled_keys]
    if new_keys:
        result_lines.append("")
        result_lines.append("# ============================================================")
        result_lines.append("# Added by GUI Settings")
        result_lines.append("# ============================================================")
        for k in new_keys:
            result_lines.append(f"{k}={data[k]}")

    path.write_text("\n".join(result_lines) + "\n", encoding="utf-8")
    # Ensure .env is readable only by owner (contains API keys)
    try:
        path.chmod(0o600)
    except OSError:
        pass


# ── Helper: password field with toggle ────────────────────────

def _make_secret_field(placeholder: str = "") -> tuple[QHBoxLayout, QLineEdit]:
    """Create a password QLineEdit with a show/hide toggle button."""
    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    if placeholder:
        field.setPlaceholderText(placeholder)
    row.addWidget(field, 1)

    toggle = QPushButton("👁")
    toggle.setFixedWidth(32)
    toggle.setToolTip("Show / Hide")
    toggle.setCheckable(True)
    toggle.setStyleSheet(
        "QPushButton { border: 1px solid #555; border-radius: 3px; padding: 2px; }"
        "QPushButton:checked { background: #444; }"
    )

    def _on_toggle(checked: bool) -> None:
        field.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        toggle.setText("🔒" if checked else "👁")

    toggle.toggled.connect(_on_toggle)
    row.addWidget(toggle)
    return row, field


# ── Helper: section label ─────────────────────────────────────

def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setFont(QFont("", 10, QFont.Weight.Bold))
    lbl.setStyleSheet("color: #00d4ff; margin-top: 12px; margin-bottom: 2px;")
    return lbl


# ==============================================================
# SettingsPanel
# ==============================================================

class SettingsPanel(QWidget):
    """Application settings panel with multiple tabs."""

    settings_changed = Signal()

    # All env var keys that will be managed via this panel
    _ENV_KEY_FIELD_MAP: dict  # populated in _build_api_tab etc.

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._config_path = "config/settings.yaml"
        self._env_path = Path(".env")
        self._env_fields: dict[str, QLineEdit] = {}  # env_key → QLineEdit
        self._build_ui()
        self._load_current()

    # ─────────────────────────────────────────────────────
    # UI Construction
    # ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        header = QLabel("⚙ Settings")
        header.setFont(QFont("", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff; padding: 4px;")
        layout.addWidget(header)

        # ── Tabs ──────────────────────────────────────
        tabs = QTabWidget()

        tabs.addTab(self._build_api_tab(), "🔑 API Keys")
        tabs.addTab(self._build_brain_tab(), "🧠 Brain Engine")
        tabs.addTab(self._build_scan_tab(), "🔍 Scan Defaults")
        tabs.addTab(self._build_output_tab(), "📁 Output & Cache")
        tabs.addTab(self._build_notify_tab(), "🔔 Notifications")

        layout.addWidget(tabs, 1)

        # ── Save / Reset Buttons ─────────────────────
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self._save_btn = QPushButton("💾  Save Settings")
        self._save_btn.setStyleSheet(
            "QPushButton { background: #1a6b1a; color: white; "
            "font-weight: bold; padding: 8px 20px; border-radius: 5px; }"
            "QPushButton:hover { background: #228b22; }"
        )
        self._save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(self._save_btn)

        self._reset_btn = QPushButton("↺  Reset")
        self._reset_btn.clicked.connect(self._load_current)
        btn_row.addWidget(self._reset_btn)

        layout.addLayout(btn_row)

    # ─────────────────────────────────────────────────────
    # Tab Builders
    # ─────────────────────────────────────────────────────

    def _add_env_field(
        self,
        form: QFormLayout,
        label: str,
        env_key: str,
        *,
        placeholder: str = "",
        secret: bool = False,
    ) -> QLineEdit:
        """Add a QLineEdit row to form and register it in _env_fields."""
        if secret:
            row_layout, field = _make_secret_field(placeholder or env_key)
            form.addRow(f"{label}:", row_layout)
        else:
            field = QLineEdit()
            if placeholder:
                field.setPlaceholderText(placeholder)
            else:
                field.setPlaceholderText(env_key)
            form.addRow(f"{label}:", field)

        self._env_fields[env_key] = field
        return field

    def _build_api_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        form = QFormLayout(content)
        form.setSpacing(6)

        form.addRow(QLabel(
            "<i>API keys are saved to <b>.env</b> and loaded into the current session. "
            "Click 👁 to reveal a secret field.</i>"
        ))

        # ── Bug Bounty Platforms ─────────────────────
        form.addRow(_section_label("🏴‍☠️  Bug Bounty Platforms"))
        self._add_env_field(form, "HackerOne Username", "HACKERONE_API_USERNAME")
        self._add_env_field(form, "HackerOne API Token", "HACKERONE_API_TOKEN", secret=True)
        self._add_env_field(form, "Bugcrowd API Token", "BUGCROWD_API_TOKEN", secret=True)

        # ── OSINT Services ───────────────────────────
        form.addRow(_section_label("🔍  OSINT Services"))
        self._add_env_field(form, "Shodan API Key", "SHODAN_API_KEY", secret=True)
        self._add_env_field(form, "Censys API ID", "CENSYS_API_ID")
        self._add_env_field(form, "Censys API Secret", "CENSYS_API_SECRET", secret=True)
        self._add_env_field(form, "GitHub Token", "GITHUB_TOKEN", secret=True,
                            placeholder="ghp_... (repo, read:org scope)")
        self._add_env_field(form, "VirusTotal API Key", "VIRUSTOTAL_API_KEY", secret=True)
        self._add_env_field(form, "SecurityTrails Key", "SECURITYTRAILS_API_KEY", secret=True)

        # ── Google Custom Search ─────────────────────
        form.addRow(_section_label("🌐  Google Custom Search (Dorking)"))
        self._add_env_field(form, "Google API Key", "GOOGLE_API_KEY", secret=True,
                            placeholder="AIza... (Custom Search API)")
        self._add_env_field(form, "Google CSE ID", "GOOGLE_CSE_ID",
                            placeholder="Custom Search Engine ID")

        # ── Interactsh (OOB Testing) ─────────────────
        form.addRow(_section_label("📡  Interactsh — Out-of-Band"))
        self._add_env_field(form, "Interactsh Server", "INTERACTSH_SERVER",
                            placeholder="https://oast.me (or self-hosted)")
        self._add_env_field(form, "Interactsh Token", "INTERACTSH_TOKEN", secret=True)

        scroll.setWidget(content)
        return scroll

    def _build_brain_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        form = QFormLayout(content)
        form.setSpacing(6)

        # ── Remote LLM Backend ───────────────────────
        form.addRow(_section_label("🌐  Remote LLM Backend (LM Studio / OpenAI API)"))
        self._add_env_field(form, "Primary API URL", "WHAI_PRIMARY_API_URL",
                            placeholder="http://127.0.0.1:1239")
        self._add_env_field(form, "Primary API Key", "WHAI_PRIMARY_API_KEY", secret=True,
                            placeholder="sk-...")
        self._add_env_field(form, "Secondary API URL", "WHAI_SECONDARY_API_URL",
                            placeholder="http://127.0.0.1:1239")
        self._add_env_field(form, "Secondary API Key", "WHAI_SECONDARY_API_KEY", secret=True,
                            placeholder="sk-...")

        # ── Local Model Paths ────────────────────────
        form.addRow(_section_label("💾  Local Model Paths (llama-cpp fallback)"))

        self._brain_primary_path = QLineEdit()
        self._brain_primary_path.setPlaceholderText("Path to BaronLLM v2 GGUF model")
        p_row = QHBoxLayout()
        p_row.addWidget(self._brain_primary_path, 1)
        p_browse = QPushButton("📂")
        p_browse.setFixedWidth(32)
        p_browse.clicked.connect(lambda: self._browse_model(self._brain_primary_path))
        p_row.addWidget(p_browse)
        form.addRow("Primary Model:", p_row)

        self._brain_secondary_path = QLineEdit()
        self._brain_secondary_path.setPlaceholderText("Path to BaronLLM v2 GGUF model (same as primary)")
        s_row = QHBoxLayout()
        s_row.addWidget(self._brain_secondary_path, 1)
        s_browse = QPushButton("📂")
        s_browse.setFixedWidth(32)
        s_browse.clicked.connect(lambda: self._browse_model(self._brain_secondary_path))
        s_row.addWidget(s_browse)
        form.addRow("Secondary Model:", s_row)

        # ── Engine Parameters ────────────────────────
        form.addRow(_section_label("⚙  Engine Parameters"))

        self._brain_gpu_layers = QSpinBox()
        self._brain_gpu_layers.setRange(-1, 200)
        self._brain_gpu_layers.setValue(-1)
        self._brain_gpu_layers.setSpecialValueText("Auto (all)")
        form.addRow("GPU Layers:", self._brain_gpu_layers)

        self._brain_threads = QSpinBox()
        self._brain_threads.setRange(1, 64)
        self._brain_threads.setValue(8)
        form.addRow("CPU Threads:", self._brain_threads)

        self._brain_ctx_primary = QSpinBox()
        self._brain_ctx_primary.setRange(1024, 131072)
        self._brain_ctx_primary.setSingleStep(1024)
        self._brain_ctx_primary.setValue(32768)
        form.addRow("Primary Context:", self._brain_ctx_primary)

        self._brain_ctx_secondary = QSpinBox()
        self._brain_ctx_secondary.setRange(1024, 131072)
        self._brain_ctx_secondary.setSingleStep(1024)
        self._brain_ctx_secondary.setValue(16384)
        form.addRow("Secondary Context:", self._brain_ctx_secondary)

        scroll.setWidget(content)
        return scroll

    def _build_scan_tab(self) -> QWidget:
        content = QWidget()
        form = QFormLayout(content)
        form.setSpacing(8)

        self._scan_profile = QComboBox()
        self._scan_profile.addItems(["stealth", "balanced", "aggressive"])
        self._scan_profile.setCurrentIndex(1)
        form.addRow("Default Profile:", self._scan_profile)

        self._scan_mode = QComboBox()
        self._scan_mode.addItems(["semi-autonomous", "autonomous"])
        form.addRow("Default Mode:", self._scan_mode)

        self._scan_parallel = QSpinBox()
        self._scan_parallel.setRange(1, 20)
        self._scan_parallel.setValue(5)
        form.addRow("Max Parallel Tools:", self._scan_parallel)

        self._scan_rps = QSpinBox()
        self._scan_rps.setRange(1, 100)
        self._scan_rps.setValue(10)
        form.addRow("Req/sec (global):", self._scan_rps)

        self._scan_rps_host = QSpinBox()
        self._scan_rps_host.setRange(1, 50)
        self._scan_rps_host.setValue(3)
        form.addRow("Req/sec (per host):", self._scan_rps_host)

        self._scan_timeout = QSpinBox()
        self._scan_timeout.setRange(30, 7200)
        self._scan_timeout.setSingleStep(30)
        self._scan_timeout.setValue(300)
        self._scan_timeout.setSuffix(" sec")
        form.addRow("Tool Timeout:", self._scan_timeout)

        return content

    def _build_output_tab(self) -> QWidget:
        content = QWidget()
        form = QFormLayout(content)
        form.setSpacing(8)

        self._output_dir = QLineEdit("output")
        form.addRow("Output Directory:", self._output_dir)

        self._cache_ttl = QSpinBox()
        self._cache_ttl.setRange(1, 168)
        self._cache_ttl.setValue(24)
        self._cache_ttl.setSuffix(" hours")
        form.addRow("Program Cache TTL:", self._cache_ttl)

        self._keep_scans = QSpinBox()
        self._keep_scans.setRange(1, 100)
        self._keep_scans.setValue(10)
        form.addRow("Keep last N scans:", self._keep_scans)

        self._auto_cleanup = QCheckBox("Auto-cleanup old scans")
        self._auto_cleanup.setChecked(True)
        form.addRow("", self._auto_cleanup)

        return content

    def _build_notify_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        form = QFormLayout(content)
        form.setSpacing(6)

        # ── Slack ────────────────────────────────────
        form.addRow(_section_label("💬  Slack"))
        self._add_env_field(form, "Webhook URL", "SLACK_WEBHOOK_URL",
                            placeholder="https://hooks.slack.com/services/...")

        # ── Telegram ─────────────────────────────────
        form.addRow(_section_label("✈  Telegram"))
        self._add_env_field(form, "Bot Token", "TELEGRAM_BOT_TOKEN", secret=True,
                            placeholder="123456:ABC-DEF...")
        self._add_env_field(form, "Chat ID", "TELEGRAM_CHAT_ID",
                            placeholder="-100123456789")

        # ── Discord ──────────────────────────────────
        form.addRow(_section_label("🎮  Discord"))
        self._add_env_field(form, "Webhook URL", "DISCORD_WEBHOOK_URL",
                            placeholder="https://discord.com/api/webhooks/...")

        # ── Behaviour ────────────────────────────────
        form.addRow(_section_label("⚙  Behaviour"))
        self._notify_on_finding = QCheckBox("Notify on new finding")
        self._notify_on_finding.setChecked(True)
        form.addRow("", self._notify_on_finding)

        self._notify_on_complete = QCheckBox("Notify on scan complete")
        self._notify_on_complete.setChecked(True)
        form.addRow("", self._notify_on_complete)

        scroll.setWidget(content)
        return scroll

    # ─────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────

    def _browse_model(self, target_field: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select GGUF Model",
            str(Path.home()),
            "GGUF Models (*.gguf);;All Files (*)",
        )
        if path:
            target_field.setText(path)

    # ─────────────────────────────────────────────────────
    # Load / Save
    # ─────────────────────────────────────────────────────

    def _load_current(self) -> None:
        """Load current settings from .env file + config YAML + env vars."""
        # 1) Read .env file first, then override with live os.environ
        dotenv = _read_dotenv(self._env_path)
        for env_key, field in self._env_fields.items():
            # Priority: os.environ > .env file > empty
            value = os.environ.get(env_key, dotenv.get(env_key, ""))
            field.setText(value)

        # 2) Config file
        config_path = Path(self._config_path)
        if not config_path.exists():
            return

        try:
            with open(config_path) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception as _exc:
            logger.debug(f"settings panel error: {_exc}")
            return

        brain = cfg.get("brain", {})
        primary = brain.get("primary", {})
        secondary = brain.get("secondary", {})

        self._brain_primary_path.setText(primary.get("model_path", ""))
        self._brain_secondary_path.setText(secondary.get("model_path", ""))
        self._brain_gpu_layers.setValue(primary.get("gpu_layers", -1))
        self._brain_threads.setValue(primary.get("threads", 8))
        self._brain_ctx_primary.setValue(primary.get("context_length", 32768))
        self._brain_ctx_secondary.setValue(secondary.get("context_length", 16384))

        tools = cfg.get("tools", {})
        rl = tools.get("rate_limit", {})
        self._scan_parallel.setValue(tools.get("max_parallel", 5))
        self._scan_rps.setValue(rl.get("max_requests_per_second", 10))
        self._scan_rps_host.setValue(rl.get("max_requests_per_host", 3))
        self._scan_timeout.setValue(tools.get("default_timeout", 300))

        idx = {"stealth": 0, "balanced": 1, "aggressive": 2}.get(
            cfg.get("scan_profile", "balanced"), 1
        )
        self._scan_profile.setCurrentIndex(idx)

        mode_idx = 0 if cfg.get("mode") == "semi-autonomous" else 1
        self._scan_mode.setCurrentIndex(mode_idx)

    def _on_save(self) -> None:
        """Save settings to .env (merge) + config YAML + set env vars for session."""
        # ── 1) Collect all env fields ──────────────────
        env_updates: OrderedDict[str, str] = OrderedDict()
        for env_key, field in self._env_fields.items():
            env_updates[env_key] = field.text().strip()

        # Set in current process so tools pick them up immediately
        for k, v in env_updates.items():
            if v:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)

        # ── 2) Merge into .env file (never overwrite) ─
        try:
            existing = _read_dotenv(self._env_path)
            existing.update(env_updates)
            _write_dotenv(self._env_path, existing)
        except Exception as exc:
            logger.error(f"Failed to write .env: {exc}")

        # ── 3) Update config YAML (comment-preserving) ──
        config_path = Path(self._config_path)
        try:
            if RuamelYAML is not None:
                ryaml = RuamelYAML()
                ryaml.preserve_quotes = True
                ryaml.default_flow_style = False

                if config_path.exists():
                    with open(config_path) as f:
                        cfg = ryaml.load(f) or {}
                else:
                    cfg = {}
            else:
                # Fallback to PyYAML (loses comments)
                if config_path.exists():
                    with open(config_path) as f:
                        cfg = yaml.safe_load(f) or {}
                else:
                    cfg = {}
                ryaml = None

            # Brain
            cfg.setdefault("brain", {}).setdefault("primary", {})
            cfg["brain"]["primary"]["model_path"] = self._brain_primary_path.text()
            cfg["brain"]["primary"]["gpu_layers"] = self._brain_gpu_layers.value()
            cfg["brain"]["primary"]["threads"] = self._brain_threads.value()
            cfg["brain"]["primary"]["context_length"] = self._brain_ctx_primary.value()

            cfg.setdefault("brain", {}).setdefault("secondary", {})
            cfg["brain"]["secondary"]["model_path"] = self._brain_secondary_path.text()
            cfg["brain"]["secondary"]["context_length"] = self._brain_ctx_secondary.value()

            # Scan
            cfg["mode"] = self._scan_mode.currentText()
            cfg["scan_profile"] = self._scan_profile.currentText()

            cfg.setdefault("tools", {})
            cfg["tools"]["max_parallel"] = self._scan_parallel.value()
            cfg["tools"]["default_timeout"] = self._scan_timeout.value()
            cfg["tools"].setdefault("rate_limit", {})
            cfg["tools"]["rate_limit"]["max_requests_per_second"] = self._scan_rps.value()
            cfg["tools"]["rate_limit"]["max_requests_per_host"] = self._scan_rps_host.value()

            with open(config_path, "w") as f:
                if ryaml is not None:
                    ryaml.dump(cfg, f)
                else:
                    yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)

            QMessageBox.information(self, "Settings", "Settings saved successfully.")
            self.settings_changed.emit()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings:\n{e}")
