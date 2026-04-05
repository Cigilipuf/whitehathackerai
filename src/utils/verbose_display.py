"""
WhiteHatHacker AI — Verbose Terminal Display (v2.1)

Rich Live Console ile gerçek zamanlı tarama ilerlemesi gösterir.
VS Code entegre terminalinde kullanılmak üzere tasarlanmıştır.

Kullanım:
  1. CLI'dan --verbose flag'i ile başlatılır
  2. Loguru sink olarak eklenir — tüm mesajlar otomatik yakalanır
  3. Rich Live panel ile stage/tool/brain durumu gösterilir

Özellikler:
  - Stage progress bar (10 aşama)
  - Aktif araç & brain durumu
  - Son N log mesajı (scrolling)
  - Bulgu sayacı (severity breakdown)
  - LLM inference zamanlaması
  - SSH tunnel durumu
"""

from __future__ import annotations

import time
import re
import threading
from collections import deque
from typing import Any

from loguru import logger
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# ============================================================
# Sabitler
# ============================================================

MAX_LOG_LINES = 25          # Terminalde görünen son log satır sayısı
REFRESH_RATE = 4            # Saniyede kaç kere güncellenir
STAGE_NAMES: list[str] = [
    "Scope Analysis",
    "Passive Recon",
    "Active Recon",
    "Enumeration",
    "Attack Surface",
    "Vuln Scan",
    "FP Elimination",
    "Reporting",
    "Platform Submit",
    "Knowledge Update",
]


# ============================================================
# VerboseState — paylaşılan durum (thread-safe)
# ============================================================

class VerboseState:
    """Thread-safe state container for verbose display."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Stage tracking
        self.target: str = ""
        self.session_id: str = ""
        self.mode: str = ""
        self.start_time: float = time.time()
        self.current_stage: str = ""
        self.current_stage_index: int = 0
        self.completed_stages: int = 0
        self.total_stages: int = 10

        # Tool tracking
        self.active_tool: str = ""
        self.tool_start_time: float = 0.0
        self.tools_run: int = 0

        # Brain tracking
        self.brain_active: bool = False
        self.brain_model: str = ""
        self.brain_call_count: int = 0
        self.brain_total_time: float = 0.0
        self.brain_last_time: float = 0.0

        # Finding tracking
        self.raw_findings: int = 0
        self.verified_findings: int = 0
        self.critical: int = 0
        self.high: int = 0
        self.medium: int = 0
        self.low: int = 0
        self.info: int = 0
        self.fp_eliminated: int = 0

        # Recon tracking
        self.subdomains: int = 0
        self.live_hosts: int = 0
        self.endpoints: int = 0

        # SSH tunnel
        self.ssh_status: str = "unknown"

        # Log lines
        self.log_lines: deque[str] = deque(maxlen=MAX_LOG_LINES)

        # Status message
        self.status_message: str = "Initializing..."

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    def increment(self, field: str, delta: int = 1) -> None:
        """Atomically increment a counter field."""
        with self._lock:
            current = getattr(self, field, 0)
            setattr(self, field, current + delta)

    def add_log(self, line: str) -> None:
        with self._lock:
            self.log_lines.append(line)

    def snapshot(self) -> dict[str, Any]:
        """Thread-safe snapshot of all state."""
        with self._lock:
            return {
                "target": self.target,
                "session_id": self.session_id,
                "mode": self.mode,
                "start_time": self.start_time,
                "elapsed": time.time() - self.start_time,
                "current_stage": self.current_stage,
                "current_stage_index": self.current_stage_index,
                "completed_stages": self.completed_stages,
                "total_stages": self.total_stages,
                "active_tool": self.active_tool,
                "tool_elapsed": time.time() - self.tool_start_time if self.tool_start_time > 0 else 0,
                "tools_run": self.tools_run,
                "brain_active": self.brain_active,
                "brain_model": self.brain_model,
                "brain_call_count": self.brain_call_count,
                "brain_total_time": self.brain_total_time,
                "brain_last_time": self.brain_last_time,
                "raw_findings": self.raw_findings,
                "verified_findings": self.verified_findings,
                "critical": self.critical,
                "high": self.high,
                "medium": self.medium,
                "low": self.low,
                "info": self.info,
                "fp_eliminated": self.fp_eliminated,
                "subdomains": self.subdomains,
                "live_hosts": self.live_hosts,
                "endpoints": self.endpoints,
                "ssh_status": self.ssh_status,
                "log_lines": list(self.log_lines),
                "status_message": self.status_message,
            }


# Global state — accessible from loguru sink and display
_verbose_state = VerboseState()


def get_verbose_state() -> VerboseState:
    """Get the global verbose state instance."""
    return _verbose_state


# ============================================================
# Loguru Sink — verbose display'e mesaj aktar
# ============================================================

# Seviye → renk mapping (Rich markup)
_LEVEL_STYLES: dict[str, str] = {
    "TRACE": "dim",
    "DEBUG": "dim cyan",
    "INFO": "green",
    "SUCCESS": "bold green",
    "WARNING": "bold yellow",
    "ERROR": "bold red",
    "CRITICAL": "bold white on red",
}


def verbose_sink(message: Any) -> None:
    """Loguru custom sink — mesajları verbose display'e yönlendirir.

    Bu fonksiyon loguru'ya sink olarak eklenir.
    Her log mesajı burada yakalanır ve state'e eklenir.
    """
    record = message.record
    level = record["level"].name
    msg = record["message"]

    # Kısa timestamp
    ts = record["time"].strftime("%H:%M:%S")

    # Seviye kısaltması
    level_short = level[:4].ljust(4)

    # Modül bilgisi
    module = record.get("name", "") or ""
    if module.startswith("src."):
        module = module[4:]
    if len(module) > 20:
        module = "..." + module[-17:]

    # Son mesajı state'e ekle (Rich markup ile)
    style = _LEVEL_STYLES.get(level, "")
    formatted = f"[dim]{ts}[/dim] [{style}]{level_short}[/{style}] [dim]{module}[/dim] {msg}"
    _verbose_state.add_log(formatted)

    # ── State güncellemeleri — log mesajlarından otomatik parse ──
    _auto_update_from_log(level, msg, record)


def _auto_update_from_log(level: str, msg: str, record: dict[str, Any]) -> None:
    """Log mesajlarından state bilgilerini otomatik çıkar."""
    msg_lower = msg.lower()

    # Stage detection
    if "STAGE:" in msg:
        stage_name = msg.split("STAGE:")[-1].strip()
        _verbose_state.update(
            current_stage=stage_name,
            status_message=f"Running: {stage_name}",
        )
        # Stage index'i bul
        for i, name in enumerate(STAGE_NAMES):
            if name.lower().replace(" ", "_") in stage_name.lower().replace(".", "_"):
                _verbose_state.update(current_stage_index=i)
                break

    # Stage completion
    if "stage completed" in msg_lower or "stage ok" in msg_lower:
        _verbose_state.increment("completed_stages")

    # Tool execution
    if "running" in msg_lower and ("tool" in msg_lower or "wrapper" in msg_lower):
        tool_name = msg.split("|")[0].strip() if "|" in msg else msg[:50]
        _verbose_state.update(
            active_tool=tool_name,
            tool_start_time=time.time(),
        )

    if "tool completed" in msg_lower or "collected" in msg_lower:
        _verbose_state.increment("tools_run")
        _verbose_state.update(active_tool="")

    # Brain/LLM calls
    if "brain inference" in msg_lower or "intelligence call" in msg_lower:
        _verbose_state.increment("brain_call_count")
        _verbose_state.update(brain_active=False)

    if "llm" in msg_lower and ("thinking" in msg_lower or "sending" in msg_lower):
        _verbose_state.update(brain_active=True)

    # Findings
    if "raw findings" in msg_lower or "raw_findings" in msg_lower:
        # Try to extract number
        match = re.search(r'(\d+)\s*raw', msg_lower)
        if match:
            _verbose_state.update(raw_findings=int(match.group(1)))

    if "verified" in msg_lower and "findings" in msg_lower:
        match = re.search(r'(\d+)\s*verified', msg_lower)
        if match:
            _verbose_state.update(verified_findings=int(match.group(1)))

    # Subdomains
    if "subdomain" in msg_lower:
        match = re.search(r'(\d+)\s*(?:unique\s*)?subdomain', msg_lower)
        if match:
            _verbose_state.update(subdomains=int(match.group(1)))

    # Live hosts
    if "live" in msg_lower and "host" in msg_lower:
        match = re.search(r'(\d+)\s*live', msg_lower)
        if match:
            _verbose_state.update(live_hosts=int(match.group(1)))

    # WORKFLOW COMPLETED
    if "workflow completed" in msg_lower:
        _verbose_state.update(
            status_message="SCAN COMPLETE",
            active_tool="",
            brain_active=False,
        )

    # SSH tunnel
    if "ssh tunnel" in msg_lower:
        if "ok" in msg_lower or "alive" in msg_lower or "active" in msg_lower:
            _verbose_state.update(ssh_status="alive")
        elif "down" in msg_lower or "dead" in msg_lower or "reconnect" in msg_lower:
            _verbose_state.update(ssh_status="reconnecting")


# ============================================================
# Rich Layout Builder
# ============================================================

def _build_header(s: dict[str, Any]) -> Panel:
    """Top header panel."""
    elapsed_min = s["elapsed"] / 60
    return Panel(
        f"[bold cyan]WhiteHatHacker AI v2.1[/bold cyan]  |  "
        f"Target: [bold white]{s['target']}[/bold white]  |  "
        f"Session: [dim]{s['session_id'][:12]}[/dim]  |  "
        f"Mode: [yellow]{s['mode']}[/yellow]  |  "
        f"Elapsed: [bold]{elapsed_min:.1f}m[/bold]  |  "
        f"SSH: {'[green]✓[/green]' if s['ssh_status'] == 'alive' else '[red]✗[/red]' if s['ssh_status'] == 'reconnecting' else '[dim]?[/dim]'}",
        style="cyan",
        height=3,
    )


def _build_stage_progress(s: dict[str, Any]) -> Panel:
    """Stage progress panel."""
    lines = []
    for i, name in enumerate(STAGE_NAMES):
        if i < s["completed_stages"]:
            lines.append(f"  [green]✓[/green] {name}")
        elif i == s["current_stage_index"] and s["completed_stages"] <= i:
            lines.append(f"  [bold yellow]▶ {name}[/bold yellow]  [dim]({s['status_message']})[/dim]")
        else:
            lines.append(f"  [dim]○ {name}[/dim]")

    return Panel(
        "\n".join(lines),
        title=f"[bold]Stages ({s['completed_stages']}/{s['total_stages']})[/bold]",
        border_style="blue",
    )


def _build_stats(s: dict[str, Any]) -> Panel:
    """Statistics panel."""
    brain_avg = s["brain_total_time"] / max(1, s["brain_call_count"])

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Label", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Subdomains", f"[cyan]{s['subdomains']}[/cyan]")
    table.add_row("Live Hosts", f"[cyan]{s['live_hosts']}[/cyan]")
    table.add_row("Endpoints", f"[cyan]{s['endpoints']}[/cyan]")
    table.add_row("", "")
    table.add_row("Raw Findings", f"[yellow]{s['raw_findings']}[/yellow]")
    table.add_row("Verified", f"[green]{s['verified_findings']}[/green]")
    table.add_row("FP Eliminated", f"[red]{s['fp_eliminated']}[/red]")
    table.add_row("", "")
    table.add_row("Critical", f"[bold red]{s['critical']}[/bold red]")
    table.add_row("High", f"[red]{s['high']}[/red]")
    table.add_row("Medium", f"[yellow]{s['medium']}[/yellow]")
    table.add_row("Low", f"[blue]{s['low']}[/blue]")
    table.add_row("Info", f"[dim]{s['info']}[/dim]")
    table.add_row("", "")
    table.add_row("Tools Run", f"{s['tools_run']}")
    table.add_row("Brain Calls", f"{s['brain_call_count']}")
    table.add_row("Brain Avg", f"{brain_avg:.1f}s")
    table.add_row("Brain Last", f"{s['brain_last_time']:.1f}s")

    return Panel(table, title="[bold]Statistics[/bold]", border_style="green")


def _build_activity(s: dict[str, Any]) -> Panel:
    """Current activity panel."""
    lines = []

    if s["active_tool"]:
        tool_elapsed = s["tool_elapsed"]
        lines.append(f"[bold yellow]🔧 Tool:[/bold yellow] {s['active_tool']} ({tool_elapsed:.0f}s)")
    else:
        lines.append("[dim]🔧 Tool: idle[/dim]")

    if s["brain_active"]:
        lines.append(f"[bold magenta]🧠 Brain:[/bold magenta] Processing... (model: {s['brain_model']})")
    else:
        lines.append(f"[dim]🧠 Brain: idle[/dim] (calls: {s['brain_call_count']})")

    return Panel(
        "\n".join(lines),
        title="[bold]Activity[/bold]",
        border_style="yellow",
        height=5,
    )


def _build_log_panel(s: dict[str, Any]) -> Panel:
    """Scrolling log panel."""
    if s["log_lines"]:
        # Son N satır
        text = "\n".join(s["log_lines"][-MAX_LOG_LINES:])
    else:
        text = "[dim]Waiting for log output...[/dim]"

    return Panel(
        text,
        title=f"[bold]Live Log (last {MAX_LOG_LINES} messages)[/bold]",
        border_style="dim",
    )


def build_layout(s: dict[str, Any]) -> Layout:
    """Full terminal layout."""
    layout = Layout()

    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="log", ratio=2),
    )

    layout["body"].split_row(
        Layout(name="stages", ratio=2),
        Layout(name="stats", ratio=1),
    )

    layout["header"].update(_build_header(s))
    layout["stages"].split_column(
        Layout(_build_stage_progress(s), name="stage_list"),
        Layout(_build_activity(s), name="activity", size=5),
    )
    layout["stats"].update(_build_stats(s))
    layout["log"].update(_build_log_panel(s))

    return layout


# ============================================================
# VerboseDisplay — Ana sınıf
# ============================================================

class VerboseDisplay:
    """Rich Live Display for verbose terminal output.

    Usage:
        display = VerboseDisplay()
        display.start()
        # ... scan runs, loguru messages flow via verbose_sink ...
        display.stop()
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._live: Live | None = None
        self._stop_event = threading.Event()
        self._update_thread: threading.Thread | None = None
        self._sink_id: int | None = None

    def start(self) -> None:
        """Start the verbose display and add loguru sink."""
        # Loguru'ya custom sink ekle
        self._sink_id = logger.add(
            verbose_sink,
            level="DEBUG",
            format="{message}",  # raw message — sink kendi formatlar
            filter=lambda record: True,
        )

        # Rich Live başlat
        self._live = Live(
            build_layout(_verbose_state.snapshot()),
            console=self.console,
            refresh_per_second=REFRESH_RATE,
            screen=False,  # VS Code terminali scroll desteklemiyor iyi
        )
        self._live.start()

        # Background güncelleme thread'i
        self._stop_event.clear()
        self._update_thread = threading.Thread(
            target=self._update_loop, daemon=True
        )
        self._update_thread.start()

        logger.debug("VerboseDisplay started")

    def stop(self) -> None:
        """Stop the verbose display and remove loguru sink."""
        self._stop_event.set()

        if self._update_thread:
            self._update_thread.join(timeout=2)

        if self._live:
            self._live.stop()
            self._live = None

        if self._sink_id is not None:
            try:
                logger.remove(self._sink_id)
            except ValueError:
                pass
            self._sink_id = None

    def _update_loop(self) -> None:
        """Background thread — layout'u periyodik günceller."""
        while not self._stop_event.is_set():
            try:
                if self._live:
                    snapshot = _verbose_state.snapshot()
                    self._live.update(build_layout(snapshot))
            except Exception as _exc:
                pass  # display hataları sessizce atlanır
            self._stop_event.wait(1.0 / REFRESH_RATE)

    def __enter__(self) -> "VerboseDisplay":
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop()


# ============================================================
# Convenience: Simple verbose log mode (non-Rich, plain text)
# ============================================================

def setup_simple_verbose_sink() -> int:
    """Add a simple colorized console sink for verbose mode.

    Simpler alternative to full Rich Live display — just adds detailed
    log messages to stderr with colors. Works well in any terminal.

    Returns:
        Sink ID for later removal.
    """
    def _simple_sink(message: Any) -> None:
        record = message.record
        level = record["level"].name
        ts = record["time"].strftime("%H:%M:%S")
        name = record.get("name", "") or ""
        if name.startswith("src."):
            name = name[4:]
        msg = record["message"]

        # ANSI renkleri direkt
        colors = {
            "TRACE": "\033[2m",     # dim
            "DEBUG": "\033[36m",    # cyan
            "INFO": "\033[32m",     # green
            "SUCCESS": "\033[1;32m",# bold green
            "WARNING": "\033[1;33m",# bold yellow
            "ERROR": "\033[1;31m",  # bold red
            "CRITICAL": "\033[1;41m",# bold red bg
        }
        reset = "\033[0m"
        color = colors.get(level, "")

        print(
            f"\033[2m{ts}\033[0m {color}{level[:4]:4s}{reset} "
            f"\033[2m{name:20s}\033[0m {msg}",
            flush=True,
        )

        # Ayrıca verbose state'i de güncelle
        _auto_update_from_log(level, msg, record)

    return logger.add(
        _simple_sink,
        level="DEBUG",
        format="{message}",
    )


__all__ = [
    "VerboseDisplay",
    "VerboseState",
    "get_verbose_state",
    "verbose_sink",
    "setup_simple_verbose_sink",
]
