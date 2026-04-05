"""
WhiteHatHacker AI — Geliştirme Tanılama Modülü (Dev Diagnostics)

Bu modül, geliştirme sürecinde projenin sağlık durumunu kontrol eder:
  • Import doğrulama — tüm modüllerin import edilebilirliği
  • Konfigürasyon doğrulama — settings.yaml tutarlılığı
  • Bağımlılık kontrolü — eksik pip paketleri
  • Araç kullanılabilirliği — os-level tool check
  • Brain engine bağlantı testi — LLM erişilebilirliği
  • Genel sistem sağlığı — RAM, disk, GPU
"""

from __future__ import annotations

import asyncio
import importlib
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any



# ============================================================
# Veri Modelleri
# ============================================================

@dataclass
class DiagnosticResult:
    """Tek bir tanılama kontrolünün sonucu."""
    name: str
    category: str  # import | config | dependency | tool | brain | system
    status: str     # ok | warn | fail | skip
    message: str = ""
    duration_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiagnosticReport:
    """Tam tanılama raporu."""
    results: list[DiagnosticResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    timestamp: str = ""

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.status == "ok")

    @property
    def warn_count(self) -> int:
        return sum(1 for r in self.results if r.status == "warn")

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == "fail")

    @property
    def skip_count(self) -> int:
        return sum(1 for r in self.results if r.status == "skip")

    @property
    def summary(self) -> str:
        total = len(self.results)
        return (
            f"Diagnostics: {total} checks | "
            f"OK={self.ok_count} WARN={self.warn_count} FAIL={self.fail_count} SKIP={self.skip_count} | "
            f"{self.total_duration_ms:.0f}ms"
        )

    def to_text(self) -> str:
        """Okunabilir text rapor."""
        lines = [
            "=" * 70,
            "  WhiteHatHacker AI — Diagnostic Report",
            f"  {self.timestamp}",
            "=" * 70,
            "",
        ]

        # Kategorilere göre grupla
        categories: dict[str, list[DiagnosticResult]] = {}
        for r in self.results:
            categories.setdefault(r.category, []).append(r)

        status_icons = {"ok": "✓", "warn": "⚠", "fail": "✗", "skip": "○"}

        for cat, items in categories.items():
            lines.append(f"── {cat.upper()} ──")
            for r in items:
                icon = status_icons.get(r.status, "?")
                line = f"  {icon} {r.name}"
                if r.message:
                    line += f" — {r.message}"
                if r.duration_ms > 100:
                    line += f" ({r.duration_ms:.0f}ms)"
                lines.append(line)
            lines.append("")

        lines.append(self.summary)
        lines.append("=" * 70)
        return "\n".join(lines)


# ============================================================
# Tanılama Kontrolleri
# ============================================================

def _check_import(module_path: str, attrs: list[str] | None = None) -> DiagnosticResult:
    """Bir modülün import edilebilirliğini kontrol et."""
    t0 = time.perf_counter()
    try:
        mod = importlib.import_module(module_path)
        if attrs:
            for attr in attrs:
                getattr(mod, attr)
        duration = (time.perf_counter() - t0) * 1000
        return DiagnosticResult(
            name=module_path,
            category="import",
            status="ok",
            duration_ms=duration,
        )
    except Exception as e:
        duration = (time.perf_counter() - t0) * 1000
        return DiagnosticResult(
            name=module_path,
            category="import",
            status="fail",
            message=str(e)[:200],
            duration_ms=duration,
        )


def _check_pip_package(package: str, import_name: str | None = None) -> DiagnosticResult:
    """Bir pip paketinin kurulu olduğunu kontrol et."""
    try:
        importlib.import_module(import_name or package)
        return DiagnosticResult(name=f"pip:{package}", category="dependency", status="ok")
    except ImportError:
        return DiagnosticResult(
            name=f"pip:{package}",
            category="dependency",
            status="fail",
            message=f"Not installed: pip install {package}",
        )


def _check_system_tool(tool_name: str, test_arg: str = "--version") -> DiagnosticResult:
    """Bir sistem aracının PATH'te olduğunu kontrol et."""
    path = shutil.which(tool_name)
    if not path:
        return DiagnosticResult(
            name=f"tool:{tool_name}",
            category="tool",
            status="warn",
            message="Not found in PATH",
        )
    try:
        result = subprocess.run(
            [path, test_arg],
            capture_output=True, text=True, timeout=10,
        )
        version_line = (result.stdout or result.stderr).strip().split("\n")[0][:100]
        return DiagnosticResult(
            name=f"tool:{tool_name}",
            category="tool",
            status="ok",
            message=version_line,
            details={"path": path},
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return DiagnosticResult(
            name=f"tool:{tool_name}",
            category="tool",
            status="warn",
            message=f"Found at {path} but {test_arg} failed: {e}",
        )


def _check_system_resources() -> list[DiagnosticResult]:
    """Sistem kaynakları kontrolü."""
    results: list[DiagnosticResult] = []

    # RAM
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    gb = kb / (1024 * 1024)
                    status = "ok" if gb >= 16 else "warn"
                    results.append(DiagnosticResult(
                        name="system:ram",
                        category="system",
                        status=status,
                        message=f"{gb:.1f} GB total",
                    ))
                    break
    except FileNotFoundError:
        results.append(DiagnosticResult(
            name="system:ram", category="system", status="skip", message="Cannot read /proc/meminfo"
        ))

    # Disk
    try:
        total, used, free = shutil.disk_usage(".")
        free_gb = free / (1024**3)
        status = "ok" if free_gb >= 10 else "warn"
        results.append(DiagnosticResult(
            name="system:disk",
            category="system",
            status=status,
            message=f"{free_gb:.1f} GB free",
        ))
    except Exception as e:
        results.append(DiagnosticResult(
            name="system:disk", category="system", status="skip", message=str(e)
        ))

    # GPU
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            results.append(DiagnosticResult(
                name="system:gpu",
                category="system",
                status="ok",
                message=result.stdout.strip(),
            ))
        else:
            results.append(DiagnosticResult(
                name="system:gpu", category="system", status="skip", message="No NVIDIA GPU"
            ))
    except FileNotFoundError:
        results.append(DiagnosticResult(
            name="system:gpu", category="system", status="skip", message="nvidia-smi not found"
        ))

    # Python version
    results.append(DiagnosticResult(
        name="system:python",
        category="system",
        status="ok" if sys.version_info >= (3, 11) else "warn",
        message=f"{platform.python_version()} ({platform.machine()})",
    ))

    return results


def _check_config() -> list[DiagnosticResult]:
    """Konfigürasyon dosyaları kontrolü."""
    results: list[DiagnosticResult] = []

    config_files = [
        "config/settings.yaml",
        "config/models.yaml",
        "config/tools.yaml",
        "config/platforms.yaml",
    ]

    for cf in config_files:
        p = Path(cf)
        if p.exists():
            try:
                import yaml
                with open(p) as f:
                    data = yaml.safe_load(f)
                if data:
                    results.append(DiagnosticResult(
                        name=cf, category="config", status="ok",
                        message=f"{len(data)} top-level keys",
                    ))
                else:
                    results.append(DiagnosticResult(
                        name=cf, category="config", status="warn", message="Empty file",
                    ))
            except Exception as e:
                results.append(DiagnosticResult(
                    name=cf, category="config", status="fail", message=f"Parse error: {e}",
                ))
        else:
            results.append(DiagnosticResult(
                name=cf, category="config", status="warn", message="File not found",
            ))

    # .env dosyası
    env_file = Path(".env")
    if env_file.exists():
        results.append(DiagnosticResult(
            name=".env", category="config", status="ok", message="Present",
        ))
    else:
        results.append(DiagnosticResult(
            name=".env", category="config", status="warn",
            message="Not found — copy from .env.example",
        ))

    return results


async def _check_brain_connectivity() -> list[DiagnosticResult]:
    """Brain engine LLM bağlantı kontrolü."""
    results: list[DiagnosticResult] = []

    try:
        from src.main import load_config
        config = load_config("config/settings.yaml")
        brain_config = config.get("brain", {})

        for label, cfg in [("primary", brain_config.get("primary", {})),
                           ("secondary", brain_config.get("secondary", {}))]:
            backend = cfg.get("backend", "remote")
            api_url = cfg.get("api_url", "")

            if backend == "remote" and api_url:
                try:
                    import httpx
                    t0 = time.perf_counter()
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.get(f"{api_url}/v1/models")
                    duration = (time.perf_counter() - t0) * 1000

                    if resp.status_code == 200:
                        data = resp.json()
                        model_ids = [m.get("id", "?") for m in data.get("data", [])]
                        results.append(DiagnosticResult(
                            name=f"brain:{label}",
                            category="brain",
                            status="ok",
                            message=f"{api_url} → models: {', '.join(model_ids[:3])}",
                            duration_ms=duration,
                        ))
                    else:
                        results.append(DiagnosticResult(
                            name=f"brain:{label}",
                            category="brain",
                            status="warn",
                            message=f"{api_url} → HTTP {resp.status_code}",
                            duration_ms=duration,
                        ))
                except Exception as e:
                    results.append(DiagnosticResult(
                        name=f"brain:{label}",
                        category="brain",
                        status="fail",
                        message=f"{api_url} → {type(e).__name__}: {e}",
                    ))
            elif backend == "local":
                model_path = cfg.get("model_path", "")
                if model_path and Path(model_path).exists():
                    results.append(DiagnosticResult(
                        name=f"brain:{label}",
                        category="brain",
                        status="ok",
                        message=f"Local model: {model_path}",
                    ))
                else:
                    results.append(DiagnosticResult(
                        name=f"brain:{label}",
                        category="brain",
                        status="warn",
                        message=f"Local model not found: {model_path or '(empty)'}",
                    ))
            else:
                results.append(DiagnosticResult(
                    name=f"brain:{label}",
                    category="brain",
                    status="warn",
                    message=f"No api_url configured for {backend} backend",
                ))
    except Exception as e:
        results.append(DiagnosticResult(
            name="brain:config",
            category="brain",
            status="fail",
            message=f"Cannot load brain config: {e}",
        ))

    return results


# ============================================================
# Ana Tanılama Çalıştırıcısı
# ============================================================

async def run_full_diagnostics(
    check_tools: bool = True,
    check_brain: bool = True,
) -> DiagnosticReport:
    """Tüm tanılama kontrollerini çalıştır ve rapor üret."""
    from datetime import datetime, timezone

    report = DiagnosticReport(
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    t0 = time.perf_counter()

    # ── 1. Kritik modül import'ları ──
    critical_modules = [
        ("src.brain.engine", ["BrainEngine", "ModelConfig", "InferenceBackend"]),
        ("src.brain.router", ["BrainRouter"]),
        ("src.tools.base", ["SecurityTool", "Finding"]),
        ("src.tools.registry", ["tool_registry"]),
        ("src.tools.executor", ["ToolExecutor"]),
        ("src.utils.scope_validator", ["ScopeValidator"]),
        ("src.utils.rate_limiter", ["RateLimiter"]),
        ("src.fp_engine.fp_detector", ["FPDetector"]),
        ("src.workflow.orchestrator", ["WorkflowOrchestrator"]),
        ("src.workflow.pipelines.full_scan", ["build_full_scan_pipeline"]),
        ("src.analysis.vulnerability_analyzer", ["VulnerabilityAnalyzer"]),
        ("src.reporting.report_generator", ["ReportGenerator"]),
        ("src.integrations.database", ["DatabaseManager"]),
        ("src.utils.logger", ["setup_logger"]),
        ("src.cli", ["app"]),
        ("src.main", ["load_config", "initialize_app"]),
    ]
    for mod_path, attrs in critical_modules:
        report.results.append(_check_import(mod_path, attrs))

    # ── 2. Pip bağımlılıkları ──
    pip_packages = [
        ("pydantic", None),
        ("loguru", None),
        ("typer", None),
        ("rich", None),
        ("httpx", None),
        ("yaml", "yaml"),
        ("aiohttp", None),
        ("aiofiles", None),
        ("dotenv", "dotenv"),
        ("tenacity", None),
    ]
    for pkg, imp in pip_packages:
        report.results.append(_check_pip_package(pkg, imp))

    # ── 3. Konfigürasyon ──
    report.results.extend(_check_config())

    # ── 4. Sistem kaynakları ──
    report.results.extend(_check_system_resources())

    # ── 5. Güvenlik araçları (opsiyonel) ──
    if check_tools:
        core_tools = [
            ("nmap", "--version"),
            ("nuclei", "-version"),
            ("subfinder", "-version"),
            ("httpx", "-version"),
            ("ffuf", "-V"),
            ("sqlmap", "--version"),
            ("nikto", "-Version"),
            ("gobuster", "version"),
        ]
        for tool, arg in core_tools:
            report.results.append(_check_system_tool(tool, arg))

    # ── 6. Brain bağlantısı (opsiyonel) ──
    if check_brain:
        report.results.extend(await _check_brain_connectivity())

    report.total_duration_ms = (time.perf_counter() - t0) * 1000
    return report


def run_diagnostics_sync(check_tools: bool = True, check_brain: bool = True) -> DiagnosticReport:
    """Senkron wrapper — CLI'dan çağırmak için."""
    return asyncio.run(run_full_diagnostics(check_tools=check_tools, check_brain=check_brain))


# ============================================================
# Public API
# ============================================================

__all__ = [
    "DiagnosticResult",
    "DiagnosticReport",
    "run_full_diagnostics",
    "run_diagnostics_sync",
]
