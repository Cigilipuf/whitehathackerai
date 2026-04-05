"""
WhiteHatHacker AI — Güvenlik Aracı Temel Sınıfı (Abstract Base)

Tüm araç wrapper'ları bu sınıftan türetilir.
Her araç: async çalıştırma, çıktı parse, scope doğrulama, rate limiting sağlar.
"""

from __future__ import annotations

import asyncio
import os
import re
import resource
import shutil
import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from loguru import logger
from pydantic import BaseModel, ConfigDict, field_validator

from src.utils.constants import (
    DEFAULT_TOOL_TIMEOUT,
    RiskLevel,
    ScanProfile,
    SeverityLevel,
    ToolCategory,
)

# Maximum stdout/stderr size to keep in memory (10 MB).
# Tools like katana can produce 120MB+ of raw output; truncating
# prevents OOM and excessive memory pressure.
MAX_OUTPUT_BYTES: int = 10 * 1024 * 1024  # 10 MB


# ============================================================
# Veri Modelleri
# ============================================================

class Finding(BaseModel):
    """Tek bir güvenlik bulgusu."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    title: str                                   # Bulgu başlığı
    description: str = ""                        # Açıklama
    vulnerability_type: str = ""                 # Zafiyet türü
    severity: SeverityLevel = SeverityLevel.INFO  # Ciddiyet
    confidence: float = 50.0                     # Güven skoru (0-100)

    # Hedef bilgileri
    target: str = ""                             # Hedef URL/IP
    endpoint: str = ""                           # Endpoint
    parameter: str = ""                          # Parametre adı

    # Teknik detaylar
    payload: str = ""                            # Kullanılan payload
    # NOTE: Finding.evidence is a str (joined via _coerce_evidence validator).
    # ReportFinding.evidence in report_generator.py is list[str].
    # Conversion happens in _convert_finding() which wraps the string in a list.
    evidence: str = ""                           # Kanıt (response snippet vb.)
    http_request: str = ""                       # HTTP istek
    http_response: str = ""                      # HTTP yanıt

    @field_validator("endpoint", "target", mode="before")
    @classmethod
    def _coerce_url_fields(cls, v: Any) -> str:
        """Coerce list values to a single string (e.g. from Swagger parsers)."""
        if v is None:
            return ""
        if isinstance(v, list):
            return v[0] if v else ""
        return v if isinstance(v, str) else str(v)

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v: Any) -> str:
        """Accept list[str] and join into a single string."""
        if v is None:
            return ""
        if isinstance(v, list):
            return "\n".join(str(item) for item in v)
        return v if isinstance(v, str) else str(v)

    # Kaynak
    tool_name: str = ""                          # Bulan araç
    raw_output: str = ""                         # Ham araç çıktısı

    # Metadata
    cvss_score: float | None = None              # CVSS skoru
    cwe_id: str = ""                             # CWE numarası
    cve_id: str = ""                             # CVE numarası (ör: CVE-2014-0160)
    remediation: str = ""                        # Düzeltme önerisi
    references: list[str] = []                   # Referanslar
    tags: list[str] = []                         # Etiketler
    timestamp: str = ""                          # Bulunma zamanı
    metadata: dict[str, Any] = {}                # Ek metadata (cross-verify info vb.)


class ToolResult(BaseModel):
    """Araç çalıştırma sonucu."""

    tool_name: str                               # Araç adı
    success: bool = True                         # Başarılı mı?
    exit_code: int = 0                           # Çıkış kodu

    # Çıktılar
    stdout: str = ""                             # Standart çıktı
    stderr: str = ""                             # Hata çıktısı
    findings: list[Finding] = []                 # Parse edilmiş bulgular

    # Performans
    execution_time: float = 0.0                  # Çalışma süresi (saniye)
    command: str = ""                            # Çalıştırılan komut

    # Metadata
    target: str = ""                             # Hedef
    error_message: str = ""                      # Hata mesajı
    metadata: dict[str, Any] = {}                # Ek veriler

    @property
    def raw_output(self) -> str:
        """stdout alias — pipeline handler'lar uyumluluğu için."""
        return self.stdout


# ============================================================
# Araç Temel Sınıfı
# ============================================================

class SecurityTool(ABC):
    """
    Tüm güvenlik araçları için abstract temel sınıf.

    Her araç wrapper'ı bu sınıftan türetilir ve şu metotları implement eder:
    - run(): Aracı çalıştır
    - parse_output(): Ham çıktıyı Finding'lere dönüştür
    - build_command(): Komut oluştur
    - is_available(): Kurulu mu kontrol et
    """

    # Alt sınıfların override etmesi gereken class değişkenleri
    name: str = "unknown_tool"
    category: ToolCategory = ToolCategory.SCANNER
    description: str = ""
    binary_name: str = ""                        # Çalıştırılabilir dosya adı
    requires_root: bool = False
    risk_level: RiskLevel = RiskLevel.SAFE
    supported_profiles: tuple[ScanProfile, ...] = (
        ScanProfile.STEALTH, ScanProfile.BALANCED, ScanProfile.AGGRESSIVE,
    )

    # B1: Category-aware default timeout (seconds).  Tools may override.
    # Recon tools are fast; scanners/exploit tools need more time.
    _CATEGORY_TIMEOUT: ClassVar[dict[str, int]] = {
        "recon.subdomain": 300,
        "recon.port_scan": 600,
        "recon.web_discovery": 300,
        "recon.dns": 120,
        "recon.osint": 300,
        "recon.tech_detect": 120,
        "scanner": 600,
        "fuzzing": 900,
        "exploit": 900,
        "network": 300,
        "api_tool": 600,
        "crypto": 300,
        "proxy": 600,
    }
    default_timeout: int = 600  # fallback; __init_subclass__ may override

    # P4-1: Per-tool memory limit in bytes for subprocess RLIMIT_AS.
    # Subclasses can override (e.g. `memory_limit = 512 * 1024 * 1024`).
    # Default is 2GB which is the global conservative limit.
    memory_limit: int = 2 * 1024 * 1024 * 1024  # 2 GB

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Auto-set default_timeout from category if subclass didn't explicitly set it
        if "default_timeout" not in cls.__dict__:
            cat = cls.__dict__.get("category", None)
            if cat is not None:
                cat_val = cat.value if hasattr(cat, "value") else str(cat)
                cls.default_timeout = cls._CATEGORY_TIMEOUT.get(cat_val, 600)

    def __init__(self) -> None:
        self._binary_path: str | None = None
        self._version: str | None = None
        self._run_count: int = 0
        self._total_time: float = 0.0

    # ── Abstract Metotlar (implement edilmesi zorunlu) ────────

    @abstractmethod
    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        """
        Aracı hedef üzerinde çalıştır.

        Args:
            target: Hedef URL/IP/domain
            options: Araç-spesifik opsiyonlar
            profile: Tarama profili (stealth/balanced/aggressive)

        Returns:
            ToolResult
        """
        ...

    @abstractmethod
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        """
        Ham araç çıktısını Finding listesine dönüştür.

        Args:
            raw_output: Aracın ham stdout çıktısı
            target: Hedef (bağlam için)

        Returns:
            Finding listesi
        """
        ...

    @abstractmethod
    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        """
        Çalıştırılacak komutu oluştur.

        Returns:
            Komut parçaları listesi (subprocess.run için)
        """
        ...

    # ── Implement Edilmiş Ortak Metotlar ──────────────────────

    def _resolve_binary(self) -> str | None:
        """
        Resolve the binary path, checking PATH and ~/go/bin/ for Go tools.

        Many security tools (subfinder, httpx, dalfox, katana, nuclei etc.)
        are Go binaries installed via `go install` to ~/go/bin/.  This
        directory is often NOT in the system PATH.
        """
        import os

        # Return cached result to avoid re-resolving (binary_name gets mutated)
        if self._binary_path is not None:
            return self._binary_path

        # 1. Check PATH first
        path = shutil.which(self.binary_name)
        if path:
            self._binary_path = path
            return path

        # 2. Check .venv/bin/ (pip-installed Python tools)
        venv_bin = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            ".venv", "bin", self.binary_name,
        )
        if os.path.isfile(venv_bin) and os.access(venv_bin, os.X_OK):
            self._binary_path = venv_bin
            return venv_bin

        # 3. Check ~/go/bin/ (Go tools installed via `go install`)
        go_bin = os.path.expanduser(f"~/go/bin/{self.binary_name}")
        if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
            self._binary_path = go_bin
            return go_bin

        # 4. Check /usr/local/go/bin/ (alternate Go install location)
        alt_go_bin = f"/usr/local/go/bin/{self.binary_name}"
        if os.path.isfile(alt_go_bin) and os.access(alt_go_bin, os.X_OK):
            self._binary_path = alt_go_bin
            return alt_go_bin

        # 5. Check ~/tools/{name}/{name}.py (standalone Python tools)
        # No execute permission needed — these run via 'python3'
        tools_py = os.path.expanduser(f"~/tools/{self.binary_name}/{self.binary_name}.py")
        if os.path.isfile(tools_py):
            self._binary_path = tools_py
            return tools_py

        return None

    def is_available(self) -> bool:
        """Aracın sistemde kurulu ve erişilebilir olup olmadığını kontrol et."""
        return self._resolve_binary() is not None

    def get_binary_path(self) -> str | None:
        """Aracın tam dosya yolunu döndür."""
        if self._binary_path is None:
            self._resolve_binary()
        return self._binary_path

    async def get_version(self) -> str:
        """Aracın versiyonunu döndür."""
        if self._version:
            return self._version

        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary_name, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = (stdout or stderr).decode("utf-8", errors="replace").strip()
            self._version = output.split("\n")[0][:100]  # İlk satır, max 100 karakter
        except (FileNotFoundError, OSError):
            self._version = "unknown"

        return self._version

    def get_default_options(self, profile: ScanProfile) -> dict[str, Any]:
        """Tarama profiline göre varsayılan opsiyonları döndür."""
        base_options: dict[str, Any] = {}

        match profile:
            case ScanProfile.STEALTH:
                base_options.update({
                    "rate_limit": 1,          # 1 req/s
                    "timeout": 30,
                    "retries": 1,
                    "delay": 2,               # İstekler arası bekleme
                    "random_agent": True,
                })
            case ScanProfile.BALANCED:
                base_options.update({
                    "rate_limit": 5,
                    "timeout": 15,
                    "retries": 2,
                    "delay": 0.5,
                    "random_agent": True,
                })
            case ScanProfile.AGGRESSIVE:
                base_options.update({
                    "rate_limit": 50,
                    "timeout": 10,
                    "retries": 3,
                    "delay": 0,
                    "random_agent": False,
                })

        return base_options

    async def execute_command(
        self,
        command: list[str],
        timeout: int = DEFAULT_TOOL_TIMEOUT,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[str, str, int]:
        """
        Komutu async olarak çalıştır.

        Returns:
            (stdout, stderr, return_code)
        """
        # Defensive: ensure timeout is numeric (0 is valid = no timeout)
        if timeout is None:
            timeout = DEFAULT_TOOL_TIMEOUT
        else:
            timeout = int(timeout)
        # 0 means "use default" in practice; truly no-timeout is dangerous
        if timeout <= 0:
            timeout = DEFAULT_TOOL_TIMEOUT

        # Auto-resolve binary path: if command[0] matches self.binary_name
        # and is not already an absolute path, replace with resolved path.
        # This handles Python-based tools installed outside PATH (e.g. ~/tools/).
        if command and command[0] == self.binary_name:
            resolved = self._resolve_binary()
            if resolved and resolved != self.binary_name:
                # Python scripts (.py) need to be invoked via python3
                if resolved.endswith(".py"):
                    command = ["python3", resolved] + list(command[1:])
                    # Standalone tools in ~/tools/ use relative imports;
                    # run from their own directory so imports resolve.
                    if "/tools/" in resolved and cwd is None:
                        cwd = os.path.dirname(resolved)
                else:
                    command = [resolved] + list(command[1:])

        # Auto-prefix sudo for tools that require root privileges
        if self.requires_root and os.name == "posix" and os.getuid() != 0:
            sudo_path = shutil.which("sudo")
            if sudo_path and command[0] != sudo_path:
                command = [sudo_path, "-n"] + list(command)

        cmd_str = " ".join(command)
        logger.debug(f"Executing: {cmd_str[:200]}")

        start = time.monotonic()

        try:
            # Capture memory_limit from instance for closure
            _mem_limit = getattr(self, "memory_limit", 2 * 1024 * 1024 * 1024)

            def _set_rlimits() -> None:
                """Set conservative resource limits for child processes."""
                try:
                    # CPU: match requested timeout (hard limit = 2x)
                    cpu_soft = max(timeout, 60)
                    resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_soft * 2))
                    # Virtual memory: per-tool limit (default 2GB)
                    resource.setrlimit(resource.RLIMIT_AS, (_mem_limit, _mem_limit))
                    # File size: 100 MB
                    fsize = 100 * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
                except (ValueError, OSError) as _rl_err:
                    # preexec_fn runs in forked child — logger unsafe, use stderr
                    import sys
                    print(f"[WHAI] rlimit setup failed: {_rl_err}", file=sys.stderr)

            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                start_new_session=True,  # Create process group for clean kill
                preexec_fn=_set_rlimits,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                # Graceful shutdown: SIGTERM first, then SIGKILL
                import os as _os
                import signal as _signal
                try:
                    pgid = _os.getpgid(proc.pid)
                    _os.killpg(pgid, _signal.SIGTERM)
                    # Wait up to 5 seconds for graceful exit
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        # Force kill
                        try:
                            _os.killpg(pgid, _signal.SIGKILL)
                        except (ProcessLookupError, PermissionError, OSError):
                            pass
                except (ProcessLookupError, PermissionError, OSError):
                    # Fallback to direct kill
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                try:
                    await proc.wait()
                except Exception as _exc:
                    logger.debug(f"base error: {_exc}")
                elapsed = time.monotonic() - start
                logger.warning(f"Tool timeout | tool={self.name} | timeout={timeout}s | elapsed={elapsed:.1f}s")
                return "", f"TIMEOUT after {timeout}s", -1

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            # M7 fix: strip ANSI escape sequences from tool output
            _ansi_re = re.compile(r'\x1b(?:\[[0-9;]*[a-zA-Z]|\(B|\]\d*;[^\x07]*\x07|\[\?[0-9;]*[hl])|\r|\x1b\[[0-9]*[JKGF]')
            stdout = _ansi_re.sub('', stdout)
            stderr = _ansi_re.sub('', stderr)

            # M5 fix: truncate oversized output with marker
            if len(stdout) > MAX_OUTPUT_BYTES:
                _orig_len = len(stdout)
                logger.warning(
                    f"Truncating stdout | tool={self.name} | "
                    f"original={_orig_len} | limit={MAX_OUTPUT_BYTES}"
                )
                stdout = stdout[:MAX_OUTPUT_BYTES] + f"\n[OUTPUT TRUNCATED: {_orig_len} bytes → {MAX_OUTPUT_BYTES}]"
            if len(stderr) > MAX_OUTPUT_BYTES:
                _orig_len = len(stderr)
                logger.warning(
                    f"Truncating stderr | tool={self.name} | "
                    f"original={_orig_len} | limit={MAX_OUTPUT_BYTES}"
                )
                stderr = stderr[:MAX_OUTPUT_BYTES] + f"\n[OUTPUT TRUNCATED: {_orig_len} bytes → {MAX_OUTPUT_BYTES}]"

            elapsed = time.monotonic() - start
            self._run_count += 1
            self._total_time += elapsed

            logger.debug(
                f"Tool completed | tool={self.name} | "
                f"exit={proc.returncode} | time={elapsed:.1f}s | "
                f"stdout_bytes={len(stdout)} | stderr_bytes={len(stderr)}"
            )

            # Log stderr content for failed tools (critical for debugging)
            if proc.returncode != 0 and stderr.strip():
                logger.warning(
                    f"Tool stderr | tool={self.name} | exit={proc.returncode} | "
                    f"stderr={stderr.strip()[:500]}"
                )

            return stdout, stderr, proc.returncode if proc.returncode is not None else -1

        except FileNotFoundError:
            logger.error(f"Tool not found: {self.binary_name}")
            return "", f"Tool not found: {self.binary_name}", -1
        except Exception as e:
            logger.error(f"Tool execution error | tool={self.name} | error={e}")
            return "", str(e), -1

    def get_stats(self) -> dict[str, Any]:
        """Araç istatistikleri."""
        return {
            "name": self.name,
            "category": self.category,
            "available": self.is_available(),
            "run_count": self._run_count,
            "total_time": round(self._total_time, 2),
            "avg_time": round(self._total_time / max(1, self._run_count), 2),
            "risk_level": self.risk_level,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} category={self.category}>"


__all__ = ["SecurityTool", "ToolResult", "Finding"]
