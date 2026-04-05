"""
WhiteHatHacker AI — Amass Wrapper

OWASP Amass — In-depth attack surface mapping & asset discovery.
Passive ve active modlarda subdomain keşfi yapar.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class AmassWrapper(SecurityTool):
    """
    Amass — Subdomain enumeration & attack surface mapping.

    Modlar:
      enum: Subdomain keşfi (passive/active)
      intel: OSINT & ASN bilgisi

    Not: Amass v5 libpostal data download'u birçok sistemde sorun çıkarır.
    is_available() bunu tespit ederek amass'ı devre dışı bırakır.
    """

    name = "amass"
    category = ToolCategory.RECON_SUBDOMAIN
    description = "In-depth attack surface mapping and asset discovery"
    binary_name = "amass"
    requires_root = False
    risk_level = RiskLevel.SAFE
    default_timeout = 600  # 10min — subdomain enum with many data sources
    _smoke_tested: bool = False
    _smoke_ok: bool = False

    def is_available(self) -> bool:
        """Override: binary var mı VE libpostal data download'a takılıyor mu kontrol et."""
        if not super().is_available():
            return False
        # Smoke test: amass'ı çok kısa timeout ile çalıştır
        if not self._smoke_tested:
            self._smoke_tested = True
            import subprocess
            import concurrent.futures
            try:
                # Run in thread pool to avoid blocking the async event loop
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        subprocess.run,
                        ["amass", "enum", "-passive", "-d", "example.com", "-timeout", "1"],
                        capture_output=True, text=True, timeout=10,
                    )
                    future.result(timeout=12)
                self._smoke_ok = True
            except subprocess.TimeoutExpired:
                logger.warning(
                    "Amass hangs on libpostal data download — marking as unavailable. "
                    "Run 'amass' manually once to complete the download."
                )
                self._smoke_ok = False
            except Exception as e:
                logger.warning(f"Amass smoke test failed: {e}")
                self._smoke_ok = False
        return self._smoke_ok

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        # Amass v5 has libpostal issues on many systems — use short timeout
        timeout = {
            ScanProfile.STEALTH: 120,
            ScanProfile.BALANCED: 120,
            ScanProfile.AGGRESSIVE: 300,
        }.get(profile, 120)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        # Amass writes status/results to stderr; exits non-zero on timeout/partial
        if not stdout.strip() and stderr.strip():
            stdout = stderr
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0 or len(findings) > 0),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            command=" ".join(command),
            target=target,
        )

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}
        # Amass v4 always uses 'enum' subcommand; passive/active is controlled via flags
        cmd = [self.binary_name, "enum"]

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-passive"])   # Sadece pasif kaynaklar
            case ScanProfile.BALANCED:
                cmd.extend(["-passive"])   # Varsayılan pasif
            case ScanProfile.AGGRESSIVE:
                pass  # Aktif brute-force dahil

        # If options request passive mode explicitly, ensure flag is present
        if options.get("mode") == "passive" and "-passive" not in cmd:
            cmd.append("-passive")

        cmd.extend(["-d", target])

        # Timeout ayarı
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw_output.strip().splitlines():
            subdomain = line.strip().lower()
            if not subdomain or subdomain in seen:
                continue
            # Basit domain doğrulama
            if not re.match(r"^[a-z0-9]([a-z0-9\-]*\.)+[a-z]{2,}$", subdomain):
                continue
            seen.add(subdomain)

            findings.append(Finding(
                title=f"Subdomain: {subdomain}",
                description=f"Discovered subdomain: {subdomain}",
                vulnerability_type="subdomain_discovery",
                severity=SeverityLevel.INFO,
                confidence=85.0,
                target=subdomain,
                endpoint=subdomain,
                tool_name=self.name,
                tags=["subdomain", "recon"],
            ))

        logger.debug(f"Amass discovered {len(findings)} subdomains for {target}")
        return findings


__all__ = ["AmassWrapper"]
