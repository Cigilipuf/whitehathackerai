"""
WhiteHatHacker AI — Masscan Wrapper

Ultra-fast internet port scanner.
SYN tarama ile saniyede milyonlarca paket gönderir.
Geniş ağ/port aralıklarında ilk keşif aşamasında kullanılır.
"""

from __future__ import annotations

import json
from typing import Any


from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import (
    RiskLevel,
    ScanProfile,
    SeverityLevel,
    ToolCategory,
)


class MasscanWrapper(SecurityTool):
    """
    Masscan — Fastest Internet Port Scanner.

    Çok hızlı SYN tarama yapar ama servis tespiti yapmaz.
    Genellikle önce masscan ile portları bulup sonra nmap ile detay alınır.
    """

    name = "masscan"
    category = ToolCategory.RECON_PORT
    description = "Mass IP port scanner — ultra fast SYN scan"
    binary_name = "masscan"
    requires_root = False   # Disabled — no passwordless sudo; falls back gracefully
    risk_level = RiskLevel.MEDIUM

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 300)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name,
            success=exit_code == 0,
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
        cmd = [self.binary_name]

        # Rate from options or profile default
        rate = str(options.get("rate", ""))
        # Ports from options override profile defaults
        ports = str(options.get("ports", ""))

        if not rate:
            match profile:
                case ScanProfile.STEALTH:
                    rate = "100"
                case ScanProfile.BALANCED:
                    rate = "1000"
                case ScanProfile.AGGRESSIVE:
                    rate = "10000"
                case _:
                    rate = "1000"
        cmd.extend(["--rate", rate])

        if not ports:
            match profile:
                case ScanProfile.STEALTH:
                    ports = "80,443,8080,8443"
                case ScanProfile.BALANCED:
                    ports = "1-1024,3306,5432,8080,8443,27017"
                case ScanProfile.AGGRESSIVE:
                    ports = "0-65535"
                case _:
                    ports = "1-1024"
        cmd.extend(["-p", ports])

        cmd.extend(["-oJ", "-"])  # JSON çıktı
        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Masscan JSON çıktısı — her satır bir JSON objesi
        for line in raw_output.strip().splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip = entry.get("ip", target)
            for port_info in entry.get("ports", []):
                port = port_info.get("port", 0)
                proto = port_info.get("proto", "tcp")
                status = port_info.get("status", "open")
                if status != "open":
                    continue

                findings.append(Finding(
                    title=f"Open Port: {port}/{proto}",
                    description=f"Port {port}/{proto} is open on {ip} (masscan fast scan)",
                    vulnerability_type="open_port",
                    severity=SeverityLevel.INFO,
                    confidence=90.0,
                    target=ip,
                    endpoint=f"{ip}:{port}",
                    tool_name=self.name,
                    tags=[f"port:{port}", f"protocol:{proto}", "fast_scan"],
                ))

        return findings


__all__ = ["MasscanWrapper"]
