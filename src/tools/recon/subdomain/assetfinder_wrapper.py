"""Assetfinder — Find domains and subdomains potentially related to a given domain."""
from __future__ import annotations
from typing import Any
from loguru import logger
from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class AssetfinderWrapper(SecurityTool):
    name = "assetfinder"
    category = ToolCategory.RECON_SUBDOMAIN
    description = "Find domains and subdomains related to a given domain"
    binary_name = "assetfinder"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def build_command(self, target: str, options: dict[str, Any] | None = None,
                      profile: ScanProfile = ScanProfile.BALANCED) -> list[str]:
        cmd = [self.binary_name]
        if (options or {}).get("subs_only", True):
            cmd.append("--subs-only")
        cmd.append(target)
        return cmd

    async def run(self, target: str, options: dict[str, Any] | None = None,
                  profile: ScanProfile = ScanProfile.BALANCED) -> ToolResult:
        cmd = self.build_command(target, options, profile)
        stdout, stderr, rc = await self.execute_command(cmd, timeout=300)
        return ToolResult(tool_name=self.name, success=rc == 0, exit_code=rc,
                          stdout=stdout, stderr=stderr,
                          findings=self.parse_output(stdout, target),
                          command=" ".join(cmd), target=target)

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw_output.strip().splitlines():
            sub = line.strip().lower()
            if sub and sub not in seen and "." in sub:
                seen.add(sub)
                findings.append(Finding(
                    title=f"Subdomain: {sub}", severity=SeverityLevel.INFO,
                    vulnerability_type="subdomain_discovery", target=sub,
                    tool_name=self.name, description=f"Discovered subdomain: {sub}",
                ))
        return findings
