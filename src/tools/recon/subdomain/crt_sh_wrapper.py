"""crt.sh — Certificate Transparency log subdomain discovery via crt.sh API."""
from __future__ import annotations
import json
from typing import Any
from loguru import logger
from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class CrtShWrapper(SecurityTool):
    name = "crt_sh"
    category = ToolCategory.RECON_SUBDOMAIN
    description = "Certificate Transparency log subdomain discovery via crt.sh"
    binary_name = "curl"  # Uses curl to query crt.sh API
    requires_root = False
    risk_level = RiskLevel.SAFE

    def build_command(self, target: str, options: dict[str, Any] | None = None,
                      profile: ScanProfile = ScanProfile.BALANCED) -> list[str]:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        return ["curl", "-s", "-m", "60", url]

    async def run(self, target: str, options: dict[str, Any] | None = None,
                  profile: ScanProfile = ScanProfile.BALANCED) -> ToolResult:
        cmd = self.build_command(target, options, profile)
        stdout, stderr, rc = await self.execute_command(cmd, timeout=120)
        return ToolResult(tool_name=self.name, success=rc == 0, exit_code=rc,
                          stdout=stdout, stderr=stderr,
                          findings=self.parse_output(stdout, target),
                          command=" ".join(cmd), target=target)

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        try:
            entries = json.loads(raw_output) if raw_output.strip() else []
        except (json.JSONDecodeError, ValueError):
            return findings
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.replace("\n", " ").split():
                sub = name.strip().lower().lstrip("*.")
                if sub and sub not in seen and "." in sub:
                    seen.add(sub)
                    findings.append(Finding(
                        title=f"Subdomain: {sub}", severity=SeverityLevel.INFO,
                        vulnerability_type="subdomain_discovery", target=sub,
                        tool_name=self.name,
                        description=f"Subdomain from Certificate Transparency: {sub}",
                    ))
        return findings
