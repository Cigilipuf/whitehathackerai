"""dnsx — Fast and multi-purpose DNS toolkit (resolution, brute-force, etc.)."""
from __future__ import annotations
import json
from typing import Any
from loguru import logger
from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class DnsxWrapper(SecurityTool):
    name = "dnsx"
    category = ToolCategory.RECON_DNS
    description = "Fast DNS resolution and multi-purpose DNS toolkit"
    binary_name = "dnsx"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def build_command(self, target: str, options: dict[str, Any] | None = None,
                      profile: ScanProfile = ScanProfile.BALANCED) -> list[str]:
        opts = options or {}
        cmd = [self.binary_name, "-json", "-retry", "2"]
        if opts.get("a", True):
            cmd.append("-a")
        if opts.get("aaaa"):
            cmd.append("-aaaa")
        if opts.get("cname"):
            cmd.append("-cname")
        if opts.get("mx"):
            cmd.append("-mx")
        if opts.get("resp"):
            cmd.append("-resp")
        domain_file = opts.get("domain_file")
        if domain_file:
            cmd.extend(["-l", domain_file])
        else:
            cmd = ["echo", target, "|"] + cmd
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
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            host = record.get("host", "")
            a_records = record.get("a", [])
            if host:
                findings.append(Finding(
                    title=f"DNS: {host} → {', '.join(a_records) if a_records else 'resolved'}",
                    severity=SeverityLevel.INFO,
                    vulnerability_type="dns_resolution", target=host,
                    tool_name=self.name,
                    description=f"DNS resolution for {host}: A={a_records}",
                    raw_evidence=line,
                ))
        return findings
