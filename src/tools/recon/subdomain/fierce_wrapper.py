"""Fierce — DNS reconnaissance tool for locating non-contiguous IP space."""
from __future__ import annotations
import re
from typing import Any
from loguru import logger
from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class FierceWrapper(SecurityTool):
    name = "fierce"
    category = ToolCategory.RECON_SUBDOMAIN
    description = "DNS reconnaissance tool for locating non-contiguous IP space"
    binary_name = "fierce"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def build_command(self, target: str, options: dict[str, Any] | None = None,
                      profile: ScanProfile = ScanProfile.BALANCED) -> list[str]:
        cmd = [self.binary_name, "--domain", target]
        opts = options or {}
        if opts.get("dns_servers"):
            cmd.extend(["--dns-servers", opts["dns_servers"]])
        if opts.get("subdomain_file"):
            cmd.extend(["--subdomain-file", opts["subdomain_file"]])
        return cmd

    async def run(self, target: str, options: dict[str, Any] | None = None,
                  profile: ScanProfile = ScanProfile.BALANCED) -> ToolResult:
        cmd = self.build_command(target, options, profile)
        stdout, stderr, rc = await self.execute_command(cmd, timeout=600)
        return ToolResult(tool_name=self.name, success=rc == 0, exit_code=rc,
                          stdout=stdout, stderr=stderr,
                          findings=self.parse_output(stdout, target),
                          command=" ".join(cmd), target=target)

    # Pattern: "Found: sub.example.com (A) - 1.2.3.4" or IP/hostname lines
    _FOUND_RE = re.compile(r"(?:Found:\s+)?(\S+\.\S+)\s.*?(\d{1,3}(?:\.\d{1,3}){3})")

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw_output.strip().splitlines():
            m = self._FOUND_RE.search(line)
            if m:
                host = m.group(1).lower().rstrip(".")
                ip = m.group(2)
                if host not in seen:
                    seen.add(host)
                    findings.append(Finding(
                        title=f"DNS: {host} → {ip}", severity=SeverityLevel.INFO,
                        vulnerability_type="dns_discovery", target=host,
                        tool_name=self.name,
                        description=f"Fierce discovered: {host} resolves to {ip}",
                    ))
        return findings
