"""Dirb — URL bruteforcer for web servers."""
from __future__ import annotations
import re
from typing import Any
from loguru import logger
from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class DirbWrapper(SecurityTool):
    name = "dirb"
    category = ToolCategory.FUZZING
    description = "URL bruteforcer for web servers"
    binary_name = "dirb"
    requires_root = False
    risk_level = RiskLevel.LOW

    WORDLIST_CANDIDATES = [
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]

    def build_command(self, target: str, options: dict[str, Any] | None = None,
                      profile: ScanProfile = ScanProfile.BALANCED) -> list[str]:
        opts = options or {}
        wordlist = opts.get("wordlist", "")
        if not wordlist:
            import os
            for wl in self.WORDLIST_CANDIDATES:
                if os.path.isfile(wl):
                    wordlist = wl
                    break
        cmd = [self.binary_name, target]
        if wordlist:
            cmd.append(wordlist)
        cmd.extend(["-S", "-w"])
        return cmd

    async def run(self, target: str, options: dict[str, Any] | None = None,
                  profile: ScanProfile = ScanProfile.BALANCED) -> ToolResult:
        cmd = self.build_command(target, options, profile)
        stdout, stderr, rc = await self.execute_command(cmd, timeout=600)
        return ToolResult(tool_name=self.name, success=rc == 0, exit_code=rc,
                          stdout=stdout, stderr=stderr,
                          findings=self.parse_output(stdout, target),
                          command=" ".join(cmd), target=target)

    # Pattern: "+ http://target/path (CODE:200|SIZE:1234)"
    _HIT_RE = re.compile(r"\+\s+(https?://\S+)\s+\(CODE:(\d+)")

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.strip().splitlines():
            m = self._HIT_RE.search(line)
            if m:
                url, code = m.group(1), m.group(2)
                findings.append(Finding(
                    title=f"Directory: {url} [{code}]", severity=SeverityLevel.INFO,
                    vulnerability_type="directory_discovery", target=url,
                    tool_name=self.name,
                    description=f"Dirb found: {url} (HTTP {code})",
                ))
        return findings
