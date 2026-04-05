"""Wfuzz — Web application fuzzer."""
from __future__ import annotations
import json
import re
from typing import Any
from loguru import logger
from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class WfuzzWrapper(SecurityTool):
    name = "wfuzz"
    category = ToolCategory.FUZZING
    description = "Web application fuzzer"
    binary_name = "wfuzz"
    requires_root = False
    risk_level = RiskLevel.LOW

    WORDLIST_CANDIDATES = [
        "/usr/share/wfuzz/wordlist/general/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
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
        fuzz_url = opts.get("url", f"{target}/FUZZ")
        cmd = [self.binary_name, "-f", "/dev/stdout,json", "--hc", "404"]
        if opts.get("hide_chars"):
            cmd.extend(["--hh", opts["hide_chars"]])
        threads = {"stealth": 5, "balanced": 20, "aggressive": 50}.get(
            profile.value if hasattr(profile, "value") else str(profile), 20)
        cmd.extend(["-t", str(opts.get("threads", threads))])
        cmd.extend(["-w", wordlist, fuzz_url])
        return cmd

    async def run(self, target: str, options: dict[str, Any] | None = None,
                  profile: ScanProfile = ScanProfile.BALANCED) -> ToolResult:
        cmd = self.build_command(target, options, profile)
        stdout, stderr, rc = await self.execute_command(cmd, timeout=600)
        return ToolResult(tool_name=self.name, success=rc == 0, exit_code=rc,
                          stdout=stdout, stderr=stderr,
                          findings=self.parse_output(stdout, target),
                          command=" ".join(cmd), target=target)

    # wfuzz JSON output: array of result objects
    _STATUS_LINE_RE = re.compile(r"(\d{3})\s+\d+\s+L\s+\d+\s+W\s+\d+\s+Ch\s+\"(.+?)\"")

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        # Try JSON mode first
        try:
            data = json.loads(raw_output) if raw_output.strip() else []
            if isinstance(data, list):
                for entry in data:
                    url = entry.get("url", "")
                    code = entry.get("code", 0)
                    if url and code and code != 404:
                        findings.append(Finding(
                            title=f"Fuzz: {url} [{code}]", severity=SeverityLevel.INFO,
                            vulnerability_type="fuzzing_discovery", target=url,
                            tool_name=self.name, description=f"Wfuzz found: {url} (HTTP {code})",
                        ))
                return findings
        except (json.JSONDecodeError, ValueError):
            pass
        # Fallback: text mode
        for line in raw_output.strip().splitlines():
            m = self._STATUS_LINE_RE.search(line)
            if m:
                code, payload = m.group(1), m.group(2)
                findings.append(Finding(
                    title=f"Fuzz hit: {payload} [{code}]", severity=SeverityLevel.INFO,
                    vulnerability_type="fuzzing_discovery", target=f"{target}/{payload}",
                    tool_name=self.name, description=f"Wfuzz found payload: {payload} (HTTP {code})",
                ))
        return findings
