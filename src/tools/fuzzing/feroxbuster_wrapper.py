"""Feroxbuster — Recursive content discovery tool written in Rust."""
from __future__ import annotations
import json
from typing import Any
from loguru import logger
from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class FeroxbusterWrapper(SecurityTool):
    name = "feroxbuster"
    category = ToolCategory.FUZZING
    description = "Recursive content discovery tool (Rust)"
    binary_name = "feroxbuster"
    requires_root = False
    risk_level = RiskLevel.LOW

    def build_command(self, target: str, options: dict[str, Any] | None = None,
                      profile: ScanProfile = ScanProfile.BALANCED) -> list[str]:
        if isinstance(target, list):
            target = target[0] if target else ""
        opts = options or {}
        cmd = [self.binary_name, "-u", target, "--json", "-q", "--no-state"]
        if opts.get("wordlist"):
            cmd.extend(["-w", opts["wordlist"]])
        threads = {"stealth": 5, "balanced": 20, "aggressive": 50}.get(
            profile.value if hasattr(profile, "value") else str(profile), 20)
        cmd.extend(["-t", str(opts.get("threads", threads))])
        if opts.get("depth"):
            cmd.extend(["-d", str(opts["depth"])])
        if opts.get("extensions"):
            cmd.extend(["-x", opts["extensions"]])
        if opts.get("status_codes"):
            cmd.extend(["-s", opts["status_codes"]])
        return cmd

    async def run(self, target: str, options: dict[str, Any] | None = None,
                  profile: ScanProfile = ScanProfile.BALANCED) -> ToolResult:
        cmd = self.build_command(target, options, profile)
        stdout, stderr, rc = await self.execute_command(cmd, timeout=900)
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
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            entry_type = entry.get("type", "")
            if entry_type != "response":
                continue
            url = entry.get("url", "")
            status = entry.get("status", 0)
            length = entry.get("content_length", entry.get("line_count", 0))
            if url and 200 <= status < 400:
                findings.append(Finding(
                    title=f"Path: {url} [{status}]", severity=SeverityLevel.INFO,
                    vulnerability_type="content_discovery", target=url,
                    tool_name=self.name,
                    description=f"Feroxbuster found: {url} (HTTP {status}, {length} bytes)",
                ))
        return findings
