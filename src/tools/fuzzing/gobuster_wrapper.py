"""
WhiteHatHacker AI — Gobuster Wrapper

Directory/DNS/VHost brute-force tool.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class GobusterWrapper(SecurityTool):
    """
    Gobuster — Dir/DNS/VHost busting.

    Modlar: dir, dns, vhost, fuzz, s3
    """

    name = "gobuster"
    category = ToolCategory.FUZZING
    description = "Directory/file, DNS, VHost brute-force tool"
    binary_name = "gobuster"
    requires_root = False
    risk_level = RiskLevel.LOW

    WORDLIST_CANDIDATES = [
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wfuzz/wordlist/general/common.txt",
    ]

    @staticmethod
    def _find_wordlist(candidates: list[str] | None = None) -> str:
        """İlk mevcut wordlist'i döndür."""
        from pathlib import Path
        for c in (candidates or GobusterWrapper.WORDLIST_CANDIDATES):
            if Path(c).is_file():
                return c
        return "/usr/share/dirb/wordlists/common.txt"

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 600)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        # gobuster writes progress/errors to stderr; exits non-zero on partial completion
        combined = stdout + "\n" + stderr if stderr else stdout
        findings = self.parse_output(combined, target)

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
        mode = options.get("mode", "dir")
        wordlist = options.get("wordlist", self._find_wordlist())

        if isinstance(target, list):
            target = target[0] if target else ""

        cmd = [self.binary_name, mode]

        if mode == "dir":
            url = target if target.startswith("http") else f"http://{target}"
            cmd.extend(["-u", url, "-w", wordlist])

            match profile:
                case ScanProfile.STEALTH:
                    cmd.extend(["-t", "5", "--delay", "500ms"])
                case ScanProfile.BALANCED:
                    cmd.extend(["-t", "20"])
                case ScanProfile.AGGRESSIVE:
                    cmd.extend(["-t", "50"])

            if options.get("extensions"):
                cmd.extend(["-x", options["extensions"]])
            if options.get("status_codes_blacklist"):
                cmd.extend(["-b", options["status_codes_blacklist"]])
            cmd.extend(["--no-error", "-q"])  # Sessiz çıktı

        elif mode == "dns":
            cmd.extend(["-d", target, "-w", wordlist])
            cmd.extend(["-t", "10", "-q"])

        elif mode == "vhost":
            url = target if target.startswith("http") else f"http://{target}"
            cmd.extend(["-u", url, "-w", wordlist])
            cmd.extend(["-t", "10", "-q"])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Gobuster dir çıktı format: /path (Status: 200) [Size: 1234]
        dir_pattern = re.compile(
            r"^(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]",
            re.MULTILINE,
        )

        for match in dir_pattern.finditer(raw_output):
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))

            findings.append(Finding(
                title=f"Discovered: {path} [{status}]",
                description=f"Path: {path} | Status: {status} | Size: {size}",
                vulnerability_type="content_discovery",
                severity=self._assess_severity(path, status),
                confidence=85.0,
                target=target,
                endpoint=f"{target}{path}",
                tool_name=self.name,
                tags=["fuzzing", "directory", f"status:{status}"],
                metadata={"status_code": status, "content_length": size},
            ))

        # DNS mode: Found: sub.domain.com
        dns_pattern = re.compile(r"Found:\s+(\S+)", re.MULTILINE)
        for match in dns_pattern.finditer(raw_output):
            subdomain = match.group(1)
            findings.append(Finding(
                title=f"Subdomain: {subdomain}",
                description=f"Discovered subdomain via brute-force: {subdomain}",
                vulnerability_type="subdomain_discovery",
                severity=SeverityLevel.INFO,
                confidence=80.0,
                target=subdomain,
                tool_name=self.name,
                tags=["subdomain", "brute"],
            ))

        logger.debug(f"gobuster parsed {len(findings)} findings")
        return findings

    @staticmethod
    def _assess_severity(path: str, status: int) -> SeverityLevel:
        path_lower = path.lower()
        sensitive = [".env", ".git", "admin", "backup", "config", "debug", ".htpasswd"]
        if any(s in path_lower for s in sensitive) and status == 200:
            return SeverityLevel.MEDIUM
        if status == 200:
            return SeverityLevel.INFO
        return SeverityLevel.INFO


__all__ = ["GobusterWrapper"]
