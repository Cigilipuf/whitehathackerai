"""
WhiteHatHacker AI — Commix Wrapper

Command injection exploitation — OS & application-level injection detection.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class CommixWrapper(SecurityTool):
    """
    Commix — Automated All-in-One OS Command Injection Exploiter.

    Detects result-based, time-based, file-based command injections.
    """

    name = "commix"
    category = ToolCategory.SCANNER
    description = "Automated OS command injection detection and exploitation"
    binary_name = "commix"
    requires_root = False
    risk_level = RiskLevel.HIGH  # Active exploitation

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
        findings = self.parse_output(stdout + "\n" + stderr, target)

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
        url = target if target.startswith("http") else f"http://{target}"

        cmd = [self.binary_name, "--url", url, "--batch"]

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["--level", "1", "--technique", "t"])  # time-based only
                cmd.append("--tamper=space2plus")
            case ScanProfile.BALANCED:
                cmd.extend(["--level", "2"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["--level", "3", "--technique", "classic,eval-based,time-based,file-based"])

        if "data" in options:
            cmd.extend(["--data", options["data"]])
        if "cookie" in options:
            cmd.extend(["--cookie", options["cookie"]])
        if "parameter" in options:
            cmd.extend(["-p", options["parameter"]])
        if "headers" in options:
            for k, v in options["headers"].items():
                cmd.extend(["--header", f"{k}: {v}"])
        if "os" in options:
            cmd.extend(["--os", options["os"]])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Detect injectable parameters
        injectable_re = re.compile(
            r"The\s+(?:GET|POST|Cookie|Header)\s+parameter\s+'(\S+)'\s+"
            r"(?:appears to be|seems to be|is)\s+injectable",
            re.IGNORECASE,
        )
        for match in injectable_re.finditer(raw_output):
            param = match.group(1)
            findings.append(Finding(
                title=f"OS Command Injection in '{param}'",
                description=(
                    f"The parameter '{param}' is vulnerable to OS command injection. "
                    "An attacker could execute arbitrary operating system commands."
                ),
                vulnerability_type="command_injection",
                severity=SeverityLevel.CRITICAL,
                confidence=90.0,
                target=target,
                parameter=param,
                tool_name=self.name,
                cwe_id="CWE-78",
                tags=["command_injection", "os_injection", "rce"],
                evidence=f"Commix detected injectable parameter: {param}",
            ))

        # Detect technique type
        technique_re = re.compile(
            r"(classic|eval-based|time-based|file-based)\s+"
            r"(?:command\s+)?injection\s+(?:technique|detected|identified)",
            re.IGNORECASE,
        )
        for match in technique_re.finditer(raw_output):
            technique = match.group(1).lower()
            # Technique-aware confidence: timing-based is FP-prone
            is_blind = "time" in technique
            _tech_conf = 35.0 if is_blind else 80.0
            _tech_sev = SeverityLevel.MEDIUM if is_blind else SeverityLevel.HIGH
            _tech_tags = ["command_injection", technique]
            if is_blind:
                _tech_tags.append("blind")
            findings.append(Finding(
                title=f"Command Injection — {technique} technique",
                description=f"Commix identified a {technique} command injection technique.",
                vulnerability_type="command_injection",
                severity=_tech_sev,
                confidence=_tech_conf,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-78",
                tags=_tech_tags,
                metadata={"technique": technique},
                evidence=f"Commix confirmed {technique} injection technique",
            ))

        # Detect OS identification
        os_re = re.compile(r"(?:The\s+)?remote\s+(?:OS|operating\s+system)\s+is\s+'?([^']+)'?", re.IGNORECASE)
        for match in os_re.finditer(raw_output):
            findings.append(Finding(
                title=f"Remote OS: {match.group(1).strip()}",
                description=f"Remote operating system identified: {match.group(1).strip()}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=80.0,
                target=target,
                tool_name=self.name,
                tags=["os_detection"],
                evidence=f"OS identified: {match.group(1).strip()}",
            ))

        # Detect command output extraction
        output_re = re.compile(r"command\s+(?:output|execution)\s*[:=]\s*(.+)", re.IGNORECASE)
        for match in output_re.finditer(raw_output):
            evidence = match.group(1).strip()[:500]
            findings.append(Finding(
                title="Command Execution Confirmed",
                description=f"Command output extracted: {evidence}",
                vulnerability_type="command_injection",
                severity=SeverityLevel.CRITICAL,
                confidence=95.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-78",
                tags=["rce", "confirmed"],
                evidence=[evidence],
            ))

        # Detect "not injectable" (info)
        if "does not seem to be injectable" in raw_output.lower():
            findings.append(Finding(
                title="No Command Injection Found",
                description="Commix did not detect command injection in the tested parameters.",
                vulnerability_type="info",
                severity=SeverityLevel.INFO,
                confidence=60.0,
                target=target,
                tool_name=self.name,
                tags=["negative", "clean"],
            ))

        logger.debug(f"commix parsed {len(findings)} findings")
        return findings


__all__ = ["CommixWrapper"]
