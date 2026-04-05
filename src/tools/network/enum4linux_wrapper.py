"""
WhiteHatHacker AI — Enum4linux Wrapper

Windows/Samba enumeration — users, shares, groups, policies, SIDs.
"""

from __future__ import annotations

import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class Enum4linuxWrapper(SecurityTool):
    """
    enum4linux — Windows/Samba enumeration via RPC, LDAP, SMB.

    Enumerates: users, shares, groups, password policies, OS info, SIDs.
    """

    name = "enum4linux"
    category = ToolCategory.NETWORK
    description = "Windows/Samba system enumeration — users, shares, groups, policies"
    binary_name = "enum4linux"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 300)
        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout + "\n" + stderr, target)
        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0 or len(findings) > 0),
            exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=" ".join(command), target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        options = options or {}
        cmd = [self.binary_name]

        match profile:
            case ScanProfile.STEALTH:
                cmd.append("-U")  # Only user enum
            case ScanProfile.BALANCED:
                cmd.append("-a")  # All simple enumeration
            case ScanProfile.AGGRESSIVE:
                cmd.append("-a")
                cmd.extend(["-r", "-R", "100-200"])  # User rid cycling

        if "username" in options:
            cmd.extend(["-u", options["username"]])
        if "password" in options:
            cmd.extend(["-p", options["password"]])

        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # OS information
        os_match = re.search(r"OS information on (\S+).*?OS=\[([^\]]*)\]", raw_output, re.DOTALL)
        if os_match:
            findings.append(Finding(
                title=f"OS: {os_match.group(2)}",
                description=f"Remote OS detected: {os_match.group(2)}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=85.0, target=target, tool_name=self.name,
                tags=["os_detection", "smb"],
            ))

        # Null session
        if re.search(r"null session.*?(successful|allowed)", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="SMB Null Session Allowed",
                description="SMB null session authentication is allowed, enabling anonymous enumeration.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=90.0, target=target, tool_name=self.name,
                cwe_id="CWE-287",
                tags=["smb", "null_session", "anonymous"],
            ))

        # Users
        user_pattern = re.compile(r"user:\[([^\]]+)\]", re.IGNORECASE)
        users = user_pattern.findall(raw_output)
        if users:
            findings.append(Finding(
                title=f"Enumerated {len(users)} SMB Users",
                description=f"Users found: {', '.join(users[:20])}{'...' if len(users) > 20 else ''}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW,
                confidence=85.0, target=target, tool_name=self.name,
                tags=["smb", "user_enum"],
                metadata={"users": users},
            ))

        # Shares
        share_pattern = re.compile(r"\s+([\w$]+)\s+(?:Disk|IPC|Printer)\s+(.*)", re.IGNORECASE)
        shares = share_pattern.findall(raw_output)
        for share_name, comment in shares:
            severity = SeverityLevel.INFO
            if share_name.upper() in ("C$", "ADMIN$", "IPC$"):
                severity = SeverityLevel.LOW
            elif "writable" in comment.lower():
                severity = SeverityLevel.MEDIUM

            findings.append(Finding(
                title=f"SMB Share: {share_name}",
                description=f"Share: {share_name} — {comment.strip() or 'No comment'}",
                vulnerability_type="information_disclosure",
                severity=severity,
                confidence=80.0, target=target, tool_name=self.name,
                tags=["smb", "share", share_name.lower()],
            ))

        # Password policy
        min_length = re.search(r"Minimum password length:\s*(\d+)", raw_output)
        lockout = re.search(r"Account Lockout Threshold:\s*(\d+)", raw_output)
        if min_length:
            length = int(min_length.group(1))
            if length < 8:
                findings.append(Finding(
                    title=f"Weak Password Policy: Min Length = {length}",
                    description=f"Minimum password length is {length} (recommended: ≥12)",
                    vulnerability_type="misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    confidence=90.0, target=target, tool_name=self.name,
                    cwe_id="CWE-521",
                    tags=["password_policy", "weak_config"],
                ))
        if lockout:
            threshold = int(lockout.group(1))
            if threshold == 0:
                findings.append(Finding(
                    title="No Account Lockout Policy",
                    description="Account lockout threshold is 0 — no brute force protection.",
                    vulnerability_type="misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    confidence=90.0, target=target, tool_name=self.name,
                    cwe_id="CWE-307",
                    tags=["password_policy", "no_lockout"],
                ))

        # Groups
        group_pattern = re.compile(r"group:\[([^\]]+)\]", re.IGNORECASE)
        groups = group_pattern.findall(raw_output)
        if groups:
            findings.append(Finding(
                title=f"Enumerated {len(groups)} SMB Groups",
                description=f"Groups: {', '.join(groups[:20])}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=80.0, target=target, tool_name=self.name,
                tags=["smb", "group_enum"],
                metadata={"groups": groups},
            ))

        logger.debug(f"enum4linux parsed {len(findings)} findings")
        return findings


__all__ = ["Enum4linuxWrapper"]
