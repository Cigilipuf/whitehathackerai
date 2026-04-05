"""
WhiteHatHacker AI — NetExec (nxc) Wrapper

Swiss-army knife for network protocol exploitation:
SMB, LDAP, WinRM, MSSQL, SSH, RDP, WMI.
"""

from __future__ import annotations

import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class NetexecWrapper(SecurityTool):
    """
    NetExec (nxc) — Network protocol exploitation framework.

    Tests: SMB signing, null sessions, credential spraying,
    share access, command execution, WinRM, MSSQL.
    """

    name = "netexec"
    category = ToolCategory.NETWORK
    description = "Network protocol exploitation — SMB, LDAP, WinRM, MSSQL, SSH"
    binary_name = "nxc"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        protocol = options.get("protocol", "smb")
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 120)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout + "\n" + stderr, target)

        return ToolResult(
            tool_name=self.name, success=exit_code == 0, exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=" ".join(command), target=target,
            metadata={"protocol": protocol},
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        options = options or {}
        protocol = options.get("protocol", "smb")
        cmd = [self.binary_name, protocol, target]

        # Authentication
        if "username" in options:
            cmd.extend(["-u", options["username"]])
        if "password" in options:
            cmd.extend(["-p", options["password"]])

        # Protocol-specific
        match protocol:
            case "smb":
                if not options.get("username"):
                    cmd.extend(["-u", "", "-p", ""])  # Null session
                if options.get("shares"):
                    cmd.append("--shares")
                if options.get("users"):
                    cmd.append("--users")
                if options.get("pass_pol"):
                    cmd.append("--pass-pol")
                if options.get("spider"):
                    cmd.extend(["--spider", options.get("spider_folder", "C$")])
            case "ldap":
                if options.get("users"):
                    cmd.append("--users")
                if options.get("groups"):
                    cmd.append("--groups")
            case "winrm":
                if options.get("command"):
                    cmd.extend(["-x", options["command"]])
            case "mssql":
                if options.get("query"):
                    cmd.extend(["-q", options["query"]])
            case "ssh":
                pass  # Basic auth check

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # SMB Signing disabled
        if re.search(r"signing:\s*False", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="SMB Signing Disabled",
                description="SMB signing is not required — enables relay attacks.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=95.0, target=target, tool_name=self.name,
                cwe_id="CWE-311",
                tags=["smb", "signing", "relay"],
            ))

        # Successful authentication (Pwn3d! or [+])
        if "Pwn3d!" in raw_output:
            findings.append(Finding(
                title="Admin Access Confirmed (Pwn3d!)",
                description="Administrative access confirmed on target via nxc.",
                vulnerability_type="auth_bypass",
                severity=SeverityLevel.CRITICAL,
                confidence=95.0, target=target, tool_name=self.name,
                tags=["admin_access", "pwned"],
            ))

        # Guest login
        if re.search(r"\[.\]\s.*Guest.*session", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="SMB Guest Session Allowed",
                description="Guest/anonymous session permitted on SMB.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["smb", "guest", "anonymous"],
            ))

        # Shares
        share_pattern = re.compile(r"\s+([\w\$]+)\s+(READ|WRITE|READ,WRITE)", re.IGNORECASE)
        for match in share_pattern.finditer(raw_output):
            share_name = match.group(1)
            access = match.group(2).upper()
            severity = SeverityLevel.HIGH if "WRITE" in access else SeverityLevel.LOW

            findings.append(Finding(
                title=f"Share: {share_name} ({access})",
                description=f"SMB share '{share_name}' accessible with {access} permissions.",
                vulnerability_type="misconfiguration" if "WRITE" in access else "information_disclosure",
                severity=severity,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["smb", "share", access.lower()],
            ))

        # Users enumerated
        user_pattern = re.compile(r"(\S+)\s+(?:badpwdcount|status|lastlogon)", re.IGNORECASE)
        users = user_pattern.findall(raw_output)
        if users:
            findings.append(Finding(
                title=f"Enumerated {len(users)} Users",
                description=f"Users: {', '.join(users[:20])}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW,
                confidence=85.0, target=target, tool_name=self.name,
                tags=["user_enum"],
                metadata={"users": users},
            ))

        # OS / hostname detection from the [*] lines
        os_match = re.search(
            r"\[\*\]\s+\S+\s+\d+\s+(\S+)\s+\(name:([^)]+)\)\s+\(domain:([^)]+)\)",
            raw_output,
        )
        if os_match:
            findings.append(Finding(
                title=f"Target: {os_match.group(2).strip()} ({os_match.group(1)})",
                description=(
                    f"OS: {os_match.group(1)} | "
                    f"Name: {os_match.group(2).strip()} | "
                    f"Domain: {os_match.group(3).strip()}"
                ),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["os_detection", "hostname"],
            ))

        logger.debug(f"netexec parsed {len(findings)} findings")
        return findings


__all__ = ["NetexecWrapper"]
