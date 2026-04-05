"""
WhiteHatHacker AI — SMBClient Wrapper

SMB share access, file listing, read/write check.
"""

from __future__ import annotations

import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class SmbclientWrapper(SecurityTool):
    """
    smbclient — SMB/CIFS share access and enumeration.

    Lists shares, checks anonymous access, identifies writable shares.
    """

    name = "smbclient"
    category = ToolCategory.NETWORK
    description = "SMB/CIFS share enumeration and access testing"
    binary_name = "smbclient"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}

        # First, list shares
        cmd_list = self._build_list_command(target, options)
        stdout, stderr, exit_code = await self.execute_command(cmd_list, timeout=1200)
        findings = self.parse_output(stdout + "\n" + stderr, target)

        # Then, try anonymous access on each share
        shares = self._extract_shares(stdout + "\n" + stderr)
        for share in shares:
            access_findings = await self._test_share_access(target, share, options)
            findings.extend(access_findings)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0 or len(findings) > 0),
            exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=" ".join(cmd_list), target=target,
            metadata={"shares_found": len(shares)},
        )

    def _build_list_command(self, target, options) -> list[str]:
        cmd = [self.binary_name, "-L", target]
        if "username" in options:
            # smbclient expects -U 'user%pass' format
            user = options["username"]
            passwd = options.get("password", "")
            cmd.extend(["-U", f"{user}%{passwd}"])
        else:
            cmd.append("-N")  # -N = no password (anonymous)
        return cmd

    async def _test_share_access(self, target, share_name, options) -> list[Finding]:
        """Try connecting to a share anonymously."""
        findings = []
        cmd = [self.binary_name, f"//{target}/{share_name}", "-N", "-c", "dir"]

        if "username" in options:
            cmd = [self.binary_name, f"//{target}/{share_name}",
                   "-U", f"{options['username']}%{options.get('password', '')}",
                   "-c", "dir"]

        try:
            stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
            if exit_code == 0 and ("blocks" in stdout.lower() or "directory" in stdout.lower()):
                # Check for sensitive files
                sensitive = self._check_sensitive_files(stdout)
                severity = SeverityLevel.HIGH if sensitive else SeverityLevel.MEDIUM

                findings.append(Finding(
                    title=f"Anonymous Access: \\\\{target}\\{share_name}",
                    description=(
                        f"Share '{share_name}' is accessible without authentication.\n"
                        f"{'Sensitive files detected: ' + ', '.join(sensitive) if sensitive else 'No obviously sensitive files.'}"
                    ),
                    vulnerability_type="misconfiguration",
                    severity=severity,
                    confidence=90.0,
                    target=target,
                    endpoint=f"\\\\{target}\\{share_name}",
                    tool_name=self.name,
                    cwe_id="CWE-284",
                    tags=["smb", "anonymous_access", f"share:{share_name}"],
                    evidence=[f"smbclient //{target}/{share_name} -N -c dir → success"],
                    metadata={"sensitive_files": sensitive},
                ))
        except Exception as exc:
            logger.debug(f"Share access test failed for {share_name}: {exc}")

        return findings

    def _check_sensitive_files(self, dir_output: str) -> list[str]:
        sensitive = []
        patterns = [
            r"\b\w+\.conf\b", r"\b\w+\.config\b", r"\bpassw",
            r"\b\.env\b", r"\b\w+\.key\b", r"\b\w+\.pem\b",
            r"\bweb\.xml\b", r"\bwp-config\b", r"\b\.htpasswd\b",
            r"\bshadow\b", r"\bsam\b", r"\bsystem\b",
            r"\b\w+\.bak\b", r"\b\w+\.sql\b", r"\b\w+\.dump\b",
        ]
        for p in patterns:
            matches = re.findall(p, dir_output, re.IGNORECASE)
            sensitive.extend(matches)
        return list(set(sensitive))[:10]

    def _extract_shares(self, output: str) -> list[str]:
        shares = []
        pattern = re.compile(r"^\s+([\w\$\-]+)\s+(?:Disk|IPC|Printer)", re.MULTILINE | re.IGNORECASE)
        for match in pattern.finditer(output):
            shares.append(match.group(1))
        return shares

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return self._build_list_command(target, options or {})

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings = []
        shares = self._extract_shares(raw_output)
        if shares:
            findings.append(Finding(
                title=f"{len(shares)} SMB Shares Found",
                description=f"Shares: {', '.join(shares)}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=85.0, target=target, tool_name=self.name,
                tags=["smb", "shares"],
                metadata={"shares": shares},
            ))
        return findings


__all__ = ["SmbclientWrapper"]
