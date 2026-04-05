"""
WhiteHatHacker AI — SSH Audit Wrapper

SSH server security analysis using Nmap NSE scripts & manual checks.
"""

from __future__ import annotations

import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# Known weak SSH algorithms
WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"}
WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}


class SshAuditWrapper(SecurityTool):
    """
    SSH Server Audit.

    Uses nmap NSE ssh scripts to analyze:
    - SSH version and protocol
    - Key exchange algorithms
    - Encryption ciphers
    - MAC algorithms
    - Host key types
    - Known vulnerabilities
    """

    name = "ssh_audit"
    category = ToolCategory.NETWORK
    description = "SSH server security analysis — ciphers, KEX, MACs, vulnerabilities"
    binary_name = "nmap"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        port = options.get("port", 22)

        # Run nmap with SSH scripts
        cmd = [
            "nmap", "-p", str(port), "--script",
            "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1",
            "-sV", target,
        ]

        stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0 or len(findings) > 0),
            exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=" ".join(cmd), target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        port = (options or {}).get("port", 22)
        return ["nmap", "-p", str(port), "--script", "ssh2-enum-algos,ssh-hostkey", "-sV", target]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # SSH version
        ver_match = re.search(r"(\d+)/tcp\s+open\s+ssh\s+(.*)", raw_output)
        if ver_match:
            ssh_version = ver_match.group(2).strip()
            findings.append(Finding(
                title=f"SSH Version: {ssh_version}",
                description=f"SSH service: {ssh_version}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=95.0, target=target, tool_name=self.name,
                tags=["ssh", "version"],
            ))

            # Check for very old OpenSSH
            old_match = re.search(r"OpenSSH[_\s](\d+)\.(\d+)", ssh_version)
            if old_match:
                major, minor = int(old_match.group(1)), int(old_match.group(2))
                if major < 7 or (major == 7 and minor < 4):
                    findings.append(Finding(
                        title=f"Outdated OpenSSH: {major}.{minor}",
                        description=f"OpenSSH {major}.{minor} is outdated and may have known vulnerabilities.",
                        vulnerability_type="outdated_software",
                        severity=SeverityLevel.MEDIUM,
                        confidence=85.0, target=target, tool_name=self.name,
                        cwe_id="CWE-1104",
                        tags=["ssh", "outdated"],
                    ))

        # SSHv1 detected
        if re.search(r"sshv1.*supported|protocol 1", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="SSH Protocol v1 Supported",
                description="SSH Protocol version 1 is enabled — critically insecure.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.HIGH,
                confidence=95.0, target=target, tool_name=self.name,
                cwe_id="CWE-327",
                tags=["ssh", "sshv1", "deprecated"],
            ))

        # Key exchange algorithms
        kex_section = re.search(r"kex_algorithms.*?(?=\n\s*\n|\Z)", raw_output, re.DOTALL)
        if kex_section:
            for weak_kex in WEAK_KEX:
                if weak_kex in kex_section.group():
                    findings.append(Finding(
                        title=f"Weak KEX: {weak_kex}",
                        description=f"Weak key exchange algorithm: {weak_kex}",
                        vulnerability_type="misconfiguration",
                        severity=SeverityLevel.MEDIUM,
                        confidence=90.0, target=target, tool_name=self.name,
                        cwe_id="CWE-327",
                        tags=["ssh", "weak_kex", weak_kex],
                    ))

        # Ciphers
        cipher_section = re.search(r"encryption_algorithms.*?(?=\n\s*\n|\Z)", raw_output, re.DOTALL)
        if cipher_section:
            for weak_cipher in WEAK_CIPHERS:
                if weak_cipher in cipher_section.group():
                    findings.append(Finding(
                        title=f"Weak Cipher: {weak_cipher}",
                        description=f"Weak encryption cipher allowed: {weak_cipher}",
                        vulnerability_type="misconfiguration",
                        severity=SeverityLevel.MEDIUM,
                        confidence=90.0, target=target, tool_name=self.name,
                        cwe_id="CWE-327",
                        tags=["ssh", "weak_cipher"],
                    ))

        # MACs
        mac_section = re.search(r"mac_algorithms.*?(?=\n\s*\n|\Z)", raw_output, re.DOTALL)
        if mac_section:
            for weak_mac in WEAK_MACS:
                if weak_mac in mac_section.group():
                    findings.append(Finding(
                        title=f"Weak MAC: {weak_mac}",
                        description=f"Weak MAC algorithm allowed: {weak_mac}",
                        vulnerability_type="misconfiguration",
                        severity=SeverityLevel.LOW,
                        confidence=85.0, target=target, tool_name=self.name,
                        tags=["ssh", "weak_mac"],
                    ))

        # Auth methods
        if "password" in raw_output.lower() and "auth-methods" in raw_output.lower():
            findings.append(Finding(
                title="SSH Password Authentication Enabled",
                description="Password authentication is allowed — consider key-only auth.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=80.0, target=target, tool_name=self.name,
                tags=["ssh", "password_auth"],
            ))

        logger.debug(f"ssh_audit parsed {len(findings)} findings")
        return findings


__all__ = ["SshAuditWrapper"]
