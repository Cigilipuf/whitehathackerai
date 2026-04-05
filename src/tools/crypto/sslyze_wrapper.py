"""
WhiteHatHacker AI — SSLyze Wrapper

Deep SSL/TLS analysis — more detailed than sslscan.
Certificate chain, OCSP, CT logs, protocol support, vulnerability checks.
"""

from __future__ import annotations

import json
import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class SslyzeWrapper(SecurityTool):
    """
    sslyze — Fast and powerful SSL/TLS scanning.

    Analyses: certificate chain, OCSP stapling, cipher suites,
    protocols, Heartbleed, CCS injection, session renegotiation,
    ROBOT attack, compression (CRIME).
    """

    name = "sslyze"
    category = ToolCategory.CRYPTO
    description = "Deep SSL/TLS configuration analysis"
    binary_name = "sslyze"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        port = options.get("port", 443)
        host_port = f"{target}:{port}" if ":" not in target else target

        command = self.build_command(host_port, options, profile)
        timeout = options.get("timeout", 120)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name, success=exit_code == 0, exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=" ".join(command), target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        options = options or {}
        cmd = [self.binary_name]

        if options.get("json_output"):
            cmd.extend(["--json_out", "-"])

        # Scan commands
        cmd.extend([
            "--heartbleed",
            "--openssl_ccs",
            "--compression",
            "--reneg",
            "--certinfo",
        ])

        match profile:
            case ScanProfile.STEALTH:
                cmd.append("--slow_connection")
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["--robot", "--early_data"])

        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Try JSON first
        try:
            data = json.loads(raw_output)
            return self._parse_json(data, target)
        except json.JSONDecodeError:
            pass

        # Heartbleed
        if re.search(r"VULNERABLE.*Heartbleed|OpenSSL Heartbleed.*VULNERABLE", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="Heartbleed Vulnerability",
                vulnerability_type="known_vulnerability",
                severity=SeverityLevel.CRITICAL, confidence=95.0,
                target=target, tool_name=self.name,
                description="OpenSSL Heartbleed (CVE-2014-0160) — server is vulnerable.",
                cve_id="CVE-2014-0160", cwe_id="CWE-126",
                tags=["ssl", "heartbleed"],
            ))

        # CCS Injection
        if re.search(r"VULNERABLE.*CCS|CCS.*VULNERABLE", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="OpenSSL CCS Injection (CVE-2014-0224)",
                vulnerability_type="known_vulnerability",
                severity=SeverityLevel.HIGH, confidence=90.0,
                target=target, tool_name=self.name,
                description="Server vulnerable to CCS injection attack.",
                cve_id="CVE-2014-0224",
                tags=["ssl", "ccs_injection"],
            ))

        # ROBOT attack
        if re.search(r"ROBOT.*VULNERABLE|vulnerable.*ROBOT", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="ROBOT Attack (Return Of Bleichenbacher's Oracle Threat)",
                vulnerability_type="known_vulnerability",
                severity=SeverityLevel.HIGH, confidence=85.0,
                target=target, tool_name=self.name,
                description="Server vulnerable to ROBOT attack — RSA key exchange exploitable.",
                tags=["ssl", "robot", "bleichenbacher"],
            ))

        # Compression (CRIME)
        if re.search(r"compression.*supported|CRIME.*VULNERABLE", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="TLS Compression Enabled (CRIME)",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM, confidence=85.0,
                target=target, tool_name=self.name,
                description="TLS compression is enabled — vulnerable to CRIME attack.",
                tags=["ssl", "crime", "compression"],
            ))

        # Insecure renegotiation
        if re.search(r"insecure.*renegotiation|client.initiated.*renegotiation.*supported", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="Insecure TLS Renegotiation",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM, confidence=85.0,
                target=target, tool_name=self.name,
                description="Server supports insecure renegotiation — MitM risk.",
                cwe_id="CWE-310",
                tags=["ssl", "renegotiation"],
            ))

        # Certificate expiry
        if re.search(r"NOT VALID|certificate.*expired|validity.*expired", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="Certificate Expired or Invalid",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM, confidence=90.0,
                target=target, tool_name=self.name,
                description="SSL/TLS certificate is expired or not yet valid.",
                tags=["ssl", "certificate", "expired"],
            ))

        # Weak signature
        if re.search(r"sha1WithRSA|md5", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="Weak Certificate Signature Algorithm",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM, confidence=85.0,
                target=target, tool_name=self.name,
                description="Certificate uses a weak signature algorithm (SHA-1 or MD5).",
                cwe_id="CWE-328",
                tags=["ssl", "weak_signature"],
            ))

        logger.debug(f"sslyze parsed {len(findings)} findings")
        return findings

    def _parse_json(self, data: dict, target: str) -> list[Finding]:
        """Parse sslyze JSON output."""
        findings = []
        results = data.get("server_scan_results", [])

        for result in results:
            commands = result.get("scan_commands_results", {})

            # Check each vulnerability test
            heartbleed = commands.get("heartbleed", {})
            if heartbleed.get("is_vulnerable_to_heartbleed"):
                findings.append(Finding(
                    title="Heartbleed (CVE-2014-0160)",
                    vulnerability_type="known_vulnerability",
                    severity=SeverityLevel.CRITICAL, confidence=95.0,
                    target=target, tool_name=self.name,
                    description="Heartbleed vulnerability confirmed via sslyze.",
                    cve_id="CVE-2014-0160", tags=["ssl", "heartbleed"],
                ))

            ccs = commands.get("openssl_ccs_injection", {})
            if ccs.get("is_vulnerable_to_ccs_injection"):
                findings.append(Finding(
                    title="CCS Injection (CVE-2014-0224)",
                    vulnerability_type="known_vulnerability",
                    severity=SeverityLevel.HIGH, confidence=90.0,
                    target=target, tool_name=self.name,
                    description="CCS injection confirmed.",
                    cve_id="CVE-2014-0224", tags=["ssl", "ccs"],
                ))

        return findings


__all__ = ["SslyzeWrapper"]
