"""
WhiteHatHacker AI — SSLScan Wrapper

SSL/TLS configuration analysis — ciphers, protocols, certificate.
"""

from __future__ import annotations

import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class SslscanWrapper(SecurityTool):
    """
    sslscan — SSL/TLS configuration analyzer.

    Checks: supported protocols, cipher suites, certificate validity,
    Heartbleed, CRIME, BEAST, POODLE, key strength.
    """

    name = "sslscan"
    category = ToolCategory.CRYPTO
    description = "SSL/TLS cipher suite and protocol analysis"
    binary_name = "sslscan"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        port = options.get("port", 443)
        host_port = f"{target}:{port}" if ":" not in target else target

        command = self.build_command(host_port, options, profile)
        timeout = options.get("timeout", 60)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name, success=exit_code == 0, exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=" ".join(command), target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        options = options or {}
        cmd = [self.binary_name, "--no-colour"]

        if options.get("show_certificate"):
            cmd.append("--show-certificate")
        if options.get("show_client_cas"):
            cmd.append("--show-client-cas")

        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # SSLv2 / SSLv3 enabled
        for proto in ("SSLv2", "SSLv3"):
            if re.search(rf"{proto}\s+enabled", raw_output, re.IGNORECASE):
                findings.append(Finding(
                    title=f"Deprecated Protocol: {proto}",
                    description=f"{proto} is enabled — critically vulnerable to known attacks.",
                    vulnerability_type="misconfiguration",
                    severity=SeverityLevel.HIGH,
                    confidence=95.0, target=target, tool_name=self.name,
                    cwe_id="CWE-326",
                    tags=["ssl", "deprecated_protocol", proto.lower()],
                ))

        # TLS 1.0 / 1.1
        for proto in ("TLSv1.0", "TLSv1.1"):
            if re.search(rf"{re.escape(proto)}\s+enabled", raw_output, re.IGNORECASE):
                findings.append(Finding(
                    title=f"Deprecated Protocol: {proto}",
                    description=f"{proto} is enabled — deprecated and should be disabled.",
                    vulnerability_type="misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    confidence=90.0, target=target, tool_name=self.name,
                    cwe_id="CWE-326",
                    tags=["tls", "deprecated_protocol", proto.lower().replace(".", "")],
                ))

        # Weak ciphers — match sslscan output lines like:
        #   Accepted  TLSv1.2  128 bits  RC4-SHA
        #   Preferred TLSv1.0  56 bits   DES-CBC3-SHA
        weak_cipher_pattern = re.compile(
            r"(?:Accepted|Preferred)\s+\S+\s+\d+\s+bits\s+(\S+)",
            re.IGNORECASE,
        )
        _WEAK_KEYWORDS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5", "CBC3"}
        for match in weak_cipher_pattern.finditer(raw_output):
            cipher = match.group(1)
            cipher_upper = cipher.upper()
            matched_weaknesses = [kw for kw in _WEAK_KEYWORDS if kw in cipher_upper]
            if not matched_weaknesses:
                continue
            weakness = matched_weaknesses[0]
            findings.append(Finding(
                title=f"Weak Cipher: {cipher}",
                description=f"Weak cipher suite accepted: {cipher} ({weakness})",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=90.0, target=target, tool_name=self.name,
                cwe_id="CWE-327",
                tags=["ssl", "weak_cipher", weakness.lower()],
            ))

        # Heartbleed — sslscan outputs "Heartbleed:    vulnerable" or "NOT vulnerable"
        hb_match = re.search(r"heartbleed\s*:\s*(.*)", raw_output, re.IGNORECASE)
        if hb_match and "vulnerable" in hb_match.group(1).lower() and "not vulnerable" not in hb_match.group(1).lower():
            findings.append(Finding(
                title="Heartbleed Vulnerability (CVE-2014-0160)",
                description="Server is vulnerable to Heartbleed — memory disclosure attack.",
                vulnerability_type="known_vulnerability",
                severity=SeverityLevel.CRITICAL,
                confidence=95.0, target=target, tool_name=self.name,
                cwe_id="CWE-126",
                cve_id="CVE-2014-0160",
                tags=["ssl", "heartbleed", "cve-2014-0160"],
            ))

        # Certificate issues
        if re.search(r"self.signed|self-signed", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="Self-Signed Certificate",
                description="Server uses a self-signed certificate.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["ssl", "self_signed"],
            ))

        if re.search(r"expired|not valid after.*(?:201\d|20[2-9]\d)", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="Expired Certificate",
                description="SSL/TLS certificate has expired.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["ssl", "expired_cert"],
            ))

        # Key size
        key_match = re.search(r"RSA Key Strength:\s+(\d+)", raw_output)
        if key_match:
            key_size = int(key_match.group(1))
            if key_size < 2048:
                findings.append(Finding(
                    title=f"Weak RSA Key: {key_size} bits",
                    description=f"RSA key size is {key_size} bits — minimum 2048 recommended.",
                    vulnerability_type="misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    confidence=90.0, target=target, tool_name=self.name,
                    cwe_id="CWE-326",
                    tags=["ssl", "weak_key"],
                ))

        logger.debug(f"sslscan parsed {len(findings)} findings")
        return findings


__all__ = ["SslscanWrapper"]
