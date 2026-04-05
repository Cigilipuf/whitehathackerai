"""
WhiteHatHacker AI — Whois Wrapper

Domain/IP registration info — registrar, dates, nameservers, contacts.
"""

from __future__ import annotations

import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class WhoisWrapper(SecurityTool):
    """
    whois — Domain/IP registration information lookup.
    """

    name = "whois"
    category = ToolCategory.RECON_OSINT
    description = "Domain/IP registration info — registrar, dates, contacts"
    binary_name = "whois"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        cmd = [self.binary_name, target]
        stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name, success=exit_code == 0, exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=f"whois {target}", target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["whois", target]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        info: dict[str, str] = {}

        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creat(?:ion|ed)\s*Date:\s*(.+)",
            "expiry_date": r"(?:Registry\s+)?Expir(?:y|ation)\s*Date:\s*(.+)",
            "updated_date": r"Updated?\s*Date:\s*(.+)",
            "registrant_org": r"Registrant\s*Organization:\s*(.+)",
            "registrant_country": r"Registrant\s*Country:\s*(.+)",
            "nameservers": r"Name\s*Server:\s*(\S+)",
            "dnssec": r"DNSSEC:\s*(.+)",
        }

        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw_output, re.IGNORECASE)
            if matches:
                info[key] = matches[0].strip() if key != "nameservers" else ", ".join(m.strip().lower() for m in matches)

        if info:
            desc_lines = [f"  {k}: {v}" for k, v in info.items()]
            findings.append(Finding(
                title=f"WHOIS: {target}",
                description="Domain registration info:\n" + "\n".join(desc_lines),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["whois", "osint", "domain_info"],
                metadata=info,
            ))

        # Emails (useful for phishing/social engineering scope)
        emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", raw_output)
        unique_emails = list(set(emails))
        if unique_emails:
            findings.append(Finding(
                title=f"WHOIS Emails: {len(unique_emails)}",
                description=f"Emails found in WHOIS: {', '.join(unique_emails[:10])}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW,
                confidence=85.0, target=target, tool_name=self.name,
                tags=["whois", "email", "osint"],
                metadata={"emails": unique_emails},
            ))

        # DNSSEC check
        dnssec = info.get("dnssec", "").lower()
        if dnssec and "unsigned" in dnssec:
            findings.append(Finding(
                title="DNSSEC Not Enabled",
                description="Domain does not have DNSSEC — vulnerable to DNS spoofing.",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=85.0, target=target, tool_name=self.name,
                tags=["dns", "dnssec", "missing"],
            ))

        logger.debug(f"whois parsed {len(findings)} findings")
        return findings


__all__ = ["WhoisWrapper"]
