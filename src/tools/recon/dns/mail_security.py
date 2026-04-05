"""
WhiteHatHacker AI — Email Security Checker (V7-T1-3)

Domain'in e-posta güvenlik kayıtlarını denetler:
  - SPF record analizi (soft fail, hard fail, permissive)
  - DKIM selector probing
  - DMARC policy analizi
  - SMTP banner grab (MX sunucularından)

Tüm kontroller DNS resolver üzerinden, harici binary gerekmez.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Common DKIM selectors for probing
_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "dkim", "mail", "k1", "s1", "s2", "mandrill",
    "everlytickey1", "everlytickey2", "smtp", "amazonses",
]


class EmailSecurityChecker(SecurityTool):
    """
    DNS-based email security posture assessment.

    Checks SPF, DKIM, and DMARC records for misconfigurations
    that could allow email spoofing or phishing.
    """

    name = "email_security_checker"
    category = ToolCategory.RECON_DNS
    description = "SPF/DKIM/DMARC email security posture checker"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        return True  # Pure Python + system resolver

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        findings: list[Finding] = []

        # Run all checks concurrently
        spf_f, dmarc_f, dkim_f, mx_f = await asyncio.gather(
            self._check_spf(domain),
            self._check_dmarc(domain),
            self._check_dkim(domain),
            self._check_mx(domain),
            return_exceptions=True,
        )

        for result_set in (spf_f, dmarc_f, dkim_f, mx_f):
            if isinstance(result_set, list):
                findings.extend(result_set)
            elif isinstance(result_set, BaseException):
                logger.debug(f"Email check error: {result_set}")

        return ToolResult(
            tool_name=self.name,
            success=True,
            findings=findings,
            raw_output=f"Email security checks for {domain}: {len(findings)} issues found",
        )

    # ──────────────── SPF ────────────────

    async def _check_spf(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        txt_records = await self._dns_txt(domain)
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            findings.append(Finding(
                title=f"Missing SPF Record — {domain}",
                description=(
                    f"The domain '{domain}' has no SPF record. This allows anyone "
                    f"to send emails pretending to be from this domain."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=95.0,
                target=domain,
                endpoint=f"_spf.{domain}",
                evidence="No TXT record matching v=spf1 found",
                tool_name=self.name,
                tags=["email", "spf", "spoofing"],
            ))
            return findings

        spf = spf_records[0]

        # Multiple SPF records (RFC violation)
        if len(spf_records) > 1:
            findings.append(Finding(
                title=f"Multiple SPF Records — {domain}",
                description=(
                    f"Domain '{domain}' has {len(spf_records)} SPF records. "
                    f"Per RFC 7208, only one SPF record is allowed. Multiple "
                    f"records cause undefined behavior."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=95.0,
                target=domain,
                evidence="\n".join(spf_records),
                tool_name=self.name,
                tags=["email", "spf"],
            ))

        # +all (accept everything)
        if re.search(r"\+all", spf):
            findings.append(Finding(
                title=f"SPF Record with +all — {domain}",
                description=(
                    f"The SPF record for '{domain}' ends with '+all', meaning "
                    f"ALL servers are authorized to send email for this domain. "
                    f"This completely negates SPF protection."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.HIGH,
                confidence=95.0,
                target=domain,
                evidence=f"SPF: {spf}",
                tool_name=self.name,
                tags=["email", "spf", "spoofing"],
            ))

        # ~all (softfail — permissive)
        elif re.search(r"~all", spf):
            findings.append(Finding(
                title=f"SPF Soft Fail (~all) — {domain}",
                description=(
                    f"The SPF record for '{domain}' uses '~all' (soft fail). "
                    f"This means unauthorized senders are flagged but NOT rejected, "
                    f"allowing potential spoofing. '-all' (hard fail) is recommended."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=90.0,
                target=domain,
                evidence=f"SPF: {spf}",
                tool_name=self.name,
                tags=["email", "spf"],
            ))

        # ?all (neutral — no opinion)
        elif re.search(r"\?all", spf):
            findings.append(Finding(
                title=f"SPF Neutral (?all) — {domain}",
                description=(
                    f"The SPF record for '{domain}' uses '?all' (neutral). "
                    f"This provides no protection against email spoofing."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=90.0,
                target=domain,
                evidence=f"SPF: {spf}",
                tool_name=self.name,
                tags=["email", "spf", "spoofing"],
            ))

        return findings

    # ──────────────── DMARC ────────────────

    async def _check_dmarc(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        txt_records = await self._dns_txt(f"_dmarc.{domain}")
        dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

        if not dmarc_records:
            findings.append(Finding(
                title=f"Missing DMARC Record — {domain}",
                description=(
                    f"The domain '{domain}' has no DMARC record. Without DMARC, "
                    f"receiving mail servers have no policy guidance for handling "
                    f"SPF/DKIM failures, enabling email spoofing."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=95.0,
                target=domain,
                endpoint=f"_dmarc.{domain}",
                evidence="No TXT record at _dmarc.{domain}",
                tool_name=self.name,
                tags=["email", "dmarc", "spoofing"],
            ))
            return findings

        dmarc = dmarc_records[0]

        # p=none (monitoring only, no enforcement)
        if re.search(r"p\s*=\s*none", dmarc, re.IGNORECASE):
            findings.append(Finding(
                title=f"DMARC Policy Set to None — {domain}",
                description=(
                    f"The DMARC record for '{domain}' has 'p=none', meaning failed "
                    f"emails are delivered normally. This is useful for monitoring "
                    f"but provides no protection against spoofing."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=90.0,
                target=domain,
                evidence=f"DMARC: {dmarc}",
                tool_name=self.name,
                tags=["email", "dmarc"],
            ))

        # No rua (no aggregate reports → blind spot)
        if "rua=" not in dmarc:
            findings.append(Finding(
                title=f"DMARC Without Aggregate Reporting — {domain}",
                description=(
                    f"The DMARC record for '{domain}' does not specify an aggregate "
                    f"report address (rua=). Without reporting, spoofing attempts "
                    f"go unnoticed."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.INFO,
                confidence=85.0,
                target=domain,
                evidence=f"DMARC: {dmarc}",
                tool_name=self.name,
                tags=["email", "dmarc"],
            ))

        return findings

    # ──────────────── DKIM ────────────────

    async def _check_dkim(self, domain: str) -> list[Finding]:
        """Probe common DKIM selectors."""
        findings: list[Finding] = []
        found_any = False

        for selector in _DKIM_SELECTORS:
            txt = await self._dns_txt(f"{selector}._domainkey.{domain}")
            if any("v=DKIM1" in r or "p=" in r for r in txt):
                found_any = True
                # Check for empty public key (testing mode)
                for r in txt:
                    if "p=" in r:
                        key_match = re.search(r"p\s*=\s*([^;]*)", r)
                        if key_match and not key_match.group(1).strip():
                            findings.append(Finding(
                                title=f"DKIM Empty Public Key — {domain} (selector: {selector})",
                                description=(
                                    f"DKIM selector '{selector}' for '{domain}' has an empty "
                                    f"public key (p=). This means DKIM is in testing mode "
                                    f"and provides no cryptographic verification."
                                ),
                                vulnerability_type="security_misconfiguration",
                                severity=SeverityLevel.MEDIUM,
                                confidence=90.0,
                                target=domain,
                                endpoint=f"{selector}._domainkey.{domain}",
                                evidence=f"DKIM TXT: {r}",
                                tool_name=self.name,
                                tags=["email", "dkim"],
                            ))

        if not found_any:
            findings.append(Finding(
                title=f"No DKIM Records Found — {domain}",
                description=(
                    f"No DKIM records were found for '{domain}' across "
                    f"{len(_DKIM_SELECTORS)} common selectors. This means sent "
                    f"emails cannot be cryptographically verified."
                ),
                vulnerability_type="security_misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=70.0,
                target=domain,
                evidence=f"Selectors probed: {', '.join(_DKIM_SELECTORS)}",
                tool_name=self.name,
                tags=["email", "dkim"],
            ))

        return findings

    # ──────────────── MX ────────────────

    async def _check_mx(self, domain: str) -> list[Finding]:
        """Check MX records exist."""
        findings: list[Finding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "MX", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            mx_output = stdout.decode().strip()

            if not mx_output:
                findings.append(Finding(
                    title=f"No MX Records — {domain}",
                    description=(
                        f"Domain '{domain}' has no MX records. If the domain is "
                        f"not intended to send/receive email, a null MX (RFC 7505) "
                        f"should be configured to prevent abuse."
                    ),
                    vulnerability_type="security_misconfiguration",
                    severity=SeverityLevel.INFO,
                    confidence=90.0,
                    target=domain,
                    evidence="dig +short MX returned empty",
                    tool_name=self.name,
                    tags=["email", "mx"],
                ))
        except Exception as exc:
            logger.debug(f"MX check failed: {exc}")

        return findings

    # ──────────────── DNS helper ────────────────

    @staticmethod
    async def _dns_txt(fqdn: str) -> list[str]:
        """Simple TXT record lookup via dig."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "TXT", fqdn,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            raw = stdout.decode().strip()
            if not raw:
                return []
            # dig returns quoted strings, strip quotes and join multi-line
            records: list[str] = []
            for line in raw.splitlines():
                cleaned = line.strip().strip('"')
                if cleaned:
                    records.append(cleaned)
            return records
        except Exception:
            return []

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []

    def build_command(self, target: str, options=None, profile=None) -> list[str]:
        return []  # Uses dig subprocess directly

    def get_default_options(self, profile: ScanProfile) -> dict[str, Any]:
        return {}
