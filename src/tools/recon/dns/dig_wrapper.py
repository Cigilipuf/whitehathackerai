"""
WhiteHatHacker AI — Dig Wrapper

DNS sorgu aracı: A, AAAA, MX, TXT, NS, SOA, CNAME, AXFR.
Zone transfer denemesi dahil.
"""

from __future__ import annotations

import re
from typing import Any


from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class DigWrapper(SecurityTool):
    """
    dig — DNS lookup utility.

    Standart DNS sorguları, zone transfer denemesi.
    """

    name = "dig"
    category = ToolCategory.RECON_DNS
    description = "DNS lookup utility — record queries, zone transfer"
    binary_name = "dig"
    requires_root = False
    risk_level = RiskLevel.SAFE

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=1200)
        findings = self.parse_output(stdout, target)

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
        # Default to "A" instead of "ANY" — many resolvers reject/limit ANY (RFC 8482)
        record_type = options.get("record_type", "A")
        cmd = [self.binary_name]

        if record_type.upper() == "AXFR":
            # Zone transfer
            nameserver = options.get("nameserver", "")
            cmd.extend(["axfr", target])
            if nameserver:
                cmd.append(f"@{nameserver}")
            # Keep stats for zone transfer detection
            cmd.append("+noall")
            cmd.append("+answer")
            cmd.append("+stats")
        else:
            cmd.extend([target, record_type])
            if "nameserver" in options:
                cmd.append(f"@{options['nameserver']}")
            cmd.append("+noall")
            cmd.append("+answer")
            # Timeout: 5 seconds
            cmd.append("+time=5")
            cmd.append("+tries=2")
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # dig +answer çıktısı: domain. TTL IN TYPE value
        record_pattern = re.compile(
            r"^(\S+)\.\s+(\d+)\s+IN\s+(\S+)\s+(.+)$",
            re.MULTILINE,
        )

        for match in record_pattern.finditer(raw_output):
            name = match.group(1)
            ttl = match.group(2)
            rtype = match.group(3)
            value = match.group(4).strip().rstrip(".")

            findings.append(Finding(
                title=f"DNS {rtype}: {name} → {value}",
                description=f"DNS {rtype} record | TTL: {ttl} | {name} → {value}",
                vulnerability_type="dns_record",
                severity=SeverityLevel.INFO,
                confidence=95.0,
                target=target,
                tool_name=self.name,
                tags=["dns", f"record:{rtype.lower()}"],
                metadata={"name": name, "ttl": int(ttl), "type": rtype, "value": value},
            ))

        # Zone transfer başarılı mı?
        # XFR size appears in +stats output; also check if we have many AXFR records
        is_axfr_query = "axfr" in raw_output.lower() or "XFR size:" in raw_output
        has_many_records = len(findings) > 10  # More reliable than counting newlines
        if is_axfr_query or (has_many_records and "XFR size:" in raw_output):
            findings.append(Finding(
                title=f"Zone Transfer Successful: {target}",
                description="DNS zone transfer (AXFR) succeeded — all DNS records exposed",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.HIGH,
                confidence=98.0,
                target=target,
                tool_name=self.name,
                tags=["dns", "zone_transfer", "critical"],
                evidence=raw_output[:2000],
                cwe_id="CWE-200",
            ))

        return findings


__all__ = ["DigWrapper"]
