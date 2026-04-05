"""
WhiteHatHacker AI — DNSRecon Wrapper

DNS enumeration: zone transfer, brute-force, SRV records, cache snooping.
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class DnsReconWrapper(SecurityTool):
    """
    DNSRecon — Comprehensive DNS enumeration.

    Types: std (standard), brt (brute), axfr (zone transfer),
    rvl (reverse lookup), srv (SRV records)
    """

    name = "dnsrecon"
    category = ToolCategory.RECON_DNS
    description = "DNS enumeration — zone transfer, brute-force, record discovery"
    binary_name = "dnsrecon"
    requires_root = False
    risk_level = RiskLevel.SAFE

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        import tempfile
        import os
        options = options or {}

        # Use temp file for JSON output (dnsrecon's -j - is unreliable)
        json_fd, json_path = tempfile.mkstemp(suffix=".json", prefix="dnsrecon_")
        os.close(json_fd)

        try:
            command = self.build_command(target, options, profile, json_path=json_path)
            stdout, stderr, exit_code = await self.execute_command(command, timeout=1200)

            # Try reading JSON from temp file first
            json_output = ""
            try:
                with open(json_path, "r") as f:
                    json_output = f.read()
            except (OSError, FileNotFoundError):
                pass

            # Parse priority: JSON file → stdout → stderr
            if json_output.strip():
                findings = self.parse_output(json_output, target)
            elif stdout.strip():
                findings = self.parse_output(stdout, target)
            else:
                findings = self.parse_output(stderr, target)

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
        finally:
            try:
                os.unlink(json_path)
            except OSError:
                pass

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
        json_path: str = "",
    ) -> list[str]:
        options = options or {}
        cmd = [self.binary_name, "-d", target]

        scan_type = options.get("type", "std")
        cmd.extend(["-t", scan_type])

        # JSON output to temp file (reliable) instead of -j - (unreliable)
        if json_path:
            cmd.extend(["-j", json_path])

        if scan_type == "brt" and "wordlist" in options:
            cmd.extend(["-D", options["wordlist"]])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # JSON parse
        try:
            records = json.loads(raw_output)
            if isinstance(records, list):
                for record in records:
                    finding = self._record_to_finding(record, target)
                    if finding:
                        findings.append(finding)
                logger.debug(f"dnsrecon parsed {len(findings)} DNS records")
                return findings
        except json.JSONDecodeError:
            pass

        # Fallback: text parse
        # [*]      A example.com 1.2.3.4
        # [*]      MX example.com mail.example.com
        # Only match known DNS record types (avoid false matches on info lines)
        _VALID_RTYPES = {
            "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR",
            "SRV", "CAA", "DNSKEY", "DS", "NSEC", "NSEC3",
        }
        record_pattern = re.compile(
            r"\[\*\]\s+(\w+)\s+(\S+)\s+(\S+)",
            re.MULTILINE,
        )
        for match in record_pattern.finditer(raw_output):
            rtype = match.group(1).upper()
            if rtype not in _VALID_RTYPES:
                continue
            rtype = match.group(1)
            name = match.group(2)
            value = match.group(3)

            findings.append(Finding(
                title=f"DNS {rtype}: {name} → {value}",
                description=f"DNS record: {rtype} {name} = {value}",
                vulnerability_type="dns_record",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=target,
                tool_name=self.name,
                tags=["dns", f"record:{rtype.lower()}"],
                metadata={"record_type": rtype, "name": name, "value": value},
            ))

        # Zone transfer tespit
        if "Zone Transfer" in raw_output and "successful" in raw_output.lower():
            findings.append(Finding(
                title=f"DNS Zone Transfer Possible: {target}",
                description="DNS zone transfer (AXFR) is allowed — this leaks all DNS records",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.HIGH,
                confidence=95.0,
                target=target,
                tool_name=self.name,
                tags=["dns", "zone_transfer", "misconfiguration"],
                evidence=raw_output[:1000],
                cwe_id="CWE-200",
            ))

        return findings

    def _record_to_finding(self, record: dict, target: str) -> Finding | None:
        rtype = record.get("type", "")
        name = record.get("name", "")
        address = record.get("address", record.get("target", record.get("exchange", "")))

        if not rtype or not name:
            return None

        severity = SeverityLevel.INFO

        # Zone transfer = HIGH
        if rtype == "info" and "zone transfer" in record.get("zone_transfer", "").lower():
            severity = SeverityLevel.HIGH

        return Finding(
            title=f"DNS {rtype}: {name}",
            description=f"DNS {rtype} record: {name} → {address}",
            vulnerability_type="dns_record",
            severity=severity,
            confidence=90.0,
            target=target,
            tool_name=self.name,
            tags=["dns", f"record:{rtype.lower()}"],
            metadata=record,
        )


__all__ = ["DnsReconWrapper"]
