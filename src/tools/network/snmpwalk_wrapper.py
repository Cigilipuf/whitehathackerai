"""
WhiteHatHacker AI — SNMP Walk Wrapper

SNMP enumeration — community strings, system info, network interfaces, ARP.
"""

from __future__ import annotations

import re

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class SnmpwalkWrapper(SecurityTool):
    """
    snmpwalk — SNMP enumeration tool.

    Walks SNMP OIDs to discover system info, network config,
    running processes, installed software, user accounts.
    """

    name = "snmpwalk"
    category = ToolCategory.NETWORK
    description = "SNMP enumeration — system info, network, users, processes"
    binary_name = "snmpwalk"
    requires_root = False
    risk_level = RiskLevel.LOW

    # Important OID prefixes
    OID_SYSTEM_DESC = "1.3.6.1.2.1.1.1"
    OID_SYSTEM_NAME = "1.3.6.1.2.1.1.5"
    OID_INTERFACES = "1.3.6.1.2.1.2.2"
    OID_IP_ADDR = "1.3.6.1.2.1.4.20"
    OID_PROCESSES = "1.3.6.1.2.1.25.4.2"
    OID_SOFTWARE = "1.3.6.1.2.1.25.6.3"

    COMMON_COMMUNITIES = ["public", "private", "community", "snmp", "monitor"]

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        community = options.get("community", "")
        findings: list[Finding] = []
        stdout = ""
        stderr = ""
        exit_code = 1  # default; overwritten by execute_command

        if community:
            cmd = self.build_command(target, options, profile)
            stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
            findings = self.parse_output(stdout, target)
        else:
            # Try common community strings
            for cs in self.COMMON_COMMUNITIES:
                opts = {**options, "community": cs}
                cmd = self.build_command(target, opts, profile)
                stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
                if exit_code == 0 and stdout.strip():
                    findings.append(Finding(
                        title=f"SNMP Community String: '{cs}'",
                        description=f"SNMP community string '{cs}' is valid and returns data.",
                        vulnerability_type="misconfiguration",
                        severity=SeverityLevel.HIGH if cs in ("public", "private") else SeverityLevel.MEDIUM,
                        confidence=95.0, target=target, tool_name=self.name,
                        cwe_id="CWE-798",
                        tags=["snmp", "community_string", "default_creds"],
                    ))
                    findings.extend(self.parse_output(stdout, target))
                    break

        return ToolResult(
            tool_name=self.name, success=len(findings) > 0,
            exit_code=exit_code, stdout=stdout,
            stderr=stderr,
            findings=findings, command=f"snmpwalk {target}", target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        options = options or {}
        community = options.get("community", "public")
        version = options.get("version", "2c")
        oid = options.get("oid", "")

        cmd = [self.binary_name, "-v", version, "-c", community, target]
        if oid:
            cmd.append(oid)
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output.strip():
            return findings

        # System description
        sys_desc_match = re.search(
            r"SNMPv2-MIB::sysDescr\.0\s*=\s*STRING:\s*(.+)", raw_output
        )
        if sys_desc_match:
            desc = sys_desc_match.group(1).strip()
            findings.append(Finding(
                title=f"SNMP System: {desc[:80]}",
                description=f"System description via SNMP: {desc}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW, confidence=90.0,
                target=target, tool_name=self.name,
                tags=["snmp", "system_info"],
            ))

        # System name
        sys_name_match = re.search(
            r"sysName\.0\s*=\s*STRING:\s*(.+)", raw_output
        )
        if sys_name_match:
            findings.append(Finding(
                title=f"SNMP Hostname: {sys_name_match.group(1).strip()}",
                description=f"System name: {sys_name_match.group(1).strip()}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO, confidence=90.0,
                target=target, tool_name=self.name,
                tags=["snmp", "hostname"],
            ))

        # IP Addresses
        ip_pattern = re.compile(r"ipAdEntAddr\.\S+\s*=\s*IpAddress:\s*(\S+)")
        ips = ip_pattern.findall(raw_output)
        if ips:
            findings.append(Finding(
                title=f"SNMP Network Interfaces: {len(ips)} IPs",
                description=f"IP addresses: {', '.join(ips)}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW, confidence=85.0,
                target=target, tool_name=self.name,
                tags=["snmp", "network", "ip_addresses"],
                metadata={"ips": ips},
            ))

        # Count total OIDs retrieved
        oid_count = len([l for l in raw_output.splitlines() if "=" in l])
        if oid_count > 100:
            findings.append(Finding(
                title=f"Extensive SNMP Data: {oid_count} OIDs",
                description=f"SNMP returned {oid_count} OIDs — extensive system information exposed.",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.MEDIUM, confidence=80.0,
                target=target, tool_name=self.name,
                tags=["snmp", "data_exposure"],
            ))

        logger.debug(f"snmpwalk parsed {len(findings)} findings")
        return findings


__all__ = ["SnmpwalkWrapper"]
