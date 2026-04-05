"""
WhiteHatHacker AI — TShark Wrapper

Network packet capture and analysis (Wireshark CLI).
"""

from __future__ import annotations


from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class TsharkWrapper(SecurityTool):
    """
    tshark — Wireshark CLI for packet capture and protocol analysis.

    Captures and analyzes: cleartext credentials, unencrypted protocols,
    sensitive data in transit, protocol anomalies.
    """

    name = "tshark"
    category = ToolCategory.NETWORK
    description = "Network packet capture and analysis (Wireshark CLI)"
    binary_name = "tshark"
    requires_root = False   # Disabled — no passwordless sudo; may fail at runtime
    risk_level = RiskLevel.LOW

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 60)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name, success=exit_code in (0, 1), exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=" ".join(command), target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        options = options or {}
        cmd = [self.binary_name]

        if "pcap_file" in options:
            cmd.extend(["-r", options["pcap_file"]])
        else:
            interface = options.get("interface", "any")
            cmd.extend(["-i", interface])
            duration = options.get("duration", 30)
            cmd.extend(["-a", f"duration:{duration}"])
            if target and target not in ("any", "all"):
                cmd.extend(["-f", f"host {target}"])

        # Display filters
        if "display_filter" in options:
            cmd.extend(["-Y", options["display_filter"]])

        # Output format
        cmd.extend(["-T", "fields"])
        cmd.extend(["-e", "frame.number"])
        cmd.extend(["-e", "ip.src"])
        cmd.extend(["-e", "ip.dst"])
        cmd.extend(["-e", "tcp.srcport"])
        cmd.extend(["-e", "tcp.dstport"])
        cmd.extend(["-e", "_ws.col.Protocol"])
        cmd.extend(["-e", "_ws.col.Info"])
        cmd.extend(["-E", "separator=|"])

        # Packet count limit
        count = options.get("count", 1000)
        cmd.extend(["-c", str(count)])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        protocols_seen: dict[str, int] = {}
        cleartext_indicators = []

        for line in raw_output.splitlines():
            parts = line.split("|")
            if len(parts) < 7:
                continue

            frame, src_ip, dst_ip, src_port, dst_port, protocol, info = (
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
            )

            protocol_lower = protocol.strip().lower()
            protocols_seen[protocol_lower] = protocols_seen.get(protocol_lower, 0) + 1

            # Check for cleartext protocols
            if protocol_lower in ("http", "ftp", "telnet", "smtp", "pop", "imap"):
                cleartext_indicators.append(f"{protocol} {src_ip}→{dst_ip}")

            # Check for credentials in cleartext
            info_lower = info.lower()
            if any(kw in info_lower for kw in ("pass", "login", "user", "auth", "credentials")):
                findings.append(Finding(
                    title=f"Cleartext Credential Indicator: {protocol}",
                    description=f"Possible cleartext credential exchange: {info[:200]}",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.HIGH,
                    confidence=60.0, target=target, tool_name=self.name,
                    cwe_id="CWE-319",
                    tags=["cleartext", "credentials", protocol_lower],
                    evidence=[f"Frame {frame}: {src_ip}:{src_port} → {dst_ip}:{dst_port} [{protocol}] {info[:100]}"],
                ))

        # Report cleartext protocols
        for proto in ("http", "ftp", "telnet", "smtp", "pop", "imap"):
            count = protocols_seen.get(proto, 0)
            if count > 0:
                findings.append(Finding(
                    title=f"Cleartext Protocol: {proto.upper()} ({count} packets)",
                    description=f"{count} {proto.upper()} packets captured — data transmitted in cleartext.",
                    vulnerability_type="misconfiguration",
                    severity=SeverityLevel.MEDIUM if proto in ("ftp", "telnet") else SeverityLevel.LOW,
                    confidence=85.0, target=target, tool_name=self.name,
                    cwe_id="CWE-319",
                    tags=["cleartext", proto],
                    metadata={"packet_count": count},
                ))

        # Protocol summary
        if protocols_seen:
            findings.append(Finding(
                title=f"Traffic Summary: {len(protocols_seen)} Protocols",
                description=f"Protocols: {', '.join(f'{k}({v})' for k, v in sorted(protocols_seen.items(), key=lambda x: -x[1])[:15])}",
                vulnerability_type="info",
                severity=SeverityLevel.INFO,
                confidence=90.0, target=target, tool_name=self.name,
                tags=["traffic_analysis"],
                metadata={"protocols": protocols_seen},
            ))

        logger.debug(f"tshark parsed {len(findings)} findings")
        return findings


__all__ = ["TsharkWrapper"]
