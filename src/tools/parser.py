"""WhiteHatHacker AI — Unified Tool Output Parser.

Central parser that converts raw tool outputs (stdout, stderr, JSON, XML, CSV)
into normalised Finding objects for downstream analysis.
"""

from __future__ import annotations

import json
import re
from typing import Any

import defusedxml.ElementTree as ET

from loguru import logger
from pydantic import BaseModel, Field

from src.tools.base import Finding


# ---------------------------------------------------------------------------
# Normalised intermediate models
# ---------------------------------------------------------------------------

class RawToolOutput(BaseModel):
    """Container for raw output from a security tool."""

    tool_name: str
    command: str = ""
    return_code: int = 0
    stdout: str = ""
    stderr: str = ""
    output_file: str | None = None
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ParsedHost(BaseModel):
    """Parsed host / service record."""

    ip: str = ""
    hostname: str = ""
    port: int | None = None
    protocol: str = ""
    service: str = ""
    version: str = ""
    state: str = "open"
    extra: dict[str, Any] = Field(default_factory=dict)


class ParsedVulnerability(BaseModel):
    """Parsed vulnerability record before conversion to Finding."""

    vuln_type: str = ""
    title: str = ""
    description: str = ""
    severity: str = "info"
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    references: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main Parser
# ---------------------------------------------------------------------------

class UnifiedParser:
    """Converts heterogeneous tool outputs into normalised structures."""

    # ---- Format detection ------------------------------------------------

    @staticmethod
    def detect_format(text: str) -> str:
        """Detect output format: json, xml, csv, nmap_grep, plain."""
        stripped = text.strip()
        if not stripped:
            return "empty"
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                json.loads(stripped)
                return "json"
            except json.JSONDecodeError:
                pass
        if stripped.startswith("<?xml") or stripped.startswith("<"):
            try:
                ET.fromstring(stripped)
                return "xml"
            except ET.ParseError:
                pass
        # nmap greppable
        if "Host:" in stripped and "Ports:" in stripped:
            return "nmap_grep"
        # CSV heuristic
        lines = stripped.splitlines()
        if len(lines) > 1 and "," in lines[0]:
            cols = lines[0].count(",")
            if all(abs(line.count(",") - cols) <= 1 for line in lines[1:5]):
                return "csv"
        return "plain"

    # ---- JSON parsing ----------------------------------------------------

    @staticmethod
    def parse_json(text: str) -> list[dict[str, Any]]:
        """Parse JSON output (single object or array)."""
        data = json.loads(text.strip())
        if isinstance(data, list):
            return data
        return [data]

    # ---- XML / Nmap XML --------------------------------------------------

    @staticmethod
    def parse_nmap_xml(xml_text: str) -> list[ParsedHost]:
        """Parse nmap XML output into host records."""
        hosts: list[ParsedHost] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning(f"Nmap XML parse error: {exc}")
            return hosts

        for host_el in root.findall(".//host"):
            addr_el = host_el.find("address")
            ip = addr_el.get("addr", "") if addr_el is not None else ""

            hostnames_el = host_el.find("hostnames")
            hostname = ""
            if hostnames_el is not None:
                hn = hostnames_el.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                hosts.append(ParsedHost(
                    ip=ip,
                    hostname=hostname,
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                    service=service_el.get("name", "") if service_el is not None else "",
                    version=service_el.get("product", "") if service_el is not None else "",
                ))
        return hosts

    # ---- Nmap greppable --------------------------------------------------

    @staticmethod
    def parse_nmap_greppable(text: str) -> list[ParsedHost]:
        """Parse nmap greppable (-oG) output."""
        hosts: list[ParsedHost] = []
        for line in text.splitlines():
            if not line.startswith("Host:"):
                continue
            match = re.match(r"Host:\s+([\d.]+)\s+\(([^)]*)\)\s+Ports:\s+(.*)", line)
            if not match:
                continue
            ip, hostname, ports_str = match.groups()
            for port_info in ports_str.split(","):
                parts = port_info.strip().split("/")
                if len(parts) >= 5:
                    hosts.append(ParsedHost(
                        ip=ip,
                        hostname=hostname,
                        port=int(parts[0]) if parts[0].isdigit() else 0,
                        state=parts[1],
                        protocol=parts[2],
                        service=parts[4],
                    ))
        return hosts

    # ---- Nuclei JSON -----------------------------------------------------

    @staticmethod
    def parse_nuclei_json(text: str) -> list[ParsedVulnerability]:
        """Parse nuclei JSONL output."""
        vulns: list[ParsedVulnerability] = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            severity_map = {"critical": "critical", "high": "high", "medium": "medium",
                            "low": "low", "info": "info"}
            info = item.get("info", {})
            vulns.append(ParsedVulnerability(
                vuln_type=info.get("name", "nuclei-finding"),
                title=info.get("name", "Unknown"),
                description=info.get("description", ""),
                severity=severity_map.get(info.get("severity", "info"), "info"),
                url=item.get("matched-at", item.get("host", "")),
                evidence=item.get("extracted-results", item.get("matcher-name", "")),
                references=info.get("reference", []) or [],
                raw_data=item,
            ))
        return vulns

    # ---- SQLmap output ---------------------------------------------------

    @staticmethod
    def parse_sqlmap_output(text: str) -> list[ParsedVulnerability]:
        """Parse sqlmap stdout for confirmed injections."""
        vulns: list[ParsedVulnerability] = []
        current_param = ""
        current_type = ""

        for line in text.splitlines():
            line = line.strip()
            # Parameter identification
            param_match = re.search(r"Parameter:\s+(.+?)(?:\s+\()", line)
            if param_match:
                current_param = param_match.group(1)

            # Injection type
            type_match = re.search(r"Type:\s+(.+)", line)
            if type_match:
                current_type = type_match.group(1)

            # Payload
            payload_match = re.search(r"Payload:\s+(.+)", line)
            if payload_match and current_param:
                vulns.append(ParsedVulnerability(
                    vuln_type="sqli",
                    title=f"SQL Injection — {current_type}",
                    description=f"Parameter '{current_param}' vulnerable to {current_type}",
                    severity="high",
                    parameter=current_param,
                    payload=payload_match.group(1),
                    evidence=line,
                ))
        return vulns

    # ---- Nikto output ----------------------------------------------------

    @staticmethod
    def parse_nikto_output(text: str) -> list[ParsedVulnerability]:
        """Parse nikto stdout."""
        vulns: list[ParsedVulnerability] = []
        for line in text.splitlines():
            # Nikto findings begin with "+ "
            if not line.strip().startswith("+"):
                continue
            content = line.strip().lstrip("+ ").strip()
            if not content or content.startswith("Start Time") or content.startswith("End Time"):
                continue

            # OSVDB reference
            osvdb = ""
            osvdb_match = re.search(r"OSVDB-(\d+)", content)
            if osvdb_match:
                osvdb = f"OSVDB-{osvdb_match.group(1)}"

            vulns.append(ParsedVulnerability(
                vuln_type="web-server",
                title=content[:120],
                description=content,
                severity="medium" if "OSVDB" in content else "info",
                references=[osvdb] if osvdb else [],
                raw_data={"line": content},
            ))
        return vulns

    # ---- Generic line parser ---------------------------------------------

    @staticmethod
    def parse_lines(text: str) -> list[str]:
        """Split output into non-empty stripped lines."""
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    # ---- High-level dispatcher -------------------------------------------

    def parse_tool_output(
        self,
        raw: RawToolOutput,
    ) -> list[Finding]:
        """Parse any tool output into a list of Finding objects.

        Dispatches to the correct sub-parser based on tool name and format.
        """
        text = raw.stdout or ""
        if not text.strip():
            logger.debug(f"Empty output from {raw.tool_name}")
            return []

        findings: list[Finding] = []
        tool = raw.tool_name.lower()

        try:
            if tool in ("nmap", "nmap_wrapper"):
                fmt = self.detect_format(text)
                if fmt == "xml":
                    hosts = self.parse_nmap_xml(text)
                    for h in hosts:
                        findings.append(Finding(
                            tool_name=raw.tool_name,
                            vulnerability_type="open-port",
                            title=f"Open port {h.port}/{h.protocol} ({h.service})",
                            severity="info",
                            target=h.ip or h.hostname,
                            metadata={
                                "port": h.port,
                                "protocol": h.protocol,
                                "service": h.service,
                                "version": h.version,
                                "state": h.state,
                            },
                        ))
                elif fmt == "nmap_grep":
                    hosts = self.parse_nmap_greppable(text)
                    for h in hosts:
                        findings.append(Finding(
                            tool_name=raw.tool_name,
                            vulnerability_type="open-port",
                            title=f"Open port {h.port}/{h.protocol} ({h.service})",
                            severity="info",
                            target=h.ip or h.hostname,
                            metadata={"port": h.port, "protocol": h.protocol,
                                     "service": h.service, "state": h.state},
                        ))

            elif tool in ("nuclei", "nuclei_wrapper"):
                vulns = self.parse_nuclei_json(text)
                for v in vulns:
                    findings.append(self._vuln_to_finding(raw.tool_name, v))

            elif tool in ("sqlmap", "sqlmap_wrapper"):
                vulns = self.parse_sqlmap_output(text)
                for v in vulns:
                    findings.append(self._vuln_to_finding(raw.tool_name, v))

            elif tool in ("nikto", "nikto_wrapper"):
                vulns = self.parse_nikto_output(text)
                for v in vulns:
                    findings.append(self._vuln_to_finding(raw.tool_name, v))

            else:
                # Attempt auto-format
                fmt = self.detect_format(text)
                if fmt == "json":
                    items = self.parse_json(text)
                    for idx, item in enumerate(items):
                        findings.append(Finding(
                            tool_name=raw.tool_name,
                            vulnerability_type=item.get("type", item.get("vuln_type", "unknown")),
                            title=item.get("title", item.get("name", f"Finding #{idx + 1}")),
                            severity=item.get("severity", "info"),
                            target=item.get("url", item.get("host", item.get("target", ""))),
                            metadata=item,
                        ))
                else:
                    # Plain text — each non-empty line becomes info finding
                    for line in self.parse_lines(text):
                        findings.append(Finding(
                            tool_name=raw.tool_name,
                            vulnerability_type="raw-output",
                            title=line[:200],
                            severity="info",
                            target="",
                            metadata={"raw": line},
                        ))

        except Exception as exc:
            logger.error(f"Parse error for {raw.tool_name}: {exc}")
            findings.append(Finding(
                tool_name=raw.tool_name,
                vulnerability_type="parse-error",
                title=f"Failed to parse {raw.tool_name} output",
                severity="info",
                target="",
                metadata={"error": str(exc), "raw_length": len(text)},
            ))

        logger.info(f"Parsed {len(findings)} findings from {raw.tool_name}")
        return findings

    # ---- Helpers ---------------------------------------------------------

    @staticmethod
    def _vuln_to_finding(tool_name: str, vuln: ParsedVulnerability) -> Finding:
        """Convert ParsedVulnerability → Finding."""
        return Finding(
            tool_name=tool_name,
            vulnerability_type=vuln.vuln_type,
            title=vuln.title,
            description=vuln.description,
            severity=vuln.severity,
            target=vuln.url,
            parameter=vuln.parameter,
            payload=vuln.payload,
            evidence=vuln.evidence,
            references=vuln.references,
            metadata=vuln.raw_data,
        )


# ---------------------------------------------------------------------------
# Convenience singleton
# ---------------------------------------------------------------------------

unified_parser = UnifiedParser()
