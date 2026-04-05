"""
WhiteHatHacker AI — Nmap Wrapper

Nmap port tarama ve servis tespiti aracı wrapper'ı.
Profil bazlı komut oluşturma ve çıktı parse desteği.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import (
    RiskLevel,
    ScanProfile,
    SeverityLevel,
    ToolCategory,
)


class NmapWrapper(SecurityTool):
    """
    Nmap — Network exploration and security auditing tool.

    Port tarama, servis tespiti, işletim sistemi parmak izi,
    script engine (NSE) desteği.
    """

    name = "nmap"
    category = ToolCategory.RECON_PORT
    description = "Network mapper — port scan, service detection, OS fingerprint"
    binary_name = "nmap"
    requires_root = False  # Use connect scan (-sT) instead of SYN scan; no root needed
    risk_level = RiskLevel.LOW
    default_timeout = 1200  # 20min — full port + service scan on large targets

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        """Nmap taramasını çalıştır."""
        options = options or {}

        # Use temp file for XML output to avoid SIGSEGV with -oX -
        # NOTE: We use a non-/tmp directory to avoid Linux protected_regular=2
        # which blocks root (via sudo) from writing to files owned by another user
        # in world-writable sticky directories like /tmp.
        scan_tmp_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)
            )))),
            "output", "scans"
        )
        os.makedirs(scan_tmp_dir, exist_ok=True)
        xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="nmap_", dir=scan_tmp_dir)
        os.close(xml_fd)
        # mkstemp already creates with 0o600 — no chmod needed
        options["_xml_output_path"] = xml_path

        command = self.build_command(target, options, profile)

        # Timeout: profil bazlı
        timeout = {
            ScanProfile.STEALTH: 1200,
            ScanProfile.BALANCED: 600,
            ScanProfile.AGGRESSIVE: 300,
        }.get(profile, 600)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)

        # Read XML from temp file instead of stdout
        xml_content = ""
        try:
            if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
                with open(xml_path, "r", encoding="utf-8", errors="replace") as f:
                    xml_content = f.read()
                logger.debug(f"Nmap XML file read: {len(xml_content)} bytes from {xml_path}")
        except Exception as e:
            logger.warning(f"Failed to read nmap XML file {xml_path}: {e}")
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

        # Parse XML content (from file), fall back to stdout/stderr
        findings = self.parse_output(xml_content, target) if xml_content else []
        if not findings and stdout.strip():
            findings = self.parse_output(stdout, target)
        if not findings and stderr.strip():
            findings = self.parse_output(stderr, target)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0 or len(findings) > 0),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            execution_time=0,  # execute_command tarafından takip edilir
            command=" ".join(command),
            target=target,
        )

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        """Profil bazlı nmap komutu oluştur."""
        options = options or {}
        cmd = [self.binary_name]

        # Profil bazlı parametreler
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend([
                    "-sT",          # Connect scan (no root needed)
                    "-T2",          # Timing: polite
                    "--top-ports", "100",
                    "-Pn",          # No ping
                    "--max-rate", "10",
                    "-sV", "--version-intensity", "2",
                ])
            case ScanProfile.BALANCED:
                cmd.extend([
                    "-sT", "-sV",   # Connect scan + version detect
                    "-T3",          # Timing: normal
                    "--top-ports", "200",
                    "-Pn",
                ])
            case ScanProfile.AGGRESSIVE:
                cmd.extend([
                    "-sT", "-sV", "-sC",  # Scripts
                    "-T4",          # Timing: aggressive
                    "--top-ports", "1000",  # Top 1000 ports (was -p- but all-port scan wastes 5-20min on CDN hosts)
                    "-A",           # Aggressive scan
                    "--max-rate", "1000",
                ])
            case _:
                cmd.extend(["-sT", "-sV", "-T3", "--top-ports", "1000", "-Pn"])

        # XML çıktı — use temp file (avoids SIGSEGV with -oX -)
        xml_path = options.get("_xml_output_path", "-")
        cmd.extend(["-oX", xml_path])

        # Özel opsiyonlar — 'ports' overrides profile port selection
        if "ports" in options:
            # Remove any existing --top-ports or -p from profile defaults
            # since explicit ports override them
            i = 0
            while i < len(cmd):
                if cmd[i] in ("--top-ports", "-p"):
                    cmd.pop(i)  # Remove flag
                    if i < len(cmd):
                        cmd.pop(i)  # Remove value
                elif cmd[i] == "-p-":
                    cmd.pop(i)
                else:
                    i += 1
            cmd.extend(["-p", str(options["ports"])])
        if "scripts" in options:
            cmd.extend(["--script", options["scripts"]])

        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        """Nmap XML çıktısını parse et."""
        findings: list[Finding] = []

        if not raw_output or raw_output.startswith("TIMEOUT"):
            return findings

        try:
            import defusedxml.ElementTree as SafeET
            root = SafeET.fromstring(raw_output)
        except Exception:
            # XML değilse normal text olarak parse et
            return self._parse_text_output(raw_output, target)

        for host in root.findall(".//host"):
            host_addr = ""
            addr_elem = host.find("address")
            if addr_elem is not None:
                host_addr = addr_elem.get("addr", "")

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = port.get("portid", "")
                protocol = port.get("protocol", "tcp")

                service = port.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                service_version = service.get("version", "") if service is not None else ""
                service_product = service.get("product", "") if service is not None else ""

                finding = Finding(
                    title=f"Open Port: {port_id}/{protocol} ({service_name})",
                    description=(
                        f"Port {port_id}/{protocol} is open on {host_addr}. "
                        f"Service: {service_product} {service_version}".strip()
                    ),
                    vulnerability_type="open_port",
                    severity=SeverityLevel.INFO,
                    confidence=95.0,
                    target=host_addr or target,
                    endpoint=f"{host_addr}:{port_id}",
                    tool_name=self.name,
                    tags=[f"port:{port_id}", f"service:{service_name}", f"protocol:{protocol}"],
                )
                findings.append(finding)

            # NSE script sonuçları
            for script in host.findall(".//script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")

                # Zafiyet script'leri için finding oluştur
                if any(kw in script_id for kw in ["vuln", "exploit", "cve"]):
                    findings.append(Finding(
                        title=f"NSE: {script_id}",
                        description=script_output[:500],
                        vulnerability_type="nse_finding",
                        severity=SeverityLevel.MEDIUM,
                        confidence=70.0,
                        target=host_addr or target,
                        tool_name=self.name,
                        evidence=script_output,
                        tags=["nse", script_id],
                    ))

        logger.debug(f"Nmap parsed {len(findings)} findings")
        return findings

    def _parse_text_output(self, output: str, target: str) -> list[Finding]:
        """Plain text nmap çıktısını parse et (fallback)."""
        findings: list[Finding] = []

        # Açık port satırlarını bul
        port_pattern = re.compile(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?")

        for match in port_pattern.finditer(output):
            port_id = match.group(1)
            protocol = match.group(2)
            service = match.group(3)
            version = match.group(4) or ""

            findings.append(Finding(
                title=f"Open Port: {port_id}/{protocol} ({service})",
                description=f"Port {port_id}/{protocol} is open. Service: {service} {version}".strip(),
                vulnerability_type="open_port",
                severity=SeverityLevel.INFO,
                confidence=95.0,
                target=target,
                endpoint=f"{target}:{port_id}",
                tool_name=self.name,
                tags=[f"port:{port_id}", f"service:{service}"],
            ))

        return findings


__all__ = ["NmapWrapper"]
