"""
WhiteHatHacker AI — Shodan Python API Wrapper

Shodan REST API entegrasyonu — CLI yerine doğrudan HTTP API kullanır.
API key .env/config'den okunur, CLI pre-config gerektirmez.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

_SHODAN_API = "https://api.shodan.io"

# Shodan API keys are 32-char alphanumeric strings
_SHODAN_KEY_RE = re.compile(r"^[A-Za-z0-9]{20,64}$")


class ShodanWrapper(SecurityTool):
    """
    Shodan — Internet device intelligence via REST API.

    Provides: open ports, services, banners, vulns (CVEs),
    SSL info, hostnames, geo-location, organization, ISP.

    Requires: SHODAN_API_KEY in .env / config
    """

    name = "shodan"
    category = ToolCategory.RECON_OSINT
    description = "Shodan REST API — device intelligence, open ports, CVEs"
    binary_name = "shodan"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self._api_key: str = os.environ.get("SHODAN_API_KEY", "")

    def is_available(self) -> bool:
        if self._api_key:
            return True
        return super().is_available()

    async def run(
        self, target: str, options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        mode = options.get("mode", "host")
        if self._api_key:
            return await self._api_run(target, mode, options)
        return await self._cli_run(target, mode, options)

    async def _api_run(self, target: str, mode: str, options: dict) -> ToolResult:
        if not _SHODAN_KEY_RE.match(self._api_key):
            logger.warning(f"Shodan API key looks invalid (length={len(self._api_key)}), skipping API call")
            return ToolResult(tool_name=self.name, success=False, error_message="Invalid Shodan API key format", target=target)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                if mode == "search":
                    return await self._api_search(client, target, options)
                return await self._api_host(client, target)
        except Exception as e:
            logger.error(f"Shodan API error: {e}")
            return ToolResult(tool_name=self.name, success=False, error_message=str(e), target=target)

    async def _api_host(self, client: httpx.AsyncClient, target: str) -> ToolResult:
        ip = target
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            resp = await client.get(f"{_SHODAN_API}/dns/resolve", params={"hostnames": target, "key": self._api_key})
            try:
                ip = resp.json().get(target, "") if resp.status_code == 200 else ""
            except Exception:
                ip = ""
            if not ip:
                return ToolResult(tool_name=self.name, success=False, error_message=f"Cannot resolve {target}", target=target)

        resp = await client.get(f"{_SHODAN_API}/shodan/host/{ip}", params={"key": self._api_key})
        if resp.status_code != 200:
            return ToolResult(tool_name=self.name, success=False, error_message=f"Shodan {resp.status_code}", target=target)

        try:
            data = resp.json()
        except Exception:
            return ToolResult(tool_name=self.name, success=False, error_message="Shodan returned non-JSON response", target=target)
        findings = self._parse_host_json(data, target)
        return ToolResult(tool_name=self.name, success=True, stdout=json.dumps(data, indent=2)[:10000], findings=findings, target=target)

    async def _api_search(self, client: httpx.AsyncClient, query: str, options: dict) -> ToolResult:
        resp = await client.get(f"{_SHODAN_API}/shodan/host/search", params={"key": self._api_key, "query": query, "page": options.get("page", 1)})
        if resp.status_code != 200:
            return ToolResult(tool_name=self.name, success=False, error_message=f"Shodan search {resp.status_code}", target=query)
        try:
            data = resp.json()
        except Exception:
            return ToolResult(tool_name=self.name, success=False, error_message="Shodan search returned non-JSON response", target=query)
        findings: list[Finding] = []
        for match in data.get("matches", [])[:50]:
            ip, port = match.get("ip_str", ""), match.get("port", 0)
            product, vulns = match.get("product", ""), list(match.get("vulns", {}).keys())
            findings.append(Finding(
                title=f"Shodan: {ip}:{port}" + (f" ({product})" if product else ""),
                description=f"Port {port} | Product: {product} | Vulns: {len(vulns)}",
                vulnerability_type="known_vulnerability" if vulns else "information_disclosure",
                severity=SeverityLevel.HIGH if vulns else SeverityLevel.INFO,
                confidence=80.0, target=ip, tool_name=self.name,
                tags=["shodan", "search"] + vulns[:5],
                metadata={"port": port, "product": product, "vulns": vulns},
            ))
        return ToolResult(tool_name=self.name, success=True, stdout=json.dumps(data, indent=2)[:10000], findings=findings, target=query)

    def _parse_host_json(self, data: dict, target: str) -> list[Finding]:
        findings: list[Finding] = []
        ip = data.get("ip_str", target)
        ports = data.get("ports", [])
        vulns = data.get("vulns", {})
        org = data.get("org", "")
        hostnames = data.get("hostnames", [])

        if ports:
            findings.append(Finding(
                title=f"Shodan: {len(ports)} Open Ports on {ip}",
                description=f"Open ports: {', '.join(str(p) for p in sorted(ports))}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO, confidence=90.0,
                target=ip, tool_name=self.name, tags=["shodan", "open_ports"],
                metadata={"ports": ports, "org": org},
            ))
        if vulns:
            cve_list = list(vulns.keys())
            findings.append(Finding(
                title=f"Shodan: {len(cve_list)} Known CVEs",
                description=f"CVEs: {', '.join(cve_list[:15])}",
                vulnerability_type="known_vulnerability",
                severity=SeverityLevel.HIGH, confidence=70.0,
                target=ip, tool_name=self.name, tags=["shodan", "cve"] + cve_list[:10],
                metadata={"cves": cve_list},
            ))
        for svc in data.get("data", [])[:20]:
            port, product = svc.get("port", 0), svc.get("product", "")
            version, banner = svc.get("version", ""), svc.get("data", "")[:300]
            svc_vulns = list(svc.get("vulns", {}).keys())
            findings.append(Finding(
                title=f"Service: {ip}:{port}" + (f" {product} {version}" if product else ""),
                description=banner[:200],
                vulnerability_type="known_vulnerability" if svc_vulns else "information_disclosure",
                severity=SeverityLevel.HIGH if svc_vulns else SeverityLevel.INFO,
                confidence=80.0, target=ip, endpoint=f"{ip}:{port}",
                tool_name=self.name, tags=["shodan", "service", f"port:{port}"],
                metadata={"port": port, "product": product, "version": version, "vulns": svc_vulns},
            ))
        if org:
            findings.append(Finding(
                title=f"Organization: {org}",
                description=f"Target belongs to {org}" + (f" | Hostnames: {', '.join(hostnames)}" if hostnames else ""),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO, confidence=90.0,
                target=ip, tool_name=self.name, tags=["shodan", "org"],
            ))
        return findings

    async def _cli_run(self, target: str, mode: str, options: dict) -> ToolResult:
        cmd = ["shodan", "search", "--limit", str(options.get("limit", 20)), target] if mode == "search" else ["shodan", "host", target]
        stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
        return ToolResult(tool_name=self.name, success=exit_code == 0, stdout=stdout, stderr=stderr, findings=self.parse_output(stdout, target), command=" ".join(cmd), target=target)

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["shodan", "host", target]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output.strip():
            return findings
        ports_m = re.search(r"Ports:\s*(.+)", raw_output)
        if ports_m:
            findings.append(Finding(title="Shodan: Open Ports", description=ports_m.group(1), vulnerability_type="information_disclosure", severity=SeverityLevel.INFO, confidence=80.0, target=target, tool_name=self.name, tags=["shodan"]))
        vuln_m = re.search(r"Vulnerabilities:\s*(.+)", raw_output)
        if vuln_m:
            findings.append(Finding(title="Shodan: CVEs", description=vuln_m.group(1), vulnerability_type="known_vulnerability", severity=SeverityLevel.HIGH, confidence=70.0, target=target, tool_name=self.name, tags=["shodan", "cve"]))
        return findings


__all__ = ["ShodanWrapper"]
