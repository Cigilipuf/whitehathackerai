"""
WhiteHatHacker AI — Censys REST API Wrapper

Censys Search API v2 entegrasyonu.  Host, sertifika ve servis arama.
API key .env/config'den okunur (CENSYS_API_ID + CENSYS_API_SECRET).
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

_CENSYS_V2 = "https://search.censys.io/api/v2"


class CensysWrapper(SecurityTool):
    """
    Censys — Internet-wide scan data intelligence via REST API v2.

    Provides: open ports, TLS certificates, services, cloud provider,
    autonomous system, geo-location, software/version, CVEs.

    Requires: CENSYS_API_ID + CENSYS_API_SECRET in .env
    """

    name = "censys"
    category = ToolCategory.RECON_OSINT
    description = "Censys REST API v2 — host intelligence, certs, services, CVEs"
    binary_name = "censys"  # pip install censys CLI (optional fallback)
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self._api_id: str = os.environ.get("CENSYS_API_ID", "")
        self._api_secret: str = os.environ.get("CENSYS_API_SECRET", "")

    # ── availability ───────────────────────────────────────────
    def is_available(self) -> bool:
        if self._api_id and self._api_secret:
            return True
        return super().is_available()

    # ── main entry ─────────────────────────────────────────────
    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        mode = options.get("mode", "host")  # host | search | cert

        if self._api_id and self._api_secret:
            return await self._api_run(target, mode, options)
        return await self._cli_run(target, mode, options)

    # ── REST API ───────────────────────────────────────────────
    async def _api_run(
        self, target: str, mode: str, options: dict
    ) -> ToolResult:
        auth = (self._api_id, self._api_secret)
        try:
            async with httpx.AsyncClient(timeout=30.0, auth=auth) as client:
                match mode:
                    case "search":
                        return await self._api_search(client, target, options)
                    case "cert":
                        return await self._api_cert(client, target)
                    case _:
                        return await self._api_host(client, target)
        except Exception as exc:
            logger.error(f"Censys API error: {exc}")
            return ToolResult(
                tool_name=self.name,
                success=False,
                error_message=str(exc),
                target=target,
            )

    async def _api_host(self, client: httpx.AsyncClient, target: str) -> ToolResult:
        """Fetch host details by IP."""
        # Resolve hostname → IP if needed
        ip = target
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            resp = await client.get(
                f"{_CENSYS_V2}/hosts/search",
                params={"q": f"dns.names: {target}", "per_page": 1},
            )
            if resp.status_code == 200:
                try:
                    hits = resp.json().get("result", {}).get("hits", [])
                except Exception:
                    hits = []
                if hits:
                    ip = hits[0].get("ip", target)
                else:
                    return ToolResult(
                        tool_name=self.name,
                        success=False,
                        error_message=f"No Censys results for {target}",
                        target=target,
                    )

        resp = await client.get(f"{_CENSYS_V2}/hosts/{ip}")
        if resp.status_code != 200:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error_message=f"Censys host API {resp.status_code}",
                target=target,
            )

        try:
            data = resp.json().get("result", {})
        except Exception:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error_message="Censys host API returned non-JSON response",
                target=target,
            )
        findings = self._parse_host_result(data, target)
        return ToolResult(
            tool_name=self.name,
            success=True,
            stdout=json.dumps(data, indent=2)[:10_000],
            findings=findings,
            target=target,
        )

    async def _api_search(
        self, client: httpx.AsyncClient, query: str, options: dict
    ) -> ToolResult:
        """Free-form host search."""
        per_page = options.get("per_page", 25)
        resp = await client.get(
            f"{_CENSYS_V2}/hosts/search",
            params={"q": query, "per_page": per_page},
        )
        if resp.status_code != 200:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error_message=f"Censys search {resp.status_code}",
                target=query,
            )

        try:
            data = resp.json().get("result", {})
        except Exception:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error_message="Censys search returned non-JSON response",
                target=query,
            )
        findings: list[Finding] = []
        for hit in data.get("hits", [])[:50]:
            ip = hit.get("ip", "")
            services = hit.get("services", [])
            ports = [s.get("port") for s in services if s.get("port")]
            findings.append(
                Finding(
                    title=f"Censys: {ip} ({len(ports)} services)",
                    description=f"Ports: {', '.join(str(p) for p in ports)}",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.INFO,
                    confidence=85.0,
                    target=ip,
                    tool_name=self.name,
                    tags=["censys", "search"],
                    metadata={"ports": ports, "services_count": len(services)},
                )
            )
        return ToolResult(
            tool_name=self.name,
            success=True,
            stdout=json.dumps(data, indent=2)[:10_000],
            findings=findings,
            target=query,
        )

    async def _api_cert(self, client: httpx.AsyncClient, fingerprint: str) -> ToolResult:
        """Fetch certificate details."""
        resp = await client.get(f"{_CENSYS_V2}/certificates/{fingerprint}")
        if resp.status_code != 200:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error_message=f"Censys cert {resp.status_code}",
                target=fingerprint,
            )
        try:
            data = resp.json().get("result", {})
        except Exception:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error_message="Censys cert API returned non-JSON response",
                target=fingerprint,
            )
        names = data.get("names", [])
        findings = [
            Finding(
                title=f"Certificate: {', '.join(names[:5])}",
                description=f"Issuer: {data.get('issuer_dn', 'N/A')} | Valid: {data.get('validity', {}).get('start', '')} → {data.get('validity', {}).get('end', '')}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=fingerprint,
                tool_name=self.name,
                tags=["censys", "certificate"] + names[:10],
            )
        ]
        return ToolResult(
            tool_name=self.name,
            success=True,
            stdout=json.dumps(data, indent=2)[:10_000],
            findings=findings,
            target=fingerprint,
        )

    # ── parse helpers ──────────────────────────────────────────
    def _parse_host_result(self, data: dict, target: str) -> list[Finding]:
        findings: list[Finding] = []
        ip = data.get("ip", target)
        services = data.get("services", [])
        asn = data.get("autonomous_system", {})

        # Open services summary
        ports = sorted({s.get("port") for s in services if s.get("port")})
        if ports:
            findings.append(
                Finding(
                    title=f"Censys: {len(ports)} Open Ports on {ip}",
                    description=f"Ports: {', '.join(str(p) for p in ports)}",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.INFO,
                    confidence=90.0,
                    target=ip,
                    tool_name=self.name,
                    tags=["censys", "open_ports"],
                    metadata={"ports": list(ports)},
                )
            )

        # Per-service detail
        for svc in services[:20]:
            port = svc.get("port", 0)
            transport = svc.get("transport_protocol", "tcp")
            svc_name = svc.get("service_name", "unknown")
            software = svc.get("software", [])
            sw_str = ", ".join(
                f"{s.get('product', '')} {s.get('version', '')}".strip()
                for s in software[:3]
            ) if software else ""
            findings.append(
                Finding(
                    title=f"Service: {ip}:{port}/{transport} ({svc_name})",
                    description=sw_str or svc_name,
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.INFO,
                    confidence=85.0,
                    target=ip,
                    endpoint=f"{ip}:{port}",
                    tool_name=self.name,
                    tags=["censys", "service", f"port:{port}"],
                    metadata={
                        "port": port,
                        "transport": transport,
                        "service": svc_name,
                        "software": sw_str,
                    },
                )
            )

        # ASN / Organization
        if asn:
            findings.append(
                Finding(
                    title=f"ASN: AS{asn.get('asn', '?')} — {asn.get('name', '')}",
                    description=f"Organization: {asn.get('description', '')} | BGP Prefix: {asn.get('bgp_prefix', '')}",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.INFO,
                    confidence=90.0,
                    target=ip,
                    tool_name=self.name,
                    tags=["censys", "asn"],
                )
            )

        return findings

    # ── CLI fallback ───────────────────────────────────────────
    async def _cli_run(self, target: str, mode: str, options: dict) -> ToolResult:
        cmd = self.build_command(target, options)
        stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
        return ToolResult(
            tool_name=self.name,
            success=exit_code == 0,
            stdout=stdout,
            stderr=stderr,
            findings=self.parse_output(stdout, target),
            command=" ".join(cmd),
            target=target,
        )

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["censys", "search", target, "--index-type", "hosts"]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output.strip():
            return findings
        # CLI outputs JSON lines
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith(("[", "#")):
                continue
            try:
                rec = json.loads(line)
                ip = rec.get("ip", target)
                findings.append(
                    Finding(
                        title=f"Censys: {ip}",
                        description=json.dumps(rec)[:300],
                        vulnerability_type="information_disclosure",
                        severity=SeverityLevel.INFO,
                        confidence=80.0,
                        target=ip,
                        tool_name=self.name,
                        tags=["censys"],
                    )
                )
            except json.JSONDecodeError:
                continue
        return findings


__all__ = ["CensysWrapper"]
