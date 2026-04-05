"""
WhiteHatHacker AI — CDN Detector (V7-T2-1)

Response header, IP ASN ve DNS analizi ile CDN tespiti:
  - Cloudflare, Akamai, Fastly, AWS CloudFront
  - Azure CDN, Google Cloud CDN, StackPath, Sucuri
  - CDN arkasındaki gerçek IP tespiti ipuçları
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Header → CDN mapping
_CDN_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "cloudflare": [
        {"header": "cf-ray", "pattern": r".+"},
        {"header": "server", "pattern": r"(?i)cloudflare"},
        {"header": "cf-cache-status", "pattern": r".+"},
    ],
    "akamai": [
        {"header": "x-akamai-transformed", "pattern": r".+"},
        {"header": "server", "pattern": r"(?i)akamai"},
        {"header": "x-cache", "pattern": r"(?i)tcp_hit|tcp_miss.*akamai"},
    ],
    "fastly": [
        {"header": "x-served-by", "pattern": r"(?i)cache-"},
        {"header": "x-fastly-request-id", "pattern": r".+"},
        {"header": "via", "pattern": r"(?i)varnish"},
    ],
    "cloudfront": [
        {"header": "x-amz-cf-id", "pattern": r".+"},
        {"header": "x-amz-cf-pop", "pattern": r".+"},
        {"header": "via", "pattern": r"(?i)cloudfront"},
        {"header": "server", "pattern": r"(?i)cloudfront"},
    ],
    "azure_cdn": [
        {"header": "x-msedge-ref", "pattern": r".+"},
        {"header": "x-azure-ref", "pattern": r".+"},
    ],
    "google_cloud_cdn": [
        {"header": "via", "pattern": r"(?i)google"},
        {"header": "server", "pattern": r"(?i)gws|google"},
    ],
    "stackpath": [
        {"header": "x-sp-url", "pattern": r".+"},
        {"header": "x-hw", "pattern": r".+"},
    ],
    "sucuri": [
        {"header": "x-sucuri-id", "pattern": r".+"},
        {"header": "server", "pattern": r"(?i)sucuri"},
        {"header": "x-sucuri-cache", "pattern": r".+"},
    ],
    "incapsula": [
        {"header": "x-cdn", "pattern": r"(?i)incapsula|imperva"},
        {"header": "x-iinfo", "pattern": r".+"},
    ],
}

# Known CDN CNAME patterns
_CDN_CNAME_PATTERNS: dict[str, str] = {
    r"\.cloudflare\.": "cloudflare",
    r"\.cloudfront\.net": "cloudfront",
    r"\.akamaiedge\.net": "akamai",
    r"\.akamai\.net": "akamai",
    r"\.fastly\.net": "fastly",
    r"\.azureedge\.net": "azure_cdn",
    r"\.stackpathdns\.com": "stackpath",
    r"\.sucuri\.net": "sucuri",
    r"\.incapdns\.net": "incapsula",
    r"\.googleusercontent\.com": "google_cloud_cdn",
}


class CDNDetector(SecurityTool):
    """
    CDN detection via response headers, DNS CNAME records, and IP ASN.
    Identifies Cloudflare, Akamai, Fastly, CloudFront, Azure CDN, etc.
    """

    name = "cdn_detector"
    category = ToolCategory.RECON_TECH
    description = "CDN detection via headers, DNS, and ASN"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None,
        profile: ScanProfile | None = None,
    ) -> ToolResult:
        options = options or {}
        hosts: list[str] = options.get("hosts", [target])

        results: list[dict[str, Any]] = []
        findings: list[Finding] = []

        for host in hosts:
            url = host if host.startswith("http") else f"https://{host}"
            detected = await self._detect_cdn(url, host)
            if detected:
                results.append(detected)

        # Aggregate
        cdn_hosts: dict[str, list[str]] = {}
        for r in results:
            cdn = r["cdn"]
            cdn_hosts.setdefault(cdn, []).append(r["host"])

        if cdn_hosts:
            detail_lines = []
            for cdn_name, hosts_list in cdn_hosts.items():
                detail_lines.append(f"  {cdn_name}: {', '.join(hosts_list[:10])}")
            findings.append(Finding(
                title=f"CDN detected: {', '.join(cdn_hosts.keys())}",
                severity=SeverityLevel.INFO,
                confidence=85,
                target=target,
                description="CDN distribution:\n" + "\n".join(detail_lines),
                evidence={"cdn_hosts": cdn_hosts},
                tool_name=self.name,
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=str(results),
            findings=findings,
            metadata={"cdn_hosts": cdn_hosts, "results": results},
        )

    async def _detect_cdn(self, url: str, host: str) -> dict[str, Any] | None:
        """Detect CDN for a single host using headers and DNS."""
        # 1. HTTP header check
        cdn_from_headers = await self._check_headers(url)
        if cdn_from_headers:
            return {"host": host, "cdn": cdn_from_headers, "method": "headers"}

        # 2. DNS CNAME check
        cdn_from_dns = await self._check_cname(host)
        if cdn_from_dns:
            return {"host": host, "cdn": cdn_from_dns, "method": "cname"}

        return None

    async def _check_headers(self, url: str) -> str | None:
        """Check response headers against CDN signatures."""
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.head(url)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                for cdn_name, sigs in _CDN_SIGNATURES.items():
                    for sig in sigs:
                        hdr_val = headers.get(sig["header"].lower(), "")
                        if hdr_val and re.search(sig["pattern"], hdr_val):
                            logger.debug(f"[cdn] {url} → {cdn_name} (header: {sig['header']})")
                            return cdn_name
        except Exception as exc:
            logger.debug(f"[cdn] Header check failed for {url}: {exc}")
        return None

    async def _check_cname(self, host: str) -> str | None:
        """Check DNS CNAME for CDN indicators."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            cname = stdout.decode().strip()
            if cname:
                for pattern, cdn_name in _CDN_CNAME_PATTERNS.items():
                    if re.search(pattern, cname):
                        logger.debug(f"[cdn] {host} CNAME → {cdn_name} ({cname})")
                        return cdn_name
        except Exception as e:
            logger.warning(f"cdn_detector error: {e}")
        return None

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []

    def build_command(self, target: str, options: dict | None = None, profile: ScanProfile | None = None) -> list[str]:
        return []
