"""
WhiteHatHacker AI — CSP Subdomain Discovery (V7-T2-2)

Content-Security-Policy header'larından domain ve subdomain çıkarır.
httpx_wrapper çıktısını zenginleştirmek için standalone kullanılabilir.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# CSP directives that may contain domain/URL values
_CSP_DIRECTIVES = (
    "default-src", "script-src", "style-src", "img-src", "connect-src",
    "font-src", "object-src", "media-src", "frame-src", "child-src",
    "worker-src", "frame-ancestors", "form-action", "base-uri",
    "report-uri", "report-to",
)

_DOMAIN_RE = re.compile(
    r"(?:\*\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})"
)


class CSPSubdomainDiscovery(SecurityTool):
    """
    Parse Content-Security-Policy headers to discover subdomains and
    third-party domains whitelisted by the target application.
    """

    name = "csp_subdomain_discovery"
    category = ToolCategory.RECON_WEB
    description = "Extract subdomains from CSP headers"
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
        urls: list[str] = options.get("urls", [])
        if not urls:
            urls = [target if target.startswith("http") else f"https://{target}"]

        all_domains: set[str] = set()
        csp_raw: list[str] = []

        for url in urls:
            csp = await self._fetch_csp(url)
            if csp:
                csp_raw.append(csp)
                domains = self._extract_domains(csp)
                all_domains.update(domains)

        # Classify into same-org vs third-party
        base = _base_domain(target)
        same_org = sorted(d for d in all_domains if base and d.endswith(base))
        third_party = sorted(d for d in all_domains if base and not d.endswith(base))

        findings: list[Finding] = []
        if same_org:
            findings.append(Finding(
                title=f"CSP: {len(same_org)} same-org domains discovered",
                severity=SeverityLevel.INFO,
                confidence=90,
                target=target,
                description="Domains from CSP (same org):\n" + "\n".join(f"  - {d}" for d in same_org),
                evidence={"domains": same_org},
                tool_name=self.name,
            ))
        if third_party:
            findings.append(Finding(
                title=f"CSP: {len(third_party)} third-party domains whitelisted",
                severity=SeverityLevel.INFO,
                confidence=85,
                target=target,
                description="Third-party CSP domains:\n" + "\n".join(f"  - {d}" for d in third_party[:30]),
                evidence={"domains": third_party},
                tool_name=self.name,
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output="\n".join(csp_raw),
            findings=findings,
            metadata={"same_org": same_org, "third_party": third_party},
        )

    async def _fetch_csp(self, url: str) -> str:
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.head(url)
                csp = resp.headers.get("content-security-policy", "")
                if not csp:
                    csp = resp.headers.get("content-security-policy-report-only", "")
                return csp
        except Exception as exc:
            logger.debug(f"[csp] Failed to fetch {url}: {exc}")
            return ""

    @staticmethod
    def _extract_domains(csp: str) -> set[str]:
        """Extract domain names from a CSP header value."""
        domains: set[str] = set()
        for match in _DOMAIN_RE.finditer(csp):
            domain = match.group(1).lower().strip(".")
            # Skip common non-interesting tokens
            if domain in ("self", "none", "unsafe-inline", "unsafe-eval"):
                continue
            if len(domain) > 4:  # skip very short fragments
                domains.add(domain)
        return domains

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        domains = self._extract_domains(raw_output)
        if not domains:
            return []
        return [Finding(
            title=f"CSP domains: {len(domains)} found",
            severity=SeverityLevel.INFO,
            confidence=85,
            target=target,
            description="\n".join(sorted(domains)),
            tool_name=self.name,
        )]

    def build_command(self, target: str, options: dict | None = None, profile: ScanProfile | None = None) -> list[str]:
        return []


def _base_domain(target: str) -> str:
    """Extract base domain (e.g., example.com from sub.example.com)."""
    host = target.split("://")[-1].split("/")[0].split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host
