"""
WhiteHatHacker AI — Google Dorking Wrapper

Automated Google dork searches for sensitive information discovery.
Uses httpx to query Google or custom search API.
"""

from __future__ import annotations

import os
import json
import urllib.parse
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Google Custom Search JSON API
_GOOGLE_CSE = "https://www.googleapis.com/customsearch/v1"

# Pre-built dork categories for bug bounty
_DORK_TEMPLATES: dict[str, list[str]] = {
    "sensitive_files": [
        'site:{domain} filetype:sql',
        'site:{domain} filetype:env',
        'site:{domain} filetype:log',
        'site:{domain} filetype:bak',
        'site:{domain} filetype:conf',
        'site:{domain} filetype:cfg',
        'site:{domain} filetype:yml OR filetype:yaml',
        'site:{domain} filetype:xml -sitemap',
        'site:{domain} filetype:json "password" OR "secret" OR "token"',
    ],
    "sensitive_pages": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:api',
        'site:{domain} inurl:debug',
        'site:{domain} inurl:config',
        'site:{domain} inurl:phpinfo',
        'site:{domain} inurl:swagger',
        'site:{domain} inurl:graphql',
        'site:{domain} intitle:"index of"',
    ],
    "credentials": [
        'site:{domain} "password" filetype:txt',
        'site:{domain} "api_key" OR "apikey" OR "api-key"',
        'site:{domain} "secret_key" OR "secret" OR "token"',
        'site:{domain} "AWS_ACCESS_KEY"',
        'site:{domain} "BEGIN RSA PRIVATE KEY"',
    ],
    "errors": [
        'site:{domain} "SQL syntax" OR "mysql_fetch"',
        'site:{domain} "Fatal error" OR "Warning:" filetype:php',
        'site:{domain} "stack trace" OR "traceback"',
        'site:{domain} "Exception in" OR "Error 500"',
    ],
    "subdomains": [
        'site:*.{domain} -www',
    ],
}


class GoogleDorkingWrapper(SecurityTool):
    """
    Google Dorking — Automated sensitive information discovery via search.

    Uses Google Custom Search JSON API if GOOGLE_API_KEY + GOOGLE_CSE_ID
    are set, otherwise generates dork strings for manual use.
    """

    name = "google_dorking"
    category = ToolCategory.RECON_OSINT
    description = "Google dorking — sensitive files, pages, credentials discovery"
    binary_name = "curl"  # fallback CLI
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self._api_key = os.environ.get("GOOGLE_API_KEY", "")
        self._cse_id = os.environ.get("GOOGLE_CSE_ID", "")

    def is_available(self) -> bool:
        # Always available — at minimum, generates dork strings
        return True

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        categories = options.get("categories", list(_DORK_TEMPLATES.keys()))
        max_dorks = {"stealth": 5, "balanced": 15, "aggressive": 30}.get(profile, 15)

        # Build dork list
        dorks: list[str] = []
        for cat in categories:
            for tpl in _DORK_TEMPLATES.get(cat, []):
                dorks.append(tpl.format(domain=domain))
                if len(dorks) >= max_dorks:
                    break
            if len(dorks) >= max_dorks:
                break

        if self._api_key and self._cse_id:
            return await self._api_search(dorks, domain)
        return self._generate_dork_report(dorks, domain)

    async def _api_search(self, dorks: list[str], domain: str) -> ToolResult:
        findings: list[Finding] = []
        raw_results: list[dict] = []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for dork in dorks[:10]:  # API limit aware
                    resp = await client.get(
                        _GOOGLE_CSE,
                        params={"key": self._api_key, "cx": self._cse_id, "q": dork, "num": 5},
                    )
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    items = data.get("items", [])
                    raw_results.append({"dork": dork, "count": len(items)})

                    for item in items:
                        link = item.get("link", "")
                        title = item.get("title", "")
                        snippet = item.get("snippet", "")
                        severity = self._classify_severity(dork)
                        findings.append(Finding(
                            title=f"Google Dork: {title[:80]}",
                            description=f"Dork: {dork}\nURL: {link}\n{snippet}",
                            vulnerability_type="information_disclosure",
                            severity=severity,
                            confidence=60.0,
                            target=domain, endpoint=link,
                            tool_name=self.name,
                            tags=["google_dorking", self._classify_category(dork)],
                            metadata={"dork": dork, "url": link},
                        ))
        except Exception as exc:
            logger.warning(f"Google API search error: {exc}")

        return ToolResult(
            tool_name=self.name,
            success=True,
            stdout=json.dumps(raw_results, indent=2),
            findings=findings,
            target=domain,
        )

    def _generate_dork_report(self, dorks: list[str], domain: str) -> ToolResult:
        """No API key — generate dork strings as findings."""
        findings: list[Finding] = []
        output_lines: list[str] = []
        for dork in dorks:
            url = f"https://www.google.com/search?q={urllib.parse.quote_plus(dork)}"
            output_lines.append(f"{dork}\n  → {url}")
            findings.append(Finding(
                title=f"Dork: {dork[:60]}",
                description=f"Manual search URL: {url}",
                vulnerability_type="information_disclosure",
                severity=self._classify_severity(dork),
                confidence=30.0,  # Low — not verified
                target=domain, endpoint=url,
                tool_name=self.name,
                tags=["google_dorking", "manual_review"],
                metadata={"dork": dork, "search_url": url},
            ))
        return ToolResult(
            tool_name=self.name,
            success=True,
            stdout="\n".join(output_lines),
            findings=findings,
            target=domain,
        )

    @staticmethod
    def _classify_severity(dork: str) -> SeverityLevel:
        d = dork.lower()
        if any(k in d for k in ("password", "secret", "private_key", "aws_access")):
            return SeverityLevel.HIGH
        if any(k in d for k in ("sql", "error", "fatal", "traceback")):
            return SeverityLevel.MEDIUM
        if any(k in d for k in ("admin", "login", "debug", "phpinfo")):
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _classify_category(dork: str) -> str:
        d = dork.lower()
        if "filetype:" in d:
            return "sensitive_files"
        if any(k in d for k in ("password", "secret", "key", "token")):
            return "credentials"
        if any(k in d for k in ("error", "fatal", "trace", "sql syntax")):
            return "errors"
        return "sensitive_pages"

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return []

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["GoogleDorkingWrapper"]
