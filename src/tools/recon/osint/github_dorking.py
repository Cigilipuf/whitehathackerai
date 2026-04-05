"""
WhiteHatHacker AI — GitHub Dorking Wrapper

Automated GitHub search for leaked secrets, credentials, and
sensitive code related to target organization/domain.
Uses GitHub Search API via personal access token.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

_GITHUB_API = "https://api.github.com/search/code"

# Pre-built GitHub dork queries for bug bounty
_GITHUB_DORK_TEMPLATES: dict[str, list[str]] = {
    "api_keys": [
        '"{domain}" api_key',
        '"{domain}" apikey',
        '"{domain}" api_secret',
        '"{domain}" access_token',
        '"{domain}" secret_key',
        '"{domain}" client_secret',
    ],
    "credentials": [
        '"{domain}" password',
        '"{domain}" passwd',
        '"{domain}" credentials',
        '"{domain}" auth_token',
        '"{domain}" bearer',
    ],
    "aws": [
        '"{domain}" AKIA',
        '"{domain}" AWS_SECRET_ACCESS_KEY',
        '"{domain}" s3.amazonaws.com',
    ],
    "config_files": [
        '"{domain}" filename:.env',
        '"{domain}" filename:.npmrc',
        '"{domain}" filename:config.yml',
        '"{domain}" filename:settings.py',
        '"{domain}" filename:database.yml',
        '"{domain}" filename:wp-config.php',
        '"{domain}" filename:application.properties',
    ],
    "private_keys": [
        '"{domain}" BEGIN RSA PRIVATE KEY',
        '"{domain}" BEGIN DSA PRIVATE KEY',
        '"{domain}" BEGIN EC PRIVATE KEY',
        '"{domain}" BEGIN OPENSSH PRIVATE KEY',
    ],
    "internal_urls": [
        '"{domain}" internal',
        '"{domain}" staging',
        '"{domain}" dev.',
        '"{domain}" intranet',
    ],
}


class GitHubDorkingWrapper(SecurityTool):
    """
    GitHub Dorking — Search GitHub for leaked secrets/credentials.

    Requires: GITHUB_TOKEN in .env (personal access token).
    Without token, generates dork queries for manual search.
    """

    name = "github_dorking"
    category = ToolCategory.RECON_OSINT
    description = "GitHub dorking — leaked secrets, credentials, config files"
    binary_name = "gh"  # GitHub CLI (optional fallback)
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self._token = os.environ.get("GITHUB_TOKEN", "")

    def is_available(self) -> bool:
        return True  # Always available — at minimum generates dork strings

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        categories = options.get("categories", list(_GITHUB_DORK_TEMPLATES.keys()))
        max_dorks = {"stealth": 3, "balanced": 10, "aggressive": 20}.get(profile, 10)

        dorks: list[str] = []
        for cat in categories:
            for tpl in _GITHUB_DORK_TEMPLATES.get(cat, []):
                dorks.append(tpl.format(domain=domain))
                if len(dorks) >= max_dorks:
                    break
            if len(dorks) >= max_dorks:
                break

        if self._token:
            return await self._api_search(dorks, domain)
        return self._generate_dork_report(dorks, domain)

    async def _api_search(self, dorks: list[str], domain: str) -> ToolResult:
        findings: list[Finding] = []
        raw_results: list[dict] = []
        headers = {
            "Authorization": f"token {self._token}",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
                for dork in dorks[:8]:  # Rate limit: 10 requests/min for code search
                    resp = await client.get(_GITHUB_API, params={"q": dork, "per_page": 5})
                    if resp.status_code == 403:
                        logger.warning("GitHub API rate limit hit")
                        break
                    if resp.status_code != 200:
                        continue

                    data = resp.json()
                    total = data.get("total_count", 0)
                    raw_results.append({"dork": dork, "total_count": total})

                    for item in data.get("items", [])[:5]:
                        repo = item.get("repository", {}).get("full_name", "")
                        path = item.get("path", "")
                        html_url = item.get("html_url", "")
                        item.get("score", 0)

                        severity = self._classify_severity(dork, path)
                        findings.append(Finding(
                            title=f"GitHub Leak: {repo}/{path}",
                            description=f"Dork: {dork}\nRepo: {repo}\nFile: {path}\nURL: {html_url}",
                            vulnerability_type="information_disclosure",
                            severity=severity,
                            confidence=65.0,
                            target=domain,
                            endpoint=html_url,
                            tool_name=self.name,
                            tags=["github_dorking", self._classify_leak_type(dork)],
                            metadata={"dork": dork, "repo": repo, "path": path, "url": html_url},
                        ))

                    # GitHub code search rate limit: wait between requests
                    import asyncio
                    await asyncio.sleep(2)

        except Exception as exc:
            logger.warning(f"GitHub API error: {exc}")

        return ToolResult(
            tool_name=self.name,
            success=True,
            stdout=json.dumps(raw_results, indent=2),
            findings=findings,
            target=domain,
        )

    def _generate_dork_report(self, dorks: list[str], domain: str) -> ToolResult:
        findings: list[Finding] = []
        lines: list[str] = []
        for dork in dorks:
            import urllib.parse
            url = f"https://github.com/search?q={urllib.parse.quote_plus(dork)}&type=code"
            lines.append(f"{dork}\n  → {url}")
            findings.append(Finding(
                title=f"GitHub Dork: {dork[:60]}",
                description=f"Manual search URL: {url}",
                vulnerability_type="information_disclosure",
                severity=self._classify_severity(dork, ""),
                confidence=25.0,
                target=domain, endpoint=url,
                tool_name=self.name,
                tags=["github_dorking", "manual_review"],
                metadata={"dork": dork},
            ))
        return ToolResult(
            tool_name=self.name,
            success=True,
            stdout="\n".join(lines),
            findings=findings,
            target=domain,
        )

    @staticmethod
    def _classify_severity(dork: str, path: str) -> SeverityLevel:
        d = (dork + path).lower()
        if any(k in d for k in ("private key", "begin rsa", "begin dsa", "begin ec")):
            return SeverityLevel.CRITICAL
        if any(k in d for k in ("akia", "aws_secret", "password", "passwd", "credentials")):
            return SeverityLevel.HIGH
        if any(k in d for k in ("api_key", "secret", "token", "bearer", ".env")):
            return SeverityLevel.HIGH
        if any(k in d for k in ("config", "settings", "database")):
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @staticmethod
    def _classify_leak_type(dork: str) -> str:
        d = dork.lower()
        if any(k in d for k in ("private key", "begin rsa")):
            return "private_key"
        if any(k in d for k in ("akia", "aws")):
            return "aws_credentials"
        if any(k in d for k in ("password", "passwd", "credentials")):
            return "credentials"
        if "filename:" in d:
            return "config_file"
        if any(k in d for k in ("api_key", "secret", "token")):
            return "api_key"
        return "general"

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return []

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["GitHubDorkingWrapper"]
