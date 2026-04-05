"""
WhiteHatHacker AI — GitHub Secret Scanner (V7-T1-1)

GitHub API üzerinden hedef domain'e ait repo'larda ve
code search'te secret/credential sızıntısı taraması.
trufflehog/gitleaks regex pattern'ları ile çalışır.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# ============================================================
# Secret Patterns (trufflehog/gitleaks inspired)
# ============================================================

SECRET_PATTERNS: dict[str, dict[str, str | str]] = {
    # Cloud providers
    "aws_access_key": {
        "regex": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    "aws_secret_key": {
        "regex": r"(?i)(?:aws.?secret.?(?:access)?.?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "description": "AWS Secret Access Key",
    },
    "gcp_service_account": {
        "regex": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "description": "GCP Service Account Key (JSON)",
    },
    "azure_storage_key": {
        "regex": r"(?i)(?:AccountKey|azure.?storage.?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{88})['\"]?",
        "severity": "critical",
        "description": "Azure Storage Account Key",
    },
    # API keys
    "stripe_secret": {
        "regex": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "description": "Stripe Secret Key",
    },
    "stripe_publishable": {
        "regex": r"pk_live_[0-9a-zA-Z]{24,}",
        "severity": "medium",
        "description": "Stripe Publishable Key",
    },
    "twilio_api_key": {
        "regex": r"SK[0-9a-fA-F]{32}",
        "severity": "high",
        "description": "Twilio API Key",
    },
    "sendgrid_api_key": {
        "regex": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "high",
        "description": "SendGrid API Key",
    },
    "slack_token": {
        "regex": r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        "severity": "high",
        "description": "Slack Token",
    },
    "slack_webhook": {
        "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
        "severity": "high",
        "description": "Slack Webhook URL",
    },
    "github_token": {
        "regex": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "description": "GitHub Personal Access Token",
    },
    "google_api_key": {
        "regex": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "medium",
        "description": "Google API Key",
    },
    "firebase_key": {
        "regex": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "severity": "high",
        "description": "Firebase Cloud Messaging Key",
    },
    "mailgun_api_key": {
        "regex": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "description": "Mailgun API Key",
    },
    "heroku_api_key": {
        "regex": r"(?i)heroku.{0,20}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]",
        "severity": "high",
        "description": "Heroku API Key",
    },
    # Database
    "postgres_uri": {
        "regex": r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "severity": "critical",
        "description": "PostgreSQL Connection String",
    },
    "mysql_uri": {
        "regex": r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "severity": "critical",
        "description": "MySQL Connection String",
    },
    "mongodb_uri": {
        "regex": r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "severity": "critical",
        "description": "MongoDB Connection String",
    },
    "redis_uri": {
        "regex": r"redis://[^\s'\"]*:[^\s'\"]+@[^\s'\"]+",
        "severity": "high",
        "description": "Redis Connection String with Password",
    },
    # JWT/Auth
    "jwt_token": {
        "regex": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
        "description": "JSON Web Token",
    },
    "private_key_header": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private Key",
    },
    # Generic
    "generic_password": {
        "regex": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
        "severity": "medium",
        "description": "Hardcoded Password",
    },
    "generic_secret": {
        "regex": r'(?i)(?:secret|api_?key|token|auth)\s*[=:]\s*[\'"][A-Za-z0-9+/=_-]{20,}[\'"]',
        "severity": "medium",
        "description": "Generic Secret/API Key",
    },
}

# Compiled patterns
_COMPILED_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(info["regex"])
    for name, info in SECRET_PATTERNS.items()
}


# ============================================================
# Scanner
# ============================================================


class GitHubSecretScanner(SecurityTool):
    """
    GitHub Secret Scanner — Hedef domain'e ait GitHub code search
    üzerinden secret/credential sızıntısı tarar.

    Requires: GITHUB_TOKEN in .env (personal access token with 'repo' scope)
    """

    name = "github_secret_scanner"
    category = ToolCategory.RECON_OSINT
    description = "GitHub code search based secret/credential leak scanner"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self._token = os.environ.get("GITHUB_TOKEN", "")

    def is_available(self) -> bool:
        return bool(self._token)

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        if not self._token:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error="GITHUB_TOKEN not set. Cannot perform GitHub secret scanning.",
            )

        all_findings: list[Finding] = []
        search_queries = self._build_search_queries(domain, options)
        max_queries = {"stealth": 3, "balanced": 8, "aggressive": 15}.get(
            str(profile), 8,
        )

        async with httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github.v3+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        ) as client:
            for query in search_queries[:max_queries]:
                try:
                    findings = await self._search_code(client, domain, query)
                    all_findings.extend(findings)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 403:
                        logger.warning("GitHub API rate limit hit, stopping search")
                        break
                    logger.debug(f"GitHub search error: {exc}")
                except httpx.HTTPError as exc:
                    logger.debug(f"GitHub search HTTP error: {exc}")

        # Dedup by (pattern, repo, path)
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in all_findings:
            key = f"{f.vulnerability_type}|{f.endpoint}|{f.parameter}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return ToolResult(
            tool_name=self.name,
            success=True,
            findings=unique,
            raw_output=f"Searched {min(len(search_queries), max_queries)} queries, "
                       f"found {len(unique)} potential secret leaks",
        )

    async def _search_code(
        self,
        client: httpx.AsyncClient,
        domain: str,
        query: str,
    ) -> list[Finding]:
        """GitHub Code Search API ile arama yap."""
        findings: list[Finding] = []

        resp = await client.get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": 30},
        )
        resp.raise_for_status()
        data = resp.json()

        for item in data.get("items", []):
            repo_name = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")

            # Her sonuç için text_matches'ı veya dosya içeriğini kontrol et
            text_matches = item.get("text_matches", [])
            code_fragment = ""
            for tm in text_matches:
                code_fragment += tm.get("fragment", "") + "\n"

            if not code_fragment:
                code_fragment = f"[Match in {file_path}]"

            # Pattern matching
            for pat_name, pattern in _COMPILED_PATTERNS.items():
                if pattern.search(code_fragment):
                    info = SECRET_PATTERNS[pat_name]
                    sev_map = {
                        "critical": SeverityLevel.CRITICAL,
                        "high": SeverityLevel.HIGH,
                        "medium": SeverityLevel.MEDIUM,
                        "low": SeverityLevel.LOW,
                    }
                    findings.append(Finding(
                        title=f"GitHub Secret Leak: {info['description']}",
                        description=(
                            f"A potential {info['description']} was found in GitHub repository "
                            f"'{repo_name}' at path '{file_path}'. This secret may be associated "
                            f"with the target domain '{domain}'."
                        ),
                        vulnerability_type="information_disclosure",
                        severity=sev_map.get(info["severity"], SeverityLevel.MEDIUM),
                        confidence=65.0,
                        target=domain,
                        endpoint=repo_name,
                        parameter=file_path,
                        evidence=f"Pattern: {pat_name}\nURL: {html_url}\n"
                                 f"Fragment: {code_fragment[:500]}",
                        tool_name=self.name,
                        tags=["github", "secret-leak", pat_name],
                        references=[html_url],
                    ))

        return findings

    def _build_search_queries(
        self, domain: str, options: dict[str, Any],
    ) -> list[str]:
        """Domain için GitHub code search sorguları oluştur."""
        org_name = options.get("org_name", "")
        queries: list[str] = []

        # Domain-based searches
        secret_terms = [
            "password", "secret", "api_key", "apikey", "token",
            "credentials", "private_key", "access_key",
        ]
        for term in secret_terms:
            queries.append(f'"{domain}" {term}')

        # Config file searches
        config_terms = [
            ".env", "config.json", "settings.yaml", "secrets.yml",
            "credentials.json", "application.properties",
        ]
        for ct in config_terms:
            queries.append(f'"{domain}" filename:{ct}')

        # Org-specific searches
        if org_name:
            queries.extend([
                f"org:{org_name} password",
                f"org:{org_name} api_key OR secret_key OR access_key",
                f"org:{org_name} filename:.env",
                f"org:{org_name} filename:docker-compose",
            ])

        return queries

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []  # Findings are generated directly in run()

    def build_command(self, target: str, options=None, profile=None) -> list[str]:
        return []  # No external binary

    def get_default_options(self, profile: ScanProfile) -> dict[str, Any]:
        return {}
