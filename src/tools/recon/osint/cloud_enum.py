"""
WhiteHatHacker AI — Cloud Storage Enumerator (V7-T1-2)

Hedef domain'e ait açık bulut depolama kaynaklarını tarar:
  - AWS S3 bucket'ları
  - Azure Blob storage
  - GCP Cloud Storage
  - DigitalOcean Spaces

Permütasyon tabanlı isim oluşturma + HTTP probe.
"""

from __future__ import annotations

from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# ============================================================
# Permutation Templates
# ============================================================

_PERMUTATIONS: list[str] = [
    "{name}",
    "{name}-dev",
    "{name}-staging",
    "{name}-stage",
    "{name}-prod",
    "{name}-production",
    "{name}-test",
    "{name}-qa",
    "{name}-uat",
    "{name}-backup",
    "{name}-backups",
    "{name}-bak",
    "{name}-data",
    "{name}-assets",
    "{name}-static",
    "{name}-media",
    "{name}-uploads",
    "{name}-files",
    "{name}-public",
    "{name}-private",
    "{name}-internal",
    "{name}-logs",
    "{name}-db",
    "{name}-database",
    "{name}-archive",
    "{name}-cdn",
    "{name}-images",
    "{name}-img",
    "{name}-docs",
    "{name}-api",
    "{name}-web",
    "{name}-app",
    "{name}-config",
    "{name}-temp",
    "{name}-tmp",
    "dev-{name}",
    "staging-{name}",
    "prod-{name}",
    "backup-{name}",
]

# Provider URL templates:  (url_template, listing_indicator)
_PROVIDERS: dict[str, list[dict[str, str]]] = {
    "aws_s3": [
        {
            "url": "https://{bucket}.s3.amazonaws.com",
            "listing": "<ListBucketResult",
            "label": "AWS S3",
        },
        {
            "url": "https://s3.amazonaws.com/{bucket}",
            "listing": "<ListBucketResult",
            "label": "AWS S3 (path-style)",
        },
    ],
    "azure_blob": [
        {
            "url": "https://{bucket}.blob.core.windows.net",
            "listing": "<EnumerationResults",
            "label": "Azure Blob",
        },
    ],
    "gcp_storage": [
        {
            "url": "https://storage.googleapis.com/{bucket}",
            "listing": "<ListBucketResult",
            "label": "GCP Storage",
        },
    ],
    "digitalocean_spaces": [
        {
            "url": "https://{bucket}.nyc3.digitaloceanspaces.com",
            "listing": "<ListBucketResult",
            "label": "DO Spaces (nyc3)",
        },
        {
            "url": "https://{bucket}.ams3.digitaloceanspaces.com",
            "listing": "<ListBucketResult",
            "label": "DO Spaces (ams3)",
        },
    ],
}


# ============================================================
# Scanner
# ============================================================


class CloudStorageEnumerator(SecurityTool):
    """
    Cloud bucket/blob enumeration via HTTP probing.

    Works without any external binary — uses httpx.
    """

    name = "cloud_storage_enum"
    category = ToolCategory.RECON_OSINT
    description = "Cloud storage (S3, Azure Blob, GCP, DO Spaces) bucket enumeration"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        return True  # Pure Python, always available

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Domain'den base name çıkar  (example.com → example)
        base_names: list[str] = self._derive_names(domain, options)
        bucket_candidates = self._generate_bucket_names(base_names)

        max_buckets = {"stealth": 20, "balanced": 60, "aggressive": 150}.get(
            str(profile), 60,
        )
        bucket_candidates = bucket_candidates[:max_buckets]

        all_findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=8.0,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10),
        ) as client:
            for bucket_name in bucket_candidates:
                findings = await self._probe_bucket(client, domain, bucket_name)
                all_findings.extend(findings)

        return ToolResult(
            tool_name=self.name,
            success=True,
            findings=all_findings,
            raw_output=(
                f"Probed {len(bucket_candidates)} bucket names across "
                f"{len(_PROVIDERS)} providers, found {len(all_findings)} open/accessible"
            ),
        )

    async def _probe_bucket(
        self,
        client: httpx.AsyncClient,
        domain: str,
        bucket_name: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for provider_key, endpoints in _PROVIDERS.items():
            for ep in endpoints:
                url = ep["url"].format(bucket=bucket_name)
                try:
                    resp = await client.get(url)
                except httpx.HTTPError:
                    continue

                status = resp.status_code
                body = resp.text[:2000]
                listing_indicator = ep["listing"]

                if status == 200 and listing_indicator in body:
                    # Directory listing enabled — HIGH severity
                    findings.append(Finding(
                        title=f"Open Cloud Bucket: {ep['label']} — {bucket_name}",
                        description=(
                            f"The {ep['label']} bucket '{bucket_name}' is publicly "
                            f"accessible with directory listing enabled. This may "
                            f"expose sensitive data belonging to '{domain}'."
                        ),
                        vulnerability_type="information_disclosure",
                        severity=SeverityLevel.HIGH,
                        confidence=85.0,
                        target=domain,
                        endpoint=url,
                        parameter=bucket_name,
                        evidence=(
                            f"URL: {url}\nStatus: 200\n"
                            f"Body snippet: {body[:300]}"
                        ),
                        tool_name=self.name,
                        tags=["cloud", provider_key, "listing-enabled"],
                    ))
                elif status == 200:
                    # Accessible but no listing — MEDIUM
                    findings.append(Finding(
                        title=f"Accessible Cloud Bucket: {ep['label']} — {bucket_name}",
                        description=(
                            f"The {ep['label']} bucket '{bucket_name}' returned HTTP 200 "
                            f"without explicit listing. It may still contain accessible objects."
                        ),
                        vulnerability_type="information_disclosure",
                        severity=SeverityLevel.MEDIUM,
                        confidence=60.0,
                        target=domain,
                        endpoint=url,
                        parameter=bucket_name,
                        evidence=f"URL: {url}\nStatus: 200",
                        tool_name=self.name,
                        tags=["cloud", provider_key, "accessible"],
                    ))
                elif status == 403:
                    # Exists but private — INFO (useful for asset mapping)
                    logger.debug(f"Bucket exists (private): {url}")

        return findings

    def _derive_names(
        self, domain: str, options: dict[str, Any],
    ) -> list[str]:
        """Domain'den olası bucket base name'leri türet."""
        names: list[str] = []

        # extra names from options
        extra = options.get("extra_names", [])
        if isinstance(extra, list):
            names.extend(extra)

        parts = domain.split(".")
        # example.com → "example"
        if len(parts) >= 2:
            names.append(parts[-2])
        # sub.example.com → "sub", "sub-example", "sub.example"
        if len(parts) >= 3:
            names.append(parts[0])
            names.append(f"{parts[0]}-{parts[-2]}")
            names.append(f"{parts[0]}.{parts[-2]}")

        # Full domain with dots replaced
        names.append(domain.replace(".", "-"))

        return list(dict.fromkeys(names))  # dedup, preserve order

    def _generate_bucket_names(self, base_names: list[str]) -> list[str]:
        """Permutation template'leri ile bucket name listesi oluştur."""
        candidates: list[str] = []
        for base in base_names:
            for tmpl in _PERMUTATIONS:
                candidates.append(tmpl.format(name=base))
        return list(dict.fromkeys(candidates))

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []  # Findings generated in run()

    def build_command(self, target: str, options=None, profile=None) -> list[str]:
        return []  # No external binary

    def get_default_options(self, profile: ScanProfile) -> dict[str, Any]:
        return {}
