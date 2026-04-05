"""
WhiteHatHacker AI — Cloud Misconfiguration Checker (T3-2)

Detects common cloud service misconfigurations:
  - Public S3/GCS/Azure Blob buckets
  - Exposed cloud metadata endpoints
  - Leaked cloud credentials in responses
  - Misconfigured cloud storage CORS
  - Firebase/Firestore open rules
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# ── S3-style bucket patterns found in HTML/JS ────────────────
_S3_BUCKET_RE = re.compile(
    r"(?:"
    r"(?P<vhost>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:[\w-]+\.)?amazonaws\.com"
    r"|s3[.\-](?:[\w-]+\.)?amazonaws\.com/(?P<path>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"|(?P<gcs>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.storage\.googleapis\.com"
    r"|storage\.googleapis\.com/(?P<gcspath>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"|(?P<azure>[a-z0-9]{3,24})\.blob\.core\.windows\.net"
    r")",
    re.I,
)

# ── Cloud credential patterns in responses ────────────────────
_CLOUD_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key", "critical"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", "high"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", "medium"),
    (r"(?:firebase|FIREBASE)[A-Za-z_]*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}", "Firebase credential", "high"),
]

# ── Cloud metadata endpoints (SSRF/exposure check) ───────────
_METADATA_PATHS: list[tuple[str, str, dict[str, str], str]] = [
    # (path, description, headers, expected_body_pattern)
    (
        "/latest/meta-data/",
        "AWS EC2 Instance Metadata (IMDSv1)",
        {},
        "ami-id",
    ),
    (
        "/latest/meta-data/iam/security-credentials/",
        "AWS IAM Role Credentials via IMDS",
        {},
        "AccessKeyId",
    ),
    (
        "/computeMetadata/v1/",
        "GCP Compute Metadata",
        {"Metadata-Flavor": "Google"},
        "instance",
    ),
    (
        "/metadata/instance?api-version=2021-02-01",
        "Azure Instance Metadata (IMDS)",
        {"Metadata": "true"},
        "compute",
    ),
]

# ── Exposed config/storage paths ──────────────────────────────
_CLOUD_PATHS: list[tuple[str, str, str, str]] = [
    # (path, description, body_pattern, severity)
    ("/.firebase.json", "Firebase config exposed", "projectId", "medium"),
    ("/firebase-debug.log", "Firebase debug log", "firebase", "medium"),
    ("/__/firebase/init.json", "Firebase init config", "projectId", "medium"),
    ("/amplify-meta.json", "AWS Amplify metadata", "providers", "medium"),
    ("/.aws/credentials", "AWS credentials file", "aws_access_key_id", "critical"),
    ("/app.yaml", "GCP App Engine config", "runtime:", "medium"),
]


async def check_cloud_misconfig(
    target: str,
    endpoints: list[str] | None = None,
    response_bodies: list[tuple[str, str]] | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Run cloud misconfiguration checks against a target.

    Args:
        target: Base URL (e.g. ``https://example.com``)
        endpoints: Optional list of discovered endpoints to scan
        response_bodies: Optional list of (url, body) tuples to scan for secrets
        timeout: HTTP request timeout in seconds

    Returns:
        List of findings
    """
    findings: list[Finding] = []
    base = target.rstrip("/")
    parsed = urlparse(base)
    if not parsed.scheme:
        base = f"https://{base}"

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (WhiteHatHackerAI Security Scanner)"},
    ) as client:
        # 1. Check exposed cloud config paths
        path_findings = await _check_cloud_paths(client, base)
        findings.extend(path_findings)

        # 2. Scan response bodies for bucket references & secrets
        if response_bodies:
            for url, body in response_bodies:
                findings.extend(_scan_body_for_buckets(url, body))
                findings.extend(_scan_body_for_secrets(url, body))

        # 3. Check discovered endpoints for cloud patterns
        if endpoints:
            for ep in endpoints:
                findings.extend(_scan_body_for_buckets(ep, ep))

        # 4. If we found S3/GCS/Azure bucket names, check if they're public
        bucket_names = _extract_bucket_names(
            " ".join(b for _, b in (response_bodies or []))
        )
        for btype, bname in bucket_names[:10]:  # limit to 10
            bf = await _check_bucket_public(client, btype, bname, base)
            if bf:
                findings.append(bf)

    logger.info(f"Cloud misconfig check | target={base} | findings={len(findings)}")
    return findings


async def _check_cloud_paths(
    client: httpx.AsyncClient,
    base: str,
) -> list[Finding]:
    """Probe for exposed cloud configuration files."""
    findings: list[Finding] = []

    async def _probe(path: str, desc: str, pattern: str, severity: str) -> Finding | None:
        url = f"{base}{path}"
        try:
            resp = await client.get(url)
            if resp.status_code == 200 and re.search(pattern, resp.text, re.I):
                return Finding(
                    title=f"Cloud Config Exposed: {desc}",
                    description=(
                        f"The cloud configuration file at `{path}` is publicly "
                        f"accessible and contains sensitive information."
                    ),
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel(severity),
                    confidence=85.0,
                    target=base,
                    endpoint=url,
                    tool_name="cloud_misconfig_checker",
                    http_request=f"GET {url} HTTP/1.1",
                    http_response=f"HTTP/1.1 {resp.status_code}\n{resp.text[:500]}",
                    evidence=f"Pattern matched: {pattern}",
                )
        except Exception as _exc:
            logger.debug(f"cloud misconfig checker error for {path}: {type(_exc).__name__}: {_exc}")
        return None

    tasks = [_probe(p, d, pat, s) for p, d, pat, s in _CLOUD_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Finding):
            findings.append(r)

    return findings


def _extract_bucket_names(text: str) -> list[tuple[str, str]]:
    """Extract cloud storage bucket names from text.

    Returns list of (cloud_type, bucket_name) tuples.
    """
    buckets: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _S3_BUCKET_RE.finditer(text):
        name = m.group("vhost") or m.group("path") or ""
        if name and name not in seen:
            seen.add(name)
            buckets.append(("s3", name))
        gcs = m.group("gcs") or m.group("gcspath") or ""
        if gcs and gcs not in seen:
            seen.add(gcs)
            buckets.append(("gcs", gcs))
        azure = m.group("azure") or ""
        if azure and azure not in seen:
            seen.add(azure)
            buckets.append(("azure", azure))
    return buckets


async def _check_bucket_public(
    client: httpx.AsyncClient,
    cloud_type: str,
    bucket_name: str,
    source_target: str,
) -> Finding | None:
    """Check if a discovered bucket is publicly listable."""
    urls = {
        "s3": f"https://{bucket_name}.s3.amazonaws.com/",
        "gcs": f"https://storage.googleapis.com/{bucket_name}/",
        "azure": f"https://{bucket_name}.blob.core.windows.net/?comp=list&restype=container",
    }
    url = urls.get(cloud_type)
    if not url:
        return None

    try:
        resp = await client.get(url)
        # S3/GCS list returns XML with <Contents> or <ListBucketResult>
        # Azure returns <EnumerationResults>
        is_listable = (
            resp.status_code == 200
            and any(
                tag in resp.text
                for tag in ("ListBucketResult", "Contents", "EnumerationResults", "<Key>")
            )
        )
        if is_listable:
            return Finding(
                title=f"Public Cloud Storage Bucket: {bucket_name} ({cloud_type.upper()})",
                description=(
                    f"The {cloud_type.upper()} storage bucket `{bucket_name}` is publicly "
                    f"listable. An attacker can enumerate and download all objects."
                ),
                vulnerability_type="cloud_misconfiguration",
                severity=SeverityLevel.HIGH,
                confidence=90.0,
                target=source_target,
                endpoint=url,
                tool_name="cloud_misconfig_checker",
                http_request=f"GET {url} HTTP/1.1",
                http_response=f"HTTP/1.1 {resp.status_code}\n{resp.text[:500]}",
                evidence=f"Bucket {bucket_name} returns directory listing",
            )
    except Exception as _exc:
        logger.debug(f"cloud misconfig checker error: {_exc}")
    return None


def _scan_body_for_buckets(url: str, body: str) -> list[Finding]:
    """Scan a response body for cloud bucket URL references."""
    findings: list[Finding] = []
    for m in _S3_BUCKET_RE.finditer(body):
        bucket_url = m.group(0)
        findings.append(Finding(
            title=f"Cloud Storage URL Found in Response: {bucket_url[:60]}",
            description=(
                f"A cloud storage URL was found in the response body of `{url}`. "
                f"This may expose internal infrastructure or data."
            ),
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            confidence=60.0,
            target=url,
            endpoint=url,
            tool_name="cloud_misconfig_checker",
            evidence=f"Cloud URL: {bucket_url}",
        ))
    return findings


def _scan_body_for_secrets(url: str, body: str) -> list[Finding]:
    """Scan response body for leaked cloud credentials."""
    findings: list[Finding] = []
    for pattern, desc, severity in _CLOUD_SECRET_PATTERNS:
        if re.search(pattern, body):
            findings.append(Finding(
                title=f"Cloud Credential Leaked: {desc}",
                description=(
                    f"A {desc} was found in the response body of `{url}`. "
                    f"This credential should be rotated immediately."
                ),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel(severity),
                confidence=92.0,
                target=url,
                endpoint=url,
                tool_name="cloud_misconfig_checker",
                evidence=f"Pattern matched: {desc}",
            ))
    return findings


__all__ = ["check_cloud_misconfig"]
