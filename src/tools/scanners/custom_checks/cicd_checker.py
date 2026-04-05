"""
WhiteHatHacker AI — CI/CD Security Checker (P4-7)

Deep analysis of CI/CD pipeline security exposures:
  - Jenkins/GitLab/GitHub Actions configuration exposure
  - Build artifact and log leaks
  - Dependency confusion detection (package.json, requirements.txt analysis)
  - Webhook endpoint discovery and validation bypass
  - Pipeline secret exposure (env vars, tokens in build logs)
  - Build system metadata leak (versions, plugins, users)

References:
  - CWE-200: Exposure of Sensitive Information
  - CWE-829: Inclusion of Functionality from Untrusted Control Sphere
  - OWASP CI/CD Top 10: https://owasp.org/www-project-top-10-ci-cd-security-risks/
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urljoin

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel
from src.utils.response_validator import ResponseValidator

# ── CI/CD Endpoint Probes ─────────────────────────────────────

# (path, description, severity, platform)
_CICD_ENDPOINTS: list[tuple[str, str, str, str]] = [
    # ── Jenkins ──
    ("/script", "Jenkins Script Console (RCE)", "critical", "jenkins"),
    ("/manage", "Jenkins Management Console", "high", "jenkins"),
    ("/job/", "Jenkins Job listing", "medium", "jenkins"),
    ("/api/json", "Jenkins API root (JSON)", "medium", "jenkins"),
    ("/api/json?tree=jobs[name,color]", "Jenkins job status", "medium", "jenkins"),
    ("/asynchPeople/", "Jenkins people/user listing", "medium", "jenkins"),
    ("/computer/", "Jenkins node/agent listing", "medium", "jenkins"),
    ("/credentials/", "Jenkins credential store", "critical", "jenkins"),
    ("/configureSecurity/", "Jenkins security config", "high", "jenkins"),
    ("/pluginManager/installed", "Jenkins installed plugins", "low", "jenkins"),
    ("/systemInfo", "Jenkins system info (JVM, OS, env)", "medium", "jenkins"),
    ("/log/", "Jenkins system log", "medium", "jenkins"),
    ("/env", "Jenkins environment variables", "high", "jenkins"),

    # ── GitLab ──
    ("/api/v4/projects?per_page=20", "GitLab API project listing", "high", "gitlab"),
    ("/api/v4/users?per_page=20", "GitLab API user listing", "medium", "gitlab"),
    ("/api/v4/groups", "GitLab API group listing", "medium", "gitlab"),
    ("/-/graphql", "GitLab GraphQL API", "medium", "gitlab"),
    ("/api/v4/application/appearance", "GitLab instance info", "low", "gitlab"),
    ("/api/v4/version", "GitLab version disclosure", "low", "gitlab"),
    ("/explore/projects", "GitLab public project explorer", "low", "gitlab"),
    ("/users/sign_in", "GitLab login page (version in HTML)", "info", "gitlab"),

    # ── GitHub ──
    ("/.github/workflows/", "GitHub Actions workflow directory", "low", "github"),
    ("/.github/CODEOWNERS", "GitHub CODEOWNERS file", "info", "github"),

    # ── Gitea / Forgejo ──
    ("/api/v1/repos/search", "Gitea/Forgejo repo search", "medium", "gitea"),
    ("/api/v1/users/search", "Gitea/Forgejo user search", "medium", "gitea"),
    ("/api/v1/admin/orgs", "Gitea admin org listing", "high", "gitea"),

    # ── CI Runners / Agents ──
    ("/runners", "CI runner listing", "medium", "generic"),
    ("/api/v4/runners/all", "GitLab runners (admin)", "high", "gitlab"),

    # ── Build Artifacts ──
    ("/artifacts/", "Build artifact directory", "medium", "generic"),
    ("/builds/", "Build listing", "medium", "generic"),
    ("/pipeline/", "Pipeline listing", "medium", "generic"),
    ("/lastSuccessfulBuild/artifact/", "Jenkins last build artifact", "medium", "jenkins"),
    ("/lastBuild/consoleText", "Jenkins last build console log", "high", "jenkins"),

    # ── Webhooks ──
    ("/generic-webhook-trigger/invoke", "Jenkins generic webhook trigger", "high", "jenkins"),
    ("/github-webhook/", "Jenkins GitHub webhook endpoint", "medium", "jenkins"),
    ("/gitlab/build_now", "Jenkins GitLab webhook build trigger", "high", "jenkins"),

    # ── Other CI Systems ──
    ("/api/v1/pipelines", "Generic pipeline API", "medium", "generic"),
    ("/api/v2/pipeline", "CircleCI-style pipeline API", "medium", "generic"),
    ("/.drone.yml", "Drone CI config file", "medium", "drone"),
    ("/.travis.yml", "Travis CI config file", "low", "travis"),
    ("/.circleci/config.yml", "CircleCI config file", "low", "circleci"),
    ("/Jenkinsfile", "Jenkins pipeline definition", "medium", "jenkins"),
    ("/azure-pipelines.yml", "Azure Pipelines config", "low", "azure"),
    ("/bitbucket-pipelines.yml", "Bitbucket Pipelines config", "low", "bitbucket"),
]

# Signatures confirming genuine CI/CD exposure (not generic 404/redirect)
_CICD_SIGNATURES: dict[str, list[str]] = {
    "jenkins": ["hudson", "jenkins", "_class", "crumbRequestField",
                "numExecutors", "useSecurity", "hudson.model"],
    "gitlab": ["gitlab", "name_with_namespace", "visibility",
               "default_branch", "created_at", "web_url"],
    "gitea": ["clone_url", "ssh_url", "full_name", "owner"],
    "github": ["on:", "jobs:", "runs-on:", "steps:", "uses:"],
    "generic": ["pipeline", "build", "artifact", "runner"],
    "drone": ["kind:", "steps:", "image:"],
    "travis": ["language:", "script:", "before_install:"],
    "circleci": ["version:", "jobs:", "workflows:"],
    "azure": ["trigger:", "pool:", "vmImage:"],
    "bitbucket": ["pipelines:", "step:", "image:"],
}

# Patterns indicating secrets in build logs/config
_SECRET_LEAK_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(api[_-]?key|api[_-]?token|api[_-]?secret)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(secret[_-]?key|private[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(aws[_-]?secret|aws[_-]?access)\s*[:=]\s*\S+"),
    re.compile(r"(?i)ghp_[a-zA-Z0-9]{36}"),  # GitHub PAT
    re.compile(r"(?i)glpat-[a-zA-Z0-9\-_]{20,}"),  # GitLab PAT
    re.compile(r"(?i)AKIA[A-Z0-9]{16}"),  # AWS Access Key
    re.compile(r"(?i)(npm_|NPM_)[a-zA-Z0-9]{36}"),  # npm token
    re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+"),  # JWT
]

# Dependency confusion — internal package indicators
_INTERNAL_PKG_PATTERNS: list[re.Pattern] = [
    re.compile(r'"@[a-zA-Z0-9_-]+/'),  # Scoped npm packages
    re.compile(r"--index-url\s+https?://(?!pypi\.org)"),  # Custom PyPI
    re.compile(r"--extra-index-url\s+https?://"),  # Extra PyPI index
    re.compile(r"registry\s*=\s*https?://(?!registry\.npmjs\.org)"),  # Custom npm registry
]

# --- v4.0: Known CI/CD SaaS domains — endpoints for the SAME platform are expected ---
_KNOWN_CICD_DOMAINS: dict[str, list[str]] = {
    "gitlab": ["gitlab.com", "gitlab.io"],
    "github": ["github.com", "github.io"],
    "gitea": ["gitea.com", "codeberg.org"],
    "bitbucket": ["bitbucket.org"],
    "circleci": ["circleci.com"],
    "travis": ["travis-ci.com", "travis-ci.org"],
    "azure": ["dev.azure.com", "visualstudio.com"],
}


def _is_self_hosted_platform(target_url: str, platform: str) -> bool:
    """Check if the target IS the CI/CD platform itself (not a separate system running it)."""
    from urllib.parse import urlparse
    host = urlparse(target_url).netloc.lower().split(":")[0]  # strip port
    for domain in _KNOWN_CICD_DOMAINS.get(platform, []):
        if host == domain or host.endswith("." + domain):
            return True
    return False


# ── Main Scanner ──────────────────────────────────────────────

async def check_cicd_security(
    targets: list[str],
    max_targets: int = 5,
    max_concurrent: int = 3,
    timeout: float = 10.0,
    extra_headers: dict[str, str] | None = None,
    technologies: list[str] | None = None,
) -> list[Finding]:
    """
    Deep CI/CD security check.

    Args:
        targets: Base URLs to probe.
        max_targets: Max targets to test.
        max_concurrent: Concurrency limit.
        timeout: Per-request timeout.
        extra_headers: Auth headers.
        technologies: Detected tech stack for filtering.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)
    test_targets = targets[:max_targets]

    # Filter endpoints by detected technologies
    active_endpoints = _filter_cicd_endpoints(_CICD_ENDPOINTS, technologies)
    if len(active_endpoints) < len(_CICD_ENDPOINTS):
        logger.debug(
            f"CI/CD checker: tech filter {len(_CICD_ENDPOINTS)} → {len(active_endpoints)}"
        )

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(timeout, connect=10)) as client:
        for base_url in test_targets:
            base_url = base_url.rstrip("/")
            if not base_url.startswith("http"):
                base_url = f"https://{base_url}"

            # Phase 1: Endpoint probing
            tasks = [
                _probe_cicd_endpoint(
                    client, sem, base_url, path, desc, sev, platform,
                    extra_headers, timeout,
                )
                for path, desc, sev, platform in active_endpoints
            ]
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout + 30,
                )
            except asyncio.TimeoutError:
                logger.warning("CI/CD endpoint probing timed out")
                results = []
            for r in results:
                if isinstance(r, Finding):
                    findings.append(r)

            # Phase 2: Dependency confusion checks on discovered files
            findings.extend(
                await _check_dependency_confusion(client, sem, base_url, timeout)
            )

            # Phase 3: Build log secret scan (if Jenkins detected)
            findings.extend(
                await _scan_build_logs(client, sem, base_url, extra_headers, timeout)
            )

    if findings:
        logger.info(f"CI/CD checker: {len(findings)} findings")

    return findings


# ── Endpoint Probing ──────────────────────────────────────────

async def _probe_cicd_endpoint(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    base_url: str,
    path: str,
    description: str,
    severity: str,
    platform: str,
    extra_headers: dict[str, str] | None,
    timeout: float,
) -> Finding | None:
    """Probe a single CI/CD endpoint."""
    # v4.0: Skip if target IS the platform itself (e.g., scanning gitlab.com for gitlab endpoints)
    if _is_self_hosted_platform(base_url, platform):
        logger.debug(f"CI/CD probe skipped — target is a {platform} platform itself: {base_url}")
        return None

    async with sem:
        url = urljoin(base_url + "/", path.lstrip("/"))
        headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (compatible; security-scanner/1.0)",
        }
        if extra_headers:
            headers.update(extra_headers)

        try:
            resp = await client.get(url, headers=headers, timeout=timeout,
                                    follow_redirects=False)

            # ── ResponseValidator: reject redirects, WAF blocks, error pages ──
            _rv = ResponseValidator()
            vr = _rv.validate(
                resp.status_code,
                dict(resp.headers),
                resp.text[:4000],
                expected_content_type="json" if platform in ("jenkins", "gitlab", "github", "gitea") else None,
                url=url,
            )
            if not vr.is_valid:
                logger.debug(f"CI/CD probe {url}: rejected — {vr.rejection_reason}")
                return None

            body = resp.text[:3000]
            sigs = _CICD_SIGNATURES.get(platform, [])
            matched = [s for s in sigs if s.lower() in body.lower()]

            # Require at least one signature match for non-config files
            ct = resp.headers.get("content-type", "")
            if not matched:
                if "json" not in ct and "yaml" not in ct and "text/plain" not in ct:
                    return None

            # Check for secrets in response
            secrets_found = _find_secrets_in_text(body)

            sev_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO,
            }
            confidence = (80.0 if matched else 50.0) + vr.confidence_modifier
            confidence = max(10.0, confidence)
            actual_sev = sev_map.get(severity, SeverityLevel.MEDIUM)

            # Escalate if secrets found
            if secrets_found and actual_sev < SeverityLevel.HIGH:
                actual_sev = SeverityLevel.HIGH
                confidence = max(confidence, 75.0)

            return Finding(
                title=f"CI/CD Exposure: {description}",
                severity=actual_sev,
                confidence=confidence,
                endpoint=url,
                description=(
                    f"Detected exposed CI/CD infrastructure at {url}.\n"
                    f"Platform: {platform}\n"
                    f"HTTP {resp.status_code} response.\n"
                    f"Signatures matched: {', '.join(matched) if matched else 'none (content-type based)'}"
                    + (f"\n\n⚠️  SECRETS DETECTED in response: {len(secrets_found)} pattern(s)"
                       if secrets_found else "")
                ),
                evidence=(
                    f"HTTP {resp.status_code} | Signatures: {matched}"
                    + (f" | Secrets: {[s[:60] for s in secrets_found[:3]]}" if secrets_found else "")
                ),
                remediation=(
                    "Restrict access to CI/CD infrastructure. Use authentication, "
                    "network policies, and IP allowlists. Never expose Jenkins, "
                    "GitLab, or build logs to the public internet. Rotate any "
                    "exposed credentials immediately."
                ),
                references=[
                    "CWE-200: Information Exposure",
                    "CWE-284: Improper Access Control",
                    "OWASP CI/CD Top 10",
                ],
                tool_name="cicd_checker",
                vulnerability_type="cicd_exposure",
                tags=["cicd", platform],
                metadata={
                    "platform": platform,
                    "secrets_found": len(secrets_found) if secrets_found else 0,
                },
            )

        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout):
            return None
        except Exception as e:
            logger.debug(f"CI/CD probe error for {url}: {e}")
            return None


# ── Dependency Confusion Detection ────────────────────────────

async def _check_dependency_confusion(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    base_url: str,
    timeout: float,
) -> list[Finding]:
    """Check for dependency confusion indicators in exposed dependency files."""
    findings: list[Finding] = []

    dep_files = [
        ("/package.json", "npm"),
        ("/package-lock.json", "npm"),
        ("/requirements.txt", "pip"),
        ("/Pipfile", "pip"),
        ("/Gemfile", "ruby"),
        ("/go.mod", "go"),
        ("/composer.json", "composer"),
        ("/.npmrc", "npm"),
        ("/.pypirc", "pip"),
        ("/yarn.lock", "yarn"),
    ]

    for path, ecosystem in dep_files:
        async with sem:
            try:
                url = urljoin(base_url + "/", path.lstrip("/"))
                resp = await client.get(url, timeout=timeout, follow_redirects=False)
                if resp.status_code != 200:
                    continue

                body = resp.text[:5000]

                # v4.0: ResponseValidator — reject WAF/SPA/error pages
                _rv = ResponseValidator()
                _dep_vr = _rv.validate(
                    resp.status_code, dict(resp.headers), body, url=url,
                )
                if not _dep_vr.is_valid:
                    continue

                # Check for internal package patterns
                internal_indicators: list[str] = []
                for pattern in _INTERNAL_PKG_PATTERNS:
                    matches = pattern.findall(body)
                    internal_indicators.extend(matches[:3])

                # Check for exposed credentials in config
                secrets = _find_secrets_in_text(body)

                if internal_indicators:
                    findings.append(Finding(
                        title=f"Dependency Confusion Risk: {path} Exposed",
                        description=(
                            f"The dependency file at {url} is publicly accessible "
                            f"and references internal/private packages or custom registries. "
                            f"This may enable dependency confusion attacks.\n"
                            f"Indicators: {', '.join(internal_indicators[:5])}"
                        ),
                        vulnerability_type="dependency_confusion",
                        severity=SeverityLevel.HIGH,
                        confidence=65.0,
                        endpoint=url,
                        evidence=f"Internal package indicators: {internal_indicators[:5]}",
                        tool_name="cicd_checker",
                        cwe_id="CWE-829",
                        tags=["cicd", "dependency-confusion", ecosystem],
                        metadata={"ecosystem": ecosystem, "indicators": internal_indicators[:5]},
                    ))

                if secrets:
                    findings.append(Finding(
                        title=f"Secrets in Dependency Config: {path}",
                        description=(
                            f"The file {url} contains potential secrets/credentials. "
                            f"Found {len(secrets)} secret pattern(s)."
                        ),
                        vulnerability_type="credential_exposure",
                        severity=SeverityLevel.HIGH,
                        confidence=70.0,
                        endpoint=url,
                        evidence=f"Secret patterns: {[s[:50] + '...' for s in secrets[:3]]}",
                        tool_name="cicd_checker",
                        cwe_id="CWE-798",
                        tags=["cicd", "secrets", ecosystem],
                    ))

            except Exception as e:
                logger.warning(f"cicd_checker error: {e}")

    return findings


# ── Build Log Secret Scanning ─────────────────────────────────

async def _scan_build_logs(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    base_url: str,
    extra_headers: dict[str, str] | None,
    timeout: float,
) -> list[Finding]:
    """Scan exposed build logs for leaked secrets."""
    findings: list[Finding] = []

    log_paths = [
        "/lastBuild/consoleText",
        "/lastSuccessfulBuild/consoleText",
        "/lastFailedBuild/consoleText",
        "/1/consoleText",
        "/2/consoleText",
    ]

    headers: dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (compatible; security-scanner/1.0)",
    }
    if extra_headers:
        headers.update(extra_headers)

    for path in log_paths:
        async with sem:
            try:
                url = urljoin(base_url + "/", path.lstrip("/"))
                resp = await client.get(url, headers=headers, timeout=timeout,
                                        follow_redirects=False)
                if resp.status_code != 200:
                    continue

                body = resp.text[:10000]
                secrets = _find_secrets_in_text(body)

                if secrets:
                    findings.append(Finding(
                        title=f"Secrets Leaked in Build Log: {path}",
                        description=(
                            f"Build log at {url} contains {len(secrets)} potential secret(s). "
                            f"Build logs often contain environment variables, API keys, "
                            f"and tokens that were logged during the build process."
                        ),
                        vulnerability_type="credential_exposure",
                        severity=SeverityLevel.HIGH,
                        confidence=75.0,
                        endpoint=url,
                        evidence=f"Secrets found: {[s[:50] + '...' for s in secrets[:3]]}",
                        tool_name="cicd_checker",
                        cwe_id="CWE-532",
                        tags=["cicd", "build-log", "secrets"],
                        metadata={"secrets_count": len(secrets), "log_path": path},
                    ))
                    break  # One log finding is enough

            except Exception as e:
                logger.warning(f"cicd_checker error: {e}")

    return findings


# ── Helpers ───────────────────────────────────────────────────

def _find_secrets_in_text(text: str) -> list[str]:
    """Find potential secrets in text using regex patterns."""
    found: list[str] = []
    for pattern in _SECRET_LEAK_PATTERNS:
        matches = pattern.findall(text)
        for m in matches:
            val = m if isinstance(m, str) else m[0] if m else ""
            if val and len(val) > 4:
                found.append(val)
    return found[:10]


def _filter_cicd_endpoints(
    endpoints: list[tuple[str, str, str, str]],
    technologies: list[str] | None,
) -> list[tuple[str, str, str, str]]:
    """Filter CI/CD endpoints based on detected technologies.

    Platform-specific endpoints are only probed when the platform is detected.
    Generic endpoints are always probed.
    """
    if not technologies:
        return endpoints

    tech_lower = {t.lower() for t in technologies}

    # Map platforms to tech detection keywords
    platform_keywords: dict[str, list[str]] = {
        "jenkins": ["jenkins", "hudson"],
        "gitlab": ["gitlab"],
        "github": ["github"],
        "gitea": ["gitea", "forgejo"],
        "drone": ["drone"],
        "travis": ["travis"],
        "circleci": ["circleci", "circle"],
        "azure": ["azure", "devops"],
        "bitbucket": ["bitbucket"],
    }

    def _platform_allowed(platform: str) -> bool:
        keywords = platform_keywords.get(platform)
        if keywords is None:
            return True  # generic → always probe
        return any(kw in t for kw in keywords for t in tech_lower)

    return [ep for ep in endpoints if _platform_allowed(ep[3])]


__all__ = ["check_cicd_security"]
