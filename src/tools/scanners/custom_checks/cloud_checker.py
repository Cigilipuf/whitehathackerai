"""
WhiteHatHacker AI — Cloud-Native Security Checker (V11-T2-3)

Detects exposed cloud-native infrastructure:
  - Kubernetes dashboards and API endpoints
  - CI/CD exposed endpoints (Jenkins, GitLab CI, GitHub Actions artifacts)
  - Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
  - Container management (Docker API, Portainer)
  - Exposed monitoring dashboards (Grafana, Prometheus, Kibana)
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory
from src.utils.response_validator import ResponseValidator


# ============================================================
# Cloud / K8s / CI-CD Endpoints to Probe
# ============================================================

# (path, description, severity, category)
_CLOUD_ENDPOINTS: list[tuple[str, str, str, str]] = [
    # ── Kubernetes ──
    ("/api/v1", "Kubernetes API server (unauthenticated)", "critical", "kubernetes"),
    ("/api/v1/pods", "Kubernetes pod listing", "critical", "kubernetes"),
    ("/api/v1/secrets", "Kubernetes secrets listing", "critical", "kubernetes"),
    ("/api/v1/namespaces", "Kubernetes namespaces listing", "high", "kubernetes"),
    ("/apis", "Kubernetes API groups", "medium", "kubernetes"),
    ("/healthz", "Kubernetes health endpoint", "info", "kubernetes"),
    ("/version", "Kubernetes version endpoint", "low", "kubernetes"),
    ("/dashboard/", "Kubernetes Dashboard UI", "high", "kubernetes"),

    # ── CI/CD ──
    ("/script", "Jenkins Script Console (RCE)", "critical", "cicd"),
    ("/manage", "Jenkins Management Console", "high", "cicd"),
    ("/job/", "Jenkins Job listing", "medium", "cicd"),
    ("/api/v4/projects", "GitLab API project listing", "high", "cicd"),
    ("/api/v4/users", "GitLab API user listing", "medium", "cicd"),
    ("/-/graphql", "GitLab GraphQL API", "medium", "cicd"),
    ("/.github/workflows/", "GitHub Actions workflow files", "low", "cicd"),
    ("/api/v1/repos/search", "Gitea/Forgejo repo search", "medium", "cicd"),

    # ── Container Management ──
    ("/v2/_catalog", "Docker Registry catalog", "critical", "container"),
    ("/containers/json", "Docker Remote API container list", "critical", "container"),
    ("/images/json", "Docker Remote API image list", "high", "container"),
    ("/_ping", "Docker Remote API ping", "medium", "container"),
    ("/api/endpoints", "Portainer API endpoints", "high", "container"),

    # ── Monitoring / Observability ──
    ("/api/datasources", "Grafana datasources (may leak credentials)", "high", "monitoring"),
    ("/api/org", "Grafana organization info", "medium", "monitoring"),
    ("/api/v1/query?query=up", "Prometheus query endpoint", "medium", "monitoring"),
    ("/api/v1/targets", "Prometheus targets", "medium", "monitoring"),
    ("/app/kibana", "Kibana dashboard", "medium", "monitoring"),
    ("/api/console/api/server", "Kibana server info", "medium", "monitoring"),

    # ── Cloud Metadata (SSRF indicators — accessible from target) ──
    ("/latest/meta-data/", "AWS EC2 metadata (SSRF indicator)", "info", "cloud_meta"),
    ("/computeMetadata/v1/", "GCP metadata (SSRF indicator)", "info", "cloud_meta"),
    ("/metadata/instance", "Azure IMDS (SSRF indicator)", "info", "cloud_meta"),

    # ── Secrets / Config ──
    ("/v1/sys/health", "HashiCorp Vault health", "medium", "secrets"),
    ("/v1/sys/seal-status", "HashiCorp Vault seal status", "medium", "secrets"),
    ("/api/v1/secrets", "Vault-like secrets endpoint", "high", "secrets"),
    ("/.env", "Environment file exposure", "critical", "config"),
    ("/config.json", "Configuration file exposure", "medium", "config"),
    ("/actuator", "Spring Boot Actuator index", "medium", "config"),
    ("/actuator/env", "Spring Boot Actuator env (secrets)", "critical", "config"),
    ("/actuator/heapdump", "Spring Boot heap dump", "high", "config"),

    # ── Git/SVN Exposure (P4-6) ──
    ("/.git/HEAD", "Git repository HEAD exposed", "high", "config"),
    ("/.git/config", "Git configuration exposed (may leak remote URLs)", "high", "config"),
    ("/.svn/entries", "SVN repository entries exposed", "high", "config"),
    ("/.hg/store/00manifest.i", "Mercurial repository exposed", "medium", "config"),

    # ── Serverless / Cloud Functions (P4-6) ──
    ("/.well-known/openid-configuration", "OpenID discovery (cloud identity)", "low", "cloud_meta"),
    ("/api/functions", "Serverless function listing", "high", "serverless"),
    ("/_functions", "Netlify/Vercel functions endpoint", "medium", "serverless"),
    ("/api/serverless", "Serverless API endpoint", "medium", "serverless"),

    # ── Artifact Registries (P4-6) ──
    ("/v2/", "Container registry root (OCI/Docker)", "high", "container"),

    # ── Additional Infrastructure (P4-6) ──
    ("/server-status", "Apache server-status", "medium", "monitoring"),
    ("/server-info", "Apache server-info", "medium", "monitoring"),
    ("/nginx_status", "Nginx stub_status", "low", "monitoring"),
    ("/.well-known/security.txt", "Security.txt (informational)", "info", "config"),
    ("/debug/pprof/", "Go pprof profiler exposed", "high", "config"),
    ("/debug/vars", "Go expvar debug variables", "medium", "config"),
    ("/metrics", "Prometheus metrics endpoint", "medium", "monitoring"),
    ("/health", "Health check endpoint", "info", "monitoring"),
    ("/info", "Application info endpoint", "low", "monitoring"),
    ("/swagger-ui.html", "Swagger UI exposed", "low", "config"),
    ("/api-docs", "API documentation exposed", "low", "config"),
    ("/graphql", "GraphQL endpoint", "low", "config"),
    ("/graphiql", "GraphiQL interactive IDE", "medium", "config"),
    ("/wp-json/wp/v2/users", "WordPress user enumeration", "medium", "config"),
    ("/elmah.axd", "ASP.NET ELMAH error log", "high", "config"),
    ("/trace.axd", "ASP.NET trace log", "high", "config"),
    ("/phpinfo.php", "PHP info page", "medium", "config"),
]

# Signatures that confirm a genuine hit (not a 404/redirect/generic page)
_POSITIVE_SIGNATURES: dict[str, list[str]] = {
    "kubernetes": ["apiVersion", "kind", "metadata", "items"],
    "cicd": ["_class", "hudson", "jobs", "projects"],
    "container": ["Repositories", "RepoTags", "containers", "repositories"],
    "monitoring": ["datasources", "targets", "prometheus", "server_version"],
    "secrets": ["sealed", "initialized", "cluster_name"],
    "config": ["DB_", "DATABASE_URL", "SECRET_KEY", "API_KEY", "PASSWORD",
               "ref: refs/", "repositoryformatversion", "phpinfo()",
               "Spring Boot", "actuator", "graphiql", "GraphQL"],
    "serverless": ["functions", "runtime", "handler", "lambda"],
    "cloud_meta": ["ami-id", "instance-id", "computeMetadata", "azEnvironment"],
}

# ── Technology-Aware Endpoint Filtering (P4-6) ──
# Maps endpoint categories to technology keywords that must be present
# for those endpoints to be probed. If a category is NOT in this dict
# it is always probed (universal checks like .env, .git).
_TECH_CATEGORY_FILTER: dict[str, list[str]] = {
    "kubernetes": ["kubernetes", "k8s", "kubectl", "helm", "kube"],
    "cicd": ["jenkins", "gitlab", "github", "gitea", "forgejo", "ci/cd", "cicd"],
    "container": ["docker", "containerd", "podman", "portainer", "registry"],
    "serverless": ["lambda", "serverless", "netlify", "vercel", "cloud function",
                   "azure function", "firebase"],
}

def _filter_endpoints_by_tech(
    endpoints: list[tuple[str, str, str, str]],
    technologies: list[str] | None,
) -> list[tuple[str, str, str, str]]:
    """Filter cloud endpoints based on detected technologies.

    Categories listed in _TECH_CATEGORY_FILTER are only probed when at
    least one matching tech keyword is detected.  Categories NOT in the
    filter dict (config, monitoring, secrets, cloud_meta) are always probed.
    """
    if not technologies:
        return endpoints  # No tech info — probe everything

    tech_lower = {t.lower() for t in technologies}

    def _cat_allowed(category: str) -> bool:
        required = _TECH_CATEGORY_FILTER.get(category)
        if required is None:
            return True  # Universal category
        return any(kw in tech_text for kw in required for tech_text in tech_lower)

    return [ep for ep in endpoints if _cat_allowed(ep[3])]


async def check_cloud_security(
    targets: list[str],
    max_targets: int = 5,
    max_concurrent: int = 3,
    timeout: float = 8.0,
    extra_headers: dict[str, str] | None = None,
    technologies: list[str] | None = None,
) -> list[Finding]:
    """
    Probe targets for exposed cloud-native infrastructure.

    Args:
        targets: List of base URLs to probe
        max_targets: Maximum number of targets to test
        max_concurrent: Concurrency limit
        timeout: Per-request timeout in seconds
        extra_headers: Optional auth headers to inject
        technologies: Detected technology stack for smart filtering

    Returns:
        List of Finding objects for confirmed cloud exposures
    """
    import asyncio

    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)
    test_targets = targets[:max_targets]

    # Technology-aware endpoint selection
    active_endpoints = _filter_endpoints_by_tech(_CLOUD_ENDPOINTS, technologies)
    if len(active_endpoints) < len(_CLOUD_ENDPOINTS):
        logger.debug(
            f"Cloud checker: tech filter reduced endpoints "
            f"{len(_CLOUD_ENDPOINTS)} → {len(active_endpoints)}"
        )

    async def _probe_endpoint(
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
        description: str,
        severity: str,
        category: str,
    ) -> Finding | None:
        async with sem:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            headers: dict[str, str] = {
                "User-Agent": "Mozilla/5.0 (compatible; security-scanner/1.0)",
            }
            if extra_headers:
                headers.update(extra_headers)

            try:
                resp = await client.get(url, headers=headers, timeout=timeout, follow_redirects=False)

                # ── ResponseValidator: reject redirects, WAF blocks, error pages ──
                _rv = ResponseValidator()
                vr = _rv.validate(
                    resp.status_code,
                    dict(resp.headers),
                    resp.text[:3000],
                    expected_content_type="json" if category in ("kubernetes", "container", "monitoring", "cloud_meta", "serverless") else None,
                    url=url,
                )
                if not vr.is_valid:
                    logger.debug(f"Cloud check {url}: rejected — {vr.rejection_reason}")
                    return None

                body = resp.text[:2000]

                # Check for positive signatures
                signatures = _POSITIVE_SIGNATURES.get(category, [])
                matched_sigs = [s for s in signatures if s.lower() in body.lower()]

                # For config/env files, any signature match is significant
                if category in ("config",) and matched_sigs:
                    pass  # Confirmed
                elif not matched_sigs and category != "cloud_meta":
                    # No signature match and not cloud metadata — likely generic page
                    # Exception: if status 200 and content-type is JSON for API endpoints
                    ct = resp.headers.get("content-type", "")
                    if "json" not in ct and "xml" not in ct:
                        return None

                severity_map = {
                    "critical": SeverityLevel.CRITICAL,
                    "high": SeverityLevel.HIGH,
                    "medium": SeverityLevel.MEDIUM,
                    "low": SeverityLevel.LOW,
                    "info": SeverityLevel.INFO,
                }

                return Finding(
                    title=f"Exposed Cloud Infrastructure: {description}",
                    severity=severity_map.get(severity, SeverityLevel.MEDIUM),
                    confidence=max(10.0, (75.0 if matched_sigs else 50.0) + vr.confidence_modifier),
                    target=base_url,
                    endpoint=url,
                    description=(
                        f"Detected potentially exposed cloud infrastructure at {url}.\n"
                        f"Category: {category}\n"
                        f"HTTP {resp.status_code} response received.\n"
                        f"Matched signatures: {', '.join(matched_sigs) if matched_sigs else 'none (status-based)'}"
                    ),
                    evidence=f"HTTP {resp.status_code} | Content-Length: {len(body)} | "
                             f"Signatures: {matched_sigs}",
                    remediation=(
                        "Restrict access to cloud infrastructure endpoints. "
                        "Use network policies, authentication, and IP allowlists. "
                        "Do not expose internal services to the public internet."
                    ),
                    references=["CWE-200: Information Exposure", "CWE-284: Improper Access Control"],
                )

            except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout):
                return None
            except Exception as e:
                logger.debug(f"Cloud check error for {url}: {e}")
                return None

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(timeout, connect=10)) as client:
        tasks = []
        for base_url in test_targets:
            for path, desc, sev, cat in active_endpoints:
                tasks.append(_probe_endpoint(client, base_url, path, desc, sev, cat))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)

    if findings:
        logger.info(f"Cloud checker: {len(findings)} exposed endpoints found")

    return findings
