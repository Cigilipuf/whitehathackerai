"""
WhiteHatHacker AI — Sensitive URL Pattern Finder

Analyzes collected URLs (from gau, waybackurls, katana) to identify
potentially sensitive endpoints: admin panels, config files, backup files,
API endpoints with parameters, debug/test pages, etc.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, parse_qs

from loguru import logger
from src.tools.base import Finding
from src.utils.constants import SeverityLevel

# Strip ANSI escape codes from URLs — tool output contamination defense
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b.')


# ── Sensitive path patterns ──────────────────────────────────────────────────

_SENSITIVE_PATTERNS: list[tuple[str, str, SeverityLevel, float]] = [
    # (regex, description, severity, confidence)

    # Admin / Management
    (r"/admin[/\.\-]", "Admin panel endpoint", SeverityLevel.MEDIUM, 60.0),
    (r"/wp-admin", "WordPress admin panel", SeverityLevel.MEDIUM, 70.0),
    (r"/manager[/\.]", "Manager panel", SeverityLevel.MEDIUM, 55.0),
    (r"/dashboard[/\.]", "Dashboard endpoint", SeverityLevel.LOW, 40.0),
    (r"/console[/\.]", "Console endpoint", SeverityLevel.MEDIUM, 55.0),
    (r"/phpmyadmin|/pma|/myadmin", "phpMyAdmin panel", SeverityLevel.HIGH, 75.0),
    (r"/cpanel", "cPanel detected", SeverityLevel.MEDIUM, 65.0),
    # WP login is expected and not a vulnerability on its own.
    # (r"/wp-login\.php", "WordPress login page", SeverityLevel.LOW, 50.0),

    # Configuration / Source files
    (r"\.(env|config|cfg|ini|conf|properties|yml|yaml|toml)(\.bak|\.old|\.orig|\.backup|\.swp|~)?$",
     "Configuration file exposed", SeverityLevel.HIGH, 70.0),
    (r"/\.git(/|$)", "Git repository exposed", SeverityLevel.HIGH, 80.0),
    (r"/\.svn(/|$)", "SVN repository exposed", SeverityLevel.HIGH, 75.0),
    (r"/\.hg(/|$)", "Mercurial repository exposed", SeverityLevel.HIGH, 75.0),
    (r"/\.DS_Store", "macOS DS_Store file", SeverityLevel.LOW, 60.0),
    (r"/\.htaccess", ".htaccess file exposed", SeverityLevel.MEDIUM, 65.0),
    (r"/\.htpasswd", ".htpasswd file exposed", SeverityLevel.HIGH, 80.0),
    (r"/web\.config", "IIS web.config exposed", SeverityLevel.MEDIUM, 65.0),
    (r"/crossdomain\.xml", "Flash crossdomain policy", SeverityLevel.LOW, 50.0),
    (r"/clientaccesspolicy\.xml", "Silverlight access policy", SeverityLevel.LOW, 50.0),
    (r"/\.npmrc|/\.pypirc", "Package manager config with tokens", SeverityLevel.HIGH, 70.0),

    # Dependency / Stack exposure
    (r"/composer\.(json|lock)$", "PHP Composer dependencies exposed", SeverityLevel.LOW, 55.0),
    (r"/package\.json$", "Node.js package.json exposed", SeverityLevel.LOW, 50.0),
    (r"/Gemfile(\.lock)?$", "Ruby Gemfile exposed", SeverityLevel.LOW, 50.0),
    (r"/requirements\.txt$", "Python requirements exposed", SeverityLevel.LOW, 45.0),

    # Infrastructure / IaC secrets
    (r"/terraform\.tfstate", "Terraform state file (may contain secrets)", SeverityLevel.CRITICAL, 85.0),
    (r"/\.terraform/", "Terraform directory exposed", SeverityLevel.HIGH, 75.0),
    (r"/\.aws/credentials", "AWS credentials file", SeverityLevel.CRITICAL, 90.0),

    # Backup files
    (r"\.(bak|backup|old|orig|save|swp|swo)$", "Backup file exposed", SeverityLevel.MEDIUM, 60.0),
    (r"\.(sql|dump|db)$", "Database dump file", SeverityLevel.HIGH, 75.0),
    (r"\.(tar|tar\.gz|tgz|zip|rar|7z)$", "Archive file exposed", SeverityLevel.MEDIUM, 55.0),
    (r"backup[s]?[/\.]", "Backup directory", SeverityLevel.MEDIUM, 55.0),

    # Debug / Test
    (r"/debug[/\.]", "Debug endpoint", SeverityLevel.MEDIUM, 55.0),
    (r"/test[/\.]", "Test endpoint", SeverityLevel.LOW, 35.0),
    (r"/trace[/\.]", "Trace endpoint", SeverityLevel.MEDIUM, 55.0),
    (r"/status[/\.]", "Status endpoint", SeverityLevel.LOW, 40.0),
    (r"/health[/\.]", "Health check endpoint", SeverityLevel.INFO, 30.0),
    (r"/info[/\.]", "Info endpoint", SeverityLevel.LOW, 40.0),
    (r"/metrics[/\.]?$", "Metrics endpoint (Prometheus?)", SeverityLevel.MEDIUM, 55.0),
    (r"/actuator", "Spring Boot Actuator", SeverityLevel.MEDIUM, 65.0),
    (r"/elmah\.axd", "ELMAH error log", SeverityLevel.MEDIUM, 65.0),
    (r"phpinfo", "phpinfo() page", SeverityLevel.MEDIUM, 70.0),
    (r"/server-status", "Apache server-status", SeverityLevel.MEDIUM, 65.0),
    (r"/server-info", "Apache server-info", SeverityLevel.MEDIUM, 65.0),
    (r"/api/v1/debug/pprof", "Go pprof profiler endpoint", SeverityLevel.MEDIUM, 65.0),
    (r"/cgi-bin/", "CGI-bin directory", SeverityLevel.LOW, 45.0),

    # API Documentation / Spec
    (r"/swagger", "Swagger UI / API docs", SeverityLevel.LOW, 50.0),
    (r"/api-docs", "API documentation", SeverityLevel.LOW, 50.0),
    (r"/openapi\.(json|yaml)", "OpenAPI spec file", SeverityLevel.LOW, 55.0),
    (r"/graphql", "GraphQL endpoint", SeverityLevel.LOW, 50.0),
    (r"/graphiql", "GraphiQL interface", SeverityLevel.MEDIUM, 60.0),
    (r"\.wsdl(\?|$)", "WSDL/SOAP service descriptor", SeverityLevel.LOW, 50.0),

    # Well-known paths
    (r"/\.well-known/apple-app-site-association", "iOS app association file", SeverityLevel.INFO, 30.0),
    (r"/\.well-known/assetlinks\.json", "Android app links file", SeverityLevel.INFO, 30.0),

    # Auth flow endpoints (useful for auth_bypass / rate_limit testing)
    # Registration/login/signup pages are expected on any web app and not
    # actionable in bug bounty context — suppress entirely.
    # (r"/(register|signup|sign-up)([/\.]|$)", "Registration endpoint", SeverityLevel.INFO, 25.0),
    (r"/(password-reset|forgot-password|reset-password)([/\.]|$)",
     "Password reset endpoint", SeverityLevel.LOW, 35.0),

    # Sensitive data patterns in URLs
    (r"[?&](token|api_key|apikey|secret|password|passwd|pwd|auth|session|jwt)=",
     "Sensitive parameter in URL", SeverityLevel.HIGH, 65.0),
    (r"[?&](redirect|url|next|return|goto|dest|destination|redir|returnUrl)=https?://",
     "Open redirect parameter", SeverityLevel.MEDIUM, 55.0),
    (r"[?&](file|path|doc|document|folder|dir|directory|src|source)=",
     "Path traversal parameter", SeverityLevel.MEDIUM, 50.0),
    (r"[?&](cmd|exec|command|ping|query|jump|code|reg|do|func|arg|option|load|include|require)=",
     "Command injection parameter", SeverityLevel.MEDIUM, 50.0),
    (r"[?&](id|user_id|uid|pid|oid|no|number)=\d+",
     "IDOR candidate parameter", SeverityLevel.LOW, 40.0),

    # Cloud / S3
    (r"s3\.amazonaws\.com|s3[-.][\w-]+\.amazonaws\.com",
     "AWS S3 bucket URL in path", SeverityLevel.LOW, 45.0),

    # Version control / CI/CD
    (r"/Jenkinsfile", "Jenkinsfile exposed", SeverityLevel.MEDIUM, 65.0),
    (r"/Dockerfile", "Dockerfile exposed", SeverityLevel.LOW, 50.0),
    (r"/docker-compose", "Docker Compose file", SeverityLevel.MEDIUM, 55.0),
    (r"/\.github/", "GitHub config directory", SeverityLevel.LOW, 45.0),
    (r"/\.gitlab-ci", "GitLab CI config", SeverityLevel.MEDIUM, 55.0),

    # Error pages that leak info
    (r"/error[/\.]", "Error page", SeverityLevel.LOW, 30.0),
    (r"/404[/\.]", "Custom 404 page", SeverityLevel.INFO, 25.0),
    (r"/500[/\.]", "Custom 500 page", SeverityLevel.INFO, 25.0),

    # WordPress specific
    (r"/wp-content/uploads/", "WordPress uploads directory", SeverityLevel.LOW, 40.0),
    (r"/xmlrpc\.php", "WordPress XML-RPC", SeverityLevel.MEDIUM, 65.0),
    (r"/wp-json/", "WordPress REST API", SeverityLevel.LOW, 45.0),
    # wp-includes is standard WordPress; not actionable.
    # (r"/wp-includes/", "WordPress includes directory", SeverityLevel.INFO, 30.0),
]

# Compile patterns for performance
_COMPILED_PATTERNS = [
    (re.compile(pat, re.IGNORECASE), desc, sev, conf)
    for pat, desc, sev, conf in _SENSITIVE_PATTERNS
]


def find_sensitive_urls(
    urls: list[str],
    target: str = "",
    max_findings_per_pattern: int = 3,
) -> list[Finding]:
    """
    Analyze a list of URLs for sensitive patterns.

    Args:
        urls: List of URLs to analyze
        target: Base target domain
        max_findings_per_pattern: Max findings per pattern to avoid flooding

    Returns:
        List of Finding objects for potentially sensitive URLs
    """
    findings: list[Finding] = []
    pattern_counts: dict[str, int] = {}
    seen_urls: set[str] = set()

    for url in urls:
        # Discard URLs contaminated with ANSI escape codes — terminal artifacts
        if '\x1b' in url:
            continue
        url_lower = url.lower().strip()
        if not url_lower or url_lower in seen_urls:
            continue
        seen_urls.add(url_lower)

        try:
            parsed = urlparse(url)
            path_and_query = parsed.path + ("?" + parsed.query if parsed.query else "")
        except Exception as _exc:
            logger.debug(f"sensitive url finder error: {_exc}")
            continue

        for compiled_re, description, severity, confidence in _COMPILED_PATTERNS:
            if compiled_re.search(path_and_query):
                # Rate-limit findings per pattern
                count = pattern_counts.get(description, 0)
                if count >= max_findings_per_pattern:
                    continue
                pattern_counts[description] = count + 1

                findings.append(Finding(
                    title=f"Sensitive URL: {description}",
                    description=(
                        f"{description} found in collected URLs.\n"
                        f"URL: {url}\n"
                        f"This endpoint may expose sensitive information or functionality."
                    ),
                    vulnerability_type="sensitive_url",
                    severity=severity,
                    confidence=confidence,
                    target=target or parsed.netloc,
                    endpoint=url,
                    tool_name="sensitive_url_finder",
                    evidence=url,
                    tags=["sensitive_url", "passive_analysis", description.lower().replace(" ", "_")],
                ))
                break  # One finding per URL (first match wins)

    # Multi-param endpoint detection disabled — produces noise with no actionable value.
    # The vuln_scan stage already performs injection testing on parameterized endpoints.
    # param_urls = _find_parameterized_urls(urls, target)
    # findings.extend(param_urls)

    logger.debug(f"Sensitive URL finder: {len(findings)} findings from {len(urls)} URLs")
    return findings


def _find_parameterized_urls(
    urls: list[str],
    target: str = "",
    max_param_findings: int = 20,
) -> list[Finding]:
    """Find URLs with interesting parameters that could be injection candidates."""
    findings: list[Finding] = []
    seen_params: set[str] = set()

    for url in urls:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
        except Exception as _exc:
            logger.debug(f"sensitive url finder error: {_exc}")
            continue

        if not params:
            continue

        # Create unique key based on path + param names (dedup)
        param_key = f"{parsed.path}:{'&'.join(sorted(params.keys()))}"
        if param_key in seen_params:
            continue
        seen_params.add(param_key)

        # URLs with many parameters are more interesting
        if len(params) >= 3:
            if len(findings) >= max_param_findings:
                break
            findings.append(Finding(
                title=f"Multi-parameter endpoint ({len(params)} params)",
                description=(
                    f"Endpoint with {len(params)} parameters found — good injection candidate.\n"
                    f"URL: {url}\n"
                    f"Parameters: {', '.join(params.keys())}"
                ),
                vulnerability_type="interesting_endpoint",
                severity=SeverityLevel.INFO,
                confidence=20.0,
                target=target or parsed.netloc,
                endpoint=url,
                tool_name="sensitive_url_finder",
                evidence=url,
                tags=["parameterized_url", "injection_candidate"],
            ))

    return findings


async def verify_sensitive_urls(
    candidates: list[Finding],
    timeout: float = 10.0,
    concurrency: int = 5,
) -> list[Finding]:
    """HTTP-verify sensitive URL findings.

    Takes regex-matched candidates from ``find_sensitive_urls`` and performs a
    lightweight HEAD/GET check to confirm the resource actually exists and is
    accessible.  Candidates returning 401/403/404/5xx or WAF block pages are
    discarded.

    Args:
        candidates: Findings produced by ``find_sensitive_urls``.
        timeout: Per-request timeout in seconds.
        concurrency: Max concurrent requests.

    Returns:
        Only those findings whose URL returned a meaningful HTTP 200 response.
    """
    if not candidates:
        return []

    try:
        import httpx
    except ImportError:
        logger.warning("httpx not available — skipping HTTP verification of sensitive URLs")
        return candidates

    from src.utils.response_validator import ResponseValidator

    sem = asyncio.Semaphore(concurrency)
    rv = ResponseValidator()
    verified: list[Finding] = []

    # Shared client for connection reuse / keep-alive
    _shared_client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=5.0),
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)"},
    )

    async def _check(finding: Finding) -> Finding | None:
        url = finding.endpoint or finding.evidence or ""
        if not isinstance(url, str) or not url.startswith("http"):
            return None
        async with sem:
            try:
                resp = await _shared_client.head(url)
                body = ""
                # If HEAD returns 405/501, fall back to GET
                if resp.status_code in (405, 501):
                    resp = await _shared_client.get(url)
                    body = resp.text[:5000] if resp.text else ""
                elif resp.status_code == 200:
                    # HEAD succeeded; do a quick GET to get body for validation
                    resp2 = await _shared_client.get(url)
                    body = resp2.text[:5000] if resp2.text else ""

                headers_dict = dict(resp.headers)
                result = rv.validate(resp.status_code, headers_dict, body, url=url)

                if not result.is_valid:
                    logger.debug(
                        f"sensitive_url_finder: URL rejected by ResponseValidator "
                        f"({result.rejection_reason}): {url}"
                    )
                    return None

                # Also reject if body is too small (< 50 bytes) — likely empty/stub
                if resp.status_code == 200 and len(body.strip()) < 50:
                    logger.debug(f"sensitive_url_finder: URL body too small (<50B): {url}")
                    return None

                return finding
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
                logger.debug(f"sensitive_url_finder: HTTP check failed for {url}")
                return None
            except Exception as exc:
                logger.debug(f"sensitive_url_finder: unexpected error for {url}: {exc}")
                return None

    tasks = [_check(f) for f in candidates]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Finding):
            verified.append(r)

    await _shared_client.aclose()

    logger.debug(
        f"Sensitive URL finder: {len(verified)}/{len(candidates)} "
        f"candidates verified via HTTP"
    )
    return verified


__all__ = ["find_sensitive_urls", "verify_sensitive_urls"]
