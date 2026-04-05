"""
WhiteHatHacker AI — Information Disclosure Checker

Detects information leakage from common misconfigurations:
  - Server version headers
  - Detailed error pages (stack traces)
  - .git, .env, .DS_Store exposure
  - phpinfo(), server-status, debug endpoints
  - Default pages revealing server software
  - Backup files (.bak, .old, ~)
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# Paths that commonly leak information
_LEAK_PATHS: list[tuple[str, str, str, str]] = [
    # (path, description, pattern_to_match_in_body, severity)
    ("/.git/HEAD", ".git repository exposed", "ref:", "high"),
    ("/.git/config", ".git config exposed", "[core]", "high"),
    ("/.env", "Environment file exposed", r"(?:DB_|APP_|SECRET|KEY|PASSWORD|TOKEN)", "critical"),
    ("/.DS_Store", "macOS .DS_Store file exposed", "\x00\x00\x00\x01Bud1", "low"),
    ("/server-status", "Apache server-status exposed", "Apache Server Status", "medium"),
    ("/server-info", "Apache server-info exposed", "Apache Server Information", "medium"),
    ("/.htaccess", ".htaccess file exposed", "RewriteRule", "medium"),
    ("/.htpasswd", ".htpasswd file exposed", r"\$apr1\$|\$2[aby]?\$|:{SHA}", "critical"),
    ("/phpinfo.php", "phpinfo() page exposed", "PHP Version", "medium"),
    ("/info.php", "PHP info page exposed", "PHP Version", "medium"),
    ("/web.config", "IIS web.config exposed", "configuration", "medium"),
    ("/robots.txt", "robots.txt (info gathering)", "Disallow:", "info"),
    ("/sitemap.xml", "sitemap.xml (info gathering)", "urlset", "info"),
    ("/crossdomain.xml", "Flash crossdomain policy", "cross-domain-policy", "low"),
    ("/.well-known/security.txt", "security.txt", "Contact:", "info"),
    ("/elmah.axd", "ELMAH error log exposed", "Error Log", "high"),
    ("/trace.axd", "ASP.NET trace exposed", "Request Details", "high"),
    ("/debug/default/view", "Yii debug panel", "yii", "high"),
    ("/_debugbar", "Laravel debugbar exposed", "debugbar", "high"),
    ("/actuator", "Spring Boot Actuator exposed", r'"_links"\s*:', "high"),
    ("/actuator/env", "Spring Boot env exposed", r'"propertySources"\s*:', "critical"),
    ("/actuator/health", "Spring Boot health endpoint", r'"status"\s*:\s*"UP', "low"),
    ("/api/swagger.json", "Swagger API spec exposed", "swagger", "low"),
    ("/api/v1/swagger.json", "Swagger v1 API spec", "swagger", "low"),
    ("/swagger-ui.html", "Swagger UI exposed", "swagger", "low"),
    ("/graphql", "GraphQL endpoint (introspection)", "__schema", "medium"),
    ("/wp-config.php.bak", "WordPress config backup", "DB_NAME", "critical"),
    ("/config.php.bak", "Config backup file", r"(?:password|database|secret)", "high"),
    ("/backup.sql", "SQL backup exposed", r"(?:INSERT INTO|CREATE TABLE)", "critical"),
    ("/dump.sql", "SQL dump exposed", r"(?:INSERT INTO|CREATE TABLE)", "critical"),
    ("/database.sql", "Database dump exposed", r"(?:INSERT INTO|CREATE TABLE)", "critical"),
]

# Error page patterns that reveal server info
_ERROR_PATTERNS = [
    (re.compile(r"<address>Apache/[\d.]+ \([\w]+\)"), "Apache version disclosure"),
    (re.compile(r"<address>nginx/[\d.]+"), "Nginx version disclosure"),
    (re.compile(r"Microsoft-IIS/[\d.]+"), "IIS version disclosure"),
    (re.compile(r"X-Powered-By:\s*PHP/[\d.]+", re.I), "PHP version disclosure"),
    (re.compile(r"X-AspNet-Version:\s*[\d.]+", re.I), "ASP.NET version disclosure"),
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"at\s+[\w.]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"<b>Fatal error</b>.*?<b>"), "PHP fatal error"),
    (re.compile(r"<b>Warning</b>:.*?in <b>"), "PHP warning with path"),
    (re.compile(r"stack_trace|stacktrace|stack trace", re.I), "Stack trace in response"),
]

# Headers that leak information
_LEAK_HEADERS = [
    ("x-powered-by", r".", "X-Powered-By header leaks technology"),
    ("server", r"[\d.]", "Server header leaks version number"),
    ("x-aspnet-version", r".", "X-AspNet-Version header"),
    ("x-aspnetmvc-version", r".", "X-AspNetMvc-Version header"),
    ("x-debug-token", r".", "Debug token exposed"),
    ("x-debug-token-link", r".", "Debug link exposed"),
]


async def _check_path(
    base_url: str,
    path: str,
    description: str,
    body_pattern: str,
    severity_str: str,
    timeout: float = 10.0,
) -> Finding | None:
    """Check if a sensitive path is accessible."""
    url = f"{base_url.rstrip('/')}{path}"
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sSL",
            "-m", str(int(timeout)),
            "-D", "-",
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode != 0 or not stdout:
            return None

        text = stdout.decode(errors="replace")
        # Split headers and body
        parts = text.split("\r\n\r\n", 1)
        headers_section = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        # Check status code from header — use LAST status line because
        # curl -L follows redirects, so intermediate 301/302 appear first.
        all_statuses = re.findall(r"HTTP/[\d.]+ (\d{3})", headers_section)
        status = int(all_statuses[-1]) if all_statuses else 0

        # Only accept 200 OK.  301/302 mean the file doesn't exist at this
        # path (redirect to login / homepage / SPA catch-all).  The body
        # after -L belongs to the *redirected* URL, not the path we tested.
        if status == 200 and body_pattern:
            if re.search(body_pattern, body, re.IGNORECASE):
                # ── SPA catch-all detection ──
                # If the response is HTML but we expected a config/data file,
                # it's likely a SPA returning index.html for all routes.
                content_type = ""
                for line in headers_section.split("\n"):
                    if line.lower().startswith("content-type:"):
                        content_type = line.split(":", 1)[1].strip().lower()
                        break
                _is_html = "text/html" in content_type or body.strip().startswith(("<!doctype", "<!DOCTYPE", "<html"))
                _expects_data = path in (
                    "/.env", "/.git/HEAD", "/.git/config", "/.htpasswd",
                    "/actuator/env", "/actuator", "/actuator/health",
                    "/phpinfo.php", "/info.php", "/web.config",
                    "/wp-config.php.bak", "/config.php.bak",
                    "/backup.sql", "/dump.sql", "/database.sql",
                    "/api/swagger.json", "/api/v1/swagger.json",
                )
                if _is_html and _expects_data:
                    # HTML response for a data endpoint = SPA catch-all, skip
                    return None

                sev_map = {
                    "info": SeverityLevel.INFO,
                    "low": SeverityLevel.LOW,
                    "medium": SeverityLevel.MEDIUM,
                    "high": SeverityLevel.HIGH,
                    "critical": SeverityLevel.CRITICAL,
                }
                sev = sev_map.get(severity_str, SeverityLevel.LOW)

                hostname = urlparse(base_url).netloc
                # Skip info-level robots.txt/sitemap
                if severity_str == "info":
                    return None

                return Finding(
                    title=f"Information Disclosure: {description}",
                    description=(
                        f"Sensitive path accessible at {url}\n"
                        f"Status: {status}\n"
                        f"Body size: {len(body)} bytes\n\n"
                        f"Pattern matched: {body_pattern}\n"
                        f"Body preview: {body[:200]}..."
                    ),
                    vulnerability_type="information_disclosure",
                    severity=sev,
                    confidence=75.0 if severity_str in ("high", "critical") else 60.0,
                    target=hostname,
                    endpoint=url,
                    tool_name="info_disclosure_checker",
                    tags=["information_disclosure", "misconfiguration"],
                    evidence=f"curl '{url}' → {status}\n{body[:300]}",
                    cwe_id="CWE-200",
                )
    except Exception as _exc:
        logger.debug(f"info disclosure checker error: {_exc}")
    return None


async def _check_error_page(
    base_url: str,
    timeout: float = 10.0,
) -> list[Finding]:
    """Test error pages for information leakage."""
    findings: list[Finding] = []
    # Trigger 404 with random string
    url = f"{base_url.rstrip('/')}/whai_nonexistent_path_404_test"
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sSL",
            "-m", str(int(timeout)),
            "-D", "-",
            "-H", "User-Agent: Mozilla/5.0 (compatible; WhiteHatHackerAI/2.0)",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        if proc.returncode != 0 or not stdout:
            return findings

        response = stdout.decode(errors="replace")
        hostname = urlparse(base_url).netloc

        # Check headers for info leakage
        parts = response.split("\r\n\r\n", 1)
        headers_section = parts[0] if parts else ""

        for header_name, pattern, desc in _LEAK_HEADERS:
            for line in headers_section.splitlines():
                if line.lower().startswith(f"{header_name}:"):
                    value = line.split(":", 1)[1].strip()
                    if re.search(pattern, value):
                        findings.append(Finding(
                            title=f"Header Information Leak: {desc}",
                            description=(
                                f"The server at {hostname} exposes information via HTTP header.\n"
                                f"Header: {line.strip()}\n\n"
                                f"Version information helps attackers identify known vulnerabilities."
                            ),
                            vulnerability_type="information_disclosure",
                            severity=SeverityLevel.LOW,
                            confidence=90.0,
                            target=hostname,
                            endpoint=base_url,
                            tool_name="info_disclosure_checker",
                            tags=["information_disclosure", "headers"],
                            evidence=f"Header: {line.strip()}",
                            cwe_id="CWE-200",
                        ))
                        break  # One finding per header type

        # Check body for error patterns
        body = parts[1] if len(parts) > 1 else ""
        for pat, desc in _ERROR_PATTERNS:
            match = pat.search(body)
            if match:
                findings.append(Finding(
                    title=f"Error Page Information Leak: {desc}",
                    description=(
                        f"The error page at {url} leaks server information.\n"
                        f"Pattern: {desc}\n"
                        f"Matched: {match.group()[:100]}\n\n"
                        f"Detailed error pages help attackers understand the tech stack."
                    ),
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.LOW,
                    confidence=85.0,
                    target=hostname,
                    endpoint=url,
                    tool_name="info_disclosure_checker",
                    tags=["information_disclosure", "error_page"],
                    evidence=f"404 page: {match.group()[:200]}",
                    cwe_id="CWE-209",
                ))
    except Exception as _exc:
        logger.debug(f"info disclosure checker error: {_exc}")

    return findings


async def check_info_disclosure(
    urls: list[str],
    max_hosts: int = 5,
    max_concurrent: int = 5,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Check for information disclosure vulnerabilities.

    Args:
        urls: Target URLs
        max_hosts: Max unique hosts to test
        max_concurrent: Max concurrent requests
        timeout: Per-request timeout

    Returns:
        List of findings
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)
    seen_hosts: set[str] = set()
    target_urls: list[str] = []

    for url in urls:
        if not url.startswith("http"):
            url = f"https://{url}"
        host = urlparse(url).netloc
        if host not in seen_hosts:
            seen_hosts.add(host)
            # Normalize to base URL
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            target_urls.append(base)
        if len(target_urls) >= max_hosts:
            break

    logger.info(f"info_disclosure_checker: Checking {len(target_urls)} hosts, {len(_LEAK_PATHS)} paths")

    # Check paths
    async def check_one_path(base_url: str, path: str, desc: str, pat: str, sev: str) -> Finding | None:
        async with sem:
            return await _check_path(base_url, path, desc, pat, sev, timeout)

    path_tasks = []
    for base_url in target_urls:
        # Only check high-value paths (not all 30+) for performance
        priority_paths = [p for p in _LEAK_PATHS if p[3] in ("critical", "high", "medium")]
        for path, desc, pat, sev in priority_paths:
            path_tasks.append(check_one_path(base_url, path, desc, pat, sev))

    # Check error pages
    error_tasks = [_check_error_page(url, timeout) for url in target_urls]

    # Run all concurrently
    all_results = await asyncio.gather(
        *path_tasks, *error_tasks,
        return_exceptions=True,
    )

    for result in all_results:
        if isinstance(result, Finding):
            findings.append(result)
        elif isinstance(result, list):
            findings.extend(result)

    # Deduplicate by title+target
    deduped: dict[str, Finding] = {}
    for f in findings:
        key = f"{f.title}:{f.target}"
        if key not in deduped:
            deduped[key] = f

    findings = list(deduped.values())

    if findings:
        logger.info(f"info_disclosure_checker: {len(findings)} findings")

    return findings


__all__ = ["check_info_disclosure"]
