"""Response Intelligence Engine — extract actionable signals from HTTP responses.

Analyzes response headers, status codes, error messages, and body patterns
collected during recon and scanning to identify:
  - Technology fingerprints (server versions, frameworks, languages)
  - Misconfigurations (verbose errors, debug mode, stack traces)
  - Interesting headers hinting at internal architecture
  - Error-based information disclosure
  - API version and schema signals

Results are stored in ``state.metadata["response_intel"]`` for downstream use
by the vulnerability scan handler (custom payload selection, priority tuning).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from loguru import logger


# ── Fingerprint patterns ────────────────────────────────────────

_SERVER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("apache", re.compile(r"Apache/?([\d.]+)?", re.I)),
    ("nginx", re.compile(r"nginx/?([\d.]+)?", re.I)),
    ("iis", re.compile(r"Microsoft-IIS/?([\d.]+)?", re.I)),
    ("lighttpd", re.compile(r"lighttpd/?([\d.]+)?", re.I)),
    ("caddy", re.compile(r"Caddy", re.I)),
    ("openresty", re.compile(r"openresty/?([\d.]+)?", re.I)),
    ("envoy", re.compile(r"envoy", re.I)),
    ("gunicorn", re.compile(r"gunicorn", re.I)),
    ("uvicorn", re.compile(r"uvicorn", re.I)),
    ("tomcat", re.compile(r"Apache-Coyote|Tomcat", re.I)),
    ("jetty", re.compile(r"Jetty\(?([^)]*)\)?", re.I)),
    ("werkzeug", re.compile(r"Werkzeug/?([\d.]+)?", re.I)),
    ("express", re.compile(r"Express", re.I)),
    ("kestrel", re.compile(r"Kestrel", re.I)),
]

_POWERED_BY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("php", re.compile(r"PHP/?([\d.]+)?", re.I)),
    ("asp.net", re.compile(r"ASP\.NET", re.I)),
    ("django", re.compile(r"Django", re.I)),
    ("flask", re.compile(r"Flask", re.I)),
    ("rails", re.compile(r"Phusion Passenger|Rails", re.I)),
    ("spring", re.compile(r"Spring", re.I)),
    ("laravel", re.compile(r"Laravel", re.I)),
    ("next.js", re.compile(r"Next\.?js", re.I)),
    ("nuxt", re.compile(r"Nuxt", re.I)),
]

_ERROR_SIGNATURES: list[tuple[str, str, re.Pattern[str]]] = [
    # (technology, description, regex)
    ("php", "PHP error disclosure", re.compile(
        r"(Fatal error|Parse error|Warning):.*in\s+(/[^\s]+\.php)", re.I)),
    ("asp.net", "ASP.NET stack trace", re.compile(
        r"(Server Error in|Stack Trace:.*at\s+System\.)", re.I | re.S)),
    ("java", "Java stack trace", re.compile(
        r"(java\.\w+Exception|at\s+[\w.]+\([\w]+\.java:\d+\))", re.I)),
    ("python", "Python traceback", re.compile(
        r"(Traceback \(most recent call last\)|File\s+\"[^\"]+\",\s+line\s+\d+)", re.I)),
    ("ruby", "Ruby error", re.compile(
        r"(NoMethodError|ActionController::RoutingError|\.rb:\d+:in)", re.I)),
    ("node", "Node.js error", re.compile(
        r"(ReferenceError|TypeError|SyntaxError):.*\n\s+at\s+", re.I)),
    ("sql", "SQL error disclosure", re.compile(
        r"(SQL syntax|ORA-\d{5}|PG::Error|mysql_|sqlite3\.OperationalError)", re.I)),
    ("debug", "Debug mode enabled", re.compile(
        r"(Werkzeug Debugger|Django Debug|X-Debug-Token|Xdebug)", re.I)),
    ("wordpress", "WordPress debug", re.compile(
        r"(wp-content/|wp-includes/|WordPress\s+database\s+error)", re.I)),
    ("laravel", "Laravel debug", re.compile(
        r"(Whoops!|Illuminate\\|laravel_session)", re.I)),
    ("spring", "Spring error page", re.compile(
        r"(Whitelabel Error Page|org\.springframework)", re.I)),
]

_INTERESTING_HEADERS: list[tuple[str, str]] = [
    # (header_name_lower, signal_description)
    ("x-debug-token", "Symfony debug profiler exposed"),
    ("x-debug-token-link", "Symfony profiler link exposed"),
    ("x-aspnet-version", "ASP.NET version disclosed"),
    ("x-aspnetmvc-version", "ASP.NET MVC version disclosed"),
    ("x-powered-cms", "CMS identified"),
    ("x-generator", "Generator meta disclosed"),
    ("x-drupal-cache", "Drupal caching revealed"),
    ("x-varnish", "Varnish cache layer detected"),
    ("x-cache", "Cache layer detected"),
    ("x-amz-cf-id", "AWS CloudFront identified"),
    ("x-amz-request-id", "AWS backend identified"),
    ("x-azure-ref", "Azure backend identified"),
    ("x-request-id", "Request tracing enabled"),
    ("x-correlation-id", "Request correlation enabled"),
    ("x-runtime", "Response timing exposed"),
    ("x-served-by", "Backend host disclosed"),
    ("x-backend-server", "Backend server disclosed"),
    ("via", "Proxy chain disclosed"),
    ("x-forwarded-for", "Forwarding chain visible"),
    ("server-timing", "Server timing metrics exposed"),
]

_SECURITY_HEADER_MISSING: list[str] = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
]


# ── Data models ─────────────────────────────────────────────────

@dataclass
class ResponseIntel:
    """Aggregated intelligence from HTTP responses."""

    technologies: dict[str, str | None] = field(default_factory=dict)
    # tech_name → version_or_None
    error_disclosures: list[dict[str, str]] = field(default_factory=list)
    # [{tech, description, evidence_snippet, url}]
    interesting_headers: list[dict[str, str]] = field(default_factory=list)
    # [{header, value, signal, url}]
    missing_security_headers: list[str] = field(default_factory=list)
    debug_mode_detected: bool = False
    api_signals: list[dict[str, str]] = field(default_factory=list)
    # [{signal, url, detail}]
    internal_paths: list[str] = field(default_factory=list)
    # internal file paths leaked in errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "technologies": dict(self.technologies),
            "error_disclosures": list(self.error_disclosures),
            "interesting_headers": list(self.interesting_headers),
            "missing_security_headers": list(self.missing_security_headers),
            "debug_mode_detected": self.debug_mode_detected,
            "api_signals": list(self.api_signals),
            "internal_paths": list(self.internal_paths),
            "summary": self.summary(),
        }

    def summary(self) -> str:
        parts: list[str] = []
        if self.technologies:
            parts.append(f"Tech: {', '.join(sorted(self.technologies))}")
        if self.error_disclosures:
            parts.append(f"Errors: {len(self.error_disclosures)}")
        if self.debug_mode_detected:
            parts.append("DEBUG MODE")
        if self.missing_security_headers:
            parts.append(f"Missing headers: {len(self.missing_security_headers)}")
        return " | ".join(parts) if parts else "No signals"


# ── Core analysis functions ─────────────────────────────────────

def analyze_response_headers(
    headers: dict[str, str],
    url: str = "",
    intel: ResponseIntel | None = None,
) -> ResponseIntel:
    """Analyze HTTP response headers for intelligence signals.

    Args:
        headers: Header dict (keys should be original case or lowercase).
        url: Source URL for attribution.
        intel: Existing ResponseIntel to merge into.

    Returns:
        Updated ResponseIntel.
    """
    intel = intel or ResponseIntel()
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # Server fingerprint
    server = lower_headers.get("server", "")
    if server:
        for tech, pat in _SERVER_PATTERNS:
            m = pat.search(server)
            if m:
                version = m.group(1) if m.lastindex else None
                intel.technologies[tech] = version
                break

    # X-Powered-By fingerprint
    powered = lower_headers.get("x-powered-by", "")
    if powered:
        for tech, pat in _POWERED_BY_PATTERNS:
            m = pat.search(powered)
            if m:
                version = m.group(1) if m.lastindex else None
                intel.technologies[tech] = version

    # Interesting headers
    for hdr, signal in _INTERESTING_HEADERS:
        val = lower_headers.get(hdr)
        if val:
            intel.interesting_headers.append({
                "header": hdr,
                "value": val[:200],
                "signal": signal,
                "url": url,
            })

    # Missing security headers
    for sec_hdr in _SECURITY_HEADER_MISSING:
        if sec_hdr not in lower_headers and sec_hdr not in intel.missing_security_headers:
            intel.missing_security_headers.append(sec_hdr)

    return intel


def analyze_response_body(
    body: str,
    url: str = "",
    intel: ResponseIntel | None = None,
) -> ResponseIntel:
    """Analyze HTTP response body for error disclosures and signals.

    Args:
        body: Response body text (first ~10KB is sufficient).
        url: Source URL for attribution.
        intel: Existing ResponseIntel to merge into.

    Returns:
        Updated ResponseIntel.
    """
    intel = intel or ResponseIntel()
    if not body:
        return intel

    # Truncate for analysis efficiency
    text = body[:10_000]

    # Error signatures
    for tech, desc, pat in _ERROR_SIGNATURES:
        m = pat.search(text)
        if m:
            snippet = m.group(0)[:300]
            intel.error_disclosures.append({
                "tech": tech,
                "description": desc,
                "evidence_snippet": snippet,
                "url": url,
            })
            intel.technologies.setdefault(tech, None)

            if tech == "debug":
                intel.debug_mode_detected = True

    # Internal path extraction from errors
    path_re = re.compile(r"""(?:/(?:var|home|opt|usr|srv|app|www|htdocs)/[\w./\-]+\.(?:py|php|rb|java|js|ts|go|rs))""")
    for path_match in path_re.findall(text):
        if path_match not in intel.internal_paths:
            intel.internal_paths.append(path_match)

    # API signals
    if re.search(r'"swagger"|"openapi"|"api-docs"', text, re.I):
        intel.api_signals.append({
            "signal": "OpenAPI/Swagger detected",
            "url": url,
            "detail": "API documentation may be exposed",
        })
    if re.search(r'"graphql"|"__schema"|"__type"', text, re.I):
        intel.api_signals.append({
            "signal": "GraphQL detected",
            "url": url,
            "detail": "GraphQL endpoint or introspection exposed",
        })

    return intel


def analyze_responses(
    responses: list[dict[str, Any]],
) -> ResponseIntel:
    """Batch-analyze a list of HTTP response dicts.

    Each response dict should have optional keys:
      - ``url`` (str)
      - ``headers`` (dict[str, str])
      - ``body`` (str)
      - ``status_code`` (int)

    Args:
        responses: List of response dicts.

    Returns:
        Merged ResponseIntel.
    """
    intel = ResponseIntel()

    for resp in responses:
        url = resp.get("url", "")
        hdrs = resp.get("headers") or {}
        body = resp.get("body") or resp.get("http_response") or ""
        status = resp.get("status_code")

        if hdrs:
            analyze_response_headers(hdrs, url=url, intel=intel)
        if body:
            analyze_response_body(body, url=url, intel=intel)

        # Status-based signals
        if status == 500:
            intel.error_disclosures.append({
                "tech": "unknown",
                "description": "Internal Server Error (500)",
                "evidence_snippet": f"HTTP 500 at {url}",
                "url": url,
            })

    # Deduplicate
    seen_errors: set[str] = set()
    deduped_errors: list[dict[str, str]] = []
    for err in intel.error_disclosures:
        key = f"{err['tech']}:{err['description']}:{err['url']}"
        if key not in seen_errors:
            seen_errors.add(key)
            deduped_errors.append(err)
    intel.error_disclosures = deduped_errors

    seen_hdrs: set[str] = set()
    deduped_hdrs: list[dict[str, str]] = []
    for hdr in intel.interesting_headers:
        key = f"{hdr['header']}:{hdr['url']}"
        if key not in seen_hdrs:
            seen_hdrs.add(key)
            deduped_hdrs.append(hdr)
    intel.interesting_headers = deduped_hdrs

    logger.info(
        f"Response intelligence: {len(intel.technologies)} techs, "
        f"{len(intel.error_disclosures)} errors, "
        f"{len(intel.interesting_headers)} interesting headers"
    )
    return intel
