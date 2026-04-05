"""
ResponseValidator — Centralized HTTP response validation for security checkers.

Phase 1.1 of the Revolution Plan.

Most custom checkers share common false-positive patterns:
  - 302/301 redirects treated as successful probe hits
  - WAF/CDN block pages (403/406/429) with body content matching signatures
  - SPA catch-all pages (200 for every path, identical body)
  - Generic HTML error pages misinterpreted as API responses
  - Login/auth redirects masking actual content

ResponseValidator provides a single call that every checker can use BEFORE
creating a Finding, eliminating these classes of FP at the source.

Usage:
    from src.utils.response_validator import ResponseValidator, ValidationResult

    rv = ResponseValidator()
    result = rv.validate(status_code, headers, body, expected_content_type="json")
    if not result.is_valid:
        return []  # Don't create finding — response is not meaningful

    # For host-profile-aware validation:
    result = rv.validate(
        status_code, headers, body,
        expected_content_type="json",
        host_profile=host_profile_dict,
    )
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from loguru import logger


# ---------------------------------------------------------------------------
# Known WAF / CDN block page signatures
# ---------------------------------------------------------------------------

_WAF_BODY_SIGNATURES: list[tuple[str, str]] = [
    # (signature_substring, waf_name)
    ("attention required! | cloudflare", "cloudflare"),
    ("cf-error-details", "cloudflare"),
    ("ray id:", "cloudflare"),
    ("checking your browser", "cloudflare"),
    ("please turn javascript on", "cloudflare"),
    ("access denied | ", "akamai"),
    ("reference #", "akamai"),
    ("ak-reference", "akamai"),
    ("access denied - sucuri", "sucuri"),
    ("sucuri website firewall", "sucuri"),
    ("powered by sucuri", "sucuri"),
    ("403 forbidden", "generic_waf"),
    ("request blocked", "generic_waf"),
    ("web application firewall", "generic_waf"),
    ("mod_security", "modsecurity"),
    ("not acceptable!", "modsecurity"),
    ("imperva", "imperva"),
    ("incapsula", "incapsula"),
    ("f5 big-ip", "f5"),
    ("the requested url was rejected", "f5"),
    ("your request has been blocked", "generic_waf"),
    ("this request has been blocked by", "generic_waf"),
    ("error 1005", "cloudflare"),     # Access denied
    ("error 1006", "cloudflare"),     # Access denied
    ("error 1015", "cloudflare"),     # Rate limited
    ("error 1020", "cloudflare"),     # Access denied
]

_WAF_HEADER_SIGNATURES: dict[str, str] = {
    "cf-ray": "cloudflare",
    "cf-chl-bypass": "cloudflare",
    "x-sucuri-id": "sucuri",
    "x-sucuri-cache": "sucuri",
    "x-cdn": "cdn",
    "server: akamaighost": "akamai",
    "x-akamai-transformed": "akamai",
    "x-iinfo": "incapsula",
    "x-cdn-geo": "imperva",
}

# ---------------------------------------------------------------------------
# Login / auth redirect indicators
# ---------------------------------------------------------------------------

_AUTH_REDIRECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/login", re.IGNORECASE),
    re.compile(r"/signin", re.IGNORECASE),
    re.compile(r"/auth", re.IGNORECASE),
    re.compile(r"/sso", re.IGNORECASE),
    re.compile(r"/oauth", re.IGNORECASE),
    re.compile(r"/cas/login", re.IGNORECASE),
    re.compile(r"/saml", re.IGNORECASE),
    re.compile(r"/account/login", re.IGNORECASE),
    re.compile(r"/users/sign_in", re.IGNORECASE),
    re.compile(r"return_to=", re.IGNORECASE),
    re.compile(r"redirect_uri=", re.IGNORECASE),
    re.compile(r"next=.*login", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Common SPA / generic HTML indicators
# ---------------------------------------------------------------------------

_SPA_BODY_INDICATORS: list[str] = [
    "<div id=\"root\">",
    "<div id=\"app\">",
    "<div id=\"__next\">",
    "<div id=\"__nuxt\">",
    "window.__INITIAL_STATE__",
    "window.__NUXT__",
    "window.__NEXT_DATA__",
    "<noscript>you need to enable javascript",
    "ng-app=",
    "data-reactroot",
]

_HTML_STARTS: tuple[str, ...] = (
    "<!doctype",
    "<html",
    "<!DOCTYPE",
    "<HTML",
)

# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    """Result of response validation."""

    is_valid: bool
    """Whether the response represents meaningful content worth analyzing."""

    rejection_reason: str = ""
    """Why the response was rejected (empty if valid)."""

    is_redirect: bool = False
    """Response is a 3xx redirect."""

    is_waf_block: bool = False
    """Response appears to be a WAF/CDN block page."""

    waf_name: str = ""
    """Detected WAF/CDN name if is_waf_block."""

    is_auth_redirect: bool = False
    """Response redirects to a login/auth page."""

    is_spa_catchall: bool = False
    """Response appears to be SPA catch-all (same page for all paths)."""

    is_error_page: bool = False
    """Response is a generic error page (404 custom, 500, etc.)."""

    is_html_for_data_endpoint: bool = False
    """Response is HTML but endpoint expected JSON/XML/data."""

    confidence_modifier: float = 0.0
    """Suggested confidence adjustment for findings from this response.
    Negative = reduce confidence, positive = increase."""

    details: dict[str, Any] = field(default_factory=dict)
    """Additional validation details for debugging."""


# ---------------------------------------------------------------------------
# ResponseValidator
# ---------------------------------------------------------------------------


class ResponseValidator:
    """Centralized HTTP response validation for security checkers.

    Call ``validate()`` before creating a Finding to filter out common
    false-positive-generating response patterns.
    """

    # Class-level body hash cache for SPA catch-all detection
    _baseline_hashes: dict[str, str] = {}

    def set_baseline(self, host: str, body: str) -> None:
        """Register a baseline body hash for SPA catch-all detection."""
        self._baseline_hashes[host] = _body_hash(body)

    def validate(
        self,
        status_code: int,
        headers: dict[str, str] | None = None,
        body: str = "",
        *,
        expected_content_type: str | None = None,
        host_profile: dict[str, Any] | None = None,
        baseline_body: str | None = None,
        url: str = "",
    ) -> ValidationResult:
        """Validate an HTTP response for meaningful content.

        Args:
            status_code: HTTP response status code.
            headers: Response headers (case-insensitive matching applied).
            body: Response body text (first few KB is sufficient).
            expected_content_type: What the checker expects ("json", "xml",
                "text", "html", or None for any).
            host_profile: HostIntelProfile.to_dict() for this host, if available.
            baseline_body: Homepage/baseline body for catch-all comparison.
            url: The URL that was requested (for logging/context).

        Returns:
            ValidationResult with is_valid=True if response is worth analyzing.
        """
        headers = headers or {}
        body = body or ""
        # Normalize header keys to lowercase for consistent matching
        h_lower = {k.lower(): v for k, v in headers.items()}
        body_lower = body[:5000].lower() if body else ""

        # ── Check 1: Redirect responses ──
        if 300 <= status_code < 400:
            location = h_lower.get("location", "")
            is_auth = _is_auth_redirect(location)
            return ValidationResult(
                is_valid=False,
                rejection_reason=f"redirect_{status_code}"
                + (f" to auth ({location[:80]})" if is_auth else ""),
                is_redirect=True,
                is_auth_redirect=is_auth,
                confidence_modifier=-20.0 if is_auth else -15.0,
                details={"status_code": status_code, "location": location[:200]},
            )

        # ── Check 1b: Not-Found responses (v4.0) ──
        # 404/410 mean the resource does not exist — never a vulnerability
        # indicator for any checker.  A custom 404 page that contains
        # interesting data (stack trace, debug info) would be better caught
        # by a dedicated info-disclosure check, not injected findings.
        if status_code in (404, 410):
            return ValidationResult(
                is_valid=False,
                rejection_reason=f"not_found_{status_code}",
                is_error_page=True,
                confidence_modifier=-20.0,
                details={"status_code": status_code},
            )

        # ── Check 1c: Authentication-Required responses (V26) ──
        # 401 Unauthorized / 407 Proxy Authentication Required indicate
        # the endpoint is behind authentication.  Without valid credentials
        # any "finding" from these responses is noise (e.g. cloud_checker
        # matching "PASSWORD" in a Basic Auth challenge page).
        if status_code in (401, 407):
            www_auth = h_lower.get("www-authenticate", "")
            auth_scheme = ""
            if www_auth:
                auth_scheme = www_auth.split()[0].lower() if www_auth.split() else ""
            return ValidationResult(
                is_valid=False,
                rejection_reason=f"auth_required_{status_code}"
                + (f" ({auth_scheme})" if auth_scheme else ""),
                is_auth_redirect=True,
                confidence_modifier=-20.0,
                details={
                    "status_code": status_code,
                    "www_authenticate": www_auth[:200],
                    "auth_scheme": auth_scheme,
                },
            )

        # ── Check 2: WAF / CDN block pages ──
        waf_from_headers = _detect_waf_headers(h_lower)
        waf_from_body = _detect_waf_body(body_lower) if body_lower else ""
        is_waf_status = status_code in (403, 406, 429, 503)

        if is_waf_status and (waf_from_headers or waf_from_body):
            waf_name = waf_from_headers or waf_from_body
            return ValidationResult(
                is_valid=False,
                rejection_reason=f"waf_block_{status_code} ({waf_name})",
                is_waf_block=True,
                waf_name=waf_name,
                confidence_modifier=-25.0,
                details={"status_code": status_code, "waf": waf_name},
            )

        # Softer WAF signal: WAF headers present even on 200
        # (don't reject, but note it for confidence adjustment)
        _waf_soft = waf_from_headers or waf_from_body
        _waf_soft_modifier = -5.0 if _waf_soft else 0.0

        # ── Check 3: Server error pages ──
        if status_code >= 500:
            # 500s might contain useful stack traces — only reject generic ones
            has_stack_trace = any(
                pat in body_lower
                for pat in (
                    "traceback", "stack trace", "exception", "at line",
                    "syntax error", "fatal error", "debug",
                    "java.lang.", "org.apache.", "microsoft.asp",
                )
            )
            if not has_stack_trace:
                return ValidationResult(
                    is_valid=False,
                    rejection_reason=f"server_error_{status_code}_no_stack_trace",
                    is_error_page=True,
                    confidence_modifier=-15.0,
                    details={"status_code": status_code},
                )
            # Stack trace present — valid for error-based detection
            # but lower confidence since it's an error state

        # ── Check 4: Content-type mismatch ──
        content_type = h_lower.get("content-type", "")
        if expected_content_type and content_type:
            is_html = "text/html" in content_type
            expects_data = expected_content_type in ("json", "xml", "text")

            if expects_data and is_html:
                # HTML response for a data endpoint — likely catch-all/error page
                # Don't auto-reject if body has real content indicators
                if _looks_like_generic_html(body_lower):
                    return ValidationResult(
                        is_valid=False,
                        rejection_reason="html_for_data_endpoint",
                        is_html_for_data_endpoint=True,
                        confidence_modifier=-15.0,
                        details={
                            "expected": expected_content_type,
                            "actual": content_type,
                        },
                    )

        # ── Check 5: SPA catch-all detection ──
        # Compare body hash with baseline — if identical for different paths,
        # the server returns the same page for all routes (SPA catch-all)
        _baseline_hash: str | None = None
        if baseline_body is not None:
            _baseline_hash = _body_hash(baseline_body)
        elif url:
            # Fallback: use stored baseline from set_baseline()
            from urllib.parse import urlparse
            _bh_host = urlparse(url).netloc
            _baseline_hash = self._baseline_hashes.get(_bh_host)
        if _baseline_hash is not None and body:
            current_hash = _body_hash(body)
            if _baseline_hash == current_hash and len(body) > 100:
                return ValidationResult(
                    is_valid=False,
                    rejection_reason="spa_catchall_identical_body",
                    is_spa_catchall=True,
                    confidence_modifier=-20.0,
                    details={"body_hash": current_hash},
                )

        # Also check SPA body indicators
        if body_lower and _has_spa_indicators(body_lower):
            # Content-type is HTML and body has SPA markers
            ct = content_type.lower()
            if "html" in ct or not ct:
                # Check if it's the only content (no real API data)
                body_stripped = body.strip()
                if body_stripped.startswith(("<", "<!")) and expected_content_type in (
                    "json", "xml", "text",
                ):
                    return ValidationResult(
                        is_valid=False,
                        rejection_reason="spa_html_for_data_endpoint",
                        is_spa_catchall=True,
                        confidence_modifier=-15.0,
                        details={"spa_indicators": True},
                    )

        # ── Check 6: Host profile context ──
        hp_modifier = 0.0
        if host_profile:
            ht = host_profile.get("host_type", "")
            if ht == "cdn_only":
                hp_modifier = -10.0
            elif ht == "static_site" and expected_content_type in (
                "json", "xml",
            ):
                hp_modifier = -8.0
            elif ht == "redirect_host":
                hp_modifier = -5.0
            elif ht == "auth_gated" and status_code in (200, 403):
                # Auth-gated but we got a response — could be public endpoint
                # or could be generic rejection
                hp_modifier = -3.0

        # ── Check 7: Empty / tiny body ──
        if expected_content_type in ("json", "xml") and len(body.strip()) < 3:
            return ValidationResult(
                is_valid=False,
                rejection_reason="empty_body_for_data_endpoint",
                confidence_modifier=-10.0,
                details={"body_length": len(body.strip())},
            )

        # ── All checks passed — response is valid ──
        total_modifier = _waf_soft_modifier + hp_modifier
        return ValidationResult(
            is_valid=True,
            confidence_modifier=total_modifier,
            details={
                "status_code": status_code,
                "content_type": content_type[:50],
                "body_length": len(body),
                "waf_detected": _waf_soft or "",
            },
        )

    def validate_for_checker(
        self,
        status_code: int,
        headers: dict[str, str] | None = None,
        body: str = "",
        *,
        checker_name: str = "",
        expected_content_type: str | None = None,
        host_profile: dict[str, Any] | None = None,
        baseline_body: str | None = None,
        url: str = "",
    ) -> ValidationResult:
        """Convenience wrapper that logs rejection for a checker.

        Same as validate() but logs a DEBUG message when a response is rejected.
        """
        result = self.validate(
            status_code,
            headers,
            body,
            expected_content_type=expected_content_type,
            host_profile=host_profile,
            baseline_body=baseline_body,
            url=url,
        )
        if not result.is_valid and checker_name:
            logger.debug(
                f"ResponseValidator rejected for {checker_name}: "
                f"{result.rejection_reason} | url={url[:80]}"
            )
        return result


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _body_hash(text: str) -> str:
    """Compute a stable hash of response body, ignoring whitespace variation."""
    normalized = re.sub(r"\s+", " ", text.strip())
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _is_auth_redirect(location: str) -> bool:
    """Check if a redirect Location points to an auth endpoint."""
    if not location:
        return False
    return any(pat.search(location) for pat in _AUTH_REDIRECT_PATTERNS)


def _detect_waf_headers(h_lower: dict[str, str]) -> str:
    """Detect WAF from response headers. Returns WAF name or empty string."""
    for hdr_key, waf_name in _WAF_HEADER_SIGNATURES.items():
        if ":" in hdr_key:
            # "server: akamaighost" — check header value
            key, val = hdr_key.split(":", 1)
            if val.strip() in h_lower.get(key.strip(), "").lower():
                return waf_name
        else:
            if hdr_key in h_lower:
                return waf_name
    return ""


def _detect_waf_body(body_lower: str) -> str:
    """Detect WAF from response body signatures. Returns WAF name or empty."""
    for sig, waf_name in _WAF_BODY_SIGNATURES:
        if sig in body_lower:
            return waf_name
    return ""


def _looks_like_generic_html(body_lower: str) -> bool:
    """Check if body looks like a generic HTML page (not API content)."""
    if not body_lower:
        return False
    # Must start like HTML
    stripped = body_lower.lstrip()
    if not stripped.startswith(("<!doctype", "<html", "<!doc")):
        return False
    # Look for common HTML-only patterns
    html_indicators = (
        "<head>", "<title>", "<body>", "<meta ", "<link ",
        "<script src=", "<div class=", "stylesheet",
    )
    return sum(1 for ind in html_indicators if ind in body_lower) >= 2


def _has_spa_indicators(body_lower: str) -> bool:
    """Check if response body has SPA framework indicators."""
    return any(ind.lower() in body_lower for ind in _SPA_BODY_INDICATORS)


# ---------------------------------------------------------------------------
# Convenience functions for common checker patterns
# ---------------------------------------------------------------------------


def is_meaningful_response(
    status_code: int,
    headers: dict[str, str] | None = None,
    body: str = "",
    expected_content_type: str | None = None,
) -> bool:
    """Quick check: is this response worth creating a finding from?

    Usage:
        resp = await client.get(url)
        if not is_meaningful_response(resp.status_code, dict(resp.headers), resp.text, "json"):
            return  # Skip this endpoint
    """
    rv = ResponseValidator()
    return rv.validate(
        status_code, headers, body,
        expected_content_type=expected_content_type,
    ).is_valid


def reject_reason(
    status_code: int,
    headers: dict[str, str] | None = None,
    body: str = "",
    expected_content_type: str | None = None,
) -> str:
    """Return rejection reason or empty string if response is valid."""
    rv = ResponseValidator()
    result = rv.validate(
        status_code, headers, body,
        expected_content_type=expected_content_type,
    )
    return result.rejection_reason
