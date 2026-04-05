"""WhiteHatHacker AI — Context Verification Module.

Analyses the HTTP request/response context around a finding to determine
whether the vulnerability is genuine or a false positive caused by WAFs,
CDNs, load balancers, or application quirks.
"""

from __future__ import annotations

import re

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class HttpContext(BaseModel):
    """Captured HTTP context for a finding."""

    request_method: str = "GET"
    request_url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0.0


class ContextVerifyResult(BaseModel):
    """Result of context-based verification."""

    is_genuine: bool = False
    confidence: float = 50.0
    checks_passed: list[str] = Field(default_factory=list)
    checks_failed: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    waf_detected: bool = False
    waf_name: str = ""
    cdn_detected: bool = False
    cdn_name: str = ""
    reasoning: str = ""


# ---------------------------------------------------------------------------
# WAF / CDN signature database
# ---------------------------------------------------------------------------

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-apigw-id", "awselb"],
    "Akamai": ["x-akamai-transformed", "akamai-grn", "akamaighost"],
    "Imperva/Incapsula": ["x-iinfo", "incap_ses_", "visid_incap_"],
    "Sucuri": ["x-sucuri-id", "sucuri-", "sucuri"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info"],
    "Barracuda": ["barra_counter_session"],
    "Fortinet": ["fortiwafsid"],
}

CDN_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "Fastly": ["x-served-by", "x-cache", "fastly"],
    "Akamai": ["x-akamai-transformed"],
    "Varnish": ["x-varnish", "via: varnish"],
    "Nginx Cache": ["x-nginx-cache", "x-cache-status"],
}


# ---------------------------------------------------------------------------
# WAF block page patterns
# ---------------------------------------------------------------------------

WAF_BLOCK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"access\s+denied", re.I),
    re.compile(r"blocked\s+by\s+security", re.I),
    re.compile(r"web\s+application\s+firewall", re.I),
    re.compile(r"your\s+request\s+has\s+been\s+blocked", re.I),
    re.compile(r"error\s+reference\s+number", re.I),
    re.compile(r"incident\s+id", re.I),
    re.compile(r"please\s+enable\s+cookies", re.I),
    re.compile(r"challenge-platform", re.I),
    re.compile(r"captcha", re.I),
    re.compile(r"ray\s+id", re.I),
    re.compile(r"attention\s+required", re.I),
]


# ---------------------------------------------------------------------------
# Context Verifier
# ---------------------------------------------------------------------------

class ContextVerifier:
    """Analyse HTTP context to verify or refute a finding."""

    def __init__(self) -> None:
        self.waf_sigs = dict(WAF_SIGNATURES)
        self.cdn_sigs = dict(CDN_SIGNATURES)

    # ---- Main entry ------------------------------------------------------

    def verify(
        self,
        vuln_type: str,
        context: HttpContext,
        *,
        payload: str = "",
        expected_evidence: str = "",
    ) -> ContextVerifyResult:
        """Run context verification checks."""
        result = ContextVerifyResult()

        # 1. WAF detection
        self._check_waf(context, result)

        # 2. CDN detection
        self._check_cdn(context, result)

        # 3. WAF block page check
        self._check_waf_block(context, result)

        # 4. Status code analysis
        self._check_status_code(vuln_type, context, result)

        # 5. Payload reflection check
        if payload:
            self._check_payload_reflection(vuln_type, payload, context, result)

        # 6. Response anomaly check
        self._check_response_anomalies(context, result)

        # 7. Expected evidence check
        if expected_evidence:
            self._check_expected_evidence(expected_evidence, context, result)

        # Compute final verdict
        self._compute_verdict(result)

        logger.debug(
            f"Context verify [{vuln_type}]: genuine={result.is_genuine}, "
            f"confidence={result.confidence:.1f}, "
            f"passed={len(result.checks_passed)}, failed={len(result.checks_failed)}"
        )
        return result

    # ---- Individual checks -----------------------------------------------

    def _check_waf(self, ctx: HttpContext, result: ContextVerifyResult) -> None:
        """Detect WAF from response headers."""
        headers_lower = {k.lower(): v.lower() for k, v in ctx.response_headers.items()}
        all_headers_str = " ".join(f"{k}:{v}" for k, v in headers_lower.items())

        for waf_name, signatures in self.waf_sigs.items():
            for sig in signatures:
                if sig.lower() in all_headers_str:
                    result.waf_detected = True
                    result.waf_name = waf_name
                    result.warnings.append(f"WAF detected: {waf_name} (signature: {sig})")
                    return

    def _check_cdn(self, ctx: HttpContext, result: ContextVerifyResult) -> None:
        """Detect CDN from response headers."""
        headers_lower = {k.lower(): v.lower() for k, v in ctx.response_headers.items()}
        all_headers_str = " ".join(f"{k}:{v}" for k, v in headers_lower.items())

        for cdn_name, signatures in self.cdn_sigs.items():
            for sig in signatures:
                if sig.lower() in all_headers_str:
                    result.cdn_detected = True
                    result.cdn_name = cdn_name
                    result.warnings.append(f"CDN detected: {cdn_name}")
                    return

    @staticmethod
    def _check_waf_block(ctx: HttpContext, result: ContextVerifyResult) -> None:
        """Check if response is a WAF block page."""
        body = ctx.response_body
        if not body:
            return

        for pattern in WAF_BLOCK_PATTERNS:
            if pattern.search(body):
                result.checks_failed.append(
                    f"WAF block page detected (pattern: {pattern.pattern})"
                )
                result.warnings.append(
                    "Response appears to be a WAF block page — finding may be FP"
                )
                return

        result.checks_passed.append("No WAF block page detected")

    @staticmethod
    def _check_status_code(
        vuln_type: str, ctx: HttpContext, result: ContextVerifyResult
    ) -> None:
        """Validate status code is consistent with the vuln type."""
        status = ctx.response_status

        if status == 403:
            result.checks_failed.append(
                f"HTTP 403 — may indicate WAF block rather than real {vuln_type}"
            )
            return

        if status == 503:
            result.checks_failed.append("HTTP 503 — service unavailable or rate limited")
            return

        if vuln_type in ("sqli", "xss", "ssti", "lfi") and status == 200:
            result.checks_passed.append(f"HTTP {status} — consistent with {vuln_type}")
        elif vuln_type == "open_redirect" and status in (301, 302, 307, 308):
            result.checks_passed.append(f"HTTP {status} — redirect as expected")
        elif 200 <= status < 400:
            result.checks_passed.append(f"HTTP {status} — success range")
        else:
            result.warnings.append(f"HTTP {status} — unexpected for {vuln_type}")

    @staticmethod
    def _check_payload_reflection(
        vuln_type: str, payload: str, ctx: HttpContext,
        result: ContextVerifyResult,
    ) -> None:
        """Check whether the payload is reflected in the response body."""
        body = ctx.response_body
        if not body:
            result.warnings.append("Empty response body — cannot check reflection")
            return

        if payload in body:
            result.checks_passed.append("Payload reflected verbatim in response body")
            return

        # Check for encoded versions
        import html as html_lib
        encoded = html_lib.escape(payload)
        if encoded in body and encoded != payload:
            result.checks_failed.append(
                "Payload reflected but HTML-encoded — likely not exploitable"
            )
            return

        # URL-encoded check
        from urllib.parse import quote
        url_encoded = quote(payload)
        if url_encoded in body and url_encoded != payload:
            result.warnings.append("Payload reflected URL-encoded")
            return

        if vuln_type in ("xss", "ssti"):
            result.checks_failed.append("Payload NOT reflected in response body")
        else:
            result.warnings.append("Payload not found in response (may be blind/indirect)")

    @staticmethod
    def _check_response_anomalies(
        ctx: HttpContext, result: ContextVerifyResult
    ) -> None:
        """Check for response anomalies."""
        # Very short response
        if ctx.response_body and len(ctx.response_body) < 50:
            result.warnings.append(
                f"Very short response ({len(ctx.response_body)} bytes) — may be error page"
            )

        # Extremely long response time might indicate time-based injection
        if ctx.response_time_ms > 10000:
            result.checks_passed.append(
                f"Long response time ({ctx.response_time_ms:.0f}ms) — may confirm time-based vuln"
            )

        # Generic error pages
        body_lower = ctx.response_body.lower() if ctx.response_body else ""
        error_patterns = ["internal server error", "500 error", "application error",
                          "something went wrong", "an error occurred"]
        for pattern in error_patterns:
            if pattern in body_lower:
                result.warnings.append(
                    f"Generic error pattern '{pattern}' in response — may be unrelated"
                )
                break

    @staticmethod
    def _check_expected_evidence(
        expected: str, ctx: HttpContext, result: ContextVerifyResult
    ) -> None:
        """Check if expected evidence string is present in response."""
        if expected in (ctx.response_body or ""):
            result.checks_passed.append("Expected evidence found in response")
        else:
            result.checks_failed.append("Expected evidence NOT found in response")

    @staticmethod
    def _compute_verdict(result: ContextVerifyResult) -> None:
        """Compute final is_genuine and confidence from accumulated checks."""
        passed = len(result.checks_passed)
        failed = len(result.checks_failed)
        warnings = len(result.warnings)
        total = passed + failed + max(warnings * 0.5, 0)

        if total == 0:
            result.confidence = 50.0
            result.is_genuine = False
            result.reasoning = "Insufficient context data for verification"
            return

        # Base confidence from pass/fail ratio
        if passed + failed > 0:
            ratio = passed / (passed + failed)
        else:
            ratio = 0.5

        confidence = ratio * 100.0

        # Warning penalty
        confidence -= warnings * 5.0

        # WAF penalty
        if result.waf_detected:
            confidence -= 15.0

        confidence = max(5.0, min(95.0, confidence))
        result.confidence = round(confidence, 1)
        result.is_genuine = confidence >= 55.0

        parts = [f"Passed {passed} checks, failed {failed}, {warnings} warnings."]
        if result.waf_detected:
            parts.append(f"WAF ({result.waf_name}) detected — confidence penalised.")
        if result.cdn_detected:
            parts.append(f"CDN ({result.cdn_name}) in use.")
        result.reasoning = " ".join(parts)
