"""
WhiteHatHacker AI — Source Map Extractor (V7-T2-5)

JavaScript dosyalarından source map (.map) referanslarını bulur,
indirir, orijinal kaynak kodu çıkarır ve secret/endpoint/API key tarar.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

_SOURCEMAP_COMMENT_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)",
)
_SOURCEMAP_HEADER = "SourceMap"  # or X-SourceMap (older)

# Patterns to look for in extracted source code
_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "api_key": re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""", re.I),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "password": re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]""", re.I),
    "internal_url": re.compile(r"https?://(?:localhost|127\.0\.0\.1|10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01]))[^\s\"']*"),
    "graphql_endpoint": re.compile(r"""['"](/graphql|/api/graphql|/gql)['"]"""),
    "admin_path": re.compile(r"""['"](/admin[^'"]*|/dashboard[^'"]*|/internal[^'"]*)['"]"""),
}


class SourceMapExtractor(SecurityTool):
    """
    Find and download JavaScript source maps, extract original source
    code, and scan for secrets, API endpoints, and internal paths.
    """

    name = "sourcemap_extractor"
    category = ToolCategory.RECON_WEB
    description = "JavaScript source map extractor and analyzer"
    binary_name = ""
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        return True

    async def run(
        self, target: str, options: dict[str, Any] | None = None,
        profile: ScanProfile | None = None,
    ) -> ToolResult:
        options = options or {}
        js_urls: list[str] = options.get("js_urls", [])
        max_download: int = options.get("max_download_mb", 5)

        if not js_urls:
            js_urls = await self._discover_js_urls(target)

        sourcemaps_found: list[dict[str, Any]] = []
        all_secrets: list[dict[str, Any]] = []
        all_endpoints: list[str] = []
        findings: list[Finding] = []

        for js_url in js_urls:
            map_url = await self._find_sourcemap_url(js_url)
            if not map_url:
                continue

            logger.debug(f"[sourcemap] Found map: {map_url}")
            source_files = await self._download_and_extract(map_url, max_download * 1024 * 1024)
            if not source_files:
                continue

            sourcemaps_found.append({
                "js_url": js_url,
                "map_url": map_url,
                "source_count": len(source_files),
            })

            # Scan extracted sources for secrets
            for filename, content in source_files.items():
                for secret_name, pattern in _SECRET_PATTERNS.items():
                    for match in pattern.finditer(content):
                        all_secrets.append({
                            "type": secret_name,
                            "file": filename,
                            "match": match.group(0)[:200],
                            "map_url": map_url,
                        })

                # Extract API endpoints
                for ep_match in re.finditer(r"""['"](/api/[^'"]+)['"]""", content):
                    all_endpoints.append(ep_match.group(1))

        if sourcemaps_found:
            findings.append(Finding(
                title=f"Source maps exposed: {len(sourcemaps_found)} JS files",
                severity=SeverityLevel.MEDIUM,
                confidence=90,
                target=target,
                description=(
                    "Exposed source maps allow access to original source code.\n\n"
                    + "\n".join(f"  - {sm['js_url']} → {sm['map_url']} ({sm['source_count']} files)"
                               for sm in sourcemaps_found)
                ),
                evidence={"sourcemaps": sourcemaps_found},
                tool_name=self.name,
            ))

        if all_secrets:
            findings.append(Finding(
                title=f"Secrets in source maps: {len(all_secrets)} found",
                severity=SeverityLevel.HIGH,
                confidence=75,
                target=target,
                description="Secrets found in extracted source code:\n" + "\n".join(
                    f"  - [{s['type']}] {s['file']}: {s['match'][:80]}"
                    for s in all_secrets[:20]
                ),
                evidence={"secrets": all_secrets[:50]},
                tool_name=self.name,
            ))

        if all_endpoints:
            unique_eps = sorted(set(all_endpoints))
            findings.append(Finding(
                title=f"API endpoints in source maps: {len(unique_eps)} found",
                severity=SeverityLevel.LOW,
                confidence=80,
                target=target,
                description="API endpoints extracted:\n" + "\n".join(f"  - {e}" for e in unique_eps[:30]),
                evidence={"endpoints": unique_eps},
                tool_name=self.name,
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=json.dumps(sourcemaps_found, indent=2),
            findings=findings,
            metadata={
                "sourcemaps": sourcemaps_found,
                "secrets_count": len(all_secrets),
                "endpoints_count": len(set(all_endpoints)),
            },
        )

    async def _discover_js_urls(self, target: str) -> list[str]:
        """Fetch the target page and extract <script src=...> URLs."""
        base_url = target if target.startswith("http") else f"https://{target}"
        js_urls: list[str] = []
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.get(base_url)
                for match in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text):
                    src = match.group(1)
                    full_url = urljoin(str(resp.url), src)
                    js_urls.append(full_url)
        except Exception as exc:
            logger.warning(f"[sourcemap] JS discovery failed: {exc}")
        return js_urls

    async def _find_sourcemap_url(self, js_url: str) -> str | None:
        """Check for sourceMappingURL comment or SourceMap header."""
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.get(js_url)

                # Check header
                for hdr in ("SourceMap", "X-SourceMap"):
                    val = resp.headers.get(hdr, "")
                    if val:
                        return urljoin(js_url, val)

                # Check last 500 bytes for comment
                tail = resp.text[-500:] if len(resp.text) > 500 else resp.text
                m = _SOURCEMAP_COMMENT_RE.search(tail)
                if m:
                    map_ref = m.group(1)
                    if map_ref.startswith("data:"):
                        return None  # inline, skip
                    return urljoin(js_url, map_ref)

                # Try appending .map
                map_url = js_url + ".map"
                probe = await client.head(map_url)
                if probe.status_code == 200:
                    ct = probe.headers.get("content-type", "")
                    if "json" in ct or "octet" in ct:
                        return map_url
        except Exception as exc:
            logger.debug(f"[sourcemap] Failed to check {js_url}: {exc}")
        return None

    async def _download_and_extract(
        self, map_url: str, max_bytes: int,
    ) -> dict[str, str]:
        """Download source map and extract source files."""
        try:
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.get(map_url)
                if resp.status_code != 200 or len(resp.content) > max_bytes:
                    return {}

                data = resp.json()
                sources = data.get("sources", [])
                contents = data.get("sourcesContent", [])

                result: dict[str, str] = {}
                for i, src_name in enumerate(sources):
                    if i < len(contents) and contents[i]:
                        result[src_name] = contents[i]
                return result
        except Exception as exc:
            logger.debug(f"[sourcemap] Failed to extract {map_url}: {exc}")
            return {}

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []

    def build_command(self, target: str, options: dict | None = None, profile: ScanProfile | None = None) -> list[str]:
        return []
