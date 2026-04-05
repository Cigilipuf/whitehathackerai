"""
WhiteHatHacker AI — Katana Wrapper

ProjectDiscovery Katana — Next-generation crawling and spidering framework.
Crawls targets to discover endpoints, JavaScript, forms, and API routes.
"""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


def _resolve_katana_binary() -> str:
    """Resolve the Go katana binary, preferring ~/go/bin."""
    go_bin = os.path.expanduser("~/go/bin/katana")
    if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
        return go_bin
    # Alternate Go location
    alt = "/usr/local/go/bin/katana"
    if os.path.isfile(alt) and os.access(alt, os.X_OK):
        return alt
    # Fallback to PATH
    import shutil
    path = shutil.which("katana")
    return path or "katana"


class KatanaWrapper(SecurityTool):
    """
    Katana — Next-gen web crawler (ProjectDiscovery).

    Crawls target to discover:
      - Endpoints (links, forms, JS-extracted URLs)
      - API routes
      - Parameters
      - JavaScript files
    """

    name = "katana"
    category = ToolCategory.RECON_WEB
    description = "Next-generation web crawling and spidering framework"
    binary_name = "katana"
    requires_root = False
    risk_level = RiskLevel.LOW  # Active crawling
    default_timeout = 900  # aggressive profile uses up to 900s internally

    def __init__(self) -> None:
        super().__init__()
        self.binary_name = _resolve_katana_binary()
        self._binary_path = self.binary_name

    def is_available(self) -> bool:
        """Check Go katana binary exists."""
        if os.path.isfile(self.binary_name) and os.access(self.binary_name, os.X_OK):
            return True
        import shutil
        return shutil.which("katana") is not None

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = {
            ScanProfile.STEALTH: 300,
            ScanProfile.BALANCED: 600,
            ScanProfile.AGGRESSIVE: 900,
        }.get(profile, 600)

        stdout, stderr, exit_code = await self.execute_command(
            command, timeout=options.get("timeout", timeout),
        )

        # Katana writes results to stdout and progress/errors to stderr.
        # Combine for robust parsing — JSON lines may appear in either stream.
        combined = stdout
        if stderr:
            combined = stdout + "\n" + stderr

        findings = self.parse_output(combined, target)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0 or len(findings) > 0),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            command=" ".join(command),
            target=target,
        )

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}
        if isinstance(target, list):
            target = target[0] if target else ""
        url = target if target.startswith("http") else f"https://{target}"
        cmd = [self.binary_name, "-u", url]

        # JSON output for structured parsing — omit response bodies to prevent
        # 100MB+ stdout (katana JSONL includes full bodies by default)
        cmd.extend(["-jsonl", "-omit-body", "-omit-raw"])

        # Silent mode (suppress banner)
        cmd.append("-silent")

        # Profile-specific settings (options can override depth)
        # NOTE: options["timeout"] controls the EXTERNAL process timeout only.
        # Katana's -timeout flag (per-request) always uses profile defaults.
        opt_depth = str(options.get("depth", ""))

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-depth", opt_depth or "2", "-rate-limit", "2",
                            "-timeout", "30", "-concurrency", "5",
                            "-delay", "2", "-crawl-duration", "30s"])
            case ScanProfile.BALANCED:
                cmd.extend(["-depth", opt_depth or "2", "-rate-limit", "10",
                            "-timeout", "15", "-concurrency", "10",
                            "-crawl-duration", "60s"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-depth", opt_depth or "4", "-rate-limit", "50",
                            "-timeout", "10", "-concurrency", "25",
                            "-crawl-duration", "120s"])

        # JavaScript crawling (extracts endpoints from JS files)
        if options.get("js_crawl", True):
            cmd.append("-js-crawl")

        # Headless browser mode
        if options.get("headless", False):
            cmd.append("-headless")

        # Scope: auto-scope to same domain by default
        if options.get("scope_filter", True):
            cmd.extend(["-fs", "dn"])  # filter scope = domain name

        # Custom headers
        if "headers" in options:
            for k, v in options["headers"].items():
                cmd.extend(["-H", f"{k}: {v}"])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen_urls: set[str] = set()

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            url = ""
            endpoint_type = "endpoint"
            source = "crawl"
            method = "GET"
            metadata: dict[str, Any] = {}

            # Try JSON parsing first (katana -jsonl output)
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    url = data.get("request", {}).get("endpoint", "")
                    if not url:
                        url = data.get("endpoint", data.get("url", ""))
                    source = data.get("source", "crawl")
                    method = data.get("request", {}).get("method", "GET")
                    endpoint_type = data.get("type", "endpoint")
                    metadata = {
                        "source": source,
                        "method": method,
                        "type": endpoint_type,
                        "status_code": data.get("response", {}).get("status_code", 0),
                    }
                except json.JSONDecodeError:
                    continue
            else:
                # Plain URL line
                url = line

            if not url or not url.startswith("http"):
                continue

            # Deduplicate
            normalized = url.split("?")[0].split("#")[0].rstrip("/")
            if normalized in seen_urls:
                continue
            seen_urls.add(normalized)

            # Classify finding
            parsed = urlparse(url)
            tags = ["crawl", "endpoint", f"source:{source}"]

            if parsed.path.endswith((".js", ".mjs")):
                tags.append("javascript")
                endpoint_type = "javascript"
            elif parsed.path.endswith((".json", ".xml", ".yaml", ".yml")):
                tags.append("config_file")
            elif any(seg in parsed.path.lower() for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
                tags.append("api_endpoint")
                endpoint_type = "api"
            if parsed.query:
                tags.append("has_params")

            findings.append(Finding(
                title=f"Endpoint: {url[:120]}",
                description=f"Discovered via {source}: {method} {url}",
                vulnerability_type="endpoint_discovery",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=target,
                endpoint=url,
                tool_name=self.name,
                tags=tags,
                metadata=metadata,
            ))

        logger.debug(f"katana parsed {len(findings)} endpoints for {target}")
        return findings


__all__ = ["KatanaWrapper"]
