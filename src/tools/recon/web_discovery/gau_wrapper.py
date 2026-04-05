"""
WhiteHatHacker AI — gau (GetAllUrls) Wrapper

gau — Fetch known URLs from AlienVault OTX, Wayback Machine,
Common Crawl, and URLScan for any given domain.
Passive URL collection — does NOT touch the target.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


def _resolve_gau_binary() -> str:
    """Resolve the Go gau binary, preferring ~/go/bin."""
    go_bin = os.path.expanduser("~/go/bin/gau")
    if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
        return go_bin
    alt = "/usr/local/go/bin/gau"
    if os.path.isfile(alt) and os.access(alt, os.X_OK):
        return alt
    import shutil
    path = shutil.which("gau")
    return path or "gau"


class GauWrapper(SecurityTool):
    """
    gau (GetAllUrls) — Passive URL collection.

    Fetches known URLs from multiple sources:
      - Wayback Machine
      - Common Crawl
      - AlienVault OTX
      - URLScan.io

    Purely passive — never contacts the target directly.
    """

    name = "gau"
    category = ToolCategory.RECON_WEB
    description = "Fetch known URLs from Wayback Machine, Common Crawl, OTX, URLScan"
    binary_name = "gau"
    requires_root = False
    risk_level = RiskLevel.SAFE  # Fully passive
    memory_limit = 256 * 1024 * 1024  # 256 MB — aggressive limit to prevent OOM

    def __init__(self) -> None:
        super().__init__()
        self.binary_name = _resolve_gau_binary()
        self._binary_path = self.binary_name

    def is_available(self) -> bool:
        """Check Go gau binary exists."""
        if os.path.isfile(self.binary_name) and os.access(self.binary_name, os.X_OK):
            return True
        import shutil
        return shutil.which("gau") is not None

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 120)

        # Set Go runtime memory limits to prevent OOM crashes.
        # GOMEMLIMIT (Go 1.19+) sets a soft memory limit; GOGC controls
        # GC aggressiveness (lower = more frequent GC = less peak memory).
        go_env = os.environ.copy()
        _mem_mb = self.memory_limit // (1024 * 1024)
        go_env["GOMEMLIMIT"] = f"{_mem_mb}MiB"
        go_env["GOGC"] = "25"

        stdout, stderr, exit_code = await self.execute_command(
            command, timeout=timeout, env=go_env,
        )

        # gau writes URLs to stdout and progress/errors to stderr.
        # Combine both — some versions write partial results to stderr
        # on network errors.
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
            metadata={"url_count": len(findings)},
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
        # gau takes bare domain (no http://)
        domain = target.replace("https://", "").replace("http://", "").rstrip("/")
        cmd = [self.binary_name, domain]

        # Providers — skip CommonCrawl by default (notoriously slow/hangy)
        providers = options.get("providers", None)
        if providers:
            cmd.extend(["--providers", ",".join(providers)])
        else:
            # Default: skip CommonCrawl for reliability
            match profile:
                case ScanProfile.AGGRESSIVE:
                    pass  # Use all providers including CommonCrawl
                case _:
                    cmd.extend(["--providers", "wayback,otx,urlscan"])

        # Per-request timeout to prevent hanging on slow APIs
        request_timeout = options.get("timeout", 15)
        cmd.extend(["--timeout", str(request_timeout)])

        # Date filters (YYYYMM format)
        if "from" in options:
            cmd.extend(["--from", str(options["from"])])
        if "to" in options:
            cmd.extend(["--to", str(options["to"])])

        # Profile-based thread/rate settings
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["--threads", "1"])
            case ScanProfile.BALANCED:
                cmd.extend(["--threads", "2"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["--threads", "5"])

        # Filter by file extensions (blacklist)
        blacklist = options.get("blacklist", None)
        if blacklist:
            cmd.extend(["--blacklist", ",".join(blacklist)])

        # Include subdomains
        if options.get("subs", False):
            cmd.append("--subs")

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen_urls: set[str] = set()

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue

            # Deduplicate by URL without fragment
            normalized = line.split("#")[0].rstrip("/")
            if normalized in seen_urls:
                continue
            seen_urls.add(normalized)

            # Classify the URL
            parsed = urlparse(line)
            tags = ["passive", "archive", "url_collection"]

            path_lower = parsed.path.lower()
            if path_lower.endswith((".js", ".mjs")):
                tags.append("javascript")
            elif path_lower.endswith((".json", ".xml", ".yaml", ".yml", ".config")):
                tags.append("config_file")
            elif path_lower.endswith((".sql", ".bak", ".old", ".backup", ".zip", ".tar.gz")):
                tags.append("sensitive_file")
            if parsed.query:
                tags.append("has_params")
            if any(seg in path_lower for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
                tags.append("api_endpoint")

            findings.append(Finding(
                title=f"Archive URL: {line[:120]}",
                description=f"Known URL from web archives: {line}",
                vulnerability_type="url_discovery",
                severity=SeverityLevel.INFO,
                confidence=80.0,
                target=target,
                endpoint=line,
                tool_name=self.name,
                tags=tags,
            ))

        logger.debug(f"gau parsed {len(findings)} URLs for {target}")
        return findings


__all__ = ["GauWrapper"]
