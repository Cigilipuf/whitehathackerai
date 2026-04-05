"""
WhiteHatHacker AI — waybackurls Wrapper

waybackurls — Fetch all URLs that the Wayback Machine knows about for a domain.
Passive URL collection — does NOT touch the target.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


def _resolve_waybackurls_binary() -> str:
    """Resolve the Go waybackurls binary, preferring ~/go/bin."""
    go_bin = os.path.expanduser("~/go/bin/waybackurls")
    if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
        return go_bin
    alt = "/usr/local/go/bin/waybackurls"
    if os.path.isfile(alt) and os.access(alt, os.X_OK):
        return alt
    import shutil
    path = shutil.which("waybackurls")
    return path or "waybackurls"


class WaybackurlsWrapper(SecurityTool):
    """
    waybackurls — Wayback Machine URL fetcher.

    Reads a domain from arguments/stdin and outputs all known URLs from
    the Wayback Machine's CDX API.  Purely passive.

    Note: waybackurls reads the domain from stdin when no argument is
    given.  We pass it as a positional argument (supported since v0.1.0)
    or pipe via stdin for older versions.
    """

    name = "waybackurls"
    category = ToolCategory.RECON_WEB
    description = "Fetch all known URLs from the Wayback Machine for a domain"
    binary_name = "waybackurls"
    requires_root = False
    risk_level = RiskLevel.SAFE  # Fully passive
    memory_limit = 256 * 1024 * 1024  # 256 MB — aggressive limit to prevent OOM

    def __init__(self) -> None:
        super().__init__()
        self.binary_name = _resolve_waybackurls_binary()
        self._binary_path = self.binary_name

    def is_available(self) -> bool:
        """Check Go waybackurls binary exists."""
        if os.path.isfile(self.binary_name) and os.access(self.binary_name, os.X_OK):
            return True
        import shutil
        return shutil.which("waybackurls") is not None

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
        go_env = os.environ.copy()
        _mem_mb = self.memory_limit // (1024 * 1024)
        go_env["GOMEMLIMIT"] = f"{_mem_mb}MiB"
        go_env["GOGC"] = "25"

        # waybackurls accepts the domain from stdin in older versions.
        # We use echo <domain> | waybackurls as a reliable fallback.
        # However, build_command passes domain as positional arg (newer).
        stdout, stderr, exit_code = await self.execute_command(
            command, timeout=timeout, env=go_env,
        )

        # waybackurls writes URLs to stdout and errors/progress to stderr.
        # Combine both for robust parsing.
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
        # Strip scheme — waybackurls expects bare domain
        domain = target.replace("https://", "").replace("http://", "").rstrip("/")
        cmd = [self.binary_name, domain]

        # Include timestamps in output
        if options.get("dates", False):
            cmd.append("-dates")

        # Do not include subdomains (default includes them)
        if options.get("no_subs", False):
            cmd.append("-no-subs")

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen_urls: set[str] = set()

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Handle -dates format: "YYYYMMDDHHMMSS url"
            url = line
            timestamp = ""
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit() and len(parts[0]) >= 8:
                timestamp = parts[0]
                url = parts[1].strip()

            if not url.startswith("http"):
                continue

            # Deduplicate
            normalized = url.split("#")[0].rstrip("/")
            if normalized in seen_urls:
                continue
            seen_urls.add(normalized)

            # Classify
            parsed = urlparse(url)
            tags = ["passive", "wayback", "archive"]

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

            metadata: dict[str, Any] = {}
            if timestamp:
                metadata["wayback_timestamp"] = timestamp

            findings.append(Finding(
                title=f"Wayback URL: {url[:120]}",
                description=f"URL known to Wayback Machine: {url}",
                vulnerability_type="url_discovery",
                severity=SeverityLevel.INFO,
                confidence=80.0,
                target=target,
                endpoint=url,
                tool_name=self.name,
                tags=tags,
                metadata=metadata,
            ))

        logger.debug(f"waybackurls parsed {len(findings)} URLs for {target}")
        return findings


__all__ = ["WaybackurlsWrapper"]
