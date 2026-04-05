"""
WhiteHatHacker AI — GoSpider Wrapper

GoSpider — Fast web spider written in Go.
Crawls websites for URLs, subdomains, JavaScript files, forms, etc.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


def _resolve_gospider_binary() -> str:
    """Resolve the Go gospider binary, preferring ~/go/bin."""
    go_bin = os.path.expanduser("~/go/bin/gospider")
    if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
        return go_bin
    alt = "/usr/local/go/bin/gospider"
    if os.path.isfile(alt) and os.access(alt, os.X_OK):
        return alt
    import shutil
    path = shutil.which("gospider")
    return path or "gospider"


class GoSpiderWrapper(SecurityTool):
    """
    GoSpider — Fast web spidering.

    Discovers:
      - Links (internal/external)
      - JavaScript files
      - Form actions
      - Subdomains (from crawled pages)
      - AWS S3 buckets
      - URL parameters
    """

    name = "gospider"
    category = ToolCategory.RECON_WEB
    description = "Fast web spider — discovers endpoints, JS files, links, subdomains"
    binary_name = "gospider"
    requires_root = False
    risk_level = RiskLevel.LOW
    default_timeout = 600  # aggressive profile can use up to 900s internally

    def __init__(self) -> None:
        super().__init__()
        self.binary_name = _resolve_gospider_binary()
        self._binary_path = self.binary_name

    def is_available(self) -> bool:
        """Check Go gospider binary exists."""
        if os.path.isfile(self.binary_name) and os.access(self.binary_name, os.X_OK):
            return True
        import shutil
        return shutil.which("gospider") is not None

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

        # GoSpider writes discovered URLs to stdout and progress/errors to
        # stderr.  Combine both streams for robust parsing — tagged lines
        # like "[url]", "[linkfinder]" may appear in either.
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
        cmd = [self.binary_name, "-s", url]

        # Quiet mode (suppress banner)
        cmd.append("-q")

        # Allow options dict to override depth
        opt_depth = str(options.get("depth", "")) if options.get("depth") else ""

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-d", opt_depth or "2", "-c", "3", "--delay", "2",
                            "-t", "5", "--timeout", "30"])
            case ScanProfile.BALANCED:
                cmd.extend(["-d", opt_depth or "3", "-c", "5", "-t", "10",
                            "--timeout", "15"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-d", opt_depth or "5", "-c", "10", "-t", "20",
                            "--timeout", "10"])

        # Include other sources
        if options.get("include_subs", False):
            cmd.append("--include-subs")

        if options.get("include_other_source", True):
            cmd.append("--other-source")

        # Robots.txt / sitemap
        if options.get("sitemap", True):
            cmd.append("--sitemap")

        # Custom headers
        if "headers" in options:
            for k, v in options["headers"].items():
                cmd.extend(["-H", f"{k}: {v}"])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        """
        Parse GoSpider output.

        GoSpider output lines are tagged:
          [url] - https://example.com/page
          [href] - https://example.com/other
          [javascript] - https://example.com/app.js
          [linkfinder] - https://example.com/api/v1/users
          [form] - https://example.com/login (POST)
          [robots] - https://example.com/admin/
          [aws-s3] - https://bucket.s3.amazonaws.com
          [subdomains] - sub.example.com
        Or plain URLs without tags.
        """
        findings: list[Finding] = []
        seen_urls: set[str] = set()

        # Pattern: [tag] - URL
        tag_pattern = re.compile(r"^\[(\w[\w\-]*)\]\s*-\s*(.+)$")

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            tag = "url"
            url = ""

            match = tag_pattern.match(line)
            if match:
                tag = match.group(1).lower()
                url = match.group(2).strip()
            elif line.startswith("http"):
                url = line
            else:
                # Skip non-URL lines (progress messages, etc.)
                continue

            if not url:
                continue

            # Deduplicate
            normalized = url.split("?")[0].split("#")[0].rstrip("/")
            if normalized in seen_urls:
                continue
            seen_urls.add(normalized)

            # Build tags & classify
            tags = ["spider", f"source:{tag}"]
            vuln_type = "endpoint_discovery"

            if tag == "javascript":
                tags.append("javascript")
            elif tag == "linkfinder":
                tags.append("js_extracted")
            elif tag == "form":
                tags.append("form")
            elif tag == "aws-s3":
                tags.append("s3_bucket")
                vuln_type = "cloud_asset"
            elif tag == "subdomains":
                tags.append("subdomain")
                vuln_type = "subdomain_discovery"
            elif tag == "robots":
                tags.append("robots_txt")

            parsed = urlparse(url)
            if parsed.query:
                tags.append("has_params")
            if any(seg in parsed.path.lower() for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
                tags.append("api_endpoint")

            findings.append(Finding(
                title=f"[{tag}] {url[:120]}",
                description=f"GoSpider discovered ({tag}): {url}",
                vulnerability_type=vuln_type,
                severity=SeverityLevel.INFO,
                confidence=85.0,
                target=target,
                endpoint=url,
                tool_name=self.name,
                tags=tags,
                metadata={"tag": tag},
            ))

        logger.debug(f"gospider parsed {len(findings)} findings for {target}")
        return findings


__all__ = ["GoSpiderWrapper"]
