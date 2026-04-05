"""
WhiteHatHacker AI — ParamSpider Wrapper

Mining parameters from web archives (Wayback Machine, CommonCrawl, etc.).
Passive reconnaissance tool — no active requests to target.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class ParamspiderWrapper(SecurityTool):
    """
    ParamSpider — Web Archive Parameter Miner.

    Passively extracts URLs with parameters from web archives
    (Wayback Machine, CommonCrawl, etc.). No active requests are sent
    to the target, making this a safe reconnaissance tool.
    """

    name = "paramspider"
    category = ToolCategory.SCANNER
    description = "Mining parameters from web archives (passive)"
    binary_name = "paramspider"
    requires_root = False
    risk_level = RiskLevel.SAFE

    # ── run ───────────────────────────────────────────────────
    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 180)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code == 0),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            findings=findings,
            command=" ".join(command),
            target=target,
        )

    # ── build_command ─────────────────────────────────────────
    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}

        # Extract domain from URL if full URL is given
        domain = target
        if "://" in target:
            domain = urlparse(target).hostname or target

        cmd = [self.binary_name, "-d", domain]

        # Exclude common static file extensions to reduce noise
        exclude = options.get(
            "exclude",
            "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot",
        )
        cmd.extend(["--exclude", exclude])

        # Crawl level
        level = options.get("level")
        if level:
            cmd.extend(["--level", str(level)])

        # Output file
        if options.get("output_file"):
            cmd.extend(["-o", options["output_file"]])

        # Placeholder string
        if options.get("placeholder"):
            cmd.extend(["-p", options["placeholder"]])

        # Profile-specific tuning (ParamSpider is largely passive so
        # profiles mainly affect output filtering / level depth)
        match profile:
            case ScanProfile.STEALTH:
                if not level:
                    cmd.extend(["--level", "shallow"])
            case ScanProfile.BALANCED:
                pass  # defaults are fine
            case ScanProfile.AGGRESSIVE:
                if not level:
                    cmd.extend(["--level", "high"])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        seen_params: set[str] = set()
        url_re = re.compile(r"https?://\S+\?[^\s]+", re.IGNORECASE)

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Skip banner / info lines
            if line.startswith(("[", "#", "=")):
                continue

            # Find URLs with query parameters
            match = url_re.search(line)
            url = match.group(0) if match else (line if "?" in line else None)
            if not url:
                continue

            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
            except Exception as _exc:
                logger.debug(f"paramspider wrapper error: {_exc}")
                continue

            for param_name in params:
                if param_name in seen_params:
                    continue
                seen_params.add(param_name)

                findings.append(Finding(
                    title=f"Archived Parameter Discovered: {param_name}",
                    description=(
                        f"ParamSpider found parameter '{param_name}' in web "
                        f"archives for {target}. Example URL: {url[:300]}"
                    ),
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.INFO,
                    confidence=55.0,
                    target=target,
                    endpoint=url[:500],
                    parameter=param_name,
                    tool_name=self.name,
                    cwe_id="CWE-200",
                    tags=["parameter_discovery", "passive", "web_archive"],
                    metadata={
                        "example_url": url[:500],
                        "source": "web_archive",
                    },
                ))

        logger.debug(
            f"paramspider parsed {len(findings)} unique parameters "
            f"from {len(raw_output.splitlines())} lines"
        )
        return findings


__all__ = ["ParamspiderWrapper"]
