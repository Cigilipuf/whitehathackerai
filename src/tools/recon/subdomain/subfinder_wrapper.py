"""
WhiteHatHacker AI — Subfinder Wrapper

ProjectDiscovery Subfinder — Fast passive subdomain enumeration tool.
Uses multiple sources for passive subdomain discovery.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


def _resolve_subfinder_binary() -> str:
    """Resolve the Go subfinder binary, preferring ~/go/bin."""
    go_bin = os.path.expanduser("~/go/bin/subfinder")
    if os.path.isfile(go_bin):
        try:
            with open(go_bin, "rb") as f:
                magic = f.read(4)
            if magic == b"\x7fELF":
                return go_bin
        except OSError:
            pass
    # Fallback to PATH
    import shutil
    path = shutil.which("subfinder")
    return path or "subfinder"


class SubfinderWrapper(SecurityTool):
    """
    Subfinder — Fast passive subdomain enumeration.

    Uses certificate transparency logs, search engines, and other passive
    sources to discover subdomains without touching the target directly.
    """

    name = "subfinder"
    category = ToolCategory.RECON_SUBDOMAIN
    description = "Fast passive subdomain enumeration tool"
    binary_name = "subfinder"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self.binary_name = _resolve_subfinder_binary()
        self._binary_path = self.binary_name

    def is_available(self) -> bool:
        """Check Go subfinder binary exists."""
        if os.path.isfile(self.binary_name):
            try:
                with open(self.binary_name, "rb") as f:
                    magic = f.read(4)
                return magic == b"\x7fELF"
            except OSError:
                return False
        # Fallback: shutil.which
        import shutil
        return shutil.which(self.binary_name) is not None

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

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name,
            success=exit_code == 0,
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
        cmd = [self.binary_name, "-d", target, "-silent"]

        # JSON output for structured parsing
        if options.get("json", True):
            cmd.append("-json")

        # Profile-based settings
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-t", "5"])        # 5 threads
                cmd.extend(["-timeout", "60"])  # 60s per source
            case ScanProfile.BALANCED:
                cmd.extend(["-t", "10"])
                cmd.extend(["-timeout", "30"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-t", "30"])
                cmd.extend(["-timeout", "20"])
                cmd.append("-all")              # Use all sources

        # Custom source list
        if "sources" in options:
            cmd.extend(["-sources", ",".join(options["sources"])])

        # Exclude sources
        if "exclude_sources" in options:
            cmd.extend(["-es", ",".join(options["exclude_sources"])])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            subdomain = ""

            # Try JSON parsing first (subfinder -json output)
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    subdomain = data.get("host", "").strip().lower()
                    source = data.get("source", "unknown")
                except (json.JSONDecodeError, KeyError):
                    subdomain = line.strip().lower()
                    source = "unknown"
            else:
                subdomain = line.strip().lower()
                source = "unknown"

            if not subdomain or subdomain in seen:
                continue

            # Basic domain validation
            if not re.match(r"^[a-z0-9]([a-z0-9\-]*\.)+[a-z]{2,}$", subdomain):
                continue

            seen.add(subdomain)

            findings.append(Finding(
                title=f"Subdomain: {subdomain}",
                description=f"Discovered subdomain via {source}: {subdomain}",
                vulnerability_type="subdomain_discovery",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=subdomain,
                endpoint=subdomain,
                tool_name=self.name,
                tags=["subdomain", "recon", "passive"],
                metadata={"source": source},
            ))

        logger.debug(f"Subfinder discovered {len(findings)} subdomains for {target}")
        return findings


__all__ = ["SubfinderWrapper"]
