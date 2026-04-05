"""
WhiteHatHacker AI — WhatWeb Wrapper

Web technology fingerprinter: CMS, framework, server, plugin detection.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class WhatWebWrapper(SecurityTool):
    """
    WhatWeb — Web technology identification.

    Detects CMS, frameworks, JavaScript libs, web servers,
    embedded devices, version numbers, email addresses.
    """

    name = "whatweb"
    category = ToolCategory.RECON_TECH
    description = "Web technology fingerprinter — CMS, framework, library detection"
    binary_name = "whatweb"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def __init__(self) -> None:
        super().__init__()
        self._resolve_binary()

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=1200)

        # WhatWeb writes JSON to stdout via --log-json=- but may also emit
        # partial results or warnings to stderr; combine for robust parsing.
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
        cmd = [self.binary_name]

        # Agresiflik seviyesi (1=stealth, 3=aggressive, 4=heavy)
        aggression = {
            ScanProfile.STEALTH: "1",
            ScanProfile.BALANCED: "1",
            ScanProfile.AGGRESSIVE: "3",
        }.get(profile, "1")
        cmd.extend(["-a", aggression])

        # JSON çıktı
        cmd.extend(["--log-json=-"])

        # URL ekle
        if isinstance(target, list):
            target = target[0] if target else ""
        url = target if target.startswith("http") else f"http://{target}"
        cmd.append(url)

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("target", target)
            plugins = data.get("plugins", {})

            for plugin_name, plugin_data in plugins.items():
                version_list = plugin_data.get("version", [])
                version = version_list[0] if version_list else ""
                string_list = plugin_data.get("string", [])

                description = f"Technology detected: {plugin_name}"
                if version:
                    description += f" v{version}"
                if string_list:
                    description += f" ({', '.join(str(s) for s in string_list[:3])})"

                tags = ["tech_detect", f"tech:{plugin_name.lower()}"]
                if version:
                    tags.append(f"version:{version}")

                findings.append(Finding(
                    title=f"Tech: {plugin_name}" + (f" {version}" if version else ""),
                    description=description,
                    vulnerability_type="tech_detection",
                    severity=SeverityLevel.INFO,
                    confidence=90.0,
                    target=url,
                    endpoint=url,
                    tool_name=self.name,
                    tags=tags,
                    metadata={
                        "technology": plugin_name,
                        "version": version,
                        "strings": string_list[:5],
                    },
                ))

        logger.debug(f"whatweb parsed {len(findings)} findings")
        return findings


__all__ = ["WhatWebWrapper"]
