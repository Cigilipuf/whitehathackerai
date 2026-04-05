"""
WhiteHatHacker AI — WPScan Wrapper

WordPress vulnerability scanner: plugins, themes, users, vulnerabilities.
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class WpscanWrapper(SecurityTool):
    """
    WPScan — WordPress Security Scanner.

    Plugin, theme, user enum + known vulnerability matching.
    """

    name = "wpscan"
    category = ToolCategory.SCANNER
    description = "WordPress vulnerability scanner — plugins, themes, users"
    binary_name = "wpscan"
    requires_root = False
    risk_level = RiskLevel.LOW

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 600)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout, target)

        return ToolResult(
            tool_name=self.name,
            success=exit_code in (0, 5),  # 5 = vulns found
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
        url = target if target.startswith("http") else f"http://{target}"

        cmd = [self.binary_name, "--url", url, "--format", "json", "--no-banner"]

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["--throttle", "3000"])
                cmd.extend(["--enumerate", "vp"])  # Sadece vulnerable plugins
            case ScanProfile.BALANCED:
                cmd.extend(["--enumerate", "vp,vt,u1-20"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["--enumerate", "ap,at,u1-50"])
                cmd.extend(["--plugins-detection", "aggressive"])

        if "api_token" in options:
            cmd.extend(["--api-token", options["api_token"]])

        cmd.extend(["--random-user-agent", "--disable-tls-checks"])
        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return self._parse_text_output(raw_output, target)

        # WordPress version
        wp_version = data.get("version", {})
        if wp_version:
            ver = wp_version.get("number", "unknown")
            status = wp_version.get("status", "")
            severity = SeverityLevel.LOW if status == "outdated" else SeverityLevel.INFO

            findings.append(Finding(
                title=f"WordPress {ver} ({status})",
                description=f"WordPress version: {ver} | Status: {status}",
                vulnerability_type="tech_detection",
                severity=severity,
                confidence=95.0,
                target=target,
                tool_name=self.name,
                tags=["wordpress", "version"],
                metadata=wp_version,
            ))

            # Version-specific vulns
            for vuln in wp_version.get("vulnerabilities", []):
                findings.append(self._vuln_to_finding(vuln, target))

        # Plugins
        plugins = data.get("plugins", {})
        for plugin_name, plugin_data in plugins.items():
            ver = plugin_data.get("version", {}).get("number", "unknown")
            findings.append(Finding(
                title=f"WP Plugin: {plugin_name} {ver}",
                description=f"WordPress plugin detected: {plugin_name} v{ver}",
                vulnerability_type="tech_detection",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=target,
                tool_name=self.name,
                tags=["wordpress", "plugin", f"plugin:{plugin_name}"],
            ))
            for vuln in plugin_data.get("vulnerabilities", []):
                findings.append(self._vuln_to_finding(vuln, target, f"Plugin: {plugin_name}"))

        # Themes
        themes = data.get("themes", data.get("main_theme", {}))
        if isinstance(themes, dict):
            for theme_name, theme_data in themes.items():
                if not isinstance(theme_data, dict):
                    continue
                for vuln in theme_data.get("vulnerabilities", []):
                    findings.append(self._vuln_to_finding(vuln, target, f"Theme: {theme_name}"))

        # Users
        users = data.get("users", {})
        for username, user_data in users.items():
            findings.append(Finding(
                title=f"WP User: {username}",
                description=f"WordPress user enumerated: {username}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.LOW,
                confidence=85.0,
                target=target,
                tool_name=self.name,
                tags=["wordpress", "user", "enum"],
                metadata=user_data,
            ))

        logger.debug(f"wpscan parsed {len(findings)} findings")
        return findings

    def _vuln_to_finding(self, vuln: dict, target: str, context: str = "") -> Finding:
        title = vuln.get("title", "Unknown Vulnerability")
        references = []
        for ref_type, ref_list in vuln.get("references", {}).items():
            if isinstance(ref_list, list):
                references.extend(ref_list)

        cvss = vuln.get("cvss", {})
        cvss_score = cvss.get("score")
        severity = SeverityLevel.MEDIUM
        if cvss_score:
            score = float(cvss_score)
            if score >= 9.0:
                severity = SeverityLevel.CRITICAL
            elif score >= 7.0:
                severity = SeverityLevel.HIGH
            elif score >= 4.0:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW

        return Finding(
            title=f"WP Vuln: {title}",
            description=f"{context} — {title}" if context else title,
            vulnerability_type="known_vulnerability",
            severity=severity,
            confidence=80.0,
            target=target,
            tool_name=self.name,
            tags=["wordpress", "vuln", "known_cve"],
            references=references,
            cvss_score=float(cvss_score) if cvss_score else None,
            metadata=vuln,
        )

    def _parse_text_output(self, output: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        vuln_pattern = re.compile(r"\|\s+Title:\s+(.+)")
        for match in vuln_pattern.finditer(output):
            findings.append(Finding(
                title=f"WP Vuln: {match.group(1).strip()}",
                description=match.group(1).strip(),
                vulnerability_type="known_vulnerability",
                severity=SeverityLevel.MEDIUM,
                confidence=70.0,
                target=target,
                tool_name=self.name,
                tags=["wordpress", "vuln"],
            ))
        return findings


__all__ = ["WpscanWrapper"]
