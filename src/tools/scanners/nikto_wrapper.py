"""
WhiteHatHacker AI — Nikto Wrapper

Web server scanner: outdated software, dangerous files, misconfigurations.
Comprehensive web server vulnerability scanning.
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class NiktoWrapper(SecurityTool):
    """
    Nikto — Web server vulnerability scanner.

    6,700+ tests for dangerous files, outdated server software,
    version-specific problems, server configuration issues.
    """

    name = "nikto"
    category = ToolCategory.SCANNER
    description = "Web server scanner — dangerous files, outdated versions, misconfigurations"
    binary_name = "nikto"
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
        timeout = {
            ScanProfile.STEALTH: 300,
            ScanProfile.BALANCED: 240,
            ScanProfile.AGGRESSIVE: 120,
        }.get(profile, 240)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        # Nikto may write findings to stderr; also exits non-zero when finding vulns
        combined = stdout + "\n" + stderr if stderr else stdout
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
        # Auto-detect HTTPS: use https:// if no scheme and port 443 or host has SSL
        if target.startswith("http"):
            url = target
        elif options.get("ssl") or options.get("port") == 443:
            url = f"https://{target}"
        else:
            url = f"https://{target}"  # Default to HTTPS for web targets

        cmd = [self.binary_name, "-h", url]

        # Nikto needs explicit -ssl flag for HTTPS URLs
        if url.startswith("https://"):
            cmd.append("-ssl")

        # Use plain text output to stdout (more reliable in subprocess).
        # For JSON, nikto needs a real file path; -output - with -Format json
        # produces unreliable/empty output. Text parsing works well.

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-Pause", "3", "-maxtime", "180s"])
            case ScanProfile.BALANCED:
                cmd.extend(["-maxtime", "120s"])  # Max 2 minutes per target
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-maxtime", "300s"])

        if "port" in options:
            cmd.extend(["-port", str(options["port"])])
        if "ssl" in options and options["ssl"] and "-ssl" not in cmd:
            cmd.append("-ssl")
        if "tuning" in options:
            cmd.extend(["-Tuning", options["tuning"]])

        cmd.append("-nointeractive")

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # JSON parse denemesi
        try:
            data = json.loads(raw_output)
            if isinstance(data, dict):
                return self._parse_json_output(data, target)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        findings.extend(self._parse_json_output(item, target))
                return findings
        except json.JSONDecodeError:
            pass

        # Text parse fallback
        # + OSVDB-XXXXX: /path: Description
        # + /path: Description
        nikto_pattern = re.compile(
            r"\+\s+(?:OSVDB-(\d+):\s+)?(/\S*)?:?\s+(.+)",
            re.MULTILINE,
        )

        for match in nikto_pattern.finditer(raw_output):
            osvdb = match.group(1) or ""
            path = match.group(2) or ""
            description = match.group(3).strip()

            # Bilgi satırlarını atla
            if any(skip in description.lower() for skip in [
                "target ip:", "target hostname:", "target port:",
                "start time:", "end time:", "host(s) tested",
            ]):
                continue

            severity = self._assess_severity(description, path, osvdb)

            tags = ["nikto", "web_server"]
            if osvdb:
                tags.append(f"OSVDB-{osvdb}")

            findings.append(Finding(
                title=f"Nikto: {description[:80]}",
                description=description,
                vulnerability_type=self._categorize_finding(description),
                severity=severity,
                confidence=30.0,  # Nikto FP rate is very high — unverified findings
                target=target,
                endpoint=f"{target}{path}" if path else target,
                tool_name=self.name,
                tags=[*tags, "unverified"],
                evidence=f"OSVDB-{osvdb}" if osvdb else "",
            ))

        logger.debug(f"nikto parsed {len(findings)} findings")
        return findings

    def _parse_json_output(self, data: dict, target: str) -> list[Finding]:
        """Nikto JSON çıktısını parse et."""
        # Strip Perl ARRAY() reference leaks from nikto output
        _PERL_ARRAY_RE = re.compile(r"ARRAY\(0x[0-9a-fA-F]+\)\s*")
        findings: list[Finding] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            osvdb = str(vuln.get("OSVDB", ""))
            method = vuln.get("method", "GET")
            url = vuln.get("url", "")
            msg = _PERL_ARRAY_RE.sub("", vuln.get("msg", "")).strip()

            severity = self._assess_severity(msg, url, osvdb)

            findings.append(Finding(
                title=f"Nikto: {msg[:80]}",
                description=f"{msg} | Method: {method} | URL: {url}",
                vulnerability_type=self._categorize_finding(msg),
                severity=severity,
                confidence=30.0,  # Nikto FP rate is very high — unverified findings
                target=target,
                endpoint=url or target,
                tool_name=self.name,
                tags=(["nikto", f"OSVDB-{osvdb}", "unverified"] if osvdb else ["nikto", "unverified"]),
                metadata={"method": method, "osvdb": osvdb},
            ))

        return findings

    @staticmethod
    def _assess_severity(desc: str, path: str, osvdb: str) -> SeverityLevel:
        desc_lower = desc.lower()
        critical_keywords = ["remote code execution", "rce", "shell upload", "backdoor"]
        high_keywords = ["sql injection", "xss", "directory traversal", "lfi", "rfi", "xxe"]
        medium_keywords = ["information disclosure", "default credentials", "admin panel", "phpinfo"]
        low_keywords = ["missing header", "server version", "allowed methods"]

        for kw in critical_keywords:
            if kw in desc_lower:
                return SeverityLevel.CRITICAL
        for kw in high_keywords:
            if kw in desc_lower:
                return SeverityLevel.HIGH
        for kw in medium_keywords:
            if kw in desc_lower:
                return SeverityLevel.MEDIUM
        for kw in low_keywords:
            if kw in desc_lower:
                return SeverityLevel.LOW
        return SeverityLevel.INFO

    @staticmethod
    def _categorize_finding(desc: str) -> str:
        desc_lower = desc.lower()
        if "sql" in desc_lower:
            return "sql_injection"
        if "xss" in desc_lower:
            return "xss_reflected"
        if "directory" in desc_lower or "listing" in desc_lower:
            return "information_disclosure"
        if "header" in desc_lower:
            return "misconfiguration"
        if "version" in desc_lower or "outdated" in desc_lower:
            return "outdated_software"
        return "web_server_finding"


__all__ = ["NiktoWrapper"]
