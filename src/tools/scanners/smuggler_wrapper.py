"""
WhiteHatHacker AI — Smuggler Wrapper

HTTP Request Smuggling / Desync attack detection tool.
Tests for CL.TE, TE.CL, and TE.TE smuggling vulnerabilities.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# Smuggling technique → severity / confidence
_TECHNIQUE_SEVERITY: dict[str, SeverityLevel] = {
    "CL.TE": SeverityLevel.HIGH,
    "TE.CL": SeverityLevel.HIGH,
    "TE.TE": SeverityLevel.HIGH,
    "CL.0": SeverityLevel.MEDIUM,
    "H2.CL": SeverityLevel.HIGH,
    "H2.TE": SeverityLevel.HIGH,
}

_TECHNIQUE_CONFIDENCE: dict[str, float] = {
    "CL.TE": 80.0,
    "TE.CL": 80.0,
    "TE.TE": 75.0,
    "CL.0": 65.0,
    "H2.CL": 80.0,
    "H2.TE": 80.0,
}


class SmugglerWrapper(SecurityTool):
    """
    Smuggler — HTTP Request Smuggling Detection.

    Detects HTTP request smuggling / desync vulnerabilities by testing
    various techniques: CL.TE, TE.CL, TE.TE, CL.0, H2.CL, H2.TE.
    These vulnerabilities can lead to cache poisoning, credential
    hijacking, and access-control bypass.
    """

    name = "smuggler"
    category = ToolCategory.SCANNER
    description = "HTTP request smuggling / desync detection tool"
    binary_name = "python3"
    requires_root = False
    risk_level = RiskLevel.HIGH

    # Path to smuggler.py script (configurable via options)
    _default_script = "smuggler.py"

    # ── run ───────────────────────────────────────────────────
    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 300)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)
        findings = self.parse_output(stdout + "\n" + stderr, target)

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

    # ── build_command ─────────────────────────────────────────
    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}

        script = options.get("script_path", self._default_script)
        cmd = [self.binary_name, script]

        # Target URL
        cmd.extend(["-u", target])

        # Input file (list of URLs)
        if options.get("list_file"):
            cmd.extend(["-l", options["list_file"]])

        # HTTP method
        method = options.get("method")
        if method:
            cmd.extend(["-m", method.upper()])

        # Timeout per request
        req_timeout = options.get("request_timeout")
        if req_timeout:
            cmd.extend(["-t", str(req_timeout)])

        # Quiet mode
        if options.get("quiet", False):
            cmd.append("-q")

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["-H", h])

        # Proxy
        if options.get("proxy"):
            cmd.extend(["--proxy", options["proxy"]])

        # Specific techniques to test
        if options.get("techniques"):
            cmd.extend(["--techniques", options["techniques"]])

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                # Slow and careful — single threaded, low timeout
                cmd.extend(["-t", "10", "-q"])
            case ScanProfile.BALANCED:
                # Moderate pace
                cmd.extend(["-t", "5"])
            case ScanProfile.AGGRESSIVE:
                # Full speed, all techniques
                pass  # default aggressive behaviour

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        seen: set[str] = set()

        # Patterns for smuggler output
        # Typical: "[VULNERABLE] CL.TE on https://example.com"
        #          "Potential request smuggling: TE.CL"
        vuln_re = re.compile(
            r"\[?VULN(?:ERABLE)?\]?\s*(?:[-:])?\s*(CL\.TE|TE\.CL|TE\.TE|CL\.0|H2\.CL|H2\.TE)\b",
            re.IGNORECASE,
        )
        potential_re = re.compile(
            r"(?:potential|possible|detected)\s+.*?"
            r"(CL\.TE|TE\.CL|TE\.TE|CL\.0|H2\.CL|H2\.TE)",
            re.IGNORECASE,
        )
        url_re = re.compile(r"(https?://\S+)", re.IGNORECASE)

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            technique: str | None = None
            is_confirmed = False

            # Check for confirmed vulnerability
            m = vuln_re.search(line)
            if m:
                technique = m.group(1).upper()
                is_confirmed = True

            # Check for potential vulnerability
            if not technique:
                m = potential_re.search(line)
                if m:
                    technique = m.group(1).upper()
                    is_confirmed = False

            # Also check for plain "VULNERABLE" keyword with technique nearby
            if not technique and re.search(r"VULNERABLE", line, re.IGNORECASE):
                tech_match = re.search(
                    r"(CL\.TE|TE\.CL|TE\.TE|CL\.0|H2\.CL|H2\.TE)",
                    line, re.IGNORECASE,
                )
                if tech_match:
                    technique = tech_match.group(1).upper()
                    is_confirmed = True

            if not technique:
                continue

            # Extract URL
            url_match = url_re.search(line)
            url = url_match.group(1) if url_match else target

            dedup_key = f"{technique}:{url}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = _TECHNIQUE_SEVERITY.get(technique, SeverityLevel.HIGH)
            confidence = _TECHNIQUE_CONFIDENCE.get(technique, 70.0)
            if not is_confirmed:
                confidence -= 15.0  # lower confidence for "potential"

            findings.append(Finding(
                title=f"HTTP Request Smuggling ({technique}): {url[:100]}",
                description=(
                    f"Smuggler detected {'confirmed' if is_confirmed else 'potential'} "
                    f"HTTP request smuggling vulnerability using {technique} technique "
                    f"at {url}. This can lead to cache poisoning, credential hijacking, "
                    f"WAF bypass, and access-control bypass."
                ),
                vulnerability_type="http_request_smuggling",
                severity=severity,
                confidence=confidence,
                target=target,
                endpoint=url,
                evidence=line[:500],
                tool_name=self.name,
                cwe_id="CWE-444",
                tags=["smuggling", "desync", technique.lower().replace(".", "_")],
                metadata={
                    "technique": technique,
                    "confirmed": is_confirmed,
                    "raw_line": line[:500],
                },
            ))

        logger.debug(f"smuggler parsed {len(findings)} findings")
        return findings


__all__ = ["SmugglerWrapper"]
