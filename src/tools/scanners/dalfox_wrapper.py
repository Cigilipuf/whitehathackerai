"""
WhiteHatHacker AI — Dalfox Wrapper

Go-based XSS vulnerability scanner.
Reflected, Stored, DOM-based XSS detection with parameter analysis.
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# Dalfox finding type → human-readable label
_TYPE_MAP: dict[str, str] = {
    "G": "Grepping (potential)",
    "R": "Reflected XSS",
    "V": "Verified XSS",
}

_TYPE_SEVERITY: dict[str, SeverityLevel] = {
    "G": SeverityLevel.LOW,
    "R": SeverityLevel.MEDIUM,
    "V": SeverityLevel.HIGH,
}

_TYPE_CONFIDENCE: dict[str, float] = {
    "G": 20.0,   # Grepping — passive match, very high FP risk (v5.0-P3.2)
    "R": 60.0,   # Reflected — dalfox verified reflection (lowered v5.0-P3.2)
    "V": 80.0,   # Verified — dalfox confirmed execution (lowered v5.0-P3.2)
}


class DalfoxWrapper(SecurityTool):
    """
    Dalfox — Parameter Analysis and XSS Scanning tool.

    Fast Go-based scanner supporting reflected, stored, and DOM-based XSS
    detection with automatic parameter mining and payload generation.
    """

    name = "dalfox"
    category = ToolCategory.SCANNER
    description = "Go-based XSS vulnerability scanner with parameter analysis"
    binary_name = "dalfox"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    # ── run ───────────────────────────────────────────────────
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

        # dalfox url <target> or dalfox file <file>
        if options.get("list_file"):
            cmd = [self.binary_name, "file", options["list_file"]]
        elif options.get("pipe"):
            # pipe mode handled externally; build url mode as fallback
            cmd = [self.binary_name, "url", target]
        else:
            cmd = [self.binary_name, "url", target]

        # Silence banner noise, request JSON output
        cmd.append("--silence")
        cmd.extend(["--format", "json"])

        # Output file
        if options.get("output_file"):
            cmd.extend(["--output", options["output_file"]])

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["--header", h])

        # Cookie
        if options.get("cookie"):
            cmd.extend(["--cookie", options["cookie"]])

        # Data (POST body)
        if options.get("data"):
            cmd.extend(["--data", options["data"]])

        # Custom payloads file
        if options.get("custom_payload"):
            cmd.extend(["--custom-payload", options["custom_payload"]])

        # Blind XSS callback
        if options.get("blind"):
            cmd.extend(["--blind", options["blind"]])

        # Mining (parameter discovery)
        if options.get("mining_dict"):
            cmd.append("--mining-dict")
        if options.get("mining_dom"):
            cmd.append("--mining-dom")

        # Proxy
        if options.get("proxy"):
            cmd.extend(["--proxy", options["proxy"]])

        # User-Agent
        if options.get("user_agent"):
            cmd.extend(["--user-agent", options["user_agent"]])

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend([
                    "--delay", "2000",
                    "--timeout", "30",
                ])
            case ScanProfile.BALANCED:
                cmd.extend([
                    "--delay", "500",
                    "--timeout", "15",
                    "--worker", "5",
                ])
            case ScanProfile.AGGRESSIVE:
                cmd.extend([
                    "--timeout", "10",
                    "--worker", "20",
                    "--follow-redirects",
                ])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON parsing first (--format json output)
            try:
                data = json.loads(line)
                finding = self._parse_json_line(data, target)
                if finding:
                    findings.append(finding)
                continue
            except json.JSONDecodeError:
                pass

            # Fallback: plain-text output parsing
            finding = self._parse_plain_line(line, target)
            if finding:
                findings.append(finding)

        logger.debug(f"dalfox parsed {len(findings)} findings")
        return findings

    # ── JSON line parser ──────────────────────────────────────
    def _parse_json_line(self, data: dict[str, Any], target: str) -> Finding | None:
        finding_type = data.get("type", "")        # G / R / V
        payload_url = data.get("data", "")          # Full URL with payload
        payload = data.get("payload", "")
        param = data.get("param", "")
        evidence = data.get("evidence", "")
        cwe = data.get("cwe", "CWE-79")
        severity_str = data.get("severity", "")

        if not finding_type and not payload:
            return None

        label = _TYPE_MAP.get(finding_type, "XSS Finding")
        severity = _TYPE_SEVERITY.get(finding_type, SeverityLevel.MEDIUM)
        confidence = _TYPE_CONFIDENCE.get(finding_type, 60.0)

        # Override severity if dalfox supplies one
        if severity_str:
            severity = self._map_severity(severity_str)

        vuln_type = self._classify_xss(payload, evidence)

        return Finding(
            title=f"XSS ({label}): {param or target}",
            description=(
                f"Dalfox detected {label} in parameter '{param}'. "
                f"Payload URL: {payload_url}"
            ),
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            target=target,
            endpoint=payload_url,
            parameter=param,
            payload=payload,
            evidence=evidence[:1000] if evidence else "",
            tool_name=self.name,
            cwe_id=cwe if cwe else "CWE-79",
            tags=["xss", vuln_type, f"dalfox_{finding_type}"],
            metadata={
                "dalfox_type": finding_type,
                "payload_url": payload_url,
            },
        )

    # ── Plain-text line parser ────────────────────────────────
    def _parse_plain_line(self, line: str, target: str) -> Finding | None:
        # Pattern: [POC][V] or [POC][R] or [POC][G] followed by payload URL
        poc_re = re.compile(
            r"\[POC\]\[([GRV])\]\s*(.*)",
            re.IGNORECASE,
        )
        m = poc_re.search(line)
        if m:
            finding_type = m.group(1).upper()
            payload_url = m.group(2).strip()
            label = _TYPE_MAP.get(finding_type, "XSS Finding")
            severity = _TYPE_SEVERITY.get(finding_type, SeverityLevel.MEDIUM)
            confidence = _TYPE_CONFIDENCE.get(finding_type, 60.0)

            return Finding(
                title=f"XSS ({label})",
                description=f"Dalfox detected {label}. Payload: {payload_url[:300]}",
                vulnerability_type="xss_reflected",
                severity=severity,
                confidence=confidence,
                target=target,
                endpoint=payload_url,
                payload=payload_url,
                tool_name=self.name,
                cwe_id="CWE-79",
                tags=["xss", f"dalfox_{finding_type}"],
            )

        # Pattern: [*] Vulnerable parameter detected
        vuln_re = re.compile(
            r"\[\*\]\s*(?:Vulnerable|Found)\s+.*?parameter[:\s]+['\"]?(\S+)['\"]?",
            re.IGNORECASE,
        )
        m = vuln_re.search(line)
        if m:
            param = m.group(1)
            return Finding(
                title=f"XSS: Vulnerable parameter '{param}'",
                description=f"Dalfox identified parameter '{param}' as vulnerable to XSS.",
                vulnerability_type="xss_reflected",
                severity=SeverityLevel.MEDIUM,
                confidence=65.0,
                target=target,
                parameter=param,
                tool_name=self.name,
                cwe_id="CWE-79",
                tags=["xss", "parameter"],
            )

        return None

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _classify_xss(payload: str, evidence: str) -> str:
        """Classify as reflected, DOM, or stored based on payload/evidence."""
        combined = (payload + " " + evidence).lower()
        if any(kw in combined for kw in ("document.", "innerhtml", "srcdoc", "dom", "eval(")):
            return "xss_dom"
        return "xss_reflected"

    @staticmethod
    def _map_severity(sev: str) -> SeverityLevel:
        mapping: dict[str, SeverityLevel] = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        return mapping.get(sev.lower(), SeverityLevel.MEDIUM)


__all__ = ["DalfoxWrapper"]
