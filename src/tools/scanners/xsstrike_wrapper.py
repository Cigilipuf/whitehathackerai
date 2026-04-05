"""
WhiteHatHacker AI — XSStrike Wrapper

Python-based advanced XSS detection suite.
Reflected, DOM, blind XSS with fuzzer, crawler, and WAF bypass capabilities.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class XsstrikeWrapper(SecurityTool):
    """
    XSStrike — Advanced XSS Detection Suite.

    Features: intelligent payload generation, WAF detection & evasion,
    DOM XSS analysis, fuzzer mode, blind XSS, and crawler.
    """

    name = "xsstrike"
    category = ToolCategory.SCANNER
    description = "Advanced XSS detection suite with intelligent payload generation"
    binary_name = "xsstrike"
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

        cmd = [self.binary_name, "-u", target]

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["--delay", "3", "-t", "1"])
                # Skip DOM check to reduce noise in stealth
                cmd.append("--skip-dom")
            case ScanProfile.BALANCED:
                cmd.extend(["--delay", "1", "-t", "3"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-t", "10"])

        # Modes
        if options.get("crawl"):
            cmd.append("--crawl")
        if options.get("blind"):
            cmd.extend(["--blind", options["blind"]])  # blind XSS callback URL
        if options.get("fuzzer"):
            cmd.append("--fuzzer")
        if options.get("skip_dom"):
            cmd.append("--skip-dom")

        # Data (POST body)
        if options.get("data"):
            cmd.extend(["--data", options["data"]])

        # Custom headers
        if options.get("headers"):
            for k, v in options["headers"].items():
                cmd.extend(["--headers", f"{k}: {v}"])

        # Cookie
        if options.get("cookie"):
            cmd.extend(["--cookie", options["cookie"]])  # XSStrike doesn't have --cookie, pass via headers

        # Custom payloads file
        if options.get("payload_file"):
            cmd.extend(["--file", options["payload_file"]])

        # Proxy
        if options.get("proxy"):
            cmd.extend(["--proxy", options["proxy"]])

        # Params
        if options.get("params"):
            cmd.extend(["--params", options["params"]])

        # Encode payloads
        if options.get("encode"):
            cmd.extend(["-e", options["encode"]])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        # ---- Pattern 1: Vulnerable lines ----
        # e.g. "[Vulnerable] <payload_here>"  or  "Vulnerable! <payload>"
        vuln_re = re.compile(
            r"\[?Vulnerable\]?\s*[:\-]?\s*(.+)",
            re.IGNORECASE,
        )
        for match in vuln_re.finditer(raw_output):
            payload = match.group(1).strip()
            confidence = self._extract_confidence_near(raw_output, match.start())

            findings.append(Finding(
                title=f"XSS Detected: {target}",
                description=(
                    f"XSStrike confirmed a cross-site scripting vulnerability. "
                    f"Payload: {payload[:300]}"
                ),
                vulnerability_type="xss_reflected",
                severity=SeverityLevel.HIGH,
                confidence=confidence,
                target=target,
                payload=payload,
                tool_name=self.name,
                cwe_id="CWE-79",
                tags=["xss", "xss_reflected", "xsstrike"],
            ))

        # ---- Pattern 2: Confidence score lines ----
        # "Confidence: 95%"
        conf_re = re.compile(
            r"Confidence\s*[:\-]\s*(\d+)\s*%",
            re.IGNORECASE,
        )
        # Attach confidence to existing findings if not already captured
        conf_matches = list(conf_re.finditer(raw_output))
        for i, cm in enumerate(conf_matches):
            conf_value = float(cm.group(1))
            if i < len(findings):
                findings[i].confidence = conf_value

        # ---- Pattern 3: Reflection context ----
        # "Reflection found ... in attribute/tag/script"
        reflection_re = re.compile(
            r"Reflection\s+found\s+.*?(?:in|at)\s+(\S+)",
            re.IGNORECASE,
        )
        for match in reflection_re.finditer(raw_output):
            context = match.group(1).strip()
            findings.append(Finding(
                title=f"XSS Reflection: {context}",
                description=f"XSStrike found reflection context: {context}",
                vulnerability_type="xss_reflected",
                severity=SeverityLevel.MEDIUM,
                confidence=55.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-79",
                tags=["xss", "reflection", context.lower()],
                metadata={"reflection_context": context},
            ))

        # ---- Pattern 4: DOM XSS ----
        dom_re = re.compile(
            r"(?:DOM\s+XSS|DOM-based)\s*(?:found|detected|vulnerability)\s*[:\-]?\s*(.*)",
            re.IGNORECASE,
        )
        for match in dom_re.finditer(raw_output):
            detail = match.group(1).strip() if match.group(1) else ""
            findings.append(Finding(
                title=f"DOM XSS Detected: {target}",
                description=f"XSStrike detected DOM-based XSS. {detail}",
                vulnerability_type="xss_dom",
                severity=SeverityLevel.HIGH,
                confidence=75.0,
                target=target,
                tool_name=self.name,
                cwe_id="CWE-79",
                tags=["xss", "xss_dom", "dom"],
                evidence=detail[:500],
            ))

        # ---- Pattern 5: WAF detection (info) ----
        waf_re = re.compile(
            r"WAF\s+(?:detected|found|identified)\s*[:\-]?\s*(\S.*)",
            re.IGNORECASE,
        )
        for match in waf_re.finditer(raw_output):
            waf_name = match.group(1).strip()
            findings.append(Finding(
                title=f"WAF Detected: {waf_name}",
                description=f"XSStrike detected a Web Application Firewall: {waf_name}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=80.0,
                target=target,
                tool_name=self.name,
                tags=["waf", "info"],
                metadata={"waf": waf_name},
            ))

        # ---- Pattern 6: No vulnerability (negative) ----
        if not findings and re.search(
            r"no\s+(?:vulnerability|xss)\s+(?:found|detected)", raw_output, re.IGNORECASE
        ):
            findings.append(Finding(
                title="No XSS Found",
                description="XSStrike did not detect XSS vulnerabilities in the target.",
                vulnerability_type="info",
                severity=SeverityLevel.INFO,
                confidence=60.0,
                target=target,
                tool_name=self.name,
                tags=["negative", "clean"],
            ))

        logger.debug(f"xsstrike parsed {len(findings)} findings")
        return findings

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _extract_confidence_near(raw_output: str, pos: int) -> float:
        """Try to find a Confidence: XX% line near a given position."""
        # Look within ~300 chars after the match
        snippet = raw_output[pos : pos + 300]
        m = re.search(r"Confidence\s*[:\-]\s*(\d+)\s*%", snippet, re.IGNORECASE)
        if m:
            return float(m.group(1))
        return 80.0  # Default confidence for confirmed vulnerable


__all__ = ["XsstrikeWrapper"]
