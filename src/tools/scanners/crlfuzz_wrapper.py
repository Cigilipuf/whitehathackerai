"""
WhiteHatHacker AI — CRLFuzz Wrapper

Fast CRLF injection scanner written in Go.
Detects HTTP header injection via CRLF (Carriage Return Line Feed) sequences.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class CrlfuzzWrapper(SecurityTool):
    """
    CRLFuzz — CRLF Injection Scanner.

    Go-based high-speed scanner that detects HTTP response splitting /
    header injection vulnerabilities via CRLF character sequences.
    """

    name = "crlfuzz"
    category = ToolCategory.SCANNER
    description = "CRLF injection vulnerability scanner (Go-based)"
    binary_name = "crlfuzz"
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
        timeout = options.get("timeout", 120)

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

        # Input: single URL (-u) or file (-l)
        if options.get("list_file"):
            cmd = [self.binary_name, "-l", options["list_file"]]
        else:
            cmd = [self.binary_name, "-u", target]

        # Silent (clean output)
        cmd.append("-s")

        # Output file
        if options.get("output_file"):
            cmd.extend(["-o", options["output_file"]])

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["-H", h])

        # Proxy
        if options.get("proxy"):
            cmd.extend(["-x", options["proxy"]])

        # Profile-specific concurrency
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-c", "1"])
            case ScanProfile.BALANCED:
                cmd.extend(["-c", "10"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-c", "50"])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        seen: set[str] = set()

        # CRLFuzz outputs vulnerable URLs — one per line, often with
        # "[VULN]" prefix or simply the URL where injection succeeded.
        vuln_re = re.compile(
            r"(?:\[VULN(?:ERABLE)?\]\s*)?(\S*https?://\S+)",
            re.IGNORECASE,
        )

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            is_vuln = False
            url = ""

            # Check for explicit VULN tag
            if re.search(r"\[VULN", line, re.IGNORECASE):
                is_vuln = True

            m = vuln_re.search(line)
            if m:
                url = m.group(1).strip()
                # In silent mode, every output line is a vulnerable URL
                is_vuln = True

            if not is_vuln or not url:
                # Also treat plain URL lines from -s (silent) output as hits
                plain_url = re.match(r"^(https?://\S+)$", line)
                if plain_url:
                    url = plain_url.group(1)
                    is_vuln = True

            if is_vuln and url and url not in seen:
                seen.add(url)
                findings.append(Finding(
                    title=f"CRLF Injection: {url[:120]}",
                    description=(
                        f"CRLFuzz detected CRLF injection (HTTP header injection) "
                        f"at {url}. An attacker can inject arbitrary HTTP headers "
                        f"which may lead to XSS, cache poisoning, or session fixation."
                    ),
                    vulnerability_type="crlf_injection",
                    severity=SeverityLevel.MEDIUM,
                    confidence=60.0,  # crlfuzz does not verify header injection
                    target=target,
                    endpoint=url,
                    tool_name=self.name,
                    cwe_id="CWE-93",
                    tags=["crlf", "header_injection", "response_splitting"],
                    metadata={"vulnerable_url": url},
                ))

        logger.debug(f"crlfuzz parsed {len(findings)} findings")
        return findings


__all__ = ["CrlfuzzWrapper"]
