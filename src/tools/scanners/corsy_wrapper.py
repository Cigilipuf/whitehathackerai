"""
WhiteHatHacker AI — Corsy Wrapper

CORS (Cross-Origin Resource Sharing) misconfiguration scanner.
Detects dangerous origin reflections, wildcard policies, null origin
acceptance, and other CORS misconfigurations.
"""

from __future__ import annotations

import json
import re
import shutil
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# Corsy finding type → severity mapping
_MISCONFIG_SEVERITY: dict[str, SeverityLevel] = {
    "reflect_origin": SeverityLevel.HIGH,
    "prefix_match": SeverityLevel.HIGH,
    "suffix_match": SeverityLevel.HIGH,
    "not_escape_dot": SeverityLevel.MEDIUM,
    "null_origin": SeverityLevel.MEDIUM,
    "wildcard": SeverityLevel.MEDIUM,
    "http_origin": SeverityLevel.MEDIUM,
    "third_party": SeverityLevel.LOW,
    "credentials_wildcard": SeverityLevel.HIGH,
}

_MISCONFIG_CONFIDENCE: dict[str, float] = {
    "reflect_origin": 85.0,
    "prefix_match": 80.0,
    "suffix_match": 80.0,
    "not_escape_dot": 75.0,
    "null_origin": 80.0,
    "wildcard": 40.0,        # no ACAC → data theft not possible
    "http_origin": 70.0,
    "third_party": 40.0,     # low-impact misconfig
    "credentials_wildcard": 85.0,
}


class CorsyWrapper(SecurityTool):
    """
    Corsy — CORS Misconfiguration Scanner.

    Detects various CORS misconfigurations including origin reflection,
    wildcard with credentials, null origin acceptance, prefix/suffix
    matching bypass, and more.
    """

    name = "corsy"
    category = ToolCategory.SCANNER
    description = "CORS misconfiguration scanner"
    binary_name = "corsy"
    requires_root = False
    risk_level = RiskLevel.LOW

    # ── is_available ──────────────────────────────────────────
    def is_available(self) -> bool:
        """Check binary availability via base class resolver (PATH + ~/go/bin + .venv/bin)."""
        # Use base class resolver which checks PATH, .venv/bin, ~/go/bin
        if self._resolve_binary() is not None:
            return True

        # Fallback: check if corsy is available as Python module
        try:
            import importlib
            importlib.import_module("corsy")
            self._binary_path = shutil.which("python3") or "python3"
            return True
        except ImportError:
            pass

        return False

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

        # Build base command — use resolved binary path from base class
        resolved = self._resolve_binary()
        if resolved:
            cmd = [resolved]
        else:
            # Fallback: try well-known locations
            import os
            go_bin = os.path.expanduser("~/go/bin/corsy")
            tools_bin = os.path.expanduser("~/tools/corsy/corsy.py")
            if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
                cmd = [go_bin]
            elif os.path.isfile(tools_bin):
                cmd = ["python3", tools_bin]
            else:
                cmd = ["python3", "-m", "corsy"]

        # Input: single URL (-u) or file (-i)
        if options.get("list_file"):
            cmd.extend(["-i", options["list_file"]])
        else:
            cmd.extend(["-u", target])

        # Output file
        if options.get("output_file"):
            cmd.extend(["-o", options["output_file"]])

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["--headers", h])

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-t", "1", "-d", "2"])
            case ScanProfile.BALANCED:
                cmd.extend(["-t", "5", "-d", "0.5"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-t", "20", "-d", "0"])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        # Strategy 1: Try JSON output (corsy -o json)
        findings = self._parse_json(raw_output, target)
        if findings:
            logger.debug(f"corsy parsed {len(findings)} findings (JSON)")
            return findings

        # Strategy 2: Text output parsing
        findings = self._parse_text(raw_output, target)
        logger.debug(f"corsy parsed {len(findings)} findings (text)")
        return findings

    # ── JSON parser ───────────────────────────────────────────
    def _parse_json(self, raw_output: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        if isinstance(data, dict):
            for url, misconfigs in data.items():
                if not isinstance(misconfigs, list):
                    misconfigs = [misconfigs]
                for entry in misconfigs:
                    if isinstance(entry, dict):
                        mtype = entry.get("type", "unknown")
                        desc = entry.get("description", "")
                        severity = _MISCONFIG_SEVERITY.get(
                            mtype, SeverityLevel.MEDIUM
                        )
                        confidence = _MISCONFIG_CONFIDENCE.get(mtype, 60.0)

                        findings.append(Finding(
                            title=f"CORS Misconfiguration ({mtype}): {url[:100]}",
                            description=(
                                f"Corsy detected CORS misconfiguration of type "
                                f"'{mtype}' at {url}. {desc}"
                            ),
                            vulnerability_type="cors_misconfiguration",
                            severity=severity,
                            confidence=confidence,
                            target=target,
                            endpoint=url,
                            tool_name=self.name,
                            cwe_id="CWE-942",
                            tags=["cors", mtype],
                            metadata={
                                "misconfiguration_type": mtype,
                                "url": url,
                            },
                        ))

        return findings

    # ── Text parser ───────────────────────────────────────────
    def _parse_text(self, raw_output: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        # Patterns for Corsy text output
        misconfig_patterns = [
            (
                re.compile(
                    r"(?:origin\s+)?reflect(?:ion|ed)", re.IGNORECASE
                ),
                "reflect_origin",
                "Origin is reflected in Access-Control-Allow-Origin header",
            ),
            (
                re.compile(r"wildcard.*credentials|credentials.*wildcard", re.IGNORECASE),
                "credentials_wildcard",
                "Wildcard (*) used with Access-Control-Allow-Credentials: true",
            ),
            (
                re.compile(r"null\s+origin", re.IGNORECASE),
                "null_origin",
                "Null origin is accepted in CORS policy",
            ),
            (
                re.compile(r"wildcard", re.IGNORECASE),
                "wildcard",
                "Wildcard (*) in Access-Control-Allow-Origin",
            ),
            (
                re.compile(r"prefix\s*match", re.IGNORECASE),
                "prefix_match",
                "CORS prefix matching bypass possible",
            ),
            (
                re.compile(r"suffix\s*match", re.IGNORECASE),
                "suffix_match",
                "CORS suffix matching bypass possible",
            ),
            (
                re.compile(r"not\s*escap(?:e|ing)\s*dot", re.IGNORECASE),
                "not_escape_dot",
                "Dot not escaped — subdomain bypass possible",
            ),
            (
                re.compile(r"http\s*origin", re.IGNORECASE),
                "http_origin",
                "HTTP origin allowed for HTTPS resource",
            ),
        ]

        # URL extraction pattern
        url_re = re.compile(r"(https?://\S+)", re.IGNORECASE)

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            for pattern, mtype, description in misconfig_patterns:
                if pattern.search(line):
                    # Extract URL from this or nearby context
                    url_match = url_re.search(line)
                    url = url_match.group(1) if url_match else target
                    dedup_key = f"{mtype}:{url}"

                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    severity = _MISCONFIG_SEVERITY.get(mtype, SeverityLevel.MEDIUM)
                    confidence = _MISCONFIG_CONFIDENCE.get(mtype, 60.0)

                    findings.append(Finding(
                        title=f"CORS Misconfiguration ({mtype}): {url[:100]}",
                        description=(
                            f"Corsy detected: {description}. "
                            f"Target: {url}"
                        ),
                        vulnerability_type="cors_misconfiguration",
                        severity=severity,
                        confidence=confidence,
                        target=target,
                        endpoint=url,
                        evidence=line[:500],
                        tool_name=self.name,
                        cwe_id="CWE-942",
                        tags=["cors", mtype],
                        metadata={
                            "misconfiguration_type": mtype,
                            "raw_line": line[:500],
                        },
                    ))
                    break  # only first matching pattern per line

        return findings


__all__ = ["CorsyWrapper"]
