"""
WhiteHatHacker AI — Arjun Wrapper

Hidden HTTP parameter discovery tool.
Finds valid parameters for endpoints using brute-force and heuristics.
"""

from __future__ import annotations

import json
import re
import tempfile
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class ArjunWrapper(SecurityTool):
    """
    Arjun — Hidden HTTP Parameter Discovery.

    Discovers hidden GET/POST/JSON parameters via intelligent brute-force.
    Supports stable mode, custom wordlists, and JSON output.
    """

    name = "arjun"
    category = ToolCategory.SCANNER
    description = "Hidden HTTP parameter discovery tool"
    binary_name = "arjun"
    requires_root = False
    risk_level = RiskLevel.LOW

    # ── run ───────────────────────────────────────────────────
    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}

        # Create a temp file for JSON output (mkstemp for security — no TOCTOU race)
        import os
        _fd, json_output_file = tempfile.mkstemp(suffix=".json", prefix="arjun_")
        os.close(_fd)  # Arjun will write to it
        options["output_file"] = json_output_file

        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 300)

        stdout, stderr, exit_code = await self.execute_command(command, timeout=timeout)

        # Read arjun's JSON output file if it exists
        parse_input = stdout
        try:
            if os.path.exists(json_output_file) and os.path.getsize(json_output_file) > 0:
                with open(json_output_file, "r", encoding="utf-8", errors="replace") as f:
                    parse_input = f.read()
                logger.debug(f"arjun JSON output file read: {len(parse_input)} bytes")
        except Exception as e:
            logger.warning(f"Failed to read arjun output file: {e}")
        finally:
            try:
                os.unlink(json_output_file)
            except OSError:
                pass

        findings = self.parse_output(parse_input, target)

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

        # Input: single URL (-u) or file (-i)
        if options.get("list_file"):
            cmd = [self.binary_name, "-i", options["list_file"]]
        else:
            cmd = [self.binary_name, "-u", target]

        # JSON output — -oJ always requires a file path
        if options.get("output_file"):
            output_file = options["output_file"]
        else:
            import os as _os
            _fd, output_file = tempfile.mkstemp(suffix=".json", prefix="arjun_")
            _os.close(_fd)
        cmd.extend(["-oJ", output_file])

        # HTTP method
        method = options.get("method", "GET").upper()
        cmd.extend(["-m", method])

        # Custom wordlist
        if options.get("wordlist"):
            cmd.extend(["-w", options["wordlist"]])

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["--headers", h])

        # Include patterns
        if options.get("include"):
            cmd.extend(["--include", options["include"]])

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend([
                    "--stable",
                    "-d", "2",
                    "-t", "1",
                ])
            case ScanProfile.BALANCED:
                cmd.extend([
                    "-t", "5",
                    "-d", "1",
                ])
            case ScanProfile.AGGRESSIVE:
                cmd.extend([
                    "-t", "20",
                ])

        return cmd

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        # Strategy 1: Try full JSON parse (arjun -oJ outputs structured JSON)
        findings = self._parse_json(raw_output, target)
        if findings:
            logger.debug(f"arjun parsed {len(findings)} findings (JSON)")
            return findings

        # Strategy 2: Fallback to line-by-line text parsing
        findings = self._parse_text(raw_output, target)
        logger.debug(f"arjun parsed {len(findings)} findings (text)")
        return findings

    # ── JSON parser ───────────────────────────────────────────
    def _parse_json(self, raw_output: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # arjun JSON output: {"url": ..., "method": ..., "params": [...]}
        # Could be a single object or multiple JSON lines
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Handle single object or list
            entries = data if isinstance(data, list) else [data]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                url = entry.get("url", target)
                method = entry.get("method", "GET")
                params = entry.get("params", [])

                if not params:
                    continue

                for param in params:
                    findings.append(Finding(
                        title=f"Hidden Parameter Discovered: {param}",
                        description=(
                            f"Arjun discovered hidden {method} parameter '{param}' "
                            f"on {url}."
                        ),
                        vulnerability_type="information_disclosure",
                        severity=SeverityLevel.LOW,
                        confidence=70.0,
                        target=target,
                        endpoint=url,
                        parameter=param,
                        tool_name=self.name,
                        cwe_id="CWE-200",
                        tags=["parameter_discovery", "hidden_param", method.lower()],
                        metadata={
                            "method": method,
                            "url": url,
                            "all_params": params,
                        },
                    ))

        # Also try parsing the whole output as a single JSON blob
        if not findings:
            try:
                data = json.loads(raw_output)
                if isinstance(data, dict):
                    for url, params_info in data.items():
                        if isinstance(params_info, dict):
                            method = params_info.get("method", "GET")
                            params = params_info.get("params", [])
                        elif isinstance(params_info, list):
                            method = "GET"
                            params = params_info
                        else:
                            continue
                        for param in params:
                            findings.append(Finding(
                                title=f"Hidden Parameter Discovered: {param}",
                                description=(
                                    f"Arjun discovered hidden {method} parameter "
                                    f"'{param}' on {url}."
                                ),
                                vulnerability_type="information_disclosure",
                                severity=SeverityLevel.LOW,
                                confidence=70.0,
                                target=target,
                                endpoint=url,
                                parameter=param,
                                tool_name=self.name,
                                cwe_id="CWE-200",
                                tags=["parameter_discovery", "hidden_param",
                                      method.lower()],
                                metadata={"method": method, "url": url},
                            ))
            except (json.JSONDecodeError, TypeError):
                pass

        return findings

    # ── Text parser ───────────────────────────────────────────
    def _parse_text(self, raw_output: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        # Pattern: "[param_name]" or "Found: param_name" or similar
        param_re = re.compile(
            r"(?:Found|Valid|param(?:eter)?)\s*[=:]\s*['\"]?(\w+)['\"]?",
            re.IGNORECASE,
        )

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            m = param_re.search(line)
            if m:
                param = m.group(1)
                if param in seen:
                    continue
                seen.add(param)
                findings.append(Finding(
                    title=f"Hidden Parameter Discovered: {param}",
                    description=f"Arjun discovered parameter '{param}' on {target}.",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.LOW,
                    confidence=65.0,
                    target=target,
                    parameter=param,
                    tool_name=self.name,
                    cwe_id="CWE-200",
                    tags=["parameter_discovery", "hidden_param"],
                ))

        return findings


__all__ = ["ArjunWrapper"]
