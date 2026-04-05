"""
WhiteHatHacker AI — Mitmproxy Wrapper

HTTP/S proxy for traffic interception and analysis.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class MitmproxyWrapper(SecurityTool):
    """
    mitmproxy/mitmdump — HTTP/HTTPS intercepting proxy.

    Uses mitmdump (non-interactive) for:
    - Request/response logging
    - Sensitive data detection in transit
    - Security header analysis
    - Cookie security analysis
    - API endpoint discovery from traffic
    """

    name = "mitmproxy"
    category = ToolCategory.PROXY
    description = "HTTP/S traffic interception and security analysis"
    binary_name = "mitmdump"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    # Inline script for security analysis
    ANALYSIS_SCRIPT = '''
import json
import re
import sys
from mitmproxy import http

findings = []

SENSITIVE_PATTERNS = [
    (r"password|passwd|pwd", "Password in transit"),
    (r"api[_-]?key|apikey", "API key in transit"),
    (r"token|bearer|jwt|session", "Token/session in transit"),
    (r"credit.?card|card.?number|cvv|cvc", "Credit card data"),
    (r"ssn|social.?security", "SSN in transit"),
    (r"secret|private.?key", "Secret/key in transit"),
]

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url

    # Check for missing security headers
    headers = flow.response.headers
    missing_headers = []
    if "strict-transport-security" not in headers:
        missing_headers.append("Strict-Transport-Security")
    if "x-content-type-options" not in headers:
        missing_headers.append("X-Content-Type-Options")
    if "x-frame-options" not in headers:
        missing_headers.append("X-Frame-Options")
    if "content-security-policy" not in headers:
        missing_headers.append("Content-Security-Policy")

    if missing_headers:
        print(json.dumps({"type": "missing_headers", "url": url, "headers": missing_headers}))

    # Check cookies — mitmproxy returns (value, attrs) tuples
    for name in flow.response.cookies:
        value_tuple = flow.response.cookies[name]
        # Extract attributes dict (second element of the tuple)
        if isinstance(value_tuple, tuple) and len(value_tuple) >= 2:
            attrs = value_tuple[1]
        else:
            attrs = {}
        issues = []
        if not (hasattr(attrs, "get") and attrs.get("Secure", attrs.get("secure", ""))):
            issues.append("missing Secure flag")
        if not (hasattr(attrs, "get") and attrs.get("HttpOnly", attrs.get("httponly", ""))):
            issues.append("missing HttpOnly flag")
        if not (hasattr(attrs, "get") and attrs.get("SameSite", attrs.get("samesite", ""))):
            issues.append("missing SameSite attribute")
        if issues:
            print(json.dumps({"type": "cookie_issue", "url": url, "cookie": name, "issues": issues}))

    # Check for sensitive data in request/response
    req_text = flow.request.get_text() or ""
    resp_text = flow.response.get_text() or ""

    for pattern, desc in SENSITIVE_PATTERNS:
        if re.search(pattern, req_text, re.IGNORECASE):
            print(json.dumps({"type": "sensitive_data", "url": url, "direction": "request", "pattern": desc}))
        if re.search(pattern, resp_text[:5000], re.IGNORECASE):
            print(json.dumps({"type": "sensitive_data", "url": url, "direction": "response", "pattern": desc}))
'''

    async def run(self, target, options=None, profile=ScanProfile.BALANCED) -> ToolResult:
        options = options or {}
        mode = options.get("mode", "analyze_dump")  # analyze_dump | capture | replay

        if mode == "analyze_dump":
            return await self._analyze_dump(target, options)
        elif mode == "capture":
            return await self._capture(target, options)
        else:
            return await self._replay(target, options)

    async def _analyze_dump(self, dump_file: str, options: dict) -> ToolResult:
        """Analyze an existing flow dump file for security issues."""
        if not Path(dump_file).exists():
            return ToolResult(
                tool_name=self.name, success=False, exit_code=1,
                stdout="", stderr=f"Dump file not found: {dump_file}",
                findings=[], command="", target=dump_file,
            )

        # Write analysis script to secure temp file (avoids TOCTOU with fixed path)
        import tempfile
        fd, script_path_str = tempfile.mkstemp(suffix=".py", prefix="whai_mitm_")
        try:
            with os.fdopen(fd, "w") as sf:
                sf.write(self.ANALYSIS_SCRIPT)

            cmd = ["mitmdump", "-r", dump_file, "-s", script_path_str, "--set", "flow_detail=0"]
            stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)
            findings = self._parse_analysis_output(stdout, dump_file)
        finally:
            Path(script_path_str).unlink(missing_ok=True)

        return ToolResult(
            tool_name=self.name, success=True, exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=findings,
            command=f"mitmdump -r {dump_file}", target=dump_file,
        )

    async def _capture(self, target: str, options: dict) -> ToolResult:
        """Start traffic capture (runs as background)."""
        port = options.get("proxy_port", 8080)
        import tempfile as _tf
        _cap_dir = os.path.join(_tf.gettempdir(), "whai")
        os.makedirs(_cap_dir, mode=0o700, exist_ok=True)
        output_file = options.get("output_file") or os.path.join(_cap_dir, f"capture_{os.getpid()}.flow")
        duration = options.get("duration", 60)

        cmd = [
            "mitmdump", "-p", str(port),
            "-w", output_file,
            "--set", "connection_strategy=lazy",
        ]

        if target and target != "all":
            cmd.extend(["--set", "upstream_cert=true"])

        stdout, stderr, exit_code = await self.execute_command(cmd, timeout=duration)

        return ToolResult(
            tool_name=self.name, success=True, exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=[],
            command=" ".join(cmd), target=target,
            metadata={"output_file": output_file, "port": port},
        )

    async def _replay(self, flow_file: str, options: dict) -> ToolResult:
        """Replay captured flows."""
        cmd = ["mitmdump", "--replay-client", flow_file]
        if options.get("server"):
            cmd.extend(["--set", f"upstream_proxy={options['server']}"])

        stdout, stderr, exit_code = await self.execute_command(cmd, timeout=1200)

        return ToolResult(
            tool_name=self.name, success=exit_code == 0, exit_code=exit_code,
            stdout=stdout, stderr=stderr, findings=[],
            command=f"mitmdump --replay-client {flow_file}", target=flow_file,
        )

    def _parse_analysis_output(self, output: str, target: str) -> list[Finding]:
        findings = []
        urls_missing_headers: dict[str, list[str]] = {}
        cookie_issues: list[dict] = []
        sensitive_data: list[dict] = []

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                match data.get("type"):
                    case "missing_headers":
                        url = data["url"]
                        if url not in urls_missing_headers:
                            urls_missing_headers[url] = data["headers"]
                    case "cookie_issue":
                        cookie_issues.append(data)
                    case "sensitive_data":
                        sensitive_data.append(data)
            except json.JSONDecodeError:
                continue

        # Aggregate missing headers findings
        for url, headers in list(urls_missing_headers.items())[:20]:
            findings.append(Finding(
                title=f"Missing Security Headers: {url[:60]}",
                description=f"Missing headers: {', '.join(headers)}\nURL: {url}",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.LOW,
                confidence=85.0, target=url, tool_name=self.name,
                cwe_id="CWE-693",
                tags=["headers", "missing_security_headers"],
                metadata={"missing": headers},
            ))

        # Cookie findings
        for ci in cookie_issues[:10]:
            findings.append(Finding(
                title=f"Insecure Cookie: {ci['cookie']}",
                description=f"Cookie '{ci['cookie']}' has issues: {', '.join(ci['issues'])}\nURL: {ci['url']}",
                vulnerability_type="misconfiguration",
                severity=SeverityLevel.MEDIUM,
                confidence=90.0, target=ci["url"], tool_name=self.name,
                cwe_id="CWE-614",
                tags=["cookie", "insecure"],
            ))

        # Sensitive data
        for sd in sensitive_data[:10]:
            findings.append(Finding(
                title=f"Sensitive Data in {sd['direction']}: {sd['pattern']}",
                description=f"{sd['pattern']} detected in {sd['direction']} to {sd['url']}",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.HIGH,
                confidence=70.0, target=sd["url"], tool_name=self.name,
                cwe_id="CWE-319",
                tags=["sensitive_data", sd["direction"]],
            ))

        logger.debug(f"mitmproxy parsed {len(findings)} findings")
        return findings

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["mitmdump", "-r", target]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return self._parse_analysis_output(raw_output, target)


__all__ = ["MitmproxyWrapper"]
