"""
WhiteHatHacker AI — OpenRedirex Wrapper

Open redirect vulnerability scanner.
Tests URL parameters for unvalidated redirects using payload lists.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class OpenredirexWrapper(SecurityTool):
    """
    OpenRedirex — Open Redirect Vulnerability Scanner.

    Scans URLs for open redirect vulnerabilities by injecting payloads
    into parameters and checking for redirect behaviour (3xx + Location
    header). Supports FUZZ placeholder keyword and custom payload files.
    """

    name = "openredirex"
    category = ToolCategory.SCANNER
    description = "Open redirect vulnerability scanner"
    binary_name = "openredirex"
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
        command = self.build_command(target, options, profile)
        timeout = options.get("timeout", 180)

        # OpenRedirex can receive URLs via stdin. If a list_file is
        # provided, we pipe it; otherwise we echo the single target.
        stdin_data: str | None = None
        if not options.get("list_file"):
            stdin_data = target

        stdout, stderr, exit_code = await self._execute_with_stdin(
            command, stdin_data=stdin_data, timeout=timeout,
        )
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

        cmd: list[str] = [self.binary_name]

        # Payload file
        if options.get("payloads"):
            cmd.extend(["-p", options["payloads"]])

        # FUZZ keyword replacement
        keyword = options.get("keyword", "FUZZ")
        cmd.extend(["-k", keyword])

        # Input from file instead of stdin
        if options.get("list_file"):
            cmd.extend(["-l", options["list_file"]])

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["--delay", "2", "--threads", "1"])
            case ScanProfile.BALANCED:
                pass  # defaults
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["--threads", "20"])

        return cmd

    # ── execute with stdin support ────────────────────────────
    async def _execute_with_stdin(
        self,
        command: list[str],
        stdin_data: str | None = None,
        timeout: int = 180,
    ) -> tuple[str, str, int]:
        """Execute command with optional stdin data piping."""
        import asyncio
        import time

        cmd_str = " ".join(command)
        logger.debug(f"Executing (stdin): {cmd_str[:200]}")

        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdin_bytes = stdin_data.encode() if stdin_data else None
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = time.monotonic() - start
                logger.warning(
                    f"Tool timeout | tool={self.name} | timeout={timeout}s | "
                    f"elapsed={elapsed:.1f}s"
                )
                return "", f"TIMEOUT after {timeout}s", -1

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            elapsed = time.monotonic() - start
            logger.debug(
                f"Tool completed | tool={self.name} | exit={proc.returncode} | "
                f"time={elapsed:.1f}s"
            )

            return stdout, stderr, proc.returncode or 0

        except FileNotFoundError:
            logger.error(f"Tool not found: {self.binary_name}")
            return "", f"Tool not found: {self.binary_name}", -1
        except Exception as e:
            logger.error(f"Tool execution error | tool={self.name} | error={e}")
            return "", str(e), -1

    # ── parse_output ──────────────────────────────────────────
    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output or not raw_output.strip():
            return findings

        seen: set[str] = set()

        # Patterns for redirect detection
        # OpenRedirex outputs lines like:
        #   [VULN] https://example.com/redir?url=http://evil.com → 302
        #   https://example.com/redirect?next=//evil.com [302] [Location: ...]
        vuln_re = re.compile(
            r"(?:\[VULN(?:ERABLE)?\]\s*)?(https?://\S+)",
            re.IGNORECASE,
        )
        status_re = re.compile(r"\[?(30[12378])\]?")
        location_re = re.compile(
            r"Location:\s*(https?://\S+|//\S+)", re.IGNORECASE
        )

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Skip obvious non-result lines
            if line.startswith("#") or line.startswith("="):
                continue

            is_vuln = bool(re.search(r"\[VULN", line, re.IGNORECASE))

            # Check for redirect status codes
            status_match = status_re.search(line)
            if status_match:
                is_vuln = True

            # Check for Location header in output
            loc_match = location_re.search(line)
            if loc_match:
                is_vuln = True

            if not is_vuln:
                continue

            url_match = vuln_re.search(line)
            url = url_match.group(1) if url_match else target

            if url in seen:
                continue
            seen.add(url)

            status_code = status_match.group(1) if status_match else "3xx"
            redirect_target = loc_match.group(1) if loc_match else ""

            findings.append(Finding(
                title=f"Open Redirect: {url[:120]}",
                description=(
                    f"OpenRedirex detected an open redirect vulnerability at "
                    f"{url}. The server responded with HTTP {status_code}"
                    f"{f' redirecting to {redirect_target}' if redirect_target else ''}. "
                    f"An attacker can abuse this to redirect users to malicious sites."
                ),
                vulnerability_type="open_redirect",
                severity=SeverityLevel.MEDIUM,
                confidence=75.0,
                target=target,
                endpoint=url,
                evidence=line[:500],
                tool_name=self.name,
                cwe_id="CWE-601",
                tags=["open_redirect", f"http_{status_code}"],
                metadata={
                    "status_code": status_code,
                    "redirect_target": redirect_target,
                    "raw_line": line[:500],
                },
            ))

        logger.debug(f"openredirex parsed {len(findings)} findings")
        return findings


__all__ = ["OpenredirexWrapper"]
