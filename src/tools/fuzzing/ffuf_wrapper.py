"""
WhiteHatHacker AI — FFuf Wrapper

Fast web fuzzer: directory/file, parameter, virtual host fuzzing.
JSON çıktı desteği ile kapsamlı sonuç parse.
"""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


class FfufWrapper(SecurityTool):
    """
    FFuf — Fast web fuzzer (Go).

    Modlar:
      - Directory/path fuzzing
      - Parameter fuzzing
      - Header fuzzing
      - Virtual host fuzzing
      - POST data fuzzing
    """

    name = "ffuf"
    category = ToolCategory.FUZZING
    description = "Fast web fuzzer — directory, parameter, header, vhost fuzzing"
    binary_name = "ffuf"
    requires_root = False
    risk_level = RiskLevel.LOW

    # Varsayılan wordlist'ler (öncelik sırasıyla denenecek)
    WORDLIST_CANDIDATES = {
        "directory": [
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wfuzz/wordlist/general/common.txt",
        ],
        "big": [
            "/usr/share/dirb/wordlists/big.txt",
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wfuzz/wordlist/general/big.txt",
        ],
        "params": [
            "/usr/share/wfuzz/wordlist/general/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ],
    }

    @staticmethod
    def _find_wordlist(candidates: list[str]) -> str:
        """İlk mevcut wordlist'i döndür."""
        from pathlib import Path
        for c in candidates:
            if Path(c).is_file():
                return c
        return candidates[0]  # fallback — may not exist

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
        # Combine stderr into stdout if stdout is empty (timeout case)
        combined = stdout
        if not stdout.strip() and stderr:
            combined = stderr
        findings = self.parse_output(combined, target)

        return ToolResult(
            tool_name=self.name,
            success=(exit_code in (0, 1) or len(findings) > 0),
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
        mode = options.get("mode", "directory")

        # URL hazırla
        if isinstance(target, list):
            target = target[0] if target else ""
        url = target if target.startswith("http") else f"http://{target}"

        # Wordlist seç
        candidates = self.WORDLIST_CANDIDATES.get(mode, self.WORDLIST_CANDIDATES["directory"])
        wordlist = options.get("wordlist", self._find_wordlist(candidates))

        cmd = [self.binary_name]

        if mode == "directory":
            fuzz_url = url.rstrip("/") + "/FUZZ"
            cmd.extend(["-u", fuzz_url, "-w", wordlist])
        elif mode == "parameter":
            fuzz_url = url + "?FUZZ=test"
            cmd.extend(["-u", fuzz_url, "-w", wordlist])
        elif mode == "vhost":
            cmd.extend(["-u", url, "-w", wordlist, "-H", "Host: FUZZ." + target])
        else:
            fuzz_url = url.rstrip("/") + "/FUZZ"
            cmd.extend(["-u", fuzz_url, "-w", wordlist])

        # Profil ayarları — allow options dict to override rate/threads
        opt_rate = str(options.get("rate", ""))
        opt_threads = str(options.get("threads", ""))

        match profile:
            case ScanProfile.STEALTH:
                cmd.extend(["-rate", opt_rate or "5", "-t", opt_threads or "2", "-timeout", "30"])
            case ScanProfile.BALANCED:
                cmd.extend(["-rate", opt_rate or "15", "-t", opt_threads or "10", "-timeout", "15"])
            case ScanProfile.AGGRESSIVE:
                cmd.extend(["-rate", opt_rate or "100", "-t", opt_threads or "50", "-timeout", "10"])

        # Auto-calibration: intelligently filter common response sizes
        if options.get("autocalibrate", True):
            cmd.append("-ac")

        # Filtreler
        if "filter_code" in options:
            cmd.extend(["-fc", str(options["filter_code"])])
        else:
            cmd.extend(["-fc", "404"])

        if "filter_size" in options:
            cmd.extend(["-fs", str(options["filter_size"])])
        if "filter_words" in options:
            cmd.extend(["-fw", str(options["filter_words"])])
        if "match_code" in options:
            cmd.extend(["-mc", str(options["match_code"])])

        # JSON ve sessiz çıktı
        cmd.extend(["-o", "-", "-of", "json", "-noninteractive"])

        if options.get("extensions"):
            cmd.extend(["-e", options["extensions"]])  # ".php,.html,.js"

        if options.get("recursion", False):
            cmd.extend(["-recursion", "-recursion-depth", str(options.get("recursion_depth", 2))])

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            # Fallback: satır-bazlı parse
            return self._parse_text_output(raw_output, target)

        results = data.get("results", [])
        for result in results:
            url = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)
            words = result.get("words", 0)
            lines = result.get("lines", 0)
            input_val = result.get("input", {}).get("FUZZ", "")
            redirect = result.get("redirectlocation", "")

            severity = self._status_to_severity(status, input_val)

            desc = f"Status: {status} | Size: {length} | Words: {words} | Lines: {lines}"
            if redirect:
                desc += f" | Redirect: {redirect}"

            tags = ["fuzzing", f"status:{status}"]
            if status in (200, 301, 302, 403):
                tags.append("interesting")

            findings.append(Finding(
                title=f"Discovered: {input_val} [{status}]",
                description=desc,
                vulnerability_type="content_discovery",
                severity=severity,
                confidence=85.0,
                target=target,
                endpoint=url,
                tool_name=self.name,
                tags=tags,
                metadata={
                    "status_code": status,
                    "content_length": length,
                    "words": words,
                    "lines": lines,
                    "redirect": redirect,
                    "fuzz_input": input_val,
                },
            ))

        logger.debug(f"ffuf parsed {len(findings)} findings")
        return findings

    def _parse_text_output(self, output: str, target: str) -> list[Finding]:
        """Plain text ffuf çıktısı fallback."""
        findings: list[Finding] = []
        import re
        pattern = re.compile(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")
        for match in pattern.finditer(output):
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))
            findings.append(Finding(
                title=f"Discovered: {path} [{status}]",
                description=f"Status: {status} | Size: {size}",
                vulnerability_type="content_discovery",
                severity=self._status_to_severity(status, path),
                confidence=80.0,
                target=target,
                endpoint=f"{target}/{path}",
                tool_name=self.name,
                tags=["fuzzing", f"status:{status}"],
            ))
        return findings

    @staticmethod
    def _status_to_severity(status: int, path: str) -> SeverityLevel:
        """Durum koduna ve yola göre ciddiyet belirle."""
        sensitive_paths = [
            "admin", "backup", ".env", "config", ".git", "debug",
            "phpinfo", "server-status", "wp-admin", ".htpasswd",
            "web.config", ".DS_Store", "robots.txt",
        ]
        path_lower = path.lower()

        if any(s in path_lower for s in sensitive_paths):
            if status == 200:
                return SeverityLevel.MEDIUM
            if status in (301, 302, 403):
                return SeverityLevel.LOW

        if status == 200:
            return SeverityLevel.INFO
        return SeverityLevel.INFO


__all__ = ["FfufWrapper"]
