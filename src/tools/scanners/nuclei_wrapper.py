"""
WhiteHatHacker AI — Nuclei Wrapper

Project Discovery Nuclei — Template-based vulnerability scanner.
Community + custom template desteği, YAML tabanlı rule engine.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.response_validator import ResponseValidator
from src.utils.constants import (
    NUCLEI_TIMEOUT,
    RiskLevel,
    ScanProfile,
    SeverityLevel,
    ToolCategory,
)


_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "info": SeverityLevel.INFO,
    "low": SeverityLevel.LOW,
    "medium": SeverityLevel.MEDIUM,
    "high": SeverityLevel.HIGH,
    "critical": SeverityLevel.CRITICAL,
}

_response_validator = ResponseValidator()


class NucleiWrapper(SecurityTool):
    """
    Nuclei — Fast, template-based vulnerability scanner.

    6000+ community templates covering:
    CVE, misconfigurations, exposed panels, default credentials,
    takeover, XSS, SQLi, SSRF, RCE, LFI, open-redirect, CORS, etc.
    """

    name = "nuclei"
    category = ToolCategory.SCANNER
    description = "Template-based vulnerability scanner — 6000+ community checks"
    binary_name = "nuclei"
    requires_root = False
    risk_level = RiskLevel.MEDIUM
    default_timeout = 1800  # 30min — large targets with 6000+ templates
    memory_limit = 512 * 1024 * 1024  # 512 MB — reduced to prevent OOM on large targets — nuclei can OOM on large template sets

    # ── run ───────────────────────────────────────────────────
    def _go_env(self) -> dict[str, str]:
        """Build env dict with Go runtime limits for nuclei subprocesses.

        GOMAXPROCS limits OS threads used by the Go scheduler, preventing
        'pthread_create failed: Resource temporarily unavailable' when
        multiple nuclei processes run in parallel.
        GOMEMLIMIT sets a soft heap memory target.
        """
        env = os.environ.copy()
        _mem_mb = self.memory_limit // (1024 * 1024)
        env["GOMEMLIMIT"] = f"{_mem_mb}MiB"
        env["GOMAXPROCS"] = "4"
        return env

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        command = self.build_command(target, options, profile)
        # Aggressive needs MORE time (all templates, high concurrency)
        timeout = options.get("timeout", {
            ScanProfile.STEALTH: NUCLEI_TIMEOUT // 2,    # Fewer templates
            ScanProfile.BALANCED: NUCLEI_TIMEOUT,         # Standard
            ScanProfile.AGGRESSIVE: NUCLEI_TIMEOUT * 2,   # All templates
        }.get(profile, NUCLEI_TIMEOUT))

        stdout, stderr, exit_code = await self.execute_command(
            command, timeout=timeout, env=self._go_env(),
        )

        # OOM retry: if nuclei crashed (exit -9 / -6 / stderr contains memory error),
        # retry once with minimal concurrency
        _oom_signals = ("out of memory", "runtime: out of memory", "mmap", "cannot allocate")
        if exit_code in (-9, -6, 137, 134) or any(s in (stderr or "").lower() for s in _oom_signals):
            logger.warning(f"nuclei OOM detected (exit={exit_code}), retrying with minimal settings")
            _retry_cmd = [c for c in command if c not in ("-c", "-bs")]
            # Strip values that follow -c and -bs flags
            _clean: list[str] = []
            _skip_next = False
            for _tok in _retry_cmd:
                if _skip_next:
                    _skip_next = False
                    continue
                if _tok in ("-c", "-bs"):
                    _skip_next = True
                    continue
                _clean.append(_tok)
            _clean.extend(["-c", "1", "-bs", "5"])
            _env2 = self._go_env()
            _env2["GOMEMLIMIT"] = "256MiB"
            stdout, stderr, exit_code = await self.execute_command(
                _clean, timeout=timeout, env=_env2,
            )

        # nuclei writes stats/progress to stderr; some findings may appear in stderr
        combined = stdout + "\n" + stderr if (stderr and not stdout.strip()) else stdout
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

    async def run_batch(
        self,
        targets: list[str],
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        """
        Birden fazla hedefi tek seferde nuclei ile tara.

        -l flag ile geçici dosya üzerinden çoklu hedef taraması yapar.
        Tek tek çalıştırmaktan çok daha verimli.
        """
        import tempfile
        import os

        options = options or {}

        # Hedefleri geçici dosyaya yaz
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="nuclei_targets_", delete=False
        )
        try:
            for t in targets:
                tmp.write(t + "\n")
            tmp.flush()
            tmp.close()

            # Build command with -l instead of -u
            batch_opts = {**options, "list_file": tmp.name}
            command = self.build_command("batch", batch_opts, profile)

            # Batch scan needs more time: base timeout + per-target allowance
            base_timeout = {
                ScanProfile.STEALTH: NUCLEI_TIMEOUT // 2,
                ScanProfile.BALANCED: NUCLEI_TIMEOUT,
                ScanProfile.AGGRESSIVE: NUCLEI_TIMEOUT * 2,
            }.get(profile, NUCLEI_TIMEOUT)
            # Allow extra time proportional to target count (30s per target)
            auto_timeout = base_timeout + (len(targets) * 30)
            # Honor caller-provided timeout override (for focused template runs)
            timeout = options.get("timeout") or auto_timeout

            stdout, stderr, exit_code = await self.execute_command(
                command, timeout=timeout, env=self._go_env(),
            )
            combined = stdout + "\n" + stderr if (stderr and not stdout.strip()) else stdout
            findings = self.parse_output(combined, "batch")

            logger.info(
                f"nuclei batch scan | targets={len(targets)} | "
                f"findings={len(findings)} | exit={exit_code}"
            )

            return ToolResult(
                tool_name=self.name,
                success=(exit_code == 0 or len(findings) > 0),
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                findings=findings,
                command=" ".join(command),
                target=f"batch({len(targets)})",
            )
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    # ── build_command ─────────────────────────────────────────
    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        options = options or {}
        cmd = [self.binary_name]

        # Target — URL, list file, or stdin
        if options.get("list_file"):
            cmd.extend(["-l", options["list_file"]])
        else:
            cmd.extend(["-u", target])

        # JSON Lines output (machine-readable)
        cmd.extend(["-jsonl", "-silent"])

        # Severity filter
        severities = options.get("severity")
        if severities:
            cmd.extend(["-severity", severities])  # e.g. "high,critical"

        # Template selection
        if options.get("templates"):
            for tpl in options["templates"]:
                # Standard nuclei template categories (e.g. "http/misconfiguration/")
                # are resolved by nuclei itself from its template directory.
                # Only validate absolute or relative file paths.
                _NUCLEI_BUILTIN_PREFIXES = (
                    "http/", "dns/", "network/", "file/", "headless/",
                    "code/", "javascript/", "multi/", "ssl/", "websocket/",
                    "workflows/", "helpers/",
                )
                if tpl.startswith(_NUCLEI_BUILTIN_PREFIXES):
                    cmd.extend(["-t", tpl])
                    continue
                # Validate custom template path — reject path traversal
                tpl_resolved = os.path.realpath(tpl)
                if not (tpl_resolved.startswith(os.path.realpath("data/nuclei_templates"))
                        or tpl_resolved.startswith(os.path.realpath(os.path.expanduser("~/nuclei-templates")))):
                    logger.warning(f"Rejecting nuclei template outside allowed dirs: {tpl}")
                    continue
                cmd.extend(["-t", tpl])
        if options.get("template_id"):
            cmd.extend(["-id", options["template_id"]])
        if options.get("tags"):
            cmd.extend(["-tags", options["tags"]])
        if options.get("exclude_tags"):
            cmd.extend(["-etags", options["exclude_tags"]])

        # Protocol
        if options.get("type"):
            cmd.extend(["-type", options["type"]])  # http, dns, network, ...

        # Custom headers
        for h in options.get("headers", []):
            cmd.extend(["-H", h])

        # Follow redirects
        if options.get("follow_redirects", True):
            cmd.append("-fr")

        # Proxy
        if options.get("proxy"):
            cmd.extend(["-proxy", options["proxy"]])

        # Interactsh (OOB)
        if options.get("interactsh_url"):
            cmd.extend(["-iserver", options["interactsh_url"]])
        if options.get("interactsh_token"):
            cmd.extend(["-itoken", options["interactsh_token"]])
        if options.get("no_interactsh"):
            cmd.append("-ni")

        # Profile-specific tuning
        match profile:
            case ScanProfile.STEALTH:
                cmd.extend([
                    "-rl", "5",          # 5 req/s
                    "-c", "2",           # 2 concurrent templates
                    "-bs", "10",         # 10 bulk size
                    "-timeout", "15",
                    "-retries", "1",
                ])
                if not severities:
                    cmd.extend(["-severity", "high,critical"])
            case ScanProfile.BALANCED:
                cmd.extend([
                    "-rl", "50",
                    "-c", "5",
                    "-bs", "15",
                    "-timeout", "10",
                    "-retries", "2",
                    "-include-rr",  # Capture HTTP request/response for evidence
                    "-etags", "tech,token-spray",  # Skip tech detection (handled by whatweb)
                    "-et", "dns/,headless/,ssl/",  # Exclude dns/headless/ssl templates
                ])
            case ScanProfile.AGGRESSIVE:
                cmd.extend([
                    "-rl", "150",
                    "-c", "25",
                    "-bs", "50",
                    "-timeout", "8",
                    "-retries", "3",
                    "-include-rr",  # Capture HTTP request/response for evidence
                ])

        # Exclude info-only in non-stealth
        if not severities and profile != ScanProfile.STEALTH:
            if not options.get("include_info"):
                cmd.extend(["-severity", "low,medium,high,critical"])

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
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # Fallback: plain-text line (e.g. "[CVE-2021-XXXX] [http] ...")
                finding = self._parse_plain_line(line, target)
                if finding:
                    findings.append(finding)
                continue

            finding = self._parse_json_result(data, target)
            if finding:
                findings.append(finding)
                logger.info(
                    f"nuclei finding: {finding.title} | "
                    f"severity={finding.severity} | "
                    f"endpoint={finding.endpoint}"
                )

        logger.debug(f"nuclei parsed {len(findings)} findings")
        return findings

    # ── JSON result parsing ───────────────────────────────────
    def _parse_json_result(self, data: dict, default_target: str) -> Finding | None:
        info = data.get("info", {})
        template_id = data.get("template-id", data.get("templateID", ""))
        name = info.get("name", template_id)
        severity_str = (info.get("severity") or "info").lower()
        severity = _SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)
        matched_at = data.get("matched-at", data.get("matched", default_target))
        host = data.get("host", default_target)

        # Matcher details
        matcher_name = data.get("matcher-name", "")
        extracted = data.get("extracted-results", [])
        curl_cmd = data.get("curl-command", "")

        # Description & references
        description_parts = [info.get("description", "")]
        if matcher_name:
            description_parts.append(f"Matcher: {matcher_name}")
        if extracted:
            description_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")
        refs = info.get("reference", [])
        if isinstance(refs, list):
            description_parts.extend(refs[:3])

        # Tags, CWE, CVE
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        classification = info.get("classification", {})
        cve_id = classification.get("cve-id", "")
        cwe_ids = classification.get("cwe-id", [])
        cwe = cwe_ids[0] if cwe_ids else ""

        # Request/Response
        request = data.get("request", "")
        response = data.get("response", "")

        vuln_type = self._classify_vuln_type(template_id, tags)

        resp_meta = self._extract_http_response_meta(response)
        if resp_meta is not None:
            validator_result = _response_validator.validate_for_checker(
                resp_meta["status_code"],
                resp_meta["headers"],
                resp_meta["body"],
                checker_name="nuclei",
                expected_content_type=self._expected_content_type(vuln_type, template_id, tags),
                url=matched_at,
            )
            if not validator_result.is_valid:
                logger.debug(
                    f"nuclei dropped finding {template_id} at {matched_at}: "
                    f"{validator_result.rejection_reason}"
                )
                return None
        else:
            validator_result = None

        # ── Evidence-based confidence (P2-1 + v5.0-P0.1) ──
        # Instead of blindly trusting template severity for confidence,
        # calculate based on actual evidence quality in the finding.
        # When no raw HTTP response is available for validation, start lower
        # because the finding cannot be independently verified.
        confidence = 40.0 if validator_result is None else 50.0
        if extracted:
            confidence += 20  # data was actually extracted
        if curl_cmd:
            confidence += 5   # reproducible curl command
        if matcher_name:
            confidence += 5   # named matcher = more specific
        if matched_at and matched_at != host:
            confidence += 5   # specific endpoint, not just the host
        if response and len(response) > 100:
            confidence += 3   # non-trivial response captured
        if cve_id:
            confidence += 7   # CVE-linked = well-researched template
        # Severity-based bonus (smaller than before)
        _sev_bonus = {
            SeverityLevel.CRITICAL: 10,
            SeverityLevel.HIGH: 7,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 0,
            SeverityLevel.INFO: -5,
        }
        confidence += _sev_bonus.get(severity, 0)
        if validator_result is not None:
            confidence += validator_result.confidence_modifier
        confidence = max(20.0, min(95.0, confidence))

        return Finding(
            title=f"Nuclei: {name}" + (f" ({cve_id})" if cve_id else ""),
            description="\n".join(d for d in description_parts if d),
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            target=host,
            endpoint=matched_at,
            tool_name=self.name,
            payload=curl_cmd[:500] if curl_cmd else "",
            evidence=(response[:1000] if response else ""),
            http_request=request[:2000] if request else "",
            http_response=response[:2000] if response else "",
            cvss_score=classification.get("cvss-score"),
            cwe_id=cwe,
            tags=["nuclei", template_id] + tags[:10],
            references=refs[:5] if isinstance(refs, list) else [],
            metadata={
                "template_id": template_id,
                "matcher_name": matcher_name,
                "extracted": extracted[:10],
                "cve": cve_id,
                "type": data.get("type", ""),
                "response_validation": validator_result.details if validator_result is not None else {},
            },
        )

    @staticmethod
    def _extract_http_response_meta(raw_response: str) -> dict[str, Any] | None:
        """Parse a raw HTTP response captured by nuclei include-rr output."""
        if not raw_response or not raw_response.lstrip().startswith("HTTP/"):
            return None

        parts = re.split(r"\r?\n\r?\n", raw_response, maxsplit=1)
        header_section = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        lines = header_section.splitlines()
        if not lines:
            return None

        status_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", lines[0])
        if not status_match:
            return None

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

        return {
            "status_code": int(status_match.group(1)),
            "headers": headers,
            "body": body,
        }

    @staticmethod
    def _expected_content_type(vuln_type: str, template_id: str, tags: list[str]) -> str | None:
        """Infer expected response type for ResponseValidator heuristics."""
        combined = f"{template_id} {' '.join(tags)} {vuln_type}".lower()
        if any(keyword in combined for keyword in (
            "swagger", "openapi", "graphql", "json", "xml", "git", "env",
            "config", "backup", "database", "dump", "exposure", "disclosure",
        )):
            return "text"
        if vuln_type in {"information_disclosure", "known_cve", "misconfiguration"}:
            return "text"
        return None

    # ── Plain-text fallback ───────────────────────────────────
    _PLAIN_RE = re.compile(
        r"\[(?P<id>[^\]]+)\]\s*\[(?P<proto>[^\]]*)\]\s*\[(?P<sev>[^\]]*)\]\s*(?P<url>\S+)",
    )

    def _parse_plain_line(self, line: str, target: str) -> Finding | None:
        m = self._PLAIN_RE.search(line)
        if not m:
            return None
        template_id = m.group("id")
        severity_str = m.group("sev").lower()
        url = m.group("url")
        severity = _SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

        return Finding(
            title=f"Nuclei: {template_id}",
            description=line,
            vulnerability_type=self._classify_vuln_type(template_id, []),
            severity=severity,
            confidence=60.0,
            target=target,
            endpoint=url,
            tool_name=self.name,
            tags=["nuclei", template_id],
        )

    # ── Vulnerability classification ──────────────────────────
    @staticmethod
    def _classify_vuln_type(template_id: str, tags: list[str]) -> str:
        combined = (template_id + " " + " ".join(tags)).lower()
        _mapping = [
            (["sqli", "sql-injection"], "sql_injection"),
            (["xss", "cross-site-scripting"], "xss"),
            (["ssrf"], "ssrf"),
            (["ssti", "template-injection"], "ssti"),
            (["rce", "remote-code", "command-injection"], "rce"),
            (["lfi", "local-file", "path-traversal"], "lfi"),
            (["rfi", "remote-file"], "rfi"),
            (["open-redirect", "redirect"], "open_redirect"),
            (["cors"], "cors_misconfiguration"),
            (["crlf"], "crlf_injection"),
            (["xxe"], "xxe"),
            (["idor", "insecure-direct"], "idor"),
            (["jwt"], "jwt_vulnerability"),
            (["takeover", "subdomain-takeover"], "subdomain_takeover"),
            (["default-login", "default-cred"], "default_credentials"),
            (["exposed-panel", "panel"], "exposed_panel"),
            (["cve-"], "known_cve"),
            (["misconfig", "misconfiguration"], "misconfiguration"),
            (["info", "tech-detect"], "information_disclosure"),
            (["ssl", "tls"], "ssl_tls_misconfiguration"),
        ]
        for keywords, vuln_type in _mapping:
            if any(k in combined for k in keywords):
                return vuln_type
        return "unknown"


__all__ = ["NucleiWrapper"]
