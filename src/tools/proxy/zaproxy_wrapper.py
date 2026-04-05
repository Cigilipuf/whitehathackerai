"""
WhiteHatHacker AI — ZAP (Zaproxy) Wrapper

OWASP ZAP integration via its REST API for:
- Passive scanning (analyze traffic for vulns without active attacks)
- Active scanning (targeted fuzzing of specific endpoints)
- Ajax spidering (discover endpoints in SPAs)
- Traditional spidering (crawl all links)
- Session management (auth token/cookie propagation)
- Alert harvesting (convert ZAP alerts → Finding objects)

Architecture:
    The wrapper manages ZAP's lifecycle (start daemon → use API → stop).
    ZAP runs as a background daemon process; all interaction is via REST API.
    This avoids the problems of routing all bot traffic through a proxy.

Requires: `zaproxy` binary (apt install zaproxy) or Docker image.
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory


# ── ZAP Alert Risk → SeverityLevel mapping ────────────────────
_ZAP_RISK_MAP: dict[int, SeverityLevel] = {
    0: SeverityLevel.INFO,       # Informational
    1: SeverityLevel.LOW,        # Low
    2: SeverityLevel.MEDIUM,     # Medium
    3: SeverityLevel.HIGH,       # High
}

# ZAP Alert Confidence → our confidence score
_ZAP_CONFIDENCE_MAP: dict[int, float] = {
    0: 25.0,   # False Positive
    1: 40.0,   # Low
    2: 65.0,   # Medium
    3: 85.0,   # High
    4: 95.0,   # User Confirmed
}

# CWE mappings for common ZAP alert types
_ZAP_CWE_MAP: dict[int, str] = {
    10010: "CWE-693",   # Cookie No HttpOnly Flag
    10011: "CWE-614",   # Cookie Without Secure Flag
    10012: "CWE-1004",  # Cookie Without SameSite
    10015: "CWE-525",   # Re-examine Cache-control Directives
    10017: "CWE-200",   # Cross-Domain JavaScript Source File Inclusion
    10020: "CWE-693",   # Missing Security Headers (X-Frame-Options)
    10021: "CWE-693",   # X-Content-Type-Options Header Missing
    10023: "CWE-200",   # Information Disclosure - Debug Error Messages
    10024: "CWE-200",   # Information Disclosure - Sensitive Info in URL
    10025: "CWE-200",   # Information Disclosure - Sensitive Info in HTTP Referrer
    10027: "CWE-200",   # Information Disclosure - Suspicious Comments
    10035: "CWE-693",   # Strict-Transport-Security Header Not Set
    10036: "CWE-693",   # HTTP Server Response Header
    10037: "CWE-693",   # Server Leaks Information via X-Powered-By
    10038: "CWE-693",   # Content Security Policy Header Not Set
    10040: "CWE-523",   # Secure Pages Include Mixed Content
    10049: "CWE-16",    # Non-Storable Content
    10054: "CWE-693",   # Cookie without SameSite Attribute
    10055: "CWE-693",   # CSP
    10096: "CWE-200",   # Timestamp Disclosure
    10098: "CWE-942",   # Cross-Domain Misconfiguration
    10105: "CWE-829",   # Weak Authentication Method
    10202: "CWE-693",   # Absence of Anti-CSRF Tokens
    20012: "CWE-525",   # Anti-clickjacking Header
    20014: "CWE-693",   # HTTP Parameter Override
    40003: "CWE-93",    # CRLF Injection
    40008: "CWE-472",   # Parameter Tampering
    40009: "CWE-78",    # Server Side Include
    40012: "CWE-79",    # Cross Site Scripting (Reflected)
    40014: "CWE-79",    # Cross Site Scripting (Persistent)
    40016: "CWE-94",    # Cross Site Scripting (DOM Based)
    40018: "CWE-89",    # SQL Injection
    40019: "CWE-89",    # SQL Injection (MySQL)
    40020: "CWE-89",    # SQL Injection (Hypersonic)
    40021: "CWE-89",    # SQL Injection (Oracle)
    40022: "CWE-89",    # SQL Injection (PostgreSQL)
    40024: "CWE-89",    # SQL Injection (SQLite)
    40026: "CWE-94",    # Cross Site Scripting (DOM)
    40029: "CWE-209",   # Trace.axd Information Leak
    40032: "CWE-200",   # .htaccess Information Leak
    40034: "CWE-200",   # .env Information Leak
    40035: "CWE-200",   # Hidden File Finder
    90001: "CWE-525",   # Insecure JSF ViewState
    90011: "CWE-200",   # Charset Mismatch
    90019: "CWE-78",    # Server-Side Code Injection
    90020: "CWE-78",    # Remote OS Command Injection
    90021: "CWE-79",    # XPath Injection
    90023: "CWE-611",   # XML External Entity Attack
    90024: "CWE-209",   # Generic Padding Oracle
    90025: "CWE-94",    # Expression Language Injection
    90028: "CWE-200",   # Insecure HTTP Method
    90033: "CWE-200",   # Loosely Scoped Cookie
}


class ZAProxyWrapper(SecurityTool):
    """
    OWASP ZAP — Web application security scanner.

    Operational modes:
    1. ``passive_scan`` — Spider target, then harvest passive alerts (no active attacks)
    2. ``active_scan`` — Full active scan of specific URL(s)
    3. ``ajax_spider`` — Headless browser crawl for JavaScript-heavy sites
    4. ``spider_only`` — Traditional link-following crawler
    5. ``alerts_only`` — Just harvest existing alerts (if ZAP already has data)
    6. ``full`` — Spider + passive + active (comprehensive)

    Lifecycle:
    - ``ensure_running()`` starts the ZAP daemon if not already up
    - All API calls go through ``_api_get()`` / ``_api_post()``
    - ``stop_daemon()`` cleanly shuts ZAP down
    """

    name = "zaproxy"
    category = ToolCategory.PROXY
    description = "OWASP ZAP — automated web app security scanner via REST API"
    binary_name = "zap.sh"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    # Default API settings
    DEFAULT_PORT = 8090
    DEFAULT_API_KEY = None  # Require explicit config or env var

    def __init__(
        self,
        api_host: str = "127.0.0.1",
        api_port: int | None = None,
        api_key: str | None = None,
    ) -> None:
        super().__init__()
        self._host = api_host
        self._port = api_port or int(os.environ.get("ZAP_PORT", self.DEFAULT_PORT))
        self._api_key = (
            api_key
            or os.environ.get("ZAP_API_KEY")
            or self.DEFAULT_API_KEY
            or secrets.token_hex(16)
        )
        self._base_url = f"http://{self._host}:{self._port}"
        self._daemon_process: asyncio.subprocess.Process | None = None
        self._client: httpx.AsyncClient | None = None

    # ── Lifecycle ──────────────────────────────────────────────

    async def ensure_running(self, timeout: float = 60.0) -> bool:
        """
        Ensure ZAP daemon is running. Start it if needed.

        Returns True if ZAP is reachable via API.
        """
        if await self._is_api_reachable():
            logger.debug(f"ZAP already running at {self._base_url}")
            return True

        # Try to start ZAP daemon
        binary = self._resolve_binary()
        if not binary:
            # Try alternative locations
            for candidate in ("/usr/share/zaproxy/zap.sh", "/opt/zaproxy/zap.sh"):
                if Path(candidate).exists():
                    binary = candidate
                    break

        if not binary:
            logger.warning("ZAP binary not found — cannot start daemon")
            return False

        logger.info(f"Starting ZAP daemon on port {self._port}...")
        try:
            self._daemon_process = await asyncio.create_subprocess_exec(
                binary,
                "-daemon",
                "-port", str(self._port),
                "-config", f"api.key={self._api_key}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "spider.maxDuration=5",
                "-config", "scanner.maxScanDurationInMins=10",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except Exception as e:
            logger.error(f"Failed to start ZAP daemon: {e}")
            return False

        # Wait for API to become available
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if await self._is_api_reachable():
                logger.info(f"ZAP daemon ready at {self._base_url}")
                return True
            await asyncio.sleep(2)

        logger.warning(f"ZAP daemon did not become ready within {timeout}s")
        return False

    async def stop_daemon(self) -> None:
        """Stop the ZAP daemon."""
        try:
            await self._api_get("core/action/shutdown")
        except Exception as _exc:
            logger.debug(f"zaproxy wrapper error: {_exc}")

        if self._daemon_process:
            try:
                self._daemon_process.terminate()
                await asyncio.wait_for(self._daemon_process.wait(), timeout=10)
            except Exception as _exc:
                try:
                    self._daemon_process.kill()
                except Exception as _exc:
                    logger.debug(f"zaproxy wrapper error: {_exc}")
            self._daemon_process = None

        if self._client:
            await self._client.aclose()
            self._client = None

        logger.info("ZAP daemon stopped")

    # ── Core API Methods ───────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx client for ZAP API."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=30.0,
            )
        return self._client

    async def _api_get(self, endpoint: str, params: dict | None = None) -> dict:
        """Make GET request to ZAP REST API."""
        client = await self._get_client()
        params = params or {}
        params["apikey"] = self._api_key
        url = f"/JSON/{endpoint}/"
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            logger.warning(f"ZAP API returned non-JSON for {endpoint}")
            return {}

    async def _api_post(self, endpoint: str, data: dict | None = None) -> dict:
        """Make POST request to ZAP REST API (for actions)."""
        client = await self._get_client()
        data = data or {}
        data["apikey"] = self._api_key
        url = f"/JSON/{endpoint}/"
        resp = await client.post(url, data=data)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            logger.warning(f"ZAP API returned non-JSON for POST {endpoint}")
            return {}

    async def _is_api_reachable(self) -> bool:
        """Check if ZAP API is responding."""
        try:
            client = await self._get_client()
            resp = await client.get(
                "/JSON/core/view/version/",
                params={"apikey": self._api_key},
                timeout=30,
            )
            return resp.status_code == 200
        except Exception as _exc:
            return False

    # ── SecurityTool Interface ─────────────────────────────────

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        """
        Run ZAP scan against a target.

        Options:
            mode: passive_scan | active_scan | ajax_spider | spider_only |
                  alerts_only | full (default: passive_scan)
            max_duration: Maximum scan duration in minutes (default: 10)
            auth_header: Optional auth header to inject (e.g., "Bearer xxx")
            context_name: ZAP context name (default: auto-generated)
        """
        options = options or {}
        mode = options.get("mode", "passive_scan")

        # Ensure ZAP is running
        if not await self.ensure_running(timeout=90):
            return ToolResult(
                tool_name=self.name,
                success=False,
                exit_code=1,
                stdout="",
                stderr="Failed to start ZAP daemon — is zaproxy installed?",
                findings=[],
                command=f"zap.sh -daemon -port {self._port}",
                target=target,
            )

        try:
            # Configure target in ZAP
            await self._configure_target(target, options)

            if mode == "spider_only":
                findings = await self._run_spider(target, options)
            elif mode == "ajax_spider":
                findings = await self._run_ajax_spider(target, options)
            elif mode == "passive_scan":
                findings = await self._run_passive_scan(target, options)
            elif mode == "active_scan":
                findings = await self._run_active_scan(target, options, profile)
            elif mode == "full":
                findings = await self._run_full_scan(target, options, profile)
            elif mode == "alerts_only":
                findings = await self._harvest_alerts(target)
            else:
                findings = await self._run_passive_scan(target, options)

            return ToolResult(
                tool_name=self.name,
                success=True,
                exit_code=0,
                stdout=f"ZAP {mode} completed — {len(findings)} findings",
                stderr="",
                findings=findings,
                command=f"zap-api {mode} {target}",
                target=target,
                metadata={"mode": mode, "zap_port": self._port},
            )
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            return ToolResult(
                tool_name=self.name,
                success=False,
                exit_code=1,
                stdout="",
                stderr=str(e),
                findings=[],
                command=f"zap-api {mode} {target}",
                target=target,
            )

    # ── Scan Modes ─────────────────────────────────────────────

    async def _configure_target(self, target: str, options: dict) -> None:
        """Pre-scan configuration: context, auth, policies."""
        # Add target to default context
        try:
            await self._api_get("context/action/includeInContext", {
                "contextName": "Default Context",
                "regex": f".*{re.escape(target.replace('https://', '').replace('http://', '').split('/')[0])}.*",
            })
        except Exception as _exc:
            pass  # Context may already have this

        # Set authentication headers if provided
        auth_header = options.get("auth_header", "")
        if auth_header:
            try:
                await self._api_get("replacer/action/addRule", {
                    "description": "whai-auth",
                    "enabled": "true",
                    "matchType": "REQ_HEADER",
                    "matchRegex": "false",
                    "matchString": "Authorization",
                    "replacement": auth_header,
                    "initiators": "",
                })
            except Exception as e:
                logger.debug(f"ZAP auth header config failed: {e}")

    async def _run_spider(
        self, target: str, options: dict, max_minutes: int = 5,
    ) -> list[Finding]:
        """Run ZAP traditional spider."""
        max_min = options.get("spider_duration", max_minutes)

        logger.info(f"ZAP spider starting: {target} (max {max_min} min)")
        result = await self._api_get("spider/action/scan", {
            "url": target,
            "maxChildren": "100",
            "subtreeOnly": "true",
        })
        scan_id = result.get("scan", "0")

        # Wait for completion
        deadline = time.monotonic() + max_min * 60
        while time.monotonic() < deadline:
            status = await self._api_get("spider/view/status", {"scanId": scan_id})
            progress = int(status.get("status", "0"))
            if progress >= 100:
                break
            await asyncio.sleep(3)

        # Get discovered URLs
        urls_result = await self._api_get("spider/view/results", {"scanId": scan_id})
        urls = urls_result.get("results", [])
        logger.info(f"ZAP spider discovered {len(urls)} URLs")

        # Harvest passive scan findings from spidered traffic
        await asyncio.sleep(5)  # Let passive scanner catch up
        return await self._harvest_alerts(target)

    async def _run_ajax_spider(
        self, target: str, options: dict, max_minutes: int = 5,
    ) -> list[Finding]:
        """Run ZAP Ajax spider (headless browser crawling for SPAs)."""
        max_min = options.get("ajax_spider_duration", max_minutes)

        logger.info(f"ZAP Ajax spider starting: {target} (max {max_min} min)")
        await self._api_get("ajaxSpider/action/scan", {
            "url": target,
            "subtreeOnly": "true",
        })

        # Wait for completion
        deadline = time.monotonic() + max_min * 60
        while time.monotonic() < deadline:
            status = await self._api_get("ajaxSpider/view/status")
            if status.get("status") == "stopped":
                break
            await asyncio.sleep(5)

        # Stop if still running
        try:
            await self._api_get("ajaxSpider/action/stop")
        except Exception as _exc:
            logger.debug(f"zaproxy wrapper error: {_exc}")

        num_results = await self._api_get("ajaxSpider/view/numberOfResults")
        logger.info(f"ZAP Ajax spider found {num_results.get('numberOfResults', '?')} resources")

        await asyncio.sleep(5)
        return await self._harvest_alerts(target)

    async def _run_passive_scan(
        self, target: str, options: dict,
    ) -> list[Finding]:
        """Spider the target, then collect passive scan results."""
        # Spider first to generate traffic for passive analysis
        await self._run_spider(target, options, max_minutes=3)

        # Wait for passive scanner to finish processing
        for _ in range(30):
            queue = await self._api_get("pscan/view/recordsToScan")
            remaining = int(queue.get("recordsToScan", "0"))
            if remaining == 0:
                break
            await asyncio.sleep(2)

        return await self._harvest_alerts(target)

    async def _run_active_scan(
        self, target: str, options: dict, profile: ScanProfile,
    ) -> list[Finding]:
        """Run active vulnerability scan against target."""
        # Configure scan policy based on profile
        policy_name = f"whai-{profile.value}"
        try:
            await self._configure_scan_policy(policy_name, profile)
        except Exception as e:
            logger.debug(f"Scan policy config failed (using defaults): {e}")

        max_min = options.get("active_scan_duration", 10)
        logger.info(f"ZAP active scan starting: {target} (max {max_min} min)")

        result = await self._api_get("ascan/action/scan", {
            "url": target,
            "recurse": "true",
            "subtreeOnly": "true",
        })
        scan_id = result.get("scan", "0")

        # Wait for completion
        deadline = time.monotonic() + max_min * 60
        while time.monotonic() < deadline:
            status = await self._api_get("ascan/view/status", {"scanId": scan_id})
            progress = int(status.get("status", "0"))
            if progress >= 100:
                break
            logger.debug(f"ZAP active scan progress: {progress}%")
            await asyncio.sleep(10)

        # Force stop if over time
        if time.monotonic() >= deadline:
            try:
                await self._api_get("ascan/action/stop", {"scanId": scan_id})
            except Exception as _exc:
                logger.debug(f"zaproxy wrapper error: {_exc}")

        return await self._harvest_alerts(target)

    async def _run_full_scan(
        self, target: str, options: dict, profile: ScanProfile,
    ) -> list[Finding]:
        """Full scan: Spider → Ajax Spider → Passive → Active."""
        all_findings: list[Finding] = []

        # Phase 1: Traditional spider
        logger.info("ZAP full scan Phase 1: Spider")
        spider_findings = await self._run_spider(target, options, max_minutes=3)
        all_findings.extend(spider_findings)

        # Phase 2: Ajax spider (for SPA content)
        logger.info("ZAP full scan Phase 2: Ajax Spider")
        ajax_findings = await self._run_ajax_spider(target, options, max_minutes=3)
        # Deduplicate against spider findings
        existing_ids = {(f.title, f.target) for f in all_findings}
        for f in ajax_findings:
            if (f.title, f.target) not in existing_ids:
                all_findings.append(f)

        # Phase 3: Active scan
        logger.info("ZAP full scan Phase 3: Active Scan")
        active_findings = await self._run_active_scan(target, options, profile)
        existing_ids = {(f.title, f.target) for f in all_findings}
        for f in active_findings:
            if (f.title, f.target) not in existing_ids:
                all_findings.append(f)

        logger.info(f"ZAP full scan complete: {len(all_findings)} total findings")
        return all_findings

    # ── Alert Harvesting ───────────────────────────────────────

    async def _harvest_alerts(self, target: str) -> list[Finding]:
        """Fetch all ZAP alerts and convert to Finding objects."""
        findings: list[Finding] = []
        start = 0
        page_size = 100

        while True:
            result = await self._api_get("alert/view/alerts", {
                "baseurl": target,
                "start": str(start),
                "count": str(page_size),
            })
            alerts = result.get("alerts", [])
            if not alerts:
                break

            for alert in alerts:
                finding = self._alert_to_finding(alert, target)
                if finding:
                    findings.append(finding)

            if len(alerts) < page_size:
                break
            start += page_size

        # Deduplicate by (title, url)
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.title, f.target)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        logger.info(f"ZAP harvested {len(unique)} unique alerts (from {len(findings)} total)")
        return unique

    def _alert_to_finding(self, alert: dict, target: str) -> Finding | None:
        """Convert a ZAP alert JSON object to a Finding."""
        risk = alert.get("risk", 0)
        if isinstance(risk, str):
            risk = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}.get(risk, 0)

        confidence = alert.get("confidence", 2)
        if isinstance(confidence, str):
            confidence = {"False Positive": 0, "Low": 1, "Medium": 2, "High": 3,
                          "User Confirmed": 4}.get(confidence, 2)

        severity = _ZAP_RISK_MAP.get(risk, SeverityLevel.INFO)
        conf_score = _ZAP_CONFIDENCE_MAP.get(confidence, 50.0)

        alert_name = alert.get("alert", alert.get("name", "Unknown"))
        url = alert.get("url", target)
        plugin_id = int(alert.get("pluginId", alert.get("id", 0)))
        cwe_id = _ZAP_CWE_MAP.get(plugin_id, f"CWE-{alert.get('cweid', 0)}")

        description_parts = [
            alert.get("description", ""),
            f"\n**URL:** {url}",
        ]
        if alert.get("param"):
            description_parts.append(f"**Parameter:** {alert['param']}")
        if alert.get("attack"):
            description_parts.append(f"**Attack:** {alert['attack']}")
        if alert.get("evidence"):
            description_parts.append(f"**Evidence:** {alert['evidence'][:500]}")
        if alert.get("solution"):
            description_parts.append(f"\n**Solution:** {alert['solution']}")
        if alert.get("reference"):
            description_parts.append(f"**References:** {alert['reference'][:300]}")

        return Finding(
            title=f"ZAP: {alert_name}",
            description="\n".join(description_parts),
            vulnerability_type=self._classify_vuln_type(alert_name, plugin_id),
            severity=severity,
            confidence=conf_score,
            target=url,
            endpoint=url,
            tool_name=self.name,
            cwe_id=cwe_id,
            tags=["zaproxy", f"pluginId-{plugin_id}"],
            metadata={
                "zap_plugin_id": plugin_id,
                "zap_risk": risk,
                "zap_confidence": confidence,
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
                "evidence": alert.get("evidence", "")[:1000],
                "solution": alert.get("solution", ""),
                "other_info": alert.get("other", "")[:500],
                "message_id": alert.get("messageId", ""),
            },
            remediation=alert.get("solution", ""),
        )

    @staticmethod
    def _classify_vuln_type(alert_name: str, plugin_id: int) -> str:
        """Map ZAP alert name/ID to our vulnerability type taxonomy."""
        name_lower = alert_name.lower()

        if "sql injection" in name_lower:
            return "sqli"
        if "cross site scripting" in name_lower or "xss" in name_lower:
            if "dom" in name_lower:
                return "xss_dom"
            if "stored" in name_lower or "persistent" in name_lower:
                return "xss_stored"
            return "xss_reflected"
        if "command injection" in name_lower or "os command" in name_lower:
            return "rce"
        if "path traversal" in name_lower or "directory traversal" in name_lower:
            return "lfi"
        if "ssrf" in name_lower or "server side request" in name_lower:
            return "ssrf"
        if "xxe" in name_lower or "xml external" in name_lower:
            return "xxe"
        if "csrf" in name_lower or "cross-site request forgery" in name_lower:
            return "csrf"
        if "open redirect" in name_lower:
            return "open_redirect"
        if "crlf" in name_lower or "header injection" in name_lower:
            return "crlf"
        if "cookie" in name_lower:
            return "cookie_security"
        if "header" in name_lower and ("missing" in name_lower or "not set" in name_lower):
            return "missing_security_header"
        if "cors" in name_lower or "cross-domain" in name_lower:
            return "cors"
        if "information disclosure" in name_lower or "information leak" in name_lower:
            return "information_disclosure"
        if "authentication" in name_lower:
            return "auth_bypass"
        if "ssl" in name_lower or "tls" in name_lower:
            return "ssl_tls"
        if "clickjack" in name_lower or "x-frame" in name_lower:
            return "clickjacking"

        return "misconfiguration"

    # ── Scan Policy Configuration ──────────────────────────────

    async def _configure_scan_policy(
        self, policy_name: str, profile: ScanProfile,
    ) -> None:
        """Configure ZAP active scan policy based on profile."""
        # Create or update policy
        try:
            await self._api_get("ascan/action/addScanPolicy", {
                "scanPolicyName": policy_name,
            })
        except Exception as _exc:
            pass  # May already exist

        if profile == ScanProfile.STEALTH:
            # Minimal scanning — low noise
            pass
        elif profile == ScanProfile.AGGRESSIVE:
            # Maximum coverage
            pass
        else:
            # Balanced
            pass

        try:
            await self._api_get("ascan/action/setOptionDefaultPolicy", {
                "String": policy_name,
            })
        except Exception as _exc:
            logger.debug(f"zaproxy wrapper error: {_exc}")

    # ── Utility Methods ────────────────────────────────────────

    async def get_discovered_urls(self) -> list[str]:
        """Get all URLs discovered by ZAP (spider + ajax spider)."""
        try:
            result = await self._api_get("core/view/urls")
            return result.get("urls", [])
        except Exception as _exc:
            logger.debug(f"zaproxy wrapper error: {_exc}")
            return []

    async def get_messages_for_url(self, url: str) -> list[dict]:
        """Get all HTTP messages (request/response) for a given URL."""
        try:
            result = await self._api_get("core/view/messages", {
                "baseurl": url,
                "start": "0",
                "count": "50",
            })
            return result.get("messages", [])
        except Exception as _exc:
            logger.debug(f"zaproxy wrapper error: {_exc}")
            return []

    async def send_request(
        self, method: str, url: str, body: str = "", headers: dict | None = None,
    ) -> dict | None:
        """
        Send a manual HTTP request through ZAP.
        Useful for replay-based FP verification.
        """
        # Build raw request string
        parsed = httpx.URL(url)
        path = str(parsed.raw_path, "ascii") if isinstance(parsed.raw_path, bytes) else parsed.raw_path
        raw_headers = f"{method} {path} HTTP/1.1\r\nHost: {parsed.host}\r\n"
        if headers:
            for k, v in headers.items():
                raw_headers += f"{k}: {v}\r\n"
        raw_headers += "\r\n"
        if body:
            raw_headers += body

        try:
            result = await self._api_get("core/other/sendRequest", {
                "request": raw_headers,
            })
            return result
        except Exception as e:
            logger.debug(f"ZAP send_request failed: {e}")
            return None

    # ── SecurityTool abstract methods ──────────────────────────

    def build_command(
        self, target: str, options: dict | None = None, profile: ScanProfile | None = None,
    ) -> list[str]:
        """Build ZAP daemon start command."""
        return [
            self.binary_name, "-daemon",
            "-port", str(self._port),
            "-config", f"api.key={self._api_key}",
        ]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        """Parse ZAP console output (minimal — most data comes via API)."""
        # ZAP daemon output is minimal; findings come from API
        return []

    def is_available(self) -> bool:
        """Check if ZAP is installed."""
        if shutil.which("zap.sh"):
            return True
        if shutil.which("zaproxy"):
            return True
        # Check common installation paths
        for path in (
            "/usr/share/zaproxy/zap.sh",
            "/opt/zaproxy/zap.sh",
            "/usr/local/bin/zap.sh",
        ):
            if Path(path).exists():
                return True
        return False

    def _resolve_binary(self) -> str | None:
        """Find ZAP binary."""
        for name in ("zap.sh", "zaproxy"):
            path = shutil.which(name)
            if path:
                return path
        for path in (
            "/usr/share/zaproxy/zap.sh",
            "/opt/zaproxy/zap.sh",
        ):
            if Path(path).exists():
                return path
        return None


__all__ = ["ZAProxyWrapper"]
