"""
WhiteHatHacker AI — Interactsh OOB Wrapper

Out-of-Band (OOB) interaction server for detecting blind vulnerabilities.
Uses the Interactsh CLI or hosted server for DNS/HTTP/SMTP callbacks.

Session-based architecture:
  1. start_session() — launch interactsh-client, get OOB domain
  2. get_payload_url(tag) — generate tagged callback URLs for payloads
  3. poll_interactions() — check for received callbacks
  4. stop_session() — cleanup background process
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import asyncio
from typing import Any

from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# ── Known infrastructure IP ranges (CDN / public DNS resolvers) ──
# These frequently generate OOB DNS callbacks that are NOT evidence of
# a vulnerability — they are normal resolver behaviour.
# Loaded from data/known_infrastructure_ips.json when available,
# with inline fallback for resilience.
_INFRASTRUCTURE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

_INLINE_FALLBACK_CIDRS: list[str] = [
    "1.1.1.0/24", "1.0.0.0/24", "8.8.8.0/24", "8.8.4.0/24",
    "9.9.9.0/24", "149.112.112.0/24", "208.67.222.0/24", "208.67.220.0/24",
    "104.16.0.0/13", "172.64.0.0/13", "23.32.0.0/11", "151.101.0.0/16",
]


def _load_infrastructure_cidrs() -> list[str]:
    """Load CIDRs from data/known_infrastructure_ips.json, fallback to inline."""
    from pathlib import Path

    json_path = Path(__file__).resolve().parents[3] / "data" / "known_infrastructure_ips.json"
    if json_path.is_file():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            cidrs: list[str] = []
            for key, val in data.items():
                if key.startswith("_"):
                    continue
                if isinstance(val, list):
                    cidrs.extend(val)
            return cidrs
        except Exception:
            logger.warning("Failed to load known_infrastructure_ips.json, using inline fallback")
    return _INLINE_FALLBACK_CIDRS


for _cidr in _load_infrastructure_cidrs():
    try:
        _INFRASTRUCTURE_NETWORKS.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        pass


def is_infrastructure_ip(addr: str) -> bool:
    """Return True if *addr* belongs to a known CDN / public resolver."""
    # Strip port if present
    if ":" in addr and not addr.startswith("["):
        # Could be IPv4:port — split off last segment
        parts = addr.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            addr = parts[0]
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _INFRASTRUCTURE_NETWORKS)


def classify_callback_quality(protocol: str, remote_addr: str) -> str:
    """Classify OOB callback quality: 'high', 'medium', 'low', or 'infrastructure'.

    - HTTP from non-infra IP → high (strong evidence of SSRF/RCE)
    - HTTP from infra IP → low (CDN edge fetching)
    - DNS from non-infra IP → medium (may indicate vuln, but DNS is noisy)
    - DNS from infra IP → infrastructure (public resolver, not evidence)
    """
    proto = protocol.upper()
    infra = is_infrastructure_ip(remote_addr)
    if proto == "HTTP":
        return "low" if infra else "high"
    if proto == "DNS":
        return "infrastructure" if infra else "medium"
    # SMTP, FTP, LDAP — same as HTTP
    return "low" if infra else "high"


class InteractshWrapper(SecurityTool):
    """
    Interactsh — Out-of-Band interaction server for blind vuln detection.

    Features:
    - Session-based OOB domain management
    - Generates unique tagged OOB URLs for payload correlation
    - Monitors DNS, HTTP, SMTP, LDAP interactions
    - Integrates with SSRF/XXE/RCE/SQLi/XSS blind testing
    - Auto-correlates interactions with payload tags

    Requires: `interactsh-client` binary (Go-based)
    """

    name = "interactsh"
    category = ToolCategory.SCANNER
    description = "Interactsh OOB server — blind vuln detection via callbacks"
    binary_name = "interactsh-client"
    requires_root = False
    risk_level = RiskLevel.LOW

    def __init__(self) -> None:
        super().__init__()
        self._oob_domain: str | None = None
        self._session_process: asyncio.subprocess.Process | None = None
        self._session_output: list[str] = []
        self._interactions: list[dict[str, Any]] = []
        self._session_active: bool = False
        self._reader_task: asyncio.Task | None = None

    # ── Session Management ────────────────────────────────────

    async def start_session(
        self,
        server: str | None = None,
        token: str | None = None,
        poll_interval: int = 5,
    ) -> str | None:
        """
        Start interactsh-client in background and capture the OOB domain.

        Returns the OOB domain (e.g. abc123.oast.fun) or None on failure.
        """
        if self._session_active:
            logger.debug(f"Interactsh session already active: {self._oob_domain}")
            return self._oob_domain

        if not self.is_available():
            logger.warning("interactsh-client not found in PATH")
            return None

        server = server or os.environ.get("INTERACTSH_SERVER", "")
        token = token or os.environ.get("INTERACTSH_TOKEN", "")

        cmd = [self._resolve_binary() or self.binary_name, "-json"]
        cmd.extend(["-poll-interval", str(poll_interval)])
        if server:
            cmd.extend(["-server", server])
        if token:
            cmd.extend(["-token", token])

        try:
            self._session_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as exc:
            logger.warning(f"Failed to start interactsh-client: {exc}")
            return None

        # Read output until we see the OOB domain (or timeout)
        domain = await self._wait_for_domain(timeout=20)
        if domain:
            self._oob_domain = domain
            self._session_active = True
            # Start background reader to capture interactions
            self._reader_task = asyncio.create_task(self._background_reader())
            logger.info(f"📡 Interactsh session started | OOB domain: {domain}")
        else:
            logger.warning("Interactsh session started but could not capture OOB domain")
            await self.stop_session()

        return self._oob_domain

    async def _wait_for_domain(self, timeout: float = 20) -> str | None:
        """Read process output until the OOB domain URL appears."""
        if not self._session_process or not self._session_process.stdout:
            return None

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = await asyncio.wait_for(
                    self._session_process.stdout.readline(),
                    timeout=max(0.5, deadline - time.monotonic()),
                )
            except asyncio.TimeoutError:
                continue

            if not line:
                break
            decoded = line.decode("utf-8", errors="replace").strip()
            self._session_output.append(decoded)

            # interactsh-client prints: [INF] Listing 1 payload for OOB Testing
            # then the domain on the next line, or in URL format
            domain_match = re.search(r"(\S+\.oast\.\S+)", decoded)
            if domain_match:
                return domain_match.group(1).rstrip(".")

        return None

    async def _background_reader(self) -> None:
        """Continuously read interactions from the running process."""
        if not self._session_process or not self._session_process.stdout:
            return

        consecutive_errors = 0
        max_consecutive_errors = 5

        while self._session_active:
            try:
                line = await asyncio.wait_for(
                    self._session_process.stdout.readline(),
                    timeout=2.0,
                )
                consecutive_errors = 0  # reset on success
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.debug("Interactsh background reader cancelled")
                return
            except Exception as exc:
                consecutive_errors += 1
                logger.warning(
                    f"Interactsh reader error ({consecutive_errors}/{max_consecutive_errors}): {exc}"
                )
                if consecutive_errors >= max_consecutive_errors:
                    logger.error(
                        "Interactsh background reader stopping after "
                        f"{max_consecutive_errors} consecutive errors"
                    )
                    break
                await asyncio.sleep(1.0)
                continue

            if not line:
                # EOF — process likely exited
                logger.warning("Interactsh process stdout EOF — reader stopping")
                break

            decoded = line.decode("utf-8", errors="replace").strip()
            self._session_output.append(decoded)

            if decoded.startswith("{"):
                try:
                    data = json.loads(decoded)
                    # Annotate callback with quality classification
                    protocol = data.get("protocol", "unknown")
                    remote = data.get("remote-address", "unknown")
                    quality = classify_callback_quality(protocol, remote)
                    data["_callback_quality"] = quality
                    data["_is_infrastructure"] = is_infrastructure_ip(remote)
                    self._interactions.append(data)
                    logger.info(
                        f"📡 OOB callback received: {protocol.upper()} from {remote}"
                        f" [quality={quality}]"
                    )
                except json.JSONDecodeError:
                    pass

    async def stop_session(self) -> None:
        """Stop the interactsh-client background process."""
        self._session_active = False

        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._session_process:
            try:
                self._session_process.terminate()
                await asyncio.wait_for(self._session_process.wait(), timeout=5)
            except Exception as _exc:
                try:
                    self._session_process.kill()
                except Exception as _exc:
                    logger.debug(f"interactsh wrapper error: {_exc}")
            self._session_process = None

        logger.info(
            f"📡 Interactsh session ended | "
            f"interactions={len(self._interactions)} | "
            f"domain={self._oob_domain}"
        )

    # ── Payload URL Generation ────────────────────────────────

    def get_payload_url(self, tag: str = "", protocol: str = "http") -> str | None:
        """
        Generate a tagged OOB URL for use in payloads.

        Args:
            tag: Short identifier (e.g. "ssrf-param1") — will be a subdomain prefix
            protocol: http or https

        Returns:
            URL like http://ssrf-param1.abc123.oast.fun or None
        """
        if not self._oob_domain:
            return None

        # Sanitize tag: only alphanum and hyphens
        safe_tag = re.sub(r"[^a-zA-Z0-9-]", "", tag)[:30]
        if safe_tag:
            return f"{protocol}://{safe_tag}.{self._oob_domain}"
        return f"{protocol}://{self._oob_domain}"

    def get_dns_canary(self, tag: str = "") -> str | None:
        """Generate a DNS-only canary domain (for XXE, SSRF, etc.)."""
        if not self._oob_domain:
            return None
        safe_tag = re.sub(r"[^a-zA-Z0-9-]", "", tag)[:30]
        if safe_tag:
            return f"{safe_tag}.{self._oob_domain}"
        return self._oob_domain

    # ── Interaction Retrieval ─────────────────────────────────

    def get_interactions(self, tag: str | None = None) -> list[dict[str, Any]]:
        """
        Retrieve received OOB interactions, optionally filtered by tag.

        Args:
            tag: If provided, only return interactions whose full-id contains this tag

        Returns:
            List of interaction dicts
        """
        if not tag:
            return list(self._interactions)
        safe_tag = re.sub(r"[^a-zA-Z0-9-]", "", tag).lower()
        return [
            i for i in self._interactions
            if safe_tag in (i.get("full-id", "") + i.get("unique-id", "")).lower()
        ]

    def has_interaction(self, tag: str | None = None) -> bool:
        """Check if any OOB interaction was received (optionally for a specific tag)."""
        return len(self.get_interactions(tag)) > 0

    async def poll_interactions(self, wait_seconds: float = 10) -> list[dict[str, Any]]:
        """Wait for new interactions for a specified duration, then return all."""
        before = len(self._interactions)
        await asyncio.sleep(wait_seconds)
        new_count = len(self._interactions) - before
        if new_count > 0:
            logger.info(f"📡 {new_count} new OOB interaction(s) received during poll")
        return list(self._interactions)

    # ── Standard SecurityTool Interface ───────────────────────

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        """
        Run interactsh-client to generate OOB domain and poll for interactions.

        For session-based use, prefer start_session() / poll_interactions() / stop_session().
        This method is a one-shot convenience wrapper.
        """
        options = options or {}
        poll_duration = options.get("poll_duration", 30)

        command = self.build_command(target, options, profile)
        stdout, stderr, exit_code = await self.execute_command(
            command, timeout=poll_duration + 15
        )
        findings = self.parse_output(stdout + "\n" + stderr, target)

        return ToolResult(
            tool_name=self.name,
            success=exit_code == 0 or len(findings) > 0,
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
        binary = self._resolve_binary() or self.binary_name
        cmd = [binary]

        # Poll duration
        cmd.extend(["-poll-interval", "5"])

        # JSON output
        cmd.append("-json")

        # Custom server
        server = options.get("server") or os.environ.get("INTERACTSH_SERVER", "")
        if server:
            cmd.extend(["-server", server])

        # Auth token
        token = options.get("token") or os.environ.get("INTERACTSH_TOKEN", "")
        if token:
            cmd.extend(["-token", token])

        # Number of interactions to keep
        cmd.extend(["-n", str(options.get("count", 1))])

        # Verbose for more details
        if profile == ScanProfile.AGGRESSIVE:
            cmd.append("-v")

        return cmd

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Extract generated URL
        url_match = re.search(
            r"(\S+\.oast\.\S+)",
            raw_output, re.IGNORECASE,
        )
        oob_domain = url_match.group(1).rstrip(".") if url_match else ""

        # Parse JSON interaction lines
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line.startswith("{"):
                url_m = re.search(r"(\S+\.oast\.\S+)", line)
                if url_m and not oob_domain:
                    oob_domain = url_m.group(1).rstrip(".")
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            protocol = data.get("protocol", "unknown").upper()
            unique_id = data.get("unique-id", "")
            full_id = data.get("full-id", "")
            remote_addr = data.get("remote-address", "")
            raw_req = data.get("raw-request", "")
            raw_resp = data.get("raw-response", "")
            timestamp = data.get("timestamp", "")

            findings.append(Finding(
                title=f"OOB Interaction: {protocol} from {remote_addr}",
                description=(
                    f"Protocol: {protocol}\n"
                    f"From: {remote_addr}\n"
                    f"OOB ID: {full_id or unique_id}\n"
                    f"Time: {timestamp}"
                ),
                vulnerability_type=self._classify_vuln_type(protocol),
                severity=SeverityLevel.HIGH,
                confidence=85.0,
                target=target,
                endpoint=oob_domain,
                tool_name=self.name,
                http_request=raw_req[:2000],
                http_response=raw_resp[:2000],
                tags=["interactsh", "oob", protocol.lower()],
                metadata={
                    "protocol": protocol,
                    "remote_address": remote_addr,
                    "unique_id": unique_id,
                    "oob_domain": oob_domain,
                },
            ))

        # If domain was generated but no interaction, still record the domain
        if oob_domain and not findings:
            findings.append(Finding(
                title=f"OOB Domain Generated: {oob_domain}",
                description="Interactsh OOB domain ready. No interactions received during poll window.",
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=100.0,
                target=target,
                endpoint=oob_domain,
                tool_name=self.name,
                tags=["interactsh", "oob_domain"],
                metadata={"oob_domain": oob_domain},
            ))

        logger.debug(f"interactsh parsed {len(findings)} findings, oob_domain={oob_domain}")
        return findings

    def interactions_to_findings(self, target: str = "") -> list[Finding]:
        """Convert accumulated session interactions into Finding objects.

        Aggregates callbacks by (protocol, remote_address) to avoid flooding
        the FP elimination stage with one finding per raw DNS/HTTP callback.

        Callback quality determines confidence:
          high (HTTP from target IP)      → 80.0
          medium (DNS from non-infra IP)  → 55.0
          low (HTTP from CDN / infra)     → 30.0
          infrastructure (DNS from CDN)   → SKIPPED (not a finding)
        """
        if not self._interactions:
            return []

        # Quality → confidence mapping
        _QUALITY_CONFIDENCE: dict[str, float] = {
            "high": 80.0,
            "medium": 55.0,
            "low": 30.0,
            "infrastructure": 0.0,  # skipped
        }

        # Group interactions by (protocol, remote_addr)
        groups: dict[tuple[str, str], list[dict]] = {}
        for data in self._interactions:
            protocol = data.get("protocol", "unknown").upper()
            remote_addr = data.get("remote-address", "unknown")
            key = (protocol, remote_addr)
            groups.setdefault(key, []).append(data)

        findings: list[Finding] = []
        for (protocol, remote_addr), interactions in groups.items():
            # Determine quality from first interaction (all same proto+addr)
            quality = interactions[0].get(
                "_callback_quality",
                classify_callback_quality(protocol, remote_addr),
            )
            is_infra = interactions[0].get(
                "_is_infrastructure",
                is_infrastructure_ip(remote_addr),
            )

            # Skip infrastructure-only callbacks entirely
            if quality == "infrastructure":
                logger.debug(
                    f"Skipping {len(interactions)}x {protocol} from {remote_addr}"
                    " — infrastructure/CDN resolver"
                )
                continue

            confidence = _QUALITY_CONFIDENCE.get(quality, 55.0)
            count = len(interactions)
            # Collect unique IDs and timestamps for evidence
            unique_ids = list({d.get("unique-id", "") or d.get("full-id", "") for d in interactions} - {""})
            timestamps = [d.get("timestamp", "") for d in interactions if d.get("timestamp")]
            raw_reqs = [d.get("raw-request", "") for d in interactions if d.get("raw-request")]

            desc_lines = [
                f"Protocol: {protocol}",
                f"Source: {remote_addr}",
                f"Callback count: {count}",
                f"Callback quality: {quality}",
                f"Infrastructure IP: {is_infra}",
                f"OOB IDs: {', '.join(unique_ids[:5])}{'...' if len(unique_ids) > 5 else ''}",
            ]
            if timestamps:
                desc_lines.append(f"First seen: {timestamps[0]}")
                if len(timestamps) > 1:
                    desc_lines.append(f"Last seen: {timestamps[-1]}")

            # Severity based on quality
            severity = SeverityLevel.HIGH if quality == "high" else SeverityLevel.MEDIUM

            findings.append(Finding(
                title=f"OOB Interaction: {count}x {protocol} from {remote_addr}",
                description="\n".join(desc_lines),
                vulnerability_type=self._classify_vuln_type(protocol),
                severity=severity,
                confidence=confidence,
                target=target,
                endpoint=self._oob_domain or "",
                tool_name=self.name,
                http_request=(raw_reqs[0][:2000] if raw_reqs else ""),
                tags=["interactsh", "oob", protocol.lower()],
                metadata={
                    "protocol": protocol,
                    "remote_address": remote_addr,
                    "callback_count": count,
                    "callback_quality": quality,
                    "is_infrastructure": is_infra,
                    "unique_ids": unique_ids[:10],
                    "oob_domain": self._oob_domain or "",
                },
            ))
        return findings

    @staticmethod
    def _classify_vuln_type(protocol: str) -> str:
        proto = protocol.upper()
        if proto == "DNS":
            return "ssrf"  # DNS callback usually indicates SSRF/XXE/RCE
        if proto == "HTTP":
            return "ssrf"
        if proto in ("SMTP", "FTP", "LDAP"):
            return "ssrf"
        return "information_disclosure"

    @property
    def oob_domain(self) -> str | None:
        """Get the current session OOB domain."""
        return self._oob_domain


__all__ = ["InteractshWrapper"]
