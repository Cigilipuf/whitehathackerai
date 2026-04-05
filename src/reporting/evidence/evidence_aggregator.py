"""
WhiteHatHacker AI — Evidence Aggregator

Collects, packages, and exports all evidence for a verified finding
into a single unified evidence package. Bridges the gap between
scattered evidence sources (PoC executor, screenshots, request logger,
evidence chain builder) and the reporting system.

Each proven finding gets a complete evidence directory containing:
  - evidence.json — structured metadata
  - poc_script.py — the PoC code that proved the vulnerability
  - poc_output.txt — execution output with evidence markers
  - http_exchanges.har — HAR-format HTTP exchanges
  - screenshots/ — visual evidence
  - evidence_chain.json — cryptographic evidence chain
  - summary.md — human-readable evidence summary
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger


@dataclass
class EvidencePackage:
    """Complete evidence package for a single finding."""
    finding_id: str = ""
    finding_title: str = ""
    vulnerability_type: str = ""
    severity: str = ""
    url: str = ""

    # Core evidence
    is_proven: bool = False
    confidence: float = 0.0
    poc_code: str = ""
    poc_output: str = ""
    evidence_items: list[str] = field(default_factory=list)

    # Evidence chain
    evidence_chain_id: str = ""
    evidence_chain_hash: str = ""
    completeness_score: float = 0.0

    # HTTP evidence
    http_exchanges: list[dict] = field(default_factory=list)

    # Screenshots
    screenshot_paths: list[str] = field(default_factory=list)

    # Metasploit
    metasploit_module: str = ""

    # Metadata
    verification_strategy: str = ""
    verification_time: float = 0.0
    iterations_used: int = 0
    created_at: float = field(default_factory=time.time)

    # Export
    package_dir: str = ""

    @property
    def evidence_count(self) -> int:
        return len(self.evidence_items) + len(self.http_exchanges) + len(self.screenshot_paths)


class EvidenceAggregator:
    """
    Unified evidence collection and export for proven findings.

    This module bridges the gap between:
    - ExploitVerifier (proves findings)
    - EvidenceChainBuilder (hashes + integrity)
    - RequestLogger (HTTP exchanges)
    - ScreenshotCapture (visual evidence)
    - PoCRecorder (PoC artifacts)
    - HARExporter (HAR format)

    Usage:
        aggregator = EvidenceAggregator(session_dir="output/evidence/session123")
        package = await aggregator.collect(proven_finding)
        aggregator.export(package)
    """

    def __init__(self, session_dir: str = "") -> None:
        self.session_dir = session_dir or f"output/evidence/{int(time.time())}"
        self._packages: list[EvidencePackage] = []

    async def collect(
        self,
        proven_finding: Any,  # ProvenFinding from ExploitVerifier
        evidence_chain: Any = None,  # EvidenceChain from builder
        capture_screenshot: bool = True,
    ) -> EvidencePackage:
        """
        Collect all evidence for a proven finding into a single package.

        Args:
            proven_finding: ProvenFinding from ExploitVerifier
            evidence_chain: Optional EvidenceChain with integrity hashes
            capture_screenshot: Whether to attempt screenshot capture

        Returns:
            Complete EvidencePackage
        """
        # Guard: proven_finding may be a dict or incompatible object
        finding = getattr(proven_finding, "finding", None)
        if finding is None:
            finding = proven_finding if isinstance(proven_finding, dict) else {}

        package = EvidencePackage(
            finding_id=str(finding.get("id", hashlib.sha256(finding.get("title", "").encode()).hexdigest()[:16])),
            finding_title=finding.get("title", "Unknown"),
            vulnerability_type=finding.get("vulnerability_type", finding.get("type", "")),
            severity=str(finding.get("severity", "unknown")),
            url=finding.get("url", ""),
            is_proven=getattr(proven_finding, "is_proven", False),
            confidence=getattr(proven_finding, "confidence", 0.0),
            poc_code=getattr(proven_finding, "poc_code", ""),
            poc_output=getattr(proven_finding, "poc_output", ""),
            evidence_items=list(getattr(proven_finding, "evidence_items", [])),
            verification_strategy=getattr(getattr(proven_finding, "strategy_used", None), "value", "unknown"),
            verification_time=getattr(proven_finding, "verification_time", 0.0),
            iterations_used=getattr(proven_finding, "iterations_used", 0),
            metasploit_module=getattr(proven_finding, "metasploit_module", ""),
        )

        # Add evidence chain metadata
        if evidence_chain:
            package.evidence_chain_id = getattr(evidence_chain, "chain_id", "")
            package.evidence_chain_hash = getattr(evidence_chain, "chain_hash", "")
            package.completeness_score = getattr(evidence_chain, "completeness_score", 0.0)

        # Capture HTTP exchanges from finding metadata
        package.http_exchanges = self._extract_http_exchanges(finding, proven_finding)

        # Capture screenshot if URL available and enabled
        if capture_screenshot and package.url and package.is_proven:
            screenshot_path = await self._capture_screenshot(package.url, package.finding_id)
            if screenshot_path:
                package.screenshot_paths.append(screenshot_path)

        self._packages.append(package)
        return package

    def export(self, package: EvidencePackage) -> str:
        """
        Export evidence package to disk as a structured directory.

        Returns path to the evidence directory.
        """
        # Create evidence directory
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in package.finding_id[:30])
        package_dir = os.path.join(self.session_dir, f"evidence_{safe_id}")
        os.makedirs(package_dir, exist_ok=True)
        package.package_dir = package_dir

        # 1. Evidence metadata JSON
        meta = {
            "finding_id": package.finding_id,
            "finding_title": package.finding_title,
            "vulnerability_type": package.vulnerability_type,
            "severity": package.severity,
            "url": package.url,
            "is_proven": package.is_proven,
            "confidence": package.confidence,
            "evidence_chain_id": package.evidence_chain_id,
            "evidence_chain_hash": package.evidence_chain_hash,
            "completeness_score": package.completeness_score,
            "verification_strategy": package.verification_strategy,
            "verification_time": package.verification_time,
            "iterations_used": package.iterations_used,
            "metasploit_module": package.metasploit_module,
            "evidence_count": package.evidence_count,
            "evidence_items": package.evidence_items,
            "created_at": package.created_at,
        }
        with open(os.path.join(package_dir, "evidence.json"), "w") as f:
            json.dump(meta, f, indent=2, default=str)

        # 2. PoC Script
        if package.poc_code:
            ext = ".py" if not package.poc_code.strip().startswith("curl") else ".sh"
            with open(os.path.join(package_dir, f"poc_script{ext}"), "w") as f:
                f.write(package.poc_code)

        # 3. PoC Output
        if package.poc_output:
            with open(os.path.join(package_dir, "poc_output.txt"), "w") as f:
                f.write(package.poc_output)

        # 4. HTTP Exchanges as HAR
        if package.http_exchanges:
            har = self._build_har(package)
            with open(os.path.join(package_dir, "http_exchanges.har"), "w") as f:
                json.dump(har, f, indent=2)

        # 5. Summary markdown
        summary = self._build_summary(package)
        with open(os.path.join(package_dir, "summary.md"), "w") as f:
            f.write(summary)

        logger.debug(f"Evidence exported to {package_dir}")
        return package_dir

    def export_all(self) -> list[str]:
        """Export all collected evidence packages."""
        paths = []
        for pkg in self._packages:
            if pkg.is_proven:
                paths.append(self.export(pkg))
        return paths

    def get_proven_packages(self) -> list[EvidencePackage]:
        """Return only packages for proven findings."""
        return [p for p in self._packages if p.is_proven]

    # ── Private Methods ───────────────────────────────────────────────────

    def _extract_http_exchanges(
        self,
        finding: dict,
        proven_finding: Any,
    ) -> list[dict]:
        """Extract HTTP exchanges from finding and PoC result."""
        exchanges = []

        # From finding metadata
        if finding.get("http_request") or finding.get("http_response"):
            exchanges.append({
                "method": finding.get("http_method", "GET"),
                "url": finding.get("url", ""),
                "request_headers": finding.get("http_request_headers", {}),
                "request_body": finding.get("http_request_body", ""),
                "response_status": finding.get("http_response_status", 0),
                "response_headers": finding.get("http_response_headers", {}),
                "response_body": str(finding.get("http_response", ""))[:5000],
                "payload": finding.get("payload", ""),
                "source": "finding",
            })

        # From PoC output (parse curl verbose)
        poc_output = getattr(proven_finding, "poc_output", "") or ""
        if "< HTTP/" in poc_output:
            import re
            status_match = re.search(r"< HTTP/[\d.]+ (\d{3})", poc_output)
            exchanges.append({
                "method": "PoC",
                "url": finding.get("url", ""),
                "response_status": int(status_match.group(1)) if status_match else 0,
                "response_body": poc_output[:3000],
                "source": "poc_execution",
            })

        return exchanges

    async def _capture_screenshot(self, url: str, finding_id: str) -> str:
        """Attempt to capture a screenshot of the vulnerable URL."""
        try:
            from src.reporting.evidence.screenshot import ScreenshotCapture
            sc = ScreenshotCapture()
            if not sc.is_available:
                return ""

            screenshot_dir = os.path.join(self.session_dir, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)

            safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in finding_id[:20])
            output_path = os.path.join(screenshot_dir, f"vuln_{safe_id}.png")

            result = await sc.capture(url, output_path=output_path)
            if result and result.success:
                return output_path
        except Exception as e:
            logger.debug(f"Screenshot capture failed: {e}")

        return ""

    def _build_har(self, package: EvidencePackage) -> dict:
        """Build HAR 1.2 format from HTTP exchanges."""
        entries = []
        for ex in package.http_exchanges:
            entry = {
                "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(package.created_at)),
                "time": 0,
                "request": {
                    "method": ex.get("method", "GET"),
                    "url": ex.get("url", ""),
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in (ex.get("request_headers") or {}).items()
                    ],
                    "queryString": [],
                    "bodySize": len(ex.get("request_body", "")),
                    "postData": {
                        "mimeType": "application/x-www-form-urlencoded",
                        "text": ex.get("request_body", ""),
                    } if ex.get("request_body") else {},
                },
                "response": {
                    "status": ex.get("response_status", 0),
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in (ex.get("response_headers") or {}).items()
                    ],
                    "content": {
                        "size": len(ex.get("response_body", "")),
                        "mimeType": "text/html",
                        "text": ex.get("response_body", ""),
                    },
                    "bodySize": len(ex.get("response_body", "")),
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
                "comment": ex.get("source", ""),
            }
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "WhiteHatHacker AI", "version": "2.4"},
                "entries": entries,
            }
        }

    def _build_summary(self, package: EvidencePackage) -> str:
        """Build human-readable evidence summary."""
        lines = [
            f"# Evidence Summary: {package.finding_title}",
            "",
            f"**Status:** {'PROVEN' if package.is_proven else 'NOT PROVEN'}",
            f"**Confidence:** {package.confidence:.0f}/100",
            f"**Severity:** {package.severity.upper()}",
            f"**URL:** {package.url}",
            f"**Vulnerability Type:** {package.vulnerability_type}",
            f"**Verification Strategy:** {package.verification_strategy}",
            f"**Verification Time:** {package.verification_time:.1f}s",
            f"**Iterations Used:** {package.iterations_used}",
            "",
        ]

        if package.metasploit_module:
            lines.append(f"**Metasploit Module:** {package.metasploit_module}")
            lines.append("")

        if package.evidence_chain_id:
            lines.extend([
                "## Evidence Chain",
                f"- **Chain ID:** {package.evidence_chain_id}",
                f"- **Integrity Hash:** {package.evidence_chain_hash}",
                f"- **Completeness:** {package.completeness_score:.0%}",
                "",
            ])

        if package.evidence_items:
            lines.append("## Evidence Indicators")
            for item in package.evidence_items:
                lines.append(f"- {item}")
            lines.append("")

        if package.poc_code:
            ext = "bash" if package.poc_code.strip().startswith("curl") else "python"
            lines.extend([
                "## PoC Code",
                f"```{ext}",
                package.poc_code[:3000],
                "```",
                "",
            ])

        if package.poc_output:
            lines.extend([
                "## PoC Output",
                "```",
                package.poc_output[:2000],
                "```",
                "",
            ])

        if package.http_exchanges:
            lines.append("## HTTP Exchanges")
            for i, ex in enumerate(package.http_exchanges, 1):
                lines.extend([
                    f"### Exchange {i}",
                    f"- **Method:** {ex.get('method', 'GET')}",
                    f"- **URL:** {ex.get('url', '')}",
                    f"- **Status:** {ex.get('response_status', 'N/A')}",
                    "",
                ])

        return "\n".join(lines)


__all__ = [
    "EvidenceAggregator",
    "EvidencePackage",
]
