"""
WhiteHatHacker AI — Evidence Quality Gate

Findings MUST present real evidence proportional to their severity
before reaching the FP elimination pipeline.  This gate prevents
status-code-only or empty-evidence findings from inflating
confidence downstream.

Severity tiers:
  CRITICAL / HIGH — At least one *positive* evidence signal required
      (payload reflection, data extraction, OOB callback from target IP,
       error-message leakage, command output, confirmed version match).
  MEDIUM          — Status-code difference or timing anomaly against
                    baseline, OR body-diff, OR any positive evidence.
  LOW / INFO      — Status code alone is acceptable (informational).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

# ── Evidence signal detectors ────────────────────────────────

# SQL/stack-trace error patterns
_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"SQL syntax",
        r"mysql_fetch",
        r"pg_query",
        r"ORA-\d{4,5}",
        r"SQLSTATE\[",
        r"syntax error at or near",
        r"unclosed quotation mark",
        r"Traceback \(most recent call",
        r"Exception in thread",
        r"stack\s*trace",
        r"at \w+\.\w+\(.*\.java:\d+\)",
        r"Fatal error.*on line \d+",
    )
]

# Payload reflection heuristic — common XSS / injection markers
_REFLECTION_MARKERS: tuple[str, ...] = (
    "<script",
    "alert(",
    "onerror=",
    "javascript:",
    "onload=",
    "onfocus=",
    "onmouseover=",
    "{{",
    "${",
    "<%",
)


@dataclass(slots=True)
class EvidenceVerdict:
    """Result of the evidence quality gate for a single finding."""

    passed: bool
    reason: str
    signals_found: list[str] = field(default_factory=list)
    confidence_cap: float | None = None  # If not None, cap confidence to this


def _has_payload_reflection(finding: dict[str, Any]) -> bool:
    """True when the payload appears reflected in evidence or HTTP response."""
    payload = (finding.get("payload") or "").strip()
    if not payload or len(payload) < 4:
        return False
    ev = (finding.get("evidence") or "").lower()
    hr = (finding.get("http_response") or "").lower()
    body = ev + hr
    if not body:
        return False
    return payload.lower() in body


def _has_error_leakage(finding: dict[str, Any]) -> bool:
    """True when evidence or HTTP response contains DB / stack-trace errors."""
    text = (finding.get("evidence") or "") + (finding.get("http_response") or "")
    if not text:
        return False
    return any(p.search(text) for p in _ERROR_PATTERNS)


def _has_data_extraction(finding: dict[str, Any]) -> bool:
    """True when metadata explicitly signals extracted data."""
    meta = finding.get("metadata") or {}
    if meta.get("data_extracted"):
        return True
    tags = set(t.lower() for t in (finding.get("tags") or []))
    return "data_extraction" in tags or "extracted" in tags


def _has_oob_callback(finding: dict[str, Any]) -> bool:
    """True when OOB callback metadata is present."""
    meta = finding.get("metadata") or {}
    tags = set(t.lower() for t in (finding.get("tags") or []))
    return bool(
        meta.get("oob_domain")
        or meta.get("interactsh_callback")
        or "oob" in tags
        or "interactsh" in tags
    )


def _has_confirmed_version(finding: dict[str, Any]) -> bool:
    """True when a specific CVE + matching version is confirmed."""
    meta = finding.get("metadata") or {}
    return bool(meta.get("version_confirmed") or meta.get("cve_confirmed"))


def _has_timing_anomaly(finding: dict[str, Any]) -> bool:
    """True when time-based detection is flagged."""
    meta = finding.get("metadata") or {}
    tags = set(t.lower() for t in (finding.get("tags") or []))
    return bool(
        meta.get("time_based")
        or meta.get("detection_method") == "time_based"
        or "time_based" in tags
    )


def _has_body_diff(finding: dict[str, Any]) -> bool:
    """True when the finding includes body-diff or response-diff evidence."""
    meta = finding.get("metadata") or {}
    return bool(
        meta.get("response_diff")
        or meta.get("body_diff")
        or meta.get("baseline_diff")
    )


def _has_reflection_markers(finding: dict[str, Any]) -> bool:
    """True when evidence/http_response contains common injection markers."""
    text = ((finding.get("evidence") or "") + (finding.get("http_response") or "")).lower()
    if not text:
        return False
    return any(m in text for m in _REFLECTION_MARKERS)


def _has_meaningful_evidence_text(finding: dict[str, Any]) -> bool:
    """Non-trivial evidence or http_response field (> 20 chars after strip)."""
    ev = (finding.get("evidence") or "").strip()
    hr = (finding.get("http_response") or "").strip()
    return len(ev) > 20 or len(hr) > 20


# ── Public API ───────────────────────────────────────────────

def evaluate(finding: dict[str, Any]) -> EvidenceVerdict:
    """Evaluate whether *finding* presents sufficient evidence for its severity.

    Returns an ``EvidenceVerdict``.  When ``passed`` is False the finding
    should either be rejected or have its confidence capped to
    ``confidence_cap``.
    """
    # ── PoC-confirmed findings always pass ──────────────
    if finding.get("poc_confirmed") or finding.get("is_proven"):
        return EvidenceVerdict(
            passed=True,
            reason="PoC-confirmed finding — evidence gate bypassed",
            signals_found=["poc_confirmed"],
        )

    severity = (finding.get("severity") or "info").strip().lower()

    # ── Collect positive evidence signals ───────────────
    signals: list[str] = []

    if _has_payload_reflection(finding):
        signals.append("payload_reflected")
    if _has_error_leakage(finding):
        signals.append("error_leakage")
    if _has_data_extraction(finding):
        signals.append("data_extracted")
    if _has_oob_callback(finding):
        signals.append("oob_callback")
    if _has_confirmed_version(finding):
        signals.append("version_confirmed")
    if _has_timing_anomaly(finding):
        signals.append("timing_anomaly")
    if _has_body_diff(finding):
        signals.append("body_diff")
    if _has_reflection_markers(finding):
        signals.append("reflection_marker")
    if _has_meaningful_evidence_text(finding):
        signals.append("evidence_text")

    # ── Gate logic per severity tier ────────────────────
    if severity in ("critical", "high"):
        # Need at least 1 *strong* positive signal
        strong = {"payload_reflected", "error_leakage", "data_extracted",
                  "oob_callback", "version_confirmed", "reflection_marker"}
        if signals and (strong & set(signals)):
            return EvidenceVerdict(
                passed=True,
                reason="Strong evidence present for CRITICAL/HIGH",
                signals_found=signals,
            )
        # Timing alone is weak for CRIT/HIGH — downgrade, don't reject
        if "timing_anomaly" in signals or "body_diff" in signals:
            return EvidenceVerdict(
                passed=False,
                reason="Only timing/body-diff for CRITICAL/HIGH — cap confidence",
                signals_found=signals,
                confidence_cap=45.0,
            )
        # No real evidence at all
        return EvidenceVerdict(
            passed=False,
            reason="No positive evidence for CRITICAL/HIGH finding",
            signals_found=signals,
            confidence_cap=35.0,
        )

    if severity == "medium":
        # Need at least *some* signal (timing, body-diff, or any positive)
        if signals:
            return EvidenceVerdict(
                passed=True,
                reason="Evidence signals present for MEDIUM",
                signals_found=signals,
            )
        # Absolutely no evidence
        return EvidenceVerdict(
            passed=False,
            reason="No evidence signals for MEDIUM finding",
            signals_found=signals,
            confidence_cap=35.0,
        )

    # LOW / INFO — always pass (informational)
    return EvidenceVerdict(
        passed=True,
        reason="LOW/INFO severity — evidence gate bypassed",
        signals_found=signals,
    )


def evaluate_batch(
    findings: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], EvidenceVerdict]]:
    """Evaluate a batch of findings.  Returns (finding, verdict) pairs."""
    return [(f, evaluate(f)) for f in findings]


__all__ = ["EvidenceVerdict", "evaluate", "evaluate_batch"]
