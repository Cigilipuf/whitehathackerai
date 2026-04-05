"""
PostValidator — Lightweight per-finding post-validation framework.

v5.0 Phase 3: Every scanner finding should pass at least one independent
validation check before being promoted to confirmed status.

This module provides reusable validation primitives that wrapper modules
can call after parsing tool output.  It does NOT replace the FP engine;
it operates much earlier — at Finding creation time inside each wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PostValidationResult:
    """Result of a per-finding post-validation check."""

    passed: bool
    reason: str = ""
    confidence_modifier: float = 0.0  # delta to apply


def has_payload_reflection(body: str, payload: str, *, min_length: int = 4) -> bool:
    """Check if *payload* (or a recognisable fragment) appears in *body*.

    Returns ``True`` when at least *min_length* consecutive characters of the
    payload appear unencoded in the response body.
    """
    if not body or not payload or len(payload) < min_length:
        return False
    return payload in body


def has_error_signature(body: str) -> bool:
    """Detect database / runtime error messages in response body."""
    if not body:
        return False
    lower = body[:8192].lower()
    return any(
        sig in lower
        for sig in (
            "sql syntax",
            "mysql_",
            "pg_query",
            "ora-",
            "sqlite3",
            "syntax error",
            "unclosed quotation",
            "unterminated string",
            "odbc driver",
            "microsoft ole db",
            "you have an error in your sql",
            "warning: mysql",
            "java.sql.",
            "org.hibernate",
            "pdo exception",
        )
    )


def has_timing_anomaly(
    baseline_ms: float,
    probe_ms: float,
    *,
    min_diff_ms: float = 4500.0,
    max_baseline_ms: float = 1000.0,
) -> bool:
    """Validate a time-based blind finding.

    Returns ``True`` only when:
    - the probe took at least *min_diff_ms* longer than baseline
    - baseline itself was fast (< *max_baseline_ms*)

    This prevents FPs from slow networks or heavy pages.
    """
    diff = probe_ms - baseline_ms
    return diff >= min_diff_ms and baseline_ms < max_baseline_ms


def body_differs_meaningfully(
    baseline_body: str,
    probe_body: str,
    *,
    min_diff_ratio: float = 0.05,
) -> bool:
    """Check that probe response body differs from baseline by at least
    *min_diff_ratio* (default 5% length difference)."""
    if not baseline_body and not probe_body:
        return False
    bl = len(baseline_body)
    pl = len(probe_body)
    if bl == 0:
        return pl > 50
    ratio = abs(pl - bl) / bl
    return ratio >= min_diff_ratio
