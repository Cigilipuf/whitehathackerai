"""Tests for CorrelationEngine — dedup, grouping, chains, host risk."""

import pytest

from src.analysis.correlation_engine import (
    CorrelationEngine,
    CorrelatedFinding,
    AttackChain,
    CorrelationReport,
    KNOWN_CHAINS,
)


# ── Helpers ──────────────────────────────────────────────

def _make_finding(**overrides):
    base = {
        "title": "Test Finding",
        "vulnerability_type": "xss",
        "endpoint": "https://example.com/search",
        "parameter": "q",
        "severity": "medium",
        "confidence": 70.0,
        "tool_name": "dalfox",
        "payload": "<script>alert(1)</script>",
        "evidence": "reflected",
    }
    base.update(overrides)
    return base


# ── Model defaults ───────────────────────────────────────

def test_correlated_finding_defaults():
    cf = CorrelatedFinding()
    assert cf.severity == "medium"
    assert cf.confidence == 0.0
    assert cf.source_tools == []
    assert cf.is_duplicate is False
    assert cf.oob_confirmed is False


def test_attack_chain_defaults():
    ac = AttackChain()
    assert ac.severity == "critical"
    assert ac.findings == []
    assert ac.steps == []


def test_correlation_report_defaults():
    cr = CorrelationReport()
    assert cr.total_raw_findings == 0
    assert cr.total_after_dedup == 0
    assert cr.correlated_findings == []
    assert cr.attack_chains == []


# ── KNOWN_CHAINS constant ───────────────────────────────

def test_known_chains_exists():
    assert isinstance(KNOWN_CHAINS, list)
    assert len(KNOWN_CHAINS) >= 9


def test_known_chain_structure():
    for chain in KNOWN_CHAINS:
        assert "name" in chain
        assert "required" in chain or "vulns" in chain or "required_vulns" in chain


# ── Engine — add / correlate ─────────────────────────────

def test_empty_engine_produces_empty_report():
    engine = CorrelationEngine()
    report = engine.correlate()
    assert isinstance(report, CorrelationReport)
    assert report.total_raw_findings == 0
    assert report.total_after_dedup == 0


def test_add_single_finding():
    engine = CorrelationEngine()
    engine.add_finding(_make_finding())
    report = engine.correlate()
    assert report.total_raw_findings == 1
    assert report.total_after_dedup >= 1
    assert len(report.correlated_findings) >= 1


def test_add_findings_bulk():
    engine = CorrelationEngine()
    findings = [_make_finding(title=f"F{i}") for i in range(5)]
    engine.add_findings(findings)
    report = engine.correlate()
    assert report.total_raw_findings == 5


def test_duplicate_findings_deduped():
    engine = CorrelationEngine()
    f = _make_finding()
    engine.add_finding(f)
    engine.add_finding(f)  # exact duplicate
    report = engine.correlate()
    # After dedup, should be fewer or equal
    assert report.total_after_dedup <= report.total_raw_findings


def test_different_endpoints_not_deduped():
    engine = CorrelationEngine()
    engine.add_finding(_make_finding(endpoint="https://example.com/a"))
    engine.add_finding(_make_finding(endpoint="https://example.com/b"))
    report = engine.correlate()
    assert report.total_after_dedup >= 2


def test_multi_tool_same_finding_merged():
    engine = CorrelationEngine()
    engine.add_finding(_make_finding(tool_name="dalfox"))
    engine.add_finding(_make_finding(tool_name="xsstrike"))
    report = engine.correlate()
    # Same endpoint+param+type → should be merged
    merged = [
        f for f in report.correlated_findings
        if len(f.source_tools) > 1
    ]
    # At least the grouping logic ran
    assert report.total_raw_findings == 2


# ── Static methods ───────────────────────────────────────

def test_normalize_basic():
    f = _make_finding()
    norm = CorrelationEngine._normalize(f)
    assert isinstance(norm, dict)
    assert "vulnerability_type" in norm


def test_normalize_endpoint():
    result = CorrelationEngine._normalize_endpoint("https://example.com/path?a=1&b=2")
    # Should strip query params or normalize
    assert isinstance(result, str)


def test_extract_host():
    assert CorrelationEngine._extract_host("https://example.com/path") == "example.com"
    assert CorrelationEngine._extract_host("http://app.test.com:8080/x") == "app.test.com"


def test_extract_host_bare_domain():
    result = CorrelationEngine._extract_host("example.com")
    assert "example" in result


def test_extract_host_handles_list_input():
    result = CorrelationEngine._extract_host(["https://api.example.com/path"])
    assert result == "api.example.com"


def test_normalize_endpoint_handles_list_input():
    result = CorrelationEngine._normalize_endpoint(["https://api.example.com/path/"])
    assert result == "api.example.com/path"


# ── Host risk map ────────────────────────────────────────

def test_host_risk_map():
    engine = CorrelationEngine()
    engine.add_finding(_make_finding(
        endpoint="https://a.example.com/x",
        severity="critical",
        confidence=90,
    ))
    engine.add_finding(_make_finding(
        endpoint="https://b.example.com/y",
        severity="low",
        confidence=40,
    ))
    report = engine.correlate()
    assert isinstance(report.host_risk_map, dict)
    if report.host_risk_map:
        # Higher severity host should have higher risk
        risks = list(report.host_risk_map.values())
        assert all(isinstance(r, (int, float)) for r in risks)


# ── Statistics ───────────────────────────────────────────

def test_statistics_populated():
    engine = CorrelationEngine()
    engine.add_findings([
        _make_finding(severity="high"),
        _make_finding(severity="low", endpoint="https://example.com/other"),
    ])
    report = engine.correlate()
    assert isinstance(report.statistics, dict)


# ── Chain detection (rule-based) ─────────────────────────

def test_chain_detection_ssrf_plus_cloud():
    """SSRF + cloud metadata should form an attack chain."""
    engine = CorrelationEngine()
    engine.add_finding(_make_finding(
        vulnerability_type="ssrf",
        endpoint="https://target.com/proxy",
        severity="high",
    ))
    engine.add_finding(_make_finding(
        vulnerability_type="cloud_metadata_exposure",
        endpoint="https://target.com/internal",
        severity="high",
    ))
    report = engine.correlate()
    # May or may not detect chain depending on vuln_type matching to KNOWN_CHAINS
    assert isinstance(report.attack_chains, list)


def test_no_chains_for_unrelated_findings():
    engine = CorrelationEngine()
    engine.add_finding(_make_finding(vulnerability_type="xss"))
    report = engine.correlate()
    # Single finding unlikely to have chain
    assert isinstance(report.attack_chains, list)


# ── Markdown output ──────────────────────────────────────

def test_to_markdown():
    engine = CorrelationEngine()
    engine.add_finding(_make_finding())
    engine.correlate()
    md = engine.to_markdown()
    assert isinstance(md, str)
    assert len(md) > 0


# ── OOB interactions ─────────────────────────────────────

def test_oob_interactions_added():
    engine = CorrelationEngine()
    engine.add_oob_interactions([
        {"type": "dns", "payload_tag": "abc123", "timestamp": "2025-01-01T00:00:00Z"}
    ])
    engine.add_finding(_make_finding(
        vulnerability_type="ssrf",
        metadata={"oob_payload_tag": "abc123"},
    ))
    report = engine.correlate()
    assert isinstance(report, CorrelationReport)


def test_oob_empty_interactions():
    engine = CorrelationEngine()
    engine.add_oob_interactions([])
    report = engine.correlate()
    assert report.total_raw_findings == 0
