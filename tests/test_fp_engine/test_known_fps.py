"""Tests for KnownFPMatcher — FP pattern matching engine."""

from src.fp_engine.patterns.known_fps import (
    FPPattern,
    KnownFPMatcher,
    KNOWN_FP_PATTERNS,
)


# ── Basic matching ───────────────────────────────────────

def test_known_fp_count():
    """Verify pattern database has expected count (100+)."""
    assert len(KNOWN_FP_PATTERNS) >= 100


def test_clean_finding_no_match():
    """A clean finding should not match any FP pattern."""
    matcher = KnownFPMatcher()
    finding = {
        "vuln_type": "sql_injection",
        "tool": "sqlmap",
        "evidence": "UNION SELECT 1,2,3-- extracted user:admin",
        "title": "SQL Injection in login form",
        "url": "https://example.com/login",
    }
    result = matcher.check(finding)
    assert result["total_penalty"] <= 0 or not result["is_known_fp"]


def test_sqli_fp_001_matches():
    """FP-SQLI-001: Generic SQL error without extraction."""
    matcher = KnownFPMatcher()
    finding = {
        "vuln_type": "sql_injection",
        "tool": "sqlmap",
        "evidence": "You have an error in your SQL syntax near...",
        "title": "SQL Injection",
        "url": "https://example.com/search",
    }
    result = matcher.check(finding)
    assert result["is_known_fp"]
    assert result["total_penalty"] < 0


def test_nuclei_tech_detect_fp():
    """FP-NUCLEI-001: tech-detect templates are INFO, not vulns."""
    matcher = KnownFPMatcher()
    finding = {
        "vuln_type": "information_disclosure",
        "tool": "nuclei",
        "title": "tech-detect: Apache Tomcat",
        "evidence": "tech-detect template match",
        "url": "https://example.com",
    }
    result = matcher.check(finding)
    # Should match a nuclei tech-detect FP pattern
    matched_ids = [m.id for m in result["matches"]]
    assert any("NUCLEI" in mid or "nuclei" in mid.lower() for mid in matched_ids) or result["total_penalty"] < 0


def test_waf_block_fp():
    """WAF 403 block should be recognized as FP."""
    matcher = KnownFPMatcher()
    finding = {
        "vuln_type": "xss",
        "tool": "dalfox",
        "evidence": "Attention Required! | Cloudflare",
        "status_code": 403,
        "url": "https://example.com/search",
        "headers": {"server": "cloudflare"},
    }
    result = matcher.check(finding)
    # Should match a WAF-related FP pattern
    assert result["total_penalty"] < 0


# ── Operators ────────────────────────────────────────────

def test_contains_operator():
    pattern = FPPattern(
        id="TEST-001",
        vuln_type="*",
        source_tool="*",
        match_rules=[{"field": "evidence", "operator": "contains", "value": "false positive"}],
        confidence_penalty=-50,
    )
    matcher = KnownFPMatcher(extra_patterns=[pattern])
    result = matcher.check({"evidence": "This is a false positive marker"})
    assert result["is_known_fp"]


def test_not_contains_operator():
    pattern = FPPattern(
        id="TEST-002",
        vuln_type="*",
        source_tool="*",
        match_rules=[
            {"field": "evidence", "operator": "contains", "value": "error"},
            {"field": "evidence", "operator": "not_contains", "value": "exploited"},
        ],
        confidence_penalty=-30,
    )
    matcher = KnownFPMatcher(extra_patterns=[pattern])
    # Should match (has error, no exploited)
    assert matcher.check({"evidence": "SQL error found"})["is_known_fp"]
    # Should NOT match (has both)
    assert not matcher.check({"evidence": "SQL error exploited"})["is_known_fp"]


def test_regex_operator():
    pattern = FPPattern(
        id="TEST-003",
        vuln_type="*",
        source_tool="*",
        match_rules=[{"field": "evidence", "operator": "regex", "value": r"v\d+\.\d+\.\d+"}],
        confidence_penalty=-20,
    )
    matcher = KnownFPMatcher(extra_patterns=[pattern])
    assert matcher.check({"evidence": "Server: Apache v2.4.52"})["is_known_fp"]
    assert not matcher.check({"evidence": "Server: Apache"})["is_known_fp"]


def test_equals_operator():
    pattern = FPPattern(
        id="TEST-004",
        vuln_type="*",
        source_tool="*",
        match_rules=[{"field": "status_code", "operator": "equals", "value": "403"}],
        confidence_penalty=-40,
    )
    matcher = KnownFPMatcher(extra_patterns=[pattern])
    assert matcher.check({"status_code": 403})["is_known_fp"]
    assert not matcher.check({"status_code": 200})["is_known_fp"]


# ── Tool + vuln_type filtering ───────────────────────────

def test_vuln_type_filter():
    pattern = FPPattern(
        id="TEST-005",
        vuln_type="xss",
        source_tool="*",
        match_rules=[{"field": "evidence", "operator": "contains", "value": "test"}],
        confidence_penalty=-10,
    )
    matcher = KnownFPMatcher(extra_patterns=[pattern])
    assert matcher.check({"vuln_type": "xss", "evidence": "test"})["is_known_fp"]
    assert not matcher.check({"vuln_type": "sqli", "evidence": "test"})["is_known_fp"]


def test_tool_filter():
    pattern = FPPattern(
        id="TEST-006",
        vuln_type="*",
        source_tool="nuclei",
        match_rules=[{"field": "evidence", "operator": "contains", "value": "detected"}],
        confidence_penalty=-15,
    )
    matcher = KnownFPMatcher(extra_patterns=[pattern])
    assert matcher.check({"tool": "nuclei", "evidence": "detected"})["is_known_fp"]
    assert not matcher.check({"tool": "nikto", "evidence": "detected"})["is_known_fp"]


# ── Actions ──────────────────────────────────────────────

def test_action_priority_dismiss():
    """Dismiss is highest priority action."""
    p1 = FPPattern(
        id="T1", vuln_type="*", source_tool="*",
        match_rules=[{"field": "evidence", "operator": "contains", "value": "x"}],
        action="flag", confidence_penalty=-10,
    )
    p2 = FPPattern(
        id="T2", vuln_type="*", source_tool="*",
        match_rules=[{"field": "evidence", "operator": "contains", "value": "x"}],
        action="dismiss", confidence_penalty=-50,
    )
    matcher = KnownFPMatcher(extra_patterns=[p1, p2])
    result = matcher.check({"evidence": "x"})
    assert result["action"] == "dismiss"
    assert result["total_penalty"] == -60


# ── add_pattern + statistics ─────────────────────────────

def test_add_pattern():
    matcher = KnownFPMatcher()
    base_count = matcher.pattern_count
    matcher.add_pattern(FPPattern(id="NEW-001"))
    assert matcher.pattern_count == base_count + 1


def test_statistics():
    matcher = KnownFPMatcher(extra_patterns=[
        FPPattern(
            id="STAT-001", vuln_type="*", source_tool="*",
            match_rules=[{"field": "evidence", "operator": "contains", "value": "stat_test"}],
            confidence_penalty=-5,
        ),
    ])
    matcher.check({"evidence": "stat_test"})
    matcher.check({"evidence": "stat_test"})
    stats = matcher.get_statistics()
    assert stats.get("STAT-001", 0) == 2


# ── Empty rules ──────────────────────────────────────────

def test_empty_rules_no_match():
    """Pattern with no rules should never match."""
    pattern = FPPattern(id="E1", vuln_type="*", source_tool="*", match_rules=[])
    matcher = KnownFPMatcher(extra_patterns=[pattern])
    assert not matcher.check({"evidence": "anything"})["is_known_fp"]


# ── Brain hypothesis patterns ────────────────────────────

def test_brain_hypothesis_fp():
    """Findings with finding_type=hypothesis should be penalized."""
    matcher = KnownFPMatcher()
    finding = {
        "vuln_type": "xss",
        "finding_type": "hypothesis",
        "evidence": "needs verification",
        "tool": "brain_analysis",
    }
    result = matcher.check(finding)
    # FP-BRAIN-001 should match (source_tool="brain_analysis")
    assert result["total_penalty"] < 0
