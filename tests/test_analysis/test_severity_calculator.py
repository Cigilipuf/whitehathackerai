"""Tests for SeverityCalculator — CVSS v3.1 scoring."""

import pytest

from src.analysis.severity_calculator import (
    CVSSMetrics,
    CVSSResult,
    SeverityCalculator,
    VULN_TYPE_DEFAULTS,
)


@pytest.fixture
def calc():
    return SeverityCalculator()


# ── Score ranges ─────────────────────────────────────────

def test_none_severity(calc):
    """All None metrics → score 0.0."""
    m = CVSSMetrics(
        confidentiality="N", integrity="N", availability="N",
    )
    result = calc.calculate(m)
    assert result.score == 0.0
    assert result.severity == "none"


def test_critical_severity(calc):
    """Network/Low/None/None/Unchanged + all High → critical."""
    m = CVSSMetrics(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N", scope="U",
        confidentiality="H", integrity="H", availability="H",
    )
    result = calc.calculate(m)
    assert result.score >= 9.0
    assert result.severity == "critical"


def test_high_severity_xss_stored(calc):
    """Stored XSS typical vector."""
    m = CVSSMetrics(
        attack_vector="N", attack_complexity="L",
        privileges_required="L", user_interaction="R", scope="C",
        confidentiality="L", integrity="L", availability="N",
    )
    result = calc.calculate(m)
    assert 4.0 <= result.score <= 7.0
    assert result.severity in ("medium", "high")


def test_low_severity(calc):
    """Physical, high complexity → low."""
    m = CVSSMetrics(
        attack_vector="P", attack_complexity="H",
        privileges_required="H", user_interaction="R", scope="U",
        confidentiality="L", integrity="N", availability="N",
    )
    result = calc.calculate(m)
    assert result.score <= 3.9
    assert result.severity == "low"


# ── Changed scope ────────────────────────────────────────

def test_scope_changed_boosts_score(calc):
    """Scope=Changed should increase score."""
    base = CVSSMetrics(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N", scope="U",
        confidentiality="H", integrity="N", availability="N",
    )
    changed = CVSSMetrics(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N", scope="C",
        confidentiality="H", integrity="N", availability="N",
    )
    r1 = calc.calculate(base)
    r2 = calc.calculate(changed)
    assert r2.score >= r1.score


# ── Vector string ────────────────────────────────────────

def test_vector_string_format(calc):
    m = CVSSMetrics()
    result = calc.calculate(m)
    assert result.vector.startswith("CVSS:3.1/")
    assert "AV:" in result.vector
    assert "AC:" in result.vector


def test_parse_vector(calc):
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    result = calc.parse_vector(vector)
    assert result.severity in ("high", "critical")
    assert result.metrics.confidentiality == "H"
    assert result.metrics.integrity == "H"
    assert result.metrics.availability == "N"


def test_parse_vector_roundtrip(calc):
    """calculate → vector → parse_vector should give same score."""
    m = CVSSMetrics(
        attack_vector="N", attack_complexity="H",
        privileges_required="L", user_interaction="R", scope="C",
        confidentiality="H", integrity="L", availability="N",
    )
    r1 = calc.calculate(m)
    r2 = calc.parse_vector(r1.vector)
    assert r1.score == r2.score


# ── estimate() ───────────────────────────────────────────

def test_estimate_sql_injection(calc):
    result = calc.estimate("sql_injection")
    assert result.severity in ("high", "critical")
    assert result.score >= 7.0


def test_estimate_info_disclosure(calc):
    result = calc.estimate("information_disclosure")
    assert result.severity in ("low", "medium")


def test_estimate_unknown_type(calc):
    """Unknown vuln type should still produce a result."""
    result = calc.estimate("totally_unknown_vuln_type")
    assert isinstance(result, CVSSResult)
    assert result.score >= 0.0


def test_estimate_with_context(calc):
    """Context overrides should affect score."""
    base = calc.estimate("information_disclosure")
    elevated = calc.estimate("information_disclosure", context={
        "rce_possible": True,
        "scope_changed": True,
    })
    assert elevated.score > base.score


def test_estimate_authenticated_reduces(calc):
    base = calc.estimate("sql_injection")
    auth = calc.estimate("sql_injection", context={"authenticated": True})
    # authenticated → PR:L instead of PR:N, score should decrease or stay
    assert auth.score <= base.score


def test_estimate_user_interaction(calc):
    base = calc.estimate("ssrf")
    ui = calc.estimate("ssrf", context={"user_interaction": True})
    assert ui.score <= base.score


# ── Invalid metrics ──────────────────────────────────────

def test_invalid_metric_raises(calc):
    m = CVSSMetrics(attack_vector="X")  # Invalid
    with pytest.raises(ValueError, match="Invalid"):
        calc.calculate(m)


# ── VULN_TYPE_DEFAULTS coverage ──────────────────────────

def test_all_defaults_produce_valid_score(calc):
    """Every entry in VULN_TYPE_DEFAULTS should produce a valid CVSS result."""
    for vuln_type in VULN_TYPE_DEFAULTS:
        result = calc.estimate(vuln_type)
        assert 0.0 <= result.score <= 10.0, f"{vuln_type} produced invalid score"
        assert result.severity in ("none", "low", "medium", "high", "critical")


# ── Score boundaries ─────────────────────────────────────

def test_max_score_is_10(calc):
    m = CVSSMetrics(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N", scope="C",
        confidentiality="H", integrity="H", availability="H",
    )
    result = calc.calculate(m)
    assert result.score <= 10.0
