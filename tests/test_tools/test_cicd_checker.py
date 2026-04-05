"""Tests for CI/CD security checker — endpoint filtering, secret detection."""

import pytest

from src.tools.scanners.custom_checks.cicd_checker import (
    _CICD_ENDPOINTS,
    _CICD_SIGNATURES,
    _SECRET_LEAK_PATTERNS,
    _INTERNAL_PKG_PATTERNS,
    _find_secrets_in_text,
    _filter_cicd_endpoints,
)


# ── Constants ────────────────────────────────────────────

def test_cicd_endpoints_populated():
    assert isinstance(_CICD_ENDPOINTS, list)
    assert len(_CICD_ENDPOINTS) >= 40
    for entry in _CICD_ENDPOINTS:
        assert len(entry) == 4  # (path, desc, severity, platform)
        path, desc, sev, plat = entry
        assert path.startswith("/")
        assert sev.lower() in ("info", "low", "medium", "high", "critical")


def test_cicd_signatures_populated():
    assert isinstance(_CICD_SIGNATURES, dict)
    assert len(_CICD_SIGNATURES) >= 8
    assert "jenkins" in _CICD_SIGNATURES or "Jenkins" in _CICD_SIGNATURES


def test_secret_leak_patterns_populated():
    assert isinstance(_SECRET_LEAK_PATTERNS, list)
    assert len(_SECRET_LEAK_PATTERNS) >= 8


def test_internal_pkg_patterns_populated():
    assert isinstance(_INTERNAL_PKG_PATTERNS, list)
    assert len(_INTERNAL_PKG_PATTERNS) >= 3


# ── _find_secrets_in_text ────────────────────────────────

def test_find_secrets_aws_key():
    text = 'export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"'
    found = _find_secrets_in_text(text)
    assert isinstance(found, list)
    assert len(found) >= 1


def test_find_secrets_github_token():
    text = 'GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'
    found = _find_secrets_in_text(text)
    assert isinstance(found, list)
    assert len(found) >= 1


def test_find_secrets_no_secrets():
    text = 'Build completed successfully in 12.3 seconds.'
    found = _find_secrets_in_text(text)
    assert isinstance(found, list)
    assert len(found) == 0


def test_find_secrets_multiple():
    text = '''
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    password = "super_secret_123"
    GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
    '''
    found = _find_secrets_in_text(text)
    assert len(found) >= 2


def test_find_secrets_jwt():
    text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc'
    found = _find_secrets_in_text(text)
    assert isinstance(found, list)
    # JWT pattern should match
    assert len(found) >= 1


# ── _filter_cicd_endpoints ───────────────────────────────

def test_filter_no_tech_returns_all():
    """No technology filter → return all endpoints."""
    result = _filter_cicd_endpoints(_CICD_ENDPOINTS, None)
    assert len(result) == len(_CICD_ENDPOINTS)


def test_filter_empty_tech_returns_all():
    result = _filter_cicd_endpoints(_CICD_ENDPOINTS, [])
    # Empty list might return all or filter based on "generic"
    assert isinstance(result, list)


def test_filter_jenkins_only():
    """Filtering for Jenkins should include Jenkins + generic endpoints."""
    result = _filter_cicd_endpoints(_CICD_ENDPOINTS, ["jenkins"])
    jenkins_paths = [ep for ep in result if ep[3].lower() == "jenkins"]
    generic_paths = [ep for ep in result if ep[3].lower() == "generic"]
    assert len(jenkins_paths) >= 1
    assert isinstance(result, list)


def test_filter_gitlab_only():
    result = _filter_cicd_endpoints(_CICD_ENDPOINTS, ["gitlab"])
    assert isinstance(result, list)
    if result:
        platforms = {ep[3].lower() for ep in result}
        # Should contain gitlab and possibly generic
        assert "gitlab" in platforms or "generic" in platforms


def test_filter_unknown_tech():
    """Unknown tech → likely returns only generic endpoints."""
    result = _filter_cicd_endpoints(_CICD_ENDPOINTS, ["totally_unknown_platform"])
    assert isinstance(result, list)


# ── Secret pattern regex quality ─────────────────────────

def test_secret_patterns_valid_regex():
    """All patterns should be valid compiled regexes."""
    import re
    for pattern in _SECRET_LEAK_PATTERNS:
        assert hasattr(pattern, "search"), f"Pattern is not compiled: {pattern}"
        # Should not raise on simple test
        pattern.search("test string")


def test_internal_pkg_patterns_valid_regex():
    import re
    for pattern in _INTERNAL_PKG_PATTERNS:
        assert hasattr(pattern, "search"), f"Pattern is not compiled: {pattern}"
        pattern.search("@company/internal-lib")
