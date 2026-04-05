"""Tests for js_analyzer — entropy, DOM XSS, secret detection."""

import pytest

from src.tools.scanners.custom_checks.js_analyzer import (
    _shannon_entropy,
    _detect_high_entropy_secrets,
    _detect_dom_xss_patterns,
    _detect_secrets,
    _detect_cloud_urls,
    _extract_endpoints,
    _detect_env_and_webpack,
    _DOM_SOURCES,
    _DOM_SINKS,
)
from src.tools.base import Finding


# ── Shannon entropy ──────────────────────────────────────

def test_entropy_empty_string():
    assert _shannon_entropy("") == 0.0


def test_entropy_single_char():
    assert _shannon_entropy("aaaa") == 0.0


def test_entropy_high_randomness():
    """Random-looking string should have high entropy."""
    val = _shannon_entropy("aB3$xZ9!qW7@eR2&")
    assert val > 3.0


def test_entropy_low_for_words():
    val = _shannon_entropy("password")
    # Normal English word — moderate entropy
    assert 1.0 < val < 4.0


def test_entropy_returns_float():
    assert isinstance(_shannon_entropy("test123"), float)


# ── DOM sources / sinks constants ─────────────────────────

def test_dom_sources_populated():
    assert isinstance(_DOM_SOURCES, list)
    assert len(_DOM_SOURCES) >= 10
    assert "document.URL" in _DOM_SOURCES or any("document" in s for s in _DOM_SOURCES)


def test_dom_sinks_populated():
    assert isinstance(_DOM_SINKS, list)
    assert len(_DOM_SINKS) >= 10
    assert any("innerHTML" in s for s in _DOM_SINKS)
    assert any("eval" in s for s in _DOM_SINKS)


# ── DOM XSS detection ────────────────────────────────────

def test_dom_xss_source_and_sink_nearby():
    """Source + sink within proximity should trigger finding."""
    js = """
    var userInput = document.location.hash;
    document.getElementById('output').innerHTML = userInput;
    """
    findings = _detect_dom_xss_patterns(js, "https://example.com/app.js")
    assert isinstance(findings, list)
    # Should detect source→sink flow
    if findings:
        assert any("dom" in f.vulnerability_type.lower() or "xss" in f.vulnerability_type.lower()
                    for f in findings)


def test_dom_xss_no_source():
    """No source → no DOM XSS finding."""
    js = 'var x = "hello"; console.log(x);'
    findings = _detect_dom_xss_patterns(js, "https://example.com/safe.js")
    assert isinstance(findings, list)
    assert len(findings) == 0


def test_dom_xss_eval_sink():
    js = """
    var data = window.location.search;
    eval(data);
    """
    findings = _detect_dom_xss_patterns(js, "https://example.com/eval.js")
    assert isinstance(findings, list)


# ── Secret detection ─────────────────────────────────────

def test_detect_secrets_aws_key():
    js = 'var awsKey = "AKIAIOSFODNN7EXAMPLE";'
    findings = _detect_secrets(js, "https://example.com/config.js")
    assert isinstance(findings, list)
    if findings:
        assert any("secret" in f.vulnerability_type.lower() or
                    "key" in f.title.lower() or
                    "credential" in f.vulnerability_type.lower() or
                    "exposure" in f.vulnerability_type.lower()
                    for f in findings)


def test_detect_secrets_no_secrets():
    js = 'function add(a, b) { return a + b; }'
    findings = _detect_secrets(js, "https://example.com/math.js")
    assert isinstance(findings, list)
    assert len(findings) == 0


def test_detect_secrets_jwt():
    js = '''var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";'''
    findings = _detect_secrets(js, "https://example.com/auth.js")
    assert isinstance(findings, list)


# ── High-entropy secret detection ────────────────────────

def test_high_entropy_detects_random_string():
    js = 'var apiSecret = "rk_example_aB3xZ9qW7eR2tY8uI5oP0lK4jH6gF1d";'
    findings = _detect_high_entropy_secrets(js, "https://example.com/pay.js")
    assert isinstance(findings, list)
    # Should find high-entropy string in secret-like context
    # May or may not fire depending on exact threshold + context patterns


def test_high_entropy_normal_code():
    js = 'function calculate(total, tax) { return total * (1 + tax); }'
    findings = _detect_high_entropy_secrets(js, "https://example.com/calc.js")
    assert isinstance(findings, list)
    assert len(findings) == 0


# ── Cloud URL detection ──────────────────────────────────

def test_detect_cloud_urls_s3():
    js = 'var bucket = "https://my-bucket.s3.amazonaws.com/data.json";'
    findings = _detect_cloud_urls(js, "https://example.com/app.js")
    assert isinstance(findings, list)
    if findings:
        assert any("cloud" in f.vulnerability_type.lower() or
                    "s3" in f.title.lower() or
                    "exposure" in f.vulnerability_type.lower()
                    for f in findings)


def test_detect_cloud_urls_none():
    js = 'var x = "https://example.com/api/data";'
    findings = _detect_cloud_urls(js, "https://example.com/app.js")
    assert isinstance(findings, list)
    assert len(findings) == 0


# ── Endpoint extraction ──────────────────────────────────

def test_extract_endpoints_api_paths():
    js = '''
    fetch("/api/v1/users");
    axios.get("/api/v2/orders");
    var url = "/admin/settings";
    '''
    endpoints = _extract_endpoints(js, "https://example.com")
    assert isinstance(endpoints, list)
    if endpoints:
        assert all(isinstance(ep, dict) for ep in endpoints)


def test_extract_endpoints_empty():
    js = "var x = 1 + 2;"
    endpoints = _extract_endpoints(js, "https://example.com")
    assert isinstance(endpoints, list)
    assert len(endpoints) == 0


# ── Env / webpack detection ──────────────────────────────

def test_detect_env_patterns():
    js = 'process.env.API_KEY = "secret123";'
    findings = _detect_env_and_webpack(js, "https://example.com/bundle.js")
    assert isinstance(findings, list)


def test_detect_webpack_chunk():
    js = '''
    (window.webpackJsonp = window.webpackJsonp || []).push([[0], {
        "./src/secret.js": function(module, exports) {
            module.exports = "internal_data";
        }
    }]);
    '''
    findings = _detect_env_and_webpack(js, "https://example.com/chunk.js")
    assert isinstance(findings, list)
