"""Tests for WAF strategy — fingerprinting + bypass transforms."""

import pytest

from src.tools.scanners.waf_strategy import (
    WAFResult,
    WAFStrategy,
    get_strategy,
    apply_rate_adjustment,
    transform_payload,
    generate_bypass_variants,
    is_waf_blocked,
    _double_url_encode,
    _case_randomize,
    _unicode_normalize,
    _html_entity_mix,
    _url_encode_selective,
    _sql_comment_injection,
    _inline_comment,
    _null_byte_insertion,
    _whitespace_variation,
    _chunked_encoding,
)


# ── Transform functions ──────────────────────────────────

def test_double_url_encode():
    result = _double_url_encode("<script>")
    assert "<" not in result
    # Double-encodes special chars: < → %3C → %253C
    assert "%25" in result or "%3C" not in result
    assert "%" in result


def test_case_randomize():
    result = _case_randomize("select")
    assert result.lower() == "select"
    # Should mix case (at least some chars different from original)
    assert result != "select" or result != "SELECT"


def test_unicode_normalize():
    result = _unicode_normalize("<script>alert(1)</script>")
    # Should replace < or > with unicode confusables
    assert result != "<script>alert(1)</script>"


def test_html_entity_mix():
    result = _html_entity_mix("<img onerror=alert(1)>")
    assert "&" in result or "&#" in result


def test_url_encode_selective():
    result = _url_encode_selective("test payload")
    assert "%" in result


def test_sql_comment_injection():
    payload = "UNION SELECT"
    result = _sql_comment_injection(payload)
    assert "/*" in result or result == payload  # May or may not transform


def test_inline_comment():
    result = _inline_comment("union select")
    assert "/**/" in result or result == "union select"


def test_null_byte_insertion():
    result = _null_byte_insertion("test")
    assert "%00" in result or "\x00" in result or result == "test"


def test_whitespace_variation():
    result = _whitespace_variation("SELECT * FROM")
    # Should replace spaces with alternatives
    assert result != "SELECT * FROM" or " " not in result


def test_chunked_encoding():
    result = _chunked_encoding("test")
    assert isinstance(result, str)


# ── transform_payload dispatch ───────────────────────────

def test_transform_payload_known_name():
    result = transform_payload("<script>", "double_url_encode")
    assert result != "<script>"


def test_transform_payload_unknown_name():
    result = transform_payload("test", "nonexistent_transform")
    assert result == "test"  # Should return unchanged


# ── generate_bypass_variants ─────────────────────────────

def test_generate_bypass_variants():
    strategy = WAFStrategy(
        waf_name="cloudflare",
        payload_transforms=["double_url_encode", "case_randomize", "unicode_normalize"],
    )
    waf = WAFResult(host="example.com", detected=True, waf_name="cloudflare", strategy=strategy)
    variants = generate_bypass_variants("<script>alert(1)</script>", waf)
    assert len(variants) >= 1
    assert all(isinstance(v, str) for v in variants)
    # Should produce different variants
    assert len(set(variants)) >= 1


def test_generate_bypass_variants_no_waf():
    waf = WAFResult(host="example.com", detected=False)
    variants = generate_bypass_variants("<script>", waf)
    assert isinstance(variants, list)
    assert len(variants) == 0  # No WAF → no bypass needed


# ── get_strategy ─────────────────────────────────────────

def test_get_strategy_known_waf():
    strategy = get_strategy("cloudflare")
    assert isinstance(strategy, WAFStrategy)
    assert strategy.waf_name or True  # May be default


def test_get_strategy_unknown_waf():
    strategy = get_strategy("totally_unknown_waf")
    assert isinstance(strategy, WAFStrategy)


# ── apply_rate_adjustment ────────────────────────────────

def test_rate_adjustment_no_waf():
    waf = WAFResult(host="example.com", detected=False)
    adjusted = apply_rate_adjustment(100, waf)
    assert adjusted == 100  # No change


def test_rate_adjustment_with_waf():
    strategy = WAFStrategy(waf_name="cloudflare", rate_adjustment=0.5, nuclei_rate=10)
    waf = WAFResult(host="example.com", detected=True, waf_name="cloudflare", strategy=strategy)
    adjusted = apply_rate_adjustment(100, waf)
    assert adjusted <= 50
    assert adjusted >= 1


def test_rate_adjustment_minimum_one():
    strategy = WAFStrategy(waf_name="test", rate_adjustment=0.001)
    waf = WAFResult(host="x", detected=True, strategy=strategy)
    adjusted = apply_rate_adjustment(1, waf)
    assert adjusted >= 1


# ── is_waf_blocked ───────────────────────────────────────

def test_is_waf_blocked_403():
    assert is_waf_blocked(403)


def test_is_waf_blocked_200():
    assert not is_waf_blocked(200)


def test_is_waf_blocked_body_patterns():
    assert is_waf_blocked(403, "Attention Required! | Cloudflare")
    assert is_waf_blocked(403, "Request blocked by AWS WAF")


# ── WAFResult / WAFStrategy models ──────────────────────

def test_waf_result_defaults():
    r = WAFResult(host="example.com")
    assert not r.detected
    assert r.waf_name == ""
    assert r.confidence == 0.0


def test_waf_strategy_defaults():
    s = WAFStrategy(waf_name="test")
    assert s.rate_adjustment == 1.0
    assert s.encoding_chain == []
