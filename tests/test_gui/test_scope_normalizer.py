"""Tests for scan_control scope identifier normalisation helpers."""

import pytest

try:
    from src.gui.widgets.scan_control import detect_scope_type, normalize_scope_identifier
except ImportError:
    pytest.skip("PySide6 not available", allow_module_level=True)


# ── normalize_scope_identifier ──────────────────────────────


class TestNormalizeScopeIdentifier:
    """URL → domain, wildcard, CIDR, IP, text filtering."""

    # --- URL extraction ---
    @pytest.mark.parametrize("url,expected", [
        ("https://support.1password.com", "support.1password.com"),
        ("https://www.1password.com/", "www.1password.com"),
        ("https://bugbounty-ctf.1password.com/", "bugbounty-ctf.1password.com"),
        ("http://github.com/cloudflare", "github.com"),
        ("https://example.com:8443/path?q=1", "example.com"),
        ("http://SUB.EXAMPLE.COM/PATH", "sub.example.com"),
    ])
    def test_url_to_domain(self, url, expected):
        assert normalize_scope_identifier(url, "URL") == expected

    # --- Wildcard passthrough ---
    @pytest.mark.parametrize("wc", [
        "*.agilebits.com",
        "*.example.com",
        "*.sub.example.org",
    ])
    def test_wildcard_passthrough(self, wc):
        assert normalize_scope_identifier(wc, "WILDCARD") == wc.lower()

    # --- Plain domain ---
    def test_plain_domain(self):
        assert normalize_scope_identifier("example.com", "DOMAIN") == "example.com"

    def test_plain_domain_uppercased(self):
        assert normalize_scope_identifier("Example.COM", "DOMAIN") == "example.com"

    # --- IP / CIDR ---
    def test_bare_ip(self):
        assert normalize_scope_identifier("10.0.0.1", "IP") == "10.0.0.1"

    def test_cidr(self):
        assert normalize_scope_identifier("192.168.1.0/24", "CIDR") == "192.168.1.0/24"

    def test_cidr_v6(self):
        result = normalize_scope_identifier("::1/128", "IP")
        assert result == "::1/128"

    # --- Filtered out (returns None) ---
    @pytest.mark.parametrize("ident,atype", [
        # Long text note
        ("All other domains, subdomains, and 1Password Accounts that are not "
         "owned by you, including accounts where you are a user but not the "
         "owner, are out of scope.", "OTHER"),
        # Non-target asset types
        ("Cloudflare D1", "OTHER"),
        ("MyApp.exe", "HARDWARE"),
        ("MyApp.apk", "DOWNLOADABLE_EXECUTABLES"),
        ("github.com/org/repo", "SOURCE_CODE"),
        # Email
        ("user@example.com", "DOMAIN"),
        # Empty
        ("", "DOMAIN"),
        ("   ", "URL"),
        # Short text with spaces
        ("Some text note", "DOMAIN"),
    ])
    def test_filtered_out(self, ident, atype):
        assert normalize_scope_identifier(ident, atype) is None

    # --- Deduplication-ready (lowercased) ---
    def test_lowercased_dedup(self):
        a = normalize_scope_identifier("https://WWW.EXAMPLE.COM/", "URL")
        b = normalize_scope_identifier("www.example.com", "DOMAIN")
        assert a == b == "www.example.com"


# ── detect_scope_type ───────────────────────────────────────


class TestDetectScopeType:

    def test_wildcard(self):
        assert detect_scope_type("*.example.com") == "wildcard"

    def test_ip(self):
        assert detect_scope_type("10.0.0.1") == "ip"

    def test_cidr(self):
        assert detect_scope_type("192.168.1.0/24") == "cidr"

    def test_domain(self):
        assert detect_scope_type("example.com") == "domain"

    def test_subdomain(self):
        assert detect_scope_type("sub.example.com") == "domain"
