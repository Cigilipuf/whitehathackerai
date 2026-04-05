"""
Regression tests: Phase 2 — Scanner Accuracy Overhaul

Tests for:
1. mass_assignment_checker: baseline diff comparison
2. js_analyzer: third-party JS filtering
3. subdomain_takeover: NXDOMAIN confidence adjustment
4. full_scan.py: OOB fast-track bypass removed
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ===================================================================
# 1. mass_assignment_checker — baseline diff
# ===================================================================

class TestMassAssignmentBaselineDiff:
    """mass_assignment_checker must compare against baseline response."""

    def test_values_match_helper(self):
        from src.tools.scanners.custom_checks.mass_assignment_checker import _values_match
        # Exact match
        assert _values_match("admin", "admin")
        assert _values_match(True, True)
        assert _values_match(0, 0)
        # Loose string match
        assert _values_match("True", True)
        assert _values_match("true", True)
        assert _values_match("1", 1)
        # Non-match
        assert not _values_match("user", "admin")
        assert not _values_match(False, True)

    def test_extract_keys_nested(self):
        from src.tools.scanners.custom_checks.mass_assignment_checker import MassAssignmentChecker
        data = {
            "id": 1,
            "name": "test",
            "data": {
                "role": "user",
                "nested": {"deep": True}
            },
            "items": [{"field_a": 1}]
        }
        keys = MassAssignmentChecker._extract_keys(data)
        assert "id" in keys
        assert "name" in keys
        assert "role" in keys
        assert "deep" in keys
        assert "field_a" in keys


# ===================================================================
# 2. js_analyzer — third-party JS filtering
# ===================================================================

class TestJsAnalyzerThirdPartyFilter:
    """js_analyzer must skip known third-party/CDN JavaScript files."""

    @pytest.fixture
    def _filter(self):
        from src.tools.scanners.custom_checks.js_analyzer import _is_third_party_js
        return _is_third_party_js

    # -- CDN domains --
    @pytest.mark.parametrize("url", [
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js",
        "https://unpkg.com/lodash@4.17.21/lodash.min.js",
        "https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "https://code.jquery.com/jquery-3.6.0.min.js",
    ])
    def test_cdn_domains_rejected(self, _filter, url):
        assert _filter(url), f"Should reject CDN URL: {url}"

    # -- Analytics / tracking --
    @pytest.mark.parametrize("url", [
        "https://www.google-analytics.com/analytics.js",
        "https://www.googletagmanager.com/gtm.js?id=GTM-XXXXX",
        "https://cdn.segment.com/analytics.js/v1/key/analytics.min.js",
        "https://cdn.amplitude.com/libs/amplitude-8.1.0-min.gz.js",
        "https://connect.facebook.net/en_US/fbevents.js",
    ])
    def test_analytics_rejected(self, _filter, url):
        assert _filter(url), f"Should reject analytics URL: {url}"

    # -- Payment / widgets --
    @pytest.mark.parametrize("url", [
        "https://js.stripe.com/v3/",
        "https://js.intercomcdn.com/app.js",
        "https://cdn.zendesk.com/widget.js",
    ])
    def test_payment_widgets_rejected(self, _filter, url):
        assert _filter(url), f"Should reject widget URL: {url}"

    # -- Path-based detection --
    @pytest.mark.parametrize("url", [
        "https://target.com/vendor/jquery.min.js",
        "https://target.com/static/react.production.min.js",
        "https://target.com/js/angular.min.js",
        "https://target.com/assets/vue.global.prod.js",
    ])
    def test_path_based_rejection(self, _filter, url):
        assert _filter(url), f"Should reject path-based third-party: {url}"

    # -- First-party JS (should PASS through) --
    @pytest.mark.parametrize("url", [
        "https://target.com/assets/app.bundle.js",
        "https://target.com/static/main.js",
        "https://target.com/js/dashboard.js",
        "https://target.com/api-client.js",
        "https://cdn.target.com/app.js",
    ])
    def test_first_party_accepted(self, _filter, url):
        assert not _filter(url), f"Should accept first-party URL: {url}"


class TestJsAnalyzerPublicKeyFiltering:
    """js_analyzer should skip public frontend keys."""

    def test_google_maps_key_filtered(self):
        from src.tools.scanners.custom_checks.js_analyzer import _detect_secrets
        # Build key at runtime to avoid GitHub push protection
        prefix = "AIza"
        suffix = "SyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        fake_key = prefix + suffix
        js_content = f'''
        var GOOGLE_MAPS_KEY = "{fake_key}";
        var map = new google.maps.Map(document.getElementById("map"), {{
            center: {{ lat: 40.7, lng: -74.0 }},
        }});
        '''
        findings = _detect_secrets(js_content, "https://target.com/app.js")
        # Google API key in maps context should be filtered
        google_findings = [f for f in findings if "Google API Key" in f.title]
        assert len(google_findings) == 0, "Google Maps API key should be filtered"

    def test_stripe_public_key_filtered(self):
        from src.tools.scanners.custom_checks.js_analyzer import _detect_secrets
        js_content = 'var stripe = Stripe("pk_test_abcdefghijklmnopqrstuvwxyz");'
        findings = _detect_secrets(js_content, "https://target.com/checkout.js")
        stripe_findings = [f for f in findings if "Stripe" in f.title]
        assert len(stripe_findings) == 0, "Stripe pk_ key should be filtered"

    def test_stripe_secret_key_not_filtered(self):
        from src.tools.scanners.custom_checks.js_analyzer import _detect_secrets
        js_content = 'var stripe_secret = "sk_test_abcdefghijklmnopqrstuvwxyz";'
        findings = _detect_secrets(js_content, "https://target.com/admin.js")
        stripe_findings = [f for f in findings if "Stripe" in f.title]
        assert len(stripe_findings) > 0, "Stripe sk_ key should NOT be filtered"

    def test_mapbox_public_token_filtered(self):
        from src.tools.scanners.custom_checks.js_analyzer import _detect_secrets
        # pk.* Mapbox tokens are always public
        js_content = 'mapboxgl.accessToken = "pk.eyJ1IjoibXl1c2VyIiwiYSI6ImNsYXJrZW50MDAxMjM0NTY3ODkwYWJjZGVmZ2hpamsifQ.abcdefg12345";'
        findings = _detect_secrets(js_content, "https://target.com/map.js")
        mapbox_findings = [f for f in findings if "Mapbox" in f.title]
        assert len(mapbox_findings) == 0, "Mapbox pk. token should be filtered"


# ===================================================================
# 3. subdomain_takeover — NXDOMAIN confidence
# ===================================================================

class TestSubdomainTakeoverNXDOMAIN:
    """NXDOMAIN confidence must vary by whether CNAME matches known service."""

    def test_known_service_nxdomain_high_confidence(self):
        """NXDOMAIN with CNAME to known service → higher confidence."""
        async def run():
            from src.tools.scanners.custom_checks.subdomain_takeover import (
                _check_single_subdomain,
            )
            with patch("src.tools.scanners.custom_checks.subdomain_takeover._resolve_cname") as mock_cname, \
                 patch("src.tools.scanners.custom_checks.subdomain_takeover._check_http_fingerprint") as mock_http, \
                 patch("src.tools.scanners.custom_checks.subdomain_takeover._check_nxdomain") as mock_nx:
                # CNAME points to heroku (known service) + NXDOMAIN
                mock_cname.return_value = "old-app.herokuapp.com"
                mock_http.return_value = True  # Fingerprint matches
                mock_nx.return_value = True
                finding = await _check_single_subdomain("test.example.com", timeout=5)
                # Should match heroku fingerprint first (HTTP confirmed)
                assert finding is not None
                assert finding.confidence >= 70.0

        asyncio.run(run())

    def test_unknown_service_nxdomain_low_confidence(self):
        """NXDOMAIN with CNAME to unknown service → low confidence."""
        async def run():
            from src.tools.scanners.custom_checks.subdomain_takeover import (
                _check_single_subdomain,
            )
            with patch("src.tools.scanners.custom_checks.subdomain_takeover._resolve_cname") as mock_cname, \
                 patch("src.tools.scanners.custom_checks.subdomain_takeover._check_nxdomain") as mock_nx:
                # CNAME to unknown internal service + NXDOMAIN
                mock_cname.return_value = "old-internal-server.corp.example.net"
                mock_nx.return_value = True
                finding = await _check_single_subdomain("test.example.com", timeout=5)
                assert finding is not None
                assert finding.confidence <= 40.0, f"Unknown NXDOMAIN should be low confidence, got {finding.confidence}"
                assert "low" in str(finding.severity).lower()

        asyncio.run(run())

    def test_no_cname_no_finding(self):
        """No CNAME record → no finding."""
        async def run():
            from src.tools.scanners.custom_checks.subdomain_takeover import (
                _check_single_subdomain,
            )
            with patch("src.tools.scanners.custom_checks.subdomain_takeover._resolve_cname") as mock_cname:
                mock_cname.return_value = None
                finding = await _check_single_subdomain("test.example.com", timeout=5)
                assert finding is None

        asyncio.run(run())


# ===================================================================
# 4. OOB fast-track bypass removed
# ===================================================================

class TestOOBFastTrackRemoval:
    """Interactsh findings must go through normal FP analysis."""

    def test_oob_fast_track_code_removed(self):
        """full_scan.py should not contain oob_fast_track logic."""
        import src.workflow.pipelines.full_scan as mod
        source = open(mod.__file__).read()
        assert "oob_fast_track" not in source, (
            "OOB fast-track bypass should be removed from full_scan.py"
        )

    def test_interactsh_comment_exists(self):
        """The replacement comment should be present."""
        import src.workflow.pipelines.full_scan as mod
        source = open(mod.__file__).read()
        assert "OOB findings go through normal FP analysis" in source
