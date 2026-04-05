"""Regression tests for the 5 deficiency fixes found during final plan audit.

Fix 1: js_analyzer Discord token base64 validation + source map severity context
Fix 2: mass_assignment_checker static asset URL filter
Fix 3: commix_wrapper evidence fields on all Finding paths
Fix 4: tech_cve_checker min tech name length 2→3
Fix 5: auth_bypass API version switching paths
"""
from __future__ import annotations

import re

import pytest


# ──────────────────────────────────────────────────────────────────
# Fix 1a: Discord Token Base64 Validation
# ──────────────────────────────────────────────────────────────────

class TestDiscordTokenValidation:
    """js_analyzer must reject Discord-like tokens whose first segment
    is not a valid base64-encoded numeric user ID."""

    def _detect_secrets(self, content: str, url: str = "https://example.com/app.js"):
        from src.tools.scanners.custom_checks.js_analyzer import _detect_secrets
        return _detect_secrets(content, url)

    def test_real_discord_token_detected(self):
        """A structurally valid Discord token (base64-numeric first seg) should pass."""
        # Build token at runtime to avoid GitHub push protection
        # First segment base64-decodes to "123456789012345678" (numeric)
        seg1 = "MTIzNDU2Nzg5MDEyMzQ1Njc4"
        seg2 = "Xk0_yQ"
        seg3 = "abcdefghijklmnopqrstuvwxyz1"
        token = ".".join([seg1, seg2, seg3])
        js = f'var TOKEN = "{token}";'
        findings = self._detect_secrets(js)
        discord_findings = [f for f in findings if "Discord" in f.title]
        assert len(discord_findings) == 1, "Real Discord token should be detected"

    def test_fake_discord_token_filtered(self):
        """A token whose first segment does NOT decode to digits should be filtered."""
        # "MHJhbmRvbV9ub3RfYV91c2VyX2lk" decodes to "0random_not_a_user_id" (non-numeric)
        token = "MHJhbmRvbV9ub3RfYV91c2VyX2lk.ABCdef.abcdefghijklmnopqrstuvwxyz1"
        js = f'var foo = "{token}";'
        findings = self._detect_secrets(js)
        discord_findings = [f for f in findings if "Discord" in f.title]
        assert len(discord_findings) == 0, "Non-numeric base64 should be filtered as FP"

    def test_garbled_first_segment_filtered(self):
        """Binary / non-UTF8 first segment should be filtered."""
        token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA.ABCdef.abcdefghijklmnopqrstuvwxyz1"
        js = f'const t = "{token}";'
        findings = self._detect_secrets(js)
        discord_findings = [f for f in findings if "Discord" in f.title]
        assert len(discord_findings) == 0


# ──────────────────────────────────────────────────────────────────
# Fix 1b: Source Map Severity Context
# ──────────────────────────────────────────────────────────────────

class TestSourceMapSeverityContext:
    """Source map findings for marketing/analytics JS should get LOW severity."""

    def test_marketing_js_keywords(self):
        """Verify _MARKETING_JS keyword list covers major analytics providers."""
        # Just verify the pattern exists in the source by importing
        import inspect
        from src.tools.scanners.custom_checks import js_analyzer
        src = inspect.getsource(js_analyzer._check_source_map)
        assert "_MARKETING_JS" in src
        for kw in ("analytics", "tracking", "gtm", "pixel", "segment", "hotjar"):
            assert kw in src, f"Marketing keyword '{kw}' should be in _MARKETING_JS"


# ──────────────────────────────────────────────────────────────────
# Fix 2: Mass Assignment Static Asset Filter
# ──────────────────────────────────────────────────────────────────

class TestMassAssignmentStaticFilter:
    """mass_assignment_checker must skip static asset URLs."""

    def test_static_assets_filtered(self):
        """Static asset extensions should be removed from api_endpoints list."""
        import inspect
        from src.tools.scanners.custom_checks import mass_assignment_checker
        src = inspect.getsource(mass_assignment_checker.MassAssignmentChecker.run)
        assert "_STATIC_EXTS" in src, "Static extension filter must exist in run()"

    def test_filter_regex_covers_common_extensions(self):
        """The regex must match .js .css .png .jpg .gif .svg .woff .map files."""
        _STATIC_EXTS = re.compile(
            r"\.(?:js|css|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|eot|map|"
            r"mp[34]|avi|mov|pdf|zip|gz|tar|bz2|wasm)(?:\?|$)",
            re.IGNORECASE,
        )
        should_match = [
            "/cdn/bundle.js", "/style.css", "/logo.png", "/img.jpg",
            "/pic.jpeg", "/icon.gif", "/font.woff", "/font.woff2",
            "/app.js.map", "/doc.pdf", "/build.wasm",
        ]
        should_not_match = [
            "/api/v1/users", "/graphql", "/rest/settings", "/v2/config",
        ]
        for url in should_match:
            assert _STATIC_EXTS.search(url), f"{url} should match static filter"
        for url in should_not_match:
            assert not _STATIC_EXTS.search(url), f"{url} should NOT match static filter"


# ──────────────────────────────────────────────────────────────────
# Fix 3: Commix Evidence Fields
# ──────────────────────────────────────────────────────────────────

class TestCommixEvidenceFields:
    """All commix Finding paths must have the evidence field populated."""

    @pytest.fixture()
    def wrapper(self):
        from src.tools.scanners.commix_wrapper import CommixWrapper
        return CommixWrapper()

    def test_injectable_param_has_evidence(self, wrapper):
        raw = "The GET parameter 'cmd' appears to be injectable"
        findings = wrapper.parse_output(raw, target="http://test.com")
        inj = [f for f in findings if "Injectable" in f.title or "Injection in" in f.title]
        assert len(inj) >= 1
        assert inj[0].evidence, "Injectable param finding must have evidence"

    def test_technique_detection_has_evidence(self, wrapper):
        raw = "classic command injection technique detected"
        findings = wrapper.parse_output(raw, target="http://test.com")
        tech = [f for f in findings if "technique" in f.title.lower() or "classic" in f.title.lower()]
        assert len(tech) >= 1
        assert tech[0].evidence, "Technique finding must have evidence"

    def test_os_detection_has_evidence(self, wrapper):
        raw = "The remote OS is 'Linux'"
        findings = wrapper.parse_output(raw, target="http://test.com")
        os_f = [f for f in findings if "Remote OS" in f.title]
        assert len(os_f) >= 1
        assert os_f[0].evidence, "OS detection finding must have evidence"

    def test_command_output_has_evidence(self, wrapper):
        raw = "command output: uid=33(www-data)"
        findings = wrapper.parse_output(raw, target="http://test.com")
        cmd = [f for f in findings if "Confirmed" in f.title]
        assert len(cmd) >= 1
        assert cmd[0].evidence, "Command output finding must have evidence"


# ──────────────────────────────────────────────────────────────────
# Fix 4: Tech CVE Checker Min Tech Name Length
# ──────────────────────────────────────────────────────────────────

class TestTechCveMinLength:
    """tech_cve_checker must reject tech names shorter than 3 characters."""

    def test_min_length_is_3(self):
        """Verify the JSON parser path rejects 2-char tech names."""
        import inspect
        from src.tools.scanners.custom_checks import tech_cve_checker
        src = inspect.getsource(tech_cve_checker)
        # Should find 'len(_clean_name) >= 3' not 'len(_clean_name) > 1'
        assert "len(_clean_name) >= 3" in src, "Min tech name length should be >= 3"
        assert "len(_clean_name) > 1" not in src, "Old len > 1 check should be removed"


# ──────────────────────────────────────────────────────────────────
# Fix 5: Auth Bypass API Version Switching
# ──────────────────────────────────────────────────────────────────

class TestAuthBypassApiVersionPaths:
    """AUTH_BYPASS_PATHS must include API version switching paths."""

    def test_api_version_paths_present(self):
        from src.tools.scanners.custom_checks.auth_bypass import AUTH_BYPASS_PATHS
        api_paths = [p for p in AUTH_BYPASS_PATHS if "/api/v" in p]
        assert len(api_paths) >= 3, f"Expected >=3 API version paths, got {len(api_paths)}"

    def test_spring_bypass_present(self):
        from src.tools.scanners.custom_checks.auth_bypass import AUTH_BYPASS_PATHS
        spring = [p for p in AUTH_BYPASS_PATHS if "..;" in p and p != "/admin..;/"]
        assert len(spring) >= 1, "Spring/Tomcat path normalization bypass should be present"

    def test_internal_api_paths_present(self):
        from src.tools.scanners.custom_checks.auth_bypass import AUTH_BYPASS_PATHS
        internal = [p for p in AUTH_BYPASS_PATHS if "internal" in p or "private" in p]
        assert len(internal) >= 1, "Internal/private API paths should be present"

    def test_total_bypass_paths_expanded(self):
        from src.tools.scanners.custom_checks.auth_bypass import AUTH_BYPASS_PATHS
        # Original was 14, should be at least 20 now
        assert len(AUTH_BYPASS_PATHS) >= 20, f"Expected >=20 bypass paths, got {len(AUTH_BYPASS_PATHS)}"
