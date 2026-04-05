"""
Tests for src/analysis/host_profiler.py — Phase 0.1 HostProfiler module.

Tests cover:
- HostType enum values and str enum behavior
- HostIntelProfile dataclass (creation, to_dict, from_dict, is_testable, should_skip_checker)
- ResponseBaseline defaults
- _similarity() helper (identical, empty, similar heads, different sizes)
- _body_hash() helper (deterministic, whitespace-strip)
- _is_auth_redirect() detection
- _detect_cdn_from_headers() detection
- _detect_waf_from_headers() detection
- _extract_technologies() extraction
- is_cdn_ip() IP range matching
- _CHECKER_SKIP_MAP completeness and structure
- HostProfiler._compute_skip_list() utility
- HostProfiler.profile_hosts() with mocked httpx (SPA, static, auth-gated, redirect, api, web_app)
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.analysis.host_profiler import (
    CDN_IP_RANGES,
    THIRD_PARTY_DOMAINS,
    HostIntelProfile,
    HostProfiler,
    HostType,
    ResponseBaseline,
    _AUTH_REDIRECT_PATTERNS,
    _CHECKER_SKIP_MAP,
    _SIMILARITY_THRESHOLD,
    _body_hash,
    _detect_cdn_from_headers,
    _detect_waf_from_headers,
    _extract_redirect_target,
    _extract_technologies,
    _is_auth_redirect,
    _similarity,
    get_all_cdn_ranges,
    is_cdn_ip,
)


# ==================================================================
# HostType Enum
# ==================================================================

class TestHostType:
    def test_all_values_exist(self):
        expected = {
            "web_app", "api_server", "spa", "static_site",
            "auth_gated", "redirect_host", "cdn_only", "unknown",
        }
        actual = {ht.value for ht in HostType}
        assert actual == expected

    def test_str_enum(self):
        """HostType inherits from str so it compares with plain strings."""
        assert HostType.WEB_APP == "web_app"
        assert HostType.SPA == "spa"

    def test_from_value(self):
        assert HostType("api_server") is HostType.API_SERVER
        with pytest.raises(ValueError):
            HostType("nonexistent_type")


# ==================================================================
# ResponseBaseline
# ==================================================================

class TestResponseBaseline:
    def test_defaults(self):
        bl = ResponseBaseline()
        assert bl.status_code == 0
        assert bl.body_hash == ""
        assert bl.body_length == 0
        assert bl.headers == {}

    def test_populated(self):
        bl = ResponseBaseline(
            status_code=200,
            body_hash="abc123",
            body_length=5000,
            content_type="text/html",
            headers={"server": "nginx"},
        )
        assert bl.status_code == 200
        assert bl.headers["server"] == "nginx"


# ==================================================================
# HostIntelProfile Dataclass
# ==================================================================

class TestHostIntelProfile:
    def test_creation_defaults(self):
        p = HostIntelProfile(host="https://example.com")
        assert p.host == "https://example.com"
        assert p.host_type is HostType.UNKNOWN
        assert p.cdn_provider == ""
        assert p.waf_detected is False
        assert p.responds_to_post is True
        assert p.technologies == []
        assert p.skip_checkers == []
        assert p.confidence_modifier == 0.0

    def test_to_dict(self):
        p = HostIntelProfile(
            host="https://target.com",
            host_type=HostType.SPA,
            cdn_provider="cloudflare",
            waf_detected=True,
            waf_name="cloudflare",
            technologies=["php", "nginx"],
        )
        d = p.to_dict()
        assert d["host"] == "https://target.com"
        assert d["host_type"] == "spa"
        assert d["cdn_provider"] == "cloudflare"
        assert d["waf_detected"] is True
        assert d["technologies"] == ["php", "nginx"]

    def test_from_dict(self):
        d = {
            "host": "https://api.example.com",
            "host_type": "api_server",
            "cdn_provider": "fastly",
            "waf_detected": False,
            "waf_name": "",
            "responds_to_post": True,
            "post_accepts_body": True,
            "technologies": ["express"],
            "server_header": "nginx/1.21",
            "powered_by": "Express",
            "skip_checkers": ["js_analyzer"],
            "confidence_modifier": 0.0,
        }
        p = HostIntelProfile.from_dict(d)
        assert p.host == "https://api.example.com"
        assert p.host_type is HostType.API_SERVER
        assert p.cdn_provider == "fastly"
        assert p.technologies == ["express"]

    def test_from_dict_unknown_type(self):
        d = {"host": "x.com", "host_type": "alien_server"}
        p = HostIntelProfile.from_dict(d)
        assert p.host_type is HostType.UNKNOWN

    def test_round_trip(self):
        original = HostIntelProfile(
            host="https://t.com",
            host_type=HostType.AUTH_GATED,
            auth_required=True,
            skip_checkers=["mass_assignment_checker", "cloud_checker"],
        )
        d = original.to_dict()
        restored = HostIntelProfile.from_dict(d)
        assert restored.host == original.host
        assert restored.host_type == original.host_type
        assert restored.auth_required == original.auth_required
        assert restored.skip_checkers == original.skip_checkers

    def test_is_testable(self):
        assert HostIntelProfile(host="x", host_type=HostType.WEB_APP).is_testable()
        assert HostIntelProfile(host="x", host_type=HostType.API_SERVER).is_testable()
        assert HostIntelProfile(host="x", host_type=HostType.SPA).is_testable()
        assert HostIntelProfile(host="x", host_type=HostType.UNKNOWN).is_testable()
        assert not HostIntelProfile(host="x", host_type=HostType.STATIC_SITE).is_testable()
        assert not HostIntelProfile(host="x", host_type=HostType.AUTH_GATED).is_testable()
        assert not HostIntelProfile(host="x", host_type=HostType.REDIRECT_HOST).is_testable()
        assert not HostIntelProfile(host="x", host_type=HostType.CDN_ONLY).is_testable()

    def test_should_skip_checker(self):
        p = HostIntelProfile(host="x", skip_checkers=["js_analyzer", "cors_checker"])
        assert p.should_skip_checker("js_analyzer") is True
        assert p.should_skip_checker("cors_checker") is True
        assert p.should_skip_checker("nuclei") is False


# ==================================================================
# _similarity() Helper
# ==================================================================

class TestSimilarity:
    def test_identical(self):
        body = b"<html><body>Hello world</body></html>"
        assert _similarity(body, body) == 1.0

    def test_empty_a(self):
        assert _similarity(b"", b"hello") == 0.0

    def test_empty_b(self):
        assert _similarity(b"hello", b"") == 0.0

    def test_both_empty(self):
        assert _similarity(b"", b"") == 0.0

    def test_high_similarity(self):
        a = b"x" * 5000
        b_body = b"x" * 5000  # same
        assert _similarity(a, b_body) == 1.0

    def test_same_head_different_tail(self):
        """Same first 2KB, different last 2KB → 0.80"""
        prefix = b"A" * 3000
        a = prefix + b"B" * 3000
        b_body = prefix + b"C" * 3000
        sim = _similarity(a, b_body)
        assert 0.7 <= sim <= 0.9

    def test_very_different_length(self):
        a = b"short"
        b_body = b"x" * 10000
        sim = _similarity(a, b_body)
        assert sim < 0.1  # Very different lengths → low similarity

    def test_whitespace_stripped_hash(self):
        a = b"   hello world   "
        b_body = b"hello world"
        # _body_hash strips, so hash comparison works
        assert _body_hash(a) == _body_hash(b_body)


# ==================================================================
# _body_hash() Helper
# ==================================================================

class TestBodyHash:
    def test_deterministic(self):
        body = b"test content"
        assert _body_hash(body) == _body_hash(body)

    def test_different_content(self):
        assert _body_hash(b"aaa") != _body_hash(b"bbb")

    def test_strips_whitespace(self):
        assert _body_hash(b"  content  ") == _body_hash(b"content")


# ==================================================================
# _is_auth_redirect()
# ==================================================================

class TestIsAuthRedirect:
    @pytest.mark.parametrize("path", [
        "/login", "/signin", "/sign-in", "/sign_in",
        "/auth", "/authorize", "/oauth", "/sso", "/cas", "/saml",
        "/accounts/login", "/users/sign_in", "/session/new",
        "/connect/authorize",
    ])
    def test_known_auth_paths(self, path):
        assert _is_auth_redirect(302, f"https://example.com{path}")

    def test_not_redirect_status(self):
        assert _is_auth_redirect(200, "/login") is False
        assert _is_auth_redirect(404, "/login") is False

    def test_non_auth_path(self):
        assert _is_auth_redirect(302, "/about") is False
        assert _is_auth_redirect(301, "/products/shoes") is False

    def test_empty_location(self):
        assert _is_auth_redirect(302, "") is False

    def test_redirect_307_308(self):
        assert _is_auth_redirect(307, "/login") is True
        assert _is_auth_redirect(308, "/login") is True


# ==================================================================
# CDN/WAF detection from headers
# ==================================================================

class TestDetectCDNFromHeaders:
    def _make_headers(self, header_dict):
        """Create an httpx.Headers-like object."""
        import httpx
        return httpx.Headers(header_dict)

    def test_cloudflare(self):
        h = self._make_headers({"cf-ray": "abc123", "server": "cloudflare"})
        assert _detect_cdn_from_headers(h) == "cloudflare"

    def test_cloudfront(self):
        h = self._make_headers({"x-amz-cf-id": "xxx"})
        assert _detect_cdn_from_headers(h) == "cloudfront"

    def test_akamai(self):
        h = self._make_headers({"x-akamai-transformed": "9 - 0 pmb=mRUM,1"})
        assert _detect_cdn_from_headers(h) == "akamai"

    def test_fastly(self):
        h = self._make_headers({"x-fastly-request-id": "abc"})
        assert _detect_cdn_from_headers(h) == "fastly"

    def test_sucuri(self):
        h = self._make_headers({"x-sucuri-id": "12345"})
        assert _detect_cdn_from_headers(h) == "sucuri"

    def test_azure_cdn(self):
        h = self._make_headers({"x-azure-ref": "abc"})
        assert _detect_cdn_from_headers(h) == "azure_cdn"

    def test_no_cdn(self):
        h = self._make_headers({"server": "nginx"})
        assert _detect_cdn_from_headers(h) == ""


class TestDetectWAFFromHeaders:
    def _make_headers(self, header_dict):
        import httpx
        return httpx.Headers(header_dict)

    def test_cloudflare_waf(self):
        h = self._make_headers({"server": "cloudflare"})
        detected, name = _detect_waf_from_headers(h)
        assert detected is True
        assert name == "cloudflare"

    def test_sucuri_waf(self):
        h = self._make_headers({"x-sucuri-id": "12345"})
        detected, name = _detect_waf_from_headers(h)
        assert detected is True
        assert name == "sucuri"

    def test_no_waf(self):
        h = self._make_headers({"server": "nginx"})
        detected, name = _detect_waf_from_headers(h)
        assert detected is False
        assert name == ""


# ==================================================================
# _extract_technologies()
# ==================================================================

class TestExtractTechnologies:
    def _make_headers(self, header_dict):
        import httpx
        return httpx.Headers(header_dict)

    def test_server_header(self):
        h = self._make_headers({"server": "Apache/2.4.41"})
        techs, server, powered = _extract_technologies(h)
        assert "server:Apache/2.4.41" in techs
        assert server == "Apache/2.4.41"

    def test_powered_by_php(self):
        h = self._make_headers({"x-powered-by": "PHP/8.1.2"})
        techs, _, powered = _extract_technologies(h)
        assert "php" in techs
        assert powered == "PHP/8.1.2"

    def test_powered_by_express(self):
        h = self._make_headers({"x-powered-by": "Express"})
        techs, _, powered = _extract_technologies(h)
        assert "express" in techs

    def test_aspnet(self):
        h = self._make_headers({"x-aspnet-version": "4.0.30319"})
        techs, _, _ = _extract_technologies(h)
        assert "asp.net" in techs


# ==================================================================
# is_cdn_ip()
# ==================================================================

class TestIsCdnIp:
    def test_cloudflare_ip(self):
        is_cdn, provider = is_cdn_ip("104.16.0.1")
        assert is_cdn is True
        assert provider == "cloudflare"

    def test_cloudfront_ip(self):
        is_cdn, provider = is_cdn_ip("54.230.0.1")
        assert is_cdn is True
        assert provider == "cloudfront"

    def test_fastly_ip(self):
        is_cdn, provider = is_cdn_ip("151.101.0.1")
        assert is_cdn is True
        assert provider == "fastly"

    def test_non_cdn_ip(self):
        is_cdn, provider = is_cdn_ip("1.2.3.4")
        assert is_cdn is False
        assert provider == ""

    def test_invalid_ip(self):
        is_cdn, provider = is_cdn_ip("not-an-ip")
        assert is_cdn is False

    def test_akamai_ip(self):
        is_cdn, provider = is_cdn_ip("23.1.0.1")
        assert is_cdn is True
        assert provider == "akamai"


# ==================================================================
# CDN_IP_RANGES and THIRD_PARTY_DOMAINS
# ==================================================================

class TestConstants:
    def test_cdn_ranges_populated(self):
        assert len(CDN_IP_RANGES) >= 4
        for provider, ranges in CDN_IP_RANGES.items():
            assert len(ranges) > 0, f"Empty ranges for {provider}"
            for cidr in ranges:
                assert "/" in cidr, f"Invalid CIDR: {cidr}"

    def test_third_party_domains(self):
        assert "cloudflare.com" in THIRD_PARTY_DOMAINS
        assert "google-analytics.com" in THIRD_PARTY_DOMAINS
        assert len(THIRD_PARTY_DOMAINS) >= 30

    def test_get_all_cdn_ranges(self):
        result = get_all_cdn_ranges()
        assert isinstance(result, dict)
        assert "cloudflare" in result


# ==================================================================
# _CHECKER_SKIP_MAP
# ==================================================================

class TestCheckerSkipMap:
    def test_structure(self):
        assert isinstance(_CHECKER_SKIP_MAP, dict)
        assert len(_CHECKER_SKIP_MAP) >= 20

    def test_values_are_sets_of_host_types(self):
        for checker_name, skip_types in _CHECKER_SKIP_MAP.items():
            assert isinstance(skip_types, set), f"{checker_name}: not a set"
            for ht in skip_types:
                assert isinstance(ht, HostType), f"{checker_name}: {ht} not HostType"

    def test_mass_assignment_skipped_on_static(self):
        assert HostType.STATIC_SITE in _CHECKER_SKIP_MAP["mass_assignment_checker"]

    def test_js_analyzer_skipped_on_api(self):
        assert HostType.API_SERVER in _CHECKER_SKIP_MAP["js_analyzer"]

    def test_redirect_host_most_skips(self):
        """REDIRECT_HOST should have the most skip entries."""
        rh_count = sum(
            1 for skips in _CHECKER_SKIP_MAP.values()
            if HostType.REDIRECT_HOST in skips
        )
        assert rh_count >= 15, f"REDIRECT_HOST only skips {rh_count} checkers"


# ==================================================================
# HostProfiler._compute_skip_list()
# ==================================================================

class TestComputeSkipList:
    def test_static_site_skips(self):
        skips = HostProfiler._compute_skip_list(HostType.STATIC_SITE)
        assert "mass_assignment_checker" in skips
        assert "deserialization_checker" in skips
        assert "race_condition" in skips

    def test_web_app_minimal_skips(self):
        skips = HostProfiler._compute_skip_list(HostType.WEB_APP)
        # WEB_APP should have minimal skips — it's the most testable
        assert len(skips) == 0, f"WEB_APP has unexpected skips: {skips}"

    def test_cdn_only_many_skips(self):
        skips = HostProfiler._compute_skip_list(HostType.CDN_ONLY)
        assert len(skips) >= 10


# ==================================================================
# HostProfiler.profile_hosts() — Integration tests with mocked HTTP
# ==================================================================

def _make_mock_response(
    status_code=200,
    content=b"<html><body>Default page</body></html>",
    headers=None,
):
    """Create a mock httpx.Response."""
    import httpx

    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.content = content
    resp.headers = httpx.Headers(headers or {"server": "nginx"})
    return resp


class TestHostProfilerProfileHosts:
    """Integration tests for profile_hosts with mocked HTTP client."""

    def test_empty_hosts(self):
        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts([]))
        assert result == {}

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_web_app_classification(self, mock_client_cls):
        """Host with different content per path → WEB_APP."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            follow = kwargs.get("follow_redirects", False)
            if url.rstrip("/") == "https://target.com" or url == "https://target.com":
                return _make_mock_response(
                    200,
                    b"<html><body>Homepage with unique content XYZ123</body></html>",
                    {"server": "nginx"},
                )
            # Random probe paths return different content (404 pages)
            return _make_mock_response(
                404,
                b"<html><body>Not Found - this is a 404 error page</body></html>",
                {"server": "nginx"},
            )

        async def mock_post(url, **kwargs):
            return _make_mock_response(
                200,
                b"<html><body>POST response different from GET</body></html>",
                {"server": "nginx"},
            )

        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://target.com"]))

        assert "https://target.com" in result
        profile = result["https://target.com"]
        assert profile.host_type == HostType.WEB_APP

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_spa_classification(self, mock_client_cls):
        """Host returning same HTML for all paths → SPA."""
        spa_body = b"""<html>
        <head><title>My SPA App</title></head>
        <body>
            <div id="app"></div>
            <script src="/static/js/bundle.js"></script>
            <script>window.__NEXT_DATA__={}</script>
        """ + b"x" * 1000 + b"""
        </body>
        </html>"""

        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            return _make_mock_response(200, spa_body, {"server": "nginx", "content-type": "text/html"})

        async def mock_post(url, **kwargs):
            return _make_mock_response(200, spa_body, {"server": "nginx"})

        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://spa.example.com"]))

        profile = result["https://spa.example.com"]
        assert profile.host_type == HostType.SPA
        assert profile.content_similarity >= _SIMILARITY_THRESHOLD

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_auth_gated_classification(self, mock_client_cls):
        """Host that redirects all paths to /login → AUTH_GATED."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            follow = kwargs.get("follow_redirects", False)
            # Everything redirects to login
            return _make_mock_response(
                302,
                b"",
                {"location": "https://gated.com/login?next=/whatever", "server": "nginx"},
            )

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://gated.com"]))

        profile = result["https://gated.com"]
        assert profile.host_type == HostType.AUTH_GATED
        assert profile.auth_required is True
        assert len(profile.skip_checkers) > 0

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_redirect_host_classification(self, mock_client_cls):
        """Host that redirects to another domain → REDIRECT_HOST."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            return _make_mock_response(
                301,
                b"",
                {"location": "https://www.otherdomain.com/", "server": "nginx"},
            )

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://redirect.com"]))

        profile = result["https://redirect.com"]
        assert profile.host_type == HostType.REDIRECT_HOST
        assert profile.confidence_modifier == -0.25

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_api_server_classification(self, mock_client_cls):
        """Host returning application/json → API_SERVER."""
        mock_client = AsyncMock()
        api_body = b'{"status": "ok", "version": "1.0"}'

        async def mock_get(url, **kwargs):
            follow = kwargs.get("follow_redirects", False)
            return _make_mock_response(
                200, api_body,
                {"server": "gunicorn", "content-type": "application/json"},
            )

        async def mock_post(url, **kwargs):
            return _make_mock_response(
                200, b'{"result": "created"}',
                {"server": "gunicorn", "content-type": "application/json"},
            )

        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://api.example.com"]))

        profile = result["https://api.example.com"]
        assert profile.host_type == HostType.API_SERVER

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_deduplication(self, mock_client_cls):
        """Duplicate hosts should only be profiled once."""
        mock_client = AsyncMock()

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            return _make_mock_response(200, b"<html>page</html>", {"server": "nginx"})

        async def mock_post(url, **kwargs):
            return _make_mock_response(200, b"<html>page</html>", {"server": "nginx"})

        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts([
            "https://dup.com", "https://dup.com", "https://dup.com",
        ]))
        assert len(result) == 1
        assert "https://dup.com" in result

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_exception_handling(self, mock_client_cls):
        """Hosts that throw exceptions get UNKNOWN profile."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            raise ConnectionError("Connection refused")

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://down.com"]))

        profile = result["https://down.com"]
        assert profile.host_type == HostType.UNKNOWN

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_static_site_classification(self, mock_client_cls):
        """Host returning same plain HTML for all paths with no JS framework → STATIC_SITE."""
        static_body = b"""<html>
        <head><title>My Blog</title></head>
        <body>
            <h1>Welcome to my static blog</h1>
            <p>This is a static HTML page with no JavaScript framework.</p>
            <p>Just plain old HTML content that never changes.</p>
        """ + b"x" * 1000 + b"""
        </body>
        </html>"""

        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            return _make_mock_response(200, static_body, {"server": "nginx", "content-type": "text/html"})

        async def mock_post(url, **kwargs):
            return _make_mock_response(200, static_body, {"server": "nginx"})

        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://static.com"]))

        profile = result["https://static.com"]
        assert profile.host_type == HostType.STATIC_SITE
        assert profile.confidence_modifier == -0.20

    @patch("src.analysis.host_profiler.httpx.AsyncClient")
    def test_cdn_and_waf_detected(self, mock_client_cls):
        """CDN and WAF info extracted from headers."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            follow = kwargs.get("follow_redirects", False)
            return _make_mock_response(
                200,
                b"<html>Cloudflare protected page with unique content for homepage</html>",
                {
                    "server": "cloudflare",
                    "cf-ray": "abc123-IAD",
                    "cf-cache-status": "HIT",
                    "content-type": "text/html",
                },
            )

        async def mock_post(url, **kwargs):
            return _make_mock_response(200, b"different post content XYZ", {"server": "cloudflare"})

        mock_client.get = mock_get
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        profiler = HostProfiler()
        result = asyncio.run(profiler.profile_hosts(["https://cf.example.com"]))

        profile = result["https://cf.example.com"]
        assert profile.cdn_provider == "cloudflare"
        assert profile.waf_detected is True
        assert profile.waf_name == "cloudflare"


# ==================================================================
# _extract_redirect_target()
# ==================================================================

class TestExtractRedirectTarget:
    def _make_headers(self, header_dict):
        import httpx
        return httpx.Headers(header_dict)

    def test_absolute_url(self):
        h = self._make_headers({"location": "https://other.com/page"})
        assert _extract_redirect_target(h, "https://example.com") == "https://other.com/page"

    def test_relative_url(self):
        h = self._make_headers({"location": "/login"})
        result = _extract_redirect_target(h, "https://example.com/path")
        assert result == "https://example.com/login"

    def test_no_location(self):
        h = self._make_headers({})
        assert _extract_redirect_target(h, "https://example.com") == ""


# ==================================================================
# Edge Cases
# ==================================================================

class TestEdgeCases:
    def test_from_dict_empty(self):
        p = HostIntelProfile.from_dict({})
        assert p.host == ""
        assert p.host_type is HostType.UNKNOWN

    def test_get_skip_map(self):
        skip_map = HostProfiler.get_skip_map()
        assert isinstance(skip_map, dict)
        assert "mass_assignment_checker" in skip_map

    def test_host_type_in_string_context(self):
        """HostType should work in f-strings and comparisons."""
        ht = HostType.SPA
        assert f"Type: {ht.value}" == "Type: spa"
        assert ht.value == "spa"
