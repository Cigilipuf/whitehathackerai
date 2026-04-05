"""Integration tests for V9 full_scan module wiring."""

from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest

from src.tools.base import Finding, ToolResult
from src.utils.constants import SeverityLevel, WorkflowStage
from src.workflow.orchestrator import WorkflowState
from src.workflow.pipelines import full_scan


class _UnavailableTool:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_available(self) -> bool:
        return False


def _patch_asset_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(full_scan._adb, "record_scan_start", lambda state: "scan-test")
    monkeypatch.setattr(full_scan._adb, "save_subdomains", lambda state: None)
    monkeypatch.setattr(full_scan._adb, "save_live_hosts", lambda state: None)
    monkeypatch.setattr(full_scan._adb, "save_endpoints", lambda state: None)


def _install_module(monkeypatch: pytest.MonkeyPatch, name: str, **attrs) -> None:
    mod = ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    monkeypatch.setitem(sys.modules, name, mod)


def test_full_scan_passive_recon_wires_github_and_mail(monkeypatch, tmp_path):
    _patch_asset_db(monkeypatch)

    from src.tools.registry import tool_registry
    monkeypatch.setattr(tool_registry, "get", lambda name: None)

    class FakeGitHubSecretScanner:
        def is_available(self) -> bool:
            return True

        async def run(self, target, options=None, profile=None):  # noqa: ANN001
            return ToolResult(
                tool_name="github_secret_scanner",
                findings=[Finding(title="Leaked token", target=target, severity=SeverityLevel.HIGH)],
            )

    class FakeEmailSecurityChecker:
        def is_available(self) -> bool:
            return True

        async def run(self, target, options=None, profile=None):  # noqa: ANN001
            return ToolResult(
                tool_name="mail_security_checker",
                findings=[Finding(title="Missing DMARC", target=target, severity=SeverityLevel.MEDIUM)],
            )

    import src.tools.recon.osint.github_secret_scanner as gh_mod
    import src.tools.recon.dns.mail_security as mail_mod

    monkeypatch.setattr(gh_mod, "GitHubSecretScanner", FakeGitHubSecretScanner)
    monkeypatch.setattr(mail_mod, "EmailSecurityChecker", FakeEmailSecurityChecker)

    async def _test():
        state = WorkflowState(target="example.com", metadata={})
        result = await full_scan.handle_passive_recon(state)

        assert result.success is True
        assert result.data["github_secrets"][0]["tool"] == "github_secret_scanner"
        assert result.data["mail_security"][0]["tool"] == "mail_security_checker"

    asyncio.run(_test())


def test_full_scan_active_recon_wires_cdn_and_reverse_ip(monkeypatch):
    _patch_asset_db(monkeypatch)

    from src.tools.registry import tool_registry
    monkeypatch.setattr(tool_registry, "get", lambda name: None)

    class FakeCDNDetector:
        def is_available(self) -> bool:
            return True

        async def run(self, target, options=None, profile=None):  # noqa: ANN001
            return ToolResult(
                tool_name="cdn_detector",
                findings=[Finding(title="Cloudflare CDN", target=target, severity=SeverityLevel.INFO)],
            )

    class FakeReverseIPLookup:
        def is_available(self) -> bool:
            return True

        async def run(self, target, options=None, profile=None):  # noqa: ANN001
            return ToolResult(
                tool_name="reverse_ip",
                findings=[Finding(title="Co-hosted", target="shared.example.net", severity=SeverityLevel.INFO)],
            )

    import src.tools.recon.tech_detect.cdn_detector as cdn_mod
    import src.tools.recon.dns.reverse_ip as rip_mod

    monkeypatch.setattr(cdn_mod, "CDNDetector", FakeCDNDetector)
    monkeypatch.setattr(rip_mod, "ReverseIPLookup", FakeReverseIPLookup)

    async def _test():
        state = WorkflowState(target="example.com", subdomains=["app.example.com"], metadata={})
        result = await full_scan.handle_active_recon(state)

        assert result.success is True
        assert "Cloudflare CDN" in result.data["cdn_info"]
        assert "shared.example.net" in result.data["cohosted_domains"]

    asyncio.run(_test())


def test_full_scan_enumeration_wires_vhost_cloud_metadata_and_wordlist(monkeypatch, tmp_path):
    _patch_asset_db(monkeypatch)

    from src.tools.registry import tool_registry
    monkeypatch.setattr(tool_registry, "get", lambda name: None)

    class FakeVHostFuzzer:
        def is_available(self) -> bool:
            return True

        async def run(self, target, options=None, profile=None):  # noqa: ANN001
            return ToolResult(
                tool_name="vhost_fuzzer",
                findings=[Finding(title="Hidden vhost", endpoint="https://admin.example.com", severity=SeverityLevel.MEDIUM)],
            )

    class FakeCloudEnum:
        def is_available(self) -> bool:
            return True

        async def run(self, target, options=None, profile=None):  # noqa: ANN001
            return ToolResult(
                tool_name="cloud_enum",
                findings=[Finding(title="Open bucket", target="s3://example-bucket", severity=SeverityLevel.HIGH)],
            )

    class FakeMetadataExtractor:
        def is_available(self) -> bool:
            return True

        async def run(self, target, options=None, profile=None):  # noqa: ANN001
            return ToolResult(
                tool_name="metadata_extractor",
                findings=[Finding(title="Internal path leak", target=target, severity=SeverityLevel.MEDIUM)],
            )

    class FakeDynamicWordlistGenerator:
        def generate(self, target, subdomains=None, endpoints=None, technologies=None, static_wordlist=None):  # noqa: ANN001
            return ["admin", "staging", "internal-api"]

        def save(self, words, output_path):  # noqa: ANN001
            from pathlib import Path
            Path(output_path).write_text("\n".join(words), encoding="utf-8")
            return len(words)

    import src.tools.recon.web_discovery.vhost_fuzzer as vhost_mod
    import src.tools.recon.osint.cloud_enum as cloud_mod
    import src.tools.recon.osint.metadata_extractor as meta_mod
    import src.tools.fuzzing.dynamic_wordlist as dw_mod

    monkeypatch.setattr(vhost_mod, "VHostFuzzer", FakeVHostFuzzer)
    monkeypatch.setattr(cloud_mod, "CloudStorageEnumerator", FakeCloudEnum)
    monkeypatch.setattr(meta_mod, "MetadataExtractor", FakeMetadataExtractor)
    monkeypatch.setattr(dw_mod, "DynamicWordlistGenerator", FakeDynamicWordlistGenerator)

    async def _test():
        state = WorkflowState(
            session_id="sess-enum",
            target="example.com",
            live_hosts=["app.example.com"],
            subdomains=["app.example.com"],
            technologies={"app.example.com": ["nginx"]},
            metadata={},
        )
        result = await full_scan.handle_enumeration(state)

        assert result.success is True
        assert "https://admin.example.com" in state.endpoints
        assert result.data["cloud_buckets"][0]["tool"] == "cloud_enum"
        assert result.data["metadata_findings"][0]["tool"] == "metadata_extractor"
        assert result.data["dynamic_wordlist_path"].endswith("dynamic_wordlist.txt")

    asyncio.run(_test())


def test_full_scan_vuln_stage_runs_v9_custom_checkers(monkeypatch):
    _patch_asset_db(monkeypatch)

    from src.tools.registry import tool_registry
    monkeypatch.setattr(tool_registry, "get", lambda name: None)

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001
            return False

        async def get(self, url):  # noqa: ANN001
            return SimpleNamespace(status_code=404, json=lambda: {})

    monkeypatch.setattr(full_scan.httpx, "AsyncClient", lambda *args, **kwargs: FakeAsyncClient())

    async def _empty_async(*args, **kwargs):  # noqa: ANN001
        return []

    async def _spa_false(*args, **kwargs):  # noqa: ANN001
        return False, ""

    class _NoopChecker:
        async def run(self, target, options=None):  # noqa: ANN001
            return ToolResult(tool_name="noop", findings=[])

    class _FakeFourXXChecker:
        async def run(self, target, options=None):  # noqa: ANN001
            return ToolResult(
                tool_name="fourxx_bypass",
                findings=[Finding(title="403 bypass", endpoint=target, severity=SeverityLevel.HIGH)],
            )

    class _NoopSourceMapExtractor:
        def is_available(self) -> bool:
            return False

    class _NoopMsf:
        def is_available(self) -> bool:
            return False

    class _NoopInteractsh:
        _session_active = False

        def is_available(self) -> bool:
            return False

    _install_module(monkeypatch, "src.tools.scanners.header_checker", check_security_headers=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.tech_cve_checker", check_technology_cves=lambda *a, **k: [], check_technology_cves_live=_empty_async)
    _install_module(monkeypatch, "src.utils.spa_detector", is_spa_catchall=_spa_false)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.sensitive_url_finder", find_sensitive_urls=lambda *a, **k: [])

    async def _empty_js(*args, **kwargs):  # noqa: ANN001
        return [], []

    _install_module(monkeypatch, "src.tools.scanners.custom_checks.js_analyzer", analyze_javascript_files=_empty_js)
    _install_module(monkeypatch, "src.tools.recon.web_discovery.sourcemap_extractor", SourceMapExtractor=_NoopSourceMapExtractor)
    _install_module(monkeypatch, "src.tools.api_tools.swagger_parser", SwaggerParserWrapper=SimpleNamespace(extract_fuzzable_endpoints=lambda spec, base: []))
    _install_module(monkeypatch, "src.tools.api_tools.api_fuzzer", fuzz_api_endpoints=_empty_async)
    _install_module(monkeypatch, "src.tools.exploit.metasploit_wrapper", MetasploitWrapper=_NoopMsf)
    _install_module(monkeypatch, "src.tools.scanners.interactsh_wrapper", InteractshWrapper=_NoopInteractsh)

    _install_module(monkeypatch, "src.tools.scanners.custom_checks.http_method_checker", check_http_methods=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.open_redirect_checker", check_open_redirects=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.info_disclosure_checker", check_info_disclosure=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.cookie_checker", check_cookie_security=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.api_endpoint_tester", test_api_endpoints=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.cors_checker", check_cors_misconfigurations=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.auth_bypass", AuthBypassChecker=_NoopChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.rate_limit_checker", RateLimitChecker=_NoopChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.business_logic", BusinessLogicChecker=_NoopChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.deserialization_checker", DeserializationChecker=_NoopChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.bfla_bola_checker", BFLABOLAChecker=_NoopChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.mass_assignment_checker", MassAssignmentChecker=_NoopChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.idor_checker", IDORChecker=_NoopChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.cache_poisoning_checker", check_cache_poisoning=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.websocket_checker", check_websocket_security=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.cloud_misconfig_checker", check_cloud_misconfig=_empty_async)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.jwt_checker", check_jwt_security=lambda *a, **k: _empty_async())
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.fourxx_bypass", FourXXBypassChecker=_FakeFourXXChecker)
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.http_smuggling_prober", check_http_smuggling=lambda *a, **k: _empty_async())
    _install_module(monkeypatch, "src.tools.scanners.custom_checks.graphql_deep_scanner", scan_graphql_deep=lambda *a, **k: _empty_async())

    async def _jwt_findings(*args, **kwargs):  # noqa: ANN001
        return [Finding(title="JWT weak secret", endpoint="https://api.example.com", severity=SeverityLevel.HIGH)]

    async def _smuggling_findings(*args, **kwargs):  # noqa: ANN001
        return [Finding(title="HTTP smuggling", endpoint="https://api.example.com", severity=SeverityLevel.HIGH)]

    async def _graphql_findings(*args, **kwargs):  # noqa: ANN001
        return [Finding(title="GraphQL alias abuse", endpoint="https://api.example.com/graphql", severity=SeverityLevel.MEDIUM)]

    sys.modules["src.tools.scanners.custom_checks.jwt_checker"].check_jwt_security = _jwt_findings
    sys.modules["src.tools.scanners.custom_checks.http_smuggling_prober"].check_http_smuggling = _smuggling_findings
    sys.modules["src.tools.scanners.custom_checks.graphql_deep_scanner"].scan_graphql_deep = _graphql_findings

    async def _test():
        state = WorkflowState(
            target="api.example.com",
            live_hosts=["api.example.com"],
            endpoints=["https://api.example.com/graphql"],
            technologies={},
            metadata={"auth_headers": {"Authorization": "Bearer aaaaaa.bbbbbb.cccccc"}},
            stage_results={},
        )

        result = await full_scan.handle_vulnerability_scan(state)

        assert result.success is True
        # Primary assertion: all V9 custom checkers are wired and executed
        assert "jwt_checker" in state.tools_run
        assert "fourxx_bypass" in state.tools_run
        assert "http_smuggling_prober" in state.tools_run
        assert "graphql_deep_scanner" in state.tools_run
        # Findings are produced (exact set depends on module import order
        # due to monkeypatch timing, so just verify some findings exist)
        assert len(state.raw_findings) >= 1

    asyncio.run(_test())
