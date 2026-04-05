"""Regression tests for secondary workflow pipelines."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from src.tools.base import Finding
from src.workflow.orchestrator import WorkflowState
from src.workflow.pipelines import api_scan, web_app
import src.main as main_module


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_available(self) -> bool:
        return True


class _SlowExecutor:
    async def execute(self, tool, target, options=None):  # noqa: ANN001
        await asyncio.sleep(0.05)
        return SimpleNamespace(success=True, findings=[])


def test_web_app_execute_tool_applies_timeout():
    async def _test():
        executor = _SlowExecutor()
        with pytest.raises(asyncio.TimeoutError):
            await web_app._execute_tool(
                executor,
                _FakeTool("httpx"),
                "https://example.com",
                {},
                timeout=0.01,
            )

    asyncio.run(_test())


def test_api_scan_execute_tool_applies_timeout():
    async def _test():
        executor = _SlowExecutor()
        with pytest.raises(asyncio.TimeoutError):
            await api_scan._execute_tool(
                executor,
                _FakeTool("ffuf"),
                "https://example.com",
                {},
                timeout=0.01,
            )

    asyncio.run(_test())


def test_build_api_scan_pipeline_wires_injected_dependencies():
    brain = object()
    executor = object()
    detector = object()

    orchestrator = api_scan.build_api_scan_pipeline(
        target="https://example.com",
        brain_engine=brain,
        tool_executor=executor,
        fp_detector=detector,
    )

    assert orchestrator.brain_engine is brain
    assert orchestrator.tool_executor is executor
    assert orchestrator.fp_detector is detector


def test_build_network_scan_pipeline_wires_injected_dependencies():
    from src.workflow.pipelines.network_scan import build_network_scan_pipeline

    brain = object()
    executor = object()
    detector = object()

    orchestrator = build_network_scan_pipeline(
        brain_engine=brain,
        tool_executor=executor,
        fp_detector=detector,
    )

    assert orchestrator.brain_engine is brain
    assert orchestrator.tool_executor is executor
    assert orchestrator.fp_detector is detector


def test_build_quick_recon_pipeline_wires_injected_dependencies():
    from src.workflow.pipelines.quick_recon import build_quick_recon_pipeline

    brain = object()
    executor = object()
    detector = object()

    orchestrator = build_quick_recon_pipeline(
        brain_engine=brain,
        tool_executor=executor,
        fp_detector=detector,
    )

    assert orchestrator.brain_engine is brain
    assert orchestrator.tool_executor is executor
    assert orchestrator.fp_detector is detector


def test_main_pipeline_selector_routes_to_requested_builder(monkeypatch):
    import src.workflow.pipelines as pipelines_module

    called = {}

    def _fake_api(**kwargs):
        called["name"] = "api"
        called["kwargs"] = kwargs
        return "api-orchestrator"

    monkeypatch.setattr(pipelines_module, "build_api_scan_pipeline", _fake_api)

    result = main_module._build_pipeline_orchestrator(
        "api",
        brain_engine="brain",
        tool_executor="executor",
        fp_detector="detector",
        mode="mode",
        profile="profile",
        session_manager="session-manager",
        brain_router="router",
    )

    assert result == "api-orchestrator"
    assert called["name"] == "api"
    assert called["kwargs"]["brain_engine"] == "brain"
    assert called["kwargs"]["tool_executor"] == "executor"
    assert called["kwargs"]["fp_detector"] == "detector"


def test_main_pipeline_selector_rejects_unknown_pipeline():
    with pytest.raises(ValueError, match="Unknown pipeline type"):
        main_module._build_pipeline_orchestrator(
            "nope",
            brain_engine="brain",
            tool_executor="executor",
            fp_detector="detector",
            mode="mode",
            profile="profile",
            session_manager="session-manager",
            brain_router="router",
        )


def test_handle_api_discovery_uses_safe_executor_bridge(monkeypatch):
    class FakeToolExecutor:
        async def execute(self, tool, target, options=None):  # noqa: ANN001
            if tool.name == "ffuf":
                return SimpleNamespace(
                    findings=[{"title": "spec", "url": "https://example.com/openapi.json"}],
                )
            if tool.name == "graphql_introspection":
                return SimpleNamespace(
                    findings=[{"title": "graphql", "url": "https://example.com/graphql"}],
                )
            if tool.name == "whatweb":
                return SimpleNamespace(
                    findings=[{"title": "tech", "technology": "FastAPI"}],
                )
            return SimpleNamespace(findings=[])

    tool_map = {
        "ffuf": _FakeTool("ffuf"),
        "graphql_introspection": _FakeTool("graphql_introspection"),
        "whatweb": _FakeTool("whatweb"),
    }

    from src.tools import executor as executor_module
    from src.tools.registry import tool_registry

    monkeypatch.setattr(executor_module, "ToolExecutor", FakeToolExecutor)
    monkeypatch.setattr(tool_registry, "get", lambda name: tool_map.get(name))

    async def _test():
        state = WorkflowState(target="https://example.com", metadata={})
        result = await api_scan.handle_api_discovery(state)

        assert result.success is True
        assert result.data["openapi_specs"] == ["https://example.com/openapi.json"]
        assert "/graphql" in result.data["graphql_endpoints"]
        assert result.data["api_endpoints"]

    asyncio.run(_test())


def test_handle_web_recon_updates_state_with_safe_executor(monkeypatch):
    class FakeToolExecutor:
        async def execute(self, tool, target, options=None):  # noqa: ANN001
            if tool.name == "amass":
                return SimpleNamespace(
                    findings=[Finding(title="sub", target="api.example.com")],
                )
            if tool.name == "httpx":
                return SimpleNamespace(success=True, findings=[])
            if tool.name == "katana":
                return SimpleNamespace(
                    findings=[SimpleNamespace(url="https://api.example.com/users")],
                )
            return SimpleNamespace(success=True, findings=[])

    tool_map = {
        "amass": _FakeTool("amass"),
        "httpx": _FakeTool("httpx"),
        "katana": _FakeTool("katana"),
    }

    from src.tools import executor as executor_module
    from src.tools.registry import tool_registry

    monkeypatch.setattr(executor_module, "ToolExecutor", FakeToolExecutor)
    monkeypatch.setattr(tool_registry, "get", lambda name: tool_map.get(name))

    async def _test():
        state = WorkflowState(target="example.com", metadata={})
        result = await web_app.handle_web_recon(state)

        assert result.success is True
        assert "api.example.com" in state.subdomains
        assert "example.com" in state.live_hosts
        assert "https://api.example.com/users" in state.endpoints

    asyncio.run(_test())


def test_web_app_finding_to_dict_prefers_endpoint_and_keeps_oob_metadata():
    finding = SimpleNamespace(
        title="Blind SSRF",
        endpoint="https://api.example.com/proxy",
        severity="high",
        confidence=80.0,
        interactsh_callback="dns-hit",
        oob_domain="oob.example",
        blind_verification=True,
    )

    result = web_app._finding_to_dict(finding, "ssrfmap", "https://example.com")

    assert result["url"] == "https://api.example.com/proxy"
    assert result["endpoint"] == "https://api.example.com/proxy"
    assert result["interactsh_callback"] == "dns-hit"
    assert result["oob_domain"] == "oob.example"
    assert result["blind_verification"] is True
