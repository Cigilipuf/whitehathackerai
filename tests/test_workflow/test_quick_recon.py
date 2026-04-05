"""Regression tests for quick_recon pipeline hardening."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from src.tools.base import Finding
from src.workflow.orchestrator import WorkflowState
from src.workflow.pipelines import quick_recon


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_available(self) -> bool:
        return True


class _SlowExecutor:
    async def execute(self, tool, target, options=None):  # noqa: ANN001
        await asyncio.sleep(0.05)
        return SimpleNamespace(success=True, findings=[])


def test_quick_recon_execute_tool_applies_timeout():
    async def _test():
        executor = _SlowExecutor()
        with pytest.raises(asyncio.TimeoutError):
            await quick_recon._execute_tool(
                executor,
                _FakeTool("httpx"),
                "https://example.com",
                {},
                timeout=0.01,
            )

    asyncio.run(_test())


def test_handle_quick_passive_uses_safe_executor(monkeypatch):
    class FakeToolExecutor:
        async def execute(self, tool, target, options=None):  # noqa: ANN001
            if tool.name == "dig":
                return SimpleNamespace(raw_output="A 1.2.3.4", findings=[])
            if tool.name == "whois":
                return SimpleNamespace(raw_output="Registrar: Example", findings=[])
            if tool.name == "subfinder":
                return SimpleNamespace(
                    findings=[
                        Finding(title="sub", target="api.example.com"),
                        Finding(title="sub", target="www.example.com"),
                    ],
                )
            return SimpleNamespace(raw_output="", findings=[])

    tool_map = {
        "dig": _FakeTool("dig"),
        "whois": _FakeTool("whois"),
        "subfinder": _FakeTool("subfinder"),
        "amass": _FakeTool("amass"),
        "assetfinder": _FakeTool("assetfinder"),
    }

    from src.tools import executor as executor_module
    from src.tools.registry import tool_registry

    monkeypatch.setattr(executor_module, "ToolExecutor", FakeToolExecutor)
    monkeypatch.setattr(tool_registry, "get", lambda name: tool_map.get(name))

    async def _test():
        state = WorkflowState(target="example.com", metadata={})
        result = await quick_recon.handle_quick_passive(state)

        assert result.success is True
        assert state.subdomains == ["api.example.com", "www.example.com"]
        assert result.data["dns_info"] == "A 1.2.3.4"
        assert "Registrar" in result.data["whois_info"]

    asyncio.run(_test())


def test_handle_quick_active_uses_safe_executor(monkeypatch):
    class FakeToolExecutor:
        async def execute(self, tool, target, options=None):  # noqa: ANN001
            if tool.name == "httpx":
                return SimpleNamespace(success=True, findings=[])
            if tool.name == "nmap":
                return SimpleNamespace(
                    findings=[
                        SimpleNamespace(target=target, port=80),
                        SimpleNamespace(target=target, port=443),
                    ],
                )
            if tool.name == "whatweb":
                return SimpleNamespace(raw_output="nginx, php", findings=[])
            return SimpleNamespace(success=True, findings=[])

    tool_map = {
        "httpx": _FakeTool("httpx"),
        "nmap": _FakeTool("nmap"),
        "whatweb": _FakeTool("whatweb"),
    }

    from src.tools import executor as executor_module
    from src.tools.registry import tool_registry

    monkeypatch.setattr(executor_module, "ToolExecutor", FakeToolExecutor)
    monkeypatch.setattr(tool_registry, "get", lambda name: tool_map.get(name))

    async def _test():
        state = WorkflowState(
            target="example.com",
            subdomains=["api.example.com"],
            metadata={},
        )
        result = await quick_recon.handle_quick_active(state)

        assert result.success is True
        assert "api.example.com" in state.live_hosts
        assert state.open_ports["api.example.com"] == [80, 443]
        assert state.technologies["api.example.com"] == "nginx, php"

    asyncio.run(_test())
