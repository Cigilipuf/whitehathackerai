"""
V26 Final Fixes — Regression Tests
P4-4: Exploit verifier timeout + template expansion
P4-3: Historical learning multi-factor scoring
P2-2: PerfProfiler record_tool kwargs fix
"""

from __future__ import annotations

import asyncio
import inspect
import json
import textwrap
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── P4-4: Exploit Verifier Timeout Fixes ───────────────────────


class TestPoCGenerationTimeout:
    """Verify generate_poc_script uses reasonable timeout (not 1200s)."""

    def test_generate_poc_source_timeout_600s(self):
        """generate_poc_script should use 600s timeout, not 1200s."""
        import ast
        from pathlib import Path

        src = Path("src/tools/exploit/payload_generator.py").read_text()
        tree = ast.parse(src)

        # Find the asyncio.wait_for calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # Match asyncio.wait_for(...)
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "wait_for"
                    and isinstance(func.value, ast.Attribute)
                    and func.value.attr == "wait_for"
                ) or (
                    isinstance(func, ast.Attribute)
                    and func.attr == "wait_for"
                ):
                    for kw in node.keywords:
                        if kw.arg == "timeout":
                            if isinstance(kw.value, ast.Constant):
                                assert kw.value.value <= 600.0, (
                                    f"Brain timeout {kw.value.value}s is too high (max 600s)"
                                )

    def test_generate_poc_source_no_1200(self):
        """No 1200.0 timeout should exist in payload_generator.py."""
        from pathlib import Path
        src = Path("src/tools/exploit/payload_generator.py").read_text()
        assert "timeout=1200" not in src, "Found legacy 1200s timeout in payload_generator.py"


class TestPoCExecutorTimeout:
    """Verify poc_executor uses reasonable defaults."""

    def test_execute_poc_default_600s(self):
        """execute_poc default timeout should be 600s."""
        from src.tools.exploit.poc_executor import execute_poc
        sig = inspect.signature(execute_poc)
        assert sig.parameters["timeout"].default == 600.0

    def test_run_poc_with_refinement_default_600s(self):
        """run_poc_with_refinement default timeout should be 600s."""
        from src.tools.exploit.poc_executor import run_poc_with_refinement
        sig = inspect.signature(run_poc_with_refinement)
        assert sig.parameters["timeout"].default == 600.0

    def test_refine_poc_no_1200_timeout(self):
        """_refine_poc_with_llm should not have 1200s timeout."""
        from pathlib import Path
        src = Path("src/tools/exploit/poc_executor.py").read_text()
        assert "timeout=1200" not in src, "Found legacy 1200s timeout in poc_executor.py"


class TestExploitVerifierDefaults:
    """Verify ExploitVerifier class uses reasonable defaults."""

    def test_poc_timeout_default_600(self):
        from src.tools.exploit.exploit_verifier import ExploitVerifier
        v = ExploitVerifier()
        assert v.poc_timeout == 600.0

    def test_max_poc_iterations_default_3(self):
        from src.tools.exploit.exploit_verifier import ExploitVerifier
        v = ExploitVerifier()
        assert v.max_poc_iterations == 3

    def test_msf_timeout_default_300(self):
        from src.tools.exploit.exploit_verifier import ExploitVerifier
        v = ExploitVerifier()
        assert v.msf_timeout == 300.0


# ── P4-4: Simple PoC Template Expansion ────────────────────────


class TestSimplePoCTemplates:
    """Test that _generate_simple_poc covers high-severity vuln types."""

    def _generate(self, vuln_type: str, **extra) -> str | None:
        from src.tools.exploit.payload_generator import _generate_simple_poc
        finding = {
            "vulnerability_type": vuln_type,
            "url": "https://example.com/test?id=1",
            "title": f"Test {vuln_type}",
            "parameter": "id",
            "payload": "test",
            **extra,
        }
        return _generate_simple_poc(finding)

    def test_sqli_template_exists(self):
        code = self._generate("sql_injection")
        assert code is not None
        assert "SQL" in code or "sql" in code.lower()
        assert "[+] VULNERABLE" in code

    def test_sqli_template_has_time_based(self):
        code = self._generate("sql_injection")
        assert code is not None
        assert "SLEEP" in code or "sleep" in code

    def test_sqli_template_has_error_patterns(self):
        code = self._generate("sql_injection")
        assert code is not None
        assert "sql syntax" in code.lower() or "SQL_ERRORS" in code

    def test_lfi_template_exists(self):
        code = self._generate("lfi")
        assert code is not None
        assert "etc/passwd" in code

    def test_lfi_path_traversal_template(self):
        code = self._generate("path_traversal")
        assert code is not None
        assert "etc/passwd" in code

    def test_command_injection_template_exists(self):
        code = self._generate("command_injection")
        assert code is not None
        assert "sleep" in code.lower()

    def test_rce_template_exists(self):
        code = self._generate("rce")
        assert code is not None
        assert "sleep" in code.lower()

    def test_ssti_template_exists(self):
        code = self._generate("ssti")
        assert code is not None
        assert "49" in code  # 7*7 = 49

    def test_template_poc_is_valid_python(self):
        """All generated templates must be syntactically valid."""
        vuln_types = [
            "sql_injection", "lfi", "path_traversal",
            "command_injection", "rce", "ssti",
            "missing_security_header", "information_disclosure",
            "clickjacking", "cors_misconfiguration",
        ]
        for vt in vuln_types:
            code = self._generate(vt)
            if code is not None:
                try:
                    compile(code, f"<{vt}>", "exec")
                except SyntaxError as e:
                    pytest.fail(f"Template for {vt} has syntax error: {e}")

    def test_existing_templates_still_work(self):
        """Existing low-severity templates shouldn't be broken."""
        for vt in ["missing_security_header", "information_disclosure", "clickjacking"]:
            code = self._generate(vt)
            assert code is not None, f"Template for {vt} should still exist"

    def test_no_url_returns_none(self):
        """No URL should return None."""
        from src.tools.exploit.payload_generator import _generate_simple_poc
        finding = {
            "vulnerability_type": "sql_injection",
            "url": "",
            "title": "Test",
        }
        assert _generate_simple_poc(finding) is None


# ── P4-3: Historical Learning Multi-Factor Scoring ─────────────


class TestHistoricalLearningScoring:
    """Verify _optimize_with_knowledge uses actual effectiveness_score."""

    def test_uses_effectiveness_score_not_binary(self):
        """Tools with higher effectiveness_score should rank higher."""
        from src.workflow.decision_engine import DecisionEngine

        # Mock KB returning tools with different effectiveness scores
        mock_kb = MagicMock()

        class FakeTE:
            def __init__(self, name, score):
                self.tool_name = name
                self.effectiveness_score = score

        mock_kb.get_best_tools_for.return_value = [
            FakeTE("nuclei", 0.9),
            FakeTE("nikto", 0.3),
            FakeTE("dalfox", 0.7),
        ]

        de = DecisionEngine(profile="balanced", knowledge_base=mock_kb)
        result = asyncio.run(
            de._optimize_with_knowledge(
                ["nikto", "nuclei", "dalfox", "sqlmap"],
                "web",
                {},
            )
        )

        # nuclei(0.9) > dalfox(0.7) > sqlmap(0.5=unknown) > nikto(0.3)
        assert result.index("nuclei") < result.index("dalfox")
        assert result.index("dalfox") < result.index("sqlmap")
        assert result.index("sqlmap") < result.index("nikto")

    def test_unknown_tools_get_neutral_score(self):
        """Tools not in KB should get 0.5 (neutral)."""
        from src.workflow.decision_engine import DecisionEngine

        mock_kb = MagicMock()

        class FakeTE:
            def __init__(self, name, score):
                self.tool_name = name
                self.effectiveness_score = score

        mock_kb.get_best_tools_for.return_value = [
            FakeTE("nuclei", 0.8),
        ]

        de = DecisionEngine(profile="balanced", knowledge_base=mock_kb)
        result = asyncio.run(
            de._optimize_with_knowledge(
                ["nuclei", "unknowntool"],
                "web",
                {},
            )
        )
        # nuclei(0.8) should be before unknowntool(0.5)
        assert result == ["nuclei", "unknowntool"]

    def test_no_kb_returns_original_order(self):
        """Without KB, tool order should be preserved."""
        from src.workflow.decision_engine import DecisionEngine

        de = DecisionEngine(profile="balanced")
        tools = ["a", "b", "c"]
        result = asyncio.run(de._optimize_with_knowledge(tools, "web", {}))
        assert result == tools

    def test_kb_exception_returns_original(self):
        """KB exception should gracefully return original list."""
        from src.workflow.decision_engine import DecisionEngine

        mock_kb = MagicMock()
        mock_kb.get_best_tools_for.side_effect = RuntimeError("DB error")

        de = DecisionEngine(profile="balanced", knowledge_base=mock_kb)
        tools = ["a", "b", "c"]
        result = asyncio.run(de._optimize_with_knowledge(tools, "web", {}))
        assert result == tools

    def test_dict_format_effectiveness_data(self):
        """KB may return dicts instead of objects — handle both."""
        from src.workflow.decision_engine import DecisionEngine

        mock_kb = MagicMock()
        mock_kb.get_best_tools_for.return_value = [
            {"name": "nuclei", "effectiveness_score": 0.9},
            {"name": "nikto", "effectiveness_score": 0.2},
        ]

        de = DecisionEngine(profile="balanced", knowledge_base=mock_kb)
        result = asyncio.run(
            de._optimize_with_knowledge(
                ["nikto", "nuclei"],
                "web",
                {},
            )
        )
        assert result == ["nuclei", "nikto"]


# ── P4-4: Strategy Selection ───────────────────────────────────


class TestVerificationStrategy:
    """Test exploit verifier strategy selection."""

    def test_cve_routes_to_metasploit(self):
        from src.tools.exploit.exploit_verifier import _select_strategy, VerificationStrategy
        f = {"title": "CVE-2021-44228 Log4Shell", "description": ""}
        assert _select_strategy(f) == VerificationStrategy.METASPLOIT

    def test_curl_poc_routes_to_curl(self):
        from src.tools.exploit.exploit_verifier import _select_strategy, VerificationStrategy
        f = {"title": "XSS", "poc_curl": "curl -X GET ..."}
        assert _select_strategy(f) == VerificationStrategy.CURL_COMMAND

    def test_nuclei_finding_routes_to_nuclei(self):
        from src.tools.exploit.exploit_verifier import _select_strategy, VerificationStrategy
        f = {"title": "XSS", "tool": "nuclei", "template_id": "xss-reflected"}
        assert _select_strategy(f) == VerificationStrategy.NUCLEI_TEMPLATE

    def test_default_routes_to_poc_script(self):
        from src.tools.exploit.exploit_verifier import _select_strategy, VerificationStrategy
        f = {"title": "XSS", "description": "Reflected XSS"}
        assert _select_strategy(f) == VerificationStrategy.POC_SCRIPT


# ── P4-4: Prioritize Candidates ───────────────────────────────


class TestPrioritizeCandidates:
    """Test exploit verifier candidate filtering."""

    def test_filters_low_confidence(self):
        from src.tools.exploit.exploit_verifier import ExploitVerifier
        v = ExploitVerifier()
        findings = [
            {"url": "https://x.com/a", "confidence": 30, "severity": "high"},
            {"url": "https://x.com/b", "confidence": 60, "severity": "high"},
        ]
        result = v._prioritize_candidates(findings)
        assert len(result) == 1
        assert result[0]["url"] == "https://x.com/b"

    def test_filters_info_severity(self):
        from src.tools.exploit.exploit_verifier import ExploitVerifier
        v = ExploitVerifier()
        findings = [
            {"url": "https://x.com/a", "confidence": 80, "severity": "info"},
            {"url": "https://x.com/b", "confidence": 80, "severity": "high"},
        ]
        result = v._prioritize_candidates(findings)
        assert len(result) == 1

    def test_sorts_by_severity_then_confidence(self):
        from src.tools.exploit.exploit_verifier import ExploitVerifier
        v = ExploitVerifier()
        findings = [
            {"url": "https://x.com/a", "confidence": 90, "severity": "medium"},
            {"url": "https://x.com/b", "confidence": 80, "severity": "critical"},
            {"url": "https://x.com/c", "confidence": 85, "severity": "high"},
        ]
        result = v._prioritize_candidates(findings)
        assert result[0]["severity"] == "critical"
        assert result[1]["severity"] == "high"
        assert result[2]["severity"] == "medium"


# ── P2-2: PerfProfiler record_tool kwargs fix ─────────────────


class TestPerfProfilerRecordToolKwargs:
    """Verify executor calls PerfProfiler.record_tool with correct kwargs."""

    def test_executor_record_tool_kwargs_match_profiler(self):
        """The executor must use name=/duration=/success= (not tool_name/duration_s/findings_count)."""
        import ast
        from pathlib import Path

        src = Path("src/tools/executor.py").read_text()
        tree = ast.parse(src)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "record_tool":
                    kw_names = {kw.arg for kw in node.keywords}
                    assert "tool_name" not in kw_names, "executor still uses tool_name= (wrong)"
                    assert "duration_s" not in kw_names, "executor still uses duration_s= (wrong)"
                    assert "findings_count" not in kw_names, "executor still uses findings_count= (wrong)"
                    assert "name" in kw_names, "executor missing name= kwarg"
                    assert "duration" in kw_names, "executor missing duration= kwarg"

    def test_record_tool_actually_works(self):
        """Calling PerfProfiler.record_tool with correct kwargs should not raise."""
        from src.utils.perf_profiler import PerfProfiler

        p = PerfProfiler()
        p.start()
        # This must NOT raise TypeError
        p.record_tool(name="nmap", duration=12.5, success=True)
        p.record_tool(name="nuclei", duration=45.0, success=False)
        p.stop()
        report = p.report()
        assert "tools" in report
        assert "nmap" in report["tools"]
        assert "nuclei" in report["tools"]
        assert report["tools"]["nmap"]["runs"] == 1
        assert report["tools"]["nuclei"]["failures"] == 1

    def test_executor_integration_with_profiler(self):
        """Simulate executor calling profiler — must succeed, not silently fail."""
        from src.utils.perf_profiler import PerfProfiler

        profiler = PerfProfiler()
        profiler.start()

        # Simulate what executor does after the fix
        tool_name = "sqlmap"
        execution_time = 123.4
        success = True
        profiler.record_tool(
            name=tool_name,
            duration=execution_time,
            success=success,
        )

        profiler.stop()
        report = profiler.report()
        assert "sqlmap" in report["tools"]
        assert report["tools"]["sqlmap"]["total_s"] == 123.4
