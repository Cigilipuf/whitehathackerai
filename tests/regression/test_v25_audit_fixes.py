"""Regression tests for V25 Deep Integration Audit fixes.

Covers:
1. HttpContext field name fix in FP detector Layer 2c
2. tplmap agentic skip check enforcement
3. GF Router supplementary tool dispatch wiring
4. Brain cache key json_mode inclusion
5. SQLite timeout standardization (30s across all stores)
6. WorkflowState nullable type hints
"""

import importlib
import inspect
import re
import sqlite3

import pytest


# ──────────────────────────────────────────────────────────────
# 1. HttpContext field names — CRITICAL fix
# ──────────────────────────────────────────────────────────────


class TestHttpContextFieldNames:
    """Verify fp_detector.py Layer 2c uses correct HttpContext field names."""

    def test_httpcontext_model_fields(self):
        """HttpContext model must have the canonical field names."""
        from src.fp_engine.verification.context_verify import HttpContext
        fields = set(HttpContext.model_fields.keys())
        expected = {
            "request_method", "request_url", "request_headers",
            "request_body", "response_status", "response_headers",
            "response_body", "response_time_ms",
        }
        assert expected.issubset(fields), f"Missing fields: {expected - fields}"

    def test_fp_detector_uses_correct_field_names(self):
        """Layer 2c in fp_detector must use request_url, request_method, etc."""
        src = inspect.getsource(importlib.import_module("src.fp_engine.fp_detector"))
        # Must use correct field names
        assert "request_url=" in src, "fp_detector must use request_url= (not url=)"
        assert "request_method=" in src, "fp_detector must use request_method= (not method=)"
        assert "response_status=" in src, "fp_detector must use response_status= (not status_code=)"
        assert "response_time_ms=" in src, "fp_detector must use response_time_ms= (not response_time=)"
        assert "request_body=" in src, "fp_detector must pass request_body= to HttpContext"

    def test_fp_detector_no_old_field_names_in_httpcontext(self):
        """Layer 2c must NOT use the old incorrect field names."""
        src = inspect.getsource(importlib.import_module("src.fp_engine.fp_detector"))
        # Extract just the HttpContext construction block
        match = re.search(r"_cv_ctx = HttpContext\((.*?)\)", src, re.DOTALL)
        assert match is not None, "HttpContext construction not found"
        block = match.group(1)
        # These old names must NOT appear in the HttpContext() call
        assert "url=" not in block or "request_url=" in block, \
            "Must use request_url= not bare url="
        assert "method=" not in block or "request_method=" in block, \
            "Must use request_method= not bare method="
        assert "status_code=" not in block, "Must use response_status= not status_code="

    def test_httpcontext_construction_valid(self):
        """HttpContext can be constructed with the fields fp_detector uses."""
        from src.fp_engine.verification.context_verify import HttpContext
        ctx = HttpContext(
            request_url="https://example.com/test",
            request_method="POST",
            request_headers={},
            request_body="param=value",
            response_headers={},
            response_body="<html>OK</html>",
            response_status=200,
            response_time_ms=150.5,
        )
        assert ctx.request_method == "POST"
        assert ctx.request_url == "https://example.com/test"
        assert ctx.response_status == 200
        assert ctx.request_body == "param=value"

    def test_method_extraction_uses_request_method(self):
        """The method extraction loop must set request_method, not method."""
        src = inspect.getsource(importlib.import_module("src.fp_engine.fp_detector"))
        # After method extraction, must assign to request_method
        assert "_cv_ctx.request_method = _cv_m" in src, \
            "Method extraction must assign to _cv_ctx.request_method"
        assert "_cv_ctx.method = _cv_m" not in src, \
            "Old _cv_ctx.method assignment must be removed"


# ──────────────────────────────────────────────────────────────
# 2. tplmap agentic skip check
# ──────────────────────────────────────────────────────────────


class TestTplmapSkipCheck:
    """Verify tplmap invocations respect _skipped_tools."""

    def test_tplmap_python_has_skip_check(self):
        """Python tplmap section must check _skipped_tools."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Find the Python SSTI condition + block (condition is BEFORE the log msg)
        pattern = r'python.*flask.*django.*jinja.*?tplmap_tool\.is_available\(\).*?_skipped_tools'
        match = re.search(pattern, src, re.DOTALL)
        assert match, "Python tplmap condition must include _skipped_tools check"

    def test_tplmap_php_has_skip_check(self):
        """PHP tplmap section must check _skipped_tools."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Find the PHP SSTI condition + block (condition is BEFORE the log msg)
        pattern = r'php.*laravel.*symfony.*?tplmap_tool\.is_available\(\).*?_skipped_tools'
        match = re.search(pattern, src, re.DOTALL)
        assert match, "PHP tplmap condition must include _skipped_tools check"

    def test_all_tplmap_conditions_include_skip(self):
        """Every tplmap availability check must include _skipped_tools guard."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Find all lines like: if tplmap_tool and tplmap_tool.is_available() and deduped_params
        tplmap_cond_lines = [
            line.strip()
            for line in src.split("\n")
            if "tplmap_tool" in line and "is_available()" in line and "if " in line
        ]
        assert len(tplmap_cond_lines) >= 2, "Expected at least 2 tplmap condition lines"
        for line in tplmap_cond_lines:
            assert "_skipped_tools" in line, \
                f"tplmap condition missing _skipped_tools: {line}"


# ──────────────────────────────────────────────────────────────
# 3. GF Router supplementary tool dispatch
# ──────────────────────────────────────────────────────────────


class TestGFRouterDispatch:
    """Verify GF Router tasks are actually executed, not just stored."""

    def test_gf_dispatch_block_exists(self):
        """full_scan.py must contain GF Router dispatch execution code."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        assert "GF Router Supplementary Tool Dispatch" in src, \
            "GF Router dispatch block must exist in full_scan.py"

    def test_gf_dispatch_handles_tool_names(self):
        """Dispatch must iterate _gf_routed_tasks and execute."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        assert "_gf_routed_tasks" in src
        assert "_GF_PIPELINE_HANDLED" in src, \
            "Must have set of already-handled tools"
        assert "_gf_dispatch" in src, \
            "Must have async dispatch helper function"

    def test_gf_pipeline_handled_set_complete(self):
        """The _GF_PIPELINE_HANDLED set must include all explicitly invoked tools."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        match = re.search(r'_GF_PIPELINE_HANDLED\s*=\s*\{([^}]+)\}', src)
        assert match, "_GF_PIPELINE_HANDLED set not found"
        handled_str = match.group(1)
        for tool in ["dalfox", "sqlmap", "ssrfmap", "tplmap", "commix", "nuclei"]:
            assert tool in handled_str, f"{tool} missing from _GF_PIPELINE_HANDLED"

    def test_gf_dispatch_respects_skip_list(self):
        """GF dispatch must check _skipped_tools."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # After _GF_PIPELINE_HANDLED check, must also check skip list
        gf_block_start = src.index("GF Router Supplementary Tool Dispatch")
        gf_block = src[gf_block_start:gf_block_start + 2000]
        assert "_skipped_tools" in gf_block, \
            "GF dispatch must check _skipped_tools"

    def test_gf_dispatch_uses_auth_headers(self):
        """GF dispatch must pass auth headers."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        gf_block_start = src.index("GF Router Supplementary Tool Dispatch")
        gf_block = src[gf_block_start:gf_block_start + 2000]
        assert "_auth_headers" in gf_block, \
            "GF dispatch must pass auth headers"


# ──────────────────────────────────────────────────────────────
# 4. Brain cache key json_mode inclusion
# ──────────────────────────────────────────────────────────────


class TestBrainCacheKey:
    """Verify brain cache key includes json_mode to prevent format collisions."""

    def test_cache_key_includes_json_mode(self):
        """Cache key hash must include json_mode parameter."""
        src = inspect.getsource(
            importlib.import_module("src.brain.intelligence")
        )
        # Find the cache key construction
        match = re.search(r'cache_key\s*=\s*hashlib\.sha256\((.*?)\)', src, re.DOTALL)
        assert match, "Cache key construction not found"
        key_content = match.group(1)
        assert "json_mode" in key_content, \
            "Cache key must include json_mode to prevent format collisions"

    def test_cache_key_includes_brain_and_prompts(self):
        """Cache key must also include brain type and prompt content."""
        src = inspect.getsource(
            importlib.import_module("src.brain.intelligence")
        )
        match = re.search(r'cache_key\s*=\s*hashlib\.sha256\((.*?)\)', src, re.DOTALL)
        assert match, "Cache key construction not found"
        key_content = match.group(1)
        assert "brain.value" in key_content
        assert "system_prompt" in key_content
        assert "prompt" in key_content


# ──────────────────────────────────────────────────────────────
# 5. SQLite timeout standardization
# ──────────────────────────────────────────────────────────────


class TestSQLiteTimeouts:
    """Verify all SQLite connections use 30s timeout."""

    @pytest.mark.parametrize("module_path,expected_timeout", [
        ("src.integrations.database", 30),
        ("src.integrations.asset_db", 30),
        ("src.integrations.cache", 30),
        ("src.analysis.global_finding_store", 30),
        ("src.analysis.benchmark", 30),
        ("src.brain.memory.knowledge_base", 30),
    ])
    def test_sqlite_timeout_standardized(self, module_path, expected_timeout):
        """Each SQLite module must use timeout=30."""
        mod = importlib.import_module(module_path)
        src = inspect.getsource(mod)
        # Find lines containing sqlite3.connect(
        connect_lines = [
            line.strip()
            for line in src.split("\n")
            if "sqlite3.connect(" in line and "def " not in line
        ]
        assert connect_lines, f"No sqlite3.connect calls found in {module_path}"
        for line in connect_lines:
            assert f"timeout={expected_timeout}" in line, \
                f"{module_path}: {line} should have timeout={expected_timeout}"

    def test_fp_feedback_all_connections_have_timeout(self):
        """fp_feedback.py must have timeout=30 on ALL sqlite3.connect calls."""
        mod = importlib.import_module("src.fp_engine.learning.fp_feedback")
        src = inspect.getsource(mod)
        connect_lines = [
            line.strip()
            for line in src.split("\n")
            if "sqlite3.connect(" in line and "def " not in line
        ]
        assert len(connect_lines) >= 6, f"Expected 6+ connect lines, found {len(connect_lines)}"
        for line in connect_lines:
            assert "timeout=30" in line, \
                f"fp_feedback.py: {line} missing timeout=30"


# ──────────────────────────────────────────────────────────────
# 6. WorkflowState nullable type hints
# ──────────────────────────────────────────────────────────────


class TestWorkflowStateTypes:
    """Verify WorkflowState component fields are properly nullable."""

    def test_injected_components_nullable(self):
        """Injected component fields must be typed as nullable."""
        from src.workflow.orchestrator import WorkflowState
        nullable_fields = [
            "tool_executor", "brain_engine", "fp_detector", "intelligence_engine"
        ]
        for field_name in nullable_fields:
            assert field_name in WorkflowState.model_fields, \
                f"WorkflowState missing field: {field_name}"
            field_info = WorkflowState.model_fields[field_name]
            assert field_info.default is None, \
                f"{field_name} default should be None"

    def test_state_construction_without_components(self):
        """WorkflowState must construct cleanly without injected components."""
        from src.workflow.orchestrator import WorkflowState
        state = WorkflowState(target="example.com")
        assert state.tool_executor is None
        assert state.brain_engine is None
        assert state.fp_detector is None
        assert state.intelligence_engine is None

    def test_nullable_type_declaration_in_source(self):
        """Source code must use 'Any | None' not bare 'Any' for nullable fields."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.orchestrator")
        )
        # Find lines with injected component declarations
        for field in ["tool_executor", "brain_engine", "fp_detector", "intelligence_engine"]:
            pattern = rf'{field}:\s*Any\s*\|\s*None\s*='
            assert re.search(pattern, src), \
                f"{field} must be typed as 'Any | None = None'"


# ──────────────────────────────────────────────────────────────
# 7. FP Layer 2c — auth_headers injection
# ──────────────────────────────────────────────────────────────


class TestLayer2cAuthHeaders:
    """Verify Layer 2c passes auth_headers into HttpContext.request_headers."""

    def test_auth_headers_source_wiring(self):
        """Layer 2c must reference self._auth_headers for request_headers."""
        src = inspect.getsource(
            importlib.import_module("src.fp_engine.fp_detector")
        )
        # The Layer 2c block should build request_headers from _auth_headers
        assert "_auth_headers" in src
        assert "request_headers=_cv_req_headers" in src

    def test_auth_headers_not_hardcoded_empty(self):
        """Layer 2c must NOT hardcode request_headers={}."""
        src = inspect.getsource(
            importlib.import_module("src.fp_engine.fp_detector")
        )
        # Find the Layer 2c section (between markers)
        l2c_start = src.find("Layer 2c")
        l2c_end = src.find("Katman 3", l2c_start) if l2c_start != -1 else -1
        if l2c_start != -1 and l2c_end != -1:
            l2c_section = src[l2c_start:l2c_end]
            assert "request_headers={}" not in l2c_section, \
                "Layer 2c should not hardcode empty request_headers"


# ──────────────────────────────────────────────────────────────
# 8. main.py hardcoded defaults documentation
# ──────────────────────────────────────────────────────────────


class TestMainDefaults:
    """Verify main.py _build_model_config defaults are documented."""

    def test_defaults_comment_present(self):
        """Hardcoded defaults section must have clarifying comment."""
        src = inspect.getsource(
            importlib.import_module("src.main")
        )
        assert "Hardcoded defaults" in src or "hardcoded defaults" in src.lower()

    def test_build_model_config_exists(self):
        """_build_model_config helper must exist in main module."""
        src = inspect.getsource(
            importlib.import_module("src.main")
        )
        assert "_build_model_config" in src


# ──────────────────────────────────────────────────────────────
# 9. Finding.evidence type documentation
# ──────────────────────────────────────────────────────────────


class TestEvidenceTypeDocumentation:
    """Verify Finding.evidence type difference is documented."""

    def test_finding_evidence_is_str(self):
        """Finding.evidence must be str type."""
        from src.tools.base import Finding
        field = Finding.model_fields["evidence"]
        assert field.annotation is str or "str" in str(field.annotation)

    def test_report_finding_evidence_is_list(self):
        """ReportFinding.evidence must be list[str] type."""
        from src.reporting.report_generator import ReportFinding
        field = ReportFinding.model_fields["evidence"]
        # annotation is list[str]
        assert "list" in str(field.annotation).lower()

    def test_evidence_type_comment_in_source(self):
        """Finding model source must document the str vs list[str] difference."""
        src = inspect.getsource(
            importlib.import_module("src.tools.base")
        )
        assert "ReportFinding" in src, \
            "Finding model should reference ReportFinding for type clarity"
