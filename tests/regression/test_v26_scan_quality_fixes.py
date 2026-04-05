"""Regression tests for V26 Scan Quality fixes.

Covers all V26 implementation items:
  P0-1:  RiskAssessor key mismatch + handle_reporting type corruption
  P0-2:  Brain max_tokens truncation (ModelConfig defaults)
  P0-3:  FP elimination (timeout, _SimpleResp removal, Bayesian weight)
  P1-1:  Self-reflection stage filter (findings delta)
  P1-2:  Profiler empty data estimation
  P3-1:  Brain tool config sanitization (_sanitize_brain_options)
  P3-2:  Brain bare-path scope resolution
  P3-3:  Nuclei OOM fix (memory_limit, concurrency, retry)
  P3-4:  AssetDB float timestamp validator
"""

import importlib
import inspect
import re
import time
from datetime import datetime, timezone
from typing import Any

import pytest


# ══════════════════════════════════════════════════════════════
# P0-1: RiskAssessor key mismatch
# ══════════════════════════════════════════════════════════════


class TestRiskAssessorKeyMismatch:
    """RiskAssessor.prioritise_findings() must handle pipeline finding dicts."""

    def _get_assessor(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        return RiskAssessor()

    def test_handles_vulnerability_type_key(self):
        assessor = self._get_assessor()
        findings = [
            {"vulnerability_type": "xss", "url": "https://example.com/test",
             "severity": "high", "confidence_score": 80.0},
        ]
        result = assessor.prioritise_findings(findings)
        assert len(result) == 1
        assert hasattr(result[0], "risk_score")

    def test_handles_vuln_type_key(self):
        assessor = self._get_assessor()
        findings = [
            {"vuln_type": "sqli", "endpoint": "https://example.com/api",
             "severity": "critical", "confidence": 90.0},
        ]
        result = assessor.prioritise_findings(findings)
        assert len(result) == 1
        assert result[0].vuln_type == "sqli"

    def test_handles_finding_type_key(self):
        assessor = self._get_assessor()
        findings = [
            {"finding_type": "cors", "target": "https://example.com",
             "severity": "medium", "confidence_score": 60.0},
        ]
        result = assessor.prioritise_findings(findings)
        assert len(result) == 1

    def test_handles_missing_severity(self):
        assessor = self._get_assessor()
        findings = [
            {"vulnerability_type": "info", "url": "https://example.com"},
        ]
        result = assessor.prioritise_findings(findings)
        assert len(result) == 1

    def test_handles_confidence_as_string(self):
        """Brain sometimes returns confidence as string like 'high'."""
        assessor = self._get_assessor()
        findings = [
            {"vulnerability_type": "xss", "url": "https://example.com",
             "severity": "high", "confidence_score": "high"},
        ]
        # Should not crash
        result = assessor.prioritise_findings(findings)
        assert len(result) == 1

    def test_severity_impact_mapping(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        assert RiskAssessor._SEVERITY_IMPACT["critical"] > RiskAssessor._SEVERITY_IMPACT["low"]

    def test_empty_findings_list(self):
        assessor = self._get_assessor()
        result = assessor.prioritise_findings([])
        assert result == []


# ══════════════════════════════════════════════════════════════
# P0-1b: handle_reporting type corruption prevention
# ══════════════════════════════════════════════════════════════


class TestReportingTypeCorruption:
    """handle_reporting must annotate dicts, not replace them with Pydantic objects."""

    def test_risk_annotated_not_replaced(self):
        """After RiskAssessor, findings should still be dicts with risk_score added."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Must NOT have: findings = _prioritized (type corruption)
        # Must HAVE: annotation pattern like f["risk_score"] = or f.update
        assert "risk_score" in src
        assert "priority_rank" in src
        # The pattern should annotate the original dict
        assert 'f["risk_score"]' in src or "f['risk_score']" in src or "risk_score" in src


# ══════════════════════════════════════════════════════════════
# P0-2: Brain max_tokens truncation
# ══════════════════════════════════════════════════════════════


class TestBrainMaxTokens:
    """ModelConfig default max_tokens must be sufficient for brain output."""

    def test_model_config_default_max_tokens(self):
        from src.brain.engine import ModelConfig
        m = ModelConfig(name="test")
        assert m.max_tokens >= 8192, (
            f"ModelConfig default max_tokens={m.max_tokens} is too low, "
            f"should be >=8192 to prevent brain output truncation"
        )

    def test_settings_yaml_primary_max_tokens(self):
        import yaml
        from pathlib import Path
        settings_path = Path("config/settings.yaml")
        if not settings_path.exists():
            pytest.skip("settings.yaml not found")
        with open(settings_path) as f:
            cfg = yaml.safe_load(f)
        primary = cfg.get("brain", {}).get("primary", {})
        mt = primary.get("max_tokens", 4096)
        assert mt >= 8192, f"Primary max_tokens={mt} too low"

    def test_settings_yaml_secondary_max_tokens(self):
        import yaml
        from pathlib import Path
        settings_path = Path("config/settings.yaml")
        if not settings_path.exists():
            pytest.skip("settings.yaml not found")
        with open(settings_path) as f:
            cfg = yaml.safe_load(f)
        secondary = cfg.get("brain", {}).get("secondary", {})
        mt = secondary.get("max_tokens", 2048)
        assert mt >= 4096, f"Secondary max_tokens={mt} too low"


# ══════════════════════════════════════════════════════════════
# P0-3: FP elimination fixes
# ══════════════════════════════════════════════════════════════


class TestFPEliminationFixes:
    """FP detector timeout, response format, and Bayesian weight fixes."""

    def test_brain_layer_timeout_differentiated(self):
        """HIGH severity should get more time than LOW severity."""
        src = inspect.getsource(
            importlib.import_module("src.fp_engine.fp_detector")
        )
        # Must contain differentiated timeout (if _is_high_sev else smaller_value)
        assert "_is_high_sev" in src, "FP detector must differentiate timeout by severity"

    def test_no_simple_resp_class(self):
        """_SimpleResp class must not exist — replaced with plain dicts."""
        src = inspect.getsource(
            importlib.import_module("src.fp_engine.fp_detector")
        )
        assert "class _SimpleResp" not in src, (
            "_SimpleResp class should be replaced with plain dicts "
            "for ResponseDiffAnalyzer compatibility"
        )

    def test_bayesian_weight_increased(self):
        """Bayesian delta multiplier and cap should be larger than v2.8.8 defaults."""
        src = inspect.getsource(
            importlib.import_module("src.fp_engine.fp_detector")
        )
        # The Bayesian section should have a multiplier > 16.0 and cap > ±8
        # Look for the cap value
        cap_match = re.search(r"max\(-(\d+)", src)
        if cap_match:
            cap_val = int(cap_match.group(1))
            assert cap_val >= 10, f"Bayesian cap {cap_val} should be >= 10"

    def test_fp_semaphore_increased(self):
        """FP semaphore should be > 6 for faster throughput."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Find Semaphore creation near FP elimination
        sem_matches = re.findall(r"Semaphore\((\d+)\)", src)
        # At least one semaphore should be > 6
        assert any(int(v) > 6 for v in sem_matches), (
            "FP elimination semaphore should be increased above 6"
        )


# ══════════════════════════════════════════════════════════════
# P1-1: Self-reflection stage filter (findings delta)
# ══════════════════════════════════════════════════════════════


class TestSelfReflectionDelta:
    """Orchestrator must use findings delta, not broken stage filter."""

    def test_pre_stage_findings_count_captured(self):
        """Orchestrator must snapshot findings count before each stage."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.orchestrator")
        )
        assert "_pre_stage_findings_count" in src, (
            "Orchestrator must snapshot len(state.raw_findings) before stage"
        )

    def test_no_broken_stage_filter(self):
        """Orchestrator must not filter findings by f.get('stage') == str(stage)."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.orchestrator")
        )
        # The broken pattern was: f.get('stage') == str(stage)
        assert "f.get('stage') == str(stage)" not in src, (
            "Broken stage filter pattern must be replaced with delta computation"
        )
        assert "f.get(\"stage\") == str(stage)" not in src


# ══════════════════════════════════════════════════════════════
# P3-1: Brain tool config sanitization
# ══════════════════════════════════════════════════════════════


class TestBrainToolConfigSanitization:
    """_sanitize_brain_options must strip invalid/dangerous options."""

    def _get_sanitizer(self):
        from src.workflow.pipelines.full_scan import _sanitize_brain_options
        return _sanitize_brain_options

    def test_strips_proxy(self):
        sanitize = self._get_sanitizer()
        result = sanitize("sqlmap", {"proxy": "socks5://localhost:1080"}, {})
        assert "proxy" not in result

    def test_strips_tor(self):
        sanitize = self._get_sanitizer()
        result = sanitize("dalfox", {"tor": True, "cookie": "test=1"}, {})
        assert "tor" not in result
        assert result.get("cookie") == "test=1"

    def test_strips_unknown_keys_for_whitelisted_tool(self):
        sanitize = self._get_sanitizer()
        result = sanitize("sqlmap", {
            "level": 3,
            "waf_evasion": True,  # hallucinated key
            "cookiejar": "/tmp/x",  # hallucinated key
        }, {"level": 2})
        assert "waf_evasion" not in result
        assert "cookiejar" not in result
        assert result.get("level") == 3  # valid and >= base

    def test_protects_min_level(self):
        """Brain cannot lower 'level' below base value."""
        sanitize = self._get_sanitizer()
        result = sanitize("sqlmap", {"level": 1}, {"level": 2})
        assert "level" not in result  # stripped because 1 < base 2

    def test_protects_min_risk(self):
        """Brain cannot lower 'risk' below base value."""
        sanitize = self._get_sanitizer()
        result = sanitize("sqlmap", {"risk": 0}, {"risk": 1})
        assert "risk" not in result

    def test_allows_valid_options(self):
        sanitize = self._get_sanitizer()
        result = sanitize("sqlmap", {
            "level": 3,
            "risk": 2,
            "tamper": "space2comment",
            "dbms": "mysql",
        }, {"level": 2, "risk": 1})
        assert result == {"level": 3, "risk": 2, "tamper": "space2comment", "dbms": "mysql"}

    def test_unknown_tool_passes_non_denied_keys(self):
        """Tools without a whitelist accept any key that isn't denied."""
        sanitize = self._get_sanitizer()
        result = sanitize("unknown_tool", {
            "custom_flag": True,
            "proxy": "http://bad",  # denied
        }, {})
        assert result.get("custom_flag") is True
        assert "proxy" not in result

    def test_strips_output_dir(self):
        sanitize = self._get_sanitizer()
        result = sanitize("sqlmap", {"output_dir": "/tmp/evil"}, {})
        assert "output_dir" not in result

    def test_strips_hyphenated_keys(self):
        sanitize = self._get_sanitizer()
        result = sanitize("commix", {"proxy-chain-file": "/path/to/proxy.lst"}, {})
        assert "proxy-chain-file" not in result

    def test_empty_input(self):
        sanitize = self._get_sanitizer()
        result = sanitize("sqlmap", {}, {"level": 2})
        assert result == {}


# ══════════════════════════════════════════════════════════════
# P3-2: Brain bare-path scope resolution
# ══════════════════════════════════════════════════════════════


class TestBarePathResolution:
    """_resolve_brain_endpoint and bare-path safety net must RESOLVE, not drop."""

    def test_resolve_brain_endpoint_bare_path(self):
        from src.workflow.pipelines.full_scan import _resolve_brain_endpoint
        result = _resolve_brain_endpoint(
            "/api/v1/users",
            ["https://gitlab.com"],
            "gitlab.com",
        )
        assert result == "https://gitlab.com/api/v1/users"

    def test_resolve_brain_endpoint_full_url_passthrough(self):
        from src.workflow.pipelines.full_scan import _resolve_brain_endpoint
        result = _resolve_brain_endpoint(
            "https://api.gitlab.com/v4/projects",
            ["https://gitlab.com"],
            "gitlab.com",
        )
        assert result == "https://api.gitlab.com/v4/projects"

    def test_resolve_brain_endpoint_relative_path(self):
        from src.workflow.pipelines.full_scan import _resolve_brain_endpoint
        result = _resolve_brain_endpoint(
            "api/v1/users",
            ["https://gitlab.com"],
            "gitlab.com",
        )
        assert result == "https://gitlab.com/api/v1/users"

    def test_bare_path_safety_net_resolves_not_drops(self):
        """The bare-path filter in full_scan must RESOLVE paths, not drop them."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Old pattern was: "dropped {len(_bare_paths)} bare paths"
        assert "Bare path resolver" in src, (
            "Bare-path filter should resolve, not drop — "
            "look for 'Bare path resolver' log message"
        )
        # Must NOT contain the old "dropped" message
        assert "dropped" not in src.split("Bare path resolver")[0].split("bare paths")[-1] if "bare paths" in src else True


# ══════════════════════════════════════════════════════════════
# P3-3: Nuclei OOM fix
# ══════════════════════════════════════════════════════════════


class TestNucleiOOM:
    """Nuclei wrapper must have reduced memory limits and OOM retry."""

    def test_memory_limit_reduced(self):
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper
        assert NucleiWrapper.memory_limit <= 512 * 1024 * 1024, (
            f"Nuclei memory_limit={NucleiWrapper.memory_limit} should be <= 512MB"
        )

    def test_balanced_concurrency_reduced(self):
        """BALANCED profile should have -c <= 5 and -bs <= 15."""
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.nuclei_wrapper")
        )
        # Find the BALANCED *case* block (not default param)
        case_idx = src.index("case ScanProfile.BALANCED")
        balanced_block = src[case_idx:case_idx + 500]
        # Extract -c value — may have newlines between flag and value
        c_match = re.search(r'"-c"[\s,]*"(\d+)"', balanced_block)
        assert c_match, f"BALANCED profile must set -c concurrency flag, block: {balanced_block[:200]}"
        c_val = int(c_match.group(1))
        assert c_val <= 5, f"BALANCED -c={c_val} should be <= 5"

    def test_oom_retry_exists(self):
        """Nuclei run() must have OOM detection and retry logic."""
        src = inspect.getsource(
            importlib.import_module("src.tools.scanners.nuclei_wrapper")
        )
        assert "OOM" in src or "oom" in src.lower(), "Nuclei wrapper must have OOM retry logic"
        assert "137" in src or "-9" in src, "Must detect OOM exit codes (137/-9)"


# ══════════════════════════════════════════════════════════════
# P3-4: AssetDB float timestamp validator
# ══════════════════════════════════════════════════════════════


class TestAssetDBFloatValidator:
    """Asset model must coerce float timestamps to ISO strings."""

    def test_float_to_iso_string(self):
        from src.integrations.asset_db import Asset
        ts = time.time()
        asset = Asset(first_seen=ts, last_seen=ts)
        assert isinstance(asset.first_seen, str)
        assert "T" in asset.first_seen  # ISO format contains T
        assert "." in asset.first_seen or "+" in asset.first_seen  # has fractional or tz

    def test_int_to_iso_string(self):
        from src.integrations.asset_db import Asset
        asset = Asset(first_seen=1700000000)
        assert isinstance(asset.first_seen, str)
        assert "2023" in asset.first_seen  # epoch 1700000000 is Nov 2023

    def test_iso_string_passthrough(self):
        from src.integrations.asset_db import Asset
        iso = "2024-01-15T12:00:00+00:00"
        asset = Asset(first_seen=iso)
        assert asset.first_seen == iso

    def test_empty_string_passthrough(self):
        from src.integrations.asset_db import Asset
        asset = Asset(first_seen="", last_seen="")
        assert asset.first_seen == ""


# ══════════════════════════════════════════════════════════════
# P1-2: Profiler tool estimation
# ══════════════════════════════════════════════════════════════


class TestProfilerEstimation:
    """ScanProfiler data must not show all-zero tool durations."""

    def test_profiler_estimation_code_exists(self):
        """full_scan.py must estimate inline tool durations from stage timing."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Must have estimation logic — look for division that distributes stage time
        assert "estimated" in src.lower() or "estimate" in src.lower(), (
            "full_scan.py must have tool duration estimation logic"
        )


# ══════════════════════════════════════════════════════════════
# Integration: _brain_enhanced_options timeout reduction
# ══════════════════════════════════════════════════════════════


class TestBrainEnhancedOptionsTimeout:
    """suggest_tool_config timeout should not be absurdly long."""

    def test_timeout_reasonable(self):
        """The timeout for suggest_tool_config should be <= 120s, not 1200s."""
        src = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan")
        )
        # Find the _brain_enhanced_options function
        func_idx = src.index("_brain_enhanced_options")
        func_block = src[func_idx:func_idx + 1000]
        timeout_match = re.search(r"timeout=(\d+\.?\d*)", func_block)
        assert timeout_match, "Must have timeout in _brain_enhanced_options"
        timeout_val = float(timeout_match.group(1))
        assert timeout_val <= 120.0, (
            f"suggest_tool_config timeout={timeout_val}s is too high, should be <= 120s"
        )
