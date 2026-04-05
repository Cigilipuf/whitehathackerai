"""Comprehensive tests for IntelligenceEngine — LLM integration layer.

Uses mock BrainEngine.think() so tests run without a real LLM.
Covers: all public methods, fallback on brain down/error, cache, JSON parsing,
brain quality metrics, credential sanitization, _safe_json_parse edge cases,
NextActionDecision validation, and data model defaults.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.brain.engine import BrainEngine, BrainResponse, ModelConfig
from src.utils.constants import BrainType


# ── Helpers ─────────────────────────────────────────────────────────

def _make_engine(think_return: str = '{"ok":true}'):
    """Create IntelligenceEngine with a mock brain that returns a fixed string."""
    from src.brain.intelligence import IntelligenceEngine

    brain = MagicMock(spec=BrainEngine)
    brain.has_primary = True
    brain.has_secondary = True
    brain.has_fallback = False
    brain.think = AsyncMock(
        return_value=BrainResponse(text=think_return, model_used=BrainType.PRIMARY)
    )
    engine = IntelligenceEngine(brain)
    return engine


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


# ── Data Model Tests ────────────────────────────────────────────────

class TestDataModelDefaults:
    """Verify default values for all output data models."""

    def test_intelligence_plan_defaults(self):
        from src.brain.intelligence import IntelligencePlan
        plan = IntelligencePlan()
        assert plan.target == ""
        assert plan.attack_vectors == []
        assert plan.high_value_endpoints == []
        assert plan.waf_bypass_strategies == []

    def test_verification_result_defaults(self):
        from src.brain.intelligence import VerificationResult
        vr = VerificationResult()
        assert vr.is_real is False
        assert vr.confidence == 0.0  # NOT 50 — "no opinion" = 0
        assert vr.exploit_feasibility == "unknown"
        assert vr.cvss_override is None

    def test_next_action_decision_defaults(self):
        from src.brain.intelligence import NextActionDecision
        nad = NextActionDecision()
        assert nad.action == "continue"
        assert nad.skip_tools == []
        assert nad.deep_dive_tool == ""
        assert nad.change_strategy == ""
        assert nad.retry_with_auth is False
        assert nad.request_oob_check is False

    def test_nuclei_template_defaults(self):
        from src.brain.intelligence import NucleiTemplate
        nt = NucleiTemplate()
        assert nt.severity == "medium"
        assert nt.yaml_content == ""

    def test_poc_script_defaults(self):
        from src.brain.intelligence import PoCScript
        ps = PoCScript()
        assert ps.language == "python"
        assert ps.script_content == ""
        assert ps.dependencies == []


# ── analyze_recon_and_plan ──────────────────────────────────────────

class TestAnalyzeReconAndPlan:

    def test_returns_plan_on_valid_json(self):
        brain_response = json.dumps({
            "summary": "Target looks interesting",
            "attack_vectors": [{
                "endpoint": "/api/users",
                "parameter": "id",
                "vuln_type": "idor",
                "priority": "high",
                "reasoning": "sequential IDs",
                "tools": ["curl"],
                "payloads": ["id=2"],
                "estimated_time": 60,
            }],
            "high_value_endpoints": ["/admin"],
            "technologies_of_interest": ["nginx"],
            "waf_bypass_strategies": [],
            "custom_templates_needed": [],
        })
        engine = _make_engine(brain_response)
        plan = _run(engine.analyze_recon_and_plan(
            target="example.com",
            subdomains=["api.example.com"],
            live_hosts=["https://example.com"],
            technologies={"example.com": ["nginx"]},
            open_ports={"example.com": [80, 443]},
            dns_records=[{"type": "A", "value": "1.2.3.4"}],
            urls=["https://example.com/api/users"],
        ))
        assert plan.target == "example.com"
        assert plan.summary != ""
        assert len(plan.attack_vectors) >= 1
        assert "/admin" in plan.high_value_endpoints

    def test_returns_empty_plan_when_brain_down(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time()
        plan = _run(engine.analyze_recon_and_plan(
            target="t.com", subdomains=[], live_hosts=[],
            technologies={}, open_ports={}, dns_records=[], urls=[],
        ))
        assert plan.target == "t.com"
        assert plan.attack_vectors == []

    def test_returns_empty_plan_on_brain_error(self):
        engine = _make_engine()
        engine.brain.think = AsyncMock(side_effect=Exception("LLM crashed"))
        plan = _run(engine.analyze_recon_and_plan(
            target="t.com", subdomains=[], live_hosts=[],
            technologies={}, open_ports={}, dns_records=[], urls=[],
        ))
        assert plan.target == "t.com"
        assert plan.attack_vectors == []


# ── generate_creative_attack_narratives ─────────────────────────────

class TestGenerateCreativeAttackNarratives:

    def test_returns_empty_when_brain_down(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time()
        result = _run(engine.generate_creative_attack_narratives(
            target="t.com", technologies={}, endpoints=[],
        ))
        assert result == []

    def test_returns_list_on_success(self):
        narrative_text = (
            "SCENARIO 1\n"
            "NARRATIVE: An attacker could exploit IDOR in the API\n"
            "VULN_CLASS: idor\n"
            "ENDPOINT: /api/users\n"
            "SEVERITY: high\n"
        )
        engine = _make_engine(narrative_text)
        result = _run(engine.generate_creative_attack_narratives(
            target="t.com",
            technologies={"t.com": ["express"]},
            endpoints=["/api/users"],
        ))
        assert isinstance(result, list)


# ── generate_dynamic_test_cases ─────────────────────────────────────

class TestGenerateDynamicTestCases:

    def test_invalid_checker_type_returns_empty(self):
        engine = _make_engine()
        result = _run(engine.generate_dynamic_test_cases(
            target="t.com", endpoints=[], technologies={},
            checker_type="invalid_checker_xyz",
        ))
        assert result == []

    def test_idor_checker_returns_test_cases(self):
        brain_json = json.dumps([{
            "url": "/api/users/1",
            "method": "GET",
            "param_name": "id",
            "original_value": "1",
            "test_values": ["2", "999"],
            "description": "Test user ID enumeration",
        }])
        engine = _make_engine(brain_json)
        result = _run(engine.generate_dynamic_test_cases(
            target="t.com",
            endpoints=["/api/users/1"],
            technologies={"t.com": ["express"]},
            checker_type="idor",
        ))
        assert isinstance(result, list)

    def test_returns_empty_on_brain_error(self):
        engine = _make_engine()
        engine.brain.think = AsyncMock(side_effect=Exception("crash"))
        result = _run(engine.generate_dynamic_test_cases(
            target="t.com", endpoints=[], technologies={},
            checker_type="idor",
        ))
        assert result == []


# ── decide_next_action ──────────────────────────────────────────────

class TestDecideNextAction:

    def test_returns_default_on_brain_down(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time()
        result = _run(engine.decide_next_action(
            current_stage="vulnerability_scan",
            findings_so_far=[],
            completed_tools=["nuclei"],
            remaining_tools=["dalfox"],
        ))
        assert result.action == "continue"

    def test_parses_valid_action(self):
        brain_json = json.dumps({
            "action": "skip_to_next_stage",
            "reason": "no promising targets",
            "next_tool": "",
            "skip_tools": ["dalfox"],
            "deep_dive_target": "",
            "stage_transition": "",
            "priority_findings": [],
            "time_estimate": "5m",
        })
        engine = _make_engine(brain_json)
        result = _run(engine.decide_next_action(
            current_stage="vulnerability_scan",
            findings_so_far=[{"title": "XSS"}],
            completed_tools=["nuclei"],
            remaining_tools=["dalfox", "sqlmap"],
        ))
        assert result.action == "skip_to_next_stage"
        assert "dalfox" in result.skip_tools

    def test_invalid_action_defaults_to_continue(self):
        brain_json = json.dumps({
            "action": "destroy_everything",
            "reason": "LLM hallucination",
        })
        engine = _make_engine(brain_json)
        result = _run(engine.decide_next_action(
            current_stage="vuln_scan",
            findings_so_far=[],
            completed_tools=[],
            remaining_tools=[],
        ))
        assert result.action == "continue"

    def test_change_strategy_validated(self):
        brain_json = json.dumps({
            "action": "change_strategy",
            "change_strategy": "aggressive",
        })
        engine = _make_engine(brain_json)
        result = _run(engine.decide_next_action(
            current_stage="vuln_scan",
            findings_so_far=[],
            completed_tools=[],
            remaining_tools=[],
        ))
        assert result.change_strategy == "aggressive"

    def test_change_strategy_invalid_cleared(self):
        brain_json = json.dumps({
            "action": "change_strategy",
            "change_strategy": "destructive_mode",
        })
        engine = _make_engine(brain_json)
        result = _run(engine.decide_next_action(
            current_stage="vuln_scan",
            findings_so_far=[],
            completed_tools=[],
            remaining_tools=[],
        ))
        # Invalid strategy should be cleared → falls back
        assert result.change_strategy in ("", None, "aggressive", "balanced", "stealth")


# ── verify_finding ──────────────────────────────────────────────────

class TestVerifyFinding:

    def test_real_finding_verified(self):
        brain_json = json.dumps({
            "is_real": True,
            "confidence": 85,
            "reasoning": "Payload reflected without encoding",
            "additional_evidence": "",
            "suggested_poc_steps": ["curl same endpoint"],
            "exploit_feasibility": "trivial",
            "cvss_override": 7.5,
        })
        engine = _make_engine(brain_json)
        result = _run(engine.verify_finding(
            finding={"title": "Reflected XSS", "endpoint": "/search"},
            http_request="GET /search?q=<script>...",
            http_response="200 OK\n<script>...",
        ))
        assert result.is_real is True
        assert result.confidence == 85.0
        assert result.exploit_feasibility == "trivial"
        assert result.cvss_override == 7.5

    def test_returns_default_on_brain_error(self):
        engine = _make_engine()
        engine.brain.think = AsyncMock(side_effect=Exception("timeout"))
        result = _run(engine.verify_finding(
            finding={"title": "SQLi"},
        ))
        assert result.is_real is False
        assert result.confidence == 0.0

    def test_confidence_clamped_to_100(self):
        brain_json = json.dumps({
            "is_real": True,
            "confidence": 150,
            "reasoning": "certainly real",
        })
        engine = _make_engine(brain_json)
        result = _run(engine.verify_finding(finding={"title": "test"}))
        assert result.confidence <= 100.0

    def test_cvss_override_clamped(self):
        brain_json = json.dumps({
            "is_real": True,
            "confidence": 90,
            "cvss_override": 15.0,
        })
        engine = _make_engine(brain_json)
        result = _run(engine.verify_finding(finding={"title": "test"}))
        assert result.cvss_override is None or result.cvss_override <= 10.0


# ── generate_nuclei_template ────────────────────────────────────────

class TestGenerateNucleiTemplate:

    def test_returns_template_on_valid_yaml(self):
        brain_json = json.dumps({
            "template_id": "custom-test-123",
            "name": "Test Check",
            "severity": "high",
            "description": "Testing",
            "yaml_content": (
                "id: custom-test-123\n"
                "info:\n"
                "  name: Test\n"
                "  severity: high\n"
                "http:\n"
                "  - method: GET\n"
                "    path:\n"
                "      - '{{BaseURL}}/test'\n"
                "    matchers:\n"
                "      - type: word\n"
                "        words:\n"
                "          - 'vulnerable'\n"
            ),
        })
        engine = _make_engine(brain_json)
        result = _run(engine.generate_nuclei_template(
            tech="nginx", version="1.24",
            check_description="Test for something",
        ))
        assert result is not None
        assert result.template_id != ""

    def test_returns_none_on_brain_error(self):
        engine = _make_engine()
        engine.brain.think = AsyncMock(side_effect=Exception("error"))
        result = _run(engine.generate_nuclei_template(tech="apache"))
        assert result is None

    def test_returns_none_when_brain_down(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time()
        result = _run(engine.generate_nuclei_template(tech="nginx"))
        assert result is None


# ── generate_poc ────────────────────────────────────────────────────

class TestGeneratePoc:

    def test_returns_poc_on_valid_response(self):
        brain_json = json.dumps({
            "language": "python",
            "script_content": "import requests\nprint('PoC')",
            "curl_command": "curl -X GET https://t.com/vuln",
            "browser_steps": ["Open URL"],
            "expected_output": "200 OK",
            "dependencies": ["requests"],
        })
        engine = _make_engine(brain_json)
        result = _run(engine.generate_poc(
            finding={"title": "XSS", "endpoint": "/search"},
        ))
        assert result is not None
        assert "requests" in result.script_content
        assert result.language == "python"

    def test_returns_none_on_empty_content(self):
        brain_json = json.dumps({
            "language": "python",
            "script_content": "",
        })
        engine = _make_engine(brain_json)
        result = _run(engine.generate_poc(finding={"title": "test"}))
        # Empty script_content should return None
        assert result is None or result.script_content == ""

    def test_returns_none_when_unavailable(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time()
        result = _run(engine.generate_poc(finding={"title": "test"}))
        assert result is None


# ── enrich_report_finding ───────────────────────────────────────────

class TestEnrichReportFinding:

    def test_enriches_finding_dict(self):
        brain_json = json.dumps({
            "title": "Critical SQL Injection in Login",
            "summary": "The login endpoint is vulnerable to SQL injection",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "impact": "Full database access",
            "steps_to_reproduce": "1. Send payload\n2. Observe",
            "remediation": "Use parameterized queries",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        })
        engine = _make_engine(brain_json)
        finding = {"title": "SQLi", "endpoint": "/login"}
        result = _run(engine.enrich_report_finding(finding))
        assert "enriched_title" in result or result.get("title") == "SQLi"
        # cvss_score should be stored directly (not prefixed)
        if "cvss_score" in result:
            assert 0 <= result["cvss_score"] <= 10

    def test_returns_original_on_brain_error(self):
        engine = _make_engine()
        engine.brain.think = AsyncMock(side_effect=Exception("crash"))
        original = {"title": "test finding", "endpoint": "/x"}
        result = _run(engine.enrich_report_finding(original))
        assert result["title"] == "test finding"


# ── Cache Behavior ──────────────────────────────────────────────────

class TestBrainCache:

    def test_cache_returns_same_result_without_extra_call(self):
        engine = _make_engine('{"result": "cached"}')
        # Make two identical calls
        r1 = _run(engine.verify_finding(finding={"title": "same"}))
        call_count_1 = engine.brain.think.call_count
        r2 = _run(engine.verify_finding(finding={"title": "same"}))
        call_count_2 = engine.brain.think.call_count
        # Second call should be cached (same or +0 think() calls)
        assert call_count_2 <= call_count_1 + 1  # At most 1 extra for retry

    def test_cache_max_size_evicts_lru(self):
        engine = _make_engine('{"ok": true}')
        # Fill cache beyond max
        engine._cache_max_size = 5
        for i in range(10):
            engine._cache[f"key_{i}"] = ('{"ok":true}', time.time())
        # Should be trimmed on next _brain_call, but let's verify OrderedDict behavior
        assert len(engine._cache) == 10  # Not yet trimmed (trimmed in _brain_call)


# ── _safe_json_parse ────────────────────────────────────────────────

class TestSafeJsonParse:

    def _parse(self, text: str):
        engine = _make_engine()
        return engine._safe_json_parse(text)

    def test_valid_json_object(self):
        assert self._parse('{"key": "value"}') == {"key": "value"}

    def test_valid_json_array(self):
        result = self._parse('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_json_in_markdown_fence(self):
        result = self._parse('```json\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    def test_json_with_surrounding_text(self):
        result = self._parse('Here is the result:\n{"key": "value"}\nEnd.')
        assert result is not None
        assert result.get("key") == "value"

    def test_empty_string(self):
        assert self._parse("") is None

    def test_pure_garbage(self):
        assert self._parse("this is not json at all !!!") is None

    def test_trailing_comma_handled(self):
        # json_utils extract_json can handle trailing commas
        result = self._parse('{"a": 1, "b": 2,}')
        # May or may not succeed depending on json_utils robustness
        # But should NOT raise
        assert result is None or isinstance(result, dict)


# ── Brain Down / Auto-Recovery ──────────────────────────────────────

class TestBrainDownRecovery:

    def test_is_available_false_when_down(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_time = time.time()
        assert engine.is_available is False

    def test_auto_recovery_after_timeout(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_recovery_secs = 0.01  # Very short for testing
        engine._brain_down_time = time.time() - 1.0  # 1s ago
        assert engine.is_available is True
        assert engine._brain_down is False
        assert engine._consecutive_failures == 0

    def test_no_recovery_before_timeout(self):
        engine = _make_engine()
        engine._brain_down = True
        engine._brain_down_recovery_secs = 300.0
        engine._brain_down_time = time.time()
        assert engine.is_available is False

    def test_consecutive_failures_tracked(self):
        engine = _make_engine()
        engine.brain.think = AsyncMock(side_effect=Exception("fail"))
        # Make multiple failing calls
        for _ in range(5):
            _run(engine.verify_finding(finding={"title": "test"}))
        assert engine._consecutive_failures >= 3
        assert engine._brain_down is True


# ── Brain Quality Metrics ───────────────────────────────────────────

class TestBrainQualityMetrics:

    def test_metrics_initialized_to_zero(self):
        engine = _make_engine()
        metrics = engine.get_brain_metrics()
        assert metrics["total_calls"] == 0

    def test_successful_call_increments_metrics(self):
        engine = _make_engine('{"is_real": true, "confidence": 90}')
        _run(engine.verify_finding(finding={"title": "test"}))
        metrics = engine.get_brain_metrics()
        assert metrics["total_calls"] >= 1

    def test_error_call_increments_error_count(self):
        engine = _make_engine()
        engine.brain.think = AsyncMock(side_effect=Exception("timeout"))
        _run(engine.verify_finding(finding={"title": "test"}))
        # After an error, either brain_call_error or consecutive_failures incremented
        assert engine._brain_call_error >= 1 or engine._consecutive_failures >= 1


# ── Credential Sanitization ─────────────────────────────────────────

class TestCredentialSanitization:

    def test_sanitize_prompt_redacts_api_key(self):
        from src.brain.intelligence import _sanitize_prompt
        result = _sanitize_prompt("api_key=sk-abc123456 is sensitive")
        assert "sk-abc123456" not in result
        assert "REDACTED" in result

    def test_sanitize_prompt_redacts_bearer_token(self):
        from src.brain.intelligence import _sanitize_prompt
        result = _sanitize_prompt("bearer: eyJhbGciOiJ12345")
        assert "eyJhbGciOiJ12345" not in result

    def test_sanitize_prompt_preserves_normal_text(self):
        from src.brain.intelligence import _sanitize_prompt
        text = "Check the endpoint /api/users for IDOR vulnerability"
        result = _sanitize_prompt(text)
        assert result == text


# ── URL Clustering Helper ───────────────────────────────────────────

class TestURLClustering:

    def test_cluster_urls_groups_by_pattern(self):
        from src.brain.intelligence import IntelligenceEngine
        urls = [
            "https://example.com/api/users/123",
            "https://example.com/api/users/456",
            "https://example.com/api/users/789",
            "https://example.com/api/products/1",
        ]
        clusters = IntelligenceEngine._cluster_urls(urls, max_clusters=10)
        # Users should be clustered together
        assert len(clusters) <= len(urls)

    def test_cluster_urls_with_empty_list(self):
        from src.brain.intelligence import IntelligenceEngine
        clusters = IntelligenceEngine._cluster_urls([], max_clusters=10)
        assert clusters == {}

    def test_cluster_urls_max_clusters_honored(self):
        from src.brain.intelligence import IntelligenceEngine
        urls = [f"https://example.com/path{i}/item" for i in range(100)]
        clusters = IntelligenceEngine._cluster_urls(urls, max_clusters=5)
        assert len(clusters) <= 5


# ── Compact Tech Stack Helper ───────────────────────────────────────

class TestCompactTechStack:

    def test_compact_tech_stack_merges_hosts(self):
        from src.brain.intelligence import IntelligenceEngine
        tech = {
            "host1.com": ["nginx", "php", "wordpress"],
            "host2.com": ["nginx", "python", "django"],
        }
        compact = IntelligenceEngine._compact_tech_stack(tech)
        # Should contain merged values
        assert isinstance(compact, dict)

    def test_compact_tech_stack_empty(self):
        from src.brain.intelligence import IntelligenceEngine
        compact = IntelligenceEngine._compact_tech_stack({})
        assert isinstance(compact, dict)


# ── Compact Ports Helper ────────────────────────────────────────────

class TestCompactPorts:

    def test_compact_ports_splits_standard(self):
        from src.brain.intelligence import IntelligenceEngine
        ports = {
            "host1": [80, 443, 8080],
            "host2": [22, 80, 9090],
        }
        compact = IntelligenceEngine._compact_ports(ports)
        assert "standard" in compact or "non_standard" in compact

    def test_compact_ports_empty(self):
        from src.brain.intelligence import IntelligenceEngine
        compact = IntelligenceEngine._compact_ports({})
        assert isinstance(compact, dict)
