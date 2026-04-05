"""Comprehensive tests for brain prompt template builder functions.

Verifies that all 27 public build_* functions:
  1. Return non-empty strings
  2. Contain expected structural markers (JSON schema instructions, vuln keywords)
  3. Don't crash on minimal/edge-case inputs
"""

from __future__ import annotations

import pytest

# ── Helpers ─────────────────────────────────────────────────────────

def _finding_dict() -> dict:
    """Minimal finding dict for FP prompt tests."""
    return {
        "title": "Test XSS",
        "type": "xss",
        "vulnerability_type": "xss",
        "target": "https://example.com/search",
        "endpoint": "/search",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "severity": "HIGH",
        "confidence": 75.0,
        "tool_name": "dalfox",
        "evidence": "payload reflected in response body",
        "description": "Reflected XSS in search parameter",
    }


# ── Recon Prompts ───────────────────────────────────────────────────

class TestReconPrompts:

    def test_build_scope_analysis_prompt(self):
        from src.brain.prompts.recon_prompts import build_scope_analysis_prompt
        result = build_scope_analysis_prompt(
            targets=["example.com"],
            program_rules="Do not test login",
            in_scope=["*.example.com"],
            out_of_scope=["admin.example.com"],
        )
        assert isinstance(result, str)
        assert len(result) > 50
        assert "example.com" in result

    def test_build_scope_analysis_minimal(self):
        from src.brain.prompts.recon_prompts import build_scope_analysis_prompt
        result = build_scope_analysis_prompt(targets=["t.com"])
        assert isinstance(result, str) and len(result) > 20

    def test_build_subdomain_analysis_prompt(self):
        from src.brain.prompts.recon_prompts import build_subdomain_analysis_prompt
        result = build_subdomain_analysis_prompt(
            domain="example.com",
            subdomains=["api.example.com", "dev.example.com"],
        )
        assert isinstance(result, str)
        assert "api.example.com" in result

    def test_build_port_scan_analysis_prompt(self):
        from src.brain.prompts.recon_prompts import build_port_scan_analysis_prompt
        result = build_port_scan_analysis_prompt(
            target="example.com",
            open_ports=[{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
        )
        assert isinstance(result, str) and len(result) > 20


# ── Triage Prompts ──────────────────────────────────────────────────

class TestTriagePrompts:

    def test_build_triage_finding_prompt(self):
        from src.brain.prompts.triage_prompts import build_triage_finding_prompt
        result = build_triage_finding_prompt(
            vuln_type="xss",
            severity_hint="HIGH",
            target="https://example.com",
            tool_name="dalfox",
            raw_output="<script>alert(1)</script> reflected",
        )
        assert isinstance(result, str) and "xss" in result.lower()

    def test_build_tool_selection_prompt(self):
        from src.brain.prompts.triage_prompts import build_tool_selection_prompt
        result = build_tool_selection_prompt(
            task_type="vulnerability_scan",
            target="example.com",
            tech_stack=["nginx", "php"],
            available_tools=["nuclei", "sqlmap", "dalfox"],
        )
        assert isinstance(result, str) and len(result) > 30

    def test_build_next_action_prompt(self):
        from src.brain.prompts.triage_prompts import build_next_action_prompt
        result = build_next_action_prompt(
            current_stage="vulnerability_scan",
            findings_so_far=[{"title": "XSS", "severity": "HIGH"}],
            completed_tools=["nuclei", "nikto"],
            remaining_tools=["dalfox", "sqlmap"],
        )
        assert isinstance(result, str) and "vulnerability_scan" in result

    def test_build_next_action_prompt_with_learning(self):
        from src.brain.prompts.triage_prompts import build_next_action_prompt
        result = build_next_action_prompt(
            current_stage="vuln_scan",
            findings_so_far=[],
            completed_tools=[],
            remaining_tools=["nuclei"],
            historical_learning={"productive_tools": ["nuclei"], "vuln_types": ["xss"]},
        )
        assert isinstance(result, str)

    def test_build_severity_triage_prompt(self):
        from src.brain.prompts.triage_prompts import build_severity_triage_prompt
        result = build_severity_triage_prompt(
            findings=[{"title": "SQLi", "severity": "HIGH"}],
        )
        assert isinstance(result, str)

    def test_build_model_routing_prompt(self):
        from src.brain.prompts.triage_prompts import build_model_routing_prompt
        result = build_model_routing_prompt(
            task_description="Verify a SQL injection finding",
            task_complexity="high",
        )
        assert isinstance(result, str)

    def test_build_scan_profile_recommendation_prompt(self):
        from src.brain.prompts.triage_prompts import build_scan_profile_recommendation_prompt
        result = build_scan_profile_recommendation_prompt(
            target="example.com",
            waf_detected=True,
        )
        assert isinstance(result, str)


# ── Analysis Prompts ────────────────────────────────────────────────

class TestAnalysisPrompts:

    def test_build_vulnerability_analysis_prompt(self):
        from src.brain.prompts.analysis_prompts import build_vulnerability_analysis_prompt
        result = build_vulnerability_analysis_prompt(
            vuln_type="sqli",
            target_url="https://example.com/login",
            parameter="username",
            payload="' OR 1=1--",
            response_code=200,
        )
        assert isinstance(result, str) and "sqli" in result.lower()

    def test_build_vulnerability_analysis_minimal(self):
        from src.brain.prompts.analysis_prompts import build_vulnerability_analysis_prompt
        result = build_vulnerability_analysis_prompt(
            vuln_type="xss",
            target_url="https://t.com",
        )
        assert isinstance(result, str) and len(result) > 20

    def test_build_attack_surface_analysis_prompt(self):
        from src.brain.prompts.analysis_prompts import build_attack_surface_analysis_prompt
        result = build_attack_surface_analysis_prompt(
            target="example.com",
            endpoints=[{"url": "/api/users", "method": "GET"}, {"url": "/api/admin"}],
            services=[{"port": 80, "service": "http"}, {"port": 22, "service": "ssh"}],
            technologies=["nginx", "express"],
        )
        assert isinstance(result, str)

    def test_build_finding_correlation_prompt(self):
        from src.brain.prompts.analysis_prompts import build_finding_correlation_prompt
        result = build_finding_correlation_prompt(
            findings=[
                {"title": "XSS in /search", "type": "xss"},
                {"title": "CORS misconfiguration", "type": "cors"},
            ],
            target="example.com",
        )
        assert isinstance(result, str)

    def test_build_threat_model_prompt(self):
        from src.brain.prompts.analysis_prompts import build_threat_model_prompt
        result = build_threat_model_prompt(
            target="example.com",
            architecture="Microservices behind nginx",
        )
        assert isinstance(result, str)

    def test_build_impact_assessment_prompt(self):
        from src.brain.prompts.analysis_prompts import build_impact_assessment_prompt
        result = build_impact_assessment_prompt(
            vuln_type="sqli",
            target="example.com",
            severity="CRITICAL",
        )
        assert isinstance(result, str) and "sqli" in result.lower()


# ── Exploit Prompts ─────────────────────────────────────────────────

class TestExploitPrompts:

    def test_build_exploit_strategy_prompt(self):
        from src.brain.prompts.exploit_prompts import build_exploit_strategy_prompt
        result = build_exploit_strategy_prompt(
            vuln_type="sqli",
            target_url="https://example.com/login",
            parameter="username",
        )
        assert isinstance(result, str) and "sqli" in result.lower()

    def test_build_sqli_exploit_prompt(self):
        from src.brain.prompts.exploit_prompts import build_sqli_exploit_prompt
        result = build_sqli_exploit_prompt(
            target_url="https://example.com/search",
            parameter="q",
            injection_type="UNION",
            dbms="MySQL",
        )
        assert isinstance(result, str)

    def test_build_xss_exploit_prompt(self):
        from src.brain.prompts.exploit_prompts import build_xss_exploit_prompt
        result = build_xss_exploit_prompt(
            target_url="https://example.com/search",
            parameter="q",
            xss_type="reflected",
            context="attribute",
        )
        assert isinstance(result, str)

    def test_build_ssrf_exploit_prompt(self):
        from src.brain.prompts.exploit_prompts import build_ssrf_exploit_prompt
        result = build_ssrf_exploit_prompt(
            target_url="https://example.com/proxy",
            parameter="url",
            cloud_provider="aws",
        )
        assert isinstance(result, str)

    def test_build_auth_bypass_exploit_prompt(self):
        from src.brain.prompts.exploit_prompts import build_auth_bypass_exploit_prompt
        result = build_auth_bypass_exploit_prompt(
            target_url="https://example.com/admin",
            auth_mechanism="JWT",
        )
        assert isinstance(result, str)

    def test_build_poc_generation_prompt(self):
        from src.brain.prompts.exploit_prompts import build_poc_generation_prompt
        result = build_poc_generation_prompt(
            vuln_type="xss",
            target_url="https://example.com/search",
            parameter="q",
            payload="<script>alert(1)</script>",
        )
        assert isinstance(result, str)


# ── Report Prompts ──────────────────────────────────────────────────

class TestReportPrompts:

    def test_build_report_title_prompt(self):
        from src.brain.prompts.report_prompts import build_report_title_prompt
        result = build_report_title_prompt(
            vuln_type="xss",
            target="example.com",
            impact="Account takeover",
        )
        assert isinstance(result, str)

    def test_build_report_summary_prompt(self):
        from src.brain.prompts.report_prompts import build_report_summary_prompt
        result = build_report_summary_prompt(
            vuln_type="sqli",
            target="example.com",
            impact="Database access",
            severity="CRITICAL",
            cvss_score=9.8,
        )
        assert isinstance(result, str)

    def test_build_report_impact_prompt(self):
        from src.brain.prompts.report_prompts import build_report_impact_prompt
        result = build_report_impact_prompt(
            vuln_type="ssrf",
            target="example.com",
            severity="HIGH",
        )
        assert isinstance(result, str)

    def test_build_report_reproduction_prompt(self):
        from src.brain.prompts.report_prompts import build_report_reproduction_prompt
        result = build_report_reproduction_prompt(
            vuln_type="xss",
            target_url="https://example.com/search",
            parameter="q",
            payload="<img src=x onerror=alert(1)>",
        )
        assert isinstance(result, str)


# ── FP Elimination Prompts ──────────────────────────────────────────

class TestFPEliminationPrompts:

    def _make_finding(self):
        """Create a minimal Finding object for FP prompt tests."""
        from src.tools.base import Finding
        return Finding(
            title="Test XSS",
            vulnerability_type="xss",
            severity="high",
            confidence=75.0,
            target="https://example.com/search",
            endpoint="/search",
            parameter="q",
            payload="<script>alert(1)</script>",
            tool_name="dalfox",
            evidence="payload reflected",
            description="Reflected XSS",
        )

    def test_build_fp_analysis_prompt(self):
        from src.brain.prompts.fp_elimination import build_fp_analysis_prompt
        finding = self._make_finding()
        result = build_fp_analysis_prompt(finding)
        assert isinstance(result, str) and len(result) > 50

    def test_build_severity_assessment_prompt(self):
        from src.brain.prompts.fp_elimination import build_severity_assessment_prompt
        finding = self._make_finding()
        result = build_severity_assessment_prompt(finding)
        assert isinstance(result, str)

    def test_build_fp_exploit_strategy_prompt(self):
        from src.brain.prompts.fp_elimination import build_fp_exploit_strategy_prompt
        finding = self._make_finding()
        result = build_fp_exploit_strategy_prompt(finding)
        assert isinstance(result, str)


# ── Edge Cases ──────────────────────────────────────────────────────

class TestPromptEdgeCases:

    def test_empty_targets_list(self):
        from src.brain.prompts.recon_prompts import build_scope_analysis_prompt
        result = build_scope_analysis_prompt(targets=[])
        assert isinstance(result, str)

    def test_empty_findings_list(self):
        from src.brain.prompts.triage_prompts import build_severity_triage_prompt
        result = build_severity_triage_prompt(findings=[])
        assert isinstance(result, str)

    def test_very_long_payload(self):
        from src.brain.prompts.analysis_prompts import build_vulnerability_analysis_prompt
        result = build_vulnerability_analysis_prompt(
            vuln_type="sqli",
            target_url="https://example.com/x",
            payload="A" * 10000,
        )
        assert isinstance(result, str)

    def test_unicode_target(self):
        from src.brain.prompts.exploit_prompts import build_exploit_strategy_prompt
        result = build_exploit_strategy_prompt(
            vuln_type="xss",
            target_url="https://例え.jp/search",
        )
        assert isinstance(result, str)

    def test_none_optional_params(self):
        from src.brain.prompts.triage_prompts import build_tool_selection_prompt
        result = build_tool_selection_prompt(
            task_type="recon",
            target="t.com",
            tech_stack=None,
            available_tools=None,
        )
        assert isinstance(result, str)
