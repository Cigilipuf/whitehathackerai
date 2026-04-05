"""
Wave 3 Phase 13 — Test coverage for untested analysis modules.

Covers:
  - vulnerability_analyzer.py (models + analyzer logic)
  - threat_model.py (ThreatModeler + ImpactAssessor)
  - impact_assessor.py (ImpactAssessor from analysis module)
  - output_aggregator.py (OutputAggregator + NormalizedFinding dedup/correlation)
"""

from __future__ import annotations

import asyncio
import hashlib
import pytest

# ===========================================================================
# Module imports — verify these all work
# ===========================================================================


class TestModuleImports:
    """Verify all target modules are importable."""

    def test_vulnerability_analyzer_import(self):
        from src.analysis.vulnerability_analyzer import (
            VulnerabilityAnalyzer,
            AnalyzedVulnerability,
            VulnContext,
            ExploitFeasibility,
            ImpactAssessment,
            VULN_KNOWLEDGE,
        )
        assert VulnerabilityAnalyzer is not None
        assert issubclass(AnalyzedVulnerability, object)

    def test_threat_model_import(self):
        from src.analysis.threat_model import (
            ThreatModeler,
            ThreatModelReport,
            Threat,
            STRIDE_CATEGORIES,
            THREAT_TEMPLATES,
            RISK_MATRIX,
        )
        assert len(STRIDE_CATEGORIES) == 6
        assert set(STRIDE_CATEGORIES.keys()) == {"S", "T", "R", "I", "D", "E"}

    def test_impact_assessor_import(self):
        from src.analysis.impact_assessor import (
            ImpactAssessor,
            ImpactReport,
            ImpactDimension,
            ImpactCategory,
            ImpactLevel,
            DataClassification,
            VULN_IMPACT_MAP,
        )
        assert len(ImpactCategory) == 9
        assert len(ImpactLevel) == 5

    def test_output_aggregator_import(self):
        from src.analysis.output_aggregator import (
            OutputAggregator,
            NormalizedFinding,
            CorrelationResult,
            VULN_TYPE_NORMALIZER,
            SEVERITY_NORMALIZER,
        )
        assert "sql injection" in VULN_TYPE_NORMALIZER


# ===========================================================================
# VulnerabilityAnalyzer tests
# ===========================================================================


class TestVulnContext:
    """VulnContext Pydantic model tests."""

    def test_default_values(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        ctx = VulnContext()
        assert ctx.target_host == ""
        assert ctx.waf_detected is False
        assert ctx.technology_stack == []

    def test_custom_values(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        ctx = VulnContext(
            target_host="example.com",
            waf_detected=True,
            waf_name="Cloudflare",
            technology_stack=["php", "mysql"],
        )
        assert ctx.waf_name == "Cloudflare"
        assert "php" in ctx.technology_stack


class TestExploitFeasibility:
    def test_defaults(self):
        from src.analysis.vulnerability_analyzer import ExploitFeasibility
        ef = ExploitFeasibility()
        assert ef.is_exploitable is False
        assert ef.complexity == "unknown"
        assert ef.automation_possible is True
        assert ef.prerequisites == []


class TestVulnerabilityAnalyzerLogic:
    """Test VulnerabilityAnalyzer without brain engine."""

    def _make_analyzer(self):
        from src.analysis.vulnerability_analyzer import VulnerabilityAnalyzer
        return VulnerabilityAnalyzer(brain_engine=None)

    def test_build_cvss_context(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        finding = {"auth_required": True, "data_extracted": True}
        ctx = VulnContext(auth_required=True)
        result = analyzer._build_cvss_context(finding, ctx)
        assert result["authenticated"] is True
        assert result["data_extracted"] is True
        assert result["user_interaction"] is False

    def test_assess_exploit_feasibility_sqli(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        finding = {"vuln_type": "sql_injection"}
        ctx = VulnContext()
        result = analyzer._assess_exploit_feasibility(finding, ctx)
        assert result.is_exploitable is True
        assert result.complexity == "low"
        assert result.automation_possible is True

    def test_assess_exploit_feasibility_waf_raises_complexity(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        finding = {"vuln_type": "sql_injection"}
        ctx = VulnContext(waf_detected=True, waf_name="Cloudflare")
        result = analyzer._assess_exploit_feasibility(finding, ctx)
        # low → medium because of WAF
        assert result.complexity == "medium"
        assert any("WAF" in lim for lim in result.limitations)

    def test_assess_exploit_feasibility_deserialization_prereqs(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        finding = {"vuln_type": "deserialization"}
        ctx = VulnContext()
        result = analyzer._assess_exploit_feasibility(finding, ctx)
        assert result.complexity == "high"
        assert result.is_exploitable is False  # high complexity → not easily exploitable
        assert any("gadget" in p.lower() for p in result.prerequisites)

    def test_assess_impact_sqli(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        result = analyzer._assess_impact("sql_injection", {}, VulnContext())
        assert result.confidentiality == "high"
        assert result.integrity == "high"
        assert result.lateral_movement is False
        assert "database" in result.business_impact.lower()

    def test_assess_impact_cmdi_has_lateral_movement(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        result = analyzer._assess_impact("command_injection", {}, VulnContext())
        assert result.lateral_movement is True
        assert result.privilege_escalation is True

    def test_assess_impact_unknown_type_fallback(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        result = analyzer._assess_impact("some_unknown_type", {}, VulnContext())
        assert result.confidentiality == "low"

    def test_analyze_returns_analyzed_vulnerability(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        finding = {
            "vuln_type": "xss_reflected",
            "title": "Reflected XSS in search",
            "url": "https://example.com/search",
            "parameter": "q",
            "confidence": 75.0,
        }
        result = asyncio.run(analyzer.analyze(finding, VulnContext()))
        assert result.vuln_type == "xss_reflected"
        assert result.confidence == 75.0
        assert result.cvss.score >= 0
        assert result.analyzed_at != ""

    def test_analyze_batch_returns_sorted(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        findings = [
            {"vuln_type": "open_redirect", "title": "Open Redirect"},
            {"vuln_type": "sql_injection", "title": "SQLi"},
        ]
        results = asyncio.run(analyzer.analyze_batch(findings, VulnContext()))
        assert len(results) == 2
        # SQLi should have higher CVSS → sorted first
        assert results[0].cvss.score >= results[1].cvss.score

    def test_get_summary_empty(self):
        analyzer = self._make_analyzer()
        s = analyzer.get_summary()
        assert s["total"] == 0

    def test_get_summary_after_analyze(self):
        from src.analysis.vulnerability_analyzer import VulnContext
        analyzer = self._make_analyzer()
        asyncio.run(
            analyzer.analyze({"vuln_type": "sql_injection", "title": "SQLi"}, VulnContext())
        )
        s = analyzer.get_summary()
        assert s["total"] == 1
        assert s["exploitable_count"] >= 0
        assert "sql_injection" in s["vuln_types"]

    def test_correlate_findings_detects_chain(self):
        from src.analysis.vulnerability_analyzer import VulnContext, AnalyzedVulnerability
        analyzer = self._make_analyzer()
        # Analyze SQLi + auth bypass → should detect chain
        asyncio.run(
            analyzer.analyze_batch(
                [
                    {"vuln_type": "sql_injection", "title": "SQLi"},
                    {"vuln_type": "authentication_bypass", "title": "Auth bypass"},
                ],
                VulnContext(),
            )
        )
        # Chain detection adds notes
        notes = [f.analysis_notes for f in analyzer._findings_cache]
        chain_notes = [n for n in notes if "Chain" in n]
        assert len(chain_notes) > 0


class TestVulnKnowledge:
    """Test VULN_KNOWLEDGE data integrity."""

    def test_all_entries_have_required_fields(self):
        from src.analysis.vulnerability_analyzer import VULN_KNOWLEDGE
        for vuln_type, info in VULN_KNOWLEDGE.items():
            assert "root_cause" in info, f"{vuln_type} missing root_cause"
            assert "attack_scenario" in info, f"{vuln_type} missing attack_scenario"
            assert "remediation" in info, f"{vuln_type} missing remediation"
            assert "references" in info, f"{vuln_type} missing references"

    def test_known_vuln_types(self):
        from src.analysis.vulnerability_analyzer import VULN_KNOWLEDGE
        expected = {
            "sql_injection", "command_injection", "xss_reflected", "xss_stored",
            "ssrf", "ssti", "idor", "authentication_bypass", "cors_misconfiguration",
            "xxe", "open_redirect", "local_file_inclusion", "deserialization",
        }
        assert expected.issubset(set(VULN_KNOWLEDGE.keys()))


# ===========================================================================
# ThreatModeler tests
# ===========================================================================


class TestThreatModeler:
    """Test STRIDE-based threat modeling."""

    def _make_modeler(self):
        from src.analysis.threat_model import ThreatModeler
        return ThreatModeler()

    def test_model_threats_default_web_app(self):
        modeler = self._make_modeler()
        report = modeler.model_threats(target="https://example.com")
        assert report.target == "https://example.com"
        assert report.total_threats > 0
        assert report.generated_at != ""
        # Default is web_application → should have STRIDE threats
        categories = {t.category for t in report.threats}
        assert "S" in categories  # Spoofing
        assert "I" in categories  # Info Disclosure

    def test_model_threats_with_technologies(self):
        modeler = self._make_modeler()
        report = modeler.model_threats(
            target="https://example.com",
            technologies=["wordpress", "php", "mysql"],
        )
        # WordPress → should add WP-specific threat
        names = [t.name for t in report.threats]
        assert any("WordPress" in n for n in names)

    def test_model_threats_with_risky_ports(self):
        modeler = self._make_modeler()
        report = modeler.model_threats(
            target="10.0.0.1",
            services=["network_service"],
            open_ports=[21, 6379, 27017],
        )
        names = [t.name for t in report.threats]
        assert any("FTP" in n for n in names)
        assert any("Redis" in n for n in names)
        assert any("MongoDB" in n for n in names)

    def test_model_threats_api_service(self):
        modeler = self._make_modeler()
        report = modeler.model_threats(
            target="https://api.example.com",
            services=["api_rest"],
        )
        names = [t.name for t in report.threats]
        assert any("JWT" in n for n in names)
        assert any("BOLA" in n for n in names)

    def test_high_risk_threats_filtering(self):
        modeler = self._make_modeler()
        report = modeler.model_threats(
            target="https://example.com",
            services=["web_application", "authentication"],
        )
        # risk_score >= 12 → high risk
        for t in report.high_risk_threats:
            assert t.risk_score >= 12.0

    def test_risk_summary_counts(self):
        modeler = self._make_modeler()
        report = modeler.model_threats(target="https://example.com")
        total_from_summary = sum(report.risk_summary.values())
        assert total_from_summary == report.total_threats

    def test_sorted_by_risk_score(self):
        modeler = self._make_modeler()
        report = modeler.model_threats(
            target="https://example.com",
            services=["web_application", "api_rest"],
        )
        scores = [t.risk_score for t in report.threats]
        assert scores == sorted(scores, reverse=True)

    def test_to_markdown_output(self):
        modeler = self._make_modeler()
        modeler.model_threats(target="https://example.com")
        md = modeler.to_markdown()
        assert "# STRIDE Threat Model" in md
        assert "THREAT-" in md

    def test_to_markdown_empty(self):
        modeler = self._make_modeler()
        md = modeler.to_markdown()
        assert "No threats modeled yet" in md

    def test_estimate_likelihood_waf_lowers(self):
        modeler = self._make_modeler()
        template = {"name": "Some Attack", "cat": "T"}
        result = modeler._estimate_likelihood(template, [], {"waf_detected": True})
        assert result == "low"

    def test_estimate_likelihood_php_sqli_high(self):
        modeler = self._make_modeler()
        template = {"name": "SQL Injection Data Modification", "cat": "T"}
        result = modeler._estimate_likelihood(template, ["php", "mysql"], {})
        assert result == "high"

    def test_estimate_impact_rce_very_high(self):
        modeler = self._make_modeler()
        template = {"name": "Command Injection via user input", "cat": "E"}
        result = modeler._estimate_impact(template, {})
        assert result == "very_high"


class TestThreatModelImpactAssessor:
    """Test the ImpactAssessor class in threat_model.py."""

    def _make_assessor(self):
        from src.analysis.threat_model import ImpactAssessor
        return ImpactAssessor()

    def test_assess_sqli(self):
        assessor = self._make_assessor()
        result = assessor.assess("sql_injection", 8.5)
        assert result["overall_impact"] in ("critical", "high", "medium", "low")
        assert 0 <= result["impact_score"] <= 100
        assert "dimensions" in result
        assert "narrative" in result

    def test_assess_xss_lower_than_sqli(self):
        assessor = self._make_assessor()
        sqli = assessor.assess("sql_injection", 8.5)
        xss = assessor.assess("xss_reflected", 4.0)
        assert sqli["impact_score"] > xss["impact_score"]

    def test_assess_with_pii_context(self):
        assessor = self._make_assessor()
        without_pii = assessor.assess("idor", 6.0)
        with_pii = assessor.assess("idor", 6.0, context={"pii_involved": True})
        assert with_pii["impact_score"] >= without_pii["impact_score"]

    def test_assess_financial_context(self):
        assessor = self._make_assessor()
        result = assessor.assess(
            "sql_injection", 9.0,
            context={"ecommerce": True, "payment_processing": True},
        )
        assert result["dimensions"]["financial"] > 80

    def test_compliance_gdpr(self):
        assessor = self._make_assessor()
        result = assessor.assess("sql_injection", 8.0, context={"gdpr": True})
        assert result["dimensions"]["compliance"] == 90.0

    def test_narrative_contains_vuln_type(self):
        assessor = self._make_assessor()
        result = assessor.assess("command_injection", 9.0)
        assert "command injection" in result["narrative"].lower()


# ===========================================================================
# ImpactAssessor (analysis/impact_assessor.py) tests
# ===========================================================================


class TestImpactAssessorModule:
    """Test the standalone ImpactAssessor in analysis/impact_assessor.py."""

    def _make_assessor(self):
        from src.analysis.impact_assessor import ImpactAssessor
        return ImpactAssessor()

    def test_assess_known_vuln_returns_report(self):
        from src.analysis.impact_assessor import ImpactReport, ImpactLevel
        assessor = self._make_assessor()
        report = assessor.assess("sqli", "https://example.com")
        assert isinstance(report, ImpactReport)
        assert report.vuln_type == "sqli"
        assert report.overall_impact != ImpactLevel.NONE
        assert len(report.dimensions) > 0
        assert report.score > 0

    def test_assess_unknown_vuln_fallback(self):
        assessor = self._make_assessor()
        report = assessor.assess("unknown_vuln_type", "https://example.com")
        assert report.vuln_type == "unknown_vuln_type"
        # Should still produce a report with defaults
        assert report.score >= 0

    def test_adjust_score_internet_facing(self):
        from src.analysis.impact_assessor import ImpactAssessor
        base = 5.0
        result = ImpactAssessor._adjust_score(base, {"internet_facing": True})
        assert result == 5.5

    def test_adjust_score_staging_env(self):
        from src.analysis.impact_assessor import ImpactAssessor
        # default internet_facing=True adds +0.5, staging subtracts -1.5 → 5.0 + 0.5 - 1.5 = 4.0
        result = ImpactAssessor._adjust_score(5.0, {"environment": "staging"})
        assert result == 4.0

    def test_adjust_score_development_env(self):
        from src.analysis.impact_assessor import ImpactAssessor
        # default internet_facing=True adds +0.5, development subtracts -2.5 → 5.0 + 0.5 - 2.5 = 3.0
        result = ImpactAssessor._adjust_score(5.0, {"environment": "development"})
        assert result == 3.0

    def test_adjust_score_clamped_to_0_10(self):
        from src.analysis.impact_assessor import ImpactAssessor
        assert ImpactAssessor._adjust_score(0.0, {"environment": "development"}) == 0.0
        assert ImpactAssessor._adjust_score(10.0, {"internet_facing": True, "handles_sensitive_data": True}) == 10.0

    def test_score_to_level(self):
        from src.analysis.impact_assessor import ImpactAssessor, ImpactLevel
        assert ImpactAssessor._score_to_level(9.5) == ImpactLevel.CRITICAL
        assert ImpactAssessor._score_to_level(7.5) == ImpactLevel.HIGH
        assert ImpactAssessor._score_to_level(5.0) == ImpactLevel.MEDIUM
        assert ImpactAssessor._score_to_level(2.0) == ImpactLevel.LOW
        assert ImpactAssessor._score_to_level(0.0) == ImpactLevel.NONE

    def test_determine_urgency(self):
        from src.analysis.impact_assessor import ImpactAssessor
        assert ImpactAssessor._determine_urgency(9.5) == "immediate"
        assert ImpactAssessor._determine_urgency(7.5) == "next-sprint"
        assert ImpactAssessor._determine_urgency(3.0) == "planned"

    def test_assess_multiple(self):
        assessor = self._make_assessor()
        findings = [
            {"vuln_type": "sqli", "target": "https://a.com"},
            {"vuln_type": "xss", "target": "https://b.com"},
            {"vuln_type": "rce", "target": "https://c.com"},
        ]
        reports = assessor.assess_multiple(findings)
        assert len(reports) == 3
        # RCE should have highest score
        rce_report = [r for r in reports if r.vuln_type == "rce"][0]
        assert rce_report.score >= 8.0

    def test_data_at_risk_populated(self):
        from src.analysis.impact_assessor import DataClassification
        assessor = self._make_assessor()
        report = assessor.assess("sqli", "https://example.com")
        assert len(report.affected_data) > 0
        assert DataClassification.CREDENTIALS in report.affected_data


# ===========================================================================
# OutputAggregator tests
# ===========================================================================


class TestOutputAggregator:
    """Test OutputAggregator dedup, normalization, and correlation."""

    def _make_aggregator(self):
        from src.analysis.output_aggregator import OutputAggregator
        return OutputAggregator()

    def _make_tool_result(self, findings_data: list[dict]):
        from src.tools.base import Finding, ToolResult
        findings = []
        for fd in findings_data:
            findings.append(Finding(
                title=fd.get("title", "Test Finding"),
                severity=fd.get("severity", "medium"),
                confidence=fd.get("confidence", 50.0),
                target=fd.get("target", "https://example.com"),
                endpoint=fd.get("endpoint", "/test"),
                parameter=fd.get("parameter", ""),
                description=fd.get("description", ""),
                evidence=fd.get("evidence", ""),
                payload=fd.get("payload", ""),
            ))
        return ToolResult(
            tool_name="test_tool",
            success=True,
            findings=findings,
            metadata={"tool": "test_tool"},
        )

    def test_ingest_single_finding(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "SQL Injection in login", "severity": "high"},
        ])
        new_count = agg.ingest_tool_result(result, "sqlmap")
        assert new_count == 1
        stats = agg.get_stats()
        assert stats["unique_findings"] == 1

    def test_dedup_same_findings(self):
        agg = self._make_aggregator()
        result1 = self._make_tool_result([
            {"title": "SQL Injection in login", "target": "https://example.com", "endpoint": "/login", "parameter": "user"},
        ])
        result2 = self._make_tool_result([
            {"title": "SQL Injection in login", "target": "https://example.com", "endpoint": "/login", "parameter": "user"},
        ])
        agg.ingest_tool_result(result1, "sqlmap")
        agg.ingest_tool_result(result2, "nuclei")
        stats = agg.get_stats()
        assert stats["raw_findings"] == 2
        assert stats["unique_findings"] == 1
        assert stats["cross_verified"] >= 0  # Will be verified after correlate

    def test_merge_boosts_verification(self):
        agg = self._make_aggregator()
        result1 = self._make_tool_result([
            {"title": "SQL Injection", "target": "https://example.com", "endpoint": "/api"},
        ])
        result2 = self._make_tool_result([
            {"title": "SQL Injection", "target": "https://example.com", "endpoint": "/api"},
        ])
        agg.ingest_tool_result(result1, "sqlmap")
        agg.ingest_tool_result(result2, "nuclei")
        # After correlation, cross-verified count should increase
        cr = agg.correlate()
        assert cr.total_cross_verified >= 1

    def test_different_findings_not_deduped(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "SQL Injection", "endpoint": "/login", "parameter": "user"},
            {"title": "XSS in search", "endpoint": "/search", "parameter": "q"},
        ])
        agg.ingest_tool_result(result, "nuclei")
        stats = agg.get_stats()
        assert stats["unique_findings"] == 2

    def test_correlate_by_severity(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "SQL Injection", "severity": "high"},
            {"title": "XSS reflected", "severity": "medium"},
            {"title": "Missing header", "severity": "low"},
        ])
        agg.ingest_tool_result(result, "nuclei")
        cr = agg.correlate()
        assert "HIGH" in cr.by_severity
        assert "MEDIUM" in cr.by_severity

    def test_get_findings_with_filters(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "SQL Injection", "severity": "high", "confidence": 90},
            {"title": "Info leak", "severity": "low", "confidence": 30},
        ])
        agg.ingest_tool_result(result, "tool")
        high_only = agg.get_findings(severity="HIGH")
        assert all(f.severity == "HIGH" for f in high_only)
        confident = agg.get_findings(min_confidence=80)
        assert all(f.confidence >= 80 for f in confident)

    def test_mark_false_positive(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "False positive finding", "severity": "high"},
        ])
        agg.ingest_tool_result(result, "tool")
        findings = agg.get_findings()
        assert len(findings) == 1
        # Mark it as FP
        agg.mark_false_positive(findings[0].finding_id, "WAF artifact")
        filtered = agg.get_findings(exclude_fp=True)
        assert len(filtered) == 0

    def test_clear(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([{"title": "Test"}])
        agg.ingest_tool_result(result, "tool")
        assert agg.get_stats()["unique_findings"] == 1
        agg.clear()
        assert agg.get_stats()["unique_findings"] == 0

    def test_vuln_type_normalization(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "SQL Injection found", "description": "blind sql injection in param"},
        ])
        agg.ingest_tool_result(result, "sqlmap")
        findings = agg.get_findings()
        assert findings[0].vuln_type == "sqli"

    def test_severity_normalization(self):
        from src.analysis.output_aggregator import SEVERITY_NORMALIZER
        assert SEVERITY_NORMALIZER["critical"] == "CRITICAL"
        assert SEVERITY_NORMALIZER["moderate"] == "MEDIUM"
        assert SEVERITY_NORMALIZER["informational"] == "INFO"

    def test_normalize_target_adds_scheme(self):
        agg = self._make_aggregator()
        result = agg._normalize_target("example.com")
        assert result.startswith("https://")

    def test_normalize_target_strips_trailing_slash(self):
        agg = self._make_aggregator()
        result = agg._normalize_target("https://example.com/")
        assert not result.endswith("/")

    def test_title_similarity(self):
        agg = self._make_aggregator()
        assert agg._title_similarity("SQL Injection in login", "SQL Injection in login page") > 0.7
        assert agg._title_similarity("SQL Injection", "XSS reflected") < 0.5

    def test_finding_priority_sort(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "Low issue", "severity": "low", "confidence": 30},
            {"title": "Critical bug", "severity": "critical", "confidence": 90},
            {"title": "Medium find", "severity": "medium", "confidence": 60},
        ])
        agg.ingest_tool_result(result, "tool")
        sorted_findings = agg.get_findings()
        assert sorted_findings[0].severity in ("CRITICAL", "HIGH")

    def test_attack_chain_detection(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "Information disclosure via verbose error", "description": "info_disclosure stack trace", "severity": "low"},
            {"title": "SQL Injection via user param", "description": "sql injection found", "severity": "high"},
        ])
        agg.ingest_tool_result(result, "tools")
        cr = agg.correlate()
        assert len(cr.attack_chains) > 0
        chain_types = [c["type"] for c in cr.attack_chains]
        assert "info_to_injection" in chain_types

    def test_get_findings_for_report(self):
        agg = self._make_aggregator()
        result = self._make_tool_result([
            {"title": "Good finding", "confidence": 80},
            {"title": "Weak finding", "confidence": 20},
        ])
        agg.ingest_tool_result(result, "tool")
        report_findings = agg.get_findings_for_report()
        # min_confidence=50, so weak finding excluded
        assert all(f.confidence >= 50 for f in report_findings)

    def test_dedup_ratio_stat(self):
        agg = self._make_aggregator()
        result1 = self._make_tool_result([{"title": "Finding A"}])
        result2 = self._make_tool_result([{"title": "Finding A"}])
        agg.ingest_tool_result(result1, "tool1")
        agg.ingest_tool_result(result2, "tool2")
        stats = agg.get_stats()
        assert "dedup_ratio" in stats
        # 2 raw, 1 unique → 50% dedup
        assert stats["dedup_ratio"] == "50.0%"
