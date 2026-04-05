"""
Tests for src.analysis.scan_quality_report — Per-Scan Quality Report (V25 T5-3).

Covers QualityMetrics, QualityScore, QualityReport, ScanQualityAnalyzer,
including score computation, warning detection, recommendations, comparison,
and edge cases.
"""

import pytest

from src.analysis.scan_quality_report import (
    QualityMetrics,
    QualityReport,
    QualityScore,
    ScanQualityAnalyzer,
    _safe_float,
)


# ── _safe_float ──


class TestSafeFloat:
    def test_int(self):
        assert _safe_float(42) == 42.0

    def test_str_numeric(self):
        assert _safe_float("3.14") == 3.14

    def test_str_non_numeric(self):
        assert _safe_float("high") == 0.0

    def test_none(self):
        assert _safe_float(None) == 0.0

    def test_default(self):
        assert _safe_float("bad", 99.0) == 99.0

    def test_list(self):
        assert _safe_float([1, 2]) == 0.0


# ── QualityMetrics defaults ──


class TestQualityMetrics:
    def test_defaults(self):
        m = QualityMetrics()
        assert m.total_tools_registered == 0
        assert m.raw_findings == 0
        assert m.brain_calls_total == 0
        assert m.total_duration_s == 0.0

    def test_severity_fields(self):
        m = QualityMetrics(critical_count=1, high_count=2, medium_count=3, low_count=4, info_count=5)
        assert m.critical_count + m.high_count + m.medium_count + m.low_count + m.info_count == 15


# ── QualityScore ──


class TestQualityScore:
    def test_defaults(self):
        s = QualityScore()
        assert s.overall == 0.0
        assert s.dimensions == {}


# ── QualityReport ──


class TestQualityReport:
    def test_to_dict(self):
        r = QualityReport(
            scan_id="scan-1",
            target="example.com",
            metrics=QualityMetrics(raw_findings=10),
            score=QualityScore(overall=75.0),
        )
        d = r.to_dict()
        assert d["scan_id"] == "scan-1"
        assert d["metrics"]["raw_findings"] == 10
        assert d["score"]["overall"] == 75.0

    def test_to_markdown_basic(self):
        r = QualityReport(
            scan_id="s1",
            target="t.com",
            metrics=QualityMetrics(raw_findings=5, confirmed_findings=3, tools_executed=10),
            score=QualityScore(overall=80.0, tool_health=90.0, brain_health=70.0,
                               fp_quality=85.0, coverage=60.0, evidence_quality=50.0),
            warnings=["Test warning"],
            recommendations=["Fix something"],
        )
        md = r.to_markdown()
        assert "# Scan Quality Report" in md
        assert "**80/100**" in md
        assert "Test warning" in md
        assert "Fix something" in md

    def test_to_markdown_with_comparison(self):
        r = QualityReport(
            scan_id="s2",
            target="t.com",
            metrics=QualityMetrics(),
            score=QualityScore(overall=50.0),
            comparison={"Raw findings": "10 (+3)"},
        )
        md = r.to_markdown()
        assert "Comparison" in md
        assert "10 (+3)" in md


# ── ScanQualityAnalyzer._compute_score ──


class TestComputeScore:
    def setup_method(self):
        self.analyzer = ScanQualityAnalyzer()

    def test_perfect_tools(self):
        m = QualityMetrics(tools_executed=10, tools_succeeded=10, tools_failed=0)
        s = self.analyzer._compute_score(m)
        assert s.tool_health == 100.0

    def test_all_tools_failed(self):
        m = QualityMetrics(tools_executed=5, tools_succeeded=0, tools_failed=5)
        s = self.analyzer._compute_score(m)
        assert s.tool_health == 0.0

    def test_no_tools(self):
        m = QualityMetrics()
        s = self.analyzer._compute_score(m)
        assert s.tool_health == 0.0

    def test_brain_health_with_calls(self):
        m = QualityMetrics(
            brain_calls_total=100, brain_calls_success=90, brain_calls_error=10,
            brain_json_parse_ok=80, brain_json_parse_fail=20,
        )
        s = self.analyzer._compute_score(m)
        # (0.9 * 60) + (0.8 * 40) = 54 + 32 = 86
        assert abs(s.brain_health - 86.0) < 1

    def test_brain_health_no_calls(self):
        m = QualityMetrics(brain_calls_total=0)
        s = self.analyzer._compute_score(m)
        assert s.brain_health == 50.0  # neutral

    def test_fp_quality_good_filtering(self):
        m = QualityMetrics(raw_findings=100, after_fp=30)
        s = self.analyzer._compute_score(m)
        assert s.fp_quality == 90.0  # 70% filtered = good

    def test_fp_quality_too_aggressive(self):
        m = QualityMetrics(raw_findings=100, after_fp=2)
        s = self.analyzer._compute_score(m)
        assert s.fp_quality == 60.0  # >95% filtered = too aggressive

    def test_fp_quality_permissive(self):
        m = QualityMetrics(raw_findings=100, after_fp=90)
        s = self.analyzer._compute_score(m)
        assert s.fp_quality == 50.0  # <20% filtered = too permissive

    def test_evidence_quality_full_poc(self):
        m = QualityMetrics(confirmed_findings=5, poc_verified=5)
        s = self.analyzer._compute_score(m)
        assert s.evidence_quality == 100.0

    def test_evidence_quality_no_poc_with_confirmed(self):
        m = QualityMetrics(confirmed_findings=5, poc_verified=0, after_fp=5)
        s = self.analyzer._compute_score(m)
        assert s.evidence_quality == 0.0  # poc_ratio = 0/5 = 0

    def test_evidence_quality_no_confirmed_with_fp_findings(self):
        m = QualityMetrics(confirmed_findings=0, poc_verified=0, after_fp=5)
        s = self.analyzer._compute_score(m)
        assert s.evidence_quality == 30.0  # findings but no confirmed → 30

    def test_overall_is_weighted_sum(self):
        m = QualityMetrics(
            tools_executed=10, tools_succeeded=10, tools_failed=0,
            brain_calls_total=10, brain_calls_success=10,
            brain_json_parse_ok=10, brain_json_parse_fail=0,
            raw_findings=100, after_fp=40,
            confirmed_findings=5, poc_verified=5,
            checkers_executed=20,
        )
        s = self.analyzer._compute_score(m)
        # Check overall is sum of weighted dimensions
        expected = sum(
            s.dimensions[dim] * self.analyzer._WEIGHTS[dim]
            for dim in self.analyzer._WEIGHTS
        )
        assert abs(s.overall - expected) < 0.01


# ── ScanQualityAnalyzer._detect_warnings ──


class TestDetectWarnings:
    def setup_method(self):
        self.analyzer = ScanQualityAnalyzer()

    def test_many_failed_tools(self):
        m = QualityMetrics(tools_failed=5)
        w = self.analyzer._detect_warnings(m)
        assert any("5 tools failed" in x for x in w)

    def test_brain_errors(self):
        m = QualityMetrics(brain_calls_total=10, brain_calls_error=5)
        w = self.analyzer._detect_warnings(m)
        assert any("Brain error rate" in x for x in w)

    def test_all_findings_eliminated(self):
        m = QualityMetrics(raw_findings=10, after_fp=0)
        w = self.analyzer._detect_warnings(m)
        assert any("All findings eliminated" in x for x in w)

    def test_no_endpoints(self):
        m = QualityMetrics(endpoints_total=0)
        w = self.analyzer._detect_warnings(m)
        assert any("No endpoints" in x for x in w)

    def test_json_parse_failures(self):
        m = QualityMetrics(brain_json_parse_ok=2, brain_json_parse_fail=10)
        w = self.analyzer._detect_warnings(m)
        assert any("JSON parse" in x for x in w)

    def test_no_warnings(self):
        m = QualityMetrics(
            tools_failed=1,
            brain_calls_total=10, brain_calls_error=1,
            raw_findings=10, after_fp=5,
            endpoints_total=10,
            brain_json_parse_ok=10, brain_json_parse_fail=2,
        )
        w = self.analyzer._detect_warnings(m)
        assert len(w) == 0


# ── ScanQualityAnalyzer._generate_recommendations ──


class TestRecommendations:
    def setup_method(self):
        self.analyzer = ScanQualityAnalyzer()

    def test_low_tool_health(self):
        m = QualityMetrics()
        s = QualityScore(tool_health=30)
        recs = self.analyzer._generate_recommendations(m, s)
        assert any("diagnose" in r for r in recs)

    def test_low_brain_health(self):
        m = QualityMetrics()
        s = QualityScore(brain_health=40)
        recs = self.analyzer._generate_recommendations(m, s)
        assert any("Brain" in r or "SSH" in r for r in recs)

    def test_no_poc_recommendation(self):
        m = QualityMetrics(poc_verified=0, confirmed_findings=5)
        s = QualityScore(evidence_quality=80)
        recs = self.analyzer._generate_recommendations(m, s)
        assert any("PoC" in r or "ExploitVerifier" in r for r in recs)

    def test_no_recs_when_good(self):
        m = QualityMetrics(poc_verified=5, confirmed_findings=5)
        s = QualityScore(
            tool_health=90, brain_health=80, fp_quality=85,
            evidence_quality=90, coverage=70,
        )
        recs = self.analyzer._generate_recommendations(m, s)
        assert len(recs) == 0


# ── ScanQualityAnalyzer._compare ──


class TestCompare:
    def setup_method(self):
        self.analyzer = ScanQualityAnalyzer()

    def test_improvement(self):
        prev = QualityMetrics(raw_findings=5, confirmed_findings=2, poc_verified=1)
        curr = QualityMetrics(raw_findings=10, confirmed_findings=5, poc_verified=3)
        diff = self.analyzer._compare(curr, prev)
        assert "+5" in diff["Raw findings"]
        assert "+3" in diff["Confirmed findings"]

    def test_regression(self):
        prev = QualityMetrics(tools_failed=1)
        curr = QualityMetrics(tools_failed=5)
        diff = self.analyzer._compare(curr, prev)
        assert "+4" in diff["Tools failed"]

    def test_unchanged(self):
        prev = QualityMetrics(raw_findings=5)
        curr = QualityMetrics(raw_findings=5)
        diff = self.analyzer._compare(curr, prev)
        assert "unchanged" in diff["Raw findings"]


# ── ScanQualityAnalyzer.analyze (full integration) ──


class TestAnalyzeIntegration:
    def test_basic_analyze(self):
        analyzer = ScanQualityAnalyzer()
        findings = [
            {"severity": "high", "confidence_score": 80, "poc_confirmed": True},
            {"severity": "medium", "confidence_score": 60},
            {"severity": "low", "confidence_score": 30},
        ]
        report = analyzer.analyze(
            scan_id="s1",
            target="example.com",
            state_metadata={
                "endpoints": ["/a", "/b"],
                "live_hosts": ["h1"],
                "failed_tools": ["tool_x"],
                "stage_finding_counts": {"vuln_scan": 3, "fp": 0},
            },
            raw_findings_count=10,
            deduped_findings_count=8,
            final_findings=findings,
            tools_run=["nuclei", "dalfox", "nikto"],
            brain_metrics={"total_calls": 20, "call_success": 18, "cache_hits": 5},
        )
        assert report.scan_id == "s1"
        assert report.target == "example.com"
        assert report.metrics.raw_findings == 10
        assert report.metrics.high_count == 1
        assert report.metrics.medium_count == 1
        assert report.metrics.low_count == 1
        assert report.metrics.poc_verified == 1
        assert 0 <= report.score.overall <= 100
        assert isinstance(report.to_markdown(), str)
        assert isinstance(report.to_dict(), dict)

    def test_analyze_with_comparison(self):
        analyzer = ScanQualityAnalyzer()
        prev = QualityMetrics(raw_findings=5, confirmed_findings=2, poc_verified=0)
        report = analyzer.analyze(
            scan_id="s2",
            target="t.com",
            state_metadata={},
            raw_findings_count=15,
            deduped_findings_count=12,
            final_findings=[{"severity": "high", "confidence_score": 85}],
            previous_metrics=prev,
        )
        assert report.comparison is not None
        assert "Raw findings" in report.comparison

    def test_analyze_zero_findings(self):
        analyzer = ScanQualityAnalyzer()
        report = analyzer.analyze(
            scan_id="s3",
            target="t.com",
            state_metadata={},
            raw_findings_count=0,
            deduped_findings_count=0,
            final_findings=[],
        )
        assert report.metrics.raw_findings == 0
        assert report.metrics.confirmed_findings == 0
        assert report.score.fp_quality == 50  # neutral

    def test_analyze_no_brain(self):
        analyzer = ScanQualityAnalyzer()
        report = analyzer.analyze(
            scan_id="s4",
            target="t.com",
            state_metadata={"endpoints": ["/x"]},
            raw_findings_count=5,
            deduped_findings_count=5,
            final_findings=[{"severity": "medium", "confidence_score": 55}],
            brain_metrics={},  # no brain data
        )
        assert report.score.brain_health == 50  # neutral


# ── Edge Cases ──


class TestEdgeCases:
    def test_findings_with_non_numeric_confidence(self):
        analyzer = ScanQualityAnalyzer()
        findings = [
            {"severity": "high", "confidence_score": "very_high"},
            {"severity": "high", "confidence": None},
        ]
        report = analyzer.analyze(
            scan_id="e1",
            target="t.com",
            state_metadata={},
            raw_findings_count=5,
            deduped_findings_count=5,
            final_findings=findings,
        )
        # Should not crash
        assert report.metrics.confirmed_findings == 0  # "very_high" parsed as 0.0

    def test_negative_values_handled(self):
        m = QualityMetrics(tools_executed=0, raw_findings=0)
        analyzer = ScanQualityAnalyzer()
        s = analyzer._compute_score(m)
        assert s.overall >= 0

    def test_markdown_escaping(self):
        r = QualityReport(
            scan_id="<script>",
            target="t.com & ' \" > <",
            metrics=QualityMetrics(),
            score=QualityScore(),
        )
        md = r.to_markdown()
        assert "t.com" in md  # shouldn't crash

    def test_weights_sum_to_one(self):
        w = ScanQualityAnalyzer._WEIGHTS
        assert abs(sum(w.values()) - 1.0) < 0.001
