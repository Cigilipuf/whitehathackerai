"""
Tests for src.analysis.benchmark_lab — Benchmark Lab Engine (v3.3 Phase 5).

Coverage:
    - normalize_vuln_type (synonym map, edge cases)
    - BenchmarkEvaluator (TP/FP/FN/noise classification, metrics)
    - BenchmarkSuiteResult (aggregate metrics)
    - CalibrationEngine (threshold recommendations)
    - BenchmarkReporter (Markdown report generation)
    - LabManager (health check, start/stop mocking)
    - load_manifests (file loading)
    - load_findings (file loading)
    - Edge cases (empty findings, unknown lab, all FP, all TP, all noise)
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.analysis.benchmark_lab import (
    BenchmarkEvaluator,
    BenchmarkReporter,
    BenchmarkSuiteResult,
    CalibrationEngine,
    CalibrationRecommendation,
    ClassifiedFinding,
    LabBenchmarkResult,
    LabManager,
    load_findings,
    load_manifests,
    normalize_vuln_type,
)


# -----------------------------------------------------------------------
#  Fixtures
# -----------------------------------------------------------------------

@pytest.fixture
def mini_manifest():
    """Minimal manifest for testing."""
    return {
        "testlab": {
            "url": "http://127.0.0.1:9999",
            "docker_service": "testlab",
            "health_endpoint": "/",
            "health_status": [200],
            "setup_notes": "",
            "expected_vulns": [
                {"class": "sql_injection", "min_count": 2},
                {"class": "xss_reflected", "min_count": 1},
                {"class": "command_injection", "min_count": 1},
            ],
            "acceptable_noise": [
                "missing_security_headers",
                "cookie_no_httponly",
                "server_version_disclosure",
            ],
        }
    }


@pytest.fixture
def evaluator(mini_manifest):
    return BenchmarkEvaluator(mini_manifest)


def _make_finding(vuln_type: str, severity: str = "HIGH", confidence: float = 70.0,
                  endpoint: str = "/test") -> dict:
    return {
        "vulnerability_type": vuln_type,
        "severity": severity,
        "confidence": confidence,
        "endpoint": endpoint,
    }


# -----------------------------------------------------------------------
#  normalize_vuln_type
# -----------------------------------------------------------------------

class TestNormalizeVulnType:
    def test_canonical_passthrough(self):
        assert normalize_vuln_type("sql_injection") == "sql_injection"

    def test_synonym_sqli(self):
        assert normalize_vuln_type("sqli") == "sql_injection"

    def test_synonym_xss(self):
        assert normalize_vuln_type("xss") == "xss_reflected"

    def test_synonym_stored_xss(self):
        assert normalize_vuln_type("stored_xss") == "xss_stored"

    def test_synonym_dom_xss(self):
        assert normalize_vuln_type("dom-xss") == "xss_dom"

    def test_synonym_rce(self):
        assert normalize_vuln_type("rce") == "command_injection"

    def test_synonym_bola(self):
        assert normalize_vuln_type("bola") == "idor"

    def test_dash_normalisation(self):
        assert normalize_vuln_type("sql-injection") == "sql_injection"

    def test_space_normalisation(self):
        assert normalize_vuln_type("SQL Injection") == "sql_injection"

    def test_mixed_case_and_whitespace(self):
        assert normalize_vuln_type("  Reflected XSS  ") == "xss_reflected"

    def test_unknown_type_passthrough(self):
        assert normalize_vuln_type("unknown_type_xyz") == "unknown_type_xyz"

    def test_empty_string(self):
        assert normalize_vuln_type("") == ""

    def test_noise_type(self):
        assert normalize_vuln_type("missing_csp") == "missing_csp"

    def test_ssrf(self):
        assert normalize_vuln_type("server_side_request_forgery") == "ssrf"

    def test_xxe(self):
        assert normalize_vuln_type("xml_external_entity") == "xxe"

    def test_ssti(self):
        assert normalize_vuln_type("ssti") == "server_side_template_injection"


# -----------------------------------------------------------------------
#  BenchmarkEvaluator
# -----------------------------------------------------------------------

class TestBenchmarkEvaluatorClassification:
    """Test TP/FP/Noise/FN classification logic."""

    def test_true_positive_exact_match(self, evaluator):
        findings = [_make_finding("sql_injection")]
        result = evaluator.evaluate("testlab", findings)
        assert result.true_positives == 1
        assert result.classified[0].classification == "tp"
        assert result.classified[0].matched_expected == "sql_injection"

    def test_true_positive_via_synonym(self, evaluator):
        findings = [_make_finding("sqli")]
        result = evaluator.evaluate("testlab", findings)
        assert result.true_positives == 1

    def test_false_positive(self, evaluator):
        findings = [_make_finding("open_redirect")]
        result = evaluator.evaluate("testlab", findings)
        assert result.false_positives == 1
        assert result.classified[0].classification == "fp"

    def test_noise_filtered(self, evaluator):
        findings = [_make_finding("missing_security_headers")]
        result = evaluator.evaluate("testlab", findings)
        assert result.noise_count == 1
        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.classified[0].classification == "noise"

    def test_false_negatives(self, evaluator):
        """No findings → all expected classes are FN."""
        result = evaluator.evaluate("testlab", [])
        assert result.false_negatives == 3  # sql_injection, xss_reflected, command_injection
        assert set(result.missed_classes) == {"sql_injection", "xss_reflected", "command_injection"}

    def test_mixed_classification(self, evaluator):
        findings = [
            _make_finding("sql_injection"),
            _make_finding("sqli"),
            _make_finding("xss_reflected"),
            _make_finding("open_redirect"),
            _make_finding("missing_security_headers"),
        ]
        result = evaluator.evaluate("testlab", findings)
        assert result.true_positives == 3  # 2 sqli + 1 xss
        assert result.false_positives == 1  # open_redirect
        assert result.noise_count == 1  # missing_security_headers
        assert result.false_negatives == 1  # command_injection missed

    def test_extra_types(self, evaluator):
        findings = [_make_finding("cache_poisoning"), _make_finding("ssrf")]
        result = evaluator.evaluate("testlab", findings)
        assert "cache_poisoning" in result.extra_types
        assert "ssrf" in result.extra_types

    def test_unknown_lab_raises(self, evaluator):
        with pytest.raises(ValueError, match="No manifest for lab"):
            evaluator.evaluate("nonexistent_lab", [])


class TestBenchmarkEvaluatorMetrics:
    """Test TPR, precision, FPR, F1 computation."""

    def test_perfect_detection(self, evaluator):
        findings = [
            _make_finding("sql_injection"),
            _make_finding("sql_injection"),
            _make_finding("xss_reflected"),
            _make_finding("command_injection"),
        ]
        result = evaluator.evaluate("testlab", findings)
        assert result.tpr == 1.0
        assert result.precision == 1.0
        assert result.fpr == 0.0
        assert result.f1 == 1.0

    def test_partial_detection(self, evaluator):
        findings = [_make_finding("sql_injection")]  # only 1 of 3 classes
        result = evaluator.evaluate("testlab", findings)
        assert result.tpr == pytest.approx(1 / 3, abs=0.01)
        assert result.precision == 1.0  # no FPs
        assert result.fpr == 0.0

    def test_all_false_positives(self, evaluator):
        findings = [
            _make_finding("open_redirect"),
            _make_finding("ssrf"),
        ]
        result = evaluator.evaluate("testlab", findings)
        assert result.true_positives == 0
        assert result.false_positives == 2
        assert result.tpr == 0.0
        assert result.precision == 0.0
        assert result.fpr == 1.0
        assert result.f1 == 0.0

    def test_empty_findings(self, evaluator):
        result = evaluator.evaluate("testlab", [])
        assert result.tpr == 0.0
        assert result.precision == 1.0  # 0 TP, 0 FP → defined as 1.0
        assert result.fpr == 0.0
        assert result.f1 == 0.0

    def test_all_noise(self, evaluator):
        findings = [
            _make_finding("missing_security_headers"),
            _make_finding("cookie_no_httponly"),
        ]
        result = evaluator.evaluate("testlab", findings)
        assert result.noise_count == 2
        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.total_findings == 2

    def test_f1_computation(self, evaluator):
        """F1 = 2*P*R / (P+R)."""
        findings = [
            _make_finding("sql_injection"),
            _make_finding("xss_reflected"),
            _make_finding("open_redirect"),
        ]
        result = evaluator.evaluate("testlab", findings)
        # TP=2 (sqli, xss), FP=1 (open_redirect), FN=1 (cmd_injection)
        # Precision = 2/3, Recall = 2/3, F1 = 2*(2/3)*(2/3) / (2/3+2/3) = 2/3
        assert result.f1 == pytest.approx(2 / 3, abs=0.01)


class TestBenchmarkEvaluatorPerClass:
    def test_per_class_breakdown(self, evaluator):
        findings = [
            _make_finding("sql_injection"),
            _make_finding("sql_injection"),
            _make_finding("sql_injection"),
        ]
        result = evaluator.evaluate("testlab", findings)
        assert result.per_class["sql_injection"]["detected"] == 3
        assert result.per_class["sql_injection"]["expected_min"] == 2
        assert result.per_class["sql_injection"]["found"] is True
        assert result.per_class["xss_reflected"]["detected"] == 0
        assert result.per_class["xss_reflected"]["found"] is False


class TestBenchmarkSuiteEvaluation:
    def test_evaluate_suite(self, mini_manifest):
        evaluator = BenchmarkEvaluator(mini_manifest)
        lab_findings = {
            "testlab": [
                _make_finding("sql_injection"),
                _make_finding("xss_reflected"),
                _make_finding("command_injection"),
            ]
        }
        suite = evaluator.evaluate_suite(lab_findings)
        assert suite.overall_tpr == 1.0
        assert suite.overall_precision == 1.0
        assert suite.overall_fpr == 0.0
        assert suite.total_tp == 3
        assert suite.total_fp == 0
        assert suite.total_fn == 0

    def test_suite_skips_unknown_lab(self, mini_manifest):
        evaluator = BenchmarkEvaluator(mini_manifest)
        lab_findings = {
            "unknown_lab": [_make_finding("sqli")],
        }
        suite = evaluator.evaluate_suite(lab_findings)
        assert len(suite.results) == 0

    def test_suite_to_dict(self, mini_manifest):
        evaluator = BenchmarkEvaluator(mini_manifest)
        suite = evaluator.evaluate_suite({
            "testlab": [_make_finding("sql_injection")],
        })
        d = suite.to_dict()
        assert "overall_tpr" in d
        assert "labs" in d
        assert "testlab" in d["labs"]


# -----------------------------------------------------------------------
#  CalibrationEngine
# -----------------------------------------------------------------------

class TestCalibrationEngine:
    def _make_suite(self, tpr: float, fpr: float) -> BenchmarkSuiteResult:
        return BenchmarkSuiteResult(
            overall_tpr=tpr,
            overall_precision=1.0 - fpr,
            overall_fpr=fpr,
            overall_f1=0.5,
        )

    def test_target_met(self):
        cal = CalibrationEngine()
        rec = cal.recommend(self._make_suite(0.85, 0.15))
        assert rec.target_met is True
        assert rec.suggested_threshold == 65.0

    def test_high_fpr(self):
        cal = CalibrationEngine()
        rec = cal.recommend(self._make_suite(0.85, 0.35))
        assert rec.target_met is False
        assert rec.suggested_threshold > 65.0

    def test_low_tpr(self):
        cal = CalibrationEngine()
        rec = cal.recommend(self._make_suite(0.60, 0.10))
        assert rec.target_met is False
        assert rec.suggested_threshold < 65.0

    def test_both_bad(self):
        cal = CalibrationEngine()
        rec = cal.recommend(self._make_suite(0.40, 0.50))
        assert rec.target_met is False
        assert rec.suggested_threshold >= 65.0

    def test_custom_current_threshold(self):
        cal = CalibrationEngine()
        rec = cal.recommend(self._make_suite(0.60, 0.10), current_threshold=70.0)
        assert rec.current_threshold == 70.0

    def test_threshold_bounds(self):
        cal = CalibrationEngine()
        rec = cal.recommend(self._make_suite(0.40, 0.50), current_threshold=78.0)
        assert rec.suggested_threshold <= 80.0
        rec2 = cal.recommend(self._make_suite(0.60, 0.10), current_threshold=52.0)
        assert rec2.suggested_threshold >= 50.0


# -----------------------------------------------------------------------
#  BenchmarkReporter
# -----------------------------------------------------------------------

class TestBenchmarkReporter:
    def test_generate_contains_summary(self, mini_manifest):
        evaluator = BenchmarkEvaluator(mini_manifest)
        suite = evaluator.evaluate_suite({
            "testlab": [_make_finding("sql_injection")],
        })
        reporter = BenchmarkReporter()
        md = reporter.generate(suite)
        assert "WhiteHatHacker AI" in md
        assert "Overall Summary" in md
        assert "TPR (Recall)" in md
        assert "TESTLAB" in md

    def test_generate_per_lab_table(self, mini_manifest):
        evaluator = BenchmarkEvaluator(mini_manifest)
        suite = evaluator.evaluate_suite({
            "testlab": [_make_finding("sql_injection"), _make_finding("xss_reflected")],
        })
        reporter = BenchmarkReporter()
        md = reporter.generate(suite)
        assert "sql_injection" in md
        assert "xss_reflected" in md
        assert "command_injection" in md  # missed
        assert "✅" in md
        assert "❌" in md

    def test_save_creates_files(self, mini_manifest, tmp_path):
        evaluator = BenchmarkEvaluator(mini_manifest)
        suite = evaluator.evaluate_suite({
            "testlab": [_make_finding("sql_injection")],
        })
        reporter = BenchmarkReporter()
        md_path = reporter.save(suite, tmp_path)
        assert md_path.exists()
        assert (tmp_path / "benchmark_report.json").exists()
        # Check JSON is valid
        data = json.loads((tmp_path / "benchmark_report.json").read_text())
        assert "overall_tpr" in data


# -----------------------------------------------------------------------
#  LabManager
# -----------------------------------------------------------------------

class TestLabManager:
    def test_check_health_unknown_lab(self, mini_manifest):
        mgr = LabManager(mini_manifest)
        import asyncio
        result = asyncio.run(mgr.check_health("nonexistent"))
        assert result is False

    @patch("src.analysis.benchmark_lab.subprocess.run")
    def test_start_labs(self, mock_run, mini_manifest):
        mock_run.return_value = MagicMock(returncode=0)
        mgr = LabManager(mini_manifest)
        # stop_labs uses docker compose down — should work structurally
        result = mgr.stop_labs()
        assert mock_run.called

    @patch("src.analysis.benchmark_lab.subprocess.run")
    def test_start_labs_failure(self, mock_run, mini_manifest):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        mgr = LabManager(mini_manifest)
        result = mgr.start_labs(["testlab"])
        assert result is False


# -----------------------------------------------------------------------
#  load_manifests / load_findings
# -----------------------------------------------------------------------

class TestManifestLoading:
    def test_load_real_manifests(self):
        """Verify the real manifests.json can be loaded."""
        manifests = load_manifests()
        assert "dvwa" in manifests
        assert "juiceshop" in manifests
        assert len(manifests) >= 7

    def test_load_manifests_strips_meta(self):
        manifests = load_manifests()
        assert "_meta" not in manifests

    def test_load_manifests_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_manifests(tmp_path / "nonexistent.json")

    def test_load_custom_manifest(self, tmp_path):
        custom = {"testlab": {"url": "http://localhost:1234", "expected_vulns": []}}
        p = tmp_path / "custom.json"
        p.write_text(json.dumps(custom))
        result = load_manifests(p)
        assert "testlab" in result


class TestLoadFindings:
    def test_load_list_of_dicts(self, tmp_path):
        data = [{"vulnerability_type": "sqli"}, {"vulnerability_type": "xss"}]
        p = tmp_path / "findings.json"
        p.write_text(json.dumps(data))
        result = load_findings(p)
        assert len(result) == 2

    def test_load_dict_with_findings_key(self, tmp_path):
        data = {"findings": [{"vulnerability_type": "sqli"}], "meta": "ignored"}
        p = tmp_path / "findings.json"
        p.write_text(json.dumps(data))
        result = load_findings(p)
        assert len(result) == 1

    def test_load_single_dict(self, tmp_path):
        data = {"vulnerability_type": "sqli"}
        p = tmp_path / "findings.json"
        p.write_text(json.dumps(data))
        result = load_findings(p)
        assert len(result) == 1


# -----------------------------------------------------------------------
#  LabBenchmarkResult
# -----------------------------------------------------------------------

class TestLabBenchmarkResult:
    def test_to_dict_excludes_classified(self):
        r = LabBenchmarkResult(
            lab="test", url="http://test",
            classified=[ClassifiedFinding(
                normalized_type="sqli", classification="tp",
            )],
        )
        d = r.to_dict()
        assert "classified" not in d
        assert d["lab"] == "test"


# -----------------------------------------------------------------------
#  Edge cases
# -----------------------------------------------------------------------

class TestEdgeCases:
    def test_finding_with_empty_vuln_type(self, evaluator):
        findings = [{"vulnerability_type": "", "severity": "LOW"}]
        result = evaluator.evaluate("testlab", findings)
        assert result.total_findings == 1
        # Empty type normalises to "" → not in expected → FP (not in noise either)
        assert result.false_positives == 1

    def test_finding_with_none_confidence(self, evaluator):
        findings = [{"vulnerability_type": "sqli", "confidence": None}]
        result = evaluator.evaluate("testlab", findings)
        assert result.true_positives == 1
        assert result.classified[0].confidence == 0.0

    def test_finding_with_string_confidence(self, evaluator):
        findings = [{"vulnerability_type": "sqli", "confidence": "high"}]
        result = evaluator.evaluate("testlab", findings)
        assert result.classified[0].confidence == 0.0

    def test_finding_with_alt_type_key(self, evaluator):
        findings = [{"type": "sql_injection"}]
        result = evaluator.evaluate("testlab", findings)
        assert result.true_positives == 1

    def test_finding_with_vuln_type_key(self, evaluator):
        findings = [{"vuln_type": "sqli"}]
        result = evaluator.evaluate("testlab", findings)
        assert result.true_positives == 1

    def test_available_labs(self, evaluator):
        assert "testlab" in evaluator.available_labs

    def test_manifest_expected_vulns_complete(self):
        """Verify real manifests have expected_vulns and acceptable_noise."""
        manifests = load_manifests()
        for lab, m in manifests.items():
            assert "expected_vulns" in m, f"{lab} missing expected_vulns"
            assert "acceptable_noise" in m, f"{lab} missing acceptable_noise"
            assert len(m["expected_vulns"]) > 0, f"{lab} has empty expected_vulns"
