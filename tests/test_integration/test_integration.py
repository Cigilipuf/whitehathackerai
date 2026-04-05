"""Integration tests for end-to-end pipeline flows."""

from __future__ import annotations

import pytest

from src.analysis.impact_assessor import ImpactAssessor
from src.analysis.severity_calculator import SeverityCalculator


class TestImpactAssessment:
    """Test the impact assessment pipeline."""

    def test_assess_sqli(self):
        assessor = ImpactAssessor()
        report = assessor.assess("sqli", "https://example.com/search")
        assert report.score > 0
        assert report.overall_impact.value in ("critical", "high", "medium", "low", "none")
        assert len(report.dimensions) > 0

    def test_assess_xss(self):
        assessor = ImpactAssessor()
        report = assessor.assess("xss", "https://example.com/profile")
        assert report.score > 0

    def test_assess_unknown_type(self):
        assessor = ImpactAssessor()
        report = assessor.assess("unknown_vuln", "https://example.com")
        assert report.score >= 0

    def test_context_adjustments(self):
        assessor = ImpactAssessor()
        # Staging env should lower score
        report_prod = assessor.assess("sqli", "target", context={"environment": "production"})
        report_stage = assessor.assess("sqli", "target", context={"environment": "staging"})
        assert report_prod.score > report_stage.score


class TestSeverityCalculator:
    """Test CVSS severity calculator."""

    def test_calculator_creation(self):
        calc = SeverityCalculator()
        assert calc is not None
