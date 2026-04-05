"""Regression tests for deep audit v2 fixes.

Covers:
1. Finding._coerce_evidence: None → "" (not "None")
2. markdown_formatter confidence dual-key fallback
3. html_formatter confidence dual-key fallback
4. KnownFPMatcher wired into FPDetector Layer 1
"""

import pytest
from src.tools.base import Finding


# ──────────────────────────────────────────────────────────────
# 1. Finding._coerce_evidence — None handling
# ──────────────────────────────────────────────────────────────

class TestFindingEvidenceCoercion:
    """Verify Finding.evidence never becomes literal 'None' string."""

    def test_evidence_none_coerces_to_empty(self):
        """None evidence → empty string, NOT 'None'."""
        f = Finding(title="test", evidence=None)
        assert f.evidence == ""
        assert f.evidence != "None"

    def test_evidence_explicit_empty_string(self):
        f = Finding(title="test", evidence="")
        assert f.evidence == ""

    def test_evidence_normal_string_preserved(self):
        f = Finding(title="test", evidence="some evidence text")
        assert f.evidence == "some evidence text"

    def test_evidence_list_joined(self):
        f = Finding(title="test", evidence=["line1", "line2"])
        assert f.evidence == "line1\nline2"

    def test_evidence_integer_coerced(self):
        f = Finding(title="test", evidence=42)
        assert f.evidence == "42"

    def test_evidence_empty_list(self):
        f = Finding(title="test", evidence=[])
        assert f.evidence == ""

    def test_evidence_list_with_none_items(self):
        f = Finding(title="test", evidence=["valid", None, "end"])
        assert "None" in f.evidence  # str(None) within list items is OK
        assert f.evidence == "valid\nNone\nend"


# ──────────────────────────────────────────────────────────────
# 2. Markdown formatter — confidence dual-key
# ──────────────────────────────────────────────────────────────

class TestMarkdownFormatterConfidence:
    """Verify markdown formatter uses confidence_score with confidence fallback."""

    def test_confidence_score_preferred(self):
        from src.reporting.formatters.markdown_formatter import MarkdownFormatter
        fmt = MarkdownFormatter()
        finding = {
            "title": "Test XSS",
            "severity": "high",
            "confidence_score": 85,
            "confidence": 50,  # should be ignored
        }
        result = fmt.format_finding(finding)
        assert "85%" in result

    def test_confidence_fallback(self):
        from src.reporting.formatters.markdown_formatter import MarkdownFormatter
        fmt = MarkdownFormatter()
        finding = {
            "title": "Test XSS",
            "severity": "high",
            "confidence": 72,
            # no confidence_score
        }
        result = fmt.format_finding(finding)
        assert "72%" in result

    def test_summary_table_uses_dual_key(self):
        from src.reporting.formatters.markdown_formatter import MarkdownFormatter
        fmt = MarkdownFormatter()
        findings = [
            {"title": "F1", "severity": "high", "confidence_score": 90},
            {"title": "F2", "severity": "medium", "confidence": 60},
        ]
        result = fmt.format_findings_summary(findings)
        assert "90%" in result
        assert "60%" in result


# ──────────────────────────────────────────────────────────────
# 3. HTML formatter — confidence dual-key
# ──────────────────────────────────────────────────────────────

class TestHtmlFormatterConfidence:
    """Verify HTML formatter uses confidence_score with confidence fallback."""

    def test_html_confidence_score_preferred(self):
        from src.reporting.formatters.html_formatter import HtmlFormatter
        fmt = HtmlFormatter()
        findings = [
            {"title": "Test SQLi", "severity": "critical", "confidence_score": 95, "confidence": 50},
        ]
        result = fmt.format_findings_table(findings)
        assert "95%" in result

    def test_html_confidence_fallback(self):
        from src.reporting.formatters.html_formatter import HtmlFormatter
        fmt = HtmlFormatter()
        findings = [
            {"title": "Test SSRF", "severity": "high", "confidence": 78},
        ]
        result = fmt.format_findings_table(findings)
        assert "78%" in result


# ──────────────────────────────────────────────────────────────
# 4. KnownFPMatcher wired into FPDetector
# ──────────────────────────────────────────────────────────────

class TestKnownFPMatcherIntegration:
    """Verify KnownFPMatcher is invoked by FPDetector Layer 1."""

    def test_fp_detector_has_matcher(self):
        """FPDetector should instantiate a KnownFPMatcher."""
        from src.fp_engine.fp_detector import FPDetector
        from src.fp_engine.patterns.known_fps import KnownFPMatcher
        detector = FPDetector()
        assert hasattr(detector, "_known_fp_matcher")
        assert isinstance(detector._known_fp_matcher, KnownFPMatcher)

    def test_layer1_invokes_matcher(self):
        """Layer 1 should check both inline patterns AND KnownFPMatcher."""
        from src.fp_engine.fp_detector import FPDetector

        detector = FPDetector()
        # Create a finding that matches a known FP pattern
        # FP-BRAIN-001: finding_type=hypothesis → penalty -25
        finding = Finding(
            title="Potential SQL Injection",
            vulnerability_type="hypothesis",
            tool_name="brain_analysis",
            description="Brain hypothesis about possible SQLi",
            metadata={"finding_type": "hypothesis"},
        )
        result, penalty, patterns = detector._layer1_pattern_matching(finding)
        # KnownFPMatcher should have matched FP-BRAIN-001
        brain_matched = any("BRAIN" in p for p in patterns)
        assert brain_matched, f"Expected BRAIN pattern match, got: {patterns}"
        assert penalty < 0, f"Expected negative penalty, got: {penalty}"

    def test_layer1_no_false_match(self):
        """Normal findings shouldn't match sophisticated FP patterns."""
        from src.fp_engine.fp_detector import FPDetector

        detector = FPDetector()
        finding = Finding(
            title="SQL Injection in login endpoint",
            vulnerability_type="sql_injection",
            tool_name="sqlmap",
            description="UNION-based SQL injection detected",
            evidence="extracted data: admin, password123",
            metadata={"finding_type": "vulnerability"},
        )
        result, penalty, patterns = detector._layer1_pattern_matching(finding)
        # This should NOT match brain-hypothesis patterns
        brain_matched = any("BRAIN" in p for p in patterns)
        assert not brain_matched


# ──────────────────────────────────────────────────────────────
# 5. End-to-end Finding roundtrip: evidence integrity
# ──────────────────────────────────────────────────────────────

class TestFindingEvidenceRoundtrip:
    """Verify evidence field survives dict conversion and back."""

    def test_none_evidence_roundtrip(self):
        f = Finding(title="test", evidence=None)
        d = f.model_dump()
        assert d["evidence"] == ""
        f2 = Finding(**d)
        assert f2.evidence == ""

    def test_normal_evidence_roundtrip(self):
        f = Finding(title="test", evidence="Extracted: admin_user")
        d = f.model_dump()
        assert d["evidence"] == "Extracted: admin_user"
        f2 = Finding(**d)
        assert f2.evidence == "Extracted: admin_user"
