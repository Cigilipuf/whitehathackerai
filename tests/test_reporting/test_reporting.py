"""Tests for Reporting System."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.reporting.formatters.markdown_formatter import MarkdownFormatter
from src.reporting.formatters.json_formatter import JsonFormatter
from src.reporting.formatters.html_formatter import HtmlFormatter
from src.reporting.report_generator import ReportGenerator
from src.reporting.templates.executive_summary import ExecutiveSummaryTemplate
from src.reporting.templates.technical_detail import TechnicalDetailTemplate


class TestMarkdownFormatter:
    """Test Markdown report formatter."""

    def test_format_finding(self, sample_finding):
        fmt = MarkdownFormatter()
        md = fmt.format_finding(sample_finding)
        assert "SQL Injection" in md
        assert "high" in md.lower() or "HIGH" in md

    def test_format_findings_summary(self, sample_findings):
        fmt = MarkdownFormatter()
        md = fmt.format_findings_summary(sample_findings)
        assert "critical" in md.lower() or "Critical" in md

    def test_format_finding_handles_none_severity(self):
        fmt = MarkdownFormatter()
        md = fmt.format_finding({"title": "Edge Case", "severity": None, "confidence": 12})
        assert "EDGE CASE" not in md
        assert "MEDIUM" in md.upper()

    def test_format_findings_summary_handles_none_severity(self):
        fmt = MarkdownFormatter()
        md = fmt.format_findings_summary([
            {"title": "Edge", "severity": None, "confidence": 10, "status": "open"}
        ])
        assert "UNKNOWN" in md


class TestJsonFormatter:
    """Test JSON report formatter."""

    def test_format_findings(self, sample_findings):
        fmt = JsonFormatter()
        result = fmt.format_findings(sample_findings)
        assert isinstance(result, str)
        data = json.loads(result)
        assert isinstance(data, (list, dict))


class TestHtmlFormatter:
    """Test HTML report formatter."""

    def test_format_report(self, sample_findings):
        fmt = HtmlFormatter()
        html = fmt.format_report({
            "findings": sample_findings,
            "target": "https://example.com",
            "title": "Test Report",
        })
        assert "<html" in html.lower()
        assert "Test Report" in html


class TestExecutiveSummary:
    """Test executive summary template."""

    def test_generate_summary(self, sample_findings):
        tmpl = ExecutiveSummaryTemplate()
        summary = tmpl.generate(sample_findings, target="example.com")
        assert summary.total_findings == len(sample_findings)
        assert summary.critical_count == 1
        assert summary.overall_risk == "critical"

    def test_render_markdown(self, sample_findings):
        tmpl = ExecutiveSummaryTemplate()
        summary = tmpl.generate(sample_findings, target="example.com")
        md = tmpl.render_markdown(summary)
        assert "Executive" in md
        assert "CRITICAL" in md

    def test_generate_summary_handles_none_severity(self):
        tmpl = ExecutiveSummaryTemplate()
        summary = tmpl.generate([{"title": "Edge", "severity": None}], target="example.com")
        assert summary.total_findings == 1


class TestTechnicalDetail:
    """Test technical detail template."""

    def test_generate_report(self, sample_findings):
        tmpl = TechnicalDetailTemplate()
        report = tmpl.generate(sample_findings, target="example.com")
        assert len(report.findings) == len(sample_findings)

    def test_render_markdown(self, sample_findings):
        tmpl = TechnicalDetailTemplate()
        report = tmpl.generate(sample_findings, target="example.com")
        md = tmpl.render_markdown(report)
        assert "Technical" in md
        assert "Methodology" in md


class TestReportGenerator:
    """Regression tests for report generation normalization."""

    def test_convert_finding_preserves_reporting_fields(self, tmp_path: Path):
        generator = ReportGenerator(output_dir=str(tmp_path))

        converted = generator._convert_finding({
            "title": "HTTP Request Smuggling",
            "type": "http_request_smuggling",
            "severity": "high",
            "summary": "Proxy and backend parse the request differently.",
            "description": "A crafted request can desync the connection.",
            "impact": "Attackers may bypass controls and poison downstream requests.",
            "confidence_score": 91,
            "tool": "smuggler",
            "tool_sources": ["nuclei", "custom_probe"],
            "tags": ["http", "desync"],
            "screenshots": ["/tmp/one.png"],
            "screenshot_path": "/tmp/two.png",
        })

        assert converted.summary == "Proxy and backend parse the request differently."
        assert converted.description == "A crafted request can desync the connection."
        assert converted.impact == "Attackers may bypass controls and poison downstream requests."
        assert converted.confidence_score == 91
        assert converted.tool_sources == ["nuclei", "custom_probe", "http", "desync", "smuggler"]
        assert converted.screenshots == ["/tmp/one.png", "/tmp/two.png"]

    def test_markdown_renders_attached_screenshots(self, tmp_path: Path):
        generator = ReportGenerator(output_dir=str(tmp_path))
        converted = generator._convert_finding({
            "title": "JWT weak secret",
            "type": "jwt_vulnerability",
            "severity": "high",
            "description": "Token signed with a weak shared secret.",
            "screenshot_path": "/tmp/jwt.png",
        })

        from src.reporting.report_generator import Report, PlatformType

        report_obj = Report(
            report_id="rpt_test",
            platform=PlatformType.GENERIC,
            target="api.example.com",
            findings=[converted],
        )

        markdown = generator.to_markdown(report_obj)
        assert "![Screenshot](/tmp/jwt.png)" in markdown

    def test_convert_finding_keeps_valid_cvss_vector(self, tmp_path: Path):
        generator = ReportGenerator(output_dir=str(tmp_path))

        converted = generator._convert_finding({
            "title": "SQL Injection",
            "type": "sql_injection",
            "severity": "high",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        })

        assert converted.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_convert_finding_falls_back_from_invalid_cvss_vector(self, tmp_path: Path):
        generator = ReportGenerator(output_dir=str(tmp_path))

        converted = generator._convert_finding({
            "title": "SQL Injection",
            "type": "sql_injection",
            "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:INVALID/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        })

        assert converted.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
