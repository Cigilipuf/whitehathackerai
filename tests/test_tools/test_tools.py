"""Tests for Security Tool Wrappers and Parser."""

from __future__ import annotations

import pytest

from src.tools.parser import UnifiedParser, RawToolOutput


class TestUnifiedParser:
    """Test the unified tool output parser."""

    def setup_method(self):
        self.parser = UnifiedParser()

    def test_detect_json(self):
        assert self.parser.detect_format('{"key": "value"}') == "json"
        assert self.parser.detect_format('[{"a": 1}]') == "json"

    def test_detect_xml(self):
        assert self.parser.detect_format('<?xml version="1.0"?><root/>') == "xml"

    def test_detect_empty(self):
        assert self.parser.detect_format("") == "empty"
        assert self.parser.detect_format("   ") == "empty"

    def test_detect_plain(self):
        assert self.parser.detect_format("just plain text") == "plain"

    def test_detect_nmap_greppable(self):
        line = "Host: 10.0.0.1 (test.com)\tPorts: 80/open/tcp//http//"
        assert self.parser.detect_format(line) == "nmap_grep"

    def test_parse_json(self):
        results = self.parser.parse_json('[{"key": "val"}]')
        assert len(results) == 1
        assert results[0]["key"] == "val"

    def test_parse_nmap_greppable(self):
        text = "Host: 10.0.0.1 (test.com)\tPorts: 80/open/tcp//http//, 443/open/tcp//https//"
        hosts = self.parser.parse_nmap_greppable(text)
        assert len(hosts) == 2
        assert hosts[0].port == 80
        assert hosts[1].port == 443

    def test_parse_sqlmap_output(self):
        text = """
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1
        """
        vulns = self.parser.parse_sqlmap_output(text)
        assert len(vulns) >= 1
        assert vulns[0].vuln_type == "sqli"  # ParsedVulnerability uses vuln_type

    def test_parse_nikto_output(self):
        text = """
+ Server: nginx/1.21
+ OSVDB-3092: /admin/: Found admin dir
+ /robots.txt: contains sensitive path
        """
        vulns = self.parser.parse_nikto_output(text)
        assert len(vulns) >= 2

    def test_parse_tool_output_plain(self):
        raw = RawToolOutput(
            tool_name="unknown_tool",
            stdout="line1\nline2\nline3",
        )
        findings = self.parser.parse_tool_output(raw)
        assert len(findings) == 3
        assert findings[0].vulnerability_type == "raw-output"

    def test_parse_tool_output_empty(self):
        raw = RawToolOutput(tool_name="test", stdout="")
        findings = self.parser.parse_tool_output(raw)
        assert len(findings) == 0


class TestToolBase:
    """Test base tool class."""

    def test_finding_model(self):
        from src.tools.base import Finding
        f = Finding(
            tool_name="nmap",
            vulnerability_type="open-port",
            title="Port 80 open",
            severity="info",
            target="10.0.0.1",
        )
        assert f.tool_name == "nmap"
        assert f.severity == "info"

    def test_tool_registry_creation(self):
        from src.tools.registry import ToolRegistry
        registry = ToolRegistry()
        assert registry is not None
