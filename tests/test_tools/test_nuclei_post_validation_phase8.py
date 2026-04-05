"""Regression tests for Phase 8: Nuclei post-scan response validation."""

from __future__ import annotations

import json


class TestNucleiPostValidation:
    def _tool(self):
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper
        return NucleiWrapper()

    def _jsonl(self, response: str, *, severity: str = "medium", matched_at: str = "https://example.com/test", extra: dict | None = None) -> str:
        payload = {
            "template-id": "exposed-config",
            "host": "example.com",
            "matched-at": matched_at,
            "info": {
                "name": "Exposed Config",
                "severity": severity,
                "tags": ["config", "exposure"],
                "description": "Configuration disclosure",
            },
            "response": response,
        }
        if extra:
            payload.update(extra)
        return json.dumps(payload)

    def test_extract_http_response_meta_parses_status_headers_and_body(self):
        from src.tools.scanners.nuclei_wrapper import NucleiWrapper

        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "CF-Ray: abc123\r\n\r\n"
            '{"ok": true}'
        )
        meta = NucleiWrapper._extract_http_response_meta(raw)
        assert meta is not None
        assert meta["status_code"] == 200
        assert meta["headers"]["Content-Type"] == "application/json"
        assert meta["body"] == '{"ok": true}'

    def test_parse_output_drops_redirect_login_response(self):
        tool = self._tool()
        raw = self._jsonl(
            "HTTP/1.1 302 Found\r\n"
            "Location: /login?next=%2Fadmin\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html>redirecting</html>",
        )
        findings = tool.parse_output(raw, "example.com")
        assert findings == []

    def test_parse_output_drops_waf_block_page(self):
        tool = self._tool()
        raw = self._jsonl(
            "HTTP/1.1 403 Forbidden\r\n"
            "CF-Ray: abc123\r\n"
            "Content-Type: text/html\r\n\r\n"
            "Attention Required! | Cloudflare Ray ID: abc123",
            severity="high",
        )
        findings = tool.parse_output(raw, "example.com")
        assert findings == []

    def test_parse_output_applies_soft_waf_confidence_penalty(self):
        tool = self._tool()
        clean_raw = self._jsonl(
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n\r\n"
            + ("sensitive-data-" * 20),
            severity="high",
        )
        waf_raw = self._jsonl(
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "CF-Ray: abc123\r\n\r\n"
            + ("sensitive-data-" * 20),
            severity="high",
        )

        clean_findings = tool.parse_output(clean_raw, "example.com")
        waf_findings = tool.parse_output(waf_raw, "example.com")

        assert len(clean_findings) == 1
        assert len(waf_findings) == 1
        assert waf_findings[0].confidence == clean_findings[0].confidence - 5.0
        assert waf_findings[0].metadata["response_validation"]["waf_detected"] == "cloudflare"

    def test_parse_output_drops_generic_500_without_stacktrace(self):
        tool = self._tool()
        raw = self._jsonl(
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html><head><title>500</title></head><body>Server error</body></html>",
            severity="high",
        )
        findings = tool.parse_output(raw, "example.com")
        assert findings == []

    def test_parse_output_keeps_valid_response_and_validation_metadata(self):
        tool = self._tool()
        raw = self._jsonl(
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n\r\n"
            + ("DB_PASSWORD=secret\n" * 10),
            severity="high",
            extra={"matcher-name": "password-leak", "curl-command": "curl https://example.com/test"},
        )
        findings = tool.parse_output(raw, "example.com")
        assert len(findings) == 1
        finding = findings[0]
        assert finding.confidence >= 70.0
        assert finding.metadata["response_validation"]["status_code"] == 200
