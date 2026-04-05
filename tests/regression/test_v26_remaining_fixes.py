"""
V26 Remaining Fixes — Regression Tests

Covers:
- P3-2: Go tool memory 256MiB, GOGC=25
- P2-4: Orchestrator heartbeat tools_run counter
- P5-2: StateMachine transition log level → DEBUG
- P5-6: Scope validation log level → DEBUG
- P4-2: DecisionEngine STAGE_TOOL_MATRIX completeness + minimum guarantee
- P3-6: Shodan API key pre-validation
- P3-7: sslscan parser hardening (weak cipher regex, Heartbleed)
"""

from __future__ import annotations

import importlib
import re

import pytest


# ---------------------------------------------------------------------------
# P3-2: Go tool memory limits tightened to 256 MiB, GOGC=25
# ---------------------------------------------------------------------------

class TestGoToolMemoryTightened:
    """Verify gau/waybackurls use 256MiB (not 512) and GOGC=25."""

    def test_gau_memory_256(self):
        from src.tools.recon.web_discovery.gau_wrapper import GauWrapper
        assert GauWrapper.memory_limit == 256 * 1024 * 1024

    def test_waybackurls_memory_256(self):
        from src.tools.recon.web_discovery.waybackurls_wrapper import WaybackurlsWrapper
        assert WaybackurlsWrapper.memory_limit == 256 * 1024 * 1024

    def test_gau_gogc_25(self):
        import src.tools.recon.web_discovery.gau_wrapper as gm
        source = open(gm.__file__).read()
        assert '"25"' in source or "'25'" in source, "GOGC should be '25'"

    def test_waybackurls_gogc_25(self):
        import src.tools.recon.web_discovery.waybackurls_wrapper as wm
        source = open(wm.__file__).read()
        assert '"25"' in source or "'25'" in source, "GOGC should be '25'"


# ---------------------------------------------------------------------------
# P2-4: Orchestrator heartbeat includes tools_run count
# ---------------------------------------------------------------------------

class TestHeartbeatToolsRun:
    """Verify orchestrator heartbeat log includes tools_run."""

    def test_heartbeat_has_tools_run(self):
        import src.workflow.orchestrator as om
        source = open(om.__file__).read()
        assert "tools_run=" in source, "Heartbeat log must include tools_run count"


# ---------------------------------------------------------------------------
# P5-2: StateMachine transition noise → DEBUG
# ---------------------------------------------------------------------------

class TestStateMachineLogLevel:
    """Invalid transition messages should be DEBUG, not WARNING."""

    def test_transition_log_debug(self):
        import src.workflow.state_machine as sm
        source = open(sm.__file__).read()
        # Find logger calls that contain "Invalid transition" — should be debug not warning
        # The pattern may span multiple lines (f-string), so search for logger.xxx(...Invalid transition
        assert re.search(r"logger\.debug\([^)]*Invalid transition", source, re.DOTALL), (
            "'Invalid transition' should use logger.debug"
        )
        assert not re.search(r"logger\.warning\([^)]*Invalid transition", source, re.DOTALL), (
            "'Invalid transition' should NOT use logger.warning"
        )


# ---------------------------------------------------------------------------
# P5-6: Scope validation REJECT messages → DEBUG
# ---------------------------------------------------------------------------

class TestScopeValidatorLogLevel:
    """SCOPE REJECT messages should be DEBUG, not WARNING."""

    def test_scope_reject_debug(self):
        import src.utils.scope_validator as sv
        source = open(sv.__file__).read()
        lines = source.split("\n")
        for line in lines:
            if "SCOPE REJECT" in line:
                assert "logger.debug" in line, (
                    f"SCOPE REJECT should use logger.debug, found: {line.strip()}"
                )


# ---------------------------------------------------------------------------
# P4-2: DecisionEngine STAGE_TOOL_MATRIX + minimum tool guarantee
# ---------------------------------------------------------------------------

class TestDecisionEngineMatrix:
    """Verify STAGE_TOOL_MATRIX includes critical tools and minimum guarantee."""

    def test_nuclei_in_vuln_scanning_web(self):
        from src.workflow.decision_engine import STAGE_TOOL_MATRIX
        web_tools = STAGE_TOOL_MATRIX["vulnerability_scanning"]["web"]
        assert "nuclei" in web_tools, "nuclei must be in vulnerability_scanning.web"

    def test_dalfox_in_vuln_scanning_web(self):
        from src.workflow.decision_engine import STAGE_TOOL_MATRIX
        web_tools = STAGE_TOOL_MATRIX["vulnerability_scanning"]["web"]
        assert "dalfox" in web_tools, "dalfox must be in vulnerability_scanning.web"

    def test_searchsploit_in_vuln_scanning_web(self):
        from src.workflow.decision_engine import STAGE_TOOL_MATRIX
        web_tools = STAGE_TOOL_MATRIX["vulnerability_scanning"]["web"]
        assert "searchsploit" in web_tools, "searchsploit must be in vulnerability_scanning.web"

    def test_corsy_in_vuln_scanning_web(self):
        from src.workflow.decision_engine import STAGE_TOOL_MATRIX
        web_tools = STAGE_TOOL_MATRIX["vulnerability_scanning"]["web"]
        assert "corsy" in web_tools, "corsy must be in vulnerability_scanning.web"

    def test_minimum_tool_guarantee_code_exists(self):
        """Verify minimum tool guarantee logic exists in select_tools."""
        import src.workflow.decision_engine as de
        source = open(de.__file__).read()
        assert "Minimum tool guarantee" in source or "fallback" in source.lower(), (
            "DecisionEngine must have minimum tool guarantee logic"
        )


# ---------------------------------------------------------------------------
# P3-6: Shodan API key pre-validation
# ---------------------------------------------------------------------------

class TestShodanKeyValidation:
    """Verify Shodan wrapper validates API key format before HTTP calls."""

    def test_key_regex_exists(self):
        from src.tools.recon.osint.shodan_wrapper import _SHODAN_KEY_RE
        assert _SHODAN_KEY_RE is not None

    def test_valid_key_passes(self):
        from src.tools.recon.osint.shodan_wrapper import _SHODAN_KEY_RE
        assert _SHODAN_KEY_RE.match("aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")

    def test_empty_key_fails(self):
        from src.tools.recon.osint.shodan_wrapper import _SHODAN_KEY_RE
        assert not _SHODAN_KEY_RE.match("")

    def test_short_key_fails(self):
        from src.tools.recon.osint.shodan_wrapper import _SHODAN_KEY_RE
        assert not _SHODAN_KEY_RE.match("abc123")

    def test_key_with_spaces_fails(self):
        from src.tools.recon.osint.shodan_wrapper import _SHODAN_KEY_RE
        assert not _SHODAN_KEY_RE.match("abc 123 def ghi jkl mno pqr stu")

    def test_api_run_checks_key(self):
        """Verify _api_run source contains key validation."""
        import src.tools.recon.osint.shodan_wrapper as sw
        source = open(sw.__file__).read()
        assert "_SHODAN_KEY_RE" in source and "_api_run" in source


# ---------------------------------------------------------------------------
# P3-7: sslscan parser hardening
# ---------------------------------------------------------------------------

class TestSslscanParserHardening:
    """Verify improved weak cipher regex and Heartbleed detection."""

    def _parser(self):
        from src.tools.crypto.sslscan_wrapper import SslscanWrapper
        w = SslscanWrapper.__new__(SslscanWrapper)
        w.name = "sslscan"
        return w

    def test_weak_cipher_rc4(self):
        parser = self._parser()
        output = "  Accepted  TLSv1.2  128 bits  RC4-SHA\n"
        findings = parser.parse_output(output, "test.com")
        assert any("RC4" in f.title for f in findings), "Should detect RC4"

    def test_weak_cipher_des(self):
        parser = self._parser()
        output = "  Accepted  TLSv1.0  56 bits   DES-CBC-SHA\n"
        findings = parser.parse_output(output, "test.com")
        assert any("DES" in f.title for f in findings), "Should detect DES"

    def test_weak_cipher_null(self):
        parser = self._parser()
        output = "  Accepted  TLSv1.2  0 bits    NULL-SHA256\n"
        findings = parser.parse_output(output, "test.com")
        assert any("NULL" in f.title for f in findings), "Should detect NULL cipher"

    def test_weak_cipher_3des(self):
        parser = self._parser()
        output = "  Accepted  TLSv1.2  168 bits  DES-CBC3-SHA\n"
        findings = parser.parse_output(output, "test.com")
        # DES-CBC3-SHA contains both DES and CBC3
        assert any(f.title for f in findings), "Should detect 3DES/DES variant"

    def test_strong_cipher_no_finding(self):
        parser = self._parser()
        output = "  Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384\n"
        findings = parser.parse_output(output, "test.com")
        weak_findings = [f for f in findings if "Weak Cipher" in f.title]
        assert len(weak_findings) == 0, "AES-GCM should not be flagged"

    def test_heartbleed_vulnerable(self):
        parser = self._parser()
        output = "Heartbleed:    vulnerable\n"
        findings = parser.parse_output(output, "test.com")
        assert any("Heartbleed" in f.title for f in findings), "Should detect Heartbleed"

    def test_heartbleed_not_vulnerable(self):
        parser = self._parser()
        output = "Heartbleed:    NOT vulnerable\n"
        findings = parser.parse_output(output, "test.com")
        assert not any("Heartbleed" in f.title for f in findings), "Should NOT flag 'NOT vulnerable'"

    def test_sslv3_enabled(self):
        parser = self._parser()
        output = "  SSLv3   enabled\n"
        findings = parser.parse_output(output, "test.com")
        assert any("SSLv3" in f.title for f in findings)

    def test_tlsv10_enabled(self):
        parser = self._parser()
        output = "  TLSv1.0   enabled\n"
        findings = parser.parse_output(output, "test.com")
        assert any("TLSv1.0" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Cross-cutting edge case tests."""

    def test_decision_engine_importable(self):
        mod = importlib.import_module("src.workflow.decision_engine")
        assert hasattr(mod, "STAGE_TOOL_MATRIX")
        assert hasattr(mod, "DecisionEngine")

    def test_sslscan_empty_output(self):
        from src.tools.crypto.sslscan_wrapper import SslscanWrapper
        w = SslscanWrapper.__new__(SslscanWrapper)
        w.name = "sslscan"
        findings = w.parse_output("", "test.com")
        assert findings == []

    def test_shodan_key_regex_special_chars_fail(self):
        from src.tools.recon.osint.shodan_wrapper import _SHODAN_KEY_RE
        # Keys with special characters should be rejected
        assert not _SHODAN_KEY_RE.match("sk-lm-A4phGljJ:WzSjYz72O7")
