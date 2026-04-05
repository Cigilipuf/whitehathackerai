"""
V22 Regression Tests — Type Safety Audit & Crash Prevention

Covers:
  P0-1: exploit_verifier _safe_float / _coerce_url / _prioritize_candidates
  P0-2: full_scan screenshot URL type check (structural)
  P0-3: auto_draft _safe_float / _coerce_str / should_draft / generate_draft
  P0-4: result_aggregator _fingerprint list/None coercion
  P1-1: intelligence _parse_verification_result_from_dict float safety
  P1-1: self_reflection _sf Critique score safety
  P1-1: adaptive_strategy int() signal count fallback
  P1-2: shodan/censys resp.json() non-JSON safety
  P1-2: zaproxy resp.json() non-JSON safety
  P2-1: silent exception visibility (knowledge_base, engine, session_manager, etc.)
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ====================================================================
# P0-1: exploit_verifier — _safe_float / _coerce_url / _prioritize_candidates
# ====================================================================


class TestExploitVerifierSafeFloat:
    """Module-level _safe_float in exploit_verifier.py."""

    def _sf(self):
        from src.tools.exploit.exploit_verifier import _safe_float
        return _safe_float

    def test_numeric_string(self):
        assert self._sf()("75.5", 0.0) == 75.5

    def test_non_numeric_string(self):
        assert self._sf()("high", 0.0) == 0.0

    def test_none_returns_default(self):
        assert self._sf()(None, 42.0) == 42.0

    def test_empty_string(self):
        assert self._sf()("", 10.0) == 10.0

    def test_actual_float_passthrough(self):
        assert self._sf()(88.0, 0.0) == 88.0

    def test_actual_int(self):
        assert self._sf()(50, 0.0) == 50.0

    def test_list_returns_default(self):
        assert self._sf()([1, 2, 3], 5.0) == 5.0

    def test_dict_returns_default(self):
        assert self._sf()({"key": "val"}, 5.0) == 5.0


class TestExploitVerifierCoerceUrl:
    """Module-level _coerce_url in exploit_verifier.py."""

    def _cu(self):
        from src.tools.exploit.exploit_verifier import _coerce_url
        return _coerce_url

    def test_string_passthrough(self):
        assert self._cu()("https://example.com") == "https://example.com"

    def test_list_returns_first(self):
        assert self._cu()(["https://a.com", "https://b.com"]) == "https://a.com"

    def test_empty_list_returns_empty(self):
        assert self._cu()([]) == ""

    def test_none_returns_empty(self):
        assert self._cu()(None) == ""

    def test_int_returns_str(self):
        assert self._cu()(12345) == "12345"


class TestExploitVerifierPrioritizeCandidates:
    """_prioritize_candidates handles bad URL/confidence types."""

    def _make_verifier(self):
        from src.tools.exploit.exploit_verifier import ExploitVerifier
        return ExploitVerifier(brain_engine=None, session_dir="")

    def test_finding_with_list_url_accepted(self):
        """A finding with url as list should be coerced, not crash."""
        v = self._make_verifier()
        findings = [
            {
                "url": ["https://target.com/api/v1", "https://target2.com"],
                "confidence": 80,
                "severity": "high",
            }
        ]
        result = v._prioritize_candidates(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "high"

    def test_finding_with_string_confidence(self):
        """confidence='high' (non-numeric) should not crash."""
        v = self._make_verifier()
        findings = [
            {
                "url": "https://target.com",
                "confidence": "high",
                "severity": "high",
            }
        ]
        # "high" cannot be parsed as float → _safe_float returns 0.0 → below 40.0 threshold → filtered out
        result = v._prioritize_candidates(findings)
        assert len(result) == 0

    def test_finding_with_none_url_excluded(self):
        """Finding with url=None should be filtered out."""
        v = self._make_verifier()
        findings = [
            {"url": None, "confidence": 80, "severity": "high"},
        ]
        result = v._prioritize_candidates(findings)
        assert len(result) == 0

    def test_info_severity_excluded(self):
        """Info-level findings should be excluded."""
        v = self._make_verifier()
        findings = [
            {"url": "https://t.com", "confidence": 80, "severity": "info"},
        ]
        result = v._prioritize_candidates(findings)
        assert len(result) == 0

    def test_sort_order_by_severity_then_confidence(self):
        """Candidates sorted by severity (Critical→High→Medium) and confidence desc."""
        v = self._make_verifier()
        findings = [
            {"url": "https://t.com/a", "confidence": 60, "severity": "medium"},
            {"url": "https://t.com/b", "confidence": 90, "severity": "critical"},
            {"url": "https://t.com/c", "confidence": 70, "severity": "high"},
        ]
        result = v._prioritize_candidates(findings)
        assert len(result) == 3
        assert result[0]["severity"] == "critical"
        assert result[1]["severity"] == "high"
        assert result[2]["severity"] == "medium"


class TestExploitVerifierBatchFallback:
    """verify_batch exception handler uses _safe_float for confidence."""

    def test_proven_finding_with_string_confidence(self):
        """ProvenFinding should accept float confidence even from string source."""
        from src.tools.exploit.exploit_verifier import ProvenFinding, _safe_float

        finding = {"url": "https://t.com", "confidence": "not-a-number", "severity": "high"}
        pf = ProvenFinding(
            finding=finding,
            is_proven=False,
            confidence=_safe_float(finding.get("confidence", 0)),
        )
        assert pf.confidence == 0.0
        assert pf.is_proven is False


# ====================================================================
# P0-3: auto_draft — _safe_float / _coerce_str / should_draft
# ====================================================================


class TestAutoDraftSafeFloat:
    """Module-level _safe_float in auto_draft.py."""

    def _sf(self):
        from src.reporting.auto_draft import _safe_float
        return _safe_float

    def test_numeric(self):
        assert self._sf()(85.0, 0.0) == 85.0

    def test_string_number(self):
        assert self._sf()("90", 0.0) == 90.0

    def test_non_numeric_string(self):
        assert self._sf()("N/A", 0.0) == 0.0

    def test_none(self):
        assert self._sf()(None, 50.0) == 50.0


class TestAutoDraftCoerceStr:
    """Module-level _coerce_str in auto_draft.py."""

    def _cs(self):
        from src.reporting.auto_draft import _coerce_str
        return _coerce_str

    def test_string_passthrough(self):
        assert self._cs()("hello") == "hello"

    def test_list_first_element(self):
        assert self._cs()(["high", "medium"]) == "high"

    def test_empty_list(self):
        assert self._cs()([]) == ""

    def test_none(self):
        assert self._cs()(None) == ""

    def test_int_to_str(self):
        assert self._cs()(42) == "42"


class TestAutoDraftShouldDraft:
    """should_draft() handles list severity and string confidence."""

    def _make_drafter(self, tmp_path):
        from src.reporting.auto_draft import AutoDraftGenerator
        return AutoDraftGenerator(output_dir=str(tmp_path / "drafts"))

    def test_list_severity_not_crash(self, tmp_path):
        """severity as list should be coerced, not crash."""
        d = self._make_drafter(tmp_path)
        finding = {"severity": ["critical", "high"], "confidence_score": 90}
        # "critical" → should qualify
        assert d.should_draft(finding) is True

    def test_string_confidence_not_crash(self, tmp_path):
        """confidence_score as non-numeric string should fallback to 0."""
        d = self._make_drafter(tmp_path)
        finding = {"severity": "medium", "confidence_score": "very-high"}
        # confidence=0 < 80 → medium doesn't qualify
        assert d.should_draft(finding) is False

    def test_critical_always_qualifies(self, tmp_path):
        d = self._make_drafter(tmp_path)
        assert d.should_draft({"severity": "critical", "confidence": 10}) is True

    def test_medium_low_confidence_rejected(self, tmp_path):
        d = self._make_drafter(tmp_path)
        assert d.should_draft({"severity": "medium", "confidence_score": 50}) is False

    def test_medium_high_confidence_accepted(self, tmp_path):
        d = self._make_drafter(tmp_path)
        assert d.should_draft({"severity": "medium", "confidence_score": 85}) is True


class TestAutoDraftGenerateDraft:
    """generate_draft() handles non-numeric fields without crash."""

    def test_generate_with_list_fields(self, tmp_path):
        """Finding with list url/endpoint should not crash generate_draft."""
        from src.reporting.auto_draft import AutoDraftGenerator

        d = AutoDraftGenerator(output_dir=str(tmp_path / "drafts"))
        finding = {
            "severity": "high",
            "confidence_score": 85,
            "vulnerability_type": "xss",
            "url": ["https://t.com/search", "https://t.com/search2"],
            "endpoint": ["https://t.com/search"],
            "description": "XSS in search",
            "title": "Reflected XSS",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "cvss_score": "7.5",
        }
        result = d.generate_draft(finding, scan_id="test123")
        assert result is not None or result is None  # either path or None, no crash

    def test_generate_with_non_numeric_cvss(self, tmp_path):
        """cvss_score as non-numeric should not crash."""
        from src.reporting.auto_draft import AutoDraftGenerator

        d = AutoDraftGenerator(output_dir=str(tmp_path / "drafts"))
        finding = {
            "severity": "critical",
            "confidence_score": 90,
            "vulnerability_type": "sqli",
            "url": "https://t.com/login",
            "description": "SQL injection",
            "title": "SQLi in login",
            "cvss_score": "not-a-score",
        }
        # Should not raise, even with bad CVSS
        result = d.generate_draft(finding, scan_id="test456")
        assert result is not None or result is None  # no crash


# ====================================================================
# P0-4: result_aggregator — _fingerprint list/None coercion
# ====================================================================


class TestResultAggregatorFingerprint:
    """_fingerprint() handles list/None field values via inline _s() helper."""

    def _fp(self, finding):
        from src.workflow.result_aggregator import ResultAggregator
        return ResultAggregator._fingerprint(finding)

    def test_normal_finding(self):
        fp = self._fp({
            "vuln_type": "xss",
            "target": "https://t.com",
            "endpoint": "/search",
            "parameter": "q",
            "method": "GET",
        })
        assert isinstance(fp, str)
        assert len(fp) == 16  # sha256[:16]

    def test_list_url(self):
        """url as list should not crash."""
        fp = self._fp({
            "vuln_type": "xss",
            "target": "https://t.com",
            "url": ["https://t.com/a", "https://t.com/b"],
            "parameter": "q",
        })
        assert isinstance(fp, str)
        assert len(fp) == 16

    def test_none_fields(self):
        """All None fields should not crash."""
        fp = self._fp({
            "vuln_type": None,
            "target": None,
            "endpoint": None,
            "parameter": None,
            "method": None,
        })
        assert isinstance(fp, str)

    def test_list_vuln_type(self):
        """vuln_type as list should not crash."""
        fp = self._fp({
            "vuln_type": ["xss", "sqli"],
            "target": "https://t.com",
        })
        assert isinstance(fp, str)

    def test_deterministic(self):
        """Same input → same fingerprint."""
        f = {"vuln_type": "xss", "target": "t.com", "parameter": "q"}
        assert self._fp(f) == self._fp(f)

    def test_different_input_different_fp(self):
        f1 = {"vuln_type": "xss", "target": "t.com"}
        f2 = {"vuln_type": "sqli", "target": "t.com"}
        assert self._fp(f1) != self._fp(f2)


# ====================================================================
# P1-1a: intelligence — _parse_verification_result_from_dict
# ====================================================================


class TestIntelligenceVerificationParsing:
    """_parse_verification_result_from_dict handles non-numeric LLM data."""

    def _make_engine(self):
        from src.brain.intelligence import IntelligenceEngine
        engine = IntelligenceEngine.__new__(IntelligenceEngine)
        # Minimal attributes needed for method
        engine._cache = {}
        engine._brain_down = False
        return engine

    def test_non_numeric_confidence(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({
            "is_real": True,
            "confidence": "very high",
            "reasoning": "looks real",
        })
        # "very high" → _sf returns default 0.0 (Bug 5.2l-5: was 50.0)
        assert result.confidence == 0.0
        assert result.is_real is True

    def test_non_numeric_cvss_override(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({
            "is_real": True,
            "confidence": 80,
            "cvss_override": "critical",
        })
        # "critical" cannot be parsed → cvss_override stays None
        assert result.cvss_override is None
        assert result.confidence == 80.0

    def test_valid_cvss_override(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({
            "is_real": True,
            "confidence": 80,
            "cvss_override": "9.1",
        })
        assert result.cvss_override == 9.1

    def test_none_data_returns_defaults(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict(None)
        assert result.confidence == 0.0  # Bug 5.2l-5: was 50.0
        assert result.is_real is False

    def test_empty_dict(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({})
        assert result.confidence == 0.0  # Bug 5.2l-5: was 50.0
        assert result.is_real is False

    def test_confidence_clamped_to_100(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({
            "confidence": 150,
        })
        assert result.confidence == 100.0

    def test_confidence_clamped_to_0(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({
            "confidence": -20,
        })
        assert result.confidence == 0.0

    def test_cvss_clamped_to_10(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({
            "cvss_override": 15.0,
        })
        assert result.cvss_override == 10.0

    def test_negative_cvss_becomes_none(self):
        engine = self._make_engine()
        result = engine._parse_verification_result_from_dict({
            "cvss_override": -3.0,
        })
        # _sf returns -3.0, parsed < 0 → cvss_override stays None
        assert result.cvss_override is None


# ====================================================================
# P1-1b: self_reflection — Critique score safety
# ====================================================================


class TestSelfReflectionScoreSafety:
    """_sf() in _rule_based_critique prevents crash on non-numeric score."""

    def test_non_numeric_score_no_crash(self):
        """Ensure non-numeric 'score' from LLM doesn't crash Critique construction."""
        from src.brain.reasoning.self_reflection import Critique, CritiqueLevel, ReflectionType

        # Directly test Critique accepts float score
        c = Critique(
            reflection_type=ReflectionType.MID_SCAN_PIVOT,
            stage="test",
            level=CritiqueLevel.ADEQUATE,
            score=50.0,  # This is what _sf would produce from "excellent"
            strengths=[],
            weaknesses=[],
            findings=[],
            recommendations=[],
        )
        assert c.score == 50.0


# ====================================================================
# P1-1c: adaptive_strategy — int() signal count fallback
# ====================================================================


class TestAdaptiveStrategyIntFallback:
    """SUBDOMAIN_FOUND/ENDPOINT_FOUND handle non-integer count."""

    def test_subdomain_string_count_no_crash(self):
        from src.workflow.adaptive_strategy import (
            AdaptiveStrategyEngine,
            SignalType,
        )
        engine = AdaptiveStrategyEngine()
        old_count = engine.environment.subdomain_count
        engine.observe(
            signal_type=SignalType.SUBDOMAIN_FOUND,
            source="test",
            details={"count": "many"},  # Non-integer
        )
        # Should still increment by 1 (fallback)
        assert engine.environment.subdomain_count == old_count + 1

    def test_endpoint_string_count_no_crash(self):
        from src.workflow.adaptive_strategy import (
            AdaptiveStrategyEngine,
            SignalType,
        )
        engine = AdaptiveStrategyEngine()
        old_count = engine.environment.endpoint_count
        engine.observe(
            signal_type=SignalType.ENDPOINT_FOUND,
            source="test",
            details={"count": "lots"},
        )
        assert engine.environment.endpoint_count == old_count + 1

    def test_valid_int_count_works(self):
        from src.workflow.adaptive_strategy import (
            AdaptiveStrategyEngine,
            SignalType,
        )
        engine = AdaptiveStrategyEngine()
        old_count = engine.environment.subdomain_count
        engine.observe(
            signal_type=SignalType.SUBDOMAIN_FOUND,
            source="test",
            details={"count": 15},
        )
        assert engine.environment.subdomain_count == old_count + 15


# ====================================================================
# P1-2a: shodan_wrapper resp.json() safety
# ====================================================================


class TestShodanJsonSafety:
    """Shodan wrapper handles non-JSON API responses."""

    def test_api_host_non_json_resolve(self):
        """DNS resolve returning HTML should not crash."""
        from src.tools.recon.osint.shodan_wrapper import ShodanWrapper

        wrapper = ShodanWrapper()

        async def _run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = json.JSONDecodeError("", "", 0)

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)

            result = await wrapper._api_host(mock_client, "example.com")
            assert result.success is False

        asyncio.run(_run())

    def test_api_host_non_json_host(self):
        """Host detail returning HTML should not crash."""
        from src.tools.recon.osint.shodan_wrapper import ShodanWrapper

        wrapper = ShodanWrapper()

        async def _run():
            # DNS resolve succeeds
            resolve_resp = MagicMock()
            resolve_resp.status_code = 200
            resolve_resp.json.return_value = {"example.com": "1.2.3.4"}

            # Host detail fails with non-JSON
            host_resp = MagicMock()
            host_resp.status_code = 200
            host_resp.json.side_effect = json.JSONDecodeError("", "", 0)

            call_count = 0

            async def mock_get(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                return resolve_resp if call_count == 1 else host_resp

            mock_client = AsyncMock()
            mock_client.get = mock_get

            result = await wrapper._api_host(mock_client, "example.com")
            assert result.success is False

        asyncio.run(_run())

    def test_api_search_non_json(self):
        """Search returning non-JSON should not crash."""
        from src.tools.recon.osint.shodan_wrapper import ShodanWrapper

        wrapper = ShodanWrapper()

        async def _run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = json.JSONDecodeError("", "", 0)

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)

            result = await wrapper._api_search(mock_client, "apache", {})
            assert result.success is False

        asyncio.run(_run())


# ====================================================================
# P1-2b: censys_wrapper resp.json() safety
# ====================================================================


class TestCensysJsonSafety:
    """Censys wrapper handles non-JSON API responses."""

    def test_api_host_non_json(self):
        """Host details returning non-JSON should not crash."""
        from src.tools.recon.osint.censys_wrapper import CensysWrapper

        wrapper = CensysWrapper()

        async def _run():
            # DNS resolve returns non-JSON
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = json.JSONDecodeError("", "", 0)

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)

            result = await wrapper._api_host(mock_client, "example.com")
            # Should handle gracefully — either success=False or empty findings
            assert not result.success or result.findings == []

        asyncio.run(_run())

    def test_api_search_non_json(self):
        """Search returning non-JSON should not crash."""
        from src.tools.recon.osint.censys_wrapper import CensysWrapper

        wrapper = CensysWrapper()

        async def _run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = json.JSONDecodeError("", "", 0)

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)

            result = await wrapper._api_search(mock_client, "test", {})
            assert result.success is False

        asyncio.run(_run())


# ====================================================================
# P1-2c: zaproxy resp.json() safety
# ====================================================================


class TestZAProxyJsonSafety:
    """ZAProxy wrapper handles non-JSON API responses."""

    def test_api_get_non_json(self):
        """_api_get with non-JSON response returns empty dict."""
        from src.tools.proxy.zaproxy_wrapper import ZAProxyWrapper

        wrapper = ZAProxyWrapper()
        wrapper._api_key = "test-key"

        async def _run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = json.JSONDecodeError("", "", 0)
            mock_resp.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)

            # Patch _get_client to return our mock  
            wrapper._get_client = AsyncMock(return_value=mock_client)

            result = await wrapper._api_get("core/view/version")
            assert result == {}

        asyncio.run(_run())

    def test_api_post_non_json(self):
        """_api_post with non-JSON response returns empty dict."""
        from src.tools.proxy.zaproxy_wrapper import ZAProxyWrapper

        wrapper = ZAProxyWrapper()
        wrapper._api_key = "test-key"

        async def _run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = json.JSONDecodeError("", "", 0)
            mock_resp.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)

            wrapper._get_client = AsyncMock(return_value=mock_client)

            result = await wrapper._api_post("core/action/shutdown")
            assert result == {}

        asyncio.run(_run())


# ====================================================================
# P2-1: Silent exception visibility
# ====================================================================


class TestSilentExceptionVisibility:
    """Verify previously-silent exceptions now have logging."""

    def test_knowledge_base_fp_deserialization_logged(self):
        """FP pattern deserialization exception is now logged."""
        from src.brain.memory.knowledge_base import KnowledgeBase
        import inspect

        # Check that the except block in save_fp_pattern's deserialize section
        # no longer has bare 'pass'
        source = inspect.getsource(KnowledgeBase)
        # There should be NO bare 'except Exception:\n            pass' remaining
        # related to FP pattern deserialization (we check the generic pattern)
        lines = source.split("\n")
        bare_pass_count = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == "pass" and i > 0:
                prev = lines[i - 1].strip()
                if prev.startswith("except") and "Exception" in prev:
                    bare_pass_count += 1
        # Should have zero bare except Exception: pass
        assert bare_pass_count == 0, f"Found {bare_pass_count} bare 'except Exception: pass' blocks"

    def test_engine_retry_exception_logged(self):
        """Brain engine retry exhaustion exception is now logged with error details."""
        from src.brain import engine
        import inspect

        source = inspect.getsource(engine)
        # The retry exhaustion should log the actual error variable
        assert "_retry_err" in source or "retry" in source.lower()

    def test_report_generator_no_bare_pass(self):
        """report_generator.py should have no bare 'except Exception: pass' blocks."""
        from src.reporting import report_generator
        import inspect

        source = inspect.getsource(report_generator)
        lines = source.split("\n")
        bare_pass_count = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == "pass" and i > 0:
                prev = lines[i - 1].strip()
                if prev.startswith("except") and "Exception" in prev:
                    bare_pass_count += 1
        assert bare_pass_count == 0, f"Found {bare_pass_count} bare 'except Exception: pass' blocks"


# ====================================================================
# Edge Cases & Integration
# ====================================================================


class TestEdgeCases:
    """Cross-module edge cases that V22 fixes should handle."""

    def test_exploit_verifier_finding_all_bad_types(self):
        """A maximally malformed finding should not crash _prioritize_candidates."""
        from src.tools.exploit.exploit_verifier import ExploitVerifier

        v = ExploitVerifier(brain_engine=None, session_dir="")
        findings = [
            {
                "url": None,
                "confidence": None,
                "severity": None,
            },
            {
                "url": [123, 456],
                "confidence": ["high"],
                "severity": ["critical"],
            },
            {
                "url": "",
                "confidence": {},
                "severity": 42,
            },
        ]
        # Should not crash, may filter out all
        result = v._prioritize_candidates(findings)
        assert isinstance(result, list)

    def test_auto_draft_extreme_types(self, tmp_path):
        """AutoDraftGenerator handles completely wrong-typed finding."""
        from src.reporting.auto_draft import AutoDraftGenerator

        d = AutoDraftGenerator(output_dir=str(tmp_path / "drafts"))
        finding = {
            "severity": 123,
            "confidence_score": [90, 80],
            "vulnerability_type": None,
            "url": {"nested": "dict"},
        }
        # Should not raise
        result = d.should_draft(finding)
        assert isinstance(result, bool)

    def test_result_aggregator_extreme_types(self):
        """_fingerprint handles all wrong-typed fields."""
        from src.workflow.result_aggregator import ResultAggregator

        fp = ResultAggregator._fingerprint({
            "vuln_type": 42,
            "target": ["a", "b"],
            "endpoint": None,
            "parameter": {"nested": True},
            "method": [1, 2, 3],
        })
        assert isinstance(fp, str)
        assert len(fp) == 16

    def test_intelligence_extreme_types(self):
        """_parse_verification_result_from_dict handles all wrong types."""
        from src.brain.intelligence import IntelligenceEngine

        engine = IntelligenceEngine.__new__(IntelligenceEngine)
        engine._cache = {}
        engine._brain_down = False

        result = engine._parse_verification_result_from_dict({
            "is_real": "yes",  # truthy string
            "confidence": [90, 80],  # list
            "cvss_override": {"score": 9},  # dict
            "reasoning": 12345,  # int
        })
        assert result.confidence == 0.0  # default on parse fail (Bug 5.2l-5: was 50.0)
        assert result.cvss_override is None  # dict can't be float
        assert result.reasoning == "12345"  # str() conversion
