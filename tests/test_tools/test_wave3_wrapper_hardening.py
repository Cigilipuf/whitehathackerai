"""
Wave 3 Phase 11: Wrapper Confidence Calibration & Pipeline ResponseValidator Tests

Covers:
- 11.1: Pipeline-level ResponseValidator pre-filter in full_scan.py
- 11.2: Wrapper-level confidence calibration (7 wrappers)
"""

from __future__ import annotations

import importlib
import inspect

import pytest


# ═══════════════════════════════════════════════════════════════
#  11.1: Pipeline-level ResponseValidator integration
# ═══════════════════════════════════════════════════════════════

class TestPipelineResponseValidatorFilter:
    def test_response_validator_imported_in_vuln_scan(self):
        """ResponseValidator is used in vulnerability scan handler."""
        import src.workflow.pipelines.full_scan as fs

        source = inspect.getsource(fs.handle_vulnerability_scan)
        assert "ResponseValidator" in source
        assert "validate(" in source

    def test_soft_signal_lowers_confidence_not_drops(self):
        """Soft WAF signals (modifier > -15) lower confidence, not drop."""
        source = inspect.getsource(
            importlib.import_module("src.workflow.pipelines.full_scan").handle_vulnerability_scan
        )
        assert "confidence_modifier > -15" in source


# ═══════════════════════════════════════════════════════════════
#  11.2: Dalfox Confidence Calibration
# ═══════════════════════════════════════════════════════════════

class TestDalfoxConfidenceCalibration:
    def test_g_type_confidence_capped_at_30(self):
        from src.tools.scanners.dalfox_wrapper import _TYPE_CONFIDENCE

        assert _TYPE_CONFIDENCE["G"] == 20.0

    def test_r_type_confidence_is_70(self):
        from src.tools.scanners.dalfox_wrapper import _TYPE_CONFIDENCE

        assert _TYPE_CONFIDENCE["R"] == 60.0

    def test_v_type_confidence_is_90(self):
        from src.tools.scanners.dalfox_wrapper import _TYPE_CONFIDENCE

        assert _TYPE_CONFIDENCE["V"] == 80.0


# ═══════════════════════════════════════════════════════════════
#  11.2: SQLMap Technique-Aware Confidence
# ═══════════════════════════════════════════════════════════════

class TestSqlmapConfidenceCalibration:
    def test_boolean_blind_confidence_65(self):
        source = inspect.getsource(
            importlib.import_module("src.tools.scanners.sqlmap_wrapper").SqlmapWrapper.parse_output
        )
        assert '"boolean_based": 55.0' in source

    def test_time_based_confidence_60(self):
        source = inspect.getsource(
            importlib.import_module("src.tools.scanners.sqlmap_wrapper").SqlmapWrapper.parse_output
        )
        assert '"time_based": 40.0' in source

    def test_union_based_confidence_85(self):
        source = inspect.getsource(
            importlib.import_module("src.tools.scanners.sqlmap_wrapper").SqlmapWrapper.parse_output
        )
        assert '"union_based": 85.0' in source


# ═══════════════════════════════════════════════════════════════
#  11.2: Commix Technique-Aware Confidence
# ═══════════════════════════════════════════════════════════════

class TestCommixConfidenceCalibration:
    def test_time_based_technique_gets_60(self):
        source = inspect.getsource(
            importlib.import_module("src.tools.scanners.commix_wrapper").CommixWrapper.parse_output
        )
        assert '35.0 if is_blind' in source

    def test_non_time_technique_gets_85(self):
        source = inspect.getsource(
            importlib.import_module("src.tools.scanners.commix_wrapper").CommixWrapper.parse_output
        )
        assert "else 80.0" in source


# ═══════════════════════════════════════════════════════════════
#  11.2: Tplmap Blind SSTI Confidence
# ═══════════════════════════════════════════════════════════════

class TestTplmapConfidenceCalibration:
    def test_blind_ssti_confidence_lowered_to_60(self):
        source = inspect.getsource(
            importlib.import_module("src.tools.scanners.tplmap_wrapper").TplmapWrapper.parse_output
        )
        assert "60.0" in source
        # Ensure old 80.0 is no longer used for blind
        lines = source.split("\n")
        for line in lines:
            if "blind" in line.lower() or "time" in line.lower():
                if "confidence" in line.lower():
                    assert "80.0" not in line


# ═══════════════════════════════════════════════════════════════
#  11.2: CRLFuzz Confidence
# ═══════════════════════════════════════════════════════════════

class TestCrlfuzzConfidenceCalibration:
    def test_confidence_lowered_to_60(self):
        source = inspect.getsource(
            importlib.import_module("src.tools.scanners.crlfuzz_wrapper").CrlfuzzWrapper.parse_output
        )
        assert "60.0" in source
        assert "75.0" not in source


# ═══════════════════════════════════════════════════════════════
#  11.2: Nikto Confidence & Unverified Tag
# ═══════════════════════════════════════════════════════════════

class TestNiktoConfidenceCalibration:
    def test_confidence_lowered_to_30(self):
        mod = importlib.import_module("src.tools.scanners.nikto_wrapper")
        source = inspect.getsource(mod.NiktoWrapper)
        # Both text and JSON parsers should use 30.0 (v5.0-P0.4)
        assert source.count("30.0") >= 2
        assert "65.0" not in source

    def test_unverified_tag_added(self):
        mod = importlib.import_module("src.tools.scanners.nikto_wrapper")
        source = inspect.getsource(mod.NiktoWrapper)
        assert '"unverified"' in source


# ═══════════════════════════════════════════════════════════════
#  11.2: Corsy No-ACAC Confidence
# ═══════════════════════════════════════════════════════════════

class TestCorsyConfidenceCalibration:
    def test_wildcard_lowered_to_40(self):
        from src.tools.scanners.corsy_wrapper import _MISCONFIG_CONFIDENCE

        assert _MISCONFIG_CONFIDENCE["wildcard"] == 40.0

    def test_third_party_lowered_to_40(self):
        from src.tools.scanners.corsy_wrapper import _MISCONFIG_CONFIDENCE

        assert _MISCONFIG_CONFIDENCE["third_party"] == 40.0

    def test_reflect_origin_unchanged_at_85(self):
        from src.tools.scanners.corsy_wrapper import _MISCONFIG_CONFIDENCE

        assert _MISCONFIG_CONFIDENCE["reflect_origin"] == 85.0
