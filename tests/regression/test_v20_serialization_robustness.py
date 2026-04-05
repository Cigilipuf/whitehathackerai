"""
V20 Regression Tests — Serialization Safety & Pipeline Robustness

Covers:
  P0-1: WAFResult/WAFStrategy to_dict() + from_dict()
  P0-2: Orchestrator checkpoint retry path (sync+checkpoint together)
  P0-3: Checkpoint on stage failure/timeout
  P0-4: Safe WAFResult consumer (_get_waf_result helper)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch, AsyncMock
import asyncio

import pytest


# ====================================================================
# P0-1: WAFResult / WAFStrategy to_dict() + from_dict()
# ====================================================================


class TestWAFStrategyToDict:
    def test_basic_serialization(self):
        from src.tools.scanners.waf_strategy import WAFStrategy

        s = WAFStrategy(
            waf_name="cloudflare",
            encoding_chain=["unicode", "chunked"],
            rate_adjustment=0.5,
            header_tweaks={"X-Forwarded-For": "127.0.0.1"},
            payload_transforms=["double_url_encode"],
            nuclei_rate=15,
            notes="Test strategy",
        )
        d = s.to_dict()
        assert d["waf_name"] == "cloudflare"
        assert d["encoding_chain"] == ["unicode", "chunked"]
        assert d["rate_adjustment"] == 0.5
        assert d["header_tweaks"] == {"X-Forwarded-For": "127.0.0.1"}
        assert d["payload_transforms"] == ["double_url_encode"]
        assert d["nuclei_rate"] == 15
        assert d["notes"] == "Test strategy"
        # Verify JSON-serializable
        json.dumps(d)

    def test_default_values(self):
        from src.tools.scanners.waf_strategy import WAFStrategy

        s = WAFStrategy(waf_name="minimal")
        d = s.to_dict()
        assert d["waf_name"] == "minimal"
        assert d["encoding_chain"] == []
        assert d["rate_adjustment"] == 1.0
        assert d["nuclei_rate"] is None

    def test_from_dict_roundtrip(self):
        from src.tools.scanners.waf_strategy import WAFStrategy

        original = WAFStrategy(
            waf_name="akamai",
            encoding_chain=["slow_rate"],
            rate_adjustment=0.3,
            header_tweaks={"X-Real-IP": "10.0.0.1"},
            payload_transforms=["case_randomize"],
            nuclei_rate=10,
            notes="Akamai evasion",
        )
        d = original.to_dict()
        restored = WAFStrategy.from_dict(d)
        assert restored.waf_name == original.waf_name
        assert restored.encoding_chain == original.encoding_chain
        assert restored.rate_adjustment == original.rate_adjustment
        assert restored.header_tweaks == original.header_tweaks
        assert restored.payload_transforms == original.payload_transforms
        assert restored.nuclei_rate == original.nuclei_rate
        assert restored.notes == original.notes

    def test_from_dict_missing_keys(self):
        from src.tools.scanners.waf_strategy import WAFStrategy

        d = {"waf_name": "unknown"}
        s = WAFStrategy.from_dict(d)
        assert s.waf_name == "unknown"
        assert s.encoding_chain == []
        assert s.rate_adjustment == 1.0
        assert s.nuclei_rate is None

    def test_from_dict_empty(self):
        from src.tools.scanners.waf_strategy import WAFStrategy

        s = WAFStrategy.from_dict({})
        assert s.waf_name == ""
        assert s.encoding_chain == []


class TestWAFResultToDict:
    def test_basic_no_strategy(self):
        from src.tools.scanners.waf_strategy import WAFResult

        r = WAFResult(host="example.com")
        d = r.to_dict()
        assert d["host"] == "example.com"
        assert d["detected"] is False
        assert d["waf_name"] == ""
        assert d["confidence"] == 0.0
        assert d["evidence"] == []
        assert d["strategy"] is None
        json.dumps(d)

    def test_with_strategy(self):
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        strategy = WAFStrategy(
            waf_name="cloudflare",
            encoding_chain=["unicode"],
            nuclei_rate=15,
        )
        r = WAFResult(
            host="target.com",
            detected=True,
            waf_name="cloudflare",
            confidence=0.85,
            evidence=["cf-ray header"],
            strategy=strategy,
        )
        d = r.to_dict()
        assert d["detected"] is True
        assert d["waf_name"] == "cloudflare"
        assert d["confidence"] == 0.85
        assert d["evidence"] == ["cf-ray header"]
        assert d["strategy"]["waf_name"] == "cloudflare"
        assert d["strategy"]["nuclei_rate"] == 15
        json.dumps(d)  # Must be JSON-serializable

    def test_json_serialization_in_metadata(self):
        """Simulate the exact checkpoint serialization path."""
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        strategy = WAFStrategy(waf_name="akamai", rate_adjustment=0.3)
        r = WAFResult(
            host="uber.com",
            detected=True,
            waf_name="akamai",
            confidence=0.9,
            evidence=["x-akamai-session header"],
            strategy=strategy,
        )
        # to_dict() is what sync_from_workflow_state calls
        d = r.to_dict()
        # This is what checkpoint() ultimately does
        metadata = {"waf_result": d, "other_key": "value"}
        serialized = json.dumps(metadata, indent=2)
        restored = json.loads(serialized)
        assert restored["waf_result"]["detected"] is True
        assert restored["waf_result"]["strategy"]["rate_adjustment"] == 0.3

    def test_from_dict_roundtrip_no_strategy(self):
        from src.tools.scanners.waf_strategy import WAFResult

        original = WAFResult(host="test.com")
        d = original.to_dict()
        restored = WAFResult.from_dict(d)
        assert restored.host == original.host
        assert restored.detected == original.detected
        assert restored.strategy is None

    def test_from_dict_roundtrip_with_strategy(self):
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        strategy = WAFStrategy(
            waf_name="cloudflare",
            encoding_chain=["unicode", "chunked"],
            nuclei_rate=15,
        )
        original = WAFResult(
            host="target.com",
            detected=True,
            waf_name="cloudflare",
            confidence=0.85,
            evidence=["cf-ray"],
            strategy=strategy,
        )
        d = original.to_dict()
        restored = WAFResult.from_dict(d)
        assert restored.host == original.host
        assert restored.detected == original.detected
        assert restored.waf_name == original.waf_name
        assert restored.confidence == original.confidence
        assert restored.evidence == original.evidence
        assert restored.strategy is not None
        assert restored.strategy.waf_name == "cloudflare"
        assert restored.strategy.nuclei_rate == 15

    def test_from_dict_missing_keys(self):
        from src.tools.scanners.waf_strategy import WAFResult

        d = {"host": "partial.com", "detected": True}
        r = WAFResult.from_dict(d)
        assert r.host == "partial.com"
        assert r.detected is True
        assert r.strategy is None

    def test_from_dict_empty(self):
        from src.tools.scanners.waf_strategy import WAFResult

        r = WAFResult.from_dict({})
        assert r.host == ""
        assert r.detected is False

    def test_json_roundtrip_full(self):
        """Full JSON serialize → deserialize → from_dict roundtrip."""
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        strategy = WAFStrategy(waf_name="imperva", nuclei_rate=5)
        original = WAFResult(
            host="bank.com",
            detected=True,
            waf_name="imperva",
            confidence=0.7,
            evidence=["incapsula cookie"],
            strategy=strategy,
        )
        json_str = json.dumps(original.to_dict())
        d = json.loads(json_str)
        restored = WAFResult.from_dict(d)
        assert restored.detected is True
        assert restored.strategy.waf_name == "imperva"
        assert restored.strategy.nuclei_rate == 5


# ====================================================================
# P0-4: _get_waf_result helper
# ====================================================================


class TestGetWAFResult:
    def test_none_metadata(self):
        from src.workflow.pipelines.full_scan import _get_waf_result

        state = MagicMock()
        state.metadata = None
        assert _get_waf_result(state) is None

    def test_missing_key(self):
        from src.workflow.pipelines.full_scan import _get_waf_result

        state = MagicMock()
        state.metadata = {}
        assert _get_waf_result(state) is None

    def test_wafresult_object(self):
        from src.workflow.pipelines.full_scan import _get_waf_result
        from src.tools.scanners.waf_strategy import WAFResult

        waf = WAFResult(host="test.com", detected=True, waf_name="cloudflare")
        state = MagicMock()
        state.metadata = {"waf_result": waf}
        result = _get_waf_result(state)
        assert isinstance(result, WAFResult)
        assert result.detected is True
        assert result.waf_name == "cloudflare"

    def test_dict_from_checkpoint(self):
        """After resume, waf_result is a dict from to_dict()."""
        from src.workflow.pipelines.full_scan import _get_waf_result
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        strategy = WAFStrategy(waf_name="akamai", nuclei_rate=10)
        original = WAFResult(
            host="uber.com",
            detected=True,
            waf_name="akamai",
            confidence=0.9,
            strategy=strategy,
        )
        state = MagicMock()
        state.metadata = {"waf_result": original.to_dict()}
        result = _get_waf_result(state)
        assert isinstance(result, WAFResult)
        assert result.detected is True
        assert result.waf_name == "akamai"
        assert result.strategy is not None
        assert result.strategy.nuclei_rate == 10

    def test_string_fallback(self):
        """If waf_result was str()-ified by old serialization, return None."""
        from src.workflow.pipelines.full_scan import _get_waf_result

        state = MagicMock()
        state.metadata = {"waf_result": "WAFResult(host='test.com', detected=True)"}
        assert _get_waf_result(state) is None

    def test_invalid_dict(self):
        """Corrupt dict data should not crash."""
        from src.workflow.pipelines.full_scan import _get_waf_result
        from src.tools.scanners.waf_strategy import WAFResult

        state = MagicMock()
        state.metadata = {"waf_result": {"invalid": "data"}}
        result = _get_waf_result(state)
        # from_dict handles missing keys gracefully
        assert isinstance(result, WAFResult)
        assert result.detected is False


# ====================================================================
# P0-1 integration: sync_from_workflow_state WAFResult handling
# ====================================================================


class TestSyncMetadataWAFResult:
    def test_wafresult_to_dict_via_hasattr(self):
        """sync_from_workflow_state should use to_dict() for WAFResult."""
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        waf = WAFResult(
            host="example.com",
            detected=True,
            waf_name="cloudflare",
            confidence=0.85,
            strategy=WAFStrategy(waf_name="cloudflare", nuclei_rate=15),
        )
        # The key check in sync_from_workflow_state
        assert hasattr(waf, "to_dict")
        d = waf.to_dict()
        assert isinstance(d, dict)
        assert d["detected"] is True
        assert d["strategy"]["nuclei_rate"] == 15
        # Must be JSON-serializable
        json.dumps(d)

    def test_wafstrategy_to_dict_via_hasattr(self):
        from src.tools.scanners.waf_strategy import WAFStrategy

        s = WAFStrategy(waf_name="test", nuclei_rate=20)
        assert hasattr(s, "to_dict")
        d = s.to_dict()
        assert isinstance(d, dict)
        json.dumps(d)


# ====================================================================
# P0-2: Orchestrator retry path
# ====================================================================


class TestOrchestratorCheckpointRetry:
    def test_retry_includes_sync(self):
        """Verify the retry path calls sync + checkpoint, not just checkpoint."""
        import ast

        with open("src/workflow/orchestrator.py") as f:
            source = f.read()

        # Find the retry block — looks for the pattern where sync is called before checkpoint in the retry
        # The key fix is that the retry block should have sync_from_workflow_state before checkpoint
        retry_section = source.split("Session checkpoint failed, retrying once")[1]
        retry_section = retry_section.split("Session checkpoint retry also failed")[0]

        assert "sync_from_workflow_state" in retry_section, (
            "Retry path must call sync_from_workflow_state before checkpoint"
        )
        assert "checkpoint" in retry_section, (
            "Retry path must call checkpoint"
        )

    def test_error_path_has_checkpoint(self):
        """Verify the stage error/timeout handler persists partial work."""
        with open("src/workflow/orchestrator.py") as f:
            source = f.read()

        # Find the error handler section
        error_section = source.split("Session Manager: record error")[1]
        error_section = error_section.split("finally:")[0]

        assert "sync_from_workflow_state" in error_section, (
            "Error path must call sync_from_workflow_state to persist partial work"
        )
        assert "checkpoint" in error_section, (
            "Error path must checkpoint after recording error"
        )


# ====================================================================
# P0-3: Checkpoint on stage failure
# ====================================================================


class TestStageFailureCheckpoint:
    def test_error_handler_persists_work(self):
        """Verify the error handler has sync+checkpoint+force=True."""
        with open("src/workflow/orchestrator.py") as f:
            source = f.read()

        # The error handler should have force=True to ensure checkpoint is saved
        error_section = source.split("record_stage_error")[1]
        error_end = error_section.split("finally:")[0]

        assert "sync_from_workflow_state" in error_end
        assert "checkpoint" in error_end
        assert "force=True" in error_end, (
            "Error checkpoint should use force=True to bypass throttle"
        )

    def test_fp_timeout_partial_findings_persisted(self):
        """If FP elimination times out and findings are promoted,
        they should be persisted via the error-path checkpoint."""
        with open("src/workflow/orchestrator.py") as f:
            source = f.read()

        # The FP timeout handler promotes findings to verified_findings
        # Then the error path (after except block) should checkpoint
        assert "FP elimination timed out" in source
        assert "unprocessed findings promoted" in source


# ====================================================================
# Edge cases: metadata serialization robustness
# ====================================================================


class TestMetadataSerializationEdgeCases:
    def test_scan_profiler_has_to_dict(self):
        """ScanProfiler must have to_dict() for sync_from_workflow_state."""
        from src.analysis.scan_profiler import ScanProfiler

        p = ScanProfiler()
        p.start_scan()
        p.end_scan()
        assert hasattr(p, "to_dict")
        d = p.to_dict()
        assert isinstance(d, dict)
        json.dumps(d)

    def test_wafresult_json_dumps_fails_but_to_dict_works(self):
        """Direct json.dumps on WAFResult should fail, but to_dict() should succeed."""
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        waf = WAFResult(
            host="test.com",
            detected=True,
            strategy=WAFStrategy(waf_name="cf"),
        )
        # Direct serialization must fail
        with pytest.raises(TypeError):
            json.dumps(waf)
        # to_dict() must succeed
        d = waf.to_dict()
        json.dumps(d)  # no error

    def test_metadata_sanitization_prefers_to_dict(self):
        """Simulate sync_from_workflow_state metadata sanitization logic."""
        from src.tools.scanners.waf_strategy import WAFResult, WAFStrategy

        metadata = {
            "scan_profiler": MagicMock(to_dict=lambda: {"stages": []}),
            "waf_result": WAFResult(
                host="t.com",
                detected=True,
                strategy=WAFStrategy(waf_name="cf"),
            ),
            "simple_key": "string_value",
            "number_key": 42,
        }

        clean: dict[str, Any] = {}
        for k, v in metadata.items():
            if hasattr(v, "to_dict"):
                clean[k] = v.to_dict()
            else:
                try:
                    json.dumps(v)
                    clean[k] = v
                except (TypeError, ValueError, OverflowError):
                    clean[k] = str(v)

        # ALL values must be JSON-serializable
        serialized = json.dumps(clean)
        restored = json.loads(serialized)

        assert restored["waf_result"]["detected"] is True
        assert restored["simple_key"] == "string_value"
        assert restored["number_key"] == 42

    def test_checkpoint_fallback_with_wafresult(self):
        """Even if model_dump_json fails, json.dumps(default=str) should work."""
        from src.tools.scanners.waf_strategy import WAFResult

        waf = WAFResult(host="test.com", detected=True)
        # Simulate the fallback path
        data = {"workflow_metadata": {"waf_result": waf}}
        result = json.dumps(data, indent=2, default=str)
        assert "test.com" in result
