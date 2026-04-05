"""Tests for evidence aggregator + exploit verifier pipeline integration (Phase 5.4)."""
from __future__ import annotations
import asyncio
from dataclasses import field
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.reporting.evidence.evidence_aggregator import EvidenceAggregator, EvidencePackage
from src.tools.exploit.exploit_verifier import ProvenFinding, VerificationStrategy


class TestEvidencePackage:
    def test_default_fields(self):
        pkg = EvidencePackage()
        assert pkg.is_proven is False
        assert pkg.confidence == 0.0
        assert pkg.evidence_items == []
        assert pkg.http_exchanges == []

    def test_evidence_count_property(self):
        pkg = EvidencePackage(
            evidence_items=["e1", "e2"],
            http_exchanges=[{"url": "http://x"}],
            screenshot_paths=["/tmp/s.png"],
        )
        assert pkg.evidence_count == 4


class TestProvenFinding:
    def test_proven_defaults(self):
        pf = ProvenFinding(finding={"title": "XSS"})
        assert pf.is_proven is False
        assert pf.strategy_used == VerificationStrategy.POC_SCRIPT

    def test_proven_with_evidence(self):
        pf = ProvenFinding(
            finding={"title": "SQLi", "severity": "HIGH"},
            is_proven=True,
            strategy_used=VerificationStrategy.CURL_COMMAND,
            confidence=0.92,
            poc_code="curl -X POST ...",
            poc_output="admin' OR '1'='1 returned 200",
            evidence_items=["HTTP 200 with SQL error"],
        )
        assert pf.is_proven is True
        assert pf.confidence == 0.92
        assert len(pf.evidence_items) == 1


class TestEvidenceAggregator:
    def test_collect_builds_package(self, tmp_path):
        async def _t():
            agg = EvidenceAggregator(session_dir=str(tmp_path / "evidence"))
            proven = ProvenFinding(
                finding={"title": "Reflected XSS", "vulnerability_type": "xss",
                         "severity": "HIGH", "url": "https://example.com/search"},
                is_proven=True,
                strategy_used=VerificationStrategy.POC_SCRIPT,
                confidence=0.88,
                poc_code='print("XSS")',
                poc_output="<script>alert(1)</script> reflected",
                evidence_items=["Payload reflected in response body"],
                verification_time=2.5,
                iterations_used=1,
            )
            pkg = await agg.collect(proven, capture_screenshot=False)
            assert isinstance(pkg, EvidencePackage)
            assert pkg.is_proven is True
            assert pkg.confidence == 0.88
            assert pkg.poc_code == 'print("XSS")'
            assert len(pkg.evidence_items) >= 1
            return pkg
        asyncio.run(_t())

    def test_export_creates_directory(self, tmp_path):
        agg = EvidenceAggregator(session_dir=str(tmp_path / "evidence"))
        pkg = EvidencePackage(
            finding_id="test-001",
            finding_title="Test finding",
            is_proven=True,
            poc_code="curl http://example.com",
        )
        result = agg.export(pkg)
        # export returns a path string
        assert result
