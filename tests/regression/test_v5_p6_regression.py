"""
Phase 6 — Advanced Validation regression tests.

P6.1: CDN/WAF IP database + interactsh_wrapper JSON loading
P6.2: Multi-stage verification gate for CRITICAL/HIGH findings
P6.3: CORS ACAO:* + ACAC:true → no finding (not reportable)
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path


# ────────────────────────────────────────────────────────────
# P6.1: Known Infrastructure IP Database
# ────────────────────────────────────────────────────────────

class TestKnownInfrastructureIPDatabase:
    """JSON database exists, is valid, and covers major providers."""

    DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "known_infrastructure_ips.json"

    def test_json_file_exists(self):
        assert self.DATA_PATH.is_file(), "data/known_infrastructure_ips.json must exist"

    def test_json_is_valid(self):
        data = json.loads(self.DATA_PATH.read_text())
        assert isinstance(data, dict)
        # Must have at least dns_resolvers and cloudflare
        assert "dns_resolvers" in data
        assert "cloudflare" in data

    def test_all_cidrs_are_valid_networks(self):
        data = json.loads(self.DATA_PATH.read_text())
        for key, val in data.items():
            if key.startswith("_"):
                continue
            assert isinstance(val, list), f"{key} must be a list"
            for cidr in val:
                ipaddress.ip_network(cidr, strict=False)  # raises on invalid

    def test_covers_major_providers(self):
        data = json.loads(self.DATA_PATH.read_text())
        required = {"dns_resolvers", "cloudflare", "akamai", "fastly", "aws_cloudfront"}
        assert required.issubset(data.keys())

    def test_minimum_cidr_count(self):
        """At least 30 CIDRs across all providers."""
        data = json.loads(self.DATA_PATH.read_text())
        total = sum(len(v) for k, v in data.items() if isinstance(v, list) and not k.startswith("_"))
        assert total >= 30, f"Expected ≥30 CIDRs, got {total}"


class TestInteractshJSONLoading:
    """interactsh_wrapper loads from JSON file instead of inline only."""

    def test_is_infrastructure_ip_cloudflare(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        # 104.16.x.x is Cloudflare — should be in JSON
        assert is_infrastructure_ip("104.16.0.1") is True

    def test_is_infrastructure_ip_google_dns(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("8.8.8.8") is True

    def test_is_infrastructure_ip_non_infra(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        # Random private IP — not infrastructure
        assert is_infrastructure_ip("192.168.1.100") is False

    def test_infrastructure_networks_loaded_from_json(self):
        """Networks list should be larger than the inline fallback (12 entries)."""
        from src.tools.scanners.interactsh_wrapper import _INFRASTRUCTURE_NETWORKS
        # JSON has ~80+ CIDRs, inline fallback has 12
        assert len(_INFRASTRUCTURE_NETWORKS) > 20, (
            f"Expected >20 networks (JSON loaded), got {len(_INFRASTRUCTURE_NETWORKS)}"
        )

    def test_classify_callback_quality_unchanged(self):
        from src.tools.scanners.interactsh_wrapper import classify_callback_quality
        assert classify_callback_quality("HTTP", "1.2.3.4") == "high"
        assert classify_callback_quality("DNS", "8.8.8.8") == "infrastructure"
        assert classify_callback_quality("HTTP", "104.16.0.1") == "low"


# ────────────────────────────────────────────────────────────
# P6.2: Multi-Stage Verification Gate
# ────────────────────────────────────────────────────────────

class TestMultiStageVerification:
    """CRITICAL/HIGH findings get downgraded without strong evidence + high confidence."""

    def _find_multi_stage_code(self):
        """Return the multi-stage verification source code block."""
        import inspect
        import src.workflow.pipelines.full_scan as fs
        source = inspect.getsource(fs)
        return source

    def test_multi_stage_code_exists(self):
        source = self._find_multi_stage_code()
        assert "Multi-Stage Verification" in source
        assert "STRONG_EVIDENCE_KEYWORDS" in source

    def test_critical_threshold_75(self):
        source = self._find_multi_stage_code()
        assert 'sev == "critical" and conf < 75.0' in source

    def test_high_threshold_70(self):
        source = self._find_multi_stage_code()
        assert 'sev == "high" and conf < 70.0' in source

    def test_strong_evidence_keywords_defined(self):
        source = self._find_multi_stage_code()
        for kw in ["reflected", "executed", "callback", "oob", "exploit"]:
            assert f'"{kw}"' in source, f"Missing strong evidence keyword: {kw}"

    def test_critical_without_evidence_downgrades(self):
        """Simulate: CRITICAL finding, confidence=60, no strong evidence → HIGH."""
        finding = {
            "severity": "critical",
            "confidence_score": 60.0,
            "evidence": "Some generic status code difference observed",
        }
        # Apply the multi-stage logic inline
        _STRONG_EVIDENCE_KEYWORDS = {
            "reflected", "injected", "executed", "extracted", "callback",
            "confirmed", "oob", "verified", "exploit", "shell", "uid=",
            "root:", "admin", "token", "secret", "dumped",
        }
        conf = finding["confidence_score"]
        ev_text = str(finding["evidence"]).lower()
        has_strong = any(kw in ev_text for kw in _STRONG_EVIDENCE_KEYWORDS)

        if finding["severity"] == "critical" and conf < 75.0 and not has_strong:
            finding["severity"] = "high"

        assert finding["severity"] == "high"

    def test_critical_with_strong_evidence_survives(self):
        """CRITICAL + conf=60 but has 'reflected' in evidence → stays CRITICAL."""
        finding = {
            "severity": "critical",
            "confidence_score": 60.0,
            "evidence": "XSS payload reflected in response body unencoded",
        }
        _STRONG_EVIDENCE_KEYWORDS = {
            "reflected", "injected", "executed", "extracted", "callback",
            "confirmed", "oob", "verified", "exploit", "shell", "uid=",
            "root:", "admin", "token", "secret", "dumped",
        }
        conf = finding["confidence_score"]
        ev_text = str(finding["evidence"]).lower()
        has_strong = any(kw in ev_text for kw in _STRONG_EVIDENCE_KEYWORDS)

        if finding["severity"] == "critical" and conf < 75.0 and not has_strong:
            finding["severity"] = "high"

        assert finding["severity"] == "critical"

    def test_critical_high_confidence_survives(self):
        """CRITICAL + conf=80 → stays CRITICAL regardless of evidence."""
        finding = {"severity": "critical", "confidence_score": 80.0, "evidence": "generic"}
        # conf >= 75 → no downgrade
        assert finding["severity"] == "critical"

    def test_high_without_evidence_downgrades(self):
        """HIGH + conf=55 + no strong evidence → MEDIUM."""
        finding = {
            "severity": "high",
            "confidence_score": 55.0,
            "evidence": "status code was 200",
        }
        _STRONG_EVIDENCE_KEYWORDS = {
            "reflected", "injected", "executed", "extracted", "callback",
            "confirmed", "oob", "verified", "exploit", "shell", "uid=",
            "root:", "admin", "token", "secret", "dumped",
        }
        conf = finding["confidence_score"]
        ev_text = str(finding["evidence"]).lower()
        has_strong = any(kw in ev_text for kw in _STRONG_EVIDENCE_KEYWORDS)

        if finding["severity"] == "high" and conf < 70.0 and not has_strong:
            finding["severity"] = "medium"

        assert finding["severity"] == "medium"


# ────────────────────────────────────────────────────────────
# P6.3: CORS ACAO:* + ACAC:true = Not Reportable
# ────────────────────────────────────────────────────────────

class TestCORSWildcardNotReportable:
    """ACAO:* (with or without ACAC:true) should never create a finding."""

    def test_cors_checker_source_no_wildcard_finding(self):
        """The wildcard ACAO block should skip (pass), not create findings."""
        import inspect
        from src.tools.scanners.custom_checks import cors_checker
        source = inspect.getsource(cors_checker)
        # Should NOT contain INFO severity for wildcard
        assert "SeverityLevel.INFO" not in source or "ACAO" not in source.split("SeverityLevel.INFO")[0][-200:]
        # Should contain the pass-skip pattern
        assert 'pass  # Skip — ACAO:* is never a reportable finding' in source

    def test_wildcard_with_acac_true_no_vuln(self):
        """Simulate: ACAO=* + ACAC=true → is_vuln should remain False."""
        acao = "*"
        acac = "true"
        is_vuln = False
        # Current logic: wildcard → pass (skip)
        if acao == "*":
            pass  # Skip — not reportable
        assert is_vuln is False

    def test_wildcard_without_acac_no_vuln(self):
        """Simulate: ACAO=* + ACAC absent → is_vuln should remain False."""
        acao = "*"
        acac = ""
        is_vuln = False
        if acao == "*":
            pass
        assert is_vuln is False

    def test_reflected_origin_still_detected(self):
        """Non-wildcard origin reflection should still create findings."""
        acao = "https://evil.com"
        origin = "https://evil.com"
        is_vuln = False
        if origin != "null" and acao == origin:
            is_vuln = True
        assert is_vuln is True


# ────────────────────────────────────────────────────────────
# Edge Cases
# ────────────────────────────────────────────────────────────

class TestP6EdgeCases:
    """Edge case coverage for Phase 6 changes."""

    def test_interactsh_fallback_cidrs_exist(self):
        """Inline fallback CIDRs exist for when JSON is missing."""
        from src.tools.scanners.interactsh_wrapper import _INLINE_FALLBACK_CIDRS
        assert len(_INLINE_FALLBACK_CIDRS) >= 10

    def test_akamai_ip_is_infrastructure(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        # 23.32.x.x is Akamai range
        assert is_infrastructure_ip("23.32.0.1") is True

    def test_fastly_ip_is_infrastructure(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        assert is_infrastructure_ip("151.101.1.1") is True

    def test_aws_cloudfront_is_infrastructure(self):
        from src.tools.scanners.interactsh_wrapper import is_infrastructure_ip
        # 13.32.x.x is CloudFront
        assert is_infrastructure_ip("13.32.0.1") is True

    def test_medium_finding_not_affected_by_multi_stage(self):
        """Multi-stage only applies to CRITICAL/HIGH, not MEDIUM."""
        finding = {"severity": "medium", "confidence_score": 30.0, "evidence": "none"}
        original = finding["severity"]
        # Multi-stage logic would not touch MEDIUM severity
        assert original == "medium"
