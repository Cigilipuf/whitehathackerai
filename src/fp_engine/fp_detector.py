"""
WhiteHatHacker AI — False Positive Tespit Motoru

Botun EN KRİTİK modülü. 5 katmanlı doğrulama stratejisi:
1. Bilinen FP kalıp eşleme
2. Çoklu araç doğrulama (cross-verification)
3. Bağlam analizi (Brain 32B ile)
4. Payload doğrulama
5. Güven puanlama (confidence scoring)
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import timedelta
from typing import Any

from loguru import logger
from pydantic import BaseModel

from src.tools.base import Finding
from src.fp_engine.scoring.confidence_scorer import ConfidenceScorer
from src.fp_engine.patterns.known_fps import KnownFPMatcher
from src.utils.constants import (
    BrainType,
    FP_AUTO_REPORT_THRESHOLD,
    FP_HIGH_CONFIDENCE_THRESHOLD,
    FP_LOW_CONFIDENCE_THRESHOLD,
    FP_MEDIUM_CONFIDENCE_THRESHOLD,
    FindingStatus,
    SeverityLevel,
)


# ── Helpers ──────────────────────────────────────────────────
def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert to float, returning *default* on failure."""
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


# ============================================================
# Veri Modelleri
# ============================================================

class FPVerdict(BaseModel):
    """False Positive değerlendirme sonucu."""

    finding: Finding                         # Orijinal bulgu
    status: FindingStatus                    # Sonuç durumu
    confidence_score: float                  # Güven skoru (0-100)
    verdict: str                             # "real" | "false_positive" | "likely_fp" | "needs_review"

    # Doğrulama detayları
    verification_layers: list[dict[str, Any]] = []  # Her katmanın sonucu
    evidence_chain: list[str] = []           # Kanıt zinciri
    reasoning: str = ""                      # Brain analiz gerekçesi

    # Metadata
    verified_by_tools: list[str] = []        # Doğrulayan araçlar
    fp_patterns_matched: list[str] = []      # Eşleşen FP kalıpları
    waf_detected: bool = False               # WAF tespit edildi mi?
    known_fp_capped: bool = False            # KnownFP ceiling applied (v4.0 Guard 3)

    @property
    def is_reportable(self) -> bool:
        """Bu bulgu raporlanabilir mi?"""
        return (
            self.status == FindingStatus.VERIFIED
            and self.confidence_score >= FP_MEDIUM_CONFIDENCE_THRESHOLD
        )

    @property
    def auto_reportable(self) -> bool:
        """Otomatik raporlanabilir mi?"""
        return self.confidence_score >= FP_AUTO_REPORT_THRESHOLD

    @property
    def needs_human_review(self) -> bool:
        """İnsan incelemesi gerekli mi?"""
        return (
            FP_MEDIUM_CONFIDENCE_THRESHOLD <= self.confidence_score < FP_HIGH_CONFIDENCE_THRESHOLD
        )


# ============================================================
# Bilinen False Positive Kalıpları
# ============================================================

KNOWN_FP_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "nuclei": [
        {
            "pattern": "tech-detect",
            "action": "info_only",
            "description": "Technology detection — not a vulnerability",
            "penalty": -50,
        },
        {
            "pattern": "ssl/deprecated-tls",
            "action": "verify_with_testssl",
            "description": "CDN/proxy TLS termination can cause FP",
            "penalty": -15,
        },
        {
            "pattern": "misconfiguration/http-missing-security-headers",
            "action": "context_check",
            "description": "Missing headers — often informational",
            "penalty": -10,
        },
    ],
    "sqlmap": [
        {
            "pattern": "boolean-based blind",
            "action": "cross_verify_time_based",
            "description": "Boolean blind often produces FP",
            "penalty": -20,
        },
        {
            "pattern": "error-based",
            "action": "verify_data_extraction",
            "description": "Error-based needs extraction proof",
            "penalty": -5,
        },
    ],
    "xss": [
        {
            "pattern": "reflected in attribute",
            "action": "check_encoding",
            "description": "Check if encoding prevents execution",
            "penalty": -15,
        },
        {
            "pattern": "reflected in comment",
            "action": "verify_breakout",
            "description": "Comment reflection rarely exploitable",
            "penalty": -25,
        },
    ],
    "ssrf": [
        {
            "pattern": "timeout difference",
            "action": "oob_verify",
            "description": "Timing-only SSRF needs OOB verification",
            "penalty": -20,
        },
    ],
}

# WAF/CDN Parmak İzleri
WAF_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cflb", "cloudflare"],
    "akamai": ["x-akamai", "akamai-origin-hop", "akamaighost"],
    "aws_waf": ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "imperva": ["x-iinfo", "incap_ses", "visid_incap"],
    "f5": ["x-wa-info", "bigipserver"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "modsecurity": ["mod_security", "modsec"],
}


class FPDetector:
    """
    False Positive tespit ve eleme motoru.

    6 katmanlı doğrulama stratejisi uygular:
    0. Inherent reliability scoring (tool + finding type)
    1. Bilinen FP kalıp eşleme
    2. Çoklu araç doğrulama (cross-verification)
    3. Bağlam analizi (Brain 32B ile)
    4. Payload doğrulama
    5. WAF/CDN tespiti

    Kullanım:
        detector = FPDetector(brain_engine=engine)
        verdict = await detector.analyze(finding)

        if verdict.is_reportable:
            # Rapor oluştur
        elif verdict.needs_human_review:
            # İnsan incelemesi iste
    """

    # ── Inherent reliability config ──
    # Tools whose findings are deterministic / factual (no FP possible)
    # and should start with higher base confidence.
    _DETERMINISTIC_TOOLS: dict[str, float] = {
        "header_checker": 20.0,          # Missing header = factual
        "info_disclosure_checker": 15.0,  # Server header / dir listing = factual
        "cookie_checker": 15.0,           # Cookie flag check = factual
        "cors_checker": 10.0,             # CORS config = factual
        "sensitive_url_finder": 15.0,     # URL exists = factual
        "rate_limit_checker": 10.0,       # Rate limit absence = factual (50 reqs sent)
    }
    # Tools that are version-based / heuristic (moderate reliability)
    _HEURISTIC_TOOLS: dict[str, float] = {
        "tech_cve_checker": 5.0,          # Version-based CVE — needs version confirm
        "http_methods_checker": 10.0,     # Method response = factual
        "open_redirect_checker": -5.0,    # High FP rate without payload confirm
        "auth_bypass_checker": -5.0,      # Needs careful validation (response diff)
        "business_logic_checker": -10.0,  # Highly heuristic — brain must validate
    }
    # Tools whose single-tool findings are EXPECTED (no multi-tool penalty)
    _SINGLE_TOOL_OK: set[str] = {
        "header_checker", "info_disclosure_checker", "cookie_checker",
        "cors_checker", "sensitive_url_finder", "tech_cve_checker",
        "http_methods_checker", "open_redirect_checker", "api_checker",
        "auth_bypass_checker", "rate_limit_checker", "business_logic_checker",
        "nuclei", "nikto", "wpscan",  # Standalone scanners
    }
    # Finding types that should get brain analysis (MEDIUM+ severity)
    _BRAIN_WORTHY_TYPES: set[str] = {
        "sql_injection", "command_injection", "xss_reflected", "xss_stored",
        "ssrf", "ssti", "idor", "authentication_bypass", "auth_bypass", "rce",
        "open_redirect", "cve", "known_cve",
        "outdated_software",           # version-unknown needs brain analysis
        "cors_misconfiguration",        # needs context verification
        "information_disclosure",       # may or may not be real
        "missing_rate_limit",           # needs context: is endpoint really sensitive?
        "business_logic",              # complex — always needs brain
        "race_condition",              # complex — always needs brain
        "subdomain_takeover",          # high impact — verify with brain
    }

    def __init__(
        self,
        brain_engine: Any | None = None,  # BrainEngine — circular import önleme
        known_patterns: dict[str, list[dict[str, Any]]] | None = None,
        intelligence_engine: Any | None = None,  # IntelligenceEngine — brain-down tracking
        response_intel: dict[str, Any] | None = None,  # ResponseIntel data from vuln_scan
        tool_executor: Any | None = None,  # ToolExecutor for active re-verification
        is_spa: bool = False,  # SPA catch-all detected for target
        auth_headers: dict[str, str] | None = None,  # Auth headers for authenticated re-requests
        host_profiles: dict[str, dict[str, Any]] | None = None,  # Per-host intelligence profiles
        waf_detection: dict[str, Any] | None = None,  # Pipeline-level WAF detection result
    ) -> None:
        self.brain_engine = brain_engine
        self.intelligence_engine = intelligence_engine
        self.known_patterns = known_patterns or KNOWN_FP_PATTERNS
        self.confidence_scorer = ConfidenceScorer()
        self._known_fp_matcher = KnownFPMatcher()
        self.response_intel = response_intel or {}
        self._tool_executor = tool_executor
        self._is_spa = is_spa
        self._auth_headers: dict[str, str] = auth_headers or {}
        self._host_profiles: dict[str, dict[str, Any]] = host_profiles or {}
        self._waf_detection: dict[str, Any] = waf_detection or {}

        self._total_analyzed = 0
        self._fp_count = 0
        self._real_count = 0
        self._review_count = 0

        logger.info("FPDetector initialized | 6-layer verification + ConfidenceScorer")

    async def analyze(self, finding: Finding) -> FPVerdict:
        """
        Bulguyu 6 katmanlı doğrulama ile analiz et.

        Args:
            finding: Doğrulanacak bulgu

        Returns:
            FPVerdict — doğrulama sonucu
        """
        self._total_analyzed += 1
        layers: list[dict[str, Any]] = []
        # Use finding's own confidence as the starting point.
        # This respects tools that already provide calibrated confidence
        # (e.g. tech_cve_checker gives 35 for version-unknown, 75 for known).
        # If confidence is 0.0 (sentinel for "tool didn't set"), use conservative 30.
        # NOTE: ``finding.confidence else 50`` would treat 0.0 as falsy, so use > 0 check.
        original_confidence = finding.confidence if finding.confidence > 0 else 30.0
        score = max(0.0, min(100.0, original_confidence))
        evidence_chain: list[str] = []
        fp_patterns: list[str] = []

        # ── Katman 0: Inherent Reliability (Tool/Type awareness) ──
        layer0_delta, layer0_reason = self._layer0_inherent_reliability(finding)
        score += layer0_delta
        layers.append({
            "layer": 0,
            "name": "Inherent Reliability",
            "result": layer0_reason,
            "score_delta": layer0_delta,
        })
        if layer0_delta != 0:
            evidence_chain.append(f"L0: {layer0_reason} ({layer0_delta:+.0f})")

        # ── Katman 1: Bilinen FP Kalıp Eşleme ──
        layer1_result, layer1_penalty, layer1_patterns = self._layer1_pattern_matching(finding)

        # v5.0: When brain is unavailable, amplify pattern penalties by 1.5x
        # to compensate for missing brain-powered FP analysis
        _brain_ok = self.brain_engine is not None and not getattr(self.brain_engine, '_brain_confirmed_down', False)
        if not _brain_ok and layer1_penalty < 0:
            layer1_penalty = layer1_penalty * 1.5

        score += layer1_penalty
        fp_patterns.extend(layer1_patterns)
        layers.append({
            "layer": 1,
            "name": "Known FP Pattern Matching",
            "result": layer1_result,
            "score_delta": layer1_penalty,
            "patterns": layer1_patterns,
        })
        if layer1_result != "pass":
            evidence_chain.append(f"L1: Known FP pattern matched: {', '.join(layer1_patterns)}")

        # ── Layer 1b: SPA Catch-All Penalty ──
        # If target is an SPA with catch-all routing, path-based findings are
        # highly likely to be false positives (200 OK for any path).
        if self._is_spa:
            _spa_vuln = finding.vulnerability_type.lower().replace(" ", "_")
            _spa_path_types = {
                "sensitive_file", "information_disclosure", "backup_file",
                "directory_listing", "admin_panel", "config_exposure",
                "path_traversal", "open_redirect", "sensitive_url",
                "exposed_panel", "exposed_config", "debug_endpoint",
                "source_code_disclosure", "git_exposure", "svn_exposure",
                "env_file", "phpinfo", "server_status",
            }
            _spa_title_kw = (
                "admin", "backup", ".bak", "config", "directory",
                ".env", ".git", "phpinfo", "server-status", "debug",
                "exposed", "panel", "disclosure", "wp-admin",
                "elmah", "trace.axd",
            )
            if _spa_vuln in _spa_path_types or any(
                kw in finding.title.lower()
                for kw in _spa_title_kw
            ):
                _spa_delta = -15.0
                score += _spa_delta
                layers.append({
                    "layer": "1b",
                    "name": "SPA Catch-All Penalty",
                    "result": "spa_path_finding",
                    "score_delta": _spa_delta,
                })
                evidence_chain.append(
                    f"L1b: SPA catch-all detected — path-based finding penalised ({_spa_delta:+.0f})"
                )

        # ── Layer 1c: Tool-Specific Quirk Penalties (V24) ──
        try:
            from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker
            _tq = ToolQuirkChecker()
            _tq_dict = {
                "vuln_type": finding.vulnerability_type,
                "type": finding.vulnerability_type,
                "evidence": str(finding.evidence or "") + " " + str(finding.raw_output or "")[:500],
            }
            _tq_result = _tq.check(finding.tool_name or "", _tq_dict)
            if _tq_result["has_quirks"]:
                _tq_delta = _safe_float(_tq_result.get("total_modifier", 0), 0.0)
                # Cap the penalty so a single layer can't nuke the score
                _tq_delta = max(-30.0, min(10.0, _tq_delta))
                score += _tq_delta
                _tq_names = [q.description[:40] for q in _tq_result["matching_quirks"][:3]]
                layers.append({
                    "layer": "1c",
                    "name": "Tool Quirk Penalties",
                    "result": f"matched {len(_tq_result['matching_quirks'])} quirks",
                    "score_delta": _tq_delta,
                    "quirks": _tq_names,
                })
                evidence_chain.append(
                    f"L1c: Tool quirks ({finding.tool_name}): "
                    f"{len(_tq_result['matching_quirks'])} matched, delta={_tq_delta:+.0f}"
                )
        except ImportError:
            pass
        except Exception as _tq_exc:
            logger.debug(f"Tool quirk check skipped: {_tq_exc}")

        # ── Layer 1d: Host Profile Intelligence (Phase 0.3D) ──
        # If we have host profiles, apply per-host-type confidence adjustments.
        # For example: finding on a CDN_ONLY host → heavy penalty; finding on
        # an AUTH_GATED host from an unauthenticated scan → penalty.
        if self._host_profiles:
            _hp_delta = self._layer1d_host_profile_adjustment(finding)
            if _hp_delta != 0.0:
                score += _hp_delta
                layers.append({
                    "layer": "1d",
                    "name": "Host Profile Intelligence",
                    "result": f"host_type_adjustment={_hp_delta:+.0f}",
                    "score_delta": _hp_delta,
                })
                evidence_chain.append(f"L1d: Host profile adjustment ({_hp_delta:+.0f})")

        # ── Layer 1e: Pipeline-level WAF awareness ──
        # If a WAF was detected at pipeline level, apply a small penalty to
        # findings that don't have strong evidence (WAF may have blocked payloads).
        if self._waf_detection and self._waf_detection.get("waf_name"):
            _waf_name = self._waf_detection.get("waf_name", "unknown")
            _waf_conf = _safe_float(self._waf_detection.get("confidence", 0), 0.0)
            if _waf_conf > 0.5:
                # Stronger penalty for lower-evidence findings
                _has_evidence = bool(finding.http_response or finding.evidence)
                _waf_penalty = -5.0 if _has_evidence else -12.0
                score += _waf_penalty
                layers.append({
                    "layer": "1e",
                    "name": "Pipeline WAF Awareness",
                    "result": f"waf={_waf_name} conf={_waf_conf:.0%}",
                    "score_delta": _waf_penalty,
                })
                evidence_chain.append(f"L1e: WAF detected ({_waf_name}) → penalty {_waf_penalty:+.0f}")

        # ── Early-layer penalty — NO cap ──
        # Strong pattern matches (known FP, SPA, tool quirks, WAF) should be
        # definitive.  The old -40 cap was rescuing obvious FPs back into the
        # pipeline.  Evidence-based layers (2+) can still rehabilitate a finding
        # if real proof exists.
        _early_total = score - original_confidence
        if _early_total < -40.0:
            evidence_chain.append(
                f"Early-layer penalty: cumulative {_early_total:.0f} (uncapped)"
            )

        # ── Katman 2: Çoklu Araç Doğrulama Kontrolü ──
        layer2_result, layer2_delta = self._layer2_multi_tool_check(finding)
        score += layer2_delta
        layers.append({
            "layer": 2,
            "name": "Multi-Tool Cross-Verification",
            "result": layer2_result,
            "score_delta": layer2_delta,
        })
        evidence_chain.append(f"L2: Multi-tool check: {layer2_result}")

        # ── Layer 2b: Active re-verification for HIGH/CRITICAL (2.3 wiring) ──
        _sev_for_active = str(finding.severity).lower() if finding.severity else "info"
        if _sev_for_active in ("high", "critical") and layer2_result == "single_tool_only":
            try:
                from src.fp_engine.verification.multi_tool_verify import MultiToolVerifier
                from src.tools.registry import tool_registry
                _executor = getattr(self, '_tool_executor', None)
                if _executor:
                    _mtv = MultiToolVerifier(
                        tool_executor=_executor, registry=tool_registry,
                        max_verification_tools=2, timeout_per_tool=600,
                    )
                    _cv_result = await _mtv.verify(finding)
                    if _cv_result.verdict == "confirmed":
                        _active_delta = 20.0
                        evidence_chain.append(
                            f"L2b: Active re-verification CONFIRMED "
                            f"(ratio={_cv_result.confirmation_ratio:.0%})"
                        )
                    elif _cv_result.verdict == "denied":
                        _active_delta = -20.0
                        evidence_chain.append("L2b: Active re-verification DENIED")
                    else:
                        _active_delta = 0.0
                    score += _active_delta
                    layers.append({
                        "layer": "2b",
                        "name": "Active Multi-Tool Re-Verification",
                        "result": _cv_result.verdict,
                        "score_delta": _active_delta,
                    })
            except ImportError:
                pass
            except Exception as _mtv_err:
                logger.debug(f"Active multi-tool verification skipped: {_mtv_err}")

        # ── Layer 2c: HTTP Context Verification (V24) ──
        try:
            from src.fp_engine.verification.context_verify import (
                ContextVerifier, HttpContext,
            )
            _cv_has_data = bool(
                finding.http_request or finding.http_response
            )
            if _cv_has_data:
                _cv_raw = finding.http_request or ""
                # Inject auth_headers so authenticated findings are verified
                # with the same credentials used during scanning.
                _cv_req_headers: dict[str, str] = dict(self._auth_headers) if self._auth_headers else {}

                # Extract real HTTP status + headers from http_response string
                _cv_resp_str = finding.http_response or ""
                _cv_status = 0  # unknown
                _cv_resp_headers: dict[str, str] = {}
                if _cv_resp_str:
                    _cv_resp_lines = _cv_resp_str.split("\n")
                    import re as _cv_re
                    _cv_status_match = _cv_re.search(r"HTTP/[\d.]+\s+(\d{3})", _cv_resp_lines[0] if _cv_resp_lines else "")
                    if _cv_status_match:
                        _cv_status = int(_cv_status_match.group(1))
                    # Parse headers until blank line
                    for _cv_hdr_line in _cv_resp_lines[1:]:
                        _cv_hdr_line = _cv_hdr_line.strip()
                        if not _cv_hdr_line:
                            break
                        if ":" in _cv_hdr_line:
                            _cv_k, _cv_v = _cv_hdr_line.split(":", 1)
                            _cv_resp_headers[_cv_k.strip().lower()] = _cv_v.strip()
                # Fallback: check finding metadata for status_code
                if _cv_status == 0:
                    try:
                        _cv_status = int(finding.metadata.get("status_code", 0)) if finding.metadata else 0
                    except (ValueError, TypeError):
                        _cv_status = 0
                if _cv_status == 0:
                    _cv_status = 200  # last resort default

                _cv_ctx = HttpContext(
                    request_url=finding.target or finding.endpoint or "",
                    request_method="GET",
                    request_headers=_cv_req_headers,
                    request_body=_cv_raw,
                    response_headers=_cv_resp_headers,
                    response_body=_cv_resp_str,
                    response_status=_cv_status,
                    response_time_ms=0.0,
                )
                # Extract method from raw request
                if _cv_raw:
                    _cv_first = _cv_raw.strip().split("\n")[0]
                    for _cv_m in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                        if _cv_first.upper().startswith(_cv_m):
                            _cv_ctx.request_method = _cv_m
                            break

                _cv_verifier = ContextVerifier()
                _cv_res = _cv_verifier.verify(
                    vuln_type=finding.vulnerability_type or "",
                    context=_cv_ctx,
                    payload=finding.payload or "",
                    expected_evidence=str(finding.evidence or "")[:200],
                )
                # Map confidence to a bounded delta: [−15, +10]
                _cv_delta = (_cv_res.confidence - 50.0) / 5.0
                _cv_delta = max(-15.0, min(10.0, _cv_delta))
                score += _cv_delta
                layers.append({
                    "layer": "2c",
                    "name": "HTTP Context Verification",
                    "result": "genuine" if _cv_res.is_genuine else "suspicious",
                    "score_delta": _cv_delta,
                    "checks_passed": _cv_res.checks_passed,
                    "checks_failed": _cv_res.checks_failed,
                })
                evidence_chain.append(
                    f"L2c: Context verify: "
                    f"{'genuine' if _cv_res.is_genuine else 'suspicious'} "
                    f"(passed={len(_cv_res.checks_passed)}, "
                    f"failed={len(_cv_res.checks_failed)}, "
                    f"delta={_cv_delta:+.1f})"
                )
        except ImportError:
            pass
        except Exception as _cv_exc:
            logger.debug(f"Context verification skipped: {_cv_exc}")

        # ── Katman 3: Bağlam Analizi (Brain) ──
        #    Only skip brain for INFO severity (pure informational, no FP risk).
        #    ALL other severities (LOW/MEDIUM/HIGH/CRITICAL) get brain analysis.
        sev_str = str(finding.severity).lower() if finding.severity else "info"
        is_brain_worthy = sev_str not in ("info", "unknown", "")
        if is_brain_worthy:
            layer3_result, layer3_delta, brain_reasoning = await self._layer3_context_analysis(finding)
        else:
            layer3_result, layer3_delta, brain_reasoning = "skipped_low_priority", 0.0, ""
        # ── v4.0 Guard: Prevent brain from overriding strong KnownFP matches ──
        # When KnownFPMatcher applies a heavy penalty (≤ -20), brain's positive
        # contribution is capped at +5.  The brain can still reduce (deny) but
        # cannot single-handedly negate a curated FP pattern match.
        if layer1_penalty <= -20 and layer3_delta > 5.0:
            _original_brain_delta = layer3_delta
            layer3_delta = 5.0
            evidence_chain.append(
                f"L3-cap: Brain capped {_original_brain_delta:+.0f}→+5 "
                f"(KnownFP penalty={layer1_penalty})"
            )
        # ── v5.0 Guard: Hard ceiling when detector score is very low ──
        # If accumulated evidence already drove score below 20, brain alone
        # should not be able to rehabilitate above 45.
        _pre_brain_score = score
        score += layer3_delta
        if _pre_brain_score < 20.0 and layer3_delta > 0 and score > 45.0:
            _capped_score = min(45.0, _pre_brain_score + 25.0)
            evidence_chain.append(
                f"L3-ceil: pre-brain {_pre_brain_score:.0f} + brain {layer3_delta:+.0f} "
                f"→ capped {score:.0f}→{_capped_score:.0f}"
            )
            score = _capped_score
        layers.append({
            "layer": 3,
            "name": "Context Analysis (Brain 32B)",
            "result": layer3_result,
            "score_delta": layer3_delta,
            "reasoning": brain_reasoning,
        })
        if brain_reasoning:
            evidence_chain.append(f"L3: Brain analysis: {brain_reasoning[:200]}")

        # ── Katman 4: Payload Doğrulama ──
        layer4_result, layer4_delta = self._layer4_payload_verification(finding)
        score += layer4_delta
        layers.append({
            "layer": 4,
            "name": "Payload Verification",
            "result": layer4_result,
            "score_delta": layer4_delta,
        })
        evidence_chain.append(f"L4: Payload verification: {layer4_result}")

        # ── Katman 5: WAF/CDN Tespiti ──
        waf_detected, waf_name, layer5_delta = self._layer5_waf_detection(finding)
        score += layer5_delta
        layers.append({
            "layer": 5,
            "name": "WAF/CDN Detection",
            "result": f"WAF detected: {waf_name}" if waf_detected else "No WAF",
            "score_delta": layer5_delta,
            "waf": waf_name,
        })
        if waf_detected:
            evidence_chain.append(f"L5: WAF detected: {waf_name}")

        # ── Katman 6: Re-request Verification (V6-T4-2) ──
        # Only run for MEDIUM+ severity findings worth verifying
        # v5.0: When brain unavailable, also verify LOW severity (compensate for no brain analysis)
        _l6_sev = finding.severity in (SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL)
        _l6_no_brain = not _brain_ok and finding.severity == SeverityLevel.LOW
        if _l6_sev or _l6_no_brain:
            try:
                layer6_result, layer6_delta = await self._layer6_rerequest_verify(finding)
                score += layer6_delta
                layers.append({
                    "layer": 6,
                    "name": "Re-request Verify",
                    "result": layer6_result,
                    "score_delta": layer6_delta,
                })
                evidence_chain.append(f"L6: Re-request: {layer6_result}")
            except Exception as exc:
                logger.warning("Layer 6 re-request verification failed: {}", exc)

        # ── Final Skor Hesaplama ──
        # Merge layer-based score with ConfidenceScorer factor analysis.
        # The layer score reflects tool-specific + brain analysis,
        # while ConfidenceScorer captures richer semantic factors.
        layer_score = max(0.0, min(100.0, score))

        # Build factor list from layer results for ConfidenceScorer
        cs_factors: list[str] = []
        # Multi-tool factor
        for lay in layers:
            if lay.get("layer") == 2:
                res = lay.get("result", "")
                if "confirmed_strong" in res:
                    cs_factors.append("multi_tool_confirmed_3plus")
                elif "confirmed" in res and "single" not in res:
                    cs_factors.append("multi_tool_confirmed_2")
                elif "single_tool_only" in res:
                    cs_factors.append("single_tool_only")
        # Payload factors
        for lay in layers:
            if lay.get("layer") == 4:
                res = lay.get("result", "")
                if "payload_reflected" in res and "encoded" not in res:
                    cs_factors.append("payload_reflected_unencoded")
                elif "encoded" in res:
                    cs_factors.append("payload_reflected_encoded")
                elif "no_payload" in res:
                    cs_factors.append("no_payload_evidence")
                elif "evidence_present" in res or "http_exchange" in res:
                    cs_factors.append("evidence_chain_complete")
        # WAF/CDN factor
        if waf_detected:
            cs_factors.append("waf_detected")
        elif waf_name.startswith("CDN:"):
            cs_factors.append("cdn_detected")
        else:
            cs_factors.append("no_waf_interference")

        # Response diff factor (from L6 rerequest)
        for lay in layers:
            if lay.get("layer") == 6:
                _l6_res = lay.get("result", "")
                if "reproduced" in _l6_res and "not reproduced" not in _l6_res:
                    cs_factors.append("response_diff_significant")

        # Tool quirk factor (from L1c)
        for lay in layers:
            if lay.get("layer") == "1c":
                if lay.get("score_delta", 0) < 0:
                    cs_factors.append("tool_known_fp_for_type")
        # Brain factor
        # v4.0 Guard: When KnownFPMatcher applied heavy penalty, suppress
        # "brain_analysis_confirms" in CS to prevent score inflation.
        _brain_fp_capped = (layer1_penalty <= -20)
        if brain_reasoning:
            for lay in layers:
                if lay.get("layer") == 3:
                    if lay.get("score_delta", 0) > 0:
                        if _brain_fp_capped:
                            pass  # Suppress brain-confirms in CS when FP pattern matched
                        else:
                            cs_factors.append("brain_analysis_confirms")
                    elif lay.get("score_delta", 0) < 0:
                        cs_factors.append("brain_analysis_denies")
        # FP pattern factor
        if fp_patterns:
            cs_factors.append("known_fp_pattern_match")
        elif finding.vulnerability_type:
            # Check if this matches a known vuln pattern
            vt_lower = finding.vulnerability_type.lower().replace(" ", "_")
            try:
                from src.brain.memory.vuln_patterns import ALL_PATTERNS
                if vt_lower in ALL_PATTERNS:
                    cs_factors.append("known_vuln_pattern_match")
            except Exception as _exc:
                logger.debug(f"fp detector error: {_exc}")
        # Severity factor
        if sev_str in ("critical",):
            cs_factors.append("critical_severity")
        elif sev_str == "info":
            cs_factors.append("info_only_finding")

        # ── Metadata/tag-based factors ──
        # Tools embed rich signals in finding.tags and finding.metadata
        # that should map to ConfidenceScorer factors.
        _tags = set(t.lower() for t in (finding.tags or []))
        _meta = finding.metadata or {}

        # OOB callback (interactsh / blind SSRF/XXE) — quality-tiered (v5.0)
        if ("oob" in _tags or "interactsh" in _tags
                or _meta.get("oob_domain") or _meta.get("interactsh_callback")):
            _oob_quality = _meta.get("callback_quality", "")
            if _oob_quality == "high":
                cs_factors.append("oob_callback_high")
            elif _oob_quality == "medium":
                cs_factors.append("oob_callback_medium")
            elif _oob_quality == "low":
                cs_factors.append("oob_callback_low")
            elif _oob_quality == "infrastructure":
                cs_factors.append("oob_callback_infrastructure")
            else:
                # Legacy — no quality annotation, use original factor
                cs_factors.append("oob_callback_received")

        # Time-based blind injection
        if ("time_based" in _tags or _meta.get("time_based")
                or _meta.get("detection_method") == "time_based"):
            cs_factors.append("time_based_confirmed")

        # Data extraction
        if ("data_extraction" in _tags or "extracted" in _tags
                or _meta.get("data_extracted")):
            cs_factors.append("data_extracted")

        # Payload executed (confirmed execution, not just reflection)
        if _meta.get("payload_executed"):
            cs_factors.append("payload_executed")

        # Error message leaked (SQL errors, stack traces)
        _evidence_lower = (finding.evidence or "").lower()
        if any(sig in _evidence_lower for sig in (
            "syntax error", "sql syntax", "mysql_fetch", "pg_query",
            "ora-", "stack trace", "traceback", "exception in",
        )):
            cs_factors.append("error_message_leaked")

        # Calculate ConfidenceScorer result
        cs_breakdown = self.confidence_scorer.calculate(
            factors=cs_factors,
            base_score=original_confidence,
        )

        # ── V23: Bayesian Probability Filter ──
        # Independent Bayesian evaluation based on accumulated evidence signals.
        # Contributes a bounded delta (±8) to the layer score.
        _bayesian_delta = 0.0
        try:
            from src.fp_engine.scoring.bayesian_filter import BayesianFilter
            _bf = BayesianFilter(default_prior=layer_score / 100.0 if layer_score > 0 else 0.5)
            _vt = finding.vulnerability_type.lower().replace(" ", "_") if finding.vulnerability_type else "default"
            # Build evidence dict from what layers have observed
            _bf_evidence: dict[str, bool] = {}
            # Multi-tool signals
            for lay in layers:
                if lay.get("layer") == 2:
                    if "confirmed" in lay.get("result", ""):
                        _bf_evidence["multi_tool_agree"] = True
                    elif "single_tool_only" in lay.get("result", ""):
                        _bf_evidence["multi_tool_agree"] = False
            # Payload signals
            for lay in layers:
                if lay.get("layer") == 4:
                    res = lay.get("result", "")
                    if "payload_reflected" in res and "encoded" not in res:
                        _bf_evidence["payload_reflected_unencoded"] = True
                    elif "no_payload" in res:
                        _bf_evidence["payload_reflected_unencoded"] = False
            # WAF signal
            _bf_evidence["waf_block"] = waf_detected
            # OOB signal
            if any("oob" in str(lay.get("result", "")).lower() for lay in layers):
                _bf_evidence["oob_callback"] = True
            # Re-request signal
            for lay in layers:
                if lay.get("layer") == 6:
                    _bf_evidence["response_anomaly"] = lay.get("score_delta", 0) > 0

            if _bf_evidence:
                _bf_result = _bf.evaluate(_vt, _bf_evidence, prior=layer_score / 100.0)
                if _bf_result.signals_used >= 2:
                    # Map posterior (0-1) to a bounded delta: ±15 max
                    _bayesian_delta = (_bf_result.posterior - 0.5) * 30.0
                    _bayesian_delta = max(-15.0, min(15.0, _bayesian_delta))
                    layer_score = max(0.0, min(100.0, layer_score + _bayesian_delta))
                    layers.append({
                        "layer": "8_bayesian",
                        "name": "Bayesian Probability Filter",
                        "result": f"posterior={_bf_result.posterior:.3f} verdict={_bf_result.verdict}",
                        "score_delta": round(_bayesian_delta, 1),
                        "signals_used": _bf_result.signals_used,
                    })
                    evidence_chain.append(
                        f"L8: Bayesian filter: posterior={_bf_result.posterior:.3f} "
                        f"delta={_bayesian_delta:+.1f} ({_bf_result.signals_used} signals)"
                    )
        except ImportError:
            pass
        except Exception as _bf_exc:
            logger.debug(f"Bayesian filter skipped: {_bf_exc}")

        # Weighted merge: 60% layer score (richer context), 40% factor scorer
        final_score = max(0.0, min(100.0,
            layer_score * 0.6 + cs_breakdown.final_score * 0.4
        ))
        final_score = round(final_score, 1)

        layers.append({
            "layer": 7,
            "name": "ConfidenceScorer (factor-based)",
            "result": f"factors={cs_factors}, scorer={cs_breakdown.final_score:.1f}",
            "score_delta": round(cs_breakdown.final_score - 50.0, 1),
            "cs_tier": cs_breakdown.tier,
            "cs_verdict": cs_breakdown.verdict,
        })
        evidence_chain.append(
            f"L7: ConfidenceScorer factors={len(cs_factors)} "
            f"score={cs_breakdown.final_score:.1f} tier={cs_breakdown.tier}"
        )

        # ── V14-T1-3: Semantic verdict integration ──
        # When ConfidenceScorer's semantic verdict STRONGLY disagrees with
        # the score-based verdict, apply a correction bump.
        cs_verdict_str = cs_breakdown.verdict  # real/needs_review/likely_fp/false_positive
        if cs_verdict_str == "real" and final_score < FP_MEDIUM_CONFIDENCE_THRESHOLD:
            # CS says confirmed real but score is low → bump up
            _bump = min(10.0, FP_MEDIUM_CONFIDENCE_THRESHOLD - final_score + 1)
            final_score = min(100.0, final_score + _bump)
            evidence_chain.append(f"L7b: CS-verdict-boost +{_bump:.1f} (scorer says real, score was low)")
        elif cs_verdict_str == "false_positive" and final_score >= FP_LOW_CONFIDENCE_THRESHOLD:
            # CS says FP but score is moderate → pull down
            _pull = min(10.0, final_score - FP_LOW_CONFIDENCE_THRESHOLD + 1)
            final_score = max(0.0, final_score - _pull)
            evidence_chain.append(f"L7b: CS-verdict-pull -{_pull:.1f} (scorer says FP, score was moderate)")

        final_score = round(final_score, 1)

        # ── v4.0 Final Guard: Hard FP-pattern ceiling ──
        # If KnownFPMatcher applied a strong penalty (≤ -20), the finding
        # is a curated known-FP.  No combination of brain confirmation,
        # no-WAF bonus, or CS-verdict boost should push it past the
        # pipeline threshold.  Enforce a hard ceiling at 49.9.
        _known_fp_capped = False
        if layer1_penalty <= -20:
            _known_fp_capped = True  # Mark for downstream pipeline guards
            if final_score >= FP_MEDIUM_CONFIDENCE_THRESHOLD:
                _pre_ceil = final_score
                final_score = FP_MEDIUM_CONFIDENCE_THRESHOLD - 0.1  # just below threshold
                evidence_chain.append(
                    f"L-final: KnownFP ceiling {_pre_ceil:.1f}→{final_score:.1f} "
                    f"(pattern penalty={layer1_penalty})"
                )

        # Karar ver
        if final_score >= FP_AUTO_REPORT_THRESHOLD:
            status = FindingStatus.VERIFIED
            verdict = "real"
            self._real_count += 1
        elif final_score >= FP_MEDIUM_CONFIDENCE_THRESHOLD:
            status = FindingStatus.VERIFIED
            verdict = "needs_review"
            self._review_count += 1
        elif final_score >= FP_LOW_CONFIDENCE_THRESHOLD:
            status = FindingStatus.RAW
            verdict = "needs_review"
            self._review_count += 1
        else:
            status = FindingStatus.FALSE_POSITIVE
            verdict = "false_positive"
            self._fp_count += 1

        logger.info(
            f"FP Analysis complete | finding='{finding.title[:50]}' | "
            f"score={final_score:.1f} | verdict={verdict} | "
            f"tool={finding.tool_name}"
        )

        return FPVerdict(
            finding=finding,
            status=status,
            confidence_score=final_score,
            verdict=verdict,
            verification_layers=layers,
            evidence_chain=evidence_chain,
            reasoning=brain_reasoning,
            fp_patterns_matched=fp_patterns,
            waf_detected=waf_detected,
            known_fp_capped=_known_fp_capped,
        )

    async def analyze_batch(self, findings: list[Finding]) -> list[FPVerdict]:
        """Birden fazla bulguyu paralel analiz et (MED-6 fix)."""
        tasks = [self.analyze(finding) for finding in findings]
        verdicts = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[FPVerdict] = []
        for i, v in enumerate(verdicts):
            if isinstance(v, FPVerdict):
                results.append(v)
            else:
                logger.error(f"FP analysis failed for finding '{findings[i].title[:50]}': {v}")
                # Create a fallback verdict — preserve original confidence, mark as needs_review
                # Do NOT set confidence to 0 (that would discard real vulns as FP)
                original_conf = getattr(findings[i], 'confidence', 50.0) or 50.0
                results.append(FPVerdict(
                    finding=findings[i],
                    status=FindingStatus.RAW,
                    confidence_score=original_conf,
                    verdict="needs_review",
                    reasoning=f"FP analysis error: {v}",
                ))
        return results

    def get_reportable(self, verdicts: list[FPVerdict]) -> list[FPVerdict]:
        """Raporlanabilir bulguları filtrele."""
        return [v for v in verdicts if v.is_reportable]

    # ── Doğrulama Katmanları ──────────────────────────────────

    def _layer0_inherent_reliability(
        self, finding: Finding
    ) -> tuple[float, str]:
        """Katman 0: Tool/finding-type inherent reliability adjustment.

        Deterministic tools (header_checker, etc.) produce factual findings
        that cannot be false positives. They get a confidence boost.

        Heuristic tools (tech_cve_checker, etc.) get moderate adjustments.

        Nuclei findings with HTTP evidence get an evidence-richness boost.
        """
        delta = 0.0
        reasons: list[str] = []
        tool = finding.tool_name or ""

        # Tool-based deterministic boost
        if tool in self._DETERMINISTIC_TOOLS:
            delta += self._DETERMINISTIC_TOOLS[tool]
            reasons.append(f"deterministic tool '{tool}'")
        elif tool in self._HEURISTIC_TOOLS:
            delta += self._HEURISTIC_TOOLS[tool]
            reasons.append(f"heuristic tool '{tool}'")

        # Nuclei evidence richness: HTTP request+response = strong evidence
        if tool == "nuclei":
            if finding.http_request and finding.http_response:
                delta += 15.0
                reasons.append("nuclei with HTTP evidence")
            elif finding.http_request or finding.http_response:
                delta += 8.0
                reasons.append("nuclei with partial HTTP evidence")
            # CVE-tagged nuclei findings are higher quality
            if finding.cvss_score and finding.cvss_score > 0:
                delta += 5.0
                reasons.append(f"CVSS score present ({finding.cvss_score})")

        # Severity-based: INFO findings are nearly always true
        sev = str(finding.severity).lower() if finding.severity else ""
        if sev == "info":
            delta += 10.0
            reasons.append("INFO severity (factual)")

        # ── V24: Historical FP feedback adjustment ──
        try:
            from src.fp_engine.learning.fp_feedback import FPFeedbackManager
            _fb = FPFeedbackManager()
            _vuln_t = finding.vulnerability_type or ""
            _fb_adj = _fb.get_confidence_adjustment(tool, _vuln_t)
            if abs(_fb_adj) >= 1.0:
                # Cap historical adjustment to ±15 to prevent runaway
                _fb_adj = max(-15.0, min(5.0, _fb_adj))
                delta += _fb_adj
                reasons.append(f"historical FP feedback ({_fb_adj:+.0f})")
        except ImportError:
            pass
        except Exception:
            pass

        reason = "; ".join(reasons) if reasons else "no inherent adjustment"
        return delta, reason

    def _layer1_pattern_matching(
        self, finding: Finding
    ) -> tuple[str, float, list[str]]:
        """Katman 1: Bilinen FP kalıplarıyla eşleme."""
        total_penalty = 0.0
        matched_patterns: list[str] = []

        tool_patterns = self.known_patterns.get(finding.tool_name, [])

        for fp in tool_patterns:
            pattern = fp["pattern"].lower()
            check_fields = [
                finding.title.lower(),
                finding.description.lower(),
                finding.vulnerability_type.lower(),
                finding.raw_output.lower()[:1000],
            ]

            if any(pattern in field for field in check_fields):
                total_penalty += fp.get("penalty", -10)
                matched_patterns.append(fp["pattern"])
                logger.debug(f"FP pattern matched | pattern={fp['pattern']} | penalty={fp['penalty']}")

        # ── KnownFPMatcher: 100-pattern sophisticated rule engine ──
        _url = finding.endpoint or finding.target
        finding_dict = {
            "vuln_type": finding.vulnerability_type,
            "type": finding.vulnerability_type,
            "finding_type": (finding.metadata or {}).get("finding_type", ""),
            "tool": finding.tool_name,
            "source_tool": finding.tool_name,
            "url": _url,
            "endpoint": _url,
            "title": finding.title,
            "name": finding.title,
            "evidence": finding.evidence,
            "description": finding.description,
            "response_body": finding.http_response,
            "response": finding.http_response,
            "header": finding.http_response or "",          # Response headers live inside http_response
            "headers": finding.http_response or "",         # Alias for header
            "status_code": (finding.metadata or {}).get("status_code", ""),
            "severity": finding.severity.value if finding.severity else "",
            "confidence_score": str(finding.confidence) if finding.confidence else "",
            "tags": finding.tags,
        }
        matcher_result = self._known_fp_matcher.check(finding_dict)
        if matcher_result["is_known_fp"]:
            total_penalty += matcher_result["total_penalty"]
            for m in matcher_result["matches"]:
                matched_patterns.append(f"{m.id}:{m.name}")

        if matched_patterns:
            return "fp_patterns_found", total_penalty, matched_patterns
        return "pass", 0.0, []

    def _layer1d_host_profile_adjustment(self, finding: Finding) -> float:
        """Layer 1d: Adjust confidence based on host intelligence profile.

        Uses HostIntelProfile data to apply context-aware adjustments:
        - CDN_ONLY hosts: heavy penalty (most findings are FP on pure CDNs)
        - STATIC_SITE: penalty for dynamic vuln types (SQLi, RCE, SSTI, etc.)
        - AUTH_GATED: penalty if finding doesn't indicate authenticated testing
        - REDIRECT_HOST: penalty for non-redirect findings
        - Confidence modifier from profile applied directly
        """
        if not self._host_profiles:
            return 0.0

        # Determine which host this finding belongs to
        finding_url = finding.endpoint or finding.target or ""
        if isinstance(finding_url, list):
            finding_url = finding_url[0] if finding_url else ""
        finding_url = str(finding_url)

        matched_profile: dict[str, Any] | None = None
        for hp_key, hp_dict in self._host_profiles.items():
            if not isinstance(hp_dict, dict):
                continue
            # Match by URL prefix or hostname containment
            if (
                finding_url.startswith(hp_key)
                or hp_key.rstrip("/") in finding_url
            ):
                matched_profile = hp_dict
                break

        if not matched_profile:
            return 0.0

        delta = 0.0
        host_type = matched_profile.get("host_type", "unknown")
        vuln_type = (finding.vulnerability_type or "").lower().replace(" ", "_")

        # CDN-only hosts: most findings are artifacts
        if host_type == "cdn_only":
            delta -= 20.0

        # Static sites: dynamic vulnerability types are almost certainly FP
        elif host_type == "static_site":
            _dynamic_vulns = {
                "sql_injection", "sqli", "command_injection", "rce",
                "remote_code_execution", "ssti", "template_injection",
                "deserialization", "file_upload", "xxe",
                "nosql_injection", "ldap_injection",
                "race_condition", "mass_assignment",
            }
            if vuln_type in _dynamic_vulns or any(v in vuln_type for v in _dynamic_vulns):
                delta -= 15.0

        # Auth-gated hosts: if scan wasn't authenticated, findings are suspect
        elif host_type == "auth_gated":
            if not self._auth_headers:
                delta -= 10.0

        # Redirect hosts: non-redirect findings are likely artifacts
        elif host_type == "redirect_host":
            if vuln_type not in ("open_redirect", "header_injection", "crlf"):
                delta -= 12.0

        # Apply profile's own confidence modifier (from HostProfiler classification)
        conf_mod = matched_profile.get("confidence_modifier", 0.0)
        if isinstance(conf_mod, (int, float)):
            delta += conf_mod

        # Cap total adjustment
        return max(-25.0, min(10.0, delta))

    def _layer2_multi_tool_check(self, finding: Finding) -> tuple[str, float]:
        """Katman 2: Bulguyu bulan araç sayısına göre değerlendir.

        Tools in _SINGLE_TOOL_OK get no penalty for being single-tool,
        because their findings are inherently single-source and factual.
        """
        # MED-5 fix: Check metadata for cross-verification info,
        # fall back to tags, and always include the source tool.
        confirmed_by: list[str] = []

        # Check metadata first (preferred — only reliable source for cross-tool confirmation)
        if isinstance(finding.metadata, dict):
            raw_confirmed = finding.metadata.get("confirmed_by_tools")
            if not raw_confirmed:
                # Backward compatibility for historical finding payloads/tests.
                raw_confirmed = finding.metadata.get("confirmed_by")

            if isinstance(raw_confirmed, list):
                confirmed_by = [str(t).strip() for t in raw_confirmed if str(t).strip()]
            elif isinstance(raw_confirmed, str) and raw_confirmed.strip():
                confirmed_by = [raw_confirmed.strip()]

        # NOTE: tag-based fallback REMOVED — tags like "cve-2024-1234", "xss",
        # "tech-detect" are NOT tool names and inflated multi-tool confirmation.

        # Always count the source tool itself
        if finding.tool_name and finding.tool_name not in confirmed_by:
            confirmed_by.append(finding.tool_name)

        if len(confirmed_by) >= 3:
            return "multi_tool_confirmed_strong", 20.0
        elif len(confirmed_by) >= 2:
            return "multi_tool_confirmed", 15.0
        elif len(confirmed_by) == 1:
            # Don't penalize tools that are expected to be single-source
            if finding.tool_name in self._SINGLE_TOOL_OK:
                return "single_tool_expected", 0.0
            return "single_tool_only", -15.0
        else:
            return "unknown_tools", -5.0

    async def _layer3_context_analysis(
        self, finding: Finding
    ) -> tuple[str, float, str]:
        """Katman 3: Brain ile bağlam analizi.

        Uses PRIMARY brain (/think mode) for HIGH/CRITICAL findings (deep analysis).
        Uses SECONDARY brain (/no_think mode) for MEDIUM/LOW (speed).
        Each call is limited to 180s (PRIMARY) or 120s (SECONDARY).
        """
        if self.brain_engine is None:
            return "skipped_no_brain", 0.0, ""

        # C10: Check brain-down flag — but also check if brain has recovered
        _intel = self.intelligence_engine
        if _intel and getattr(_intel, '_brain_down', False):
            # Check auto-recovery: if _brain_down_since + recovery_timeout elapsed,
            # try a lightweight probe before giving up
            _down_since = getattr(_intel, '_brain_down_since', None)
            _recovery_timeout = getattr(_intel, '_brain_recovery_timeout', 300)
            if _down_since and (time.time() - _down_since) > _recovery_timeout:
                # Attempt recovery: reset flag and let the call proceed
                try:
                    _intel._brain_down = False
                    logger.info("Brain-down flag cleared (recovery timeout elapsed) — retrying")
                except Exception:
                    pass
            else:
                return "skipped_brain_down", 0.0, ""
        # Fallback: check brain_confirmed_down on brain_engine (set by orchestrator)
        if getattr(self.brain_engine, '_brain_confirmed_down', False):
            return "skipped_brain_down", 0.0, ""

        from src.brain.prompts.fp_elimination import build_fp_analysis_prompt

        prompt = build_fp_analysis_prompt(finding)

        # Use PRIMARY for HIGH/CRITICAL findings (better accuracy matters)
        _is_high_sev = finding.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
        _brain_type = BrainType.PRIMARY if _is_high_sev else BrainType.SECONDARY
        _timeout = 180.0 if _is_high_sev else 120.0

        try:
            response = await asyncio.wait_for(
                self.brain_engine.think(
                    prompt=prompt,
                    brain=_brain_type,
                    system_prompt=(
                        "You are an expert cybersecurity analyst. "
                        "Analyze the given vulnerability finding and determine whether it is "
                        "a REAL vulnerability or a FALSE POSITIVE. "
                        "Respond in JSON format: "
                        '{"verdict": "real"|"false_positive", "confidence": 0-100, "reasoning": "..."}'
                    ),
                    json_mode=True,
                    temperature=0.05,
                ),
                timeout=_timeout,
            )

            try:
                # Use shared JSON extractor with heuristic fallback
                from src.utils.json_utils import extract_json_or_heuristic
                raw_text = response.text.strip()

                analysis = extract_json_or_heuristic(
                    raw_text,
                    heuristic_keywords={
                        "false_positive": {"verdict": "false_positive", "confidence": 40, "reasoning": raw_text[:300]},
                        "false positive": {"verdict": "false_positive", "confidence": 40, "reasoning": raw_text[:300]},
                        "real": {"verdict": "real", "confidence": 60, "reasoning": raw_text[:300]},
                    },
                )

                if not analysis:
                    logger.warning("Brain response not parseable as JSON")
                    return "parse_error", 0.0, raw_text[:200]

                brain_verdict = analysis.get("verdict", "unknown")
                brain_confidence = _safe_float(analysis.get("confidence", 50), 50.0)
                reasoning = analysis.get("reasoning", "")

                # Brain güvenine göre skor ayarla
                if brain_verdict == "real":
                    delta = min(15.0, brain_confidence * 0.15)
                elif brain_verdict == "false_positive":
                    delta = max(-20.0, -brain_confidence * 0.2)
                else:
                    delta = 0.0

                return brain_verdict, delta, reasoning

            except (json.JSONDecodeError, ValueError, KeyError):
                logger.warning("Brain response not parseable as JSON")
                return "parse_error", 0.0, response.text[:200]

        except asyncio.TimeoutError:
            logger.warning(f"Brain FP analysis timed out ({_timeout}s) for: {finding.title[:50]}")
            # Timeout = incomplete analysis → apply heuristic penalty
            # so the finding doesn't auto-pass through on existing score alone.
            return "timeout", -10.0, f"Brain analysis timed out ({_timeout}s) — incomplete verification"
        except Exception as e:
            logger.error(f"Brain analysis failed: {e}")
            return "error", 0.0, str(e)

    def _layer4_payload_verification(self, finding: Finding) -> tuple[str, float]:
        """Katman 4: Payload doğrulama."""
        score_delta = 0.0

        # Payload var mı?
        if finding.payload:
            score_delta += 5.0

            # Response'da payload reflect olmuş mu?
            if finding.http_response and finding.payload in finding.http_response:
                score_delta += 15.0
                return "payload_reflected", score_delta

            # Only check encoded variants if raw payload NOT reflected
            encoded_variants = [
                finding.payload.replace("<", "&lt;"),
                finding.payload.replace("<", "%3C"),
                finding.payload.replace("'", "&#39;"),
            ]
            if finding.http_response and any(
                enc in finding.http_response for enc in encoded_variants
            ):
                score_delta -= 10.0  # Encoded — muhtemelen güvenli
                return "encoded_reflection", score_delta

            return "no_reflection", score_delta

        # Evidence var mı?
        if finding.evidence:
            score_delta += 10.0
            return "evidence_present", score_delta

        # HTTP request/response pair counts as evidence (common for nuclei)
        if finding.http_request and finding.http_response:
            score_delta += 8.0
            return "http_exchange_present", score_delta
        elif finding.http_request or finding.http_response:
            score_delta += 4.0
            return "partial_http_evidence", score_delta

        return "no_payload_no_evidence", -10.0

    def _layer5_waf_detection(
        self, finding: Finding
    ) -> tuple[bool, str, float]:
        """Katman 5: WAF/CDN tespiti.

        Enhanced (V24): Uses WafArtifactDetector for deep block-page
        analysis with per-WAF penalty scores + ResponseIntel fallback.
        """
        response = finding.http_response or ""

        # ── V24: Try WafArtifactDetector for deep analysis ──
        try:
            from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector

            # Parse response headers/body/status from finding
            _wa_headers: dict[str, str] = {}
            _wa_body = ""
            _wa_status = 200
            _wa_cookies: dict[str, str] = {}

            if response:
                # Split raw response into headers and body
                _parts = response.split("\n\n", 1)
                _header_block = _parts[0] if _parts else ""
                _wa_body = _parts[1] if len(_parts) > 1 else response

                for _hline in _header_block.split("\n"):
                    if ": " in _hline:
                        _hk, _hv = _hline.split(": ", 1)
                        _wa_headers[_hk.strip().lower()] = _hv.strip()
                    elif _hline.upper().startswith("HTTP/"):
                        # Status line: HTTP/1.1 403 Forbidden
                        _status_parts = _hline.split(" ", 2)
                        if len(_status_parts) >= 2:
                            try:
                                _wa_status = int(_status_parts[1])
                            except ValueError:
                                pass

                # Extract cookies from headers (may have multiple Set-Cookie lines)
                # In raw response, each Set-Cookie appears on its own line
                for _hline2 in _header_block.split("\n"):
                    if ": " in _hline2:
                        _h2k, _h2v = _hline2.split(": ", 1)
                        if _h2k.strip().lower() == "set-cookie":
                            # Parse cookie name=value (before first ";")
                            _cookie_part = _h2v.strip().split(";", 1)[0]
                            if "=" in _cookie_part:
                                _ck_name, _ck_val = _cookie_part.split("=", 1)
                                _wa_cookies[_ck_name.strip()] = _ck_val.strip()

            _wa_detector = WafArtifactDetector()
            _wa_result = _wa_detector.analyze(
                response_headers=_wa_headers,
                response_body=_wa_body,
                status_code=_wa_status,
                cookies=_wa_cookies,
            )

            if _wa_result.get("waf_detected") or _wa_result.get("is_block_page"):
                _wa_name = _wa_result.get("waf_name", "unknown")
                _wa_penalty = _safe_float(_wa_result.get("total_penalty", -10), -10.0)
                _wa_penalty = max(-30.0, min(0.0, _wa_penalty))
                logger.debug(
                    f"WAF detected via WafArtifactDetector: {_wa_name} "
                    f"(penalty={_wa_penalty})"
                )
                return True, _wa_name, _wa_penalty

            if _wa_result.get("cdn_detected"):
                _cdn_name = _wa_result.get("cdn_name", "CDN")
                logger.debug(f"CDN detected: {_cdn_name}")
                # CDN alone is just a minor concern, not a penalty
                return False, f"CDN:{_cdn_name}", 3.0

        except ImportError:
            pass
        except Exception as _wa_exc:
            logger.debug(f"WafArtifactDetector skipped: {_wa_exc}")

        # ── Fallback: ResponseIntel pipeline-level signals ──
        ri = self.response_intel
        if ri:
            ri_headers = ri.get("interesting_headers", [])
            for h in ri_headers:
                sig = h.get("signal", "").lower()
                if "waf" in sig or "cdn" in sig or "firewall" in sig:
                    waf_name = h.get("value", h.get("header", "ResponseIntel-detected"))
                    logger.debug(f"WAF detected via ResponseIntel: {waf_name}")
                    return True, f"ResponseIntel:{waf_name}", -10.0

        # ── Fallback: Simple header signature check ──
        response_lower = response.lower()
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in response_lower:
                    logger.debug(f"WAF detected: {waf_name} | signature={sig}")
                    return True, waf_name, -10.0

        return False, "", 5.0  # WAF yok = iyi işaret

    # ── Katman 6: Re-request Verification (V6-T4-2) ──────────

    async def _layer6_rerequest_verify(
        self, finding: Finding
    ) -> tuple[str, float]:
        """Katman 6: Re-send the original request to verify reproducibility.

        Enhanced: reconstructs the full original request (method, headers,
        body, payload) instead of just a simple GET. This accurately
        replays POST-based attacks (SQLi, SSTI, etc.) and verifies
        whether the payload actually produces a different response
        compared to a clean control request.
        """
        url = finding.target or finding.endpoint
        if not url or not url.startswith("http"):
            return "skipped (no valid URL)", 0.0

        import httpx as _httpx

        try:
            # Determine HTTP method — default GET, use finding metadata if available
            method = "GET"
            request_body = None
            request_headers: dict[str, str] = {}

            # Extract method from finding metadata
            raw_req = finding.http_request or ""
            if raw_req:
                first_line = raw_req.strip().split("\n")[0] if raw_req.strip() else ""
                for m in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                    if first_line.upper().startswith(m):
                        method = m
                        break

            # Extract body from finding (for POST/PUT/PATCH)
            # Finding model stores body inside http_request raw text
            if method in ("POST", "PUT", "PATCH") and raw_req:
                # Body is after the double newline in raw request
                parts = raw_req.split("\n\n", 1)
                if len(parts) == 2:
                    request_body = parts[1]

            # Extract headers from finding metadata
            _meta = finding.metadata if isinstance(finding.metadata, dict) else {}
            _meta_headers = _meta.get("http_request_headers", None)
            if isinstance(_meta_headers, dict):
                request_headers = dict(_meta_headers)

            # Inject auth headers so authenticated findings can be reproduced.
            # Auth headers have lower priority — finding-specific headers win.
            if self._auth_headers:
                for k, v in self._auth_headers.items():
                    request_headers.setdefault(k, v)

            # Extract payload from finding for the control comparison
            payload_used = ""
            if hasattr(finding, "payload"):
                payload_used = finding.payload or ""
            elif hasattr(finding, "evidence"):
                # Try to extract payload from evidence text
                evidence_str = str(finding.evidence or "")
                if "payload" in evidence_str.lower():
                    payload_used = evidence_str[:200]

            async with _httpx.AsyncClient(
                timeout=15, verify=False, follow_redirects=False,
            ) as client:
                # 1. Re-send WITH payload (original request)
                try:
                    payload_resp = await client.request(
                        method=method,
                        url=url,
                        headers=request_headers or None,
                        content=request_body,
                    )
                    payload_status = payload_resp.status_code
                    payload_body = payload_resp.text
                    payload_body_len = len(payload_body)
                except _httpx.HTTPError:
                    return "error (payload request failed)", 0.0

                # 2. Control request: same URL but WITHOUT query params/payload
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(url)
                control_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, "", "", "",
                ))

                # For POST/PUT: send empty body as control
                control_body = "" if method in ("POST", "PUT", "PATCH") else None

                # For control: use auth headers but NOT finding-specific ones
                control_headers = dict(self._auth_headers) if self._auth_headers else None

                try:
                    control_resp = await client.request(
                        method=method,
                        url=control_url,
                        headers=control_headers,
                        content=control_body,
                    )
                    control_status = control_resp.status_code
                    control_body_text = control_resp.text
                    control_body_len = len(control_body_text)
                except _httpx.HTTPError:
                    # Control failed but payload worked — interesting signal
                    return "partial (control request failed, payload succeeded)", 3.0

                # 3. Deep differential analysis via ResponseDiffAnalyzer (V24)
                try:
                    from src.fp_engine.verification.response_diff import (
                        ResponseDiffAnalyzer,
                    )

                    _rda = ResponseDiffAnalyzer()
                    _normal = {
                        "status_code": control_status,
                        "body": control_body_text,
                        "headers": dict(control_resp.headers) if hasattr(control_resp, "headers") else {},
                        "time": getattr(control_resp, "elapsed", timedelta()).total_seconds(),
                    }
                    _payload = {
                        "status_code": payload_status,
                        "body": payload_body,
                        "headers": dict(payload_resp.headers) if hasattr(payload_resp, "headers") else {},
                        "time": getattr(payload_resp, "elapsed", timedelta()).total_seconds(),
                    }
                    _diff_result = _rda.analyze(
                        normal_response=_normal,
                        payload_response=_payload,
                        payload=payload_used,
                        vuln_type=finding.vulnerability_type or "",
                    )

                    # Use ResponseDiff for richer scoring
                    _rd_delta = _safe_float(
                        getattr(_diff_result, "confidence_delta", 0.0), 0.0
                    )
                    _rd_reflected = getattr(_diff_result, "payload_reflected", False)
                    _rd_encoded = getattr(_diff_result, "payload_encoded", False)
                    _rd_context = getattr(_diff_result, "payload_in_html_context", False)
                    _rd_vuln_specific = getattr(_diff_result, "vuln_specific_match", False)
                    _rd_timing = getattr(_diff_result, "timing_anomaly", False)
                    _rd_significant = getattr(_diff_result, "is_significant", False)

                    # Build composite label + score from ResponseDiff
                    _rd_signals: list[str] = []
                    _rd_score = 0.0
                    if _rd_reflected:
                        _rd_signals.append("reflected")
                        _rd_score += 8.0
                    if _rd_encoded:
                        _rd_signals.append(f"encoded:{getattr(_diff_result, 'encoding_type', '?')}")
                        _rd_score += 4.0
                    if _rd_context:
                        _rd_signals.append("in_html_context")
                        _rd_score += 4.0
                    if _rd_vuln_specific:
                        _rd_signals.append("vuln_specific")
                        _rd_score += 6.0
                    if _rd_timing:
                        _rd_signals.append("timing_anomaly")
                        _rd_score += 4.0

                    status_diff = payload_status != control_status
                    body_len_diff = abs(len(payload_body) - len(control_body_text))

                    if status_diff:
                        _rd_signals.append("status_diff")
                        _rd_score += 3.0
                    if body_len_diff > 50:
                        _rd_signals.append("body_diff")
                        _rd_score += 2.0

                    # No positive signals at all → not reproduced
                    if not _rd_signals:
                        return "not reproduced (ResponseDiff: no signals)", -8.0

                    # Cap final score
                    _rd_score = min(14.0, _rd_score)
                    if _rd_score <= 0 and not _rd_significant:
                        return "not reproduced (ResponseDiff: insignificant)", -8.0

                    _label = "reproduced" if _rd_score >= 6.0 else "partial"
                    return (
                        f"{_label} (ResponseDiff: {', '.join(_rd_signals[:4])})",
                        _rd_score,
                    )

                except ImportError:
                    pass
                except Exception as _rda_exc:
                    logger.debug(f"ResponseDiffAnalyzer skipped, using fallback: {_rda_exc}")

                # ── Fallback: simple ad-hoc comparison ──
                status_diff = payload_status != control_status
                body_len_diff = abs(payload_body_len - control_body_len)
                body_significant = body_len_diff > 50

                payload_reflected = False
                if payload_used and payload_used in payload_body:
                    payload_reflected = True
                elif payload_used:
                    from urllib.parse import unquote
                    decoded = unquote(payload_used)
                    if decoded in payload_body:
                        payload_reflected = True

                if payload_reflected and (status_diff or body_significant):
                    return "reproduced (payload reflected + response differs)", 12.0
                if payload_reflected:
                    return "reproduced (payload reflected in response)", 10.0
                if status_diff and body_significant:
                    return "reproduced (status + body differ)", 10.0
                if status_diff:
                    return "partial (status differs)", 5.0
                if body_significant:
                    return "partial (body length differs)", 3.0
                return "not reproduced (identical responses)", -8.0

        except Exception as exc:
            logger.warning("Layer 6 re-request failed: {}", exc)
            return "error", 0.0

    # ── İstatistikler ─────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """FP engine istatistikleri."""
        return {
            "total_analyzed": self._total_analyzed,
            "real_findings": self._real_count,
            "false_positives": self._fp_count,
            "needs_review": self._review_count,
            "fp_rate": round(
                self._fp_count / max(1, self._total_analyzed) * 100, 1
            ),
        }


__all__ = ["FPDetector", "FPVerdict", "KNOWN_FP_PATTERNS", "WAF_SIGNATURES"]
