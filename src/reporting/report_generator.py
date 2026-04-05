"""
WhiteHatHacker AI — Report Generator

Doğrulanmış zafiyet bulguları için profesyonel bug bounty raporları
oluşturur. HackerOne, Bugcrowd ve generic formatları destekler.

Brain 32B modeli ile ikna edici, profesyonel rapor yazılır.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, field_validator

from src.analysis.severity_calculator import SeverityCalculator
from src.utils.constants import BrainType, PlatformType, SeverityLevel


# ============================================================
# Veri Modelleri
# ============================================================

class ReportFinding(BaseModel):
    """Rapor edilecek tek bir bulgu."""

    title: str
    vulnerability_type: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    cvss_score: float = 0.0
    cvss_vector: str = ""

    # Açıklama
    summary: str = ""
    description: str = ""
    impact: str = ""

    # Reproduksiyon
    steps_to_reproduce: list[str] = []
    prerequisites: list[str] = []

    # Teknik Detaylar
    endpoint: str = ""
    parameter: str = ""
    payload: str = ""
    http_request: str = ""
    http_response: str = ""

    # Kanıtlar
    evidence: list[str] = []
    screenshots: list[str] = []
    poc_code: str = ""

    # Düzeltme
    remediation: str = ""
    references: list[str] = []
    cwe_ids: list[str] = []

    # Metadata
    confidence_score: float = 0.0
    tool_sources: list[str] = []
    target: str = ""
    metadata: dict[str, Any] = {}

    @field_validator(
        "endpoint", "target", "parameter", "payload",
        "http_request", "http_response", "poc_code",
        "summary", "description", "impact", "remediation",
        mode="before",
    )
    @classmethod
    def _coerce_str_fields(cls, v: Any) -> str:
        """Coerce non-string values to string (defense-in-depth).

        Tool wrappers and Brain/LLM may produce list, None, or non-string
        values for fields declared as str.
        """
        if v is None:
            return ""
        if isinstance(v, list):
            return v[0] if v else ""
        return str(v) if not isinstance(v, str) else v

    @field_validator("confidence_score", mode="before")
    @classmethod
    def _coerce_confidence(cls, v: Any) -> float:
        """Safely coerce confidence_score to float."""
        try:
            return float(v)
        except (ValueError, TypeError):
            return 0.0

    @field_validator("cvss_vector")
    @classmethod
    def validate_cvss_vector(cls, value: str) -> str:
        """Allow empty CVSS vectors, but reject malformed ones."""
        vector = (value or "").strip()
        if not vector:
            return ""

        try:
            SeverityCalculator().parse_vector(vector)
        except Exception as exc:
            logger.warning(f"Invalid CVSS vector dropped from report finding: {vector} ({exc})")
            return ""

        return vector


class Report(BaseModel):
    """Tam bir bug bounty raporu."""

    report_id: str = ""
    platform: PlatformType = PlatformType.GENERIC
    target: str = ""
    program_name: str = ""

    # İçerik
    title: str = ""
    executive_summary: str = ""
    findings: list[ReportFinding] = []

    # Metadata
    generated_at: float = 0.0
    session_id: str = ""
    total_scan_time: float = 0.0
    tools_used: list[str] = []

    # V13-T3-2: Report quality enhancement fields
    technology_stack: dict[str, Any] = {}   # host → tech info
    waf_detected: str = ""                  # WAF name or ""
    scan_profile: str = ""                  # stealth/balanced/aggressive

    # Dosya yolları
    markdown_path: str = ""
    html_path: str = ""
    json_path: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)


# ============================================================
# CVSS v3.1 Hesaplama
# ============================================================

CVSS_VULN_DEFAULTS: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "score": 8.6,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe": ["CWE-89"],
    },
    "command_injection": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-78"],
    },
    "xss_reflected": {
        "score": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": ["CWE-79"],
    },
    "xss_stored": {
        "score": 7.2,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "cwe": ["CWE-79"],
    },
    "xss_dom": {
        "score": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": ["CWE-79"],
    },
    "ssrf": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": ["CWE-918"],
    },
    "ssti": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-1336"],
    },
    "idor": {
        "score": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": ["CWE-639"],
    },
    "authentication_bypass": {
        "score": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": ["CWE-287"],
    },
    "cors_misconfiguration": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "cwe": ["CWE-942"],
    },
    "open_redirect": {
        "score": 4.7,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "cwe": ["CWE-601"],
    },
    "local_file_inclusion": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": ["CWE-22"],
    },
    "ssl_tls_misconfiguration": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": ["CWE-326"],
    },
    "information_disclosure": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-200"],
    },
    "race_condition": {
        "score": 5.9,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": ["CWE-362"],
    },
    "business_logic": {
        "score": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cwe": ["CWE-840"],
    },
    "rate_limit_bypass": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": ["CWE-799"],
    },
    # ── Additional types found in real scans ──
    "missing_security_header": {
        "score": 3.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-693"],
    },
    "clickjacking": {
        "score": 4.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cwe": ["CWE-1021"],
    },
    "outdated_software": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-1104"],
    },
    "known_cve": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-1104"],
    },
    "sensitive_url": {
        "score": 3.7,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-200"],
    },
    "interesting_endpoint": {
        "score": 2.0,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe": [],
    },
    "misconfiguration": {
        "score": 4.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cwe": ["CWE-16"],
    },
    "cve": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": [],
    },
    "crlf_injection": {
        "score": 5.4,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "cwe": ["CWE-113"],
    },
    # ── Aliases for custom checker vuln types ──
    "auth_bypass": {
        "score": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": ["CWE-287"],
    },
    "missing_rate_limit": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": ["CWE-307"],
    },
    "dangerous_http_method": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": ["CWE-749"],
    },
    "cookie_security": {
        "score": 3.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-614"],
    },
    "subdomain_takeover": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": ["CWE-923"],
    },
}


# ============================================================
# Report Generator
# ============================================================

class ReportGenerator:
    """
    Profesyonel bug bounty rapor oluşturma motoru.

    Doğrulanmış bulguları platform-uyumlu profesyonel raporlara
    dönüştürür. Brain 32B ile rapor metni zenginleştirilebilir.

    Kullanım:
        generator = ReportGenerator(brain_engine=engine)
        report = await generator.generate(
            findings=[...],
            target="example.com",
            platform=PlatformType.HACKERONE,
        )

        # Kaydet
        generator.save_markdown(report, "output/reports/")
        generator.save_json(report, "output/reports/")
    """

    def __init__(
        self,
        brain_engine: Any | None = None,
        output_dir: str = "output/reports",
    ) -> None:
        self.brain = brain_engine
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"ReportGenerator initialized | output={output_dir}")

    @staticmethod
    def _select_valid_cvss_vector(primary: Any, fallback: str) -> str:
        """Prefer a finding-provided CVSS vector only when it parses correctly."""
        candidate = str(primary or "").strip()
        if candidate:
            try:
                SeverityCalculator().parse_vector(candidate)
                return candidate
            except Exception as exc:
                logger.debug(f"Ignoring malformed finding CVSS vector '{candidate}': {exc}")
        return fallback

    async def generate(
        self,
        findings: list[Any],  # Finding or FPVerdict objects
        target: str,
        platform: PlatformType = PlatformType.GENERIC,
        program_name: str = "",
        session_id: str = "",
        scan_time: float = 0.0,
        tools_used: list[str] | None = None,
        use_brain: bool = True,
    ) -> Report:
        """
        Doğrulanmış bulgulardan rapor oluştur.

        Args:
            findings: Doğrulanmış bulgular
            target: Ana hedef
            platform: Hedef platform formatı
            program_name: Bug bounty program adı
            session_id: Tarama oturum ID'si
            scan_time: Toplam tarama süresi
            tools_used: Kullanılan araçlar
            use_brain: Brain ile rapor zenginleştir

        Returns:
            Report
        """
        report = Report(
            report_id=f"rpt_{int(time.time())}_{session_id[:8] if session_id else 'gen'}",
            platform=platform,
            target=target,
            program_name=program_name,
            generated_at=time.time(),
            session_id=session_id,
            total_scan_time=scan_time,
            tools_used=tools_used or [],
        )

        # Bulguları ReportFinding'e dönüştür
        for finding in findings:
            try:
                rf = self._convert_finding(finding)

                # Brain ile zenginleştir
                if use_brain and self.brain:
                    rf = await self._enrich_with_brain(rf)

                report.findings.append(rf)
            except Exception as _conv_err:
                logger.warning(
                    f"Finding conversion failed, skipping: {_conv_err} | "
                    f"finding_type={finding.get('vulnerability_type', 'unknown') if isinstance(finding, dict) else 'object'}"
                )

        # Severity'ye göre sırala (en kritik ilk)
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        report.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        # Report title
        if report.finding_count == 1:
            report.title = report.findings[0].title
        else:
            report.title = (
                f"Security Assessment Report: {target} "
                f"({report.finding_count} findings)"
            )

        # Executive summary
        report.executive_summary = self._generate_executive_summary(report)

        logger.info(
            f"Report generated | target={target} | "
            f"findings={report.finding_count} | "
            f"critical={report.critical_count} | "
            f"high={report.high_count}"
        )

        return report

    def _convert_finding(self, finding: Any) -> ReportFinding:
        """Finding objesini ReportFinding'e dönüştür. Dict veya object kabul eder."""
        # FPVerdict ise inner finding'i al
        actual = getattr(finding, "finding", finding)

        # Dict mi yoksa object mi?
        def _g(obj: Any, key: str, default: Any = "") -> Any:
            """Get attribute for both dicts and objects."""
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        vuln_type = str(_g(actual, "vulnerability_type", _g(actual, "type", ""))).lower()

        summary_text = self._first_non_empty_text(
            _g(actual, "summary", ""),
            _g(actual, "description", ""),
        )
        description_text = self._first_non_empty_text(
            _g(actual, "description", ""),
            summary_text,
        )
        impact_text = self._first_non_empty_text(
            _g(actual, "impact", ""),
            _g(actual, "business_impact", ""),
            _g(actual, "impact_analysis", ""),
        )

        # CVSS defaults
        cvss_info = CVSS_VULN_DEFAULTS.get(vuln_type, {
            "score": 5.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe": [],
        })

        # Use finding's CVSS if available (e.g. from nuclei), else defaults
        finding_cvss = _g(actual, "cvss_score", None)
        try:
            _fv = float(finding_cvss) if finding_cvss is not None else None
        except (ValueError, TypeError):
            _fv = None
        if _fv is not None and 0.0 <= _fv <= 10.0:
            cvss_score = _fv
        else:
            cvss_score = cvss_info["score"]

        cvss_vector = self._select_valid_cvss_vector(
            _g(actual, "cvss_vector", None) or _g(actual, "vector", None),
            cvss_info.get("vector", ""),
        )

        # Severity: prefer finding's original severity, then derive from CVSS
        finding_severity = _g(actual, "severity", "")
        if finding_severity:
            sev_str = str(finding_severity).lower()
            try:
                severity = SeverityLevel(sev_str)
            except (ValueError, KeyError):
                # Derive from CVSS score
                severity = self._severity_from_cvss(cvss_score)
        else:
            severity = self._severity_from_cvss(cvss_score)

        # Endpoint: dict'lerde "url" key, object'lerde "endpoint" attr
        endpoint_val = _g(actual, "url", "") or _g(actual, "endpoint", "")
        if isinstance(endpoint_val, list):
            endpoint_val = endpoint_val[0] if endpoint_val else ""
        elif not isinstance(endpoint_val, str):
            endpoint_val = str(endpoint_val)

        # Evidence: list veya string olabilir
        evidence_raw = _g(actual, "evidence", "")
        if isinstance(evidence_raw, list):
            evidence = evidence_raw
        elif evidence_raw:
            evidence = [str(evidence_raw)]
        else:
            evidence = []

        if isinstance(actual, dict):
            screenshot_candidates = self._normalize_string_list(
                actual.get("screenshots", []),
                actual.get("screenshot_path", ""),
            )
            tool_sources = self._normalize_string_list(
                actual.get("tool_sources", []),
                actual.get("tags", []),
                actual.get("tool", ""),
                actual.get("tool_name", ""),
                actual.get("source_tool", ""),
            )
            confidence_score = _g(actual, "confidence_score", _g(actual, "confidence", 0.0))
        else:
            screenshot_candidates = self._normalize_string_list(
                _g(actual, "screenshots", []),
                _g(actual, "screenshot_path", ""),
            )
            tool_sources = self._normalize_string_list(
                _g(actual, "tool_sources", []),
                _g(actual, "tags", []),
                _g(actual, "tool", ""),
                _g(actual, "tool_name", ""),
                _g(actual, "source_tool", ""),
            )
            confidence_score = _g(finding, "confidence_score", _g(actual, "confidence_score", _g(actual, "confidence", 0.0)))

        # Build PoC code: prefer brain-generated PoC (curl/script), then payload
        _poc_code = ""
        _poc_curl = _g(actual, "poc_curl", "")
        _poc_script_path = _g(actual, "poc_script_path", "")
        _brain_poc_steps = _g(actual, "brain_poc_steps", "")
        _poc_browser = _g(actual, "poc_browser_steps", "")
        if _poc_curl:
            _poc_code = _poc_curl
        elif _poc_script_path:
            # Read the PoC script file
            try:
                import os
                if os.path.isfile(_poc_script_path):
                    with open(_poc_script_path) as _pf:
                        _poc_code = _pf.read()[:3000]
            except Exception as _exc:
                _poc_code = f"# PoC: see {_poc_script_path}"
        elif _g(actual, "payload", ""):
            _poc_code = _g(actual, "payload", "")
        elif _g(actual, "curl_command", ""):
            _poc_code = _g(actual, "curl_command", "")
        # Append browser steps if available
        if _poc_browser and _poc_code:
            _poc_code += "\n\n# Browser Steps:\n# " + "\n# ".join(
                _poc_browser if isinstance(_poc_browser, list) else [str(_poc_browser)]
            )
        elif _brain_poc_steps and _poc_code:
            _poc_code += "\n\n# PoC Steps:\n# " + "\n# ".join(
                _brain_poc_steps if isinstance(_brain_poc_steps, list) else [str(_brain_poc_steps)]
            )

        # Preserve original finding metadata (poc_confirmed, risk_score, etc.)
        _orig_metadata = _g(actual, "metadata", {})
        _finding_metadata: dict[str, Any] = dict(_orig_metadata) if isinstance(_orig_metadata, dict) else {}

        # Extract evidence chain for the finding metadata (V13-T3-2)
        _evidence_chain = _g(actual, "evidence_chain", None) or []
        if isinstance(actual, dict):
            _evidence_chain = _evidence_chain or actual.get("fp_evidence_chain", [])
        if _evidence_chain and isinstance(_evidence_chain, list):
            _finding_metadata["evidence_chain"] = _evidence_chain

        return ReportFinding(
            title=_g(actual, "title", "Untitled Finding"),
            vulnerability_type=vuln_type,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            summary=summary_text,
            description=description_text,
            impact=impact_text,
            endpoint=endpoint_val,
            parameter=_g(actual, "parameter", ""),
            payload=_g(actual, "payload", ""),
            http_request=_g(actual, "http_request", ""),
            http_response=_g(actual, "http_response", ""),
            evidence=evidence,
            screenshots=screenshot_candidates,
            poc_code=_poc_code,
            cwe_ids=self._normalize_cwe_ids(
                _g(actual, "cwe", None) or _g(actual, "cwe_ids", None) or cvss_info.get("cwe", [])
            ),
            confidence_score=confidence_score,
            tool_sources=tool_sources,
            target=_g(actual, "target", ""),
            remediation=_g(actual, "remediation", "") or self._get_comprehensive_remediation(vuln_type),  # Bug 5.2m-3: preserve finding-provided remediation
            references=_g(actual, "references", None) or self._default_references(vuln_type),
            steps_to_reproduce=self._auto_generate_steps(actual, _g),
            metadata=_finding_metadata,
        )

    async def _enrich_with_brain(self, rf: ReportFinding) -> ReportFinding:
        """Brain 32B ile rapor metnini zenginleştir."""
        if not self.brain:
            return rf

        try:
            prompt = (
                f"You are writing a professional bug bounty report.\n"
                f"Vulnerability: {rf.title}\n"
                f"Type: {rf.vulnerability_type}\n"
                f"Endpoint: {rf.endpoint}\n"
                f"Parameter: {rf.parameter}\n"
                f"Payload: {rf.payload}\n"
                f"CVSS: {rf.cvss_score}\n\n"
                f"Write a concise JSON with:\n"
                f'{{"impact": "business impact analysis (2-3 sentences)",'
                f'"remediation": "actionable fix recommendation (2-3 sentences)",'
                f'"steps": ["step 1", "step 2", "step 3"]}}'
            )

            response = await asyncio.wait_for(
                self.brain.think(
                    prompt=prompt,
                    brain=BrainType.PRIMARY,
                    temperature=0.15,
                    json_mode=True,
                ),
                timeout=1200,
            )

            try:
                enhanced = json.loads(response.text)
                if enhanced.get("impact"):
                    rf.impact = enhanced["impact"]
                if enhanced.get("remediation"):
                    rf.remediation = enhanced["remediation"]
                if enhanced.get("steps") and isinstance(enhanced["steps"], list):
                    rf.steps_to_reproduce = enhanced["steps"]
            except json.JSONDecodeError:
                pass

        except Exception as e:
            logger.debug(f"Brain enrichment failed: {e}")

        return rf

    def _generate_executive_summary(self, report: Report) -> str:
        """Executive summary oluştur."""
        lines = [
            f"A comprehensive security assessment was conducted on **{report.target}** "
            f"as part of the bug bounty program.",
        ]

        if report.total_scan_time > 0:
            mins = report.total_scan_time / 60
            lines.append(
                f"The assessment lasted **{mins:.0f} minutes** and employed "
                f"**{len(report.tools_used)}** security tools."
            )

        lines.append(
            f"\nThe assessment identified **{report.finding_count}** security finding(s):"
        )

        severity_counts = {}
        for f in report.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.upper()}**: {count}")

        # Add risk context
        if report.critical_count > 0:
            lines.append(
                "\n**Immediate attention is required** for critical findings "
                "that could lead to data breach or system compromise."
            )
        elif report.high_count > 0:
            lines.append(
                "\n**Prompt remediation is recommended** for high-severity findings "
                "that pose significant risk to data confidentiality or integrity."
            )

        # Highlight top findings
        high_plus = [f for f in report.findings
                     if f.severity.value in ("critical", "high") and f.confidence_score >= 60]
        if high_plus:
            lines.append("\n**Key findings requiring immediate attention:**")
            for f in high_plus[:3]:
                lines.append(
                    f"- **{f.title}** ({f.severity.value.upper()}, "
                    f"confidence: {f.confidence_score:.0f}%)"
                )

        return "\n".join(lines)

    # ── Markdown Output ───────────────────────────────────────

    @staticmethod
    def _render_finding(lines: list[str], f: "ReportFinding", idx: int) -> None:
        """Render a single finding into markdown lines."""
        lines.append(f"## Finding #{idx}: {f.title}")
        lines.append(f"\n**Severity:** {f.severity.value.upper()} ({f.cvss_score})")
        lines.append(f"**CVSS Vector:** `{f.cvss_vector}`")
        lines.append(f"**Type:** {f.vulnerability_type}")
        if f.cwe_ids:
            lines.append(f"**CWE:** {', '.join(f.cwe_ids)}")
        lines.append(f"**Confidence:** {f.confidence_score:.0f}%")

        # V13-T3-2: Confidence narrative from evidence chain
        _ev = getattr(f, "evidence_chain", None) or (
            f.metadata.get("evidence_chain") if f.metadata else None
        )
        if _ev and isinstance(_ev, list) and len(_ev) > 0:
            lines.append("\n<details><summary>Confidence Evidence</summary>\n")
            for ev_item in _ev:
                lines.append(f"- {ev_item}")
            lines.append("\n</details>")

        if f.summary:
            lines.append(f"\n### Summary\n{f.summary}")
        if f.impact:
            lines.append(f"\n### Impact\n{f.impact}")
        if f.steps_to_reproduce:
            lines.append("\n### Steps to Reproduce")
            for j, step in enumerate(f.steps_to_reproduce, 1):
                lines.append(f"{j}. {step}")
        if f.endpoint or f.parameter or f.payload:
            lines.append("\n### Technical Details")
            if f.endpoint:
                lines.append(f"- **Endpoint:** `{f.endpoint}`")
            if f.parameter:
                lines.append(f"- **Parameter:** `{f.parameter}`")
            if f.payload:
                lines.append(f"- **Payload:** `{f.payload}`")
        if f.http_request:
            lines.append(f"\n### HTTP Request\n```http\n{f.http_request[:3000]}\n```")
        if f.http_response:
            lines.append(f"\n### HTTP Response\n```http\n{f.http_response[:3000]}\n```")
        if f.poc_code:
            lines.append(f"\n### Proof of Concept\n```\n{f.poc_code[:2000]}\n```")
        for ss in f.screenshots:
            lines.append(f"\n![Screenshot]({ss})")
        if f.remediation:
            lines.append(f"\n### Remediation\n{f.remediation}")
        if f.references:
            lines.append("\n### References")
            for ref in f.references:
                lines.append(f"- {ref}")
        lines.append("\n---\n")

    def to_markdown(self, report: Report) -> str:
        """Raporu Markdown formatına dönüştür."""
        lines = []

        # Header
        lines.append(f"# {report.title}")
        lines.append(f"\n**Target:** {report.target}")
        if report.program_name:
            lines.append(f"**Program:** {report.program_name}")
        lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(report.generated_at))}")
        lines.append(f"**Report ID:** `{report.report_id}`")
        lines.append(f"**Scan Duration:** {report.total_scan_time:.0f}s")
        lines.append(f"**Platform:** {report.platform.value}")

        if report.scan_profile:
            lines.append(f"**Scan Profile:** {report.scan_profile}")

        # Executive Summary
        lines.append("\n## Executive Summary\n")
        lines.append(report.executive_summary)

        # Technology Stack (V13-T3-2)
        if report.technology_stack:
            lines.append("\n## Technology Stack\n")
            for host, techs in report.technology_stack.items():
                if isinstance(techs, dict):
                    items = ", ".join(f"{k}: {v}" for k, v in techs.items() if v)
                elif isinstance(techs, (list, set)):
                    items = ", ".join(str(t) for t in techs)
                else:
                    items = str(techs)
                if items:
                    lines.append(f"- **{host}**: {items}")

        # WAF Considerations (V13-T3-2)
        if report.waf_detected:
            lines.append("\n## WAF / CDN Considerations\n")
            lines.append(
                f"A WAF/CDN was detected: **{report.waf_detected}**. "
                "Some findings may have been affected by WAF filtering. "
                "Confidence scores already account for WAF interference where applicable."
            )

        # Finding Clusters (V14-T3-2) — show cluster summary when multi-finding clusters exist
        try:
            from src.analysis.finding_cluster import FindingClusterer
            _clusterer = FindingClusterer()
            # Convert ReportFindings to dicts for clustering
            _f_dicts = [
                {
                    "title": f.title, "vulnerability_type": f.vulnerability_type,
                    "url": f.endpoint, "endpoint": f.endpoint,
                    "parameter": f.parameter, "severity": f.severity.value,
                    "confidence_score": f.confidence_score,
                }
                for f in report.findings
            ]
            _clusters = _clusterer.cluster(_f_dicts)
            _cluster_md = _clusterer.cluster_summary_markdown(_clusters)
            if _cluster_md:
                lines.append(f"\n{_cluster_md}")
        except Exception as _cluster_err:
            logger.debug(f"Finding clustering skipped: {_cluster_err}")

        # Findings — grouped by confidence tier (P6-4)
        lines.append("\n---\n")

        confirmed = [f for f in report.findings if f.confidence_score > 80]
        likely = [f for f in report.findings if 50 <= f.confidence_score <= 80]  # Bug 5.2m-1: was `50 <` (off-by-one)
        investigate = [f for f in report.findings if f.confidence_score < 50]  # Bug 5.2m-1: was `<= 50`

        _idx = 0
        if confirmed:
            lines.append("# Confirmed Findings (Confidence > 80%)\n")
            for f in confirmed:
                _idx += 1
                self._render_finding(lines, f, _idx)
        if likely:
            lines.append("\n# Likely Findings (Confidence 50-80%)\n")
            for f in likely:
                _idx += 1
                self._render_finding(lines, f, _idx)
        if investigate:
            lines.append("\n# Needs Investigation (Confidence < 50%)\n")
            for f in investigate:
                _idx += 1
                self._render_finding(lines, f, _idx)

        if _idx == 0:
            lines.append("\nNo confirmed findings.")

        # Footer
        lines.append("\n## Tools Used\n")
        for tool in report.tools_used:
            lines.append(f"- {tool}")

        lines.append(
            f"\n---\n*Report generated by WhiteHatHacker AI v2.8 | "
            f"Session: {report.session_id}*"
        )

        return "\n".join(lines)

    def to_json(self, report: Report) -> str:
        """Raporu JSON formatına dönüştür."""
        return report.model_dump_json(indent=2)

    # ── Dosya Kaydetme ────────────────────────────────────────

    def save_markdown(self, report: Report, output_dir: str | None = None) -> str:
        """Markdown raporu dosyaya kaydet."""
        dir_path = Path(output_dir) if output_dir else self.output_dir
        dir_path.mkdir(parents=True, exist_ok=True)

        filename = f"{report.report_id}.md"
        filepath = dir_path / filename

        try:
            content = self.to_markdown(report)
            filepath.write_text(content, encoding="utf-8")
        except Exception as exc:
            logger.warning(f"save_markdown failed for {filepath}: {exc}")
            # Emergency fallback: write raw finding data so nothing is lost
            try:
                fallback = f"# Report {report.report_id}\n\n*Markdown generation failed: {exc}*\n\n"
                fallback += f"Findings count: {len(report.findings)}\n"
                filepath.write_text(fallback, encoding="utf-8")
            except Exception as _fallback_err:
                logger.warning(f"Emergency fallback write also failed: {_fallback_err}")
            return str(filepath)

        report.markdown_path = str(filepath)
        logger.info(f"Markdown report saved: {filepath}")

        return str(filepath)

    def save_json(self, report: Report, output_dir: str | None = None) -> str:
        """JSON raporu dosyaya kaydet."""
        dir_path = Path(output_dir) if output_dir else self.output_dir
        dir_path.mkdir(parents=True, exist_ok=True)

        filename = f"{report.report_id}.json"
        filepath = dir_path / filename

        try:
            content = self.to_json(report)
            filepath.write_text(content, encoding="utf-8")
        except Exception as exc:
            logger.warning(f"save_json failed for {filepath}: {exc}")
            return str(filepath)

        report.json_path = str(filepath)
        logger.info(f"JSON report saved: {filepath}")

        return str(filepath)

    # ── Self-Assessment ───────────────────────────────────────

    async def self_assess(self, report: Report) -> dict:
        """Ask brain to critique the generated report and return quality metrics.

        Returns a dict with overall_score, dimensions, missing_sections,
        improvements list, and verdict.  Falls back gracefully if brain
        is unavailable.
        """
        if not self.brain:
            return {"verdict": "skipped", "reason": "no brain available"}

        from src.brain.prompts.report_prompts import (
            REPORT_SELF_ASSESS_SYSTEM,
            build_report_self_assess_prompt,
        )

        md_text = self.to_markdown(report)
        prompt = build_report_self_assess_prompt(md_text)

        try:
            response = await asyncio.wait_for(
                self.brain.think(
                    prompt=prompt,
                    brain=BrainType.SECONDARY,
                    system_prompt=REPORT_SELF_ASSESS_SYSTEM,
                    temperature=0.1,
                    json_mode=True,
                ),
                timeout=1200,
            )

            from src.utils.json_utils import extract_json
            assessment = extract_json(response.text)
            if assessment and isinstance(assessment, dict):
                logger.info(
                    f"Report self-assessment | score={assessment.get('overall_score', '?')} | "
                    f"verdict={assessment.get('verdict', '?')}"
                )
                return assessment
        except TimeoutError:
            logger.debug("Report self-assessment timed out")
        except Exception as e:
            logger.debug(f"Report self-assessment failed: {e}")

        return {"verdict": "skipped", "reason": "brain assessment failed"}

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _normalize_string_list(*values: Any) -> list[str]:
        """Flatten strings/lists into a deduplicated list of non-empty strings."""
        normalized: list[str] = []
        for value in values:
            if not value:
                continue
            if isinstance(value, str):
                candidate = value.strip()
                if candidate and candidate not in normalized:
                    normalized.append(candidate)
                continue
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    if isinstance(item, str):
                        candidate = item.strip()
                        if candidate and candidate not in normalized:
                            normalized.append(candidate)
                    elif item is not None:
                        candidate = str(item).strip()
                        if candidate and candidate not in normalized:
                            normalized.append(candidate)
                continue
            candidate = str(value).strip()
            if candidate and candidate not in normalized:
                normalized.append(candidate)
        return normalized

    @staticmethod
    def _first_non_empty_text(*values: Any) -> str:
        """Return the first non-empty string-like value."""
        for value in values:
            if value is None:
                continue
            if isinstance(value, str):
                candidate = value.strip()
                if candidate:
                    return candidate
                continue
            candidate = str(value).strip()
            if candidate:
                return candidate
        return ""

    @staticmethod
    def _severity_from_cvss(score: float) -> SeverityLevel:
        """Derive severity level from CVSS v3.1 score."""
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score >= 0.1:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    @staticmethod
    def _auto_generate_steps(actual: Any, _g) -> list[str]:
        """Auto-generate steps-to-reproduce from finding data."""
        steps: list[str] = []

        endpoint = _g(actual, "url", "") or _g(actual, "endpoint", "")
        http_request = _g(actual, "http_request", "")
        curl_cmd = _g(actual, "curl_command", "")
        payload = _g(actual, "payload", "")
        parameter = _g(actual, "parameter", "")
        tool = _g(actual, "tool", "") or _g(actual, "tool_name", "")
        description = _g(actual, "description", "")

        if endpoint:
            steps.append(f"Navigate to the target endpoint: `{endpoint}`")

        if parameter and payload:
            steps.append(
                f"Supply the following payload in the `{parameter}` parameter: `{payload}`"
            )
        elif payload:
            steps.append(f"Send the following payload: `{payload}`")

        if curl_cmd:
            steps.append(f"Reproduce with curl:\n```bash\n{curl_cmd}\n```")
        elif http_request:
            # Extract method and path from HTTP request
            req_preview = http_request[:500] if len(http_request) > 500 else http_request
            steps.append(f"Send the following HTTP request:\n```http\n{req_preview}\n```")

        if not steps and endpoint:
            # Minimal steps for findings with only an endpoint
            steps.append(f"Access `{endpoint}` in a browser or with curl")
            steps.append("Observe the response indicating the vulnerability")

        if description and not steps:
            steps.append(description[:300])

        if tool:
            steps.append(f"Detected by: {tool}")

        return steps

    # ── Normalizer Helpers ────────────────────────────────────

    @staticmethod
    def _normalize_cwe_ids(raw) -> list[str]:
        """Normalize cwe_ids to a list of strings.

        Brain enrichment may return a single string like
        ``"CWE-200: Information Exposure"`` or a comma-separated list.
        This ensures the value is always ``list[str]``.
        """
        if raw is None:
            return []
        if isinstance(raw, list):
            return [str(c) for c in raw if c]
        if isinstance(raw, str):
            if not raw.strip():
                return []
            # Handle comma / semicolon separated strings
            parts = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
            # Validate CWE format: CWE-<digits> optionally followed by description
            import re as _re
            return [p for p in parts if _re.match(r'^CWE-\d+', p, _re.I)]
        return []

    # ── Comprehensive Remediation ─────────────────────────────

    @staticmethod
    def _get_comprehensive_remediation(vuln_type: str) -> str:
        """Get comprehensive, actionable remediation text using the remediation module.

        Falls back to the legacy _default_remediation() if the module
        returns a generic response (no detailed advice available).
        """
        try:
            from src.reporting.remediation import get_remediation, format_remediation_markdown

            advice = get_remediation(vuln_type)
            # If we got a specific match (has detail or code examples), use it
            if advice.detail or advice.code_examples:
                return format_remediation_markdown(advice)
            # Specific summary but no detail — still better than generic
            if advice.summary and "security best practices" not in advice.summary:
                return advice.summary
        except Exception as _exc:
            logger.debug(f"report generator error: {_exc}")
        # Fallback to legacy
        return ReportGenerator._default_remediation(vuln_type)

    # ── Default Metinler ──────────────────────────────────────

    @staticmethod
    def _default_remediation(vuln_type: str) -> str:
        """Zafiyet türü bazlı varsayılan düzeltme önerisi."""
        REMEDIATIONS: dict[str, str] = {
            "sql_injection": (
                "Use parameterized queries or prepared statements for all database interactions. "
                "Apply input validation and implement a Web Application Firewall (WAF)."
            ),
            "command_injection": (
                "Avoid passing user input to system commands. Use secure APIs "
                "instead of shell commands. Apply strict input validation with allowlists."
            ),
            "xss_reflected": (
                "Implement output encoding/escaping for all user-controlled data "
                "rendered in HTML. Use Content-Security-Policy headers."
            ),
            "xss_stored": (
                "Sanitize and encode all user input before storage and rendering. "
                "Implement Content-Security-Policy and HTTPOnly cookie flags."
            ),
            "ssrf": (
                "Validate and restrict URLs that the application can request. "
                "Use allowlists for permitted domains/IPs. Block internal network ranges."
            ),
            "ssti": (
                "Avoid passing user input directly to template engines. "
                "Use sandboxed template environments and implement strict input validation."
            ),
            "idor": (
                "Implement proper access control checks on every data access request. "
                "Use indirect object references (UUIDs) instead of sequential IDs."
            ),
            "authentication_bypass": (
                "Review and strengthen authentication mechanisms. "
                "Implement multi-factor authentication and proper session management."
            ),
            "cors_misconfiguration": (
                "Restrict Access-Control-Allow-Origin to specific trusted domains. "
                "Never use wildcard (*) with credentials. Validate the Origin header."
            ),
            "open_redirect": (
                "Validate and sanitize redirect URLs. Use allowlists for permitted "
                "redirect destinations. Avoid using user input in redirect targets."
            ),
            "local_file_inclusion": (
                "Validate file paths against an allowlist. Remove path traversal "
                "sequences (../) and use chroot or jail environments."
            ),
            "ssl_tls_misconfiguration": (
                "Disable deprecated TLS versions (TLS 1.0, 1.1). Use strong cipher "
                "suites. Enable HSTS. Keep SSL certificates up to date."
            ),
            # Header / hardening findings
            "missing_security_header": (
                "Add the missing security headers to all HTTP responses. "
                "Recommended headers: Content-Security-Policy, X-Frame-Options, "
                "X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, "
                "Permissions-Policy. Configure at the web server or reverse proxy level."
            ),
            "missing_csp": (
                "Implement a Content-Security-Policy header to prevent XSS and data injection attacks. "
                "Start with a restrictive policy (default-src 'self') and relax as needed."
            ),
            "missing_x_frame_options": (
                "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to prevent clickjacking. "
                "Alternatively use CSP frame-ancestors directive."
            ),
            "missing_hsts": (
                "Enable HTTP Strict Transport Security (HSTS) with 'max-age=31536000; includeSubDomains'. "
                "This prevents SSL-stripping attacks."
            ),
            # Information disclosure
            "information_disclosure": (
                "Remove or restrict access to sensitive information exposed in responses. "
                "Disable server version banners, directory listings, and verbose error messages. "
                "Ensure debug/development endpoints are not accessible in production."
            ),
            "sensitive_url": (
                "Restrict access to sensitive administrative URLs (wp-admin, xmlrpc.php, etc.) "
                "using IP allowlists, authentication, or WAF rules. Disable XML-RPC if not needed. "
                "Remove or protect backup files, configuration files, and debug endpoints."
            ),
            "sensitive_information": (
                "Remove server version banners, technology stack information, and internal "
                "path disclosures from HTTP responses. Configure the web server to suppress "
                "the Server header or set it to a generic value."
            ),
            "server_header_disclosure": (
                "Remove or obfuscate the Server header to prevent technology fingerprinting. "
                "Configure your web server (nginx: server_tokens off; Apache: ServerTokens Prod)."
            ),
            # CVE / technology findings
            "cve": (
                "Update the affected software component to the latest patched version. "
                "If immediate patching is not possible, apply vendor-recommended mitigations "
                "or WAF rules to block known exploitation vectors for this CVE."
            ),
            "outdated_software": (
                "Update the affected software to the latest stable version. "
                "Implement a patch management process to regularly update all components."
            ),
            # Cookie findings
            "insecure_cookie": (
                "Set the Secure, HttpOnly, and SameSite attributes on all session cookies. "
                "Ensure cookies are only transmitted over HTTPS."
            ),
            # API findings
            "api_misconfiguration": (
                "Review API access controls and authentication. Disable unnecessary API endpoints. "
                "Implement rate limiting and proper input validation on all API endpoints."
            ),
            # CRLF
            "crlf_injection": (
                "Sanitize user input by stripping or encoding CR (\\r) and LF (\\n) characters "
                "before including them in HTTP headers. Use framework-provided safe header methods."
            ),
            # HTTP method
            "dangerous_http_method": (
                "Disable unnecessary HTTP methods (TRACE, PUT, DELETE, OPTIONS) "
                "that are not required by the application. Configure at the web server level."
            ),
            # Rate limiting
            "rate_limit_bypass": (
                "Implement robust server-side rate limiting on all authentication "
                "and sensitive endpoints. Use progressive delays and CAPTCHA after failed attempts."
            ),
            # Race condition
            "race_condition": (
                "Implement proper locking mechanisms (mutexes, database-level locks) "
                "for critical operations. Use idempotency tokens for state-changing requests."
            ),
        }
        return REMEDIATIONS.get(vuln_type, "Review and fix the identified vulnerability following security best practices.")

    @staticmethod
    def _default_references(vuln_type: str) -> list[str]:
        """Zafiyet türü bazlı varsayılan referanslar."""
        REFS: dict[str, list[str]] = {
            "sql_injection": [
                "CWE-89: SQL Injection — https://cwe.mitre.org/data/definitions/89.html",
                "OWASP SQL Injection — https://owasp.org/www-community/attacks/SQL_Injection",
            ],
            "xss_reflected": [
                "CWE-79: Cross-site Scripting — https://cwe.mitre.org/data/definitions/79.html",
                "OWASP XSS — https://owasp.org/www-community/attacks/xss/",
            ],
            "xss_stored": [
                "CWE-79: Cross-site Scripting — https://cwe.mitre.org/data/definitions/79.html",
                "OWASP XSS — https://owasp.org/www-community/attacks/xss/",
            ],
            "command_injection": [
                "CWE-78: OS Command Injection — https://cwe.mitre.org/data/definitions/78.html",
                "OWASP Command Injection — https://owasp.org/www-community/attacks/Command_Injection",
            ],
            "ssrf": [
                "CWE-918: Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html",
                "OWASP SSRF — https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            ],
            "idor": [
                "CWE-639: Insecure Direct Object Reference — https://cwe.mitre.org/data/definitions/639.html",
                "OWASP IDOR — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            ],
            "cors_misconfiguration": [
                "CWE-942: Overly Permissive CORS Policy — https://cwe.mitre.org/data/definitions/942.html",
                "OWASP CORS — https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                "PortSwigger CORS — https://portswigger.net/web-security/cors",
            ],
            "information_disclosure": [
                "CWE-200: Exposure of Sensitive Information — https://cwe.mitre.org/data/definitions/200.html",
                "OWASP Information gathering — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
            ],
            "missing_security_header": [
                "OWASP Secure Headers — https://owasp.org/www-project-secure-headers/",
                "Mozilla Observatory — https://observatory.mozilla.org/",
            ],
            "clickjacking": [
                "CWE-1021: Clickjacking — https://cwe.mitre.org/data/definitions/1021.html",
                "OWASP Clickjacking — https://owasp.org/www-community/attacks/Clickjacking",
            ],
            "outdated_software": [
                "CWE-1104: Use of Unmaintained Third Party Components — https://cwe.mitre.org/data/definitions/1104.html",
                "OWASP Vulnerable Components — https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            ],
            "known_cve": [
                "NVD — https://nvd.nist.gov/",
                "OWASP Vulnerable Components — https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            ],
            "open_redirect": [
                "CWE-601: Open Redirect — https://cwe.mitre.org/data/definitions/601.html",
                "OWASP Unvalidated Redirects — https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            ],
            "ssti": [
                "CWE-1336: Server-Side Template Injection — https://cwe.mitre.org/data/definitions/1336.html",
                "PortSwigger SSTI — https://portswigger.net/web-security/server-side-template-injection",
            ],
            "sensitive_url": [
                "CWE-200: Exposure of Sensitive Information — https://cwe.mitre.org/data/definitions/200.html",
                "OWASP Security Misconfiguration — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ],
            "auth_bypass": [
                "CWE-287: Improper Authentication — https://cwe.mitre.org/data/definitions/287.html",
                "OWASP Broken Authentication — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ],
            "authentication_bypass": [
                "CWE-287: Improper Authentication — https://cwe.mitre.org/data/definitions/287.html",
                "OWASP Broken Authentication — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ],
            "missing_rate_limit": [
                "CWE-307: Improper Restriction of Excessive Authentication Attempts — https://cwe.mitre.org/data/definitions/307.html",
                "OWASP Brute Force — https://owasp.org/www-community/attacks/Brute_force_attack",
            ],
            "business_logic": [
                "CWE-840: Business Logic Errors — https://cwe.mitre.org/data/definitions/840.html",
                "OWASP Business Logic Testing — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
            ],
            "race_condition": [
                "CWE-362: Race Condition — https://cwe.mitre.org/data/definitions/362.html",
                "PortSwigger Race Conditions — https://portswigger.net/web-security/race-conditions",
            ],
            "subdomain_takeover": [
                "CWE-923: Improper Restriction of Communication Channel — https://cwe.mitre.org/data/definitions/923.html",
                "HackerOne Subdomain Takeover — https://www.hackerone.com/knowledge-center/subdomain-takeover",
            ],
            "crlf_injection": [
                "CWE-113: CRLF Injection — https://cwe.mitre.org/data/definitions/113.html",
                "OWASP CRLF Injection — https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
            ],
            "dangerous_http_method": [
                "CWE-749: Exposed Dangerous Method — https://cwe.mitre.org/data/definitions/749.html",
                "OWASP HTTP Methods Testing — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            ],
        }
        # Also check common aliases
        refs = REFS.get(vuln_type)
        if not refs:
            # Try broader category match
            if "xss" in vuln_type:
                refs = REFS.get("xss_reflected")
            elif "injection" in vuln_type or "sqli" in vuln_type:
                refs = REFS.get("sql_injection")
            elif "auth" in vuln_type and "bypass" in vuln_type:
                refs = REFS.get("auth_bypass")
            elif "rate_limit" in vuln_type or "rate-limit" in vuln_type:
                refs = REFS.get("missing_rate_limit")
            elif "takeover" in vuln_type:
                refs = REFS.get("subdomain_takeover")
            elif "crlf" in vuln_type:
                refs = REFS.get("crlf_injection")
        return refs or [
            "OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/",
        ]


__all__ = [
    "ReportGenerator",
    "Report",
    "ReportFinding",
    "CVSS_VULN_DEFAULTS",
]
