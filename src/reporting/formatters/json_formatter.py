"""
WhiteHatHacker AI — JSON Report Formatter

Zafiyet raporlarını yapılandırılmış JSON formatında çıktılar.
API entegrasyonları ve otomatik işleme için idealdir.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# JSON Schema Models
# ============================================================

class JsonSeverity(BaseModel):
    """Severity bilgisi."""
    label: str = "medium"
    cvss_score: float = 0.0
    cvss_vector: str = ""


class JsonEvidence(BaseModel):
    """Tek bir kanıt parçası."""
    type: str = "http"          # http, screenshot, code, log
    description: str = ""
    request: str = ""
    response: str = ""
    path: str = ""               # dosya yolu (screenshot vb.)
    timestamp: str = ""


class JsonFinding(BaseModel):
    """Tek bir zafiyet bulgusu."""
    id: str = ""
    title: str = ""
    description: str = ""
    severity: JsonSeverity = Field(default_factory=JsonSeverity)
    vuln_type: str = ""
    cwe: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    confidence: int = 0
    status: str = "unverified"
    steps_to_reproduce: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    evidence: list[JsonEvidence] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tool_source: str = ""
    tags: list[str] = Field(default_factory=list)
    discovered_at: str = ""


class JsonReport(BaseModel):
    """Tam rapor modeli."""
    report_id: str = ""
    title: str = ""
    target: str = ""
    session_id: str = ""
    generated_at: str = ""
    scan_profile: str = ""
    summary: str = ""
    findings: list[JsonFinding] = Field(default_factory=list)
    statistics: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)


# ============================================================
# JSON Formatter
# ============================================================

class JsonFormatter:
    """
    Structured JSON report formatter.

    Usage:
        fmt = JsonFormatter()
        json_str = fmt.format_report(report_data)
        fmt.save(json_str, "output/reports/findings.json")
    """

    def __init__(self, indent: int = 2, ensure_ascii: bool = False) -> None:
        self.indent = indent
        self.ensure_ascii = ensure_ascii

    def format_report(self, report: dict[str, Any]) -> str:
        """Dict → JSON string (doğrudan veya model üzerinden)."""

        json_report = JsonReport(
            report_id=report.get("report_id", ""),
            title=report.get("title", ""),
            target=report.get("target", ""),
            session_id=report.get("session_id", ""),
            generated_at=report.get("generated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
            scan_profile=report.get("scan_profile", ""),
            summary=report.get("summary", ""),
            meta=report.get("meta", {}),
        )

        # Findings
        for f in report.get("findings", []):
            finding = self._parse_finding(f)
            json_report.findings.append(finding)

        # Statistics
        json_report.statistics = self._compute_statistics(json_report.findings)

        return json_report.model_dump_json(indent=self.indent)

    def format_findings(self, findings: list[dict[str, Any]]) -> str:
        """Bulgu listesini JSON olarak formatla."""
        parsed = [self._parse_finding(f) for f in findings]
        data = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": len(parsed),
            "findings": [f.model_dump() for f in parsed],
            "statistics": self._compute_statistics(parsed),
        }
        return json.dumps(data, indent=self.indent, ensure_ascii=self.ensure_ascii)

    def format_raw(self, data: Any) -> str:
        """Herhangi bir dict/list'i JSON'a çevir."""
        return json.dumps(data, indent=self.indent, ensure_ascii=self.ensure_ascii, default=str)

    # --------- Private ---------

    def _parse_finding(self, f: dict[str, Any]) -> JsonFinding:
        """Dict finding → JsonFinding model."""
        severity_raw = f.get("severity", {})
        if isinstance(severity_raw, str):
            severity = JsonSeverity(label=severity_raw)
        elif isinstance(severity_raw, dict):
            severity = JsonSeverity(**severity_raw)
        else:
            severity = JsonSeverity()

        evidence = []
        for e in f.get("evidence", f.get("http_evidence", [])):
            if isinstance(e, dict):
                evidence.append(JsonEvidence(**{
                    k: v for k, v in e.items()
                    if k in JsonEvidence.model_fields
                }))

        return JsonFinding(
            id=f.get("id", ""),
            title=f.get("title", ""),
            description=f.get("description", f.get("summary", "")),
            severity=severity,
            vuln_type=f.get("vuln_type", f.get("type", "")),
            cwe=f.get("cwe", ""),
            url=f.get("url", ""),
            parameter=f.get("parameter", ""),
            payload=f.get("payload", ""),
            confidence=f.get("confidence_score", f.get("confidence", 0)),
            status=f.get("status", "unverified"),
            steps_to_reproduce=f.get("steps_to_reproduce", []),
            impact=f.get("impact", ""),
            remediation=f.get("remediation", ""),
            evidence=evidence,
            references=f.get("references", []),
            tool_source=f.get("tool_source", f.get("source_tool", "")),
            tags=f.get("tags", []),
            discovered_at=f.get("discovered_at", ""),
        )

    @staticmethod
    def _compute_statistics(findings: list[JsonFinding]) -> dict[str, Any]:
        """Bulgu istatistikleri."""
        sev_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        confidences: list[int] = []

        for f in findings:
            label = f.severity.label.lower()
            sev_counts[label] = sev_counts.get(label, 0) + 1

            if f.vuln_type:
                type_counts[f.vuln_type] = type_counts.get(f.vuln_type, 0) + 1

            status_counts[f.status] = status_counts.get(f.status, 0) + 1

            if f.confidence > 0:
                confidences.append(f.confidence)

        avg_conf = round(sum(confidences) / len(confidences), 1) if confidences else 0

        return {
            "total": len(findings),
            "by_severity": sev_counts,
            "by_type": type_counts,
            "by_status": status_counts,
            "avg_confidence": avg_conf,
        }

    # --------- Save ---------

    def save(self, content: str, filepath: str) -> str:
        """JSON dosyasına kaydet."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"JSON report saved: {path}")
        return str(path)


__all__ = [
    "JsonFormatter",
    "JsonReport",
    "JsonFinding",
    "JsonSeverity",
    "JsonEvidence",
]
