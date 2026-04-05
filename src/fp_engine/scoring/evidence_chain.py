"""
WhiteHatHacker AI — Evidence Chain Builder

Zafiyet bulguları için kriptografik olarak doğrulanabilir
kanıt zinciri oluşturur. Her kanıt timestamp'li ve
hash'lidir, böylece rapor bütünlüğü garanti altına alınır.
"""

from __future__ import annotations

import hashlib
import json
import time

from loguru import logger
from pydantic import BaseModel


class Evidence(BaseModel):
    """Tek bir kanıt parçası."""

    evidence_id: str = ""
    timestamp: float = 0.0
    evidence_type: str = ""        # request | response | screenshot | tool_output | brain_analysis | manual
    title: str = ""
    description: str = ""

    # İçerik
    content: str = ""              # Ham kanıt içeriği
    content_hash: str = ""         # SHA256 hash (integrity)

    # HTTP veri
    http_method: str = ""
    http_url: str = ""
    http_request_headers: dict[str, str] = {}
    http_request_body: str = ""
    http_response_status: int = 0
    http_response_headers: dict[str, str] = {}
    http_response_body: str = ""

    # Metadata
    tool_name: str = ""
    payload_used: str = ""
    parameter: str = ""
    screenshot_path: str = ""
    tags: list[str] = []


class EvidenceChain(BaseModel):
    """Tam kanıt zinciri — bir bulgu için tüm kanıtlar."""

    chain_id: str = ""
    finding_id: str = ""
    finding_title: str = ""
    vulnerability_type: str = ""

    # Zincir
    evidences: list[Evidence] = []
    chain_hash: str = ""           # Zincirdeki tüm kanıtların hash'i

    # Durum
    is_complete: bool = False
    completeness_score: float = 0.0  # 0-1.0 (gerekli kanıtların doluluk oranı)

    # Zaman
    created_at: float = 0.0
    updated_at: float = 0.0

    @property
    def evidence_count(self) -> int:
        return len(self.evidences)

    @property
    def has_http_evidence(self) -> bool:
        return any(e.evidence_type in ("request", "response") for e in self.evidences)

    @property
    def has_tool_evidence(self) -> bool:
        return any(e.evidence_type == "tool_output" for e in self.evidences)

    @property
    def has_brain_evidence(self) -> bool:
        return any(e.evidence_type == "brain_analysis" for e in self.evidences)


# Zafiyet türüne göre gerekli kanıt türleri
REQUIRED_EVIDENCE: dict[str, list[str]] = {
    "sql_injection": [
        "tool_output",          # SQLMap çıktısı
        "request",              # Payload'lu HTTP istek
        "response",             # Hata/veri içeren yanıt
    ],
    "xss_reflected": [
        "request",              # Payload'lu istek
        "response",             # Reflect olan yanıt
    ],
    "xss_stored": [
        "request",              # Payload gönderme isteği
        "response",             # Payload'ın saklanıp serve edildiği yanıt
    ],
    "command_injection": [
        "tool_output",          # Commix çıktısı
        "request",
        "response",
    ],
    "ssrf": [
        "request",
        "response",
        "tool_output",
    ],
    "idor": [
        "request",              # İlk kullanıcı isteği
        "response",             # Başka kullanıcının verisi
    ],
    "authentication_bypass": [
        "request",
        "response",
    ],
    "cors_misconfiguration": [
        "request",
        "response",             # CORS headers
    ],
    "ssl_tls_misconfiguration": [
        "tool_output",          # SSLScan/SSLyze çıktısı
    ],
    "information_disclosure": [
        "request",
        "response",
    ],
}

DEFAULT_REQUIRED = ["tool_output"]


class EvidenceChainBuilder:
    """
    Kanıt zinciri oluşturma motoru.

    Her bulgu için:
    1. Gerekli kanıt türlerini belirle
    2. Tool output, HTTP request/response, brain analysis ekle
    3. Her kanıtı hash'le
    4. Zincir bütünlüğünü doğrula
    5. Tamamlanma oranını hesapla

    Kullanım:
        builder = EvidenceChainBuilder()
        chain = builder.create_chain("xss_123", "Reflected XSS", "xss_reflected")
        builder.add_http_evidence(chain, method="GET", url="...", ...)
        builder.add_tool_output(chain, "dalfox", "XSS found at ...")
        builder.finalize(chain)
    """

    def __init__(self) -> None:
        self._chains: dict[str, EvidenceChain] = {}
        self._counter = 0

    def create_chain(
        self,
        finding_id: str,
        finding_title: str,
        vulnerability_type: str,
    ) -> EvidenceChain:
        """Yeni kanıt zinciri oluştur."""
        chain = EvidenceChain(
            chain_id=f"ec_{finding_id}_{int(time.time())}",
            finding_id=finding_id,
            finding_title=finding_title,
            vulnerability_type=vulnerability_type,
            created_at=time.time(),
            updated_at=time.time(),
        )
        self._chains[chain.chain_id] = chain
        logger.debug(
            f"Evidence chain created | id={chain.chain_id} | "
            f"vuln={vulnerability_type}"
        )
        return chain

    def add_http_evidence(
        self,
        chain: EvidenceChain,
        method: str,
        url: str,
        request_headers: dict[str, str] | None = None,
        request_body: str = "",
        response_status: int = 0,
        response_headers: dict[str, str] | None = None,
        response_body: str = "",
        payload: str = "",
        parameter: str = "",
        title: str = "",
    ) -> Evidence:
        """HTTP request/response kanıtı ekle."""
        self._counter += 1

        # Request content hash
        content = f"{method} {url}\n{request_body}\n---\n{response_status}\n{response_body}"
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]

        evidence = Evidence(
            evidence_id=f"ev_{self._counter}",
            timestamp=time.time(),
            evidence_type="request" if not response_status else "response",
            title=title or f"{method} {url[:80]}",
            description=f"HTTP {method} to {url} → {response_status}",
            content=content[:10000],  # Max 10K chars
            content_hash=content_hash,
            http_method=method,
            http_url=url,
            http_request_headers=request_headers or {},
            http_request_body=request_body[:5000],
            http_response_status=response_status,
            http_response_headers=response_headers or {},
            http_response_body=response_body[:10000],
            payload_used=payload,
            parameter=parameter,
        )

        chain.evidences.append(evidence)
        chain.updated_at = time.time()
        self._update_completeness(chain)

        return evidence

    def add_tool_output(
        self,
        chain: EvidenceChain,
        tool_name: str,
        output: str,
        title: str = "",
        tags: list[str] | None = None,
    ) -> Evidence:
        """Tool çıktısı kanıtı ekle."""
        self._counter += 1
        content_hash = hashlib.sha256(output.encode()).hexdigest()[:32]

        evidence = Evidence(
            evidence_id=f"ev_{self._counter}",
            timestamp=time.time(),
            evidence_type="tool_output",
            title=title or f"{tool_name} output",
            description=f"Output from {tool_name}",
            content=output[:20000],
            content_hash=content_hash,
            tool_name=tool_name,
            tags=tags or [],
        )

        chain.evidences.append(evidence)
        chain.updated_at = time.time()
        self._update_completeness(chain)

        return evidence

    def add_brain_analysis(
        self,
        chain: EvidenceChain,
        analysis: str,
        model_used: str = "primary",
        verdict: str = "",
        confidence: float = 0.0,
    ) -> Evidence:
        """Brain AI analiz kanıtı ekle."""
        self._counter += 1

        content = json.dumps({
            "model": model_used,
            "verdict": verdict,
            "confidence": confidence,
            "analysis": analysis,
        }, indent=2)
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]

        evidence = Evidence(
            evidence_id=f"ev_{self._counter}",
            timestamp=time.time(),
            evidence_type="brain_analysis",
            title=f"AI Analysis ({model_used}): {verdict}",
            description=f"Brain model '{model_used}' verdict: {verdict} ({confidence:.0f}%)",
            content=content,
            content_hash=content_hash,
            tags=[model_used, verdict],
        )

        chain.evidences.append(evidence)
        chain.updated_at = time.time()
        self._update_completeness(chain)

        return evidence

    def add_screenshot(
        self,
        chain: EvidenceChain,
        path: str,
        title: str = "Screenshot",
        description: str = "",
    ) -> Evidence:
        """Ekran görüntüsü kanıtı referansı ekle."""
        self._counter += 1

        evidence = Evidence(
            evidence_id=f"ev_{self._counter}",
            timestamp=time.time(),
            evidence_type="screenshot",
            title=title,
            description=description or f"Screenshot: {path}",
            screenshot_path=path,
            content_hash=hashlib.sha256(path.encode()).hexdigest()[:32],
        )

        chain.evidences.append(evidence)
        chain.updated_at = time.time()

        return evidence

    def finalize(self, chain: EvidenceChain) -> EvidenceChain:
        """
        Zinciri tamamla ve bütünlük hash'i hesapla.
        """
        # Tüm kanıt hash'lerini birleştirerek zincir hash'i oluştur
        combined = "".join(e.content_hash for e in chain.evidences)
        chain.chain_hash = hashlib.sha256(combined.encode()).hexdigest()[:48]

        self._update_completeness(chain)

        logger.info(
            f"Evidence chain finalized | id={chain.chain_id} | "
            f"evidences={chain.evidence_count} | "
            f"completeness={chain.completeness_score:.0%} | "
            f"hash={chain.chain_hash[:16]}..."
        )

        return chain

    def _update_completeness(self, chain: EvidenceChain) -> None:
        """Tamamlanma oranını güncelle."""
        vuln_type = chain.vulnerability_type.lower()
        required = REQUIRED_EVIDENCE.get(vuln_type, DEFAULT_REQUIRED)

        if not required:
            chain.completeness_score = 1.0 if chain.evidences else 0.0
            chain.is_complete = bool(chain.evidences)
            return

        present_types = {e.evidence_type for e in chain.evidences}
        matched = sum(1 for r in required if r in present_types)

        chain.completeness_score = matched / len(required)
        chain.is_complete = chain.completeness_score >= 1.0

    def get_chain(self, chain_id: str) -> EvidenceChain | None:
        """Zincir ID ile getir."""
        return self._chains.get(chain_id)

    def get_all_chains(self) -> list[EvidenceChain]:
        """Tüm zincirleri getir."""
        return list(self._chains.values())

    def verify_integrity(self, chain: EvidenceChain) -> bool:
        """Zincir bütünlüğünü doğrula."""
        if not chain.chain_hash:
            return False

        combined = "".join(e.content_hash for e in chain.evidences)
        expected = hashlib.sha256(combined.encode()).hexdigest()[:48]

        return expected == chain.chain_hash

    def to_report_format(self, chain: EvidenceChain) -> str:
        """Zinciri rapor formatına dönüştür (Markdown)."""
        lines = [
            f"## Evidence Chain: {chain.finding_title}",
            f"**Chain ID:** `{chain.chain_id}`",
            f"**Integrity Hash:** `{chain.chain_hash}`",
            f"**Completeness:** {chain.completeness_score:.0%}",
            f"**Evidence Count:** {chain.evidence_count}",
            "",
        ]

        for i, ev in enumerate(chain.evidences, 1):
            lines.append(f"### Evidence #{i}: {ev.title}")
            lines.append(f"**Type:** {ev.evidence_type}")
            lines.append(f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ev.timestamp))}")

            if ev.evidence_type in ("request", "response"):
                lines.append(f"\n**{ev.http_method} {ev.http_url}**")
                if ev.http_request_headers:
                    lines.append("\n```http")
                    lines.append(f"{ev.http_method} {ev.http_url} HTTP/1.1")
                    for k, v in ev.http_request_headers.items():
                        lines.append(f"{k}: {v}")
                    if ev.http_request_body:
                        lines.append(f"\n{ev.http_request_body[:2000]}")
                    lines.append("```")

                if ev.http_response_status:
                    lines.append(f"\n**Response: {ev.http_response_status}**")
                    lines.append("```http")
                    lines.append(f"HTTP/1.1 {ev.http_response_status}")
                    for k, v in ev.http_response_headers.items():
                        lines.append(f"{k}: {v}")
                    if ev.http_response_body:
                        lines.append(f"\n{ev.http_response_body[:3000]}")
                    lines.append("```")

            elif ev.evidence_type == "tool_output":
                lines.append(f"**Tool:** {ev.tool_name}")
                lines.append(f"\n```\n{ev.content[:5000]}\n```")

            elif ev.evidence_type == "brain_analysis":
                lines.append(f"\n```json\n{ev.content[:3000]}\n```")

            elif ev.evidence_type == "screenshot":
                lines.append(f"\n![Screenshot]({ev.screenshot_path})")

            lines.append(f"\n**Hash:** `{ev.content_hash}`\n")

        return "\n".join(lines)


__all__ = [
    "EvidenceChainBuilder",
    "EvidenceChain",
    "Evidence",
    "REQUIRED_EVIDENCE",
]
