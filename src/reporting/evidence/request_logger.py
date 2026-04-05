"""
WhiteHatHacker AI — HTTP Request/Response Logger

Tüm HTTP trafiğini kanıt olarak kaydeder.
Her istek/yanıt çifti benzersiz ID ile saklanır.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel


class HttpExchange(BaseModel):
    """Tek bir HTTP istek/yanıt çifti."""

    exchange_id: str = ""
    timestamp: float = 0.0

    # Request
    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = {}
    request_body: str = ""
    request_raw: str = ""

    # Response
    status_code: int = 0
    response_headers: dict[str, str] = {}
    response_body: str = ""
    response_raw: str = ""
    response_time_ms: float = 0.0

    # Metadata
    tool_name: str = ""
    finding_id: str = ""
    is_payload: bool = False
    payload_used: str = ""
    notes: str = ""

    def generate_id(self) -> str:
        """Benzersiz exchange ID oluştur."""
        data = f"{self.method}|{self.url}|{self.timestamp}|{self.request_body[:200]}"
        self.exchange_id = hashlib.sha256(data.encode()).hexdigest()[:16]
        return self.exchange_id

    def to_raw_request(self) -> str:
        """Ham HTTP request string oluştur."""
        if self.request_raw:
            return self.request_raw

        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{self.method} {path} HTTP/1.1"]

        if "Host" not in self.request_headers and parsed.hostname:
            lines.append(f"Host: {parsed.hostname}")

        for key, value in self.request_headers.items():
            lines.append(f"{key}: {value}")

        if self.request_body:
            if "Content-Length" not in self.request_headers:
                lines.append(f"Content-Length: {len(self.request_body)}")
            lines.append("")
            lines.append(self.request_body)

        return "\r\n".join(lines)

    def to_raw_response(self) -> str:
        """Ham HTTP response string oluştur."""
        if self.response_raw:
            return self.response_raw

        lines = [f"HTTP/1.1 {self.status_code}"]

        for key, value in self.response_headers.items():
            lines.append(f"{key}: {value}")

        if self.response_body:
            lines.append("")
            lines.append(self.response_body[:5000])
            if len(self.response_body) > 5000:
                lines.append(f"... [truncated, {len(self.response_body)} bytes total]")

        return "\r\n".join(lines)


class RequestLogger:
    """
    HTTP trafiğini kanıt olarak kaydetme sistemi.

    Features:
    - Her exchange benzersiz ID ile saklanır
    - JSON + raw text formatında kayıt
    - Finding'e bağlama (finding_id)
    - Otomatik hassas veri maskeleme
    - Session bazlı log dosyaları

    Usage:
        logger = RequestLogger(output_dir="output/evidence")

        exchange = HttpExchange(
            method="POST",
            url="https://target.com/login",
            request_headers={"Content-Type": "application/json"},
            request_body='{"user":"admin","pass":"test"}',
            status_code=200,
            response_body="...",
        )

        logger.log(exchange)
        logger.save_session()
    """

    # Maskelenecek header'lar
    SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }

    # Maskelenecek body key'leri
    SENSITIVE_KEYS = {
        "password", "passwd", "pass", "secret", "token",
        "api_key", "apikey", "access_token", "refresh_token",
        "credit_card", "ssn", "cvv",
    }

    def __init__(
        self,
        output_dir: str = "output/evidence/http",
        session_id: str = "",
        mask_sensitive: bool = True,
        max_body_size: int = 50_000,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or f"sess_{int(time.time())}"
        self.mask_sensitive = mask_sensitive
        self.max_body_size = max_body_size

        self.exchanges: list[HttpExchange] = []
        self._finding_map: dict[str, list[str]] = {}  # finding_id → [exchange_ids]

        logger.info(
            f"RequestLogger initialized | session={self.session_id} | "
            f"output={output_dir}"
        )

    def log(self, exchange: HttpExchange) -> str:
        """
        HTTP exchange'i kaydet.

        Returns:
            Exchange ID
        """
        if not exchange.timestamp:
            exchange.timestamp = time.time()

        exchange.generate_id()

        # Body truncation
        if len(exchange.request_body) > self.max_body_size:
            exchange.request_body = (
                exchange.request_body[:self.max_body_size]
                + f"\n[TRUNCATED at {self.max_body_size} bytes]"
            )
        if len(exchange.response_body) > self.max_body_size:
            exchange.response_body = (
                exchange.response_body[:self.max_body_size]
                + f"\n[TRUNCATED at {self.max_body_size} bytes]"
            )

        # Hassas veri maskeleme
        if self.mask_sensitive:
            exchange = self._mask_exchange(exchange)

        self.exchanges.append(exchange)

        # Finding mapping
        if exchange.finding_id:
            if exchange.finding_id not in self._finding_map:
                self._finding_map[exchange.finding_id] = []
            self._finding_map[exchange.finding_id].append(exchange.exchange_id)

        logger.debug(
            f"HTTP logged | id={exchange.exchange_id} | "
            f"{exchange.method} {exchange.url} → {exchange.status_code}"
        )

        return exchange.exchange_id

    def log_from_raw(
        self,
        raw_request: str,
        raw_response: str = "",
        tool_name: str = "",
        finding_id: str = "",
        is_payload: bool = False,
    ) -> str:
        """Ham HTTP text'ten exchange oluştur ve kaydet."""
        exchange = HttpExchange(
            request_raw=raw_request,
            response_raw=raw_response,
            tool_name=tool_name,
            finding_id=finding_id,
            is_payload=is_payload,
        )

        # Parse basic info from raw
        lines = raw_request.strip().split("\n")
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                exchange.method = parts[0]
                exchange.url = parts[1]

        # Parse status code from response
        resp_lines = raw_response.strip().split("\n")
        if resp_lines:
            parts = resp_lines[0].split()
            if len(parts) >= 2:
                try:
                    exchange.status_code = int(parts[1])
                except (ValueError, IndexError):
                    pass

        return self.log(exchange)

    def get_by_finding(self, finding_id: str) -> list[HttpExchange]:
        """Belirli bir finding ile ilişkili tüm exchange'leri getir."""
        exchange_ids = self._finding_map.get(finding_id, [])
        return [
            e for e in self.exchanges
            if e.exchange_id in exchange_ids
        ]

    def get_by_id(self, exchange_id: str) -> HttpExchange | None:
        """Exchange ID ile getir."""
        for e in self.exchanges:
            if e.exchange_id == exchange_id:
                return e
        return None

    def save_session(self) -> str:
        """Tüm oturum exchange'lerini dosyaya kaydet."""
        if not self.exchanges:
            logger.warning("No exchanges to save")
            return ""

        # JSON format
        json_path = self.output_dir / f"{self.session_id}_traffic.json"
        data = {
            "session_id": self.session_id,
            "total_exchanges": len(self.exchanges),
            "saved_at": time.time(),
            "exchanges": [e.model_dump() for e in self.exchanges],
        }
        json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

        # Raw text format (human readable)
        txt_path = self.output_dir / f"{self.session_id}_traffic.txt"
        lines = [
            f"# HTTP Traffic Log — Session: {self.session_id}",
            f"# Total Exchanges: {len(self.exchanges)}",
            f"# Saved: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "",
            "=" * 70,
        ]

        for i, ex in enumerate(self.exchanges, 1):
            lines.append(f"\n{'='*70}")
            lines.append(f"Exchange #{i} | ID: {ex.exchange_id}")
            lines.append(f"Tool: {ex.tool_name} | Finding: {ex.finding_id}")
            lines.append(f"Payload: {ex.is_payload} | Time: {ex.response_time_ms:.0f}ms")
            if ex.notes:
                lines.append(f"Notes: {ex.notes}")
            lines.append(f"{'─'*70}")
            lines.append("")
            lines.append(">>> REQUEST >>>")
            lines.append(ex.to_raw_request())
            lines.append("")
            lines.append("<<< RESPONSE <<<")
            lines.append(ex.to_raw_response())
            lines.append("")

        txt_path.write_text("\n".join(lines), encoding="utf-8")

        logger.info(
            f"Session traffic saved | exchanges={len(self.exchanges)} | "
            f"json={json_path} | txt={txt_path}"
        )

        return str(json_path)

    def to_report_evidence(self, finding_id: str) -> dict[str, str]:
        """Finding için rapor kanıt bölümü oluştur."""
        exchanges = self.get_by_finding(finding_id)

        if not exchanges:
            return {"request": "", "response": ""}

        # Payload exchange'leri filtrele
        payload = [e for e in exchanges if e.is_payload]

        # Payload exchange'i tercih et
        primary = payload[0] if payload else exchanges[0]

        return {
            "request": primary.to_raw_request(),
            "response": primary.to_raw_response(),
            "total_exchanges": len(exchanges),
            "payload_exchanges": len(payload),
        }

    def _mask_exchange(self, exchange: HttpExchange) -> HttpExchange:
        """Hassas verileri maskele."""
        # Header maskeleme
        masked_req_headers = {}
        for key, value in exchange.request_headers.items():
            if key.lower() in self.SENSITIVE_HEADERS:
                masked_req_headers[key] = self._mask_value(value)
            else:
                masked_req_headers[key] = value
        exchange.request_headers = masked_req_headers

        masked_resp_headers = {}
        for key, value in exchange.response_headers.items():
            if key.lower() in self.SENSITIVE_HEADERS:
                masked_resp_headers[key] = self._mask_value(value)
            else:
                masked_resp_headers[key] = value
        exchange.response_headers = masked_resp_headers

        # Body maskeleme (JSON)
        exchange.request_body = self._mask_body(exchange.request_body)

        return exchange

    @staticmethod
    def _mask_value(value: str) -> str:
        """Değeri maskele, ilk ve son 4 karakter bırak."""
        if len(value) <= 12:
            return "****"
        return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"

    def _mask_body(self, body: str) -> str:
        """JSON body'deki hassas alanları maskele."""
        if not body:
            return body

        try:
            data = json.loads(body)
            if isinstance(data, dict):
                data = self._mask_dict(data)
                return json.dumps(data)
        except (json.JSONDecodeError, TypeError):
            pass

        return body

    def _mask_dict(self, d: dict) -> dict:
        """Dict'teki hassas key'leri maskele."""
        masked = {}
        for key, value in d.items():
            if key.lower() in self.SENSITIVE_KEYS:
                masked[key] = "****MASKED****"
            elif isinstance(value, dict):
                masked[key] = self._mask_dict(value)
            else:
                masked[key] = value
        return masked

    @property
    def exchange_count(self) -> int:
        return len(self.exchanges)

    def get_stats(self) -> dict[str, Any]:
        """Oturum istatistikleri."""
        methods: dict[str, int] = {}
        status_codes: dict[int, int] = {}
        tools: dict[str, int] = {}

        for ex in self.exchanges:
            methods[ex.method] = methods.get(ex.method, 0) + 1
            if ex.status_code:
                status_codes[ex.status_code] = status_codes.get(ex.status_code, 0) + 1
            if ex.tool_name:
                tools[ex.tool_name] = tools.get(ex.tool_name, 0) + 1

        return {
            "total_exchanges": len(self.exchanges),
            "payload_exchanges": sum(1 for e in self.exchanges if e.is_payload),
            "unique_findings": len(self._finding_map),
            "methods": methods,
            "status_codes": status_codes,
            "tools": tools,
        }


__all__ = [
    "RequestLogger",
    "HttpExchange",
]
