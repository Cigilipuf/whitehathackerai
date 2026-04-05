"""
WhiteHatHacker AI — Response Differential Analysis

Normal istek ile payload'lu istek arasındaki farkları analiz eder.
Bu fark analizi, bir zafiyetin gerçek mi yoksa false positive mı
olduğunu belirlemede kullanılır.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from typing import Any

from pydantic import BaseModel


class ResponseDiff(BaseModel):
    """İki HTTP yanıtı arasındaki fark analiz sonucu."""

    # Status
    status_code_normal: int = 0
    status_code_payload: int = 0
    status_code_changed: bool = False

    # Body
    body_hash_normal: str = ""
    body_hash_payload: str = ""
    body_changed: bool = False
    body_similarity: float = 0.0  # 0.0 — 1.0 (1 = identical)
    body_size_normal: int = 0
    body_size_payload: int = 0
    body_size_diff: int = 0

    # Content
    payload_reflected: bool = False
    payload_encoded: bool = False
    encoding_type: str = ""              # html_entity | url_encode | none
    payload_in_html_context: str = ""    # attribute | tag | script | comment | body | none

    # Headers
    header_diff: dict[str, Any] = {}
    content_type_changed: bool = False

    # Timing
    response_time_normal: float = 0.0
    response_time_payload: float = 0.0
    timing_anomaly: bool = False  # Significant timing diff (>2x)

    # Verdict
    is_significant: bool = False
    confidence_delta: float = 0.0
    analysis_notes: list[str] = []


class ResponseDiffAnalyzer:
    """
    HTTP response karşılaştırma motoru.

    Normal bir isteğin yanıtı ile payload içeren isteğin yanıtını
    karşılaştırarak zafiyetin gerçek olup olmadığını belirler.

    Kullanım:
        analyzer = ResponseDiffAnalyzer()
        diff = analyzer.analyze(
            normal_response=normal_resp,
            payload_response=payload_resp,
            payload="<script>alert(1)</script>",
        )

        if diff.is_significant and diff.payload_reflected:
            # Muhtemelen gerçek zafiyet
    """

    # Bilinen encoding türleri
    HTML_ENTITY_MAP = {
        "<": ["&lt;", "&#60;", "&#x3c;"],
        ">": ["&gt;", "&#62;", "&#x3e;"],
        '"': ["&quot;", "&#34;", "&#x22;"],
        "'": ["&#39;", "&#x27;", "&apos;"],
        "&": ["&amp;", "&#38;", "&#x26;"],
    }

    URL_ENCODE_MAP = {
        "<": ["%3C", "%3c"],
        ">": ["%3E", "%3e"],
        '"': ["%22"],
        "'": ["%27"],
        "(": ["%28"],
        ")": ["%29"],
        "/": ["%2F", "%2f"],
    }

    # HTML bağlam tespiti regex'leri
    CONTEXT_PATTERNS = {
        "script": re.compile(
            r"<script[^>]*>.*?PAYLOAD_MARKER.*?</script>", re.DOTALL | re.IGNORECASE
        ),
        "attribute": re.compile(
            r'[a-z-]+\s*=\s*["\']?[^"\']*PAYLOAD_MARKER', re.IGNORECASE
        ),
        "tag": re.compile(
            r"<[^>]*PAYLOAD_MARKER[^>]*>", re.IGNORECASE
        ),
        "comment": re.compile(
            r"<!--.*?PAYLOAD_MARKER.*?-->", re.DOTALL
        ),
        "href": re.compile(
            r'(?:href|src|action)\s*=\s*["\']?[^"\']*PAYLOAD_MARKER', re.IGNORECASE
        ),
    }

    # Timing anomaly threshold (saniye)
    TIMING_THRESHOLD_FACTOR = 2.5
    TIMING_MIN_DIFF = 3.0  # En az 3 saniyelik fark olmalı

    def analyze(
        self,
        normal_response: dict[str, Any],
        payload_response: dict[str, Any],
        payload: str = "",
        vuln_type: str = "",
    ) -> ResponseDiff:
        """
        Normal ve payload yanıtlarını karşılaştır.

        Args:
            normal_response: Normal isteğin yanıtı:
                {"status_code": 200, "body": "...", "headers": {...}, "time": 0.5}
            payload_response: Payload'lu isteğin yanıtı (aynı format)
            payload: Kullanılan payload metni
            vuln_type: Zafiyet türü (bağlam duyarlı analiz için)

        Returns:
            ResponseDiff
        """
        diff = ResponseDiff()
        notes: list[str] = []
        confidence_delta = 0.0

        # ── Status Code Analizi ──
        normal_status = normal_response.get("status_code", 0)
        payload_status = payload_response.get("status_code", 0)
        diff.status_code_normal = normal_status
        diff.status_code_payload = payload_status
        diff.status_code_changed = normal_status != payload_status

        if diff.status_code_changed:
            # 5xx değişimi → server error (payload etkili olmuş olabilir)
            if 500 <= payload_status < 600 and 200 <= normal_status < 300:
                confidence_delta += 10.0
                notes.append(f"Status changed to {payload_status} (server error → possible injection)")
            # 403/WAF block
            elif payload_status in (403, 406, 429):
                confidence_delta -= 5.0
                notes.append(f"Status {payload_status} suggests WAF/rate limit block")
            # Redirect
            elif 300 <= payload_status < 400:
                if vuln_type in ("open_redirect", "ssrf"):
                    confidence_delta += 8.0
                    notes.append("Redirect detected — consistent with open redirect/SSRF")

        # ── Body Analizi ──
        normal_body = normal_response.get("body", "")
        payload_body = payload_response.get("body", "")

        diff.body_hash_normal = hashlib.md5(normal_body.encode()).hexdigest()[:16]
        diff.body_hash_payload = hashlib.md5(payload_body.encode()).hexdigest()[:16]
        diff.body_changed = diff.body_hash_normal != diff.body_hash_payload
        diff.body_size_normal = len(normal_body)
        diff.body_size_payload = len(payload_body)
        diff.body_size_diff = diff.body_size_payload - diff.body_size_normal

        # Similarity ratio
        if normal_body and payload_body:
            diff.body_similarity = difflib.SequenceMatcher(
                None, normal_body[:5000], payload_body[:5000]
            ).ratio()
        elif not normal_body and not payload_body:
            diff.body_similarity = 1.0
        else:
            diff.body_similarity = 0.0

        if diff.body_changed:
            notes.append(
                f"Body changed (similarity={diff.body_similarity:.2f}, "
                f"size_diff={diff.body_size_diff:+d})"
            )

        # ── Payload Reflection Analizi ──
        if payload and payload_body:
            reflection = self._analyze_reflection(payload, payload_body)
            diff.payload_reflected = reflection["reflected"]
            diff.payload_encoded = reflection["encoded"]
            diff.encoding_type = reflection["encoding_type"]
            diff.payload_in_html_context = reflection["context"]

            if diff.payload_reflected and not diff.payload_encoded:
                confidence_delta += 20.0
                notes.append(f"Payload reflected UNENCODED in {diff.payload_in_html_context} context")
            elif diff.payload_reflected and diff.payload_encoded:
                confidence_delta -= 5.0
                notes.append(f"Payload reflected but ENCODED ({diff.encoding_type})")
            elif not diff.payload_reflected:
                confidence_delta -= 8.0
                notes.append("Payload NOT reflected in response body")

        # ── Header Analizi ──
        normal_headers = normal_response.get("headers", {})
        payload_headers = payload_response.get("headers", {})
        diff.header_diff = self._compare_headers(normal_headers, payload_headers)

        normal_ct = str(normal_headers.get("content-type", ""))
        payload_ct = str(payload_headers.get("content-type", ""))
        diff.content_type_changed = normal_ct != payload_ct
        if diff.content_type_changed:
            notes.append(f"Content-Type changed: {normal_ct} → {payload_ct}")

        # ── Timing Analizi ──
        diff.response_time_normal = normal_response.get("time", 0.0)
        diff.response_time_payload = payload_response.get("time", 0.0)

        if diff.response_time_normal > 0 and diff.response_time_payload > 0:
            time_ratio = diff.response_time_payload / max(diff.response_time_normal, 0.001)
            time_diff = diff.response_time_payload - diff.response_time_normal

            if time_ratio > self.TIMING_THRESHOLD_FACTOR and time_diff > self.TIMING_MIN_DIFF:
                diff.timing_anomaly = True
                # Time-based SQLi/SSRFiçin önemli
                if vuln_type in ("sql_injection", "command_injection", "ssrf"):
                    confidence_delta += 15.0
                    notes.append(
                        f"Timing anomaly: {diff.response_time_payload:.2f}s vs "
                        f"{diff.response_time_normal:.2f}s (ratio={time_ratio:.1f}x)"
                    )

        # ── Vuln-Type Specific Checks ──
        confidence_delta += self._vuln_specific_checks(
            vuln_type, diff, payload_body, payload, notes
        )

        # ── Final ──
        diff.is_significant = (
            diff.body_changed
            or diff.status_code_changed
            or diff.payload_reflected
            or diff.timing_anomaly
        )
        diff.confidence_delta = confidence_delta
        diff.analysis_notes = notes

        return diff

    def _analyze_reflection(
        self,
        payload: str,
        body: str,
    ) -> dict[str, Any]:
        """Payload'ın response body'de nasıl reflect olduğunu analiz et."""
        result = {
            "reflected": False,
            "encoded": False,
            "encoding_type": "none",
            "context": "none",
        }

        # 1. Ham payload reflect olmuş mu?
        if payload in body:
            result["reflected"] = True
            result["encoded"] = False
            result["context"] = self._detect_context(payload, body)
            return result

        # 2. HTML entity encoded mi?
        for char, encodings in self.HTML_ENTITY_MAP.items():
            if char in payload:
                for enc in encodings:
                    encoded_payload = payload.replace(char, enc)
                    if encoded_payload in body:
                        result["reflected"] = True
                        result["encoded"] = True
                        result["encoding_type"] = "html_entity"
                        return result

        # 3. URL encoded mi?
        for char, encodings in self.URL_ENCODE_MAP.items():
            if char in payload:
                for enc in encodings:
                    encoded_payload = payload.replace(char, enc)
                    if encoded_payload in body:
                        result["reflected"] = True
                        result["encoded"] = True
                        result["encoding_type"] = "url_encode"
                        return result

        # 4. Double encoded mi?
        for char, url_encs in self.URL_ENCODE_MAP.items():
            if char in payload:
                for enc in url_encs:
                    double_enc = enc.replace("%", "%25")
                    double_payload = payload.replace(char, double_enc)
                    if double_payload in body:
                        result["reflected"] = True
                        result["encoded"] = True
                        result["encoding_type"] = "double_encode"
                        return result

        # 5. Partial reflection check (payload parçalı mı?)
        if len(payload) > 5:
            # Payload'ın en az %60'ı reflect olmuşsa partial
            for i in range(0, len(payload) - 3):
                substr = payload[i:i+4]
                if substr in body and not all(c.isalnum() for c in substr):
                    # Özel karakter içeren kısım reflect olmuş
                    result["reflected"] = True
                    result["encoded"] = False
                    result["encoding_type"] = "partial"
                    result["context"] = self._detect_context(substr, body)
                    return result

        return result

    def _detect_context(self, payload: str, body: str) -> str:
        """Payload'ın HTML'deki bağlamını tespit et."""
        # Payload yerine marker koyarak regex ile bağlam tespiti
        marker = "PAYLOAD_MARKER"
        marked_body = body.replace(payload, marker, 1)

        for ctx_name, pattern in self.CONTEXT_PATTERNS.items():
            if pattern.search(marked_body):
                return ctx_name

        return "body"  # Genel body bağlamı

    def _compare_headers(
        self,
        normal: dict[str, Any],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Header farkları hesapla."""
        diff = {}
        all_keys = set(normal.keys()) | set(payload.keys())

        for key in all_keys:
            n_val = str(normal.get(key, ""))
            p_val = str(payload.get(key, ""))
            if n_val != p_val:
                diff[key] = {"normal": n_val, "payload": p_val}

        return diff

    def _vuln_specific_checks(
        self,
        vuln_type: str,
        diff: ResponseDiff,
        payload_body: str,
        payload: str,
        notes: list[str],
    ) -> float:
        """Zafiyet türüne özel ek kontroller."""
        delta = 0.0
        body_lower = payload_body.lower()

        if vuln_type == "sql_injection":
            # SQL hata mesajları
            sql_errors = [
                "you have an error in your sql syntax",
                "unclosed quotation mark",
                "microsoft ole db provider",
                "syntax error at or near",
                "pg_query()",
                "mysql_fetch",
                "sqlite3.operationalerror",
                "ora-01756",
                "warning: mysql",
                "unexpected end of sql command",
            ]
            for err in sql_errors:
                if err in body_lower:
                    delta += 12.0
                    notes.append(f"SQL error message found: '{err[:50]}'")
                    break

        elif vuln_type in ("xss_reflected", "xss_stored", "xss_dom"):
            # Script execution context kontrolü
            if diff.payload_reflected and not diff.payload_encoded:
                if diff.payload_in_html_context == "script":
                    delta += 10.0
                    notes.append("Payload in script context — high XSS confidence")
                elif diff.payload_in_html_context == "attribute":
                    delta += 5.0
                    notes.append("Payload in attribute context — medium XSS confidence")

        elif vuln_type == "command_injection":
            # OS output patterns
            cmd_patterns = [
                r"uid=\d+\(\w+\)",       # id command
                r"root:x:0:0",           # /etc/passwd
                r"total\s+\d+",          # ls output
                r"Volume Serial Number",  # Windows dir
                r"\d+\.\d+\.\d+\.\d+",  # IP output from ifconfig
            ]
            for pattern in cmd_patterns:
                if re.search(pattern, payload_body):
                    delta += 15.0
                    notes.append(f"OS command output pattern detected: {pattern[:30]}")
                    break

        elif vuln_type == "ssti":
            # Template injection markers (7*7=49, etc.)
            if payload and "49" in payload_body and "7*7" in payload:
                delta += 12.0
                notes.append("Template expression resolved (7*7=49)")

        elif vuln_type == "lfi" or vuln_type == "local_file_inclusion":
            lfi_patterns = ["root:x:0:0", "[boot loader]", "\\windows\\system32"]
            for p in lfi_patterns:
                if p.lower() in body_lower:
                    delta += 15.0
                    notes.append(f"LFI content detected: {p[:30]}")
                    break

        return delta


__all__ = ["ResponseDiffAnalyzer", "ResponseDiff"]
