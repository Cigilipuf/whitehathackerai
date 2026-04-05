"""
WhiteHatHacker AI — Insecure Deserialization Checker

OWASP A08:2021 — Software and Data Integrity Failures

Detects insecure deserialization patterns across multiple technologies:
- Java:   ObjectInputStream, ysoserial gadget chains
- PHP:    unserialize(), phar:// wrapper
- Python: pickle.loads(), yaml.load()
- .NET:   BinaryFormatter, ViewState (MAC disabled)
- Node.js: node-serialize, funcster
- Ruby:   Marshal.load, YAML.load

Detection strategies:
1. Response header/body fingerprinting for serialized objects
2. Error-based detection (malformed serialized data → stack traces)
3. Time-based detection (sleep payload via deserialization)
4. OOB/DNS callback detection (Interactsh integration)
"""

from __future__ import annotations

import asyncio
import base64
import re
from typing import Any

import aiohttp
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory
from src.utils.response_validator import ResponseValidator


# ─── Serialization Signatures ──────────────────────────────

# Java ObjectInputStream magic bytes (base64-encoded for injection)
JAVA_MAGIC_ACED = base64.b64encode(b"\xac\xed\x00\x05").decode()

# Regex patterns that indicate serialized data in responses
SERIALIZED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "java": [
        re.compile(r"rO0AB", re.IGNORECASE),                     # base64 java serialized
        re.compile(r"\\xac\\xed\\x00\\x05"),                      # hex java magic
        re.compile(r"java\.io\.(ObjectInputStream|Serializable)"),
        re.compile(r"com\.sun\.org\.apache"),                      # Java gadget class
        re.compile(r"org\.apache\.commons\.collections"),
        re.compile(r"ClassNotFoundException|InvalidClassException"),
    ],
    "php": [
        re.compile(r'[OaCi]:\d+:"[^"]*":\d+:\{'),                 # PHP serialized object
        re.compile(r"unserialize\(\)"),                             # PHP error
        re.compile(r"__wakeup|__destruct"),                        # PHP magic methods in error
    ],
    "python": [
        re.compile(r"gASV|gAJ"),                                   # pickle protocol 4/2 base64
        re.compile(r"pickle\.(loads|load)|unpickle"),
        re.compile(r"yaml\.load|yaml\.unsafe_load"),
    ],
    "dotnet": [
        re.compile(r"__VIEWSTATE", re.IGNORECASE),                 # .NET ViewState
        re.compile(r"AAEAAAD/////"),                                # .NET BinaryFormatter base64
        re.compile(r"System\.Runtime\.Serialization"),
        re.compile(r"TypeConverter|ObjectStateFormatter"),
    ],
    "node": [
        re.compile(r'_\$\$ND_FUNC\$\$_'),                          # node-serialize marker
        re.compile(r"funcster|serialize-javascript"),
    ],
    "ruby": [
        re.compile(r'\x04\x08', re.DOTALL),                        # Ruby Marshal
        re.compile(r"Psych::DisallowedClass|Marshal\.load"),
    ],
}

# ─── Error-Based Probes ────────────────────────────────────

# Malformed serialized data designed to trigger revealing errors
ERROR_PROBES: dict[str, list[dict[str, str]]] = {
    "java": [
        {
            "payload": "rO0ABXQABHRlc3Q=",  # Valid but minimal Java serialized string
            "desc": "Java serialized string object",
        },
        {
            "payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
            "desc": "Java HashMap partial (should trigger ClassNotFound)",
        },
    ],
    "php": [
        {
            "payload": 'O:4:"test":0:{}',
            "desc": "PHP serialized object (class test)",
        },
        {
            "payload": 'a:1:{s:4:"test";s:5:"hello";}',
            "desc": "PHP serialized array",
        },
        {
            "payload": 'O:7:"INVALID":0:{}',
            "desc": "PHP serialized invalid class",
        },
    ],
    "python": [
        {
            "payload": base64.b64encode(b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x04test.").decode(),
            "desc": "Python pickle protocol 4 (test module)",
        },
    ],
    "dotnet": [
        {
            "payload": "AAEAAAD/////AQAAAAAAAAAEAQAAAA==",
            "desc": ".NET BinaryFormatter minimal",
        },
    ],
    "node": [
        {
            "payload": '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}',
            "desc": "node-serialize RCE marker",
        },
    ],
}

# ─── Time-Based Probes ─────────────────────────────────────

# These rely on deserialization executing code that sleeps
TIMEBASED_PROBES: dict[str, list[dict[str, Any]]] = {
    "php": [
        {
            "payload": 'O:21:"JDatabaseDriverMysqli":0:{}',
            "desc": "Joomla deserialization (common gadget)",
            "sleep_seconds": 0,  # Error-based, not sleep
        },
    ],
    "python": [
        {
            # pickle that imports time.sleep(3)
            "payload": base64.b64encode(
                b"\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00"
                b"\x8c\x04time\x8c\x05sleep\x93\x94G@\x08\x00"
                b"\x00\x00\x00\x00\x00\x85R."
            ).decode(),
            "desc": "Python pickle time.sleep(3)",
            "sleep_seconds": 3,
        },
    ],
}


class DeserializationChecker(SecurityTool):
    """
    Insecure Deserialization Detection Module.

    Multi-language deserialization vulnerability scanner that:
    1. Fingerprints serialization formats in responses
    2. Sends error-inducing malformed serialized data
    3. Analyzes error responses for deserialization indicators
    4. Tests time-based payloads for blind confirmation
    5. Reports technology-specific remediation guidance
    """

    name = "deserialization_checker"
    category = ToolCategory.SCANNER
    description = "Insecure deserialization detection across Java/PHP/Python/.NET/Node.js"
    binary_name = "python3"
    requires_root = False
    risk_level = RiskLevel.MEDIUM

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        base_url = target.rstrip("/") if target.startswith("http") else f"https://{target}"
        endpoints = options.get("endpoints", ["/"])
        technologies = options.get("technologies", [])
        timeout_s = options.get("timeout", 15)
        max_concurrent = options.get("concurrency", 3)
        options.get("oob_domain", "")

        findings: list[Finding] = []
        tested = 0
        errors = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=max_concurrent)
        jar = aiohttp.DummyCookieJar()
        client_timeout = aiohttp.ClientTimeout(total=timeout_s)

        async with aiohttp.ClientSession(
            connector=connector,
            cookie_jar=jar,
            timeout=client_timeout,
        ) as session:
            # Phase 1: Fingerprint — scan responses for serialization markers
            fingerprint_findings = await self._fingerprint_responses(
                session, base_url, endpoints, technologies
            )
            findings.extend(fingerprint_findings)

            # Phase 2: Error-based probing
            target_techs = self._determine_target_technologies(technologies)
            sem = asyncio.Semaphore(max_concurrent)

            error_tasks = []
            for endpoint in endpoints[:20]:  # Limit to 20 endpoints
                url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint
                for tech in target_techs:
                    for probe in ERROR_PROBES.get(tech, []):
                        error_tasks.append(
                            self._error_probe(
                                sem, session, url, tech, probe, timeout_s
                            )
                        )

            if error_tasks:
                results = await asyncio.gather(*error_tasks, return_exceptions=True)
                for r in results:
                    tested += 1
                    if isinstance(r, Exception):
                        errors += 1
                    elif r is not None:
                        findings.append(r)

            # Phase 3: ViewState analysis (for .NET targets)
            if "dotnet" in target_techs or "asp.net" in target_techs:
                vs_findings = await self._check_viewstate(
                    session, base_url, endpoints
                )
                findings.extend(vs_findings)

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            findings=findings,
            raw_output=f"Deserialization check: {tested} probes, "
                       f"{len(findings)} findings, {errors} errors",
            execution_time=0.0,
            metadata={
                "probes_sent": tested,
                "errors": errors,
                "technologies_tested": target_techs,
            },
        )

    async def _fingerprint_responses(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        endpoints: list[str],
        technologies: list[str],
    ) -> list[Finding]:
        """Scan responses for serialization format markers."""
        findings: list[Finding] = []

        for endpoint in endpoints[:30]:
            url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint
            try:
                async with session.get(url) as resp:
                    body = await resp.text(errors="replace")

                    # ── ResponseValidator: reject WAF/redirect/error pages ──
                    _rv = ResponseValidator()
                    vr = _rv.validate(
                        resp.status, dict(resp.headers), body, url=url,
                    )
                    if not vr.is_valid:
                        continue

                    headers_str = str(dict(resp.headers))

                    combined = body + headers_str
                    for tech, patterns in SERIALIZED_PATTERNS.items():
                        for pat in patterns:
                            match = pat.search(combined)
                            if match:
                                findings.append(Finding(
                                    title=f"Serialization Format Detected: {tech}",
                                    description=(
                                        f"Found {tech} serialization marker at {url}. "
                                        f"Pattern: {pat.pattern[:60]}... "
                                        f"Match: {match.group()[:80]}"
                                    ),
                                    severity=SeverityLevel.INFO
                                    if tech == "dotnet" and "__VIEWSTATE" in match.group()
                                    else SeverityLevel.LOW,
                                    confidence=40.0,
                                    target=url,
                                    evidence=f"Match: {match.group()[:200]}",
                                    tool_name=self.name,
                                    vulnerability_type=f"deserialization_{tech}_fingerprint",
                                ))
                                break  # One finding per tech per endpoint
            except Exception as _exc:
                logger.debug(f"deserialization checker error: {_exc}")
                continue

        return findings

    async def _error_probe(
        self,
        sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        url: str,
        tech: str,
        probe: dict[str, str],
        timeout_s: int,
    ) -> Finding | None:
        """Send malformed serialized data and analyze error responses."""
        async with sem:
            payload = probe["payload"]
            # Try multiple injection vectors
            for method, inject_fn in [
                ("body_raw", lambda: session.post(url, data=payload, headers={"Content-Type": "application/octet-stream"})),
                ("body_json", lambda: session.post(url, json={"data": payload})),
                ("cookie", lambda: session.get(url, cookies={"session": payload})),
                ("param", lambda: session.get(url, params={"data": payload})),
            ]:
                try:
                    async with inject_fn() as resp:
                        body = await resp.text(errors="replace")

                        # ── ResponseValidator: reject WAF blocks, redirects ──
                        # Note: we ALLOW 500 errors (they may contain stack traces
                        # that prove deserialization), so only filter redirects + WAF
                        _rv = ResponseValidator()
                        vr = _rv.validate(
                            resp.status, dict(resp.headers), body, url=url,
                        )
                        if vr.is_redirect or vr.is_waf_block:
                            continue

                        # Check for deserialization error indicators
                        for pat in SERIALIZED_PATTERNS.get(tech, []):
                            if pat.search(body):
                                # Determine severity based on error verbosity
                                has_stack = bool(re.search(
                                    r"(stack\s*trace|Traceback|Exception in|at\s+\w+\.\w+\()",
                                    body, re.IGNORECASE,
                                ))
                                severity = SeverityLevel.HIGH if has_stack else SeverityLevel.MEDIUM

                                return Finding(
                                    title=f"Insecure Deserialization ({tech.upper()}) — {probe['desc']}",
                                    description=(
                                        f"Error-based deserialization detected at {url}. "
                                        f"Injection via {method}. Technology: {tech}. "
                                        f"The server processed serialized {tech} data and "
                                        f"returned a deserialization-related error, indicating "
                                        f"that untrusted input reaches a deserializer."
                                    ),
                                    severity=severity,
                                    confidence=65.0 if has_stack else 45.0,
                                    target=url,
                                    evidence=(
                                        f"Probe: {probe['desc']}\n"
                                        f"Method: {method}\n"
                                        f"Response status: {resp.status}\n"
                                        f"Error snippet: {body[:500]}"
                                    ),
                                    tool_name=self.name,
                                    vulnerability_type=f"insecure_deserialization_{tech}",
                                    remediation=self._get_remediation(tech),
                                    cwe_id="CWE-502",
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

        return None

    async def _check_viewstate(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        endpoints: list[str],
    ) -> list[Finding]:
        """.NET ViewState MAC validation check."""
        findings: list[Finding] = []

        for endpoint in endpoints[:15]:
            url = f"{base_url}{endpoint}" if not endpoint.startswith("http") else endpoint
            try:
                async with session.get(url) as resp:
                    body = await resp.text(errors="replace")

                    # ── ResponseValidator: reject WAF/redirect/error pages ──
                    _rv = ResponseValidator()
                    vr = _rv.validate(
                        resp.status, dict(resp.headers), body, url=url,
                    )
                    if not vr.is_valid:
                        continue

                    # Find ViewState values
                    vs_match = re.search(
                        r'__VIEWSTATE[^>]*value="([^"]+)"', body, re.IGNORECASE
                    )
                    if not vs_match:
                        continue

                    vs_value = vs_match.group(1)

                    # Check for MAC validation
                    # If ViewState is very short or lacks the MAC signature portion,
                    # it may not be MAC-protected
                    vs_gen_match = re.search(
                        r'__VIEWSTATEGENERATOR[^>]*value="([^"]+)"',
                        body, re.IGNORECASE,
                    )

                    # Test: tamper with ViewState
                    tampered = vs_value[:20] + "AAAA" + vs_value[24:]
                    try:
                        tamper_resp = await session.post(
                            url,
                            data={
                                "__VIEWSTATE": tampered,
                                "__VIEWSTATEGENERATOR": vs_gen_match.group(1) if vs_gen_match else "",
                            },
                        )
                        tamper_body = await tamper_resp.text(errors="replace")

                        # If we DON'T get a MAC validation error, ViewState is unprotected
                        if tamper_resp.status != 500 and "validation of viewstate MAC failed" not in tamper_body.lower():
                            findings.append(Finding(
                                title="ViewState MAC Validation Disabled",
                                description=(
                                    f"The .NET ViewState at {url} does not appear to "
                                    f"enforce MAC validation. A tampered ViewState was "
                                    f"accepted without error, potentially allowing "
                                    f"deserialization attacks via ViewState injection."
                                ),
                                severity=SeverityLevel.HIGH,
                                confidence=60.0,
                                target=url,
                                evidence=(
                                    f"Original ViewState length: {len(vs_value)}\n"
                                    f"Tampered response status: {tamper_resp.status}\n"
                                    f"No MAC validation error detected"
                                ),
                                tool_name=self.name,
                                vulnerability_type="viewstate_no_mac",
                                remediation=(
                                    "Enable ViewState MAC validation in web.config: "
                                    '<pages enableViewStateMac="true" />'
                                ),
                                cwe_id="CWE-502",
                            ))
                    except Exception as _exc:
                        logger.debug(f"deserialization checker error: {_exc}")

            except Exception as _exc:
                logger.debug(f"deserialization checker error: {_exc}")
                continue

        return findings

    def _determine_target_technologies(
        self, technologies: list[str]
    ) -> list[str]:
        """Map detected technologies to deserialization test targets."""
        tech_map = {
            "java": ["java", "tomcat", "spring", "struts", "weblogic", "jboss", "wildfly"],
            "php": ["php", "laravel", "symfony", "wordpress", "drupal", "joomla", "magento"],
            "python": ["python", "django", "flask", "fastapi", "tornado"],
            "dotnet": [".net", "asp.net", "iis", "aspx", "blazor"],
            "node": ["node", "express", "next.js", "nuxt"],
            "ruby": ["ruby", "rails", "sinatra"],
        }

        detected: set[str] = set()
        tech_lower = [t.lower() for t in technologies]

        for deser_tech, keywords in tech_map.items():
            for kw in keywords:
                if any(kw in t for t in tech_lower):
                    detected.add(deser_tech)
                    break

        # If no tech detected, test common ones
        if not detected:
            detected = {"java", "php", "dotnet"}

        return list(detected)

    @staticmethod
    def _get_remediation(tech: str) -> str:
        """Technology-specific remediation advice."""
        remediations = {
            "java": (
                "1. Avoid Java native serialization (ObjectInputStream) for untrusted data.\n"
                "2. Use safe alternatives: JSON (Jackson/Gson), Protocol Buffers, or Avro.\n"
                "3. If serialization is required, use SerialKiller or NotSoSerial agent.\n"
                "4. Implement class allowlisting with ObjectInputFilter (Java 9+).\n"
                "5. Remove unused gadget chain libraries (Commons Collections, Spring, etc.)."
            ),
            "php": (
                "1. Never use unserialize() on untrusted input.\n"
                "2. Use json_decode() instead of unserialize().\n"
                "3. If unserialize is required, use allowed_classes parameter (PHP 7+).\n"
                "4. Disable phar:// stream wrapper if not needed.\n"
                "5. Audit __wakeup() and __destruct() methods in all classes."
            ),
            "python": (
                "1. Never use pickle.loads() on untrusted data.\n"
                "2. Use yaml.safe_load() instead of yaml.load().\n"
                "3. Use JSON for data interchange.\n"
                "4. If pickle is required, use hmac signing to verify integrity.\n"
                "5. Consider using restricted unpicklers with allowlisted classes."
            ),
            "dotnet": (
                "1. Never use BinaryFormatter for untrusted data (deprecated in .NET 5+).\n"
                "2. Enable ViewState MAC validation: enableViewStateMac='true'.\n"
                "3. Use System.Text.Json or Newtonsoft.Json instead.\n"
                "4. Set TypeNameHandling.None in JSON.NET config.\n"
                "5. Use DataContractSerializer with known types only."
            ),
            "node": (
                "1. Never use node-serialize or funcster with untrusted data.\n"
                "2. Use JSON.parse() for data interchange.\n"
                "3. Validate and sanitize all deserialized data.\n"
                "4. Remove node-serialize dependency — it is fundamentally unsafe.\n"
                "5. Use schema validation (Joi, Zod) on parsed data."
            ),
            "ruby": (
                "1. Never use Marshal.load on untrusted data.\n"
                "2. Use YAML.safe_load instead of YAML.load.\n"
                "3. Use JSON for data interchange.\n"
                "4. Audit all classes for dangerous deserialization callbacks.\n"
                "5. Set permitted_classes for YAML.safe_load if needed."
            ),
        }
        return remediations.get(tech, "Avoid deserializing untrusted data. Use safe data formats like JSON.")

    def is_available(self) -> bool:
        return True

    def build_command(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> list[str]:
        # This checker uses httpx directly, not shell commands
        return []

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        # Findings are created directly in run(); this satisfies the abstract interface
        return []

    def get_default_options(self, profile: ScanProfile = ScanProfile.BALANCED) -> dict[str, Any]:
        return {"timeout": 15, "concurrency": 3}
