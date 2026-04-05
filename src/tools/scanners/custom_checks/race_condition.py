"""
WhiteHatHacker AI — Race Condition Checker

Detect TOCTOU / race condition vulnerabilities via concurrent request replay.
Targets: coupon/discount application, account balance, vote/like manipulation,
         file upload overwrite, registration duplicate.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import aiohttp

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Tokens that indicate a WAF/CDN challenge page
_WAF_BODY_TOKENS = (
    "cloudflare", "attention required", "ray id", "request blocked",
    "access denied", "captcha", "akamai", "incapsula", "sucuri",
    "web application firewall", "just a moment", "checking your browser",
)


def _is_waf_body(body: str) -> bool:
    """Detect WAF/CDN challenge page in response body."""
    body_lower = body[:3000].lower()
    return any(tok in body_lower for tok in _WAF_BODY_TOKENS)


class RaceConditionChecker(SecurityTool):
    """
    Race Condition / TOCTOU Detector.

    Sends N identical requests simultaneously to detect:
    - Double-spend (balance/credits)
    - Coupon reuse
    - Duplicate resource creation
    - Vote/like manipulation
    - Follow/unfollow toggling bypass

    Analysis approach:
    - All responses must be captured and compared
    - If more than expected succeed → race condition
    - Response body differential checked for state inconsistency
    """

    name = "race_condition_checker"
    category = ToolCategory.SCANNER
    description = "TOCTOU / race condition detection via concurrent request flooding"
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
        test_cases = options.get("test_cases", [])
        concurrency = options.get("concurrency", 10)
        rounds = options.get("rounds", 3)
        timeout_s = options.get("timeout", 15)

        if not test_cases:
            return ToolResult(
                tool_name=self.name,
                success=False,
                exit_code=1,
                stdout="",
                stderr="No test cases provided. Provide 'test_cases' in options.",
                findings=[],
                command=f"race_condition_checker {target}",
                target=target,
            )

        findings: list[Finding] = []
        total_tested = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency * 2)
        timeout = aiohttp.ClientTimeout(total=timeout_s)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for tc in test_cases:
                for round_num in range(rounds):
                    result = await self._race_test(session, tc, concurrency, round_num)
                    if result:
                        findings.append(result)
                    total_tested += 1

        return ToolResult(
            tool_name=self.name,
            success=True,
            exit_code=0,
            stdout=f"Tested {total_tested} race scenarios, {len(findings)} potential races detected",
            stderr="",
            findings=findings,
            command=f"race_condition_checker {target}",
            target=target,
            metadata={"total_tested": total_tested, "findings": len(findings)},
        )

    async def _race_test(
        self,
        session: aiohttp.ClientSession,
        test_case: dict,
        concurrency: int,
        round_num: int,
    ) -> Finding | None:
        """
        Execute a single race condition test.

        Sends `concurrency` identical requests at the exact same moment
        using asyncio.gather() with a shared event barrier.
        """
        url = test_case.get("url", "")
        method = test_case.get("method", "POST").upper()
        headers = test_case.get("headers", {})
        body = test_case.get("body", {})
        expected_successes = test_case.get("expected_successes", 1)
        success_indicator = test_case.get("success_indicator", "")
        failure_indicator = test_case.get("failure_indicator", "")
        description = test_case.get("description", "Race condition test")

        if not url:
            return None

        # Barrier to synchronize all requests
        barrier = asyncio.Barrier(concurrency)

        async def _fire():
            """Single request in the race."""
            try:
                try:
                    await asyncio.wait_for(barrier.wait(), timeout=10.0)
                except asyncio.TimeoutError:
                    return {"status": 0, "body": "barrier timeout", "body_hash": "", "length": 0, "elapsed": 0}
                start = time.monotonic()
                async with session.request(
                    method, url, headers=headers,
                    json=body if body else None,
                    allow_redirects=False,
                ) as resp:
                    elapsed = time.monotonic() - start
                    resp_body = await resp.text()
                    return {
                        "status": resp.status,
                        "body": resp_body,
                        "body_hash": hashlib.sha256(resp_body.encode()).hexdigest()[:32],
                        "length": len(resp_body),
                        "elapsed": elapsed,
                    }
            except Exception as exc:
                return {"status": 0, "body": str(exc), "body_hash": "", "length": 0, "elapsed": 0}

        # Fire all requests simultaneously
        tasks = [_fire() for _ in range(concurrency)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        valid_results = [r for r in results if isinstance(r, dict) and r["status"] > 0]

        if not valid_results:
            return None

        # Filter out WAF/CDN challenge responses
        waf_count = sum(1 for r in valid_results if _is_waf_body(r["body"]))
        if waf_count > len(valid_results) * 0.5:
            # Majority WAF responses — skip entire test
            return None

        # Count successes (excluding WAF responses)
        successes = 0
        for r in valid_results:
            if _is_waf_body(r["body"]):
                continue
            if success_indicator and success_indicator in r["body"]:
                successes += 1
            elif failure_indicator and failure_indicator not in r["body"]:
                successes += 1
            elif r["status"] in (200, 201):
                successes += 1

        # Analyze response diversity
        unique_hashes = set(r["body_hash"] for r in valid_results)
        status_codes = [r["status"] for r in valid_results]
        unique_statuses = set(status_codes)

        # Detection logic
        race_detected = False
        confidence = 0.0
        indicators = []

        # More successes than expected → race condition
        if successes > expected_successes:
            race_detected = True
            confidence += 40.0
            indicators.append(
                f"Expected {expected_successes} success(es), got {successes}/{concurrency}"
            )

        # All responses identical (same state snapshot) → suspicious
        if len(unique_hashes) == 1 and successes > 1:
            confidence += 15.0
            indicators.append("All responses identical (same state snapshot)")

        # All 200s when some should have been rejected
        if len(unique_statuses) == 1 and 200 in unique_statuses and expected_successes < concurrency:
            confidence += 20.0
            indicators.append("All requests returned 200 — no rejection")

        # Timing analysis — all responses very fast (no lock contention)
        avg_elapsed = sum(r["elapsed"] for r in valid_results) / len(valid_results)
        if avg_elapsed < 0.1 and successes > expected_successes:
            confidence += 10.0
            indicators.append(f"Average response time: {avg_elapsed:.3f}s (no lock contention)")

        if race_detected and confidence >= 40.0:
            return Finding(
                title=f"Race Condition: {description}",
                description=(
                    f"Race condition / TOCTOU vulnerability detected.\n"
                    f"URL: {method} {url}\n"
                    f"Concurrent requests: {concurrency}\n"
                    f"Expected successes: {expected_successes}\n"
                    f"Actual successes: {successes}\n"
                    f"Round: {round_num + 1}\n"
                    f"Indicators: {'; '.join(indicators)}"
                ),
                vulnerability_type="race_condition",
                severity=SeverityLevel.HIGH,
                confidence=min(confidence, 90.0),
                target=url,
                endpoint=url,
                tool_name=self.name,
                cwe_id="CWE-362",
                tags=["race_condition", "toctou", "concurrency"],
                evidence=[
                    f"Sent {concurrency} concurrent {method} requests",
                    f"Successes: {successes}/{concurrency} (expected: {expected_successes})",
                    f"Unique response hashes: {len(unique_hashes)}",
                    f"Status codes: {status_codes}",
                ],
                metadata={
                    "concurrency": concurrency,
                    "successes": successes,
                    "expected_successes": expected_successes,
                    "unique_hashes": len(unique_hashes),
                    "avg_elapsed": avg_elapsed,
                    "round": round_num + 1,
                },
            )

        return None

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return ["python3", "-c", "pass"]

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["RaceConditionChecker"]
