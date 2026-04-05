"""WhiteHatHacker AI — Manual Verification Guide Generator.

Produces step-by-step human-readable guides for manually verifying
findings that cannot be confidently classified by automated methods.
"""

from __future__ import annotations

from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class VerificationStep(BaseModel):
    """Single manual verification step."""

    step_number: int
    action: str
    expected_result: str = ""
    tool_hint: str = ""  # curl, browser, burp, etc.
    command_example: str = ""
    notes: str = ""


class ManualVerifyGuide(BaseModel):
    """Complete manual verification guide for a finding."""

    vuln_type: str
    target: str
    summary: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    steps: list[VerificationStep] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    failure_criteria: list[str] = Field(default_factory=list)
    estimated_time_minutes: int = 5
    difficulty: str = "moderate"  # easy / moderate / hard


# ---------------------------------------------------------------------------
# Verification templates per vuln type
# ---------------------------------------------------------------------------

VERIFY_TEMPLATES: dict[str, dict[str, Any]] = {
    "sqli": {
        "summary": "Verify SQL injection by attempting data extraction or time-based confirmation",
        "prerequisites": ["HTTP intercepting proxy (Burp/mitmproxy)", "curl or similar HTTP client"],
        "difficulty": "moderate",
        "estimated_time": 10,
        "steps": [
            {"action": "Replay the original vulnerable request and confirm the anomalous response",
             "tool_hint": "curl", "expected_result": "Same anomalous response as the scanner reported"},
            {"action": "Send a baseline request without any payload and compare responses",
             "tool_hint": "curl", "expected_result": "Normal response for comparison"},
            {"action": "Try time-based confirmation: inject SLEEP/WAITFOR DELAY and measure response time",
             "tool_hint": "curl", "command_example": "curl -o /dev/null -s -w '%{time_total}' '<URL_WITH_SLEEP>'",
             "expected_result": "Response delayed by ≥5 seconds compared to baseline"},
            {"action": "Try UNION-based extraction: attempt to extract version() or @@version",
             "tool_hint": "curl or browser",
             "expected_result": "Database version string visible in response"},
            {"action": "Confirm with sqlmap in --level 3 --risk 2 mode against the specific parameter",
             "tool_hint": "sqlmap",
             "command_example": "sqlmap -u '<URL>' -p '<PARAM>' --level=3 --risk=2 --batch"},
        ],
        "success_criteria": ["Time delay correlates with injected sleep value",
                             "Data extracted from database", "sqlmap confirms injectable"],
        "failure_criteria": ["No timing difference", "Payload reflected but not executed",
                             "WAF blocks all payloads consistently"],
    },
    "xss": {
        "summary": "Verify XSS by confirming JavaScript execution in the browser context",
        "prerequisites": ["Modern web browser with DevTools", "HTTP proxy for request interception"],
        "difficulty": "easy",
        "estimated_time": 5,
        "steps": [
            {"action": "Open the target URL with the XSS payload in a browser",
             "tool_hint": "browser", "expected_result": "JavaScript alert or console log triggers"},
            {"action": "Check with a non-destructive payload like <img src=x onerror=alert(document.domain)>",
             "tool_hint": "browser",
             "expected_result": "Alert box shows the target's domain — confirming execution context"},
            {"action": "View page source — check if payload is reflected unencoded",
             "tool_hint": "browser (View Source)",
             "expected_result": "Raw HTML/JS payload visible without entity encoding"},
            {"action": "Check CSP headers — does Content-Security-Policy block inline scripts?",
             "tool_hint": "browser DevTools → Network tab",
             "expected_result": "No CSP or CSP allows unsafe-inline/unsafe-eval"},
        ],
        "success_criteria": ["JavaScript executes in victim's origin context",
                             "Payload reflected without encoding in HTML"],
        "failure_criteria": ["Payload HTML-encoded (&lt;script&gt;)",
                             "CSP blocks execution", "Payload stripped entirely"],
    },
    "ssrf": {
        "summary": "Verify SSRF by confirming the server makes requests to attacker-controlled destinations",
        "prerequisites": ["Public callback server (Burp Collaborator / interactsh / webhook.site)",
                         "Knowledge of internal IP ranges"],
        "difficulty": "moderate",
        "estimated_time": 10,
        "steps": [
            {"action": "Set up a callback listener (webhook.site or interactsh)",
             "tool_hint": "interactsh / webhook.site",
             "expected_result": "Listener ready to receive callbacks"},
            {"action": "Inject the callback URL into the vulnerable parameter",
             "tool_hint": "curl",
             "expected_result": "HTTP/DNS callback received from the target server's IP"},
            {"action": "Try accessing internal metadata: http://169.254.169.254/latest/meta-data/",
             "tool_hint": "curl",
             "expected_result": "AWS/GCP/Azure metadata content in response"},
            {"action": "Try accessing localhost: http://127.0.0.1:<common_ports>",
             "tool_hint": "curl",
             "expected_result": "Different response compared to external URL — internal service content"},
        ],
        "success_criteria": ["Out-of-band callback received", "Internal metadata accessible",
                             "Internal service content in response"],
        "failure_criteria": ["No callback received", "Request blocked by SSRF protection",
                             "Response identical for all URLs (not following)"],
    },
    "idor": {
        "summary": "Verify IDOR by accessing another user's resources with manipulated identifiers",
        "prerequisites": ["Two test accounts with different privileges",
                         "HTTP proxy for request interception"],
        "difficulty": "easy",
        "estimated_time": 5,
        "steps": [
            {"action": "Log in as User A and note the object ID in the request (e.g., /api/user/123/profile)",
             "tool_hint": "browser + proxy",
             "expected_result": "Observe the numeric/UUID identifier used"},
            {"action": "Log in as User B (different account) and get their session token",
             "tool_hint": "browser",
             "expected_result": "Valid session for User B"},
            {"action": "Using User B's session, request User A's resource by changing the ID",
             "tool_hint": "curl or proxy (Repeater)",
             "expected_result": "User A's data returned — IDOR confirmed"},
            {"action": "Try incrementing/decrementing IDs to access other resources",
             "tool_hint": "curl",
             "expected_result": "Can enumerate and access multiple users' data"},
        ],
        "success_criteria": ["User B can access User A's data",
                             "No authorisation check on resource ownership"],
        "failure_criteria": ["403/401 returned for cross-user access",
                             "Data returned is User B's own data despite ID change"],
    },
    "default": {
        "summary": "Generic manual verification procedure",
        "prerequisites": ["HTTP client (curl/Postman)", "Web browser"],
        "difficulty": "moderate",
        "estimated_time": 10,
        "steps": [
            {"action": "Replay the exact request that triggered the finding",
             "tool_hint": "curl", "expected_result": "Same response as scanner observed"},
            {"action": "Send baseline request without payload — compare responses",
             "tool_hint": "curl", "expected_result": "Clear difference between normal and payload responses"},
            {"action": "Try payload variations to confirm the behaviour is consistent",
             "tool_hint": "curl", "expected_result": "Consistent vulnerable behaviour across variations"},
            {"action": "Check for WAF/CDN interference by examining response headers",
             "tool_hint": "curl -v", "expected_result": "No WAF block signatures in headers"},
        ],
        "success_criteria": ["Consistent anomalous behaviour with payload",
                             "Response differs meaningfully from baseline"],
        "failure_criteria": ["Behaviour identical with and without payload",
                             "WAF blocking causes the anomaly"],
    },
}


# ---------------------------------------------------------------------------
# Manual Verify Guide Generator
# ---------------------------------------------------------------------------

class ManualVerifyGuideGenerator:
    """Generates step-by-step manual verification guides."""

    def __init__(self) -> None:
        self.templates = dict(VERIFY_TEMPLATES)

    def generate(
        self,
        vuln_type: str,
        target: str,
        *,
        parameter: str = "",
        payload: str = "",
        extra_context: dict[str, Any] | None = None,
    ) -> ManualVerifyGuide:
        """Generate a manual verification guide for the given finding."""
        template = self.templates.get(vuln_type, self.templates["default"])

        steps: list[VerificationStep] = []
        for idx, step_data in enumerate(template.get("steps", []), 1):
            action = step_data["action"]
            cmd = step_data.get("command_example", "")

            # Substitute placeholders
            if parameter:
                action = action.replace("<PARAM>", parameter)
                cmd = cmd.replace("<PARAM>", parameter)
            if target:
                action = action.replace("<URL>", target)
                cmd = cmd.replace("<URL>", target)

            steps.append(VerificationStep(
                step_number=idx,
                action=action,
                expected_result=step_data.get("expected_result", ""),
                tool_hint=step_data.get("tool_hint", ""),
                command_example=cmd,
                notes=step_data.get("notes", ""),
            ))

        guide = ManualVerifyGuide(
            vuln_type=vuln_type,
            target=target,
            summary=template.get("summary", f"Manual verification for {vuln_type}"),
            prerequisites=template.get("prerequisites", []),
            steps=steps,
            success_criteria=template.get("success_criteria", []),
            failure_criteria=template.get("failure_criteria", []),
            estimated_time_minutes=template.get("estimated_time", 10),
            difficulty=template.get("difficulty", "moderate"),
        )

        logger.info(
            f"Generated manual verify guide for {vuln_type}@{target} "
            f"({len(steps)} steps, ~{guide.estimated_time_minutes}min)"
        )
        return guide

    def generate_markdown(self, guide: ManualVerifyGuide) -> str:
        """Render a guide as Markdown text."""
        lines: list[str] = [
            f"# Manual Verification: {guide.vuln_type.upper()}",
            f"\n**Target:** `{guide.target}`",
            f"**Difficulty:** {guide.difficulty}  |  **Estimated Time:** ~{guide.estimated_time_minutes} min",
            f"\n## Summary\n{guide.summary}",
            "\n## Prerequisites",
        ]
        for p in guide.prerequisites:
            lines.append(f"- {p}")

        lines.append("\n## Steps")
        for step in guide.steps:
            lines.append(f"\n### Step {step.step_number}: {step.action}")
            if step.tool_hint:
                lines.append(f"**Tool:** {step.tool_hint}")
            if step.command_example:
                lines.append(f"```bash\n{step.command_example}\n```")
            if step.expected_result:
                lines.append(f"**Expected:** {step.expected_result}")
            if step.notes:
                lines.append(f"> {step.notes}")

        lines.append("\n## ✅ Success Criteria")
        for c in guide.success_criteria:
            lines.append(f"- {c}")

        lines.append("\n## ❌ Failure Criteria (likely FP)")
        for c in guide.failure_criteria:
            lines.append(f"- {c}")

        return "\n".join(lines)
