"""WhiteHatHacker AI — Technical Detail Report Template.

Generates deep-dive technical reports with full reproduction steps,
HTTP traces, code snippets, and remediation guidance suitable for
developers and security engineers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class HttpTrace(BaseModel):
    """HTTP request/response pair."""

    request_method: str = "GET"
    request_url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: str = ""
    notes: str = ""


class ReproductionStep(BaseModel):
    """Single step in reproduction procedure."""

    step_number: int
    description: str
    command: str = ""
    expected_result: str = ""
    screenshot: str = ""


class TechnicalFinding(BaseModel):
    """Full technical detail for a single finding."""

    title: str
    vuln_type: str
    severity: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    target_url: str = ""
    affected_parameter: str = ""
    payload: str = ""
    technical_description: str = ""
    root_cause: str = ""
    reproduction_steps: list[ReproductionStep] = Field(default_factory=list)
    http_traces: list[HttpTrace] = Field(default_factory=list)
    poc_code: str = ""
    screenshots: list[str] = Field(default_factory=list)
    impact_analysis: str = ""
    remediation: str = ""
    remediation_code: str = ""
    references: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    tools_used: list[str] = Field(default_factory=list)


class TechnicalReport(BaseModel):
    """Full technical report."""

    title: str = "Technical Security Assessment Report"
    target: str = ""
    assessment_date: str = ""
    findings: list[TechnicalFinding] = Field(default_factory=list)
    methodology: str = ""
    tools_employed: list[str] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Remediation database
# ---------------------------------------------------------------------------

_VULN_TYPE_ALIASES: dict[str, str] = {
    "sql_injection": "sqli",
    "sql_injection_blind": "sqli",
    "sql_injection_error": "sqli",
    "sqli_blind": "sqli",
    "sqli_error": "sqli",
    "sqli_union": "sqli",
    "xss_reflected": "xss",
    "xss_stored": "xss",
    "xss_dom": "xss",
    "cross_site_scripting": "xss",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "dom_xss": "xss",
    "server_side_request_forgery": "ssrf",
    "insecure_direct_object_reference": "idor",
    "broken_access_control": "idor",
    "command_injection": "rce",
    "remote_code_execution": "rce",
    "os_command_injection": "rce",
    "server_side_template_injection": "ssti",
    "template_injection": "ssti",
}

REMEDIATION_DB: dict[str, dict[str, str]] = {
    "sqli": {
        "description": "Use parameterised queries (prepared statements) for all database operations.",
        "code": (
            "# Python (SQLAlchemy)\n"
            "stmt = text('SELECT * FROM users WHERE id = :uid')\n"
            "result = db.execute(stmt, {'uid': user_id})\n\n"
            "# PHP (PDO)\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n"
            "$stmt->execute([$userId]);"
        ),
    },
    "xss": {
        "description": "Apply context-aware output encoding and implement Content-Security-Policy.",
        "code": (
            "# Python (Jinja2 auto-escaping)\n"
            "# Ensure autoescape=True in Jinja2 environment\n"
            "{{ user_input }}  {# auto-escaped #}\n\n"
            "# CSP Header\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self'"
        ),
    },
    "ssrf": {
        "description": "Validate and whitelist allowed outbound URLs. Block internal/metadata IPs.",
        "code": (
            "import ipaddress\n\n"
            "BLOCKED_RANGES = [\n"
            "    ipaddress.ip_network('10.0.0.0/8'),\n"
            "    ipaddress.ip_network('172.16.0.0/12'),\n"
            "    ipaddress.ip_network('192.168.0.0/16'),\n"
            "    ipaddress.ip_network('169.254.0.0/16'),  # metadata\n"
            "]\n\n"
            "def is_safe_url(url: str) -> bool:\n"
            "    ip = socket.gethostbyname(urlparse(url).hostname)\n"
            "    addr = ipaddress.ip_address(ip)\n"
            "    return not any(addr in net for net in BLOCKED_RANGES)"
        ),
    },
    "idor": {
        "description": "Implement server-side authorisation checks on every resource access.",
        "code": (
            "# Always verify ownership\n"
            "def get_user_profile(request, profile_id):\n"
            "    profile = Profile.objects.get(id=profile_id)\n"
            "    if profile.owner_id != request.user.id:\n"
            "        raise PermissionDenied('Access denied')\n"
            "    return profile"
        ),
    },
    "rce": {
        "description": "Never pass user input to system commands. Use safe APIs instead.",
        "code": (
            "# BAD — command injection\n"
            "os.system(f'ping {user_input}')\n\n"
            "# GOOD — use subprocess with list args\n"
            "import subprocess\n"
            "subprocess.run(['ping', '-c', '4', validated_hostname], check=True)"
        ),
    },
    "ssti": {
        "description": "Use sandboxed template environments. Never render user input as templates.",
        "code": (
            "# BAD\n"
            "template = Template(user_input)\n"
            "template.render()\n\n"
            "# GOOD — use safe template with sandboxed env\n"
            "from jinja2.sandbox import SandboxedEnvironment\n"
            "env = SandboxedEnvironment()\n"
            "template = env.from_string(safe_template_string)\n"
            "template.render(data=user_data)"
        ),
    },
}


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

class TechnicalDetailTemplate:
    """Generate technical assessment reports with full detail."""

    def generate(
        self,
        findings: list[dict[str, Any]],
        *,
        target: str = "",
        tools_used: list[str] | None = None,
    ) -> TechnicalReport:
        """Build a TechnicalReport from raw finding dicts."""
        tech_findings: list[TechnicalFinding] = []

        for f in findings:
            vuln_type = f.get("vuln_type", f.get("vulnerability_type", "unknown"))
            _norm_vt = _VULN_TYPE_ALIASES.get(vuln_type, vuln_type)
            remediation = REMEDIATION_DB.get(_norm_vt, {})

            steps = []
            for idx, s in enumerate(f.get("reproduction_steps", []), 1):
                if isinstance(s, str):
                    steps.append(ReproductionStep(step_number=idx, description=s))
                elif isinstance(s, dict):
                    steps.append(ReproductionStep(step_number=idx, **s))

            traces = []
            for t in f.get("http_traces", []):
                traces.append(HttpTrace(**t) if isinstance(t, dict) else t)

            tech_findings.append(TechnicalFinding(
                title=f.get("title", "Unnamed"),
                vuln_type=vuln_type,
                severity=f.get("severity", "info"),
                cvss_score=f.get("cvss_score", 0.0),
                cvss_vector=f.get("cvss_vector", ""),
                cwe_id=f.get("cwe_id", ""),
                target_url=f.get("url", f.get("target", "")),
                affected_parameter=f.get("parameter", ""),
                payload=f.get("payload", ""),
                technical_description=f.get("description", ""),
                root_cause=f.get("root_cause", ""),
                reproduction_steps=steps,
                http_traces=traces,
                poc_code=f.get("poc_code", ""),
                screenshots=f.get("screenshots", []),
                impact_analysis=f.get("impact_analysis", f.get("business_impact", "")),
                remediation=remediation.get("description", f.get("remediation", "")),
                remediation_code=remediation.get("code", ""),
                references=f.get("references", []),
                confidence=f.get("confidence_score", f.get("confidence", 0.0)),
                tools_used=f.get("tools_used", []),
            ))

        report = TechnicalReport(
            target=target,
            assessment_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            findings=tech_findings,
            methodology=(
                "Black-box security assessment combining automated vulnerability scanning, "
                "intelligent fuzzing, manual verification, and AI-assisted analysis with "
                "multi-layer false positive elimination."
            ),
            tools_employed=tools_used or [],
        )

        logger.info(f"Technical report: {len(tech_findings)} findings for {target}")
        return report

    def render_markdown(self, report: TechnicalReport) -> str:
        """Render the full technical report as Markdown."""
        lines = [
            f"# {report.title}",
            "",
            f"**Target:** {report.target}",
            f"**Date:** {report.assessment_date}",
            f"**Tools:** {', '.join(report.tools_employed) or 'N/A'}",
            "",
            "---",
            "",
            "## Methodology",
            "",
            report.methodology,
            "",
            "---",
            "",
        ]

        for idx, f in enumerate(report.findings, 1):
            lines.extend([
                f"## Finding {idx}: {f.title}",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Severity | **{f.severity.upper()}** |",
                f"| CVSS | {f.cvss_score} |",
                f"| CVSS Vector | `{f.cvss_vector}` |" if f.cvss_vector else "",
                f"| CWE | {f.cwe_id} |" if f.cwe_id else "",
                f"| URL | `{f.target_url}` |",
                f"| Parameter | `{f.affected_parameter}` |" if f.affected_parameter else "",
                f"| Confidence | {f.confidence}% |",
                "",
            ])

            if f.technical_description:
                lines.extend(["### Description", "", f.technical_description, ""])

            if f.root_cause:
                lines.extend(["### Root Cause", "", f.root_cause, ""])

            if f.reproduction_steps:
                lines.extend(["### Reproduction Steps", ""])
                for step in f.reproduction_steps:
                    lines.append(f"{step.step_number}. {step.description}")
                    if step.command:
                        lines.extend(["   ```bash", f"   {step.command}", "   ```"])
                    if step.expected_result:
                        lines.append(f"   **Expected:** {step.expected_result}")
                lines.append("")

            if f.payload:
                lines.extend([
                    "### Payload",
                    "```",
                    f"{f.payload}",
                    "```",
                    "",
                ])

            if f.http_traces:
                lines.extend(["### HTTP Evidence", ""])
                for tidx, trace in enumerate(f.http_traces, 1):
                    lines.extend([
                        f"**Request {tidx}:**",
                        "```http",
                        f"{trace.request_method} {trace.request_url}",
                    ])
                    for hk, hv in trace.request_headers.items():
                        lines.append(f"{hk}: {hv}")
                    if trace.request_body:
                        lines.extend(["", trace.request_body])
                    lines.extend(["```", ""])

                    lines.extend([
                        f"**Response {tidx}:**",
                        "```http",
                        f"HTTP/1.1 {trace.response_status}",
                    ])
                    for hk, hv in trace.response_headers.items():
                        lines.append(f"{hk}: {hv}")
                    if trace.response_body_excerpt:
                        lines.extend(["", trace.response_body_excerpt])
                    lines.extend(["```", ""])

            if f.poc_code:
                lines.extend([
                    "### Proof of Concept",
                    "```python",
                    f.poc_code,
                    "```",
                    "",
                ])

            if f.impact_analysis:
                lines.extend(["### Impact Analysis", "", f.impact_analysis, ""])

            if f.remediation:
                lines.extend(["### Remediation", "", f.remediation, ""])
                if f.remediation_code:
                    lines.extend(["```", f.remediation_code, "```", ""])

            if f.references:
                lines.extend(["### References", ""])
                for ref in f.references:
                    lines.append(f"- {ref}")
                lines.append("")

            lines.extend(["---", ""])

        lines.append(f"*Generated: {report.generated_at}*")
        # Filter out empty strings from conditional fields
        return "\n".join(line for line in lines if line is not None)
