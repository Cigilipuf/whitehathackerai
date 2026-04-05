"""
WhiteHatHacker AI — Agentic Loop Prompts

Decision-making prompts for the ReAct agent loop.
Primary Brain (BaronLLM v2 /think) drives THINK and EVALUATE steps.

These prompts power the autonomous agent's core decision cycle:

    OBSERVE → THINK → ACT → EVALUATE → DECIDE

Each builder consumes an ``AgentContext`` (the per-iteration snapshot)
and/or a ``ToolUnitResult`` and returns a compact prompt string that
fits within ~10K tokens (working memory ~6K + structure ~3K + examples ~1K).

Usage::

    from src.brain.prompts.agent_prompts import (
        AGENT_THINK_SYSTEM,
        build_agent_think_prompt,
    )

    system = AGENT_THINK_SYSTEM
    user   = build_agent_think_prompt(ctx)
    response = await brain.call(system_prompt=system, user_prompt=user)
"""

from __future__ import annotations

from typing import Any

from src.workflow.agent_context import AgentAction, AgentContext
from src.workflow.tool_unit import ToolUnitResult


# ============================================================
# System Prompts
# ============================================================

AGENT_THINK_SYSTEM = """\
You are BaronLLM, an elite autonomous bug bounty hunter agent.

You operate in a ReAct loop: OBSERVE → THINK → ACT → EVALUATE.
Right now you are in the THINK step — decide what to do next.

RULES:
- NEVER test out-of-scope targets
- Minimize redundant tool executions — don't re-run completed units
- Prioritize high-impact findings over breadth
- Adapt strategy to WAF/CDN/rate-limit signals
- Use backward stage transitions sparingly (max 2 total across the scan)
- Time is limited — balance thoroughness with efficiency
- You MUST return ONLY valid JSON. No markdown, no explanation outside JSON.
  Start with { and end with }. Parseable by json.loads().
"""

AGENT_EVALUATE_SYSTEM = """\
You are BaronLLM, analyzing the results of a security tool execution.

Your job: extract meaning from tool output. What did we learn?
Which hypotheses are confirmed or refuted? Are there attack chain
opportunities? What should we do next?

RULES:
- Be specific — reference actual findings, endpoints, parameters
- Update hypotheses based on evidence, not guesses
- Identify chain opportunities between findings
- Recommend concrete next actions
- You MUST return ONLY valid JSON. Start with { and end with }.
"""

AGENT_STAGE_SYSTEM = """\
You are deciding whether to move to the next scan stage, go back
to a previous stage, or skip ahead. Base your decision on:
coverage completeness, finding quality, and time budget.

You MUST return ONLY valid JSON. Start with { and end with }.
"""

AGENT_CHAIN_SYSTEM = """\
You are an expert vulnerability chainer. Analyze findings to
discover attack chains where combining vulnerabilities amplifies
impact beyond individual severity ratings.

You MUST return ONLY valid JSON. Start with { and end with }.
"""


# ============================================================
# Shared Action Reference (included in THINK prompt)
# ============================================================

_ACTION_REFERENCE = """\

### Action Reference
- `execute_unit`: Run a single tool unit. Set `unit_id`.
- `execute_parallel`: Run multiple independent units concurrently. Set `unit_ids`.
- `go_back_stage`: Return to a previous scan stage. Set `target_stage`. Max 2 total.
- `skip_to_stage`: Jump forward to a later stage. Set `target_stage`.
- `deep_dive`: Focused testing on a specific endpoint/parameter. Set `deep_dive_target`.
- `chain_attack`: Exploit connections between findings. Set `chain_findings`.
- `change_strategy`: Switch scan mode. Set `strategy` to stealth|balanced|aggressive.
- `add_hypothesis`: Register new test hypotheses. Set `hypotheses` list.
- `retry_with_auth`: Re-test with authentication headers injected.
- `request_oob`: Deploy Interactsh OOB callback for blind vuln detection.
- `pause`: Request operator input (semi-autonomous mode only).
- `complete`: Finish the scan — all worthwhile testing is done."""


# ============================================================
# Prompt Builders
# ============================================================

def build_agent_think_prompt(context: AgentContext) -> str:
    """
    Build the THINK step prompt.

    The brain sees the full scan context and must decide the single
    best next action from the allowed action set.

    Token budget breakdown:
      - working_memory.to_context() ≈ 6 000 tokens
      - prompt structure + units   ≈ 2 000 tokens
      - calibration examples       ≈ 1 000 tokens
      ─────────────────────────────────────────
      Total ≈ 9 000 tokens  (well within 32K context)

    Args:
        context: The per-iteration AgentContext snapshot.

    Returns:
        Prompt string ready for the brain.
    """
    memory_ctx = context.working_memory.to_context()

    return f"""\
## Current Scan State

{memory_ctx}

## Progress
{context.progress_summary()}

## Current Stage: {context.current_stage}
Stage History: {" → ".join(context.stage_history) if context.stage_history else "scan just started"}
Backward Transitions Used: {context.total_backward_count}/2

## Available Tool Units
{context.units_for_prompt()}

## Completed Units
{context.completed_for_prompt()}

## Allowed Actions
{context.available_actions_for_prompt()}
{_ACTION_REFERENCE}

## Your Task
Analyze the current state and decide the SINGLE best next action.
Consider: What has been done? What's left? What signals (WAF, findings,
time) suggest the optimal path? Are there hypotheses to test?

### Required JSON Response
```json
{{{{
  "action": "one of the allowed actions above",
  "unit_id": "tool_unit_id (for execute_unit)",
  "unit_ids": ["id1", "id2"],
  "target_stage": "stage name (for go_back_stage / skip_to_stage)",
  "reason": "brief reasoning for this decision",
  "hypotheses": [{{"text": "hypothesis", "priority": 0.0-1.0}}],
  "strategy": "stealth|balanced|aggressive (for change_strategy)",
  "deep_dive_target": "URL or endpoint (for deep_dive)",
  "deep_dive_tool": "specific tool name (for deep_dive)",
  "chain_findings": ["finding_ids (for chain_attack)"],
  "confidence": 0.0-1.0
}}}}
```
Only include fields relevant to your chosen action.
`action`, `reason`, and `confidence` are always required.

### Calibration Examples

**Example 1 — Execute a tool unit:**
Situation: Enumeration stage. 12 live hosts found. WAF: Cloudflare.
No endpoints discovered yet. katana_crawl is available.
→ {{{{"action": "execute_unit", "unit_id": "katana_crawl", "reason": "Need endpoint discovery on 12 live hosts. Katana's headless crawling handles JS-heavy sites behind Cloudflare better than basic spiders.", "confidence": 0.85}}}}

**Example 2 — Go back to a previous stage:**
Situation: Vulnerability scan stage. JS analyzer found 3 new subdomains
(api-v2.target.com, staging.target.com) not in initial recon.
Backward transitions: 0/2.
→ {{{{"action": "go_back_stage", "target_stage": "active_recon", "reason": "JS analysis discovered 3 unprobed subdomains that significantly expand the attack surface. Must fingerprint and enumerate before continuing vulnerability testing.", "confidence": 0.9}}}}

**Example 3 — Complete the scan:**
Situation: 78% time budget used. All HIGH-priority units completed.
0 medium+ findings after 42 tool executions. Stage: vulnerability_scan.
→ {{{{"action": "complete", "reason": "All high-priority tools executed across all stages with zero actionable findings. 78% time spent. Diminishing returns from remaining low-priority units do not justify additional time investment.", "confidence": 0.8}}}}"""


def build_agent_evaluate_prompt(
    result: ToolUnitResult,
    context: AgentContext,
) -> str:
    """
    Build the EVALUATE step prompt.

    After a tool executes, the brain analyzes results: what did we
    learn, which hypotheses changed, are there chain opportunities?

    Args:
        result: The ToolUnitResult from the just-executed unit.
        context: Current AgentContext.

    Returns:
        Prompt string ready for the brain.
    """
    # Compact findings summary from the tool result
    findings_text = "None."
    if result.findings:
        lines: list[str] = []
        for i, f in enumerate(result.findings[:10], 1):
            sev = f.get("severity", "?")
            vuln = f.get("vulnerability_type", f.get("type", "?"))
            url = f.get("url", f.get("endpoint", "?"))
            conf = f.get("confidence", f.get("confidence_score", "?"))
            lines.append(f"  {i}. [{sev}] {vuln} at {url} (conf={conf})")
        findings_text = "\n".join(lines)
        if len(result.findings) > 10:
            findings_text += f"\n  ... (+{len(result.findings) - 10} more)"

    # Context updates from the tool
    updates_text = "None."
    if result.context_updates:
        updates_lines: list[str] = []
        for k, v in result.context_updates.items():
            if isinstance(v, list):
                updates_lines.append(f"  - {k}: {len(v)} items")
            else:
                updates_lines.append(f"  - {k}: {v}")
        updates_text = "\n".join(updates_lines)

    # Active hypotheses for cross-referencing
    hyp_text = "None."
    active_hyps = context.working_memory.get_active_hypotheses()
    if active_hyps:
        hyp_lines: list[str] = []
        for h in active_hyps[:8]:
            hyp_lines.append(
                f"  - [{h.h_id[:8]}] {h.text} (p={h.priority:.1f})"
            )
        hyp_text = "\n".join(hyp_lines)

    # Errors as text
    errors_text = "None."
    if result.errors:
        errors_text = "\n".join(f"  - {e}" for e in result.errors[:5])

    return f"""\
## Tool Execution Result

- **Unit:** {result.unit_id}
- **Success:** {result.success}
- **Duration:** {result.duration:.1f}s
- **Finding Count:** {result.finding_count}
- **Tools Run:** {", ".join(result.tools_run) if result.tools_run else "N/A"}

### Observations
{result.observations or "No observations recorded."}

### Findings
{findings_text}

### Context Updates
{updates_text}

### Errors
{errors_text}

## Active Hypotheses
{hyp_text}

## Overall Progress
{context.progress_summary()}

## Your Task
Analyze this tool result and determine:
1. What did we learn? Summarize the key insight.
2. Which active hypotheses are confirmed or refuted by this evidence?
3. Are there NEW hypotheses suggested by these results?
4. Do any findings create CHAIN opportunities with previous findings?
5. What should we do next?

### Required JSON Response
```json
{{{{
  "analysis": "concise analysis of what this result means",
  "new_hypotheses": [
    {{"text": "hypothesis text", "priority": 0.0-1.0}}
  ],
  "confirmed_hypotheses": ["h_id1"],
  "refuted_hypotheses": ["h_id2"],
  "confidence_adjustments": {{"finding_url": 0.1}},
  "chain_opportunities": [
    {{
      "findings": ["finding1_url", "finding2_url"],
      "type": "chain description",
      "next_step": "what to do to exploit the chain"
    }}
  ],
  "recommended_next": "hint for what to do next",
  "stage_complete": false,
  "new_targets": ["newly_discovered_url1"]
}}}}
```

### Calibration Examples

**Example 1 — Significant findings:**
Unit: nuclei_fast. Success: true. Findings: 3 (1×HIGH, 2×MEDIUM).
Observations: "Found .env exposure at staging.target.com/.env (AWS keys visible).
CORS wildcard on api.target.com. Git directory exposed at staging.target.com/.git/"
→ {{{{"analysis": ".env exposure on staging reveals AWS credentials — CRITICAL escalation path. CORS wildcard allows cross-origin reads. Git exposure may leak source code with additional secrets.", "new_hypotheses": [{{"text": "Staging environment has weaker security controls than production", "priority": 0.9}}, {{"text": "AWS credentials from .env may grant S3/IAM access", "priority": 0.85}}], "confirmed_hypotheses": [], "refuted_hypotheses": [], "confidence_adjustments": {{}}, "chain_opportunities": [{{"findings": ["env-exposure-staging", "cors-wildcard-api"], "type": "info_leak + CORS = credential theft from cross-origin", "next_step": "Verify CORS Access-Control-Allow-Credentials header; craft PoC"}}], "recommended_next": "deep_dive on staging.target.com", "stage_complete": false, "new_targets": ["staging.target.com/.env", "staging.target.com/.git/"]}}}}

**Example 2 — No findings:**
Unit: sqlmap_injection. Success: true. Findings: 0. Duration: 180s.
Observations: "Tested 15 parameterized endpoints. All returned WAF 403
or used parameterized queries. No injection points found."
→ {{{{"analysis": "No SQL injection found. Consistent 403 pattern suggests WAF intervention rather than secure code, but no bypass found. Application may also use ORM/prepared statements.", "new_hypotheses": [{{"text": "Application uses ORM — try NoSQL injection or SSTI instead", "priority": 0.6}}], "confirmed_hypotheses": [], "refuted_hypotheses": ["h-sqli-likely"], "confidence_adjustments": {{}}, "chain_opportunities": [], "recommended_next": "Try nosql_injection or tplmap_ssti units", "stage_complete": false, "new_targets": []}}}}"""


def build_stage_selection_prompt(context: AgentContext) -> str:
    """
    Build the stage transition decision prompt.

    Called when the agent believes the current stage may be complete
    and needs guidance on where to go next.

    Args:
        context: Current AgentContext.

    Returns:
        Prompt string.
    """
    # Remaining units in current stage
    current_stage_units = [
        u for u in context.available_units
        if u.stage == context.current_stage
    ]
    remaining_current = (
        ", ".join(u.unit_id for u in current_stage_units[:10])
        or "none"
    )

    # Stage-level unit counts overview
    stage_unit_counts: dict[str, int] = {}
    for u in context.available_units:
        stage_unit_counts[u.stage] = stage_unit_counts.get(u.stage, 0) + 1

    stage_overview_lines: list[str] = []
    for s, c in sorted(stage_unit_counts.items()):
        marker = " ← CURRENT" if s == context.current_stage else ""
        stage_overview_lines.append(f"  - {s}: {c} units available{marker}")
    stage_overview = (
        "\n".join(stage_overview_lines)
        if stage_overview_lines
        else "  No units available in any stage."
    )

    findings = context.working_memory.findings_summary

    return f"""\
## Stage Transition Decision

### Current State
- **Current Stage:** {context.current_stage}
- **Stage History:** {" → ".join(context.stage_history) if context.stage_history else "just started"}
- **Backward Transitions Used:** {context.total_backward_count}/2
- **Remaining Units (current stage):** {remaining_current}

### Stage Overview (units available)
{stage_overview}

### Findings Summary
{findings.to_compact()}

### Time Budget
{context.working_memory.time_budget.to_compact()}

### Progress
{context.progress_summary()}

## Your Task
Decide the next stage transition. Options:
1. **Stay** — continue with current stage (remaining units exist)
2. **Advance** — move to the natural next stage
3. **Skip** — jump forward past one or more stages
4. **Backward** — return to a previous stage (ONLY if new intelligence
   justifies it AND backward count < 2)

### Required JSON Response
```json
{{{{
  "next_stage": "stage_name or 'stay'",
  "reason": "why this transition",
  "skip_stages": ["stages to skip if skipping ahead"],
  "backward_reason": "detailed justification if going backward, null otherwise"
}}}}
```

### Calibration Examples

**Example 1 — Advance forward:**
Current: enumeration. All enumeration units completed. 52 endpoints
mapped, 8 with parameters. Tech: React, Express, PostgreSQL.
→ {{{{"next_stage": "attack_surface_map", "reason": "Enumeration complete — 52 endpoints mapped with full tech stack identified. Ready for attack surface analysis and vulnerability testing.", "skip_stages": [], "backward_reason": null}}}}

**Example 2 — Go backward:**
Current: vulnerability_scan. JS analysis found 2 new subdomains.
Backward transitions: 0/2.
→ {{{{"next_stage": "active_recon", "reason": "2 new subdomains discovered during vuln scan that expand attack surface. Must probe and fingerprint before continuing.", "skip_stages": [], "backward_reason": "api-v2.target.com and internal.target.com found in JS bundles — these high-value subdomains host separate API services missed in initial recon."}}}}

**Example 3 — Stay in current stage:**
Current: vulnerability_scan. 5 units remaining (sqlmap, tplmap,
jwt_check, etc). Only 40% time used.
→ {{{{"next_stage": "stay", "reason": "5 high-value vulnerability units remain untested with 60% time budget available. Continue current stage.", "skip_stages": [], "backward_reason": null}}}}"""


def build_chain_attack_prompt(
    findings: list[dict[str, Any]],
    context: AgentContext,
) -> str:
    """
    Build the attack chain analysis prompt.

    Examines multiple findings to discover chains where combined
    exploitation amplifies impact beyond individual severities.

    Args:
        findings: List of finding dicts to analyze for chains.
        context: Current AgentContext.

    Returns:
        Prompt string.
    """
    # Render findings compactly
    findings_lines: list[str] = []
    for i, f in enumerate(findings[:20], 1):
        sev = f.get("severity", "?")
        vuln = f.get("vulnerability_type", f.get("type", "unknown"))
        url = f.get("url", f.get("endpoint", "?"))
        param = f.get("parameter", "")
        conf = f.get("confidence", f.get("confidence_score", "?"))
        evidence = str(f.get("evidence", ""))[:100]
        line = f"  {i}. [{sev}] {vuln} at {url}"
        if param:
            line += f" (param={param})"
        line += f" conf={conf}"
        if evidence:
            line += f"\n     Evidence: {evidence}"
        findings_lines.append(line)

    findings_text = (
        "\n".join(findings_lines) if findings_lines else "  No findings."
    )

    tech_stack = context.working_memory.target_profile.technology_stack

    return f"""\
## Attack Chain Analysis

### Findings to Analyze ({len(findings)} total)
{findings_text}

### Technology Stack
{", ".join(tech_stack) if tech_stack else "unknown"}

### Target
{context.target}

## Your Task
Analyze the findings above for attack chain potential:
1. Which findings can be COMBINED for amplified impact?
2. What is the chain type (e.g., SSRF→metadata→IAM, XSS+CORS→session_hijack)?
3. How much does chaining boost the severity?
4. What is the next concrete step to exploit the chain?

Only report chains where combined impact is genuinely greater than
individual findings. Do not force chains that don't exist.

### Required JSON Response
```json
{{{{
  "chains": [
    {{
      "findings": ["finding1_description", "finding2_description"],
      "chain_type": "human-readable chain label",
      "individual_severity": "highest individual severity",
      "chained_severity": "combined severity with chain",
      "severity_boost": "e.g., HIGH → CRITICAL",
      "exploitation_narrative": "step-by-step how the chain works",
      "next_step": "immediate action to validate the chain"
    }}
  ],
  "no_chains_reason": "if no chains found, explain why"
}}}}
```

### Calibration Examples

**Example 1 — SSRF + Cloud:**
Findings: SSRF via /api/fetch?url=, exposed .env with AWS_REGION=us-east-1.
→ {{{{"chains": [{{"findings": ["SSRF at /api/fetch?url=", ".env exposure with AWS credentials"], "chain_type": "SSRF → Cloud Metadata → IAM Credential Theft", "individual_severity": "HIGH", "chained_severity": "CRITICAL", "severity_boost": "HIGH → CRITICAL", "exploitation_narrative": "1. Use SSRF to access http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2. Extract IAM temp credentials 3. .env confirms AWS deployment, validating metadata endpoint", "next_step": "Send SSRF request to cloud metadata endpoint via /api/fetch?url=http://169.254.169.254/latest/meta-data/"}}], "no_chains_reason": null}}}}

**Example 2 — XSS + CORS:**
Findings: Reflected XSS at /search?q=, CORS misconfiguration with ACAC:true.
→ {{{{"chains": [{{"findings": ["Reflected XSS at /search?q=", "CORS misconfig with ACAC:true"], "chain_type": "XSS + CORS = Cross-Origin Session Hijack", "individual_severity": "MEDIUM", "chained_severity": "HIGH", "severity_boost": "MEDIUM → HIGH", "exploitation_narrative": "1. Host XSS payload on *.target.com subdomain 2. XSS triggers cross-origin fetch to API 3. CORS ACAC:true sends cookies 4. Extract authenticated API responses", "next_step": "Verify CORS reflects origin with credentials flag, then craft PoC HTML page"}}], "no_chains_reason": null}}}}

**Example 3 — No chains exist:**
Findings: Missing X-Frame-Options (INFO), Missing HSTS (INFO), Server banner (INFO).
→ {{{{"chains": [], "no_chains_reason": "All findings are informational header issues. No exploitable chain potential — these are defense-in-depth recommendations, not vulnerabilities that amplify each other."}}}}"""


__all__ = [
    "AGENT_THINK_SYSTEM",
    "AGENT_EVALUATE_SYSTEM",
    "AGENT_STAGE_SYSTEM",
    "AGENT_CHAIN_SYSTEM",
    "build_agent_think_prompt",
    "build_agent_evaluate_prompt",
    "build_stage_selection_prompt",
    "build_chain_attack_prompt",
]
