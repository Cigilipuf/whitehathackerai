"""
WhiteHatHacker AI — Triage & Routing Prompts

Hızlı triage, önceliklendirme ve görev yönlendirme için brain
modeline verilecek promptlar.
Secondary Brain (BaronLLM v2 /no_think) tarafından kullanılır — hızlı karar.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# System Prompts
# ============================================================

TRIAGE_SYSTEM_PROMPT = """\
You are a fast triage specialist for a bug bounty hunting bot.
Your job: make quick, accurate decisions about what to do next.

RULES:
- Speed over perfection — make quick decisions
- Prioritize by potential impact and likelihood
- Route to the right tools and brain model
- Skip obviously low-value targets
- Always return structured JSON responses
"""

TOOL_SELECTION_SYSTEM = """\
You are selecting the optimal security tools for a given task.
Consider: target type, technology stack, available tools, scan
profile (stealth/balanced/aggressive), and previous results.
Choose the minimum set of tools needed for thorough coverage.
"""

PRIORITY_SYSTEM = """\
You are a priority assessment engine. Score every finding and
task by urgency and potential reward. Consider both technical
risk and bug bounty payout potential.
"""


# ============================================================
# Task Prompt Builders
# ============================================================

def build_triage_finding_prompt(
    vuln_type: str,
    severity_hint: str,
    target: str,
    tool_name: str,
    raw_output: str = "",
    confidence: int = 50,
) -> str:
    """Bir bulguyu hızlıca triage et."""
    output_preview = raw_output[:1500] if raw_output else "N/A"

    return f"""\
## Task: Quick Triage

Quickly assess this finding and decide what to do with it.

### Finding
- **Type:** {vuln_type}
- **Target:** {target}
- **Detected By:** {tool_name}
- **Tool Confidence:** {confidence}%
- **Severity Hint:** {severity_hint}

### Raw Tool Output
```
{output_preview}
```

### Decision Required
```json
{{
  "action": "verify|report|skip|investigate_deeper",
  "priority": 1-10,
  "confidence_adjustment": -20 to +20,
  "reason": "brief reason for decision",
  "next_tool": "tool to use for verification (if verify)",
  "estimated_severity": "critical|high|medium|low|info",
  "false_positive_risk": "low|medium|high",
  "time_investment": "minutes estimated"
}}
```

### Calibration Examples

**Example 1 (VERIFY):**
Finding: SQLi boolean-based blind in `id=` param, detected by sqlmap, confidence 70%.
→ {{"action": "verify", "priority": 8, "confidence_adjustment": 0, "reason": "Boolean-based blind SQLi needs time-based confirmation to rule out WAF interference", "next_tool": "nuclei_sqli", "estimated_severity": "high", "false_positive_risk": "medium", "time_investment": "5"}}

**Example 2 (SKIP):**
Finding: Missing X-Frame-Options header, detected by nikto, confidence 30%.
→ {{"action": "skip", "priority": 1, "confidence_adjustment": -15, "reason": "Missing security header is informational — not accepted by most bug bounty programs", "next_tool": "", "estimated_severity": "info", "false_positive_risk": "low", "time_investment": "0"}}
"""


def build_tool_selection_prompt(
    task_type: str,
    target: str,
    tech_stack: list[str] | None = None,
    available_tools: list[str] | None = None,
    scan_profile: str = "balanced",
    previous_results: list[str] | None = None,
) -> str:
    """Görev için optimal araç seçimi."""
    tech_text = ", ".join(tech_stack) if tech_stack else "unknown"
    tools_text = ", ".join(available_tools) if available_tools else "all available"
    prev_text = "\n".join(
        f"  - {r}" for r in (previous_results or [])[:10]
    )

    return f"""\
## Task: Select Optimal Tools

Choose the best tools for the given task and configuration.

### Task
- **Type:** {task_type}
- **Target:** {target}
- **Tech Stack:** {tech_text}
- **Scan Profile:** {scan_profile}

### Available Tools
{tools_text}

### Previous Results
{prev_text or "  No previous results"}

### Required JSON Response
```json
{{
  "primary_tools": [
    {{
      "tool": "tool_name",
      "reason": "why this tool",
      "priority": 1,
      "options": {{"key": "value"}},
      "expected_duration": "minutes"
    }}
  ],
  "secondary_tools": [
    {{
      "tool": "tool_name",
      "condition": "run if primary finds X",
      "reason": "verification / deeper analysis"
    }}
  ],
  "tool_order": ["tool1", "tool2", "tool3"],
  "parallel_safe": ["tools that can run simultaneously"],
  "estimated_total_time": "minutes",
  "coverage_note": "what's covered vs what's not"
}}
```
"""


def build_next_action_prompt(
    current_stage: str,
    findings_so_far: list[dict[str, Any]],
    completed_tools: list[str],
    remaining_tools: list[str],
    time_elapsed: str = "",
    scan_profile: str = "balanced",
    historical_learning: dict[str, Any] | None = None,
) -> str:
    """Sonraki adımı belirle."""
    findings_text = "\n".join(
        f"  - [{f.get('severity', '?')}] {f.get('type', '?')} "
        f"at {f.get('target', '?')}"
        for f in findings_so_far[:20]
    )
    learning = historical_learning or {}
    learning_text = "\n".join(
        line for line in [
            (
                f"- Recommended Tools: {', '.join(learning.get('recommended_tools', [])[:6])}"
                if learning.get("recommended_tools") else ""
            ),
            (
                f"- Common Vuln Types: {', '.join(learning.get('common_vuln_types', [])[:6])}"
                if learning.get("common_vuln_types") else ""
            ),
            (
                f"- Matched Historical Chains: {learning.get('matched_chains', 0)}"
                if learning.get("matched_chains") else ""
            ),
        ] if line
    )

    return f"""\
## Task: Decide Next Action

Based on current progress, decide what to do next.

### Current State
- **Stage:** {current_stage}
- **Profile:** {scan_profile}
- **Time Elapsed:** {time_elapsed or "unknown"}

### Findings ({len(findings_so_far)} total)
{findings_text or "  None yet"}

### Completed Tools
{", ".join(completed_tools) or "None"}

### Remaining Tools
{", ".join(remaining_tools) or "All done"}

### Historical Learning
{learning_text or "  No relevant historical learning"}

### Decision Required
```json
{{
  "action": "continue|skip_to_next_stage|deep_dive|deep_dive_tool|change_strategy|retry_with_auth|request_oob_check|pause|complete",
  "reason": "why this action",
  "next_tool": "specific tool to run next",
  "skip_tools": ["tools to skip and why"],
  "deep_dive_target": "if deep_dive, what endpoint/target to focus on",
  "deep_dive_tool": "if deep_dive_tool, specific tool to focus with (e.g. sqlmap, ssrfmap)",
  "change_strategy": "if change_strategy: stealth|balanced|aggressive",
  "retry_with_auth": false,
  "request_oob_check": false,
  "stage_transition": "if moving stages, which stage",
  "priority_findings": [
    "findings that need immediate attention"
  ],
  "time_estimate": "remaining time estimate"
}}
```

Action descriptions:
- **continue**: Proceed with the next remaining tool in order.
- **skip_to_next_stage**: Skip remaining tools and move to next pipeline stage.
- **deep_dive**: Focus scanning on a specific endpoint/target before continuing.
- **deep_dive_tool**: Run a specific tool on a specific target for deeper investigation.
- **change_strategy**: Switch scan profile (e.g. stealth→aggressive if no WAF detected).
- **retry_with_auth**: Re-run a skipped/failed tool with authentication headers injected.
- **request_oob_check**: Check Interactsh/OOB callbacks for blind vulnerability confirmation.
- **pause**: Pause scanning (human review needed).
- **complete**: Scanning is sufficient — proceed to reporting.
```

### Calibration Examples

**Example 1 (DEEP_DIVE):**
Stage: vulnerability_scan, 3 findings so far: [HIGH] SSRF at /api/proxy, [MEDIUM] CORS at /api/data, [INFO] tech-detect nginx. Completed: nuclei, nikto. Remaining: dalfox, sqlmap, corsy.
→ {{"action": "deep_dive", "reason": "SSRF at /api/proxy is high-value — cloud metadata may be accessible. Focus there before running remaining tools.", "next_tool": "ssrfmap", "skip_tools": ["corsy"], "deep_dive_target": "/api/proxy", "stage_transition": "", "priority_findings": ["SSRF at /api/proxy"], "time_estimate": "15 minutes"}}

**Example 2 (CONTINUE):**
Stage: vulnerability_scan, 0 findings. Completed: nuclei. Remaining: dalfox, sqlmap, nikto, commix.
→ {{"action": "continue", "reason": "No findings yet — continue systematic scanning with remaining tools. Too early to skip or dive deep.", "next_tool": "dalfox", "skip_tools": [], "deep_dive_target": "", "stage_transition": "", "priority_findings": [], "time_estimate": "25 minutes"}}
"""


def build_severity_triage_prompt(
    findings: list[dict[str, Any]],
) -> str:
    """Toplu bulgu önceliklendirme."""
    findings_text = "\n".join(
        f"  {i+1}. [{f.get('tool', '?')}] {f.get('type', '?')} — "
        f"{f.get('target', '?')} (raw severity: {f.get('severity', '?')})"
        for i, f in enumerate(findings[:30])
    )

    return f"""\
## Task: Batch Severity Assessment

Quickly assess and prioritize all findings by potential reward
and exploitability.

### Findings ({len(findings)} total)
{findings_text}

### Required JSON Response
```json
{{
  "prioritized": [
    {{
      "finding_index": 1,
      "severity": "critical|high|medium|low|info",
      "bounty_potential": "$$$$|$$$|$$|$|none",
      "exploitability": "easy|moderate|hard|unlikely",
      "false_positive_risk": "low|medium|high",
      "action": "verify_first|report_now|investigate|skip"
    }}
  ],
  "top_3_to_pursue": [1, 5, 3],
  "likely_fps": [2, 7],
  "needs_chaining": [4, 6],
  "quick_wins": [5]
}}
```
"""


def build_model_routing_prompt(
    task_description: str,
    task_complexity: str = "unknown",
    context_length_needed: int = 0,
    time_critical: bool = False,
) -> str:
    """Hangi beyin modelini kullanacağını belirle."""
    return f"""\
## Task: Brain Model Routing Decision

Decide which AI model should handle this task.

### Task
- **Description:** {task_description}
- **Estimated Complexity:** {task_complexity}
- **Context Length Needed:** ~{context_length_needed} tokens
- **Time Critical:** {time_critical}

### Available Models
1. **Primary (BaronLLM v2 /think):** Deep analysis, complex reasoning,
   report writing, FP elimination. Slower but more accurate.
   Context: 32,768 tokens.

2. **Secondary (BaronLLM v2 /no_think):** Fast triage, tool selection,
   quick decisions. Faster but less deep (no chain-of-thought).
   Context: 32,768 tokens.

3. **Both (Consensus):** Critical decisions requiring agreement
   from both models.

### Required JSON Response
```json
{{
  "selected_model": "primary|secondary|both",
  "reason": "why this model is best",
  "confidence": 0-100,
  "fallback_model": "if selected fails, use this",
  "context_warning": "if context might be too long for selected model"
}}
```
"""


def build_scan_profile_recommendation_prompt(
    target: str,
    target_type: str = "web_application",
    waf_detected: bool = False,
    rate_limit_detected: bool = False,
    program_rules: str = "",
) -> str:
    """Tarama profili önerisi."""
    return f"""\
## Task: Recommend Scan Profile

Recommend the optimal scan profile for the target.

### Target
- **URL/Host:** {target}
- **Type:** {target_type}
- **WAF Detected:** {waf_detected}
- **Rate Limiting:** {rate_limit_detected}
- **Program Rules:** {program_rules or "standard rules"}

### Available Profiles
1. **Stealth:** Very slow, low footprint, evades detection.
   Good for: strict rate limits, sensitive targets.
2. **Balanced:** Moderate speed, reasonable coverage.
   Good for: most targets, standard bug bounty programs.
3. **Aggressive:** Fast, comprehensive, high footprint.
   Good for: permissive programs, testing environments.

### Required JSON Response
```json
{{
  "recommended_profile": "stealth|balanced|aggressive",
  "reason": "why this profile",
  "custom_overrides": {{
    "max_requests_per_second": 5,
    "use_random_delays": true,
    "rotate_user_agents": true,
    "throttle_on_errors": true
  }},
  "warnings": ["any specific concerns"]
}}
```
"""


__all__ = [
    "TRIAGE_SYSTEM_PROMPT",
    "TOOL_SELECTION_SYSTEM",
    "PRIORITY_SYSTEM",
    "build_triage_finding_prompt",
    "build_tool_selection_prompt",
    "build_next_action_prompt",
    "build_severity_triage_prompt",
    "build_model_routing_prompt",
    "build_scan_profile_recommendation_prompt",
]
