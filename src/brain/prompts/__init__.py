"""WhiteHatHacker AI — Brain Prompts Module."""

# FP Elimination
from src.brain.prompts.fp_elimination import (
    build_fp_analysis_prompt,
    build_severity_assessment_prompt,
    build_fp_exploit_strategy_prompt,
)

# Recon
from src.brain.prompts.recon_prompts import (
    RECON_SYSTEM_PROMPT,
    PASSIVE_RECON_SYSTEM,
    ACTIVE_RECON_SYSTEM,
    build_scope_analysis_prompt,
    build_subdomain_analysis_prompt,
    build_port_scan_analysis_prompt,
    build_tech_detection_analysis_prompt,
    build_osint_analysis_prompt,
    build_web_crawl_analysis_prompt,
    build_recon_summary_prompt,
)

# Analysis
from src.brain.prompts.analysis_prompts import (
    ANALYSIS_SYSTEM_PROMPT,
    ATTACK_SURFACE_SYSTEM,
    CORRELATION_SYSTEM,
    build_vulnerability_analysis_prompt,
    build_attack_surface_analysis_prompt,
    build_finding_correlation_prompt,
    build_threat_model_prompt,
    build_impact_assessment_prompt,
)

# Exploit
from src.brain.prompts.exploit_prompts import (
    EXPLOIT_SYSTEM_PROMPT,
    build_exploit_strategy_prompt,  # Full multi-param version
    build_sqli_exploit_prompt,
    build_xss_exploit_prompt,
    build_ssrf_exploit_prompt,
    build_auth_bypass_exploit_prompt,
    build_poc_generation_prompt,
)

# Report
from src.brain.prompts.report_prompts import (
    REPORT_SYSTEM_PROMPT,
    build_report_title_prompt,
    build_report_summary_prompt,
    build_report_impact_prompt,
    build_report_reproduction_prompt,
    build_report_remediation_prompt,
    build_full_report_prompt,
    build_executive_summary_prompt,
)

# Triage
from src.brain.prompts.triage_prompts import (
    TRIAGE_SYSTEM_PROMPT,
    build_triage_finding_prompt,
    build_tool_selection_prompt,
    build_next_action_prompt,
    build_severity_triage_prompt,
    build_model_routing_prompt,
    build_scan_profile_recommendation_prompt,
)

# Agent Loop
from src.brain.prompts.agent_prompts import (
    AGENT_THINK_SYSTEM,
    AGENT_EVALUATE_SYSTEM,
    AGENT_STAGE_SYSTEM,
    AGENT_CHAIN_SYSTEM,
    build_agent_think_prompt,
    build_agent_evaluate_prompt,
    build_stage_selection_prompt,
    build_chain_attack_prompt,
)

__all__ = [
    # FP Elimination
    "build_fp_analysis_prompt",
    "build_severity_assessment_prompt",
    "build_fp_exploit_strategy_prompt",
    # Recon
    "RECON_SYSTEM_PROMPT",
    "PASSIVE_RECON_SYSTEM",
    "ACTIVE_RECON_SYSTEM",
    "build_scope_analysis_prompt",
    "build_subdomain_analysis_prompt",
    "build_port_scan_analysis_prompt",
    "build_tech_detection_analysis_prompt",
    "build_osint_analysis_prompt",
    "build_web_crawl_analysis_prompt",
    "build_recon_summary_prompt",
    # Analysis
    "ANALYSIS_SYSTEM_PROMPT",
    "ATTACK_SURFACE_SYSTEM",
    "CORRELATION_SYSTEM",
    "build_vulnerability_analysis_prompt",
    "build_attack_surface_analysis_prompt",
    "build_finding_correlation_prompt",
    "build_threat_model_prompt",
    "build_impact_assessment_prompt",
    # Exploit
    "EXPLOIT_SYSTEM_PROMPT",
    "build_sqli_exploit_prompt",
    "build_xss_exploit_prompt",
    "build_ssrf_exploit_prompt",
    "build_auth_bypass_exploit_prompt",
    "build_poc_generation_prompt",
    # Report
    "REPORT_SYSTEM_PROMPT",
    "build_report_title_prompt",
    "build_report_summary_prompt",
    "build_report_impact_prompt",
    "build_report_reproduction_prompt",
    "build_report_remediation_prompt",
    "build_full_report_prompt",
    "build_executive_summary_prompt",
    # Triage
    "TRIAGE_SYSTEM_PROMPT",
    "build_triage_finding_prompt",
    "build_tool_selection_prompt",
    "build_next_action_prompt",
    "build_severity_triage_prompt",
    "build_model_routing_prompt",
    "build_scan_profile_recommendation_prompt",
    # Agent Loop
    "AGENT_THINK_SYSTEM",
    "AGENT_EVALUATE_SYSTEM",
    "AGENT_STAGE_SYSTEM",
    "AGENT_CHAIN_SYSTEM",
    "build_agent_think_prompt",
    "build_agent_evaluate_prompt",
    "build_stage_selection_prompt",
    "build_chain_attack_prompt",
]
