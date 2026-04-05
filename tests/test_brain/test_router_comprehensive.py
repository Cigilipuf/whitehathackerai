"""Comprehensive tests for BrainRouter — task→model routing logic.

Covers: all DEFAULT_ROUTING_RULES, priority ordering, override, history,
custom rules, empty/None task_type edge cases.
"""

from __future__ import annotations

import pytest

from src.brain.router import BrainRouter, RoutingRule, DEFAULT_ROUTING_RULES
from src.utils.constants import BrainType


# ── Parametrized: every known task_type used in _brain_call() ───────

class TestRouterKnownTaskTypes:
    """Verify the 7 task_type strings used by IntelligenceEngine."""

    @pytest.mark.parametrize("task_type, expected_brain", [
        # strategy → no rule matches "strategy" → default (SECONDARY)
        ("strategy", BrainType.SECONDARY),
        # analyze → matches "analyze_vuln|deep_analysis|vulnerability_analysis"? No.
        # "analyze" alone doesn't match any rule → SECONDARY (default)
        ("analyze", BrainType.SECONDARY),
        # triage → matches r"triage|quick_assess|..." → SECONDARY
        ("triage", BrainType.SECONDARY),
        # tool_select → matches r"tool_select|tool_config|..." → SECONDARY
        ("tool_select", BrainType.SECONDARY),
        # fp_check → matches r"fp_check|fp_eliminate|..." → PRIMARY (priority 25)
        ("fp_check", BrainType.PRIMARY),
        # exploit → "exploit_strategy|attack_plan|exploitation" uses | alternation,
        # but re.search("exploit_strategy|attack_plan|exploitation", "exploit") checks
        # each branch: "exploit" is NOT in any branch → SECONDARY (default)
        ("exploit", BrainType.SECONDARY),
        # report → same: "report_write|generate_report|write_report" branches don't
        # contain bare "report" → SECONDARY (default)
        ("report", BrainType.SECONDARY),
    ])
    def test_pipeline_task_type_routing(self, task_type: str, expected_brain: BrainType):
        router = BrainRouter()
        result = router.route(task_type)
        assert result == expected_brain, (
            f"task_type={task_type!r} routed to {result}, expected {expected_brain}"
        )


class TestRouterSecondaryRules:
    """Verify all SECONDARY pattern matches."""

    @pytest.mark.parametrize("task_type", [
        "recon", "discover", "enumerate_subdomain", "dns_lookup",
        "tool_select", "tool_config", "scan_config", "parameter",
        "triage", "quick_assess", "categorize", "prioritize_targets",
        "scope_check", "scope_analysis", "validate_scope",
        "parse_output", "aggregate_results", "merge_findings",
    ])
    def test_secondary_routing(self, task_type: str):
        router = BrainRouter()
        assert router.route(task_type) == BrainType.SECONDARY


class TestRouterPrimaryRules:
    """Verify all PRIMARY pattern matches."""

    @pytest.mark.parametrize("task_type", [
        "analyze_vuln", "deep_analysis", "vulnerability_analysis",
        "exploit_strategy", "attack_plan", "exploitation",
        "fp_check", "fp_eliminate", "false_positive", "verify_finding",
        "report_write", "generate_report", "write_report",
        "business_logic", "idor_analysis", "auth_bypass_analysis",
        "chain_of_thought", "complex_reason", "risk_assess",
        "threat_model", "attack_surface_analysis", "impact_assess",
        "severity_calculate", "cvss_score", "impact_rating",
    ])
    def test_primary_routing(self, task_type: str):
        router = BrainRouter()
        assert router.route(task_type) == BrainType.PRIMARY


class TestRouterBothRules:
    """Verify BOTH (ensemble) pattern matches."""

    @pytest.mark.parametrize("task_type", [
        "critical_decision", "final_verify", "submit_decision",
        "high_confidence_check", "ensemble_verify",
    ])
    def test_both_routing(self, task_type: str):
        router = BrainRouter()
        assert router.route(task_type) == BrainType.BOTH


class TestRouterPriorityOrdering:
    """Priority 30 (BOTH) beats priority 25 (PRIMARY) beats priority 10 (SECONDARY)."""

    def test_high_priority_wins_over_lower(self):
        """If a task matches both a p=10 and p=25 rule, p=25 wins."""
        # fp_check matches PRIMARY at p=25; also matches nothing in SECONDARY
        router = BrainRouter()
        assert router.route("fp_check") == BrainType.PRIMARY

    def test_both_priority_wins(self):
        """BOTH rules at priority 30 should be checked first."""
        router = BrainRouter()
        # critical_decision matches BOTH at p=30
        assert router.route("critical_decision") == BrainType.BOTH

    def test_rules_sorted_by_priority_descending(self):
        """Rules are stored in descending priority order."""
        router = BrainRouter()
        priorities = [r.priority for r in router.rules]
        assert priorities == sorted(priorities, reverse=True)


class TestRouterDefaultFallback:
    """Unknown task types should return the default brain."""

    @pytest.mark.parametrize("task_type", [
        "unknown_xyz", "random_task", "", "123",
        "this_matches_nothing_at_all", "strategy",
    ])
    def test_default_fallback(self, task_type: str):
        router = BrainRouter()
        result = router.route(task_type)
        assert result == router.default_brain

    def test_custom_default_brain(self):
        router = BrainRouter(default_brain=BrainType.PRIMARY)
        assert router.route("unknown_gibberish") == BrainType.PRIMARY


class TestRouterOverride:
    """route_with_override should bypass rules."""

    def test_override_bypasses_rules(self):
        router = BrainRouter()
        # fp_check normally goes to PRIMARY, but override forces SECONDARY
        result = router.route_with_override("fp_check", override=BrainType.SECONDARY)
        assert result == BrainType.SECONDARY

    def test_override_none_falls_through_to_rules(self):
        router = BrainRouter()
        result = router.route_with_override("fp_check", override=None)
        assert result == BrainType.PRIMARY

    def test_override_with_both(self):
        router = BrainRouter()
        result = router.route_with_override("triage", override=BrainType.BOTH)
        assert result == BrainType.BOTH


class TestRouterHistory:
    """Routing history should be tracked."""

    def test_history_populated(self):
        router = BrainRouter()
        router.route("recon")
        router.route("fp_check")
        history = router.get_routing_history()
        assert len(history) == 2
        assert history[0]["task"] == "recon"
        assert history[0]["brain"] == BrainType.SECONDARY
        assert history[1]["task"] == "fp_check"
        assert history[1]["brain"] == BrainType.PRIMARY

    def test_history_bounded_at_1000(self):
        router = BrainRouter()
        for i in range(1050):
            router.route(f"task_{i}")
        assert len(router.get_routing_history()) == 1000

    def test_history_includes_default_entries(self):
        router = BrainRouter()
        router.route("no_match_xyz")
        history = router.get_routing_history()
        assert history[0]["rule_pattern"] == "default"


class TestRouterCustomRules:
    """Custom rules and add_rule behavior."""

    def test_custom_rules_replace_defaults(self):
        custom = [RoutingRule(
            pattern=r".*",  # match everything
            brain=BrainType.BOTH,
            priority=99,
        )]
        router = BrainRouter(rules=custom)
        assert router.route("anything") == BrainType.BOTH

    def test_add_rule_inserts_sorted(self):
        router = BrainRouter()
        initial_count = len(router.rules)
        router.add_rule(RoutingRule(
            pattern=r"my_custom_task",
            brain=BrainType.BOTH,
            priority=50,
        ))
        assert len(router.rules) == initial_count + 1
        assert router.rules[0].priority >= 50  # top rule is >= 50
        assert router.route("my_custom_task") == BrainType.BOTH


class TestRouterStats:
    """get_stats() should return brain usage counts."""

    def test_stats_counting(self):
        router = BrainRouter()
        router.route("recon")
        router.route("recon")
        router.route("fp_check")
        stats = router.get_stats()
        assert stats["total_routes"] == 3
        assert "secondary" in stats["routes_by_brain"]
        assert "primary" in stats["routes_by_brain"]


class TestRoutingRuleMatching:
    """Test individual RoutingRule.matches() behavior."""

    def test_case_insensitive(self):
        rule = RoutingRule(pattern=r"fp_check", brain=BrainType.PRIMARY)
        assert rule.matches("FP_CHECK") is True
        assert rule.matches("Fp_Check") is True

    def test_partial_match_via_search(self):
        """re.search matches anywhere in the string."""
        rule = RoutingRule(pattern=r"exploit", brain=BrainType.PRIMARY)
        assert rule.matches("exploit_strategy") is True
        assert rule.matches("pre_exploit_analysis") is True

    def test_no_match(self):
        rule = RoutingRule(pattern=r"^exact_only$", brain=BrainType.PRIMARY)
        assert rule.matches("exact_only") is True
        assert rule.matches("some_exact_only_task") is False
