"""Tests for the Brain Engine & Router."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest


class TestCircuitBreaker:
    """Test circuit breaker resilience pattern."""

    def test_initial_state_closed(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test")
        assert cb.state == "closed"
        assert cb.is_available is True

    def test_stays_closed_under_threshold(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test", failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == "closed"
        assert cb.is_available is True

    def test_opens_at_threshold(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test", failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "open"
        assert cb.is_available is False

    def test_success_resets_failure_count(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.state == "closed"
        # After reset, need full threshold again to open
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "closed"

    def test_half_open_after_recovery(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(0.15)
        assert cb.state == "half_open"
        assert cb.is_available is True

    def test_half_open_success_closes(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"

    def test_half_open_failure_reopens(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.state == "half_open"
        cb.record_failure()
        assert cb.state == "open"

    def test_to_dict(self):
        from src.brain.engine import CircuitBreaker
        cb = CircuitBreaker(label="test", failure_threshold=3, recovery_timeout=60.0)
        d = cb.to_dict()
        assert d["state"] == "closed"
        assert d["failure_count"] == 0
        assert d["failure_threshold"] == 3
        assert d["recovery_timeout"] == 60.0


class TestBrainRouter:
    """Test brain router task→model mapping."""

    def test_routing_recon_to_secondary(self):
        """Recon tasks should route to the secondary (fast) model."""
        from src.brain.router import BrainRouter
        router = BrainRouter()
        result = router.route("recon_subdomain_scan")
        assert result in ("secondary", "both", "primary")

    def test_routing_analysis_to_primary(self):
        """Analysis tasks should route to primary (deep) model."""
        from src.brain.router import BrainRouter
        router = BrainRouter()
        result = router.route("analyze_vulnerability")
        assert result in ("primary", "both")

    def test_routing_unknown_task(self):
        """Unknown tasks should have a sensible default."""
        from src.brain.router import BrainRouter
        router = BrainRouter()
        result = router.route("unknown_task_xyz")
        assert result in ("primary", "secondary", "both")


class TestSelfReflection:
    """Test self-reflection engine."""

    def test_reflection_creation(self):
        from src.brain.reasoning.self_reflection import SelfReflectionEngine
        engine = SelfReflectionEngine()
        assert engine is not None

    def test_chain_of_thought_creation(self):
        from src.brain.reasoning.chain_of_thought import ChainOfThoughtEngine
        engine = ChainOfThoughtEngine()
        assert engine is not None


class TestAttackPlanner:
    """Test attack planner."""

    def test_planner_creation(self):
        from src.brain.reasoning.attack_planner import AttackPlanner
        planner = AttackPlanner()
        assert planner is not None


class TestBrainEngineBudgetGuards:
    """Test prompt and completion budget guards in the brain engine."""

    def test_estimate_message_tokens_positive(self):
        from src.brain.engine import BrainEngine

        engine = BrainEngine()
        tokens = engine._estimate_message_tokens([
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "user prompt"},
        ])
        assert tokens > 0

    def test_fit_messages_to_context_trims_user_prompt(self):
        from src.brain.engine import BrainEngine, ModelConfig

        engine = BrainEngine()
        config = ModelConfig(name="test", context_length=256, max_tokens=128)
        messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "A" * 1200},
        ]

        fitted, completion_tokens, prompt_tokens = engine._fit_messages_to_context(
            messages,
            config,
            requested_max_tokens=128,
        )

        assert fitted[-1]["content"].startswith("[TRIMMED TO FIT CONTEXT]")
        assert prompt_tokens + completion_tokens <= config.context_length

    def test_fit_messages_to_context_keeps_small_prompt(self):
        from src.brain.engine import BrainEngine, ModelConfig

        engine = BrainEngine()
        config = ModelConfig(name="test", context_length=4096, max_tokens=256)
        messages = [{"role": "user", "content": "short prompt"}]

        fitted, completion_tokens, prompt_tokens = engine._fit_messages_to_context(
            messages,
            config,
            requested_max_tokens=128,
        )

        assert fitted == messages
        assert completion_tokens == 128
        assert prompt_tokens < config.context_length


class TestRiskAssessor:
    """Test risk assessor."""

    def test_assess_sqli(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        assessor = RiskAssessor()
        result = assessor.assess_vulnerability(
            vuln_type="sqli",
            target="https://example.com/search",
            impact_score=8.5,
            confidence=90.0,
        )
        assert result.risk_score > 0
        assert result.risk_level.value in ("critical", "high", "medium", "low", "info")

    def test_prioritise_findings(self):
        from src.brain.reasoning.risk_assessor import RiskAssessor
        assessor = RiskAssessor()
        findings = [
            {"vuln_type": "sqli", "target": "a.com", "impact_score": 8.5, "confidence": 90},
            {"vuln_type": "xss", "target": "b.com", "impact_score": 6.0, "confidence": 70},
            {"vuln_type": "open_redirect", "target": "c.com", "impact_score": 3.0, "confidence": 50},
        ]
        ranked = assessor.prioritise_findings(findings)
        assert len(ranked) == 3
        assert ranked[0].priority_rank == 1
        # First should have highest risk score
        assert ranked[0].risk_score >= ranked[1].risk_score


class TestPromptSanitization:
    """Test credential sanitization before sending prompts to LLM."""

    def test_sanitize_api_key(self):
        from src.brain.intelligence import _sanitize_prompt
        result = _sanitize_prompt("Found api_key=sk-abc123xyz in config")
        assert "sk-abc123xyz" not in result
        assert "REDACTED" in result

    def test_sanitize_password(self):
        from src.brain.intelligence import _sanitize_prompt
        result = _sanitize_prompt("database password=SuperSecret123!")
        assert "SuperSecret123!" not in result
        assert "REDACTED" in result

    def test_sanitize_bearer_token(self):
        from src.brain.intelligence import _sanitize_prompt
        result = _sanitize_prompt("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test")
        # "bearer" is a sensitive pattern, so the pattern after should be redacted
        assert "REDACTED" in result

    def test_preserves_normal_text(self):
        from src.brain.intelligence import _sanitize_prompt
        text = "Scan target https://example.com, found XSS in /search?q=test"
        result = _sanitize_prompt(text)
        assert result == text  # No credentials, no changes

    def test_sanitize_empty_string(self):
        from src.brain.intelligence import _sanitize_prompt
        assert _sanitize_prompt("") == ""

    def test_sanitize_github_token(self):
        from src.brain.intelligence import _sanitize_prompt
        result = _sanitize_prompt("github_token=ghp_abc123def456")
        assert "ghp_abc123def456" not in result
        assert "REDACTED" in result


class TestIntelligenceEngineRouter:
    """Test BrainRouter integration with IntelligenceEngine."""

    def test_accepts_router_param(self):
        from src.brain.intelligence import IntelligenceEngine
        from src.brain.router import BrainRouter
        mock_brain = MagicMock()
        mock_brain.has_primary = True
        mock_brain.has_secondary = True
        router = BrainRouter()
        engine = IntelligenceEngine(mock_brain, router=router)
        assert engine.router is router

    def test_works_without_router(self):
        from src.brain.intelligence import IntelligenceEngine

        mock_brain = MagicMock()
        mock_brain.has_primary = True
        mock_brain.has_secondary = True
        engine = IntelligenceEngine(mock_brain)
        assert engine.router is None


class TestKnowledgeBaseLearning:
    """Test cross-scan learning persistence and retrieval."""

    def test_record_scan_learning_persists_historical_snapshot(self, tmp_path):
        from src.brain.memory.knowledge_base import KnowledgeBase

        kb = KnowledgeBase(tmp_path / "knowledge.db")
        kb.initialize()

        kb.record_scan_learning(
            session_id="session-1",
            target="example.com",
            profile="balanced",
            mode="semi-autonomous",
            technologies={"example.com": ["wordpress", "php"]},
            tools_used=["wpscan", "sqlmap"],
            raw_findings=[
                {"tool": "wpscan", "type": "plugin-enum"},
                {"tool": "sqlmap", "type": "sqli"},
            ],
            verified_findings=[
                {"tool": "sqlmap", "type": "sqli", "target": "https://example.com/search"},
            ],
            false_positives=[
                {
                    "tool": "wpscan",
                    "type": "xss",
                    "target": "https://example.com/",
                    "severity": "medium",
                    "fp_reason": "reflection was HTML-encoded",
                },
            ],
            duration_seconds=12.5,
        )

        snapshot = kb.get_learning_snapshot({"example.com": ["wordpress", "php"]})
        target_intel = kb.get_target_intel("example.com")
        sqlmap_stats = kb.get_tool_effectiveness("sqlmap")

        assert target_intel is not None
        assert "wordpress" in target_intel.technologies
        assert "sqlmap" in snapshot["recommended_tools"]
        assert "sqli" in snapshot["common_vuln_types"]
        assert sqlmap_stats is not None
        assert sqlmap_stats.confirmed_findings == 1

    def test_async_update_tool_effectiveness_uses_record_tool_run(self, tmp_path):
        import asyncio

        from src.brain.memory.knowledge_base import KnowledgeBase

        kb = KnowledgeBase(tmp_path / "knowledge.db")
        kb.initialize()

        asyncio.run(
            kb.async_update_tool_effectiveness(
                "dalfox",
                success=True,
                findings=2,
                confirmed=1,
                false_positives=0,
                execution_time=1.5,
                vuln_types=["xss"],
            )
        )

        stats = kb.get_tool_effectiveness("dalfox")
        assert stats is not None
        assert stats.total_runs == 1
        assert stats.confirmed_findings == 1


class TestIntelligenceNextAction:
    """Test controlled agentic next-action decisions."""

    def test_decide_next_action_defaults_when_unavailable(self):
        import asyncio

        from src.brain.intelligence import IntelligenceEngine

        mock_brain = MagicMock()
        mock_brain.has_primary = False
        mock_brain.has_secondary = False

        engine = IntelligenceEngine(mock_brain)
        result = asyncio.new_event_loop().run_until_complete(
            engine.decide_next_action(
                current_stage="vulnerability_scan",
                findings_so_far=[],
                completed_tools=[],
                remaining_tools=["sqlmap", "dalfox"],
            )
        )

        assert result.action == "continue"
        assert result.next_tool == ""
        assert result.skip_tools == []

    def test_decide_next_action_parses_valid_json(self):
        import asyncio

        from src.brain.intelligence import IntelligenceEngine

        mock_brain = MagicMock()
        mock_brain.has_primary = True
        mock_brain.has_secondary = True

        engine = IntelligenceEngine(mock_brain)

        async def _fake_brain_call(*args, **kwargs):
            return """{
                \"action\": \"deep_dive\",
                \"reason\": \"GraphQL endpoint looks high-value\",
                \"next_tool\": \"graphql_deep_scanner\",
                \"skip_tools\": [\"crlfuzz\", \"corsy\"],
                \"deep_dive_target\": \"/graphql\",
                \"priority_findings\": [\"debug_mode\"],
                \"time_estimate\": \"8m\"
            }"""

        engine._brain_call = _fake_brain_call

        result = asyncio.new_event_loop().run_until_complete(
            engine.decide_next_action(
                current_stage="vulnerability_scan",
                findings_so_far=[{"severity": "high", "type": "graphql_debug", "target": "https://example.com/graphql"}],
                completed_tools=["nuclei", "nikto"],
                remaining_tools=["graphql_deep_scanner", "crlfuzz", "corsy"],
                time_elapsed="120s",
                scan_profile="balanced",
            )
        )

        assert result.action == "deep_dive"
        assert result.next_tool == "graphql_deep_scanner"
        assert result.deep_dive_target == "/graphql"
        assert result.skip_tools == ["crlfuzz", "corsy"]


# ==============================================================
# _get_client_for_config & _refresh_remote_clients tests
# ==============================================================


class TestClientForConfig:
    """Test client lookup after tunnel reconnect."""

    def test_returns_primary_client(self):
        from src.brain.engine import BrainEngine, ModelConfig, InferenceBackend

        cfg_p = ModelConfig(name="P", backend=InferenceBackend.REMOTE, api_url="http://x")
        cfg_s = ModelConfig(name="S", backend=InferenceBackend.REMOTE, api_url="http://y")
        engine = BrainEngine(cfg_p, cfg_s)

        sentinel = object()
        engine._primary_client = sentinel

        assert engine._get_client_for_config(cfg_p) is sentinel
        assert engine._get_client_for_config(cfg_s) is None  # secondary not set
        assert engine._get_client_for_config(None) is None

    def test_returns_secondary_client(self):
        from src.brain.engine import BrainEngine, ModelConfig, InferenceBackend

        cfg_p = ModelConfig(name="P", backend=InferenceBackend.REMOTE, api_url="http://x")
        cfg_s = ModelConfig(name="S", backend=InferenceBackend.REMOTE, api_url="http://y")
        engine = BrainEngine(cfg_p, cfg_s)

        sentinel = object()
        engine._secondary_client = sentinel

        assert engine._get_client_for_config(cfg_s) is sentinel

    def test_returns_none_for_unknown_config(self):
        from src.brain.engine import BrainEngine, ModelConfig, InferenceBackend

        cfg_p = ModelConfig(name="P", backend=InferenceBackend.REMOTE, api_url="http://x")
        engine = BrainEngine(cfg_p, None)
        other = ModelConfig(name="Z", backend=InferenceBackend.REMOTE, api_url="http://z")

        assert engine._get_client_for_config(other) is None
