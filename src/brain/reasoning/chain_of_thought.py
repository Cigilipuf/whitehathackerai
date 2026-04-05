"""
WhiteHatHacker AI — Chain of Thought Reasoning Engine

Implements step-by-step reasoning through the attack lifecycle.
The bot explicitly "thinks out loud" — generating hypotheses,
evaluating evidence, identifying gaps, and planning next steps
with full visibility into its reasoning process.

Uses the Primary (32B) model for deep reasoning tasks.
"""

from __future__ import annotations

import json
import re
import time
from enum import Enum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from src.utils.constants import BrainType


class ReasoningPhase(str, Enum):
    """Phases of the reasoning process."""
    OBSERVE = "observe"          # Gather and understand data
    HYPOTHESIZE = "hypothesize"  # Generate hypotheses
    PLAN = "plan"                # Plan tests/actions
    EXECUTE = "execute"          # Execute planned actions
    EVALUATE = "evaluate"        # Evaluate results
    CONCLUDE = "conclude"        # Draw conclusions


class HypothesisStatus(str, Enum):
    """Status of a hypothesis."""
    PROPOSED = "proposed"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class Hypothesis(BaseModel):
    """A testable hypothesis about a potential vulnerability."""

    hypothesis_id: str
    statement: str           # "Target X is vulnerable to SQLi at param Y"
    vuln_type: str          # e.g., "sqli", "xss", "ssrf"
    target: str             # Specific endpoint/host
    parameter: str = ""     # Specific parameter if applicable
    confidence: float = 0.0  # 0-100, starts at 0
    status: HypothesisStatus = HypothesisStatus.PROPOSED

    # Evidence tracking
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)

    # Test plan
    tests_planned: list[str] = Field(default_factory=list)
    tests_completed: list[str] = Field(default_factory=list)

    # Reasoning chain
    reasoning_steps: list[str] = Field(default_factory=list)

    created: float = Field(default_factory=time.time)
    updated: float = Field(default_factory=time.time)


class ReasoningStep(BaseModel):
    """A single step in the chain of thought."""

    step_number: int
    phase: ReasoningPhase
    thought: str                # The actual reasoning
    evidence: list[str] = Field(default_factory=list)
    conclusion: str = ""
    next_action: str = ""
    confidence_delta: float = 0.0  # Change in confidence
    timestamp: float = Field(default_factory=time.time)


class ReasoningChain(BaseModel):
    """A complete chain of thought from observation to conclusion."""

    chain_id: str
    target: str
    goal: str               # What we're trying to determine
    steps: list[ReasoningStep] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    final_conclusion: str = ""
    overall_confidence: float = 0.0
    started: float = Field(default_factory=time.time)
    completed: float = 0.0


# ── Reasoning Prompts ──────────────────────────────────────────────

REASONING_PROMPTS = {
    "observation": """You are analyzing security data. Think step-by-step.

OBSERVATION DATA:
{data}

TASK: Analyze this data and identify:
1. What services/technologies are running?
2. What potential attack vectors do you see?
3. What's unusual or noteworthy?
4. What information is missing that we need?

Respond in JSON:
{{
    "observations": ["observation1", "observation2", ...],
    "technologies": ["tech1", "tech2", ...],
    "attack_vectors": ["vector1", "vector2", ...],
    "unusual_findings": ["finding1", ...],
    "missing_info": ["info1", "info2", ...],
    "priority_targets": ["target1", "target2", ...]
}}""",

    "hypothesis_generation": """You are a security researcher generating hypotheses.

CONTEXT:
Target: {target}
Technologies: {technologies}
Observations: {observations}
Previous Findings: {previous_findings}

TASK: Generate testable hypotheses about potential vulnerabilities.
For each hypothesis:
- State it clearly and specifically
- Explain why you think it might be true
- Describe how to test it
- Rate initial confidence (0-100)

Respond in JSON:
{{
    "hypotheses": [
        {{
            "statement": "specific hypothesis",
            "vuln_type": "sqli|xss|ssrf|idor|etc",
            "target": "specific endpoint",
            "parameter": "param name if applicable",
            "reasoning": "why you suspect this",
            "test_plan": ["step1", "step2", ...],
            "initial_confidence": 0-100,
            "tools_needed": ["tool1", "tool2"]
        }}
    ]
}}""",

    "evidence_evaluation": """You are evaluating security evidence. Think critically.

HYPOTHESIS: {hypothesis}
TARGET: {target}

EVIDENCE FOR:
{supporting_evidence}

EVIDENCE AGAINST:
{contradicting_evidence}

TOOL RESULTS:
{tool_results}

TASK: Evaluate this evidence and determine:
1. Does the evidence support or refute the hypothesis?
2. What is the confidence level (0-100)?
3. Is there a real vulnerability, a false positive, or need more testing?
4. What additional tests would help clarify?

Think about:
- Could WAF/CDN cause false results?
- Is the response genuinely abnormal or just application behavior?
- Are there multiple independent confirmations?
- Is the payload actually executing or just reflected?

Respond in JSON:
{{
    "verdict": "supported|refuted|inconclusive",
    "confidence": 0-100,
    "reasoning": "detailed step-by-step reasoning",
    "key_evidence": "the most compelling piece of evidence",
    "false_positive_risk": "low|medium|high",
    "fp_reason": "if FP risk is medium/high, explain why",
    "additional_tests": ["test1", "test2", ...],
    "next_action": "what to do next"
}}""",

    "attack_reasoning": """You are planning a security test. Think strategically.

TARGET: {target}
TECHNOLOGY: {technology}
DISCOVERED ENDPOINTS: {endpoints}
DISCOVERED PARAMETERS: {parameters}
CURRENT FINDINGS: {findings}

TASK: Reason through the best attack approach:
1. Given the technology stack, what vulnerabilities are most likely?
2. Which endpoints/parameters are highest priority?
3. What tool chain would be most effective?
4. What order should tests be performed?
5. What are potential rabbit holes to avoid?

Respond in JSON:
{{
    "tech_analysis": "analysis of technology implications",
    "likely_vulns": [
        {{"type": "vuln_type", "probability": "high|medium|low", "reason": "why"}}
    ],
    "priority_targets": [
        {{"endpoint": "/path", "param": "param", "test": "what to test", "tool": "which tool"}}
    ],
    "tool_chain": ["tool1 → tool2 → tool3"],
    "avoid": ["potential time waste 1", "rabbit hole 2"],
    "estimated_time": "rough time estimate"
}}""",

    "finding_analysis": """You are analyzing a security finding. Be thorough and skeptical.

FINDING:
Title: {title}
Severity: {severity}
Tool: {tool_name}
Target: {target}
Evidence: {evidence}

RAW TOOL OUTPUT:
{raw_output}

KNOWN FP PATTERNS FOR THIS TOOL:
{fp_patterns}

TASK: Analyze this finding deeply:
1. Is this a genuine vulnerability or false positive?
2. What is the real-world impact?
3. Can it be exploited? How?
4. What CVSS score is appropriate?
5. What remediation do you recommend?

Think about:
- Is the evidence conclusive?
- Could this be caused by WAF/CDN/load balancer?
- Does the tool have known false positive patterns for this type?
- Is the context appropriate for this vulnerability?

Respond in JSON:
{{
    "is_valid": true/false,
    "confidence": 0-100,
    "analysis": "detailed analysis",
    "real_impact": "what an attacker could actually do",
    "exploitability": "trivial|moderate|difficult|theoretical",
    "cvss_score": X.X,
    "cvss_vector": "CVSS:3.1/...",
    "remediation": "specific fix recommendation",
    "additional_verification": ["verify step 1", "verify step 2"],
    "false_positive_indicators": ["indicator1"] // if likely FP
}}""",

    "conclusion": """You are writing the final analysis for a security assessment phase.

TARGET: {target}
PHASE: {phase}
HYPOTHESES TESTED:
{hypotheses_summary}

CONFIRMED FINDINGS:
{confirmed_findings}

REJECTED (FP):
{rejected_findings}

TASK: Provide final conclusions:
1. What was discovered?
2. What's the overall security posture?
3. What should be investigated further?
4. Priority recommendations?

Respond in JSON:
{{
    "summary": "brief overall summary",
    "confirmed_vulns": [{{"title": "...", "severity": "...", "confidence": 0-100}}],
    "security_posture": "strong|moderate|weak|critical",
    "further_investigation": ["area1", "area2"],
    "recommendations": ["rec1", "rec2", "rec3"],
    "next_phase_focus": "what to focus on in the next phase"
}}"""
}


# ── Chain of Thought Engine ────────────────────────────────────────

class ChainOfThoughtEngine:
    """
    Implements structured reasoning through the attack lifecycle.

    Capabilities:
    - Observation → Hypothesis → Test → Evaluate → Conclude cycle
    - Multi-hypothesis tracking with confidence scoring
    - Evidence-based reasoning with explicit support/contradiction
    - Integration with brain models for deep analysis
    - Integration with vuln_patterns for pattern matching
    - Full reasoning audit trail

    Uses PRIMARY (32B) model for all reasoning tasks.
    """

    def __init__(self, brain_engine=None, context_manager=None, knowledge_base=None):
        self._brain = brain_engine
        self._context = context_manager
        self._knowledge = knowledge_base

        # Active reasoning chains
        self._active_chains: dict[str, ReasoningChain] = {}
        self._completed_chains: list[ReasoningChain] = []

        # Hypothesis registry
        self._hypotheses: dict[str, Hypothesis] = {}
        self._hypothesis_counter = 0

    async def observe(
        self,
        data: dict[str, Any],
        target: str,
        goal: str = "Identify potential vulnerabilities",
    ) -> dict:
        """
        Phase 1: Observe and analyze raw data.

        Takes tool outputs, scan results, or other data and
        extracts observations, patterns, and potential targets.
        """
        chain = self._get_or_create_chain(target, goal)

        prompt = REASONING_PROMPTS["observation"].format(
            data=json.dumps(data, indent=2, default=str)[:8000]
        )

        result = await self._reason(prompt)

        step = ReasoningStep(
            step_number=len(chain.steps) + 1,
            phase=ReasoningPhase.OBSERVE,
            thought=f"Observed: {json.dumps(result, default=str)[:500]}",
            evidence=[f"Raw data from {len(data)} sources"],
            conclusion=result.get("observations", ["No clear observations"])[0] if isinstance(result, dict) else str(result),
            next_action="Generate hypotheses based on observations",
        )
        chain.steps.append(step)

        logger.info(f"[CoT] Observation phase complete for {target}")
        return result

    async def generate_hypotheses(
        self,
        target: str,
        technologies: list[str],
        observations: list[str],
        previous_findings: list[str] | None = None,
    ) -> list[Hypothesis]:
        """
        Phase 2: Generate testable hypotheses.

        Based on observations and technology stack, creates specific,
        testable hypotheses about potential vulnerabilities.
        """
        chain = self._get_or_create_chain(target, "Security assessment")

        prompt = REASONING_PROMPTS["hypothesis_generation"].format(
            target=target,
            technologies=", ".join(technologies),
            observations="\n".join(f"- {o}" for o in observations),
            previous_findings="\n".join(f"- {f}" for f in (previous_findings or ["None"])),
        )

        result = await self._reason(prompt)
        new_hypotheses = []

        if isinstance(result, dict) and "hypotheses" in result:
            for h_data in result["hypotheses"]:
                self._hypothesis_counter += 1
                hyp = Hypothesis(
                    hypothesis_id=f"H-{self._hypothesis_counter:04d}",
                    statement=h_data.get("statement", "Unknown"),
                    vuln_type=h_data.get("vuln_type", "unknown"),
                    target=h_data.get("target", target),
                    parameter=h_data.get("parameter", ""),
                    confidence=h_data.get("initial_confidence", 20),
                    tests_planned=h_data.get("test_plan", []),
                    reasoning_steps=[h_data.get("reasoning", "Brain-generated hypothesis")],
                )
                self._hypotheses[hyp.hypothesis_id] = hyp
                chain.hypotheses.append(hyp)
                new_hypotheses.append(hyp)

        step = ReasoningStep(
            step_number=len(chain.steps) + 1,
            phase=ReasoningPhase.HYPOTHESIZE,
            thought=f"Generated {len(new_hypotheses)} hypotheses",
            evidence=observations,
            conclusion=f"Top hypothesis: {new_hypotheses[0].statement}" if new_hypotheses else "No hypotheses generated",
            next_action="Plan and execute tests for top hypotheses",
        )
        chain.steps.append(step)

        logger.info(f"[CoT] Generated {len(new_hypotheses)} hypotheses for {target}")
        return new_hypotheses

    async def evaluate_evidence(
        self,
        hypothesis_id: str,
        tool_results: dict[str, Any],
    ) -> dict:
        """
        Phase 4: Evaluate evidence for/against a hypothesis.

        Takes tool results and evaluates whether they support or
        refute the hypothesis. Updates confidence accordingly.
        """
        hyp = self._hypotheses.get(hypothesis_id)
        if not hyp:
            return {"error": f"Hypothesis {hypothesis_id} not found"}

        hyp.status = HypothesisStatus.TESTING

        prompt = REASONING_PROMPTS["evidence_evaluation"].format(
            hypothesis=hyp.statement,
            target=hyp.target,
            supporting_evidence="\n".join(f"- {e}" for e in hyp.supporting_evidence) or "None yet",
            contradicting_evidence="\n".join(f"- {e}" for e in hyp.contradicting_evidence) or "None yet",
            tool_results=json.dumps(tool_results, indent=2, default=str)[:6000],
        )

        result = await self._reason(prompt)

        if isinstance(result, dict):
            verdict = result.get("verdict", "inconclusive")
            confidence = result.get("confidence", hyp.confidence)
            reasoning = result.get("reasoning", "")

            # Update hypothesis
            hyp.confidence = confidence
            hyp.reasoning_steps.append(f"Evidence evaluation: {reasoning[:200]}")

            if verdict == "supported":
                hyp.status = HypothesisStatus.SUPPORTED
                hyp.supporting_evidence.append(
                    result.get("key_evidence", "Tool results support hypothesis")
                )
            elif verdict == "refuted":
                hyp.status = HypothesisStatus.REFUTED
                hyp.contradicting_evidence.append(
                    result.get("key_evidence", "Tool results refute hypothesis")
                )
            else:
                hyp.status = HypothesisStatus.INCONCLUSIVE

            hyp.updated = time.time()

        logger.info(
            f"[CoT] Evidence evaluation for {hypothesis_id}: "
            f"{hyp.status.value} (confidence: {hyp.confidence})"
        )
        return result

    async def analyze_finding(
        self,
        title: str,
        severity: str,
        tool_name: str,
        target: str,
        evidence: str,
        raw_output: str = "",
        fp_patterns: list[str] | None = None,
    ) -> dict:
        """
        Deep analysis of a specific finding.

        Uses the brain to critically evaluate whether a finding
        is genuine, assess its impact, and recommend next steps.
        """
        prompt = REASONING_PROMPTS["finding_analysis"].format(
            title=title,
            severity=severity,
            tool_name=tool_name,
            target=target,
            evidence=evidence,
            raw_output=raw_output[:4000],
            fp_patterns="\n".join(f"- {p}" for p in (fp_patterns or ["No known patterns"])),
        )

        result = await self._reason(prompt)
        logger.info(f"[CoT] Finding analysis complete: {title}")
        return result

    async def plan_attack(
        self,
        target: str,
        technology: list[str],
        endpoints: list[str],
        parameters: list[str],
        current_findings: list[str] | None = None,
    ) -> dict:
        """
        Strategic attack planning based on gathered intelligence.

        Creates a prioritized plan of what to test, with which tools,
        and in what order.
        """
        prompt = REASONING_PROMPTS["attack_reasoning"].format(
            target=target,
            technology=", ".join(technology),
            endpoints="\n".join(f"- {e}" for e in endpoints[:30]),
            parameters="\n".join(f"- {p}" for p in parameters[:30]),
            findings="\n".join(f"- {f}" for f in (current_findings or ["None yet"])),
        )

        result = await self._reason(prompt)
        logger.info(f"[CoT] Attack plan generated for {target}")
        return result

    async def conclude(self, target: str, phase: str) -> dict:
        """
        Draw final conclusions for a phase of testing.

        Summarizes hypotheses tested, findings confirmed/rejected,
        and recommends next steps.
        """
        # Gather hypothesis summary
        hyp_summary = []
        confirmed = []
        rejected = []

        for hyp in self._hypotheses.values():
            status = hyp.status.value
            hyp_summary.append(
                f"[{status}] {hyp.statement} (confidence: {hyp.confidence})"
            )
            if hyp.status == HypothesisStatus.SUPPORTED and hyp.confidence >= 70:
                confirmed.append(hyp.statement)
            elif hyp.status == HypothesisStatus.REFUTED:
                rejected.append(hyp.statement)

        prompt = REASONING_PROMPTS["conclusion"].format(
            target=target,
            phase=phase,
            hypotheses_summary="\n".join(hyp_summary) or "No hypotheses tested",
            confirmed_findings="\n".join(f"- {f}" for f in confirmed) or "None",
            rejected_findings="\n".join(f"- {f}" for f in rejected) or "None",
        )

        result = await self._reason(prompt)
        logger.info(f"[CoT] Conclusion phase complete for {target}")
        return result

    # ── Hypothesis Management ──────────────────────────────────────

    def add_evidence(
        self, hypothesis_id: str, evidence: str, supports: bool
    ) -> None:
        """Add evidence for or against a hypothesis."""
        hyp = self._hypotheses.get(hypothesis_id)
        if hyp:
            if supports:
                hyp.supporting_evidence.append(evidence)
                hyp.confidence = min(100, hyp.confidence + 5)
            else:
                hyp.contradicting_evidence.append(evidence)
                hyp.confidence = max(0, hyp.confidence - 10)
            hyp.updated = time.time()

    def mark_test_completed(self, hypothesis_id: str, test: str) -> None:
        """Mark a planned test as completed."""
        hyp = self._hypotheses.get(hypothesis_id)
        if hyp:
            hyp.tests_completed.append(test)
            if test in hyp.tests_planned:
                hyp.tests_planned.remove(test)

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        """Get a specific hypothesis."""
        return self._hypotheses.get(hypothesis_id)

    def get_active_hypotheses(self) -> list[Hypothesis]:
        """Get all non-concluded hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]

    def get_supported_hypotheses(self, min_confidence: float = 70) -> list[Hypothesis]:
        """Get hypotheses that are likely true."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.SUPPORTED and h.confidence >= min_confidence
        ]

    def get_hypothesis_summary(self) -> dict:
        """Get a summary of all hypothesis statuses."""
        summary = {s.value: 0 for s in HypothesisStatus}
        for h in self._hypotheses.values():
            summary[h.status.value] += 1
        return {
            "total": len(self._hypotheses),
            "by_status": summary,
            "avg_confidence": (
                sum(h.confidence for h in self._hypotheses.values()) / len(self._hypotheses)
                if self._hypotheses else 0
            ),
        }

    # ── Internal ───────────────────────────────────────────────────

    def _get_or_create_chain(self, target: str, goal: str) -> ReasoningChain:
        """Get existing chain for target or create new one."""
        chain_id = f"chain_{target}_{len(self._active_chains)}"
        if target not in self._active_chains:
            self._active_chains[target] = ReasoningChain(
                chain_id=chain_id,
                target=target,
                goal=goal,
            )
        return self._active_chains[target]

    async def _reason(self, prompt: str) -> dict:
        """
        Send a reasoning prompt to the brain engine.

        Uses PRIMARY (32B) model for deep reasoning.
        Falls back to structured rule-based parsing if brain unavailable.
        """
        if self._brain:
            try:
                response = await self._brain.think(
                    prompt=prompt,
                    brain=BrainType.PRIMARY,
                    temperature=0.1,
                    max_tokens=4096,
                )

                # Try to parse JSON from response
                text = response.text if hasattr(response, 'text') else str(response)
                return self._extract_json(text)
            except Exception as e:
                logger.warning(f"[CoT] Brain reasoning failed: {e}, using fallback")

        return self._fallback_reasoning(prompt)

    def _extract_json(self, text: str) -> dict:
        """Extract JSON from brain response text."""
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find JSON block
        patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*(.*?)\s*```',
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1) if '```' in pattern else match.group(0))
                except (json.JSONDecodeError, IndexError):
                    continue

        # Return as plain text
        return {"raw_response": text}

    def _fallback_reasoning(self, prompt: str) -> dict:
        """Rule-based fallback when brain is unavailable."""
        return {
            "status": "fallback",
            "message": "Brain model unavailable, using rule-based fallback",
            "observations": ["Rule-based analysis not yet implemented"],
            "hypotheses": [],
            "verdict": "inconclusive",
            "confidence": 0,
        }


__all__ = [
    "ChainOfThoughtEngine",
    "ReasoningChain",
    "ReasoningStep",
    "ReasoningPhase",
    "Hypothesis",
    "HypothesisStatus",
]
