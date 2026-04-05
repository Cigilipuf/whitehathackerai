"""
WhiteHatHacker AI — Adaptive Strategy Engine

Dynamic strategy adjustment engine that responds to environmental
signals detected during a scan. A professional bug bounty hunter
continuously adapts their approach based on what they observe:

- **WAF detected** → Switch to stealth techniques, encode payloads
- **Rate limiting** → Slow down, increase delays, rotate user agents
- **Technology detected** → Add specialised checks for that framework
- **Success pattern** → Double down on what's working
- **Failure pattern** → Abandon unproductive approaches
- **New attack surface** → Expand scope of testing

The engine maintains an "environmental model" of the target and makes
strategy decisions that maximise the probability of finding real
vulnerabilities while minimising detection and wasted effort.

Architecture:
    AdaptiveStrategyEngine
    ├── observe()         ← feed environmental signals
    ├── adapt()           → compute strategy adjustments
    ├── get_profile()     → current effective scan profile
    ├── get_tool_config() → per-tool parameter overrides
    └── explain()         → human-readable strategy explanation
"""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ────────────────────────────────────────────────────────────
# Enumerations
# ────────────────────────────────────────────────────────────


class SignalType(StrEnum):
    """Types of environmental signals the engine can process."""

    WAF_DETECTED = "waf_detected"
    WAF_BLOCKING = "waf_blocking"
    RATE_LIMITED = "rate_limited"
    CDN_DETECTED = "cdn_detected"
    TECH_DETECTED = "tech_detected"
    AUTH_REQUIRED = "auth_required"
    TOOL_BLOCKED = "tool_blocked"
    TOOL_SUCCESS = "tool_success"
    TOOL_FAILED = "tool_failed"
    FINDING_CONFIRMED = "finding_confirmed"
    FINDING_FP = "finding_fp"
    HIGH_FP_RATE = "high_fp_rate"
    ZERO_FINDINGS = "zero_findings"
    ENDPOINT_FOUND = "endpoint_found"
    SUBDOMAIN_FOUND = "subdomain_found"
    CUSTOM_ERROR_PAGE = "custom_error_page"
    TARGET_DOWN = "target_down"
    LARGE_ATTACK_SURFACE = "large_attack_surface"


class StrategyMode(StrEnum):
    """Overall strategy modes the engine can switch between."""

    STANDARD = "standard"          # Normal balanced scanning
    STEALTH = "stealth"            # Slow, low-profile, evasive
    AGGRESSIVE = "aggressive"      # Fast, comprehensive, noisy
    DEEP_DIVE = "deep_dive"        # Focus on specific areas
    WAF_EVASION = "waf_evasion"    # WAF bypass techniques
    API_FOCUSED = "api_focused"    # Prioritise API testing
    AUTH_FOCUSED = "auth_focused"  # Focus on auth/authz issues


class AdaptationPriority(StrEnum):
    """Priority level for strategy adaptations."""

    CRITICAL = "critical"   # Must apply immediately
    HIGH = "high"           # Apply before next tool run
    MEDIUM = "medium"       # Apply before next stage
    LOW = "low"             # Apply when convenient


# ────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────


class EnvironmentalSignal(BaseModel):
    """A single observed environmental signal."""

    signal_type: SignalType
    source: str = ""          # Tool or detector that produced the signal
    value: str = ""           # Signal value (e.g., WAF name, tech name)
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class TargetEnvironment(BaseModel):
    """Model of the target's environment, built from observations."""

    # Infrastructure
    waf_detected: bool = False
    waf_type: str = ""
    waf_aggressiveness: str = "unknown"   # passive | moderate | aggressive
    cdn_detected: bool = False
    cdn_type: str = ""
    custom_error_pages: bool = False

    # Rate limiting
    rate_limited: bool = False
    rate_limit_threshold_rps: float = 0.0  # Estimated max RPS before limiting
    rate_limit_recovery_seconds: float = 0.0

    # Technologies
    technologies: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    cms: str = ""
    web_server: str = ""

    # Authentication
    auth_required: bool = False
    auth_type: str = ""                    # basic | session | jwt | oauth | saml

    # Attack surface size
    subdomain_count: int = 0
    endpoint_count: int = 0
    parameter_count: int = 0

    # Health
    target_responsive: bool = True
    avg_response_time_ms: float = 0.0

    # Tool effectiveness observations
    blocked_tools: list[str] = Field(default_factory=list)
    effective_tools: list[str] = Field(default_factory=list)


class Adaptation(BaseModel):
    """A single strategy adaptation decision."""

    adaptation_id: str = ""
    priority: AdaptationPriority = AdaptationPriority.MEDIUM
    category: str = ""           # e.g., "rate_limit", "waf_evasion", "tool_config"
    description: str = ""
    trigger_signal: str = ""

    # What changes
    parameter_changes: dict[str, Any] = Field(default_factory=dict)
    tool_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)
    tools_to_add: list[str] = Field(default_factory=list)
    tools_to_remove: list[str] = Field(default_factory=list)
    mode_change: StrategyMode | None = None

    # Tracking
    applied: bool = False
    applied_at: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class ScanProfile(BaseModel):
    """Effective scan profile after all adaptations are applied."""

    mode: StrategyMode = StrategyMode.STANDARD

    # Rate limiting
    max_rps: float = 10.0               # Requests per second
    max_rps_per_host: float = 3.0       # Per-host RPS
    delay_between_requests_ms: int = 0   # Extra delay

    # Timeouts
    request_timeout_seconds: int = 30
    tool_timeout_seconds: int = 300

    # User agent & headers
    user_agent: str = ""
    custom_headers: dict[str, str] = Field(default_factory=dict)
    rotate_user_agents: bool = False

    # Payload configuration
    payload_encoding: list[str] = Field(default_factory=list)  # url, double-url, html, unicode
    waf_evasion_enabled: bool = False
    payload_obfuscation: bool = False

    # Threading
    max_parallel_tools: int = 5
    max_concurrent_requests: int = 10

    # Scope
    follow_redirects: bool = True
    max_redirect_depth: int = 3
    test_parameters: bool = True

    # Tool selection hints
    preferred_tools: list[str] = Field(default_factory=list)
    disabled_tools: list[str] = Field(default_factory=list)
    tool_specific_options: dict[str, dict[str, Any]] = Field(default_factory=dict)


# ────────────────────────────────────────────────────────────
# Technology → Tool Recommendations
# ────────────────────────────────────────────────────────────

TECH_SPECIFIC_TOOLS: dict[str, list[dict[str, Any]]] = {
    "wordpress": [
        {"tool": "wpscan", "priority": "critical", "reason": "WordPress-specific scanner"},
    ],
    "php": [
        {"tool": "sqlmap", "priority": "high", "reason": "PHP apps commonly vulnerable to SQLi"},
        {"tool": "tplmap", "priority": "medium", "reason": "PHP template injection"},
    ],
    "node.js": [
        {"tool": "nuclei", "priority": "high", "reason": "Check for prototype pollution, SSRF"},
        {"tool": "jwt_tool", "priority": "medium", "reason": "Node apps often use JWT"},
    ],
    "python": [
        {"tool": "tplmap", "priority": "high", "reason": "Jinja2/Django SSTI"},
        {"tool": "sqlmap", "priority": "medium", "reason": "ORM bypass / raw SQL"},
    ],
    "java": [
        {"tool": "nuclei", "priority": "high", "reason": "Deserialisation, Log4j, Spring vulns"},
    ],
    "asp.net": [
        {"tool": "nuclei", "priority": "high", "reason": "ViewState, IIS vulns"},
    ],
    "graphql": [
        {"tool": "graphql_introspection", "priority": "critical", "reason": "GraphQL enumeration"},
    ],
    "nginx": [
        {"tool": "nuclei", "priority": "medium", "reason": "Nginx misconfigurations"},
    ],
    "apache": [
        {"tool": "nuclei", "priority": "medium", "reason": "Apache misconfigurations, mod_*"},
    ],
    "react": [
        {"tool": "katana", "priority": "high", "reason": "SPA crawling for endpoints"},
    ],
    "angular": [
        {"tool": "katana", "priority": "high", "reason": "SPA crawling for endpoints"},
    ],
    "jwt": [
        {"tool": "jwt_tool", "priority": "critical", "reason": "JWT analysis & attacks"},
    ],
}

# WAF-specific evasion configurations
WAF_EVASION_CONFIGS: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "max_rps": 2,
        "delay_ms": 1000,
        "payload_encoding": ["double-url", "unicode"],
        "rotate_user_agents": True,
        "notes": "Cloudflare is aggressive; use very low request rate",
    },
    "akamai": {
        "max_rps": 3,
        "delay_ms": 500,
        "payload_encoding": ["url", "unicode"],
        "rotate_user_agents": True,
        "notes": "Akamai uses behavioural analysis",
    },
    "aws_waf": {
        "max_rps": 5,
        "delay_ms": 200,
        "payload_encoding": ["url"],
        "notes": "AWS WAF rules vary by configuration",
    },
    "imperva": {
        "max_rps": 2,
        "delay_ms": 1500,
        "payload_encoding": ["double-url", "html"],
        "rotate_user_agents": True,
        "notes": "Imperva is very strict",
    },
    "modsecurity": {
        "max_rps": 5,
        "delay_ms": 200,
        "payload_encoding": ["url", "unicode"],
        "notes": "ModSecurity rules depend on OWASP CRS version",
    },
    "unknown": {
        "max_rps": 3,
        "delay_ms": 500,
        "payload_encoding": ["url", "unicode"],
        "rotate_user_agents": True,
        "notes": "Unknown WAF — use conservative defaults",
    },
}


# ────────────────────────────────────────────────────────────
# Adaptive Strategy Engine
# ────────────────────────────────────────────────────────────


class AdaptiveStrategyEngine:
    """
    Dynamic strategy adjustment engine.

    Continuously adapts the scanning strategy based on environmental
    observations. Maintains a model of the target environment and
    produces a continuously updated ScanProfile.

    Usage::

        engine = AdaptiveStrategyEngine(initial_profile="balanced")

        # Feed signals during scanning
        engine.observe(SignalType.WAF_DETECTED, value="cloudflare")
        engine.observe(SignalType.RATE_LIMITED, details={"status": 429})
        engine.observe(SignalType.TECH_DETECTED, value="wordpress")

        # Get current effective profile
        profile = engine.get_effective_profile()
        print(profile.max_rps)  # → 2.0 (reduced due to WAF + rate limit)

        # Get tool-specific overrides
        overrides = engine.get_tool_config("sqlmap")
        # → {"tamper": "between,randomcase", "delay": 2, ...}
    """

    def __init__(
        self,
        initial_profile: str = "balanced",
        brain_engine: Any | None = None,
    ) -> None:
        self.brain_engine = brain_engine

        # Environmental model
        self.environment = TargetEnvironment()

        # Signal history
        self._signals: list[EnvironmentalSignal] = []

        # Adaptations (ordered by timestamp)
        self._adaptations: list[Adaptation] = []
        self._adaptation_counter = 0

        # Base profile (configured at start)
        self._base_profile = self._create_base_profile(initial_profile)

        # Current effective profile (after adaptations)
        self._effective_profile: ScanProfile | None = None

        # Technology-specific tools queued for addition
        self._tech_tools_queued: list[dict[str, Any]] = []

        logger.info(
            f"AdaptiveStrategyEngine initialized | profile={initial_profile}"
        )

    # ─── Signal Observation ──────────────────────────────────

    def observe(
        self,
        signal_type: SignalType,
        source: str = "",
        value: str = "",
        details: dict[str, Any] | None = None,
    ) -> list[Adaptation]:
        """
        Feed an environmental signal into the engine.

        Returns a list of new adaptations triggered by this signal.
        """
        signal = EnvironmentalSignal(
            signal_type=signal_type,
            source=source,
            value=value,
            details=details or {},
        )
        self._signals.append(signal)

        # Update environment model
        self._update_environment(signal)

        # Generate adaptations
        new_adaptations = self._react_to_signal(signal)

        for a in new_adaptations:
            self._adaptation_counter += 1
            a.adaptation_id = f"adapt_{self._adaptation_counter:04d}"
            self._adaptations.append(a)

        # Invalidate cached profile only if adaptations were generated
        if new_adaptations:
            self._effective_profile = None

        if new_adaptations:
            logger.info(
                f"Strategy adapted | signal={signal_type} | "
                f"new_adaptations={len(new_adaptations)} | "
                f"value={value}"
            )

        return new_adaptations

    def observe_batch(
        self,
        signals: list[EnvironmentalSignal],
    ) -> list[Adaptation]:
        """Feed multiple signals at once."""
        all_adaptations: list[Adaptation] = []
        for sig in signals:
            adaptations = self.observe(
                signal_type=sig.signal_type,
                source=sig.source,
                value=sig.value,
                details=sig.details,
            )
            all_adaptations.extend(adaptations)
        return all_adaptations

    # ─── Profile Queries ─────────────────────────────────────

    def get_effective_profile(self) -> ScanProfile:
        """
        Get the current effective scan profile.

        This is the base profile with all adaptations applied.
        Cached until a new signal invalidates it.
        """
        if self._effective_profile is not None:
            return self._effective_profile

        profile = self._base_profile.model_copy(deep=True)
        self._apply_adaptations(profile)
        self._effective_profile = profile
        return profile

    def get_tool_config(self, tool_name: str) -> dict[str, Any]:
        """
        Get tool-specific configuration overrides.

        Combines base tool options with environmental adaptations.
        """
        profile = self.get_effective_profile()
        config: dict[str, Any] = {}

        # Base tool-specific options
        config.update(profile.tool_specific_options.get(tool_name, {}))

        # WAF evasion per tool
        if profile.waf_evasion_enabled:
            config.update(self._get_waf_evasion_for_tool(tool_name))

        # Rate limit adjustments
        config["rate_limit_rps"] = profile.max_rps_per_host
        config["request_timeout"] = profile.request_timeout_seconds

        # User agent
        if profile.user_agent:
            config["user_agent"] = profile.user_agent

        return config

    def get_recommended_tools(self) -> list[dict[str, Any]]:
        """
        Get tools recommended based on detected technologies.

        Returns tool recommendations sorted by priority.
        """
        recommendations: list[dict[str, Any]] = []
        seen_tools: set[str] = set()

        for tech in self.environment.technologies + self.environment.frameworks:
            tech_lower = tech.lower()
            for key, tools in TECH_SPECIFIC_TOOLS.items():
                if key in tech_lower:
                    for tool_rec in tools:
                        if tool_rec["tool"] not in seen_tools:
                            recommendations.append({
                                **tool_rec,
                                "trigger_tech": tech,
                            })
                            seen_tools.add(tool_rec["tool"])

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(
            key=lambda r: priority_order.get(r.get("priority", "low"), 3)
        )

        return recommendations

    def should_skip_tool(self, tool_name: str) -> tuple[bool, str]:
        """
        Check if a tool should be skipped based on current environment.

        Returns (should_skip, reason).
        """
        profile = self.get_effective_profile()

        if tool_name in profile.disabled_tools:
            return True, "Disabled by strategy adaptation"

        if tool_name in self.environment.blocked_tools:
            return True, "Previously blocked by target defences"

        return False, ""

    # ─── Strategy Explanation ────────────────────────────────

    def explain(self) -> dict[str, Any]:
        """
        Produce a human-readable explanation of the current strategy.

        Useful for logging, debugging, and user transparency.
        """
        profile = self.get_effective_profile()

        return {
            "current_mode": profile.mode,
            "reason_for_mode": self._explain_mode_choice(),
            "environmental_model": {
                "waf": f"{self.environment.waf_type or 'none'} "
                       f"(aggressive={self.environment.waf_aggressiveness})"
                if self.environment.waf_detected
                else "none",
                "cdn": self.environment.cdn_type or "none",
                "rate_limited": self.environment.rate_limited,
                "technologies": self.environment.technologies,
                "auth_required": self.environment.auth_required,
                "blocked_tools": self.environment.blocked_tools,
                "effective_tools": self.environment.effective_tools,
            },
            "effective_settings": {
                "max_rps": profile.max_rps,
                "max_rps_per_host": profile.max_rps_per_host,
                "delay_ms": profile.delay_between_requests_ms,
                "waf_evasion": profile.waf_evasion_enabled,
                "payload_encoding": profile.payload_encoding,
                "parallel_tools": profile.max_parallel_tools,
            },
            "signals_observed": len(self._signals),
            "adaptations_made": len(self._adaptations),
            "tech_tools_recommended": len(self.get_recommended_tools()),
        }

    # ─── Internal: Environment Update ────────────────────────

    def _update_environment(self, signal: EnvironmentalSignal) -> None:
        """Update the target environment model from a signal."""
        env = self.environment

        match signal.signal_type:
            case SignalType.WAF_DETECTED:
                env.waf_detected = True
                env.waf_type = signal.value or env.waf_type
                env.waf_aggressiveness = signal.details.get(
                    "aggressiveness", "moderate"
                )

            case SignalType.WAF_BLOCKING:
                env.waf_detected = True
                env.waf_aggressiveness = "aggressive"

            case SignalType.RATE_LIMITED:
                env.rate_limited = True
                env.rate_limit_threshold_rps = signal.details.get(
                    "threshold_rps", 0
                )

            case SignalType.CDN_DETECTED:
                env.cdn_detected = True
                env.cdn_type = signal.value

            case SignalType.TECH_DETECTED:
                tech = signal.value.lower()
                if tech and tech not in env.technologies:
                    env.technologies.append(tech)
                # Classify
                frameworks = {"django", "flask", "express", "spring", "laravel", "rails", "nextjs"}
                languages = {"php", "python", "java", "ruby", "go", "node.js", "c#"}
                cms_list = {"wordpress", "joomla", "drupal", "magento", "shopify"}
                servers = {"nginx", "apache", "iis", "lighttpd", "caddy"}

                if tech in frameworks and tech not in env.frameworks:
                    env.frameworks.append(tech)
                if tech in languages and tech not in env.languages:
                    env.languages.append(tech)
                if tech in cms_list:
                    env.cms = tech
                if tech in servers:
                    env.web_server = tech

            case SignalType.AUTH_REQUIRED:
                env.auth_required = True
                env.auth_type = signal.value or signal.details.get("type", "")

            case SignalType.TOOL_BLOCKED:
                tool = signal.value or signal.source
                if tool and tool not in env.blocked_tools:
                    env.blocked_tools.append(tool)

            case SignalType.TOOL_SUCCESS:
                tool = signal.value or signal.source
                if tool and tool not in env.effective_tools:
                    env.effective_tools.append(tool)

            case SignalType.TARGET_DOWN:
                env.target_responsive = False

            case SignalType.SUBDOMAIN_FOUND:
                try:
                    env.subdomain_count += int(signal.details.get("count", 1))
                except (ValueError, TypeError):
                    env.subdomain_count += 1

            case SignalType.ENDPOINT_FOUND:
                try:
                    env.endpoint_count += int(signal.details.get("count", 1))
                except (ValueError, TypeError):
                    env.endpoint_count += 1

            case SignalType.CUSTOM_ERROR_PAGE:
                env.custom_error_pages = True

    # ─── Internal: Signal Reaction ───────────────────────────

    def _react_to_signal(self, signal: EnvironmentalSignal) -> list[Adaptation]:
        """Generate adaptations in response to a signal."""
        adaptations: list[Adaptation] = []

        match signal.signal_type:
            case SignalType.WAF_DETECTED | SignalType.WAF_BLOCKING:
                adaptations.extend(self._adapt_for_waf(signal))

            case SignalType.RATE_LIMITED:
                adaptations.append(self._adapt_for_rate_limit(signal))

            case SignalType.TECH_DETECTED:
                adaptations.extend(self._adapt_for_technology(signal))

            case SignalType.TOOL_BLOCKED:
                adaptations.append(self._adapt_for_blocked_tool(signal))

            case SignalType.TOOL_FAILED:
                adaptations.append(self._adapt_for_tool_failure(signal))

            case SignalType.HIGH_FP_RATE:
                adaptations.append(self._adapt_for_high_fp_rate())

            case SignalType.ZERO_FINDINGS:
                adaptations.append(self._adapt_for_zero_findings(signal))

            case SignalType.TARGET_DOWN:
                adaptations.append(self._adapt_for_target_down())

            case SignalType.LARGE_ATTACK_SURFACE:
                adaptations.append(self._adapt_for_large_surface())

            case SignalType.AUTH_REQUIRED:
                adaptations.extend(self._adapt_for_auth(signal))

        return adaptations

    def _adapt_for_waf(self, signal: EnvironmentalSignal) -> list[Adaptation]:
        """Adapt strategy for WAF detection."""
        waf_type = (signal.value or "unknown").lower()
        _default_waf_config = {"max_rps": 3, "delay_ms": 500, "payload_encoding": ["url"], "techniques": ["case_variation"]}
        config = WAF_EVASION_CONFIGS.get(
            waf_type, WAF_EVASION_CONFIGS.get("unknown", _default_waf_config)
        )

        adaptations: list[Adaptation] = []

        # Reduce speed
        adaptations.append(Adaptation(
            priority=AdaptationPriority.CRITICAL,
            category="rate_limit",
            description=f"WAF detected ({waf_type}). Reducing request rate.",
            trigger_signal=str(signal.signal_type),
            parameter_changes={
                "max_rps": config["max_rps"],
                "delay_between_requests_ms": config.get("delay_ms", 500),
            },
        ))

        # Enable WAF evasion
        adaptations.append(Adaptation(
            priority=AdaptationPriority.HIGH,
            category="waf_evasion",
            description=f"Enabling WAF evasion techniques for {waf_type}.",
            trigger_signal=str(signal.signal_type),
            parameter_changes={
                "waf_evasion_enabled": True,
                "payload_encoding": config.get("payload_encoding", ["url"]),
                "payload_obfuscation": True,
                "rotate_user_agents": config.get("rotate_user_agents", False),
            },
        ))

        # Mode switch
        if signal.signal_type == SignalType.WAF_BLOCKING:
            adaptations.append(Adaptation(
                priority=AdaptationPriority.CRITICAL,
                category="mode_change",
                description="WAF is actively blocking — switching to stealth mode.",
                trigger_signal=str(signal.signal_type),
                mode_change=StrategyMode.WAF_EVASION,
            ))

        return adaptations

    def _adapt_for_rate_limit(self, signal: EnvironmentalSignal) -> Adaptation:
        """Adapt for rate limiting."""
        current_rps = self.get_effective_profile().max_rps
        new_rps = max(0.5, current_rps * 0.5)  # Halve the rate

        return Adaptation(
            priority=AdaptationPriority.CRITICAL,
            category="rate_limit",
            description=f"Rate limited. Reducing RPS from {current_rps} to {new_rps}.",
            trigger_signal=str(signal.signal_type),
            parameter_changes={
                "max_rps": new_rps,
                "max_rps_per_host": max(0.5, new_rps / 3),
                "delay_between_requests_ms": max(1000, 1000 / new_rps),
            },
        )

    def _adapt_for_technology(
        self, signal: EnvironmentalSignal
    ) -> list[Adaptation]:
        """Add technology-specific tools and checks."""
        tech = signal.value.lower()
        adaptations: list[Adaptation] = []

        for key, tools in TECH_SPECIFIC_TOOLS.items():
            if key in tech:
                for tool_rec in tools:
                    # Don't add if already in blocked list
                    if tool_rec["tool"] not in self.environment.blocked_tools:
                        adaptations.append(Adaptation(
                            priority=AdaptationPriority.MEDIUM,
                            category="tool_recommendation",
                            description=(
                                f"Technology '{tech}' detected — "
                                f"recommending {tool_rec['tool']} "
                                f"({tool_rec['reason']})."
                            ),
                            trigger_signal=str(signal.signal_type),
                            tools_to_add=[tool_rec["tool"]],
                        ))

        return adaptations

    def _adapt_for_blocked_tool(self, signal: EnvironmentalSignal) -> Adaptation:
        """Suggest alternatives for a blocked tool."""
        tool = signal.value or signal.source

        # Tool → alternative mapping
        alternatives_map: dict[str, list[str]] = {
            "sqlmap": ["nuclei"],
            "nmap": ["rustscan", "masscan"],
            "ffuf": ["feroxbuster", "gobuster"],
            "dalfox": ["xsstrike"],
            "subfinder": ["amass", "assetfinder"],
            "katana": ["gospider", "hakrawler"],
        }

        alternatives = alternatives_map.get(tool, [])

        return Adaptation(
            priority=AdaptationPriority.HIGH,
            category="tool_substitution",
            description=f"{tool} blocked by target. Suggesting alternatives: {alternatives}.",
            trigger_signal=str(signal.signal_type),
            tools_to_remove=[tool],
            tools_to_add=alternatives,
        )

    def _adapt_for_tool_failure(self, signal: EnvironmentalSignal) -> Adaptation:
        """Handle a tool failure gracefully."""
        tool = signal.value or signal.source
        error = signal.details.get("error", "")

        return Adaptation(
            priority=AdaptationPriority.MEDIUM,
            category="tool_failure",
            description=f"{tool} failed: {error[:100]}. Flagged for retry/replacement.",
            trigger_signal=str(signal.signal_type),
            parameter_changes={
                "retry_tool": tool,
                "retry_with_timeout": signal.details.get("timeout", 600),
            },
        )

    def _adapt_for_high_fp_rate(self) -> Adaptation:
        """Tighten verification when FP rate is too high."""
        return Adaptation(
            priority=AdaptationPriority.HIGH,
            category="verification",
            description="High false positive rate detected. Tightening verification.",
            trigger_signal=str(SignalType.HIGH_FP_RATE),
            parameter_changes={
                "min_confidence_threshold": 70,
                "require_multi_tool_confirm": True,
                "min_tools_for_confirm": 2,
            },
        )

    def _adapt_for_zero_findings(self, signal: EnvironmentalSignal) -> Adaptation:
        """When a stage produces zero findings, suggest broader testing."""
        stage = signal.details.get("stage", "unknown")

        return Adaptation(
            priority=AdaptationPriority.MEDIUM,
            category="coverage",
            description=(
                f"Zero findings in {stage}. Target may be well-hardened. "
                "Consider deeper testing or different approach."
            ),
            trigger_signal=str(signal.signal_type),
            parameter_changes={
                "enable_custom_checks": True,
                "try_business_logic_tests": True,
            },
            tools_to_add=["nuclei", "arjun"],
        )

    def _adapt_for_target_down(self) -> Adaptation:
        """Handle an unresponsive target."""
        return Adaptation(
            priority=AdaptationPriority.CRITICAL,
            category="health",
            description="Target appears to be down. Pausing scan and waiting.",
            trigger_signal=str(SignalType.TARGET_DOWN),
            parameter_changes={
                "pause_scanning": True,
                "retry_after_seconds": 300,
            },
        )

    def _adapt_for_large_surface(self) -> Adaptation:
        """Optimise for a large attack surface."""
        return Adaptation(
            priority=AdaptationPriority.MEDIUM,
            category="optimisation",
            description=(
                "Large attack surface detected. "
                "Prioritising high-value targets and reducing breadth."
            ),
            trigger_signal=str(SignalType.LARGE_ATTACK_SURFACE),
            parameter_changes={
                "max_parallel_tools": 8,
                "prioritise_critical_endpoints": True,
                "max_endpoints_per_tool": 100,
            },
        )

    def _adapt_for_auth(
        self, signal: EnvironmentalSignal
    ) -> list[Adaptation]:
        """Handle authentication requirements."""
        auth_type = signal.value or signal.details.get("type", "")
        adaptations: list[Adaptation] = []

        adaptations.append(Adaptation(
            priority=AdaptationPriority.HIGH,
            category="auth",
            description=f"Authentication required ({auth_type}). Adding auth-focused tools.",
            trigger_signal=str(signal.signal_type),
            tools_to_add=["jwt_tool"] if "jwt" in auth_type.lower() else [],
            parameter_changes={
                "auth_type": auth_type,
                "prioritise_auth_testing": True,
            },
        ))

        if auth_type.lower() == "jwt":
            adaptations.append(Adaptation(
                priority=AdaptationPriority.HIGH,
                category="mode_change",
                description="JWT auth detected — switching to auth-focused mode.",
                trigger_signal=str(signal.signal_type),
                mode_change=StrategyMode.AUTH_FOCUSED,
            ))

        return adaptations

    # ─── Internal: Apply Adaptations ─────────────────────────

    def _apply_adaptations(self, profile: ScanProfile) -> None:
        """Apply all adaptations to a profile (in order)."""
        for adaptation in self._adaptations:
            if adaptation.applied:
                continue

            params = adaptation.parameter_changes

            # Mode change
            if adaptation.mode_change:
                profile.mode = adaptation.mode_change

            # Rate limit changes — allow both reduction (from rate limiting)
            # and recovery (from stable conditions)
            if "max_rps" in params:
                new_rps = params["max_rps"]
                if adaptation.description and "recover" in adaptation.description.lower():
                    # Recovery: allow increasing rate (but cap at base profile)
                    profile.max_rps = min(self._base_profile.max_rps, max(profile.max_rps, new_rps))
                else:
                    # Throttle: only decrease
                    profile.max_rps = min(profile.max_rps, new_rps)
            if "max_rps_per_host" in params:
                new_rps_host = params["max_rps_per_host"]
                if adaptation.description and "recover" in adaptation.description.lower():
                    profile.max_rps_per_host = min(
                        self._base_profile.max_rps_per_host,
                        max(profile.max_rps_per_host, new_rps_host),
                    )
                else:
                    profile.max_rps_per_host = min(
                        profile.max_rps_per_host, new_rps_host
                    )
            if "delay_between_requests_ms" in params:
                profile.delay_between_requests_ms = max(
                    profile.delay_between_requests_ms,
                    int(params["delay_between_requests_ms"]),
                )

            # WAF evasion
            if params.get("waf_evasion_enabled"):
                profile.waf_evasion_enabled = True
            if params.get("payload_obfuscation"):
                profile.payload_obfuscation = True
            if params.get("rotate_user_agents"):
                profile.rotate_user_agents = True
            if "payload_encoding" in params:
                for enc in params["payload_encoding"]:
                    if enc not in profile.payload_encoding:
                        profile.payload_encoding.append(enc)

            # Tool changes
            for tool in adaptation.tools_to_add:
                if tool not in profile.preferred_tools:
                    profile.preferred_tools.append(tool)
            for tool in adaptation.tools_to_remove:
                if tool not in profile.disabled_tools:
                    profile.disabled_tools.append(tool)

            # Tool-specific overrides
            for tool_name, overrides in adaptation.tool_overrides.items():
                existing = profile.tool_specific_options.get(tool_name, {})
                existing.update(overrides)
                profile.tool_specific_options[tool_name] = existing

            # Threading
            if "max_parallel_tools" in params:
                profile.max_parallel_tools = params["max_parallel_tools"]

            adaptation.applied = True
            adaptation.applied_at = time.time()

    # ─── Internal: WAF Evasion Per Tool ──────────────────────

    def _get_waf_evasion_for_tool(self, tool_name: str) -> dict[str, Any]:
        """Get WAF evasion parameters for a specific tool."""
        config: dict[str, Any] = {}
        waf_type = self.environment.waf_type.lower()

        tool_lower = tool_name.lower()

        if tool_lower == "sqlmap":
            config["tamper"] = "between,randomcase,space2comment"
            config["random-agent"] = True
            config["delay"] = 2
            if "cloudflare" in waf_type:
                config["tamper"] += ",charunicodeencode"

        elif tool_lower == "nuclei":
            config["rate-limit"] = max(
                1, int(self.get_effective_profile().max_rps)
            )
            config["retries"] = 2

        elif tool_lower in ("ffuf", "feroxbuster", "gobuster"):
            config["rate"] = max(1, int(self.get_effective_profile().max_rps * 2))
            config["timeout"] = 30

        elif tool_lower in ("dalfox", "xsstrike"):
            config["delay"] = 2
            config["timeout"] = 30

        return config

    # ─── Internal: Mode Explanation ──────────────────────────

    def _explain_mode_choice(self) -> str:
        """Explain why the current mode was chosen."""
        mode = self.get_effective_profile().mode

        match mode:
            case StrategyMode.WAF_EVASION:
                return (
                    f"WAF detected ({self.environment.waf_type}). "
                    "Using evasion techniques and reduced speed."
                )
            case StrategyMode.STEALTH:
                return "Stealth mode: low-profile scanning to avoid detection."
            case StrategyMode.AGGRESSIVE:
                return "Aggressive mode: maximising coverage and speed."
            case StrategyMode.DEEP_DIVE:
                return "Deep dive: focused testing on specific areas."
            case StrategyMode.API_FOCUSED:
                return "API-focused: prioritising API endpoint testing."
            case StrategyMode.AUTH_FOCUSED:
                return "Auth-focused: prioritising authentication/authorisation testing."
            case StrategyMode.STANDARD:
                return "Standard balanced scanning profile."

        return "No specific mode selected."

    # ─── Internal: Base Profile Creation ─────────────────────

    @staticmethod
    def _create_base_profile(profile_name: str) -> ScanProfile:
        """Create a base ScanProfile from a named profile."""
        profiles: dict[str, dict[str, Any]] = {
            "stealth": {
                "mode": StrategyMode.STEALTH,
                "max_rps": 2.0,
                "max_rps_per_host": 1.0,
                "delay_between_requests_ms": 1000,
                "max_parallel_tools": 2,
                "max_concurrent_requests": 3,
                "rotate_user_agents": True,
            },
            "balanced": {
                "mode": StrategyMode.STANDARD,
                "max_rps": 10.0,
                "max_rps_per_host": 3.0,
                "delay_between_requests_ms": 0,
                "max_parallel_tools": 5,
                "max_concurrent_requests": 10,
            },
            "aggressive": {
                "mode": StrategyMode.AGGRESSIVE,
                "max_rps": 50.0,
                "max_rps_per_host": 15.0,
                "delay_between_requests_ms": 0,
                "max_parallel_tools": 10,
                "max_concurrent_requests": 30,
            },
        }

        config = profiles.get(profile_name, profiles["balanced"])
        return ScanProfile(**config)

    # ─── Reset ───────────────────────────────────────────────

    def reset(self) -> None:
        """Reset all state (for a new scan)."""
        self.environment = TargetEnvironment()
        self._signals.clear()
        self._adaptations.clear()
        self._effective_profile = None
        self._tech_tools_queued.clear()
        self._adaptation_counter = 0
        logger.debug("AdaptiveStrategyEngine reset")


__all__ = [
    "AdaptiveStrategyEngine",
    "TargetEnvironment",
    "EnvironmentalSignal",
    "Adaptation",
    "ScanProfile",
    "SignalType",
    "StrategyMode",
    "AdaptationPriority",
    "TECH_SPECIFIC_TOOLS",
    "WAF_EVASION_CONFIGS",
]
