"""
WhiteHatHacker AI — Attack Planner

Strategic attack planning module that creates prioritized,
phased attack plans based on discovered intelligence. Uses
technology stack analysis, vulnerability pattern matching,
and tool effectiveness data to build optimal attack strategies.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


class AttackPhase(str, Enum):
    QUICK_WINS = "quick_wins"                    # Low-effort, high-probability checks
    STANDARD_SCANNING = "standard_scanning"       # Comprehensive automated scanning
    DEEP_TESTING = "deep_testing"                 # Manual-like deep testing
    BUSINESS_LOGIC = "business_logic"             # Business logic & authorization
    CHAINED_ATTACKS = "chained_attacks"            # Multi-step attack chains


class Priority(str, Enum):
    CRITICAL = "critical"   # Must test — high probability, high impact
    HIGH = "high"          # Should test — good probability or high impact
    MEDIUM = "medium"      # Can test — moderate probability/impact
    LOW = "low"            # Nice to test — low priority or already covered
    SKIP = "skip"          # Skip — out of scope, unlikely, or redundant


class AttackTask(BaseModel):
    """A single actionable task in the attack plan."""

    task_id: str
    phase: AttackPhase
    priority: Priority

    # What to test
    title: str                     # e.g., "SQL Injection on /api/user?id="
    description: str = ""
    vuln_type: str = ""            # e.g., "sqli", "xss", "ssrf"
    target_endpoint: str = ""      # Specific URL/endpoint
    target_parameter: str = ""     # Specific parameter

    # How to test
    tools: list[str] = Field(default_factory=list)       # Tools to use (ordered)
    tool_options: dict[str, dict] = Field(default_factory=dict)  # Tool-specific options
    payloads: list[str] = Field(default_factory=list)    # Test payloads

    # Context
    reasoning: str = ""            # Why this task was selected
    prerequisites: list[str] = Field(default_factory=list)  # Tasks that must complete first
    estimated_time_seconds: int = 60
    risk_level: str = "low"        # Risk of disruption to target

    # Execution status
    status: str = "pending"        # pending, running, done, skipped, failed
    result: str = ""
    findings_count: int = 0
    completed_at: float = 0.0


class AttackPlan(BaseModel):
    """A complete attack plan for a target."""

    plan_id: str
    target: str
    technologies: list[str] = Field(default_factory=list)
    scan_profile: str = "balanced"

    # Phases and tasks
    tasks: list[AttackTask] = Field(default_factory=list)

    # Statistics
    total_estimated_time: int = 0    # seconds
    tasks_completed: int = 0
    tasks_total: int = 0
    findings_total: int = 0

    created: float = Field(default_factory=time.time)
    updated: float = Field(default_factory=time.time)


# ── Technology → Attack Vector Mapping ─────────────────────────────

TECH_VULN_MAP: dict[str, list[dict[str, Any]]] = {
    # Web Frameworks
    "php": [
        {"vuln": "sqli", "probability": "high", "tools": ["sqlmap"]},
        {"vuln": "lfi", "probability": "high", "tools": ["ffuf", "nuclei"]},
        {"vuln": "rce", "probability": "medium", "tools": ["commix"]},
        {"vuln": "file_upload", "probability": "medium", "tools": ["ffuf"]},
        {"vuln": "ssti", "probability": "low", "tools": ["commix"]},
    ],
    "wordpress": [
        {"vuln": "plugin_vulns", "probability": "high", "tools": ["wpscan"]},
        {"vuln": "sqli", "probability": "medium", "tools": ["wpscan", "sqlmap"]},
        {"vuln": "xss", "probability": "medium", "tools": ["wpscan"]},
        {"vuln": "auth_bypass", "probability": "medium", "tools": ["wpscan"]},
        {"vuln": "file_upload", "probability": "medium", "tools": ["wpscan"]},
    ],
    "node.js": [
        {"vuln": "nosqli", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "ssti", "probability": "medium", "tools": ["commix"]},
        {"vuln": "prototype_pollution", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "ssrf", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "xss", "probability": "medium", "tools": ["nuclei"]},
    ],
    "python": [
        {"vuln": "ssti", "probability": "high", "tools": ["commix"]},
        {"vuln": "ssrf", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "deserialization", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "sqli", "probability": "medium", "tools": ["sqlmap"]},
    ],
    "java": [
        {"vuln": "deserialization", "probability": "high", "tools": ["nuclei"]},
        {"vuln": "sqli", "probability": "medium", "tools": ["sqlmap"]},
        {"vuln": "ssti", "probability": "medium", "tools": ["commix"]},
        {"vuln": "xxe", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "log4j", "probability": "medium", "tools": ["nuclei"]},
    ],
    "asp.net": [
        {"vuln": "sqli", "probability": "medium", "tools": ["sqlmap"]},
        {"vuln": "viewstate_deser", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "path_traversal", "probability": "medium", "tools": ["ffuf"]},
        {"vuln": "xss", "probability": "medium", "tools": ["nuclei"]},
    ],
    # Databases
    "mysql": [
        {"vuln": "sqli", "probability": "high", "tools": ["sqlmap"]},
        {"vuln": "weak_auth", "probability": "medium", "tools": ["hydra", "nmap"]},
    ],
    "postgresql": [
        {"vuln": "sqli", "probability": "high", "tools": ["sqlmap"]},
        {"vuln": "weak_auth", "probability": "medium", "tools": ["hydra"]},
    ],
    "mongodb": [
        {"vuln": "nosqli", "probability": "high", "tools": ["nuclei"]},
        {"vuln": "unauthenticated_access", "probability": "medium", "tools": ["nmap"]},
    ],
    "redis": [
        {"vuln": "unauthenticated_access", "probability": "high", "tools": ["nmap"]},
        {"vuln": "ssrf_to_redis", "probability": "medium", "tools": ["nuclei"]},
    ],
    # Servers
    "nginx": [
        {"vuln": "misconfiguration", "probability": "medium", "tools": ["nikto", "nuclei"]},
        {"vuln": "path_traversal", "probability": "low", "tools": ["ffuf"]},
    ],
    "apache": [
        {"vuln": "misconfiguration", "probability": "medium", "tools": ["nikto", "nuclei"]},
        {"vuln": "mod_vulns", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "path_traversal", "probability": "low", "tools": ["ffuf"]},
    ],
    "iis": [
        {"vuln": "short_name", "probability": "medium", "tools": ["nuclei"]},
        {"vuln": "misconfiguration", "probability": "medium", "tools": ["nikto"]},
    ],
    # Services
    "ssh": [
        {"vuln": "weak_ciphers", "probability": "medium", "tools": ["ssh_audit", "nmap"]},
        {"vuln": "brute_force", "probability": "low", "tools": ["hydra"]},
    ],
    "smb": [
        {"vuln": "null_session", "probability": "medium", "tools": ["enum4linux", "netexec"]},
        {"vuln": "signing_disabled", "probability": "medium", "tools": ["netexec"]},
        {"vuln": "eternalblue", "probability": "low", "tools": ["nmap"]},
    ],
    "ftp": [
        {"vuln": "anonymous_access", "probability": "medium", "tools": ["nmap"]},
        {"vuln": "brute_force", "probability": "medium", "tools": ["hydra"]},
    ],
    "ldap": [
        {"vuln": "anonymous_bind", "probability": "medium", "tools": ["ldapsearch"]},
        {"vuln": "injection", "probability": "low", "tools": ["nuclei"]},
    ],
    "snmp": [
        {"vuln": "default_community", "probability": "high", "tools": ["snmpwalk"]},
    ],
}

# Quick win checks that should always be run
QUICK_WIN_CHECKS: list[dict[str, Any]] = [
    {
        "title": "Sensitive file exposure",
        "vuln_type": "info_disclosure",
        "description": "Check for exposed .git, .env, backups, configs",
        "tools": ["ffuf"],
        "tool_options": {
            "ffuf": {"mode": "dir", "wordlist": "sensitive_files"}
        },
        "estimated_time": 30,
    },
    {
        "title": "Security headers check",
        "vuln_type": "misconfiguration",
        "description": "Verify presence of security headers",
        "tools": ["httpx"],
        "estimated_time": 10,
    },
    {
        "title": "SSL/TLS configuration",
        "vuln_type": "crypto",
        "description": "Check for weak SSL/TLS configuration",
        "tools": ["sslscan"],
        "estimated_time": 20,
    },
    {
        "title": "Known CVE scan",
        "vuln_type": "known_vuln",
        "description": "Scan for known CVEs based on detected versions",
        "tools": ["nmap", "searchsploit"],
        "estimated_time": 60,
    },
    {
        "title": "Default credentials check",
        "vuln_type": "auth",
        "description": "Check for default/common credentials on services",
        "tools": ["hydra"],
        "estimated_time": 30,
    },
    {
        "title": "CORS misconfiguration",
        "vuln_type": "cors",
        "description": "Test for overly permissive CORS policies",
        "tools": ["httpx"],
        "estimated_time": 15,
    },
    {
        "title": "Directory bruteforce",
        "vuln_type": "info_disclosure",
        "description": "Discover hidden directories and files",
        "tools": ["ffuf", "gobuster"],
        "estimated_time": 120,
    },
]


class AttackPlanner:
    """
    Strategic attack planning engine.

    Creates optimized, phased attack plans by combining:
    1. Technology stack analysis (what vulns are likely?)
    2. Vulnerability pattern matching (what indicators exist?)
    3. Tool effectiveness data (which tools work best?)
    4. Knowledge base (what worked before on similar targets?)
    5. Brain reasoning (deep strategic analysis)

    Plans are organized in phases:
    - Quick Wins: Fast, high-probability checks (< 5 min each)
    - Standard Scanning: Comprehensive automated scanning
    - Deep Testing: Targeted, manual-like testing
    - Business Logic: Authorization, workflow, race conditions
    - Chained Attacks: Multi-step exploitation
    """

    def __init__(
        self,
        brain_engine=None,
        knowledge_base=None,
        tool_registry=None,
        chain_of_thought=None,
    ):
        self._brain = brain_engine
        self._knowledge = knowledge_base
        self._registry = tool_registry
        self._cot = chain_of_thought

        self._plans: dict[str, AttackPlan] = {}
        self._task_counter = 0

    async def create_plan(
        self,
        target: str,
        technologies: list[str],
        endpoints: list[str] | None = None,
        parameters: list[str] | None = None,
        open_ports: list[int] | None = None,
        services: dict[int, str] | None = None,
        scan_profile: str = "balanced",
        existing_findings: list[str] | None = None,
    ) -> AttackPlan:
        """
        Create a comprehensive attack plan for a target.

        Args:
            target: Primary target (domain/IP)
            technologies: Detected technology stack
            endpoints: Discovered web endpoints
            parameters: Discovered parameters
            open_ports: Open ports from scanning
            services: Port → service mapping
            scan_profile: stealth/balanced/aggressive
            existing_findings: Already known findings

        Returns:
            AttackPlan with prioritized tasks
        """
        plan = AttackPlan(
            plan_id=f"plan_{target}_{int(time.time())}",
            target=target,
            technologies=technologies,
            scan_profile=scan_profile,
        )

        # Phase 1: Quick wins (always)
        self._add_quick_wins(plan, target, technologies)

        # Phase 2: Technology-based vulnerability scanning
        self._add_tech_based_tasks(plan, target, technologies, endpoints or [], parameters or [])

        # Phase 3: Service-based tasks (network services)
        if open_ports and services:
            self._add_service_tasks(plan, target, open_ports, services)

        # Phase 4: Deep testing for web endpoints
        if endpoints:
            self._add_deep_testing(plan, target, technologies, endpoints, parameters or [])

        # Phase 5: Business logic (if web application)
        if endpoints:
            self._add_business_logic_tasks(plan, target, endpoints)

        # Use brain for strategic prioritization if available
        if self._cot:
            try:
                strategic_plan = await self._cot.plan_attack(
                    target=target,
                    technology=technologies,
                    endpoints=endpoints or [],
                    parameters=parameters or [],
                    current_findings=existing_findings,
                )
                self._apply_brain_prioritization(plan, strategic_plan)
            except Exception as e:
                logger.warning(f"Brain planning failed: {e}")

        # Apply knowledge base insights
        if self._knowledge:
            self._apply_knowledge_insights(plan, target, technologies)

        # Sort tasks by priority and phase
        plan.tasks.sort(key=lambda t: (
            self._phase_order(t.phase),
            self._priority_order(t.priority),
        ))

        # Update statistics
        plan.tasks_total = len(plan.tasks)
        plan.total_estimated_time = sum(t.estimated_time_seconds for t in plan.tasks)

        self._plans[plan.plan_id] = plan

        logger.info(
            f"[Planner] Created plan for {target}: "
            f"{plan.tasks_total} tasks, ~{plan.total_estimated_time // 60} min estimated"
        )
        return plan

    def get_next_task(self, plan_id: str) -> AttackTask | None:
        """Get the next pending task in the plan, respecting prerequisites."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        completed_ids = {t.task_id for t in plan.tasks if t.status == "done"}

        for task in plan.tasks:
            if task.status != "pending":
                continue
            # Check prerequisites
            if task.prerequisites:
                if not all(p in completed_ids for p in task.prerequisites):
                    continue
            return task

        return None

    def mark_task_done(
        self,
        plan_id: str,
        task_id: str,
        findings_count: int = 0,
        result: str = "",
    ) -> None:
        """Mark a task as completed."""
        plan = self._plans.get(plan_id)
        if not plan:
            return

        for task in plan.tasks:
            if task.task_id == task_id:
                task.status = "done"
                task.findings_count = findings_count
                task.result = result
                task.completed_at = time.time()
                plan.tasks_completed += 1
                plan.findings_total += findings_count
                plan.updated = time.time()
                break

    def skip_task(self, plan_id: str, task_id: str, reason: str = "") -> None:
        """Skip a task."""
        plan = self._plans.get(plan_id)
        if not plan:
            return
        for task in plan.tasks:
            if task.task_id == task_id:
                task.status = "skipped"
                task.result = f"Skipped: {reason}"
                plan.updated = time.time()
                break

    def add_task(self, plan_id: str, task: AttackTask) -> None:
        """Dynamically add a task to an existing plan."""
        plan = self._plans.get(plan_id)
        if plan:
            plan.tasks.append(task)
            plan.tasks_total += 1
            plan.total_estimated_time += task.estimated_time_seconds
            plan.updated = time.time()

    def get_plan_progress(self, plan_id: str) -> dict:
        """Get current progress of a plan."""
        plan = self._plans.get(plan_id)
        if not plan:
            return {"error": "Plan not found"}

        statuses = {}
        for task in plan.tasks:
            statuses[task.status] = statuses.get(task.status, 0) + 1

        return {
            "plan_id": plan_id,
            "target": plan.target,
            "progress": f"{plan.tasks_completed}/{plan.tasks_total}",
            "percentage": round(plan.tasks_completed / max(1, plan.tasks_total) * 100, 1),
            "findings": plan.findings_total,
            "statuses": statuses,
            "estimated_remaining": sum(
                t.estimated_time_seconds for t in plan.tasks if t.status == "pending"
            ),
        }

    # ── Plan Building Methods ──────────────────────────────────────

    def _add_quick_wins(self, plan: AttackPlan, target: str, technologies: list[str]) -> None:
        """Add quick-win checks to the plan."""
        for check in QUICK_WIN_CHECKS:
            # Verify tools are available
            available_tools = self._filter_available_tools(check["tools"])
            if not available_tools:
                continue

            self._task_counter += 1
            task = AttackTask(
                task_id=f"QW-{self._task_counter:04d}",
                phase=AttackPhase.QUICK_WINS,
                priority=Priority.HIGH,
                title=check["title"],
                description=check["description"],
                vuln_type=check["vuln_type"],
                target_endpoint=target,
                tools=available_tools,
                tool_options=check.get("tool_options", {}),
                reasoning="Standard quick-win check (high ROI, low effort)",
                estimated_time_seconds=check["estimated_time"],
                risk_level="low",
            )
            plan.tasks.append(task)

    def _add_tech_based_tasks(
        self,
        plan: AttackPlan,
        target: str,
        technologies: list[str],
        endpoints: list[str],
        parameters: list[str],
    ) -> None:
        """Add tasks based on detected technology stack."""
        for tech in technologies:
            tech_lower = tech.lower()
            vulns = TECH_VULN_MAP.get(tech_lower, [])

            for vuln_info in vulns:
                available_tools = self._filter_available_tools(vuln_info["tools"])
                if not available_tools:
                    continue

                prob = vuln_info["probability"]
                priority = {
                    "high": Priority.HIGH,
                    "medium": Priority.MEDIUM,
                    "low": Priority.LOW,
                }.get(prob, Priority.MEDIUM)

                self._task_counter += 1

                # Determine target endpoints for this vuln type
                target_ep = target
                target_param = ""
                if vuln_info["vuln"] in ("sqli", "xss", "ssti", "ssrf", "cmdi") and endpoints:
                    target_ep = endpoints[0] if endpoints else target
                if vuln_info["vuln"] in ("sqli", "xss", "ssti") and parameters:
                    target_param = parameters[0] if parameters else ""

                task = AttackTask(
                    task_id=f"TS-{self._task_counter:04d}",
                    phase=AttackPhase.STANDARD_SCANNING,
                    priority=priority,
                    title=f"{vuln_info['vuln'].upper()} scan ({tech})",
                    description=f"Test for {vuln_info['vuln']} based on {tech} detection",
                    vuln_type=vuln_info["vuln"],
                    target_endpoint=target_ep,
                    target_parameter=target_param,
                    tools=available_tools,
                    reasoning=f"{tech} detected → {vuln_info['vuln']} probability: {prob}",
                    estimated_time_seconds=120 if prob == "high" else 60,
                    risk_level="low" if prob != "high" else "medium",
                )
                plan.tasks.append(task)

    def _add_service_tasks(
        self,
        plan: AttackPlan,
        target: str,
        open_ports: list[int],
        services: dict[int, str],
    ) -> None:
        """Add tasks for discovered network services."""
        service_tests: dict[str, list[dict]] = {
            "ssh": [
                {"title": "SSH audit", "tools": ["ssh_audit", "nmap"], "vuln": "weak_crypto", "time": 30},
            ],
            "smb": [
                {"title": "SMB enumeration", "tools": ["enum4linux", "netexec"], "vuln": "smb_misconfig", "time": 60},
                {"title": "SMB share access", "tools": ["smbclient"], "vuln": "anon_access", "time": 30},
            ],
            "ftp": [
                {"title": "FTP anonymous access", "tools": ["nmap"], "vuln": "anon_access", "time": 20},
                {"title": "FTP brute force", "tools": ["hydra"], "vuln": "weak_creds", "time": 120},
            ],
            "snmp": [
                {"title": "SNMP community strings", "tools": ["snmpwalk"], "vuln": "info_disclosure", "time": 30},
            ],
            "ldap": [
                {"title": "LDAP anonymous bind", "tools": ["ldapsearch"], "vuln": "anon_access", "time": 30},
            ],
            "http": [
                {"title": "Web vulnerability scan", "tools": ["nikto"], "vuln": "web_vuln", "time": 120},
            ],
            "https": [
                {"title": "Web vulnerability scan (HTTPS)", "tools": ["nikto"], "vuln": "web_vuln", "time": 120},
                {"title": "SSL/TLS scan", "tools": ["sslscan", "sslyze"], "vuln": "weak_crypto", "time": 30},
            ],
        }

        for port in open_ports:
            service = services.get(port, "unknown").lower()

            # Match service to tests
            for svc_key, tests in service_tests.items():
                if svc_key in service:
                    for test in tests:
                        available_tools = self._filter_available_tools(test["tools"])
                        if not available_tools:
                            continue

                        self._task_counter += 1
                        task = AttackTask(
                            task_id=f"SV-{self._task_counter:04d}",
                            phase=AttackPhase.STANDARD_SCANNING,
                            priority=Priority.MEDIUM,
                            title=f"{test['title']} (port {port})",
                            vuln_type=test["vuln"],
                            target_endpoint=f"{target}:{port}",
                            tools=available_tools,
                            reasoning=f"Service {service} on port {port}",
                            estimated_time_seconds=test["time"],
                            risk_level="low",
                        )
                        plan.tasks.append(task)

    def _add_deep_testing(
        self,
        plan: AttackPlan,
        target: str,
        technologies: list[str],
        endpoints: list[str],
        parameters: list[str],
    ) -> None:
        """Add deep testing tasks for specific endpoints."""
        # Prioritize interesting endpoints
        interesting_keywords = [
            "login", "auth", "admin", "api", "upload", "search",
            "user", "profile", "edit", "delete", "import", "export",
            "download", "file", "exec", "eval", "proxy", "redirect",
        ]

        high_priority_eps = []
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in interesting_keywords):
                high_priority_eps.append(ep)

        # For top endpoints, add parameter testing
        for ep in high_priority_eps[:10]:
            # SQL Injection testing
            if self._filter_available_tools(["sqlmap"]):
                self._task_counter += 1
                plan.tasks.append(AttackTask(
                    task_id=f"DT-{self._task_counter:04d}",
                    phase=AttackPhase.DEEP_TESTING,
                    priority=Priority.HIGH,
                    title=f"SQLi deep test on {ep}",
                    vuln_type="sqli",
                    target_endpoint=ep,
                    tools=["sqlmap"],
                    tool_options={"sqlmap": {"level": 3, "risk": 2}},
                    reasoning="High-interest endpoint with potential SQL injection points",
                    estimated_time_seconds=300,
                    risk_level="medium",
                ))

            # Command injection
            if self._filter_available_tools(["commix"]):
                self._task_counter += 1
                plan.tasks.append(AttackTask(
                    task_id=f"DT-{self._task_counter:04d}",
                    phase=AttackPhase.DEEP_TESTING,
                    priority=Priority.MEDIUM,
                    title=f"Command injection test on {ep}",
                    vuln_type="cmdi",
                    target_endpoint=ep,
                    tools=["commix"],
                    reasoning="Testing command injection on interesting endpoint",
                    estimated_time_seconds=180,
                    risk_level="medium",
                ))

    def _add_business_logic_tasks(
        self, plan: AttackPlan, target: str, endpoints: list[str]
    ) -> None:
        """Add business logic testing tasks."""
        # IDOR testing
        self._task_counter += 1
        plan.tasks.append(AttackTask(
            task_id=f"BL-{self._task_counter:04d}",
            phase=AttackPhase.BUSINESS_LOGIC,
            priority=Priority.HIGH,
            title=f"IDOR testing on {target}",
            vuln_type="idor",
            target_endpoint=target,
            tools=["custom_idor_checker"],
            reasoning="Authorization bypass is a high-impact vulnerability class",
            estimated_time_seconds=120,
            risk_level="low",
        ))

        # Rate limiting
        self._task_counter += 1
        plan.tasks.append(AttackTask(
            task_id=f"BL-{self._task_counter:04d}",
            phase=AttackPhase.BUSINESS_LOGIC,
            priority=Priority.MEDIUM,
            title=f"Rate limiting check on {target}",
            vuln_type="rate_limit",
            target_endpoint=target,
            tools=["custom_rate_limit_checker"],
            reasoning="Missing rate limiting enables brute force and DoS",
            estimated_time_seconds=60,
            risk_level="low",
        ))

        # Auth bypass
        self._task_counter += 1
        plan.tasks.append(AttackTask(
            task_id=f"BL-{self._task_counter:04d}",
            phase=AttackPhase.BUSINESS_LOGIC,
            priority=Priority.HIGH,
            title=f"Authentication bypass on {target}",
            vuln_type="auth_bypass",
            target_endpoint=target,
            tools=["custom_auth_bypass"],
            reasoning="Auth bypass is critical — direct access to protected resources",
            estimated_time_seconds=120,
            risk_level="low",
        ))

    # ── Intelligence Methods ───────────────────────────────────────

    def _apply_brain_prioritization(self, plan: AttackPlan, brain_result: dict) -> None:
        """Apply brain's strategic recommendations to plan priorities."""
        if not isinstance(brain_result, dict):
            return

        priority_targets = brain_result.get("priority_targets", [])
        avoid_list = brain_result.get("avoid", [])

        for task in plan.tasks:
            # Boost priority if brain recommends this target
            for pt in priority_targets:
                if isinstance(pt, dict):
                    if pt.get("endpoint", "") in task.target_endpoint:
                        task.priority = Priority.CRITICAL
                        task.reasoning += f" (Brain priority: {pt.get('test', '')})"

            # Lower priority if brain says to avoid
            for avoid in avoid_list:
                if isinstance(avoid, str) and avoid.lower() in task.title.lower():
                    task.priority = Priority.LOW
                    task.reasoning += " (Brain: may be time waste)"

    def _apply_knowledge_insights(
        self, plan: AttackPlan, target: str, technologies: list[str]
    ) -> None:
        """Apply knowledge base insights to plan."""
        if not self._knowledge:
            return

        # Check if we have previous intel on this target
        intel = self._knowledge.get_target_intel(target)
        if intel:
            # Skip known FPs
            for fp in intel.false_positives:
                for task in plan.tasks:
                    if fp.lower() in task.vuln_type.lower():
                        task.priority = Priority.LOW
                        task.reasoning += " (KB: known FP pattern)"

        # Boost tools with good track record
        for task in plan.tasks:
            for tool_name in task.tools:
                eff = self._knowledge.get_tool_effectiveness(tool_name)
                if eff and eff.effectiveness_score > 0.8:
                    task.reasoning += f" ({tool_name}: {eff.effectiveness_score:.0%} effective)"

    def _filter_available_tools(self, tools: list[str]) -> list[str]:
        """Filter tool list to only available ones."""
        if not self._registry:
            return tools  # Assume all available if no registry

        available = []
        for tool_name in tools:
            tool = self._registry.get(tool_name)
            if tool and tool.is_available():
                available.append(tool_name)
        if not available:
            logger.warning("No tools from requested list are available: %s", tools)
        return available

    @staticmethod
    def _phase_order(phase: AttackPhase) -> int:
        """Numeric ordering for attack phases."""
        return {
            AttackPhase.QUICK_WINS: 0,
            AttackPhase.STANDARD_SCANNING: 1,
            AttackPhase.DEEP_TESTING: 2,
            AttackPhase.BUSINESS_LOGIC: 3,
            AttackPhase.CHAINED_ATTACKS: 4,
        }.get(phase, 5)

    @staticmethod
    def _priority_order(priority: Priority) -> int:
        """Numeric ordering for priorities (lower = higher priority)."""
        return {
            Priority.CRITICAL: 0,
            Priority.HIGH: 1,
            Priority.MEDIUM: 2,
            Priority.LOW: 3,
            Priority.SKIP: 4,
        }.get(priority, 5)


__all__ = [
    "AttackPlanner",
    "AttackPlan",
    "AttackTask",
    "AttackPhase",
    "Priority",
    "TECH_VULN_MAP",
]
