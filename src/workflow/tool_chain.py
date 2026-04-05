"""
WhiteHatHacker AI — Tool Chain Intelligence

Intelligent tool sequencing engine that builds directed acyclic graphs
(DAGs) of tool dependencies and executes them with smart parameter
passing. A professional bug bounty hunter doesn't run tools randomly —
they follow a logical chain where each tool's output feeds the next.

Examples of tool chains:
    subfinder → httpx → katana → nuclei
    nmap → service_detector → searchsploit
    arjun → sqlmap → poc_generator
    waybackurls → ffuf → dalfox

Architecture:
    ToolChainEngine
    ├── register_chain()  ← define a named chain
    ├── resolve()         → compute execution plan from findings
    ├── next_tools()      → what should run next given current results
    ├── transform_output()→ adapt tool A's output for tool B's input
    └── get_chain_status()→ execution progress of active chain
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


class ChainNodeStatus(StrEnum):
    """Status of a single node in a chain."""

    PENDING = "pending"
    READY = "ready"        # All dependencies satisfied
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class DataType(StrEnum):
    """Types of data that flow between tools."""

    SUBDOMAINS = "subdomains"
    LIVE_HOSTS = "live_hosts"
    URLS = "urls"
    ENDPOINTS = "endpoints"
    PARAMETERS = "parameters"
    PORTS = "ports"
    PORT_SERVICES = "port_services"
    TECHNOLOGIES = "technologies"
    FINDINGS = "findings"
    IPS = "ips"
    EMAILS = "emails"
    JS_FILES = "js_files"
    API_SPECS = "api_specs"
    SCREENSHOTS = "screenshots"
    WORDLIST = "wordlist"
    RAW_TEXT = "raw_text"


class TriggerCondition(StrEnum):
    """When should a chain node trigger."""

    ALWAYS = "always"                     # Always run when deps satisfied
    IF_RESULTS = "if_results"             # Only if predecessor has results
    IF_TECH = "if_tech"                   # Only if specific tech detected
    IF_FINDING_TYPE = "if_finding_type"   # Only if specific finding type
    IF_PORT_OPEN = "if_port_open"         # Only if specific port open
    MANUAL = "manual"                     # Requires manual trigger


# ────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────


class DataPort(BaseModel):
    """
    Defines what data a tool produces or consumes.

    Used for automatic parameter wiring between tools.
    """

    name: str                                    # e.g., "target_urls"
    data_type: DataType                          # e.g., DataType.URLS
    description: str = ""
    required: bool = True                        # Must be available before run
    format_hint: str = ""                        # e.g., "one_per_line", "json"


class ChainNode(BaseModel):
    """A single tool in a chain DAG."""

    tool_name: str
    node_id: str = ""                            # Unique within chain

    # Dependencies
    depends_on: list[str] = Field(default_factory=list)  # Node IDs

    # I/O ports
    inputs: list[DataPort] = Field(default_factory=list)
    outputs: list[DataPort] = Field(default_factory=list)

    # Execution conditions
    trigger: TriggerCondition = TriggerCondition.ALWAYS
    trigger_value: str = ""                     # Tech name, port, vuln type, etc.

    # Tool configuration overrides
    tool_options: dict[str, Any] = Field(default_factory=dict)

    # Execution state
    status: ChainNodeStatus = ChainNodeStatus.PENDING
    started_at: float = 0.0
    finished_at: float = 0.0
    result_data: dict[str, Any] = Field(default_factory=dict)
    error: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.node_id:
            self.node_id = self.tool_name


class ToolChainDef(BaseModel):
    """
    Definition of a named tool chain (a DAG of nodes).

    Chains are templates that get instantiated when a scan starts.
    """

    chain_id: str
    name: str
    description: str = ""
    category: str = ""                           # recon | scan | exploit | full
    nodes: list[ChainNode] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ChainExecution(BaseModel):
    """Runtime state of a chain being executed."""

    chain_id: str
    chain_name: str = ""
    nodes: list[ChainNode] = Field(default_factory=list)

    # Shared data bus (tool outputs stored here keyed by node_id.port_name)
    data_bus: dict[str, Any] = Field(default_factory=dict)

    started_at: float = Field(default_factory=time.time)
    finished_at: float = 0.0
    completed: bool = False


# ────────────────────────────────────────────────────────────
# Pre-defined Tool Chains
# ────────────────────────────────────────────────────────────

def _build_default_chains() -> list[ToolChainDef]:
    """Build the library of pre-defined tool chains."""
    chains: list[ToolChainDef] = []

    # ── 1. Full Subdomain → Web Discovery chain ─────────
    chains.append(ToolChainDef(
        chain_id="subdomain_web_discovery",
        name="Subdomain → Web Discovery",
        description=(
            "Enumerate subdomains, probe for live hosts, "
            "crawl for URLs, and take screenshots."
        ),
        category="recon",
        nodes=[
            ChainNode(
                tool_name="subfinder",
                node_id="subfinder",
                outputs=[DataPort(name="subdomains", data_type=DataType.SUBDOMAINS)],
            ),
            ChainNode(
                tool_name="amass",
                node_id="amass",
                outputs=[DataPort(name="subdomains", data_type=DataType.SUBDOMAINS)],
            ),
            ChainNode(
                tool_name="assetfinder",
                node_id="assetfinder",
                outputs=[DataPort(name="subdomains", data_type=DataType.SUBDOMAINS)],
            ),
            ChainNode(
                tool_name="httpx",
                node_id="httpx",
                depends_on=["subfinder", "amass", "assetfinder"],
                inputs=[DataPort(name="targets", data_type=DataType.SUBDOMAINS, required=True)],
                outputs=[DataPort(name="live_hosts", data_type=DataType.LIVE_HOSTS)],
                trigger=TriggerCondition.IF_RESULTS,
            ),
            ChainNode(
                tool_name="katana",
                node_id="katana",
                depends_on=["httpx"],
                inputs=[DataPort(name="targets", data_type=DataType.LIVE_HOSTS, required=True)],
                outputs=[DataPort(name="urls", data_type=DataType.URLS)],
                trigger=TriggerCondition.IF_RESULTS,
            ),
            ChainNode(
                tool_name="gospider",
                node_id="gospider",
                depends_on=["httpx"],
                inputs=[DataPort(name="targets", data_type=DataType.LIVE_HOSTS, required=True)],
                outputs=[DataPort(name="urls", data_type=DataType.URLS)],
                trigger=TriggerCondition.IF_RESULTS,
            ),
        ],
        tags=["recon", "subdomain", "web"],
    ))

    # ── 2. Port Scan → Service Detection chain ──────────
    chains.append(ToolChainDef(
        chain_id="port_service_discovery",
        name="Port Scan → Service Detection",
        description="Fast port scan then detailed service version detection.",
        category="recon",
        nodes=[
            ChainNode(
                tool_name="rustscan",
                node_id="rustscan",
                outputs=[DataPort(name="open_ports", data_type=DataType.PORTS)],
            ),
            ChainNode(
                tool_name="nmap",
                node_id="nmap_version",
                depends_on=["rustscan"],
                inputs=[DataPort(name="ports", data_type=DataType.PORTS, required=True)],
                outputs=[
                    DataPort(name="services", data_type=DataType.PORT_SERVICES),
                    DataPort(name="technologies", data_type=DataType.TECHNOLOGIES),
                ],
                trigger=TriggerCondition.IF_RESULTS,
                tool_options={"scan_type": "version_scan", "script": "default"},
            ),
        ],
        tags=["recon", "port", "service"],
    ))

    # ── 3. URL Collection → Vulnerability Scan chain ────
    chains.append(ToolChainDef(
        chain_id="url_vuln_scan",
        name="URL Collection → Vuln Scan",
        description=(
            "Collect URLs from archives, discover parameters, "
            "then scan for SQL injection and XSS."
        ),
        category="scan",
        nodes=[
            ChainNode(
                tool_name="waybackurls",
                node_id="waybackurls",
                outputs=[DataPort(name="urls", data_type=DataType.URLS)],
            ),
            ChainNode(
                tool_name="gau",
                node_id="gau",
                outputs=[DataPort(name="urls", data_type=DataType.URLS)],
            ),
            ChainNode(
                tool_name="arjun",
                node_id="arjun",
                depends_on=["waybackurls", "gau"],
                inputs=[DataPort(name="urls", data_type=DataType.URLS, required=True)],
                outputs=[DataPort(name="parameters", data_type=DataType.PARAMETERS)],
                trigger=TriggerCondition.IF_RESULTS,
            ),
            ChainNode(
                tool_name="sqlmap",
                node_id="sqlmap",
                depends_on=["arjun"],
                inputs=[DataPort(name="targets", data_type=DataType.PARAMETERS, required=True)],
                outputs=[DataPort(name="sqli_findings", data_type=DataType.FINDINGS)],
                trigger=TriggerCondition.IF_RESULTS,
            ),
            ChainNode(
                tool_name="dalfox",
                node_id="dalfox",
                depends_on=["arjun"],
                inputs=[DataPort(name="targets", data_type=DataType.PARAMETERS, required=True)],
                outputs=[DataPort(name="xss_findings", data_type=DataType.FINDINGS)],
                trigger=TriggerCondition.IF_RESULTS,
            ),
        ],
        tags=["scan", "sqli", "xss", "url"],
    ))

    # ── 4. Directory Brute Force → Content Discovery ────
    chains.append(ToolChainDef(
        chain_id="directory_discovery",
        name="Directory Brute Force",
        description="Multi-tool directory and file discovery.",
        category="recon",
        nodes=[
            ChainNode(
                tool_name="ffuf",
                node_id="ffuf",
                outputs=[DataPort(name="endpoints", data_type=DataType.ENDPOINTS)],
                tool_options={"wordlist": "directories.txt"},
            ),
            ChainNode(
                tool_name="feroxbuster",
                node_id="feroxbuster",
                outputs=[DataPort(name="endpoints", data_type=DataType.ENDPOINTS)],
                tool_options={"wordlist": "directories.txt", "recursive": True},
            ),
        ],
        tags=["recon", "directory", "content"],
    ))

    # ── 5. Nuclei Full Scan chain ───────────────────────
    chains.append(ToolChainDef(
        chain_id="nuclei_full",
        name="Nuclei Comprehensive Scan",
        description="Comprehensive Nuclei template scan against discovered targets.",
        category="scan",
        nodes=[
            ChainNode(
                tool_name="nuclei",
                node_id="nuclei_critical",
                inputs=[DataPort(name="targets", data_type=DataType.LIVE_HOSTS, required=True)],
                outputs=[DataPort(name="findings", data_type=DataType.FINDINGS)],
                tool_options={"severity": "critical,high", "rate_limit": 10},
            ),
            ChainNode(
                tool_name="nuclei",
                node_id="nuclei_medium_low",
                depends_on=["nuclei_critical"],
                inputs=[DataPort(name="targets", data_type=DataType.LIVE_HOSTS, required=True)],
                outputs=[DataPort(name="findings", data_type=DataType.FINDINGS)],
                tool_options={"severity": "medium,low", "rate_limit": 15},
                trigger=TriggerCondition.ALWAYS,
            ),
        ],
        tags=["scan", "nuclei", "comprehensive"],
    ))

    # ── 6. API Security chain ───────────────────────────
    chains.append(ToolChainDef(
        chain_id="api_security",
        name="API Security Testing",
        description="Discover and test API endpoints for common vulnerabilities.",
        category="scan",
        nodes=[
            ChainNode(
                tool_name="swagger_parser",
                node_id="swagger_parser",
                outputs=[DataPort(name="api_spec", data_type=DataType.API_SPECS)],
                trigger=TriggerCondition.IF_TECH,
                trigger_value="swagger|openapi",
            ),
            ChainNode(
                tool_name="graphql_introspection",
                node_id="graphql_introspection",
                outputs=[DataPort(name="api_spec", data_type=DataType.API_SPECS)],
                trigger=TriggerCondition.IF_TECH,
                trigger_value="graphql",
            ),
            ChainNode(
                tool_name="jwt_tool",
                node_id="jwt_tool",
                outputs=[DataPort(name="jwt_findings", data_type=DataType.FINDINGS)],
                trigger=TriggerCondition.IF_TECH,
                trigger_value="jwt",
            ),
        ],
        tags=["scan", "api", "jwt", "graphql"],
    ))

    return chains


# ────────────────────────────────────────────────────────────
# Output Transformers
# ────────────────────────────────────────────────────────────

# How to transform tool A's output to tool B's input
_TRANSFORMER_MAP: dict[tuple[str, str], str] = {
    # (source_tool, dest_tool): transformer_key
    ("subfinder", "httpx"): "list_to_stdin",
    ("amass", "httpx"): "list_to_stdin",
    ("assetfinder", "httpx"): "list_to_stdin",
    ("httpx", "katana"): "list_to_stdin",
    ("httpx", "gospider"): "list_to_stdin",
    ("httpx", "nuclei"): "list_to_file",
    ("httpx", "ffuf"): "single_url",
    ("rustscan", "nmap"): "ports_to_flag",
    ("waybackurls", "arjun"): "urls_to_file",
    ("gau", "arjun"): "urls_to_file",
    ("arjun", "sqlmap"): "params_to_targets",
    ("arjun", "dalfox"): "urls_to_stdin",
    ("katana", "nuclei"): "list_to_file",
    ("gospider", "nuclei"): "list_to_file",
}


def transform_data(
    source_tool: str,
    dest_tool: str,
    data: Any,
    data_type: DataType,
) -> dict[str, Any]:
    """
    Transform output from source tool to input format for dest tool.

    Returns a dict of command-line arguments / stdin data for the
    destination tool.
    """
    key = (source_tool, dest_tool)
    transformer = _TRANSFORMER_MAP.get(key, "passthrough")

    result: dict[str, Any] = {}

    match transformer:
        case "list_to_stdin":
            # Tool reads target list from stdin
            if isinstance(data, list):
                result["stdin"] = "\n".join(str(d) for d in data)
            else:
                result["stdin"] = str(data)

        case "list_to_file":
            # Tool reads target list from a file
            if isinstance(data, list):
                result["target_list"] = data
                result["input_type"] = "file"
            else:
                result["target_list"] = [str(data)]
                result["input_type"] = "file"

        case "single_url":
            # Tool takes a single URL
            if isinstance(data, list) and data:
                result["url"] = data[0]
            else:
                result["url"] = str(data)

        case "ports_to_flag":
            # Convert port list to nmap -p flag
            if isinstance(data, list):
                result["ports_flag"] = ",".join(str(p) for p in data)
            elif isinstance(data, dict):
                # {host: [ports]} format
                all_ports: set[str] = set()
                for ports in data.values():
                    for p in ports:
                        all_ports.add(str(p))
                result["ports_flag"] = ",".join(sorted(all_ports))

        case "urls_to_file":
            if isinstance(data, list):
                result["url_file"] = data
                result["input_type"] = "file"
            else:
                result["url_file"] = [str(data)]

        case "params_to_targets":
            # Arjun output → sqlmap targets
            if isinstance(data, list):
                result["targets"] = data
            elif isinstance(data, dict):
                result["targets"] = [
                    {"url": url, "params": params}
                    for url, params in data.items()
                ]

        case "urls_to_stdin":
            if isinstance(data, list):
                result["stdin"] = "\n".join(str(u) for u in data)
            else:
                result["stdin"] = str(data)

        case _:  # passthrough
            result["data"] = data
            result["data_type"] = str(data_type)

    return result


# ────────────────────────────────────────────────────────────
# Tool Chain Engine
# ────────────────────────────────────────────────────────────


class ToolChainEngine:
    """
    Intelligent tool sequencing engine.

    Manages tool chain definitions, resolves execution order based on
    dependency graphs, and handles data flow between tools.

    Usage::

        engine = ToolChainEngine()

        # Get pre-defined chain
        chain = engine.get_chain("subdomain_web_discovery")

        # Start execution
        execution = engine.start_chain("subdomain_web_discovery", target="example.com")

        # After a tool completes, report its results
        engine.report_node_complete("subfinder", data={"subdomains": [...]})

        # Ask what to run next
        next_nodes = engine.next_tools(execution.chain_id)
        # → [ChainNode(tool_name="httpx", ...)]
    """

    def __init__(self) -> None:
        # Chain definitions library
        self._chain_defs: dict[str, ToolChainDef] = {}

        # Active chain executions
        self._executions: dict[str, ChainExecution] = {}

        # Register defaults
        for chain in _build_default_chains():
            self._chain_defs[chain.chain_id] = chain

        logger.info(
            f"ToolChainEngine initialized | "
            f"built_in_chains={len(self._chain_defs)}"
        )

    # ─── Chain Management ────────────────────────────────

    def register_chain(self, chain_def: ToolChainDef) -> None:
        """Register a new tool chain definition."""
        self._chain_defs[chain_def.chain_id] = chain_def
        logger.debug(f"Chain registered | id={chain_def.chain_id} | name={chain_def.name}")

    def get_chain(self, chain_id: str) -> ToolChainDef | None:
        """Get a chain definition by ID."""
        return self._chain_defs.get(chain_id)

    def list_chains(self, category: str | None = None) -> list[ToolChainDef]:
        """List all available chain definitions."""
        chains = list(self._chain_defs.values())
        if category:
            chains = [c for c in chains if c.category == category]
        return chains

    # ─── Chain Execution ─────────────────────────────────

    def start_chain(
        self,
        chain_id: str,
        initial_data: dict[str, Any] | None = None,
    ) -> ChainExecution | None:
        """
        Start executing a chain.

        Creates a ChainExecution instance with deep-copied nodes.
        Optionally pre-seeds the data bus with initial data.
        """
        chain_def = self._chain_defs.get(chain_id)
        if not chain_def:
            logger.error(f"Chain not found | id={chain_id}")
            return None

        # Deep copy nodes for this execution
        nodes = [node.model_copy(deep=True) for node in chain_def.nodes]

        execution = ChainExecution(
            chain_id=chain_id,
            chain_name=chain_def.name,
            nodes=nodes,
            data_bus=initial_data or {},
        )

        # Mark nodes with no dependencies as READY
        for node in execution.nodes:
            if not node.depends_on:
                node.status = ChainNodeStatus.READY

        self._executions[chain_id] = execution

        logger.info(
            f"Chain started | id={chain_id} | name={chain_def.name} | "
            f"nodes={len(nodes)}"
        )

        return execution

    def next_tools(self, chain_id: str) -> list[ChainNode]:
        """
        Get the next tools that should be executed.

        Returns nodes whose dependencies are all satisfied and
        whose trigger conditions are met.
        """
        execution = self._executions.get(chain_id)
        if not execution:
            return []

        ready: list[ChainNode] = []

        for node in execution.nodes:
            if node.status != ChainNodeStatus.PENDING:
                if node.status == ChainNodeStatus.READY:
                    ready.append(node)
                continue

            # Check if all dependencies are satisfied
            deps_satisfied = all(
                self._get_node(execution, dep_id) is not None
                and self._get_node(execution, dep_id).status == ChainNodeStatus.COMPLETED  # type: ignore[union-attr]
                for dep_id in node.depends_on
            )

            if not deps_satisfied:
                continue

            # Check trigger condition
            if self._check_trigger(execution, node):
                node.status = ChainNodeStatus.READY
                ready.append(node)
            else:
                node.status = ChainNodeStatus.SKIPPED
                logger.debug(
                    f"Node skipped (trigger not met) | "
                    f"chain={chain_id} | node={node.node_id}"
                )

        return ready

    def get_input_data(
        self,
        chain_id: str,
        node_id: str,
    ) -> dict[str, Any]:
        """
        Get the input data for a node, assembled from the data bus.

        Automatically transforms data from predecessor outputs to
        this node's expected input format.
        """
        execution = self._executions.get(chain_id)
        if not execution:
            return {}

        node = self._get_node(execution, node_id)
        if not node:
            return {}

        input_data: dict[str, Any] = {}

        for dep_id in node.depends_on:
            dep_node = self._get_node(execution, dep_id)
            if not dep_node or dep_node.status != ChainNodeStatus.COMPLETED:
                continue

            # Collect all data from dependency's outputs
            for output_port in dep_node.outputs:
                bus_key = f"{dep_id}.{output_port.name}"
                data = execution.data_bus.get(bus_key)
                if data is None:
                    continue

                # Transform for this specific tool
                transformed = transform_data(
                    source_tool=dep_node.tool_name,
                    dest_tool=node.tool_name,
                    data=data,
                    data_type=output_port.data_type,
                )
                input_data.update(transformed)

        # Merge with node's own tool_options
        input_data.update(node.tool_options)

        return input_data

    def report_node_started(self, chain_id: str, node_id: str) -> None:
        """Mark a node as running."""
        execution = self._executions.get(chain_id)
        if not execution:
            return

        node = self._get_node(execution, node_id)
        if node:
            node.status = ChainNodeStatus.RUNNING
            node.started_at = time.time()

    def report_node_complete(
        self,
        chain_id: str,
        node_id: str,
        output_data: dict[str, Any] | None = None,
    ) -> list[ChainNode]:
        """
        Mark a node as completed and store its output data.

        Returns the list of newly ready nodes (next steps).
        """
        execution = self._executions.get(chain_id)
        if not execution:
            return []

        node = self._get_node(execution, node_id)
        if not node:
            return []

        node.status = ChainNodeStatus.COMPLETED
        node.finished_at = time.time()

        # Store output data in the bus
        if output_data:
            node.result_data = output_data
            for output_port in node.outputs:
                if output_port.name in output_data:
                    bus_key = f"{node_id}.{output_port.name}"
                    execution.data_bus[bus_key] = output_data[output_port.name]

        logger.info(
            f"Chain node completed | chain={chain_id} | node={node_id} | "
            f"tool={node.tool_name} | "
            f"duration={node.finished_at - node.started_at:.1f}s"
        )

        # Check if chain is complete
        self._check_chain_completion(execution)

        # Return newly ready nodes
        return self.next_tools(chain_id)

    def report_node_failed(
        self,
        chain_id: str,
        node_id: str,
        error: str = "",
    ) -> list[ChainNode]:
        """
        Mark a node as failed.

        Downstream nodes that strictly depend on this node will be
        skipped. Nodes with other satisfied paths may still proceed.
        """
        execution = self._executions.get(chain_id)
        if not execution:
            return []

        node = self._get_node(execution, node_id)
        if node:
            node.status = ChainNodeStatus.FAILED
            node.finished_at = time.time()
            node.error = error

            logger.warning(
                f"Chain node failed | chain={chain_id} | node={node_id} | "
                f"error={error[:200]}"
            )

        # Cascade: skip nodes whose ONLY dependency is this failed node
        self._cascade_failure(execution, node_id)
        self._check_chain_completion(execution)

        return self.next_tools(chain_id)

    def skip_node(self, chain_id: str, node_id: str, reason: str = "") -> None:
        """Manually skip a node."""
        execution = self._executions.get(chain_id)
        if not execution:
            return

        node = self._get_node(execution, node_id)
        if node:
            node.status = ChainNodeStatus.SKIPPED
            node.error = reason
            self._check_chain_completion(execution)

    # ─── Chain Queries ───────────────────────────────────

    def get_chain_status(self, chain_id: str) -> dict[str, Any]:
        """Get detailed status of a chain execution."""
        execution = self._executions.get(chain_id)
        if not execution:
            return {"error": "Chain not found"}

        node_statuses: dict[str, str] = {}
        for node in execution.nodes:
            node_statuses[node.node_id] = node.status

        total = len(execution.nodes)
        completed = sum(
            1 for n in execution.nodes
            if n.status in (ChainNodeStatus.COMPLETED, ChainNodeStatus.SKIPPED)
        )
        failed = sum(
            1 for n in execution.nodes
            if n.status == ChainNodeStatus.FAILED
        )

        return {
            "chain_id": chain_id,
            "chain_name": execution.chain_name,
            "completed": execution.completed,
            "progress": f"{completed}/{total}",
            "progress_pct": round(completed / total * 100, 1) if total > 0 else 0,
            "failed_nodes": failed,
            "node_statuses": node_statuses,
            "data_bus_keys": list(execution.data_bus.keys()),
            "elapsed_seconds": round(
                (execution.finished_at or time.time()) - execution.started_at,
                1,
            ),
        }

    def get_active_chains(self) -> list[str]:
        """Get IDs of actively running chains."""
        return [
            cid
            for cid, ex in self._executions.items()
            if not ex.completed
        ]

    def get_collected_data(
        self,
        chain_id: str,
        data_type: DataType | None = None,
    ) -> dict[str, Any]:
        """
        Get all collected data from a chain execution.

        Optionally filter by DataType.
        """
        execution = self._executions.get(chain_id)
        if not execution:
            return {}

        if data_type is None:
            return dict(execution.data_bus)

        result: dict[str, Any] = {}
        for node in execution.nodes:
            for port in node.outputs:
                if port.data_type == data_type:
                    bus_key = f"{node.node_id}.{port.name}"
                    if bus_key in execution.data_bus:
                        result[bus_key] = execution.data_bus[bus_key]

        return result

    # ─── Dynamic Chain Building ──────────────────────────

    def build_chain_for_target(
        self,
        target_type: str,
        technologies: list[str] | None = None,
    ) -> ToolChainDef:
        """
        Dynamically build a chain based on target type and technologies.

        Args:
            target_type: "web_app" | "api" | "network" | "full"
            technologies: Detected technologies (e.g., ["wordpress", "php"])
        """
        technologies = technologies or []
        nodes: list[ChainNode] = []
        node_ids: set[str] = set()

        def add_node(
            tool: str,
            nid: str | None = None,
            **kwargs: Any,
        ) -> str:
            """Helper to add a node and return its ID."""
            node_id = nid or tool
            if node_id in node_ids:
                return node_id
            node_ids.add(node_id)
            nodes.append(ChainNode(tool_name=tool, node_id=node_id, **kwargs))
            return node_id

        if target_type in ("web_app", "full"):
            # Recon phase
            sf = add_node("subfinder", outputs=[
                DataPort(name="subdomains", data_type=DataType.SUBDOMAINS)
            ])
            am = add_node("amass", outputs=[
                DataPort(name="subdomains", data_type=DataType.SUBDOMAINS)
            ])
            hx = add_node(
                "httpx",
                depends_on=[sf, am],
                inputs=[DataPort(name="targets", data_type=DataType.SUBDOMAINS)],
                outputs=[DataPort(name="live_hosts", data_type=DataType.LIVE_HOSTS)],
                trigger=TriggerCondition.IF_RESULTS,
            )
            add_node(
                "katana",
                depends_on=[hx],
                inputs=[DataPort(name="targets", data_type=DataType.LIVE_HOSTS)],
                outputs=[DataPort(name="urls", data_type=DataType.URLS)],
                trigger=TriggerCondition.IF_RESULTS,
            )

            # Scan phase
            add_node(
                "nuclei",
                nid="nuclei_main",
                depends_on=[hx],
                inputs=[DataPort(name="targets", data_type=DataType.LIVE_HOSTS)],
                outputs=[DataPort(name="findings", data_type=DataType.FINDINGS)],
            )

        if target_type in ("api", "full"):
            add_node(
                "swagger_parser",
                outputs=[DataPort(name="api_spec", data_type=DataType.API_SPECS)],
                trigger=TriggerCondition.IF_TECH,
                trigger_value="swagger|openapi",
            )
            add_node(
                "graphql_introspection",
                outputs=[DataPort(name="api_spec", data_type=DataType.API_SPECS)],
                trigger=TriggerCondition.IF_TECH,
                trigger_value="graphql",
            )

        if target_type in ("network", "full"):
            rs = add_node("rustscan", outputs=[
                DataPort(name="open_ports", data_type=DataType.PORTS)
            ])
            add_node(
                "nmap",
                nid="nmap_version",
                depends_on=[rs],
                inputs=[DataPort(name="ports", data_type=DataType.PORTS)],
                outputs=[
                    DataPort(name="services", data_type=DataType.PORT_SERVICES),
                    DataPort(name="technologies", data_type=DataType.TECHNOLOGIES),
                ],
                trigger=TriggerCondition.IF_RESULTS,
            )

        # Technology-specific nodes
        tech_lower = [t.lower() for t in technologies]
        if "wordpress" in tech_lower:
            add_node("wpscan", outputs=[
                DataPort(name="findings", data_type=DataType.FINDINGS)
            ])
        if any(t in tech_lower for t in ("jwt", "json web token")):
            add_node("jwt_tool", outputs=[
                DataPort(name="findings", data_type=DataType.FINDINGS)
            ])

        chain_def = ToolChainDef(
            chain_id=f"dynamic_{target_type}_{int(time.time())}",
            name=f"Dynamic {target_type} chain",
            description=f"Auto-generated chain for {target_type} with techs {technologies}",
            category=target_type,
            nodes=nodes,
            tags=["dynamic", target_type] + technologies,
        )

        logger.info(
            f"Dynamic chain built | type={target_type} | "
            f"nodes={len(nodes)} | techs={technologies}"
        )

        return chain_def

    # ─── Internal Helpers ────────────────────────────────

    @staticmethod
    def _get_node(
        execution: ChainExecution, node_id: str
    ) -> ChainNode | None:
        """Find a node by ID in an execution."""
        for node in execution.nodes:
            if node.node_id == node_id:
                return node
        return None

    def _check_trigger(
        self, execution: ChainExecution, node: ChainNode
    ) -> bool:
        """Check if a node's trigger condition is met."""
        match node.trigger:
            case TriggerCondition.ALWAYS:
                return True

            case TriggerCondition.IF_RESULTS:
                # Check if any dependency produced non-empty data
                for dep_id in node.depends_on:
                    dep_node = self._get_node(execution, dep_id)
                    if dep_node and dep_node.result_data:
                        return True
                return False

            case TriggerCondition.IF_TECH:
                # Check data bus for matching technology
                trigger_val = node.trigger_value.lower()
                for key, val in execution.data_bus.items():
                    if ".technologies" in key or ".tech" in key:
                        if isinstance(val, list):
                            for t in val:
                                if trigger_val in str(t).lower():
                                    return True
                        elif trigger_val in str(val).lower():
                            return True
                return False

            case TriggerCondition.IF_PORT_OPEN:
                for key, val in execution.data_bus.items():
                    if ".ports" in key or ".open_ports" in key:
                        target_port = node.trigger_value
                        if isinstance(val, list) and target_port in [
                            str(p) for p in val
                        ]:
                            return True
                return False

            case TriggerCondition.MANUAL:
                return False  # Must be manually triggered

        return True

    def _cascade_failure(
        self, execution: ChainExecution, failed_node_id: str
    ) -> None:
        """Skip downstream nodes that exclusively depend on a failed node."""
        for node in execution.nodes:
            if node.status not in (
                ChainNodeStatus.PENDING,
                ChainNodeStatus.READY,
            ):
                continue

            if failed_node_id in node.depends_on:
                # Check if ALL other dependencies are also failed/skipped
                all_deps_dead = all(
                    self._get_node(execution, dep_id) is not None
                    and self._get_node(execution, dep_id).status  # type: ignore[union-attr]
                    in (ChainNodeStatus.FAILED, ChainNodeStatus.SKIPPED)
                    for dep_id in node.depends_on
                )

                if all_deps_dead:
                    node.status = ChainNodeStatus.SKIPPED
                    node.error = (
                        f"Skipped: all dependencies failed/skipped "
                        f"(includes {failed_node_id})"
                    )
                    logger.debug(
                        f"Cascade skip | chain={execution.chain_id} | "
                        f"node={node.node_id}"
                    )

    def _check_chain_completion(self, execution: ChainExecution) -> None:
        """Check if all nodes are in a terminal state."""
        terminal_states = {
            ChainNodeStatus.COMPLETED,
            ChainNodeStatus.FAILED,
            ChainNodeStatus.SKIPPED,
        }
        all_done = all(n.status in terminal_states for n in execution.nodes)

        if all_done and not execution.completed:
            execution.completed = True
            execution.finished_at = time.time()
            logger.info(
                f"Chain completed | id={execution.chain_id} | "
                f"name={execution.chain_name} | "
                f"duration={execution.finished_at - execution.started_at:.1f}s"
            )

    # ─── Cleanup ─────────────────────────────────────────

    def stop_chain(self, chain_id: str) -> None:
        """Stop and clean up a chain execution."""
        execution = self._executions.pop(chain_id, None)
        if execution:
            execution.completed = True
            execution.finished_at = time.time()
            logger.info(f"Chain stopped | id={chain_id}")

    def reset(self) -> None:
        """Clear all active executions (chain definitions are kept)."""
        self._executions.clear()
        logger.debug("ToolChainEngine executions reset")


__all__ = [
    "ToolChainEngine",
    "ToolChainDef",
    "ChainNode",
    "ChainExecution",
    "ChainNodeStatus",
    "DataType",
    "DataPort",
    "TriggerCondition",
    "transform_data",
]
