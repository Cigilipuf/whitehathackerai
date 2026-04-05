"""
WhiteHatHacker AI — GraphQL Introspection Wrapper

Discovers and analyzes GraphQL endpoints.
Tests for introspection enabled, query complexity, mutations, etc.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Common GraphQL endpoint locations
_GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/gql", "/query",
    "/api/graphql", "/api/gql",
    "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/graphql/v2",
    "/graphql/console", "/graphiql",
    "/playground", "/altair",
]

# Introspection query
_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
"""

# Shorter probe query
_PROBE_QUERY = '{"query": "{ __typename }"}'


class GraphQLIntrospectionWrapper(SecurityTool):
    """
    GraphQL Introspection — Discover and analyze GraphQL APIs.

    Features:
    - Auto-discovers GraphQL endpoints
    - Tests introspection (schema leak)
    - Enumerates queries, mutations, subscriptions
    - Identifies sensitive types & fields
    - Detects common misconfigurations
    """

    name = "graphql_introspection"
    category = ToolCategory.API_TOOL
    description = "GraphQL endpoint discovery, introspection & security analysis"
    binary_name = "curl"
    requires_root = False
    risk_level = RiskLevel.LOW

    def is_available(self) -> bool:
        return True  # Uses httpx

    async def run(
        self,
        target: str,
        options: dict[str, Any] | None = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> ToolResult:
        options = options or {}
        base_url = target.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        graphql_url = options.get("graphql_url")
        headers = options.get("headers", {})

        findings: list[Finding] = []
        discovered_url = ""
        schema_data: dict | None = None

        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=True, verify=False,
            ) as client:
                # Step 1: Discover GraphQL endpoint
                if graphql_url:
                    endpoints_to_try = [graphql_url]
                else:
                    endpoints_to_try = [f"{base_url}{p}" for p in _GRAPHQL_PATHS]

                for url in endpoints_to_try:
                    try:
                        resp = await client.post(
                            url,
                            content=_PROBE_QUERY,
                            headers={"Content-Type": "application/json", **headers},
                        )
                        if resp.status_code == 200:
                            body = resp.json()
                            if "data" in body or "errors" in body:
                                discovered_url = url
                                break
                    except Exception as _exc:
                        logger.debug(f"graphql introspection error: {_exc}")
                        continue

                if not discovered_url:
                    return ToolResult(
                        tool_name=self.name, success=True,
                        stdout="No GraphQL endpoint found",
                        findings=[], target=target,
                    )

                # Step 2: GraphQL endpoint found
                findings.append(Finding(
                    title="GraphQL Endpoint Discovered",
                    description=f"Active GraphQL endpoint at {discovered_url}",
                    vulnerability_type="information_disclosure",
                    severity=SeverityLevel.LOW,
                    confidence=95.0,
                    target=base_url, endpoint=discovered_url,
                    tool_name=self.name,
                    tags=["graphql", "endpoint"],
                ))

                # Step 3: Try introspection
                intro_resp = await client.post(
                    discovered_url,
                    json={"query": _INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json", **headers},
                )
                if intro_resp.status_code == 200:
                    intro_data = intro_resp.json()
                    if "data" in intro_data and intro_data["data"].get("__schema"):
                        schema_data = intro_data["data"]["__schema"]
                        findings.append(Finding(
                            title="GraphQL Introspection Enabled",
                            description="Full schema introspection is enabled — leaks all types, queries, mutations",
                            vulnerability_type="information_disclosure",
                            severity=SeverityLevel.MEDIUM,
                            confidence=95.0,
                            target=base_url, endpoint=discovered_url,
                            tool_name=self.name,
                            tags=["graphql", "introspection"],
                            cwe_id="CWE-200",
                        ))

                # Step 4: Analyze schema
                if schema_data:
                    findings.extend(self._analyze_schema(schema_data, base_url, discovered_url))

        except Exception as exc:
            logger.warning(f"GraphQL introspection error: {exc}")
            return ToolResult(
                tool_name=self.name, success=False,
                error_message=str(exc), target=target,
            )

        return ToolResult(
            tool_name=self.name, success=True,
            stdout=json.dumps({
                "graphql_url": discovered_url,
                "introspection": schema_data is not None,
                "findings": len(findings),
            }, indent=2),
            findings=findings, target=target,
        )

    def _analyze_schema(self, schema: dict, base_url: str, gql_url: str) -> list[Finding]:
        findings: list[Finding] = []
        types = schema.get("types", [])

        # Count queries, mutations
        queries = []
        mutations = []
        sensitive_fields: list[str] = []
        all_type_names: list[str] = []

        for t in types:
            name = t.get("name", "")
            _kind = t.get("kind", "")
            fields = t.get("fields") or []
            all_type_names.append(name)

            # Skip built-in types
            if name.startswith("__"):
                continue

            for field in fields:
                fname = field.get("name", "").lower()
                # Detect sensitive fields
                if any(s in fname for s in (
                    "password", "token", "secret", "credit_card",
                    "ssn", "private", "auth", "session", "cookie",
                )):
                    sensitive_fields.append(f"{name}.{field.get('name', '')}")

            # Check if this type is the query/mutation root
            query_type = schema.get("queryType", {}).get("name", "")
            mutation_type = schema.get("mutationType", {}).get("name", "")
            if name == query_type:
                queries = [f.get("name", "") for f in fields]
            elif name == mutation_type:
                mutations = [f.get("name", "") for f in fields]

        # Report mutations (write operations)
        if mutations:
            findings.append(Finding(
                title=f"GraphQL: {len(mutations)} Mutations Available",
                description="\n".join(mutations[:30]),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.MEDIUM,
                confidence=90.0,
                target=base_url, endpoint=gql_url,
                tool_name=self.name,
                tags=["graphql", "mutations"],
                metadata={"mutations": mutations},
            ))

        # Report queries
        if queries:
            findings.append(Finding(
                title=f"GraphQL: {len(queries)} Queries Available",
                description="\n".join(queries[:30]),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=90.0,
                target=base_url, endpoint=gql_url,
                tool_name=self.name,
                tags=["graphql", "queries"],
                metadata={"queries": queries},
            ))

        # Sensitive fields
        if sensitive_fields:
            findings.append(Finding(
                title=f"GraphQL: {len(sensitive_fields)} Sensitive Fields",
                description="\n".join(sensitive_fields[:20]),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.HIGH,
                confidence=70.0,
                target=base_url, endpoint=gql_url,
                tool_name=self.name,
                tags=["graphql", "sensitive_fields"],
                cwe_id="CWE-200",
                metadata={"fields": sensitive_fields},
            ))

        return findings

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return []

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["GraphQLIntrospectionWrapper"]
