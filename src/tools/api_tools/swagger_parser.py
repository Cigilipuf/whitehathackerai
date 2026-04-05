"""
WhiteHatHacker AI — Swagger/OpenAPI Parser

Parses Swagger/OpenAPI specification files to discover endpoints,
parameters, authentication methods, and potential security issues.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding, SecurityTool, ToolResult
from src.utils.constants import RiskLevel, ScanProfile, SeverityLevel, ToolCategory

# Common OpenAPI/Swagger endpoint locations
_SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api-docs.json",
    "/openapi.json", "/openapi.yaml",
    "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui.html", "/swagger-ui/",
    "/api/swagger.json", "/api/openapi.json",
    "/docs", "/redoc",
    "/.well-known/openapi.json",
]


class SwaggerParserWrapper(SecurityTool):
    """
    Swagger/OpenAPI Parser — Discovers and parses API specification files.

    Features:
    - Auto-discovers swagger/openapi endpoints
    - Parses endpoints, methods, parameters
    - Identifies authentication requirements
    - Flags security issues (no auth, excessive data exposure, etc.)
    """

    name = "swagger_parser"
    category = ToolCategory.API_TOOL
    description = "Swagger/OpenAPI spec discovery & security analysis"
    binary_name = "curl"
    requires_root = False
    risk_level = RiskLevel.SAFE

    def is_available(self) -> bool:
        return True  # Uses httpx — always available

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

        spec_url = options.get("spec_url")
        spec_data = None
        found_url = ""

        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                verify=False,
            ) as client:
                if spec_url:
                    resp = await client.get(spec_url)
                    if resp.status_code == 200:
                        spec_data = resp.json()
                        found_url = spec_url
                else:
                    # Auto-discover
                    for path in _SWAGGER_PATHS:
                        url = f"{base_url}{path}"
                        try:
                            resp = await client.get(url)
                            if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
                                spec_data = resp.json()
                                found_url = url
                                break
                        except Exception as _exc:
                            logger.debug(f"swagger parser error: {_exc}")
                            continue

        except Exception as exc:
            logger.warning(f"Swagger discovery error: {exc}")
            return ToolResult(
                tool_name=self.name, success=False,
                error_message=str(exc), target=target,
            )

        if not spec_data:
            return ToolResult(
                tool_name=self.name, success=True,
                stdout="No Swagger/OpenAPI spec found",
                findings=[], target=target,
            )

        findings = self._analyze_spec(spec_data, base_url, found_url)
        return ToolResult(
            tool_name=self.name, success=True,
            stdout=json.dumps({"spec_url": found_url, "endpoints": len(findings)}, indent=2),
            findings=findings, target=target,
        )

    def _analyze_spec(self, spec: dict, base_url: str, spec_url: str) -> list[Finding]:
        findings: list[Finding] = []
        version = spec.get("openapi", spec.get("swagger", "unknown"))
        info = spec.get("info", {})

        # Spec exposure finding
        findings.append(Finding(
            title=f"API Spec Exposed: {info.get('title', 'API')} v{info.get('version', '?')}",
            description=f"OpenAPI {version} spec publicly accessible at {spec_url}",
            vulnerability_type="information_disclosure",
            severity=SeverityLevel.LOW,
            confidence=95.0,
            target=base_url, endpoint=spec_url,
            tool_name=self.name,
            tags=["swagger", "api_spec", "information_disclosure"],
            metadata={"openapi_version": version, "api_title": info.get("title", "")},
        ))

        # Parse paths
        paths = spec.get("paths", {})
        _security_defs = spec.get("securityDefinitions", spec.get("components", {}).get("securitySchemes", {}))

        unauthenticated: list[str] = []
        sensitive_params: list[str] = []
        all_endpoints: list[str] = []

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ("parameters", "servers", "summary", "description"):
                    continue
                method = method.upper()
                endpoint = f"{method} {path}"
                all_endpoints.append(endpoint)

                # Check auth
                has_security = bool(details.get("security") or spec.get("security"))
                if not has_security and method in ("POST", "PUT", "DELETE", "PATCH"):
                    unauthenticated.append(endpoint)

                # Check sensitive parameters
                params = details.get("parameters", [])
                for param in params:
                    pname = param.get("name", "").lower()
                    if any(s in pname for s in ("password", "token", "secret", "key", "auth", "credit")):
                        sensitive_params.append(f"{endpoint} → {param.get('name')}")

        # Unauthenticated write endpoints
        if unauthenticated:
            findings.append(Finding(
                title=f"API: {len(unauthenticated)} Unauthenticated Write Endpoints",
                description="\n".join(unauthenticated[:20]),
                vulnerability_type="authentication_bypass",
                severity=SeverityLevel.HIGH,
                confidence=70.0,
                target=base_url,
                tool_name=self.name,
                tags=["swagger", "no_auth", "api"],
                cwe_id="CWE-306",
                metadata={"endpoints": unauthenticated},
            ))

        # Sensitive parameters
        if sensitive_params:
            findings.append(Finding(
                title=f"API: {len(sensitive_params)} Sensitive Parameters",
                description="\n".join(sensitive_params[:15]),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.MEDIUM,
                confidence=60.0,
                target=base_url,
                tool_name=self.name,
                tags=["swagger", "sensitive_params"],
                cwe_id="CWE-200",
            ))

        # All endpoints summary
        if all_endpoints:
            findings.append(Finding(
                title=f"API: {len(all_endpoints)} Endpoints Discovered",
                description="\n".join(all_endpoints[:30]),
                vulnerability_type="information_disclosure",
                severity=SeverityLevel.INFO,
                confidence=95.0,
                target=base_url,
                tool_name=self.name,
                tags=["swagger", "endpoints"],
                metadata={"total_endpoints": len(all_endpoints)},
            ))

        return findings

    @staticmethod
    def extract_fuzzable_endpoints(spec: dict, base_url: str) -> list[dict[str, Any]]:
        """
        Extract structured endpoint data from an OpenAPI spec for fuzzer consumption.

        Returns a list of dicts with keys:
            method, path, url, parameters, has_auth, content_types
        """
        endpoints: list[dict[str, Any]] = []
        base = base_url.rstrip("/")

        # Support OpenAPI 3.x servers array
        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            server_url = servers[0].get("url", "")
            if server_url.startswith("http"):
                base = server_url.rstrip("/")
            elif server_url.startswith("/"):
                base = base + server_url.rstrip("/")

        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() in ("parameters", "servers", "summary", "description", "$ref"):
                    continue
                if not isinstance(details, dict):
                    continue

                params: list[dict[str, Any]] = []
                for p in details.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", "query"),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", p.get("type", "string")),
                        "enum": p.get("schema", {}).get("enum", p.get("enum")),
                    })

                # Extract request body params (OpenAPI 3.x)
                req_body = details.get("requestBody", {})
                content = req_body.get("content", {})
                content_types = list(content.keys())
                for ct, ct_details in content.items():
                    schema = ct_details.get("schema", {})
                    props = schema.get("properties", {})
                    for pname, pdetails in props.items():
                        params.append({
                            "name": pname,
                            "in": "body",
                            "required": pname in schema.get("required", []),
                            "type": pdetails.get("type", "string"),
                            "enum": pdetails.get("enum"),
                        })

                has_auth = bool(details.get("security") or spec.get("security"))

                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "url": f"{base}{path}",
                    "parameters": params,
                    "has_auth": has_auth,
                    "content_types": content_types or ["application/json"],
                    "deprecated": details.get("deprecated", False),
                })

        return endpoints

    def build_command(self, target, options=None, profile=None) -> list[str]:
        return []

    def parse_output(self, raw_output: str, target: str = "") -> list[Finding]:
        return []


__all__ = ["SwaggerParserWrapper"]
