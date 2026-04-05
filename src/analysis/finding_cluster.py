"""
WhiteHatHacker AI — Finding Cluster Engine (V14-T3-2)

Groups related findings by root cause to reduce report noise.
Clustering criteria:
  1. Same canonical vuln type + same parameter → likely same root cause
  2. Same canonical vuln type + same path pattern → same endpoint family
  3. Tool merge findings that differ only in payload variant

Used by report generator to present grouped findings instead of
redundant individual entries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from loguru import logger


# ── Canonical vuln type normalization (subset from global_finding_store) ──

_VULN_SYNONYMS: dict[str, str] = {
    "xss_reflected": "xss", "reflected_xss": "xss", "xss_stored": "xss",
    "stored_xss": "xss", "xss_dom": "xss", "dom_xss": "xss",
    "dom-based_xss": "xss", "cross-site_scripting": "xss",
    "sqli_error": "sqli", "sqli_blind": "sqli", "sqli_time": "sqli",
    "sqli_union": "sqli", "sql_injection": "sqli", "sql-injection": "sqli",
    "blind_sqli": "sqli",
    "ssrf_internal": "ssrf", "ssrf_external": "ssrf",
    "server-side_request_forgery": "ssrf",
    "open_redirect": "redirect", "open-redirect": "redirect",
    "url_redirect": "redirect",
    "ssti": "template_injection", "server_side_template_injection": "template_injection",
    "command_injection": "rce", "os_command_injection": "rce",
    "remote_code_execution": "rce",
    "lfi": "path_traversal", "local_file_inclusion": "path_traversal",
    "directory_traversal": "path_traversal",
    "cors_misconfiguration": "cors", "cors_misconfig": "cors",
    "crlf_injection": "crlf", "http_response_splitting": "crlf",
    "idor": "idor", "insecure_direct_object_reference": "idor",
    "nosql_injection": "nosqli", "nosql-injection": "nosqli",
    "xxe": "xxe", "xml_external_entity": "xxe",
    "csrf": "csrf", "cross-site_request_forgery": "csrf",
}

# Regex to strip dynamic path segments for path-pattern grouping
_DYNAMIC_SEGMENT_RE = re.compile(r"/\d+|/[0-9a-f]{8,}|/[0-9a-f-]{36}", re.IGNORECASE)


def _canonical_vuln(raw: str) -> str:
    """Normalize a vulnerability type string to its canonical form."""
    key = raw.lower().strip().replace(" ", "_").replace("-", "_")
    return _VULN_SYNONYMS.get(key, key)


def _extract_path_pattern(url: str) -> str:
    """Extract a normalized path pattern from a URL, replacing dynamic segments."""
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
    except Exception:
        path = url
    return _DYNAMIC_SEGMENT_RE.sub("/{id}", path).lower()


def _g(obj: Any, key: str, default: Any = "") -> Any:
    """Get attribute from dict or object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ── Data Structures ──


@dataclass
class FindingCluster:
    """A group of related findings sharing a root cause."""

    cluster_id: str = ""
    canonical_vuln_type: str = ""
    root_cause_label: str = ""      # Human-readable cluster label
    path_pattern: str = ""          # Shared path pattern
    parameter: str = ""             # Shared parameter (if any)
    findings: list[Any] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def representative(self) -> Any:
        """Return the finding with the highest confidence as representative."""
        if not self.findings:
            return None
        return max(
            self.findings,
            key=lambda f: float(_g(f, "confidence_score", _g(f, "confidence", 0.0)) or 0),
        )

    @property
    def max_severity(self) -> str:
        """Return the highest severity across cluster findings."""
        _ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        best = "info"
        for f in self.findings:
            sev = str(_g(f, "severity", "info")).lower()
            if _ORDER.get(sev, 5) < _ORDER.get(best, 5):
                best = sev
        return best


# ── Clustering Engine ──


class FindingClusterer:
    """
    Groups findings into clusters based on root cause similarity.

    Clustering rules (applied in order of specificity):
      1. Exact (vuln_type + path_pattern + parameter) → same cluster
      2. Broad (vuln_type + path_pattern, different params) → same cluster
         only if ≥2 findings share it
    """

    def cluster(self, findings: list[Any]) -> list[FindingCluster]:
        """
        Group findings into clusters.

        Returns a list of FindingCluster objects. Singletons (clusters with
        only 1 finding) are included for completeness.
        """
        if not findings:
            return []

        # Stage 1: Build grouping key → findings mapping
        exact_groups: dict[tuple[str, str, str], list[Any]] = {}
        for f in findings:
            vuln = _canonical_vuln(
                str(_g(f, "vulnerability_type", _g(f, "type", "unknown")))
            )
            url = str(_g(f, "url", _g(f, "endpoint", "")))
            param = str(_g(f, "parameter", "")).lower().strip()
            path_pat = _extract_path_pattern(url)

            key = (vuln, path_pat, param)
            exact_groups.setdefault(key, []).append(f)

        # Stage 2: Merge groups that share (vuln, path_pattern) but differ only in param
        broad_groups: dict[tuple[str, str], list[tuple[str, list[Any]]]] = {}
        for (vuln, path_pat, param), group_findings in exact_groups.items():
            broad_key = (vuln, path_pat)
            broad_groups.setdefault(broad_key, []).append((param, group_findings))

        # Stage 3: Build clusters
        clusters: list[FindingCluster] = []
        cid = 0
        for (vuln, path_pat), param_groups in broad_groups.items():
            if len(param_groups) == 1:
                # Single param group — one cluster
                param, group_findings = param_groups[0]
                cid += 1
                _label = f"{vuln} on {path_pat}"
                if param:
                    _label += f" (param: {param})"
                clusters.append(FindingCluster(
                    cluster_id=f"CLU-{cid:04d}",
                    canonical_vuln_type=vuln,
                    root_cause_label=_label,
                    path_pattern=path_pat,
                    parameter=param,
                    findings=group_findings,
                ))
            else:
                # Multiple param groups on same path — merge into one cluster
                all_findings = []
                params = []
                for param, group_findings in param_groups:
                    all_findings.extend(group_findings)
                    if param:
                        params.append(param)
                cid += 1
                _label = f"{vuln} on {path_pat}"
                if params:
                    _label += f" (params: {', '.join(sorted(set(params)))})"
                clusters.append(FindingCluster(
                    cluster_id=f"CLU-{cid:04d}",
                    canonical_vuln_type=vuln,
                    root_cause_label=_label,
                    path_pattern=path_pat,
                    parameter=", ".join(sorted(set(params))),
                    findings=all_findings,
                ))

        # Sort clusters: multi-finding first, then by severity
        _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        clusters.sort(key=lambda c: (
            0 if c.count > 1 else 1,
            _SEV_ORDER.get(c.max_severity, 5),
        ))

        _multi = sum(1 for c in clusters if c.count > 1)
        if _multi:
            logger.info(
                f"Finding clustering: {len(findings)} findings → "
                f"{len(clusters)} clusters ({_multi} multi-finding)"
            )

        return clusters

    def cluster_summary_markdown(self, clusters: list[FindingCluster]) -> str:
        """Generate a markdown summary of finding clusters."""
        multi = [c for c in clusters if c.count > 1]
        if not multi:
            return ""

        lines = [
            "## Finding Clusters\n",
            "The following groups of findings share a common root cause:\n",
        ]
        for c in multi:
            rep = c.representative
            _title = str(_g(rep, "title", "")) if rep else c.root_cause_label
            lines.append(
                f"- **{c.cluster_id}** ({c.count} findings): "
                f"{c.root_cause_label} — highest severity: {c.max_severity.upper()}"
            )
        lines.append("")
        return "\n".join(lines)
