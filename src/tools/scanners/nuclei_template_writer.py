"""
WhiteHatHacker AI — Dynamic Nuclei Template Writer

Uses the LLM brain to generate custom Nuclei YAML templates on-the-fly
based on discovered attack vectors, endpoints, and vulnerability patterns.

Flow:
  1. Receive attack surface data (endpoint, params, tech stack, headers)
  2. LLM generates a targeted nuclei template
  3. Template is validated (YAML syntax + Nuclei schema compliance)
  4. Saved to data/nuclei_templates/custom/ for execution
  5. After execution, results are fed back for template refinement

This is what separates a scanner from a HUNTER — writing custom checks
instead of relying solely on community templates.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from pathlib import Path
from typing import Any

import yaml
from loguru import logger

# ── Template directory ────────────────────────────────────────
_TEMPLATE_DIR = Path("data/nuclei_templates/custom")
_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences from LLM output, preserving the YAML."""
    text = text.strip()
    # Handle ```yaml ... ``` or ```yml ... ``` or ``` ... ```
    fence_re = re.compile(r'^```(?:ya?ml)?\s*\n?', re.IGNORECASE)
    if fence_re.match(text):
        text = fence_re.sub('', text, count=1)
    if text.endswith("```"):
        text = text[:-3]
    # Handle stray leading/trailing backticks
    text = text.strip("`").strip()
    return text


def _sanitize_llm_yaml(text: str) -> str:
    """Pre-sanitize common LLM YAML mistakes before yaml.safe_load.

    Handles:
    - Tab indentation → 2 spaces
    - Unbalanced double-quoted scalars (most common LLM YAML error)
    - Trailing whitespace that can confuse YAML parsers
    """
    # Replace tabs with 2 spaces (LLMs sometimes output tabs)
    text = text.replace("\t", "  ")

    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.rstrip()

        # Fix unbalanced double-quoted scalars on value lines.
        # Pattern: `key: "some text with unbalanced "quotes" inside"`
        # We detect lines where the value portion has an odd number of
        # unescaped double-quotes and switch them to single-quoted YAML.
        if ": " in stripped:
            colon_idx = stripped.index(": ")
            value_part = stripped[colon_idx + 2:]
            # Count unescaped double-quotes in value
            dq_count = value_part.count('"') - value_part.count('\\"')
            if dq_count > 0 and dq_count % 2 != 0:
                # Odd number of double-quotes → replace outer quotes with
                # single quotes and escape internal single quotes
                inner = value_part.strip('"').replace("'", "''")
                stripped = stripped[:colon_idx + 2] + f"'{inner}'"

        # Fix list items with unbalanced double-quotes
        # Pattern: `- "some "broken" quote"`
        list_match = re.match(r'^(\s*-\s+)"(.+)"$', stripped)
        if list_match:
            prefix = list_match.group(1)
            inner = list_match.group(2)
            # Check for internal unescaped double-quotes
            if '"' in inner:
                inner_clean = inner.replace("'", "''")
                stripped = f"{prefix}'{inner_clean}'"

        lines.append(stripped)

    return "\n".join(lines)


# ── Template categories ──────────────────────────────────────

TEMPLATE_CATEGORIES = {
    "xss": {
        "tags": ["xss", "cross-site-scripting"],
        "payloads": [
            '<script>alert(1)</script>',
            '"><img/src=x onerror=alert(1)>',
            "'-alert(1)-'",
            "{{constructor.constructor('return this')()}}"
        ],
        "matchers": ["type: word", "words: alert(1), <script>"],
    },
    "sqli": {
        "tags": ["sqli", "sql-injection"],
        "payloads": ["'", "' OR '1'='1", "1 UNION SELECT NULL--", "' AND SLEEP(5)--"],
        "matchers": ["type: word", "words: SQL syntax, mysql, PostgreSQL, ORA-"],
    },
    "ssrf": {
        "tags": ["ssrf", "server-side-request-forgery"],
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80",
            "http://[::]:80/",
        ],
        "matchers": ["type: word", "words: ami-id, instance-id, local-ipv4"],
    },
    "ssti": {
        "tags": ["ssti", "template-injection"],
        "payloads": ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}"],
        "matchers": ["type: word", "words: 49"],
    },
    "open_redirect": {
        "tags": ["redirect", "open-redirect"],
        "payloads": [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%00",
        ],
        "matchers": ["type: regex", "regex: '(?i)location:\\s*https?://evil\\.com'"],
    },
    "lfi": {
        "tags": ["lfi", "path-traversal", "local-file-inclusion"],
        "payloads": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
        ],
        "matchers": ["type: word", "words: root:x:0:0"],
    },
    "cors": {
        "tags": ["cors", "misconfiguration"],
        "payloads": [],  # Origin header manipulation
        "matchers": ["type: word", "part: header", "words: access-control-allow-origin"],
    },
    "header_injection": {
        "tags": ["crlf", "header-injection"],
        "payloads": ["%0d%0aSet-Cookie:injected=1", "%0aX-Injected:true"],
        "matchers": ["type: word", "part: header", "words: injected"],
    },
    "idor": {
        "tags": ["idor", "broken-access-control"],
        "payloads": [],  # ID manipulation
        "matchers": ["type: dsl", "condition: status_code == 200"],
    },
    "info_disclosure": {
        "tags": ["exposure", "information-disclosure"],
        "payloads": [],
        "matchers": ["type: word", "words: password, secret, api_key, private_key"],
    },
}


def validate_nuclei_template(template_str: str) -> tuple[bool, str]:
    """
    Validate a nuclei YAML template for correctness.

    Checks:
      1. Valid YAML syntax
      2. Has required top-level fields: id, info, http/dns/network
      3. Info has name and severity
      4. Has at least one matcher
      5. No dangerous payloads (we're bug bounty, not attackers)

    Returns:
        (is_valid, reason)
    """
    if not template_str or not template_str.strip():
        return False, "Empty template"

    try:
        data = yaml.safe_load(template_str)
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {e}"

    if not isinstance(data, dict):
        return False, "Template must be a YAML mapping"

    # Required: id
    if "id" not in data:
        return False, "Missing 'id' field"

    # Required: info block
    info = data.get("info", {})
    if not info:
        return False, "Missing 'info' block"
    if "name" not in info:
        return False, "Missing 'info.name'"
    if "severity" not in info:
        return False, "Missing 'info.severity'"
    if info["severity"] not in ("info", "low", "medium", "high", "critical"):
        return False, f"Invalid severity: {info['severity']}"

    # Must have at least one protocol block
    protocol_blocks = {"http", "dns", "network", "file", "headless", "ssl", "websocket", "whois", "code", "javascript"}
    has_protocol = any(k in data for k in protocol_blocks)
    if not has_protocol:
        return False, f"No protocol block found (need one of: {protocol_blocks})"

    # HTTP block validation
    if "http" in data:
        http_block = data["http"]
        if not isinstance(http_block, list) or len(http_block) == 0:
            return False, "'http' must be a non-empty list"
        for i, req in enumerate(http_block):
            if not isinstance(req, dict):
                return False, f"http[{i}] must be a mapping"
            # Must have path or raw
            if "path" not in req and "raw" not in req:
                return False, f"http[{i}] must have 'path' or 'raw'"
            # Must have matchers
            if "matchers" not in req:
                return False, f"http[{i}] missing 'matchers'"

            # ── P2-1: Quality gate — high/critical must have content matchers ──
            sev = str(info.get("severity") or "").lower()
            if sev in ("high", "critical"):
                matchers = req.get("matchers", [])
                has_content_matcher = False
                for m in matchers:
                    if not isinstance(m, dict):
                        continue
                    mtype = m.get("type", "")
                    # Body/header content checks count as quality evidence
                    if mtype in ("word", "regex") and not m.get("negative"):
                        has_content_matcher = True
                        break
                if not has_content_matcher:
                    return False, (
                        f"http[{i}]: high/critical severity templates must have "
                        f"at least one positive body/header content matcher "
                        f"(word or regex without negative:true)"
                    )

    # Safety: no destructive payloads
    template_str_lower = template_str.lower()
    dangerous = [
        ("DROP TABLE", "SQL destruction"),
        ("DELETE FROM", "SQL deletion"),
        ("rm -rf", "filesystem destruction"),
        ("shutdown", "system shutdown"),
        ("format c:", "disk format"),
    ]
    for pattern, desc in dangerous:
        if pattern.lower() in template_str_lower:
            return False, f"Dangerous payload detected: {desc}"

    return True, "Valid"


async def generate_nuclei_template(
    brain_engine: Any,
    target_info: dict,
    vuln_category: str = "",
    context: str = "",
) -> str | None:
    """
    Use LLM to generate a custom Nuclei template for a specific target/endpoint.

    Args:
        brain_engine: BrainEngine instance for LLM calls
        target_info: Dict with keys like:
            - url: Target URL
            - endpoint: Specific endpoint path
            - parameters: List of discovered parameters
            - method: HTTP method (GET/POST)
            - tech_stack: Identified technologies
            - headers: Notable response headers
            - response_sample: Sample response body snippet
        vuln_category: Category from TEMPLATE_CATEGORIES (e.g., "xss", "sqli")
        context: Additional context about what to test

    Returns:
        YAML template string, or None if generation failed
    """
    from src.brain.engine import BrainType

    # Build a rich context prompt
    category_info = TEMPLATE_CATEGORIES.get(vuln_category, {})
    category_tags = category_info.get("tags", [vuln_category]) if vuln_category else ["security"]
    sample_payloads = category_info.get("payloads", [])

    url = target_info.get("url", target_info.get("endpoint", ""))
    params = target_info.get("parameters", [])
    method = target_info.get("method", "GET")
    tech_stack = target_info.get("tech_stack", [])
    headers = target_info.get("headers", {})
    response_sample = target_info.get("response_sample", "")

    prompt = f"""## Generate Nuclei YAML Template

You are a security researcher writing a custom Nuclei template to test a specific endpoint.

### Target Information
- URL: {url}
- Method: {method}
- Parameters: {', '.join(params[:20]) if params else 'None found'}
- Technology Stack: {', '.join(tech_stack[:10]) if tech_stack else 'Unknown'}
- Response Headers: {json.dumps(dict(list(headers.items())[:10])) if headers else 'N/A'}
- Response Sample: {response_sample[:500] if response_sample else 'N/A'}

### Vulnerability Category: {vuln_category or 'general security'}
- Tags: {', '.join(category_tags)}
- Known Payloads for this category: {json.dumps(sample_payloads[:5]) if sample_payloads else 'N/A'}

### Additional Context
{context or 'Perform a thorough test for this vulnerability category on the given endpoint.'}

### Template Requirements
1. Use `id:` with format: `custom-{{category}}-{{unique-identifier}}`
2. `info:` must include name, author (use "whitehat-ai"), severity, description, tags
3. For HTTP templates:
   - Use `{{{{BaseURL}}}}` for the base URL
   - Test EACH parameter individually with targeted payloads
   - Include multiple matchers (word, status, regex) with `matchers-condition: and`
   - Use `extractors` to capture evidence when possible
4. Payloads should be safe for bug bounty (no destructive actions)
5. Include at least 3 different payload variations
6. For each parameter, generate a separate HTTP request block if needed
7. The template MUST be valid Nuclei YAML

### SKELETON TEMPLATE (follow this exact structure)
```yaml
id: custom-{vuln_category or "check"}-example

info:
  name: Example Check
  author: whitehat-ai
  severity: medium
  description: Description here
  tags: tag1,tag2

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/endpoint?param=PAYLOAD"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "expected_reflection"
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        regex:
          - "evidence_pattern"
```
Important YAML rules:
- `http:` is a list of request objects (each starts with `- method:`)
- `matchers:` is a list of matcher objects (each starts with `- type:`)
- `path:` under http is a list of strings (each starts with `- "..."`)
- Do NOT put matchers outside the http request object
- Indent consistently with 2 spaces
- Strings with special characters MUST be quoted

### Technology-Aware Notes
{_get_tech_specific_notes(tech_stack)}

Return ONLY the valid YAML template. No markdown fences, no explanations."""

    try:
        response = await asyncio.wait_for(
            brain_engine.think(
                prompt=prompt,
                brain=BrainType.PRIMARY,
                temperature=0.3,
            ),
            timeout=1200.0,  # BaronLLM v2 /think: skip if brain doesn't respond in 2min
        )

        template = response.text.strip()

        # Clean markdown fences and sanitize common LLM YAML mistakes
        template = _strip_markdown_fences(template)
        template = _sanitize_llm_yaml(template)

        # Validate
        is_valid, reason = validate_nuclei_template(template)
        if not is_valid:
            logger.warning(f"Generated template invalid: {reason}")
            # Try to get LLM to fix it
            template = await _fix_template_with_llm(brain_engine, template, reason)
            if template:
                is_valid, reason = validate_nuclei_template(template)
                if not is_valid:
                    logger.error(f"Template still invalid after fix: {reason}")
                    return None
            else:
                return None

        return template

    except asyncio.TimeoutError:
        logger.warning("Nuclei template generation timed out")
        return None
    except Exception as e:
        logger.error(f"Template generation error: {e}")
        return None


async def generate_targeted_templates(
    brain_engine: Any,
    endpoints: list[dict],
    tech_stack: list[str],
    max_templates: int = 5,
) -> list[tuple[str, str]]:
    """
    Generate multiple targeted nuclei templates for a list of high-value endpoints.

    Analyzes the endpoints, picks the best candidates for custom templates,
    and generates them using the LLM.

    Args:
        brain_engine: BrainEngine instance
        endpoints: List of endpoint dicts with url, params, method, etc.
        tech_stack: Identified technology stack
        max_templates: Maximum number of templates to generate

    Returns:
        List of (filename, template_yaml) tuples
    """

    templates = []

    # Prioritize endpoints with parameters
    param_endpoints = [
        ep for ep in endpoints
        if ep.get("parameters") or ep.get("params")
    ]

    # If no param endpoints, use endpoints with interesting patterns
    if not param_endpoints:
        interesting_patterns = [
            "api", "search", "query", "redirect", "url", "path",
            "file", "page", "load", "include", "template", "render",
            "login", "auth", "callback", "return", "next",
        ]
        param_endpoints = [
            ep for ep in endpoints
            if any(p in str(ep.get("url", "")).lower() for p in interesting_patterns)
        ]

    # Take top N candidates
    candidates = param_endpoints[:max_templates * 2]

    # Determine which vulnerability categories to test for each endpoint
    for endpoint in candidates[:max_templates]:
        url = endpoint.get("url", endpoint.get("endpoint", ""))
        params = endpoint.get("parameters", endpoint.get("params", []))

        # Determine best vuln category for this endpoint
        categories = _suggest_vuln_categories(url, params, tech_stack)

        for cat in categories[:2]:  # Max 2 categories per endpoint
            try:
                template = await generate_nuclei_template(
                    brain_engine=brain_engine,
                    target_info={
                        **endpoint,
                        "tech_stack": tech_stack,
                    },
                    vuln_category=cat,
                )

                if template:
                    # Generate filename
                    slug = re.sub(r'[^\w\-]', '-', f"{cat}-{url.split('/')[-1][:30]}")
                    filename = f"whai-{slug}-{uuid.uuid4().hex[:6]}.yaml"
                    templates.append((filename, template))

                    logger.info(f"Generated nuclei template: {filename} for {cat} on {url[:60]}")

                if len(templates) >= max_templates:
                    break
            except Exception as e:
                logger.debug(f"Template generation failed for {url}: {e}")
                continue

        if len(templates) >= max_templates:
            break

    return templates


def save_template(filename: str, template_yaml: str) -> Path | None:
    """Save a nuclei template to the custom templates directory."""
    try:
        filepath = _TEMPLATE_DIR / filename
        filepath.write_text(template_yaml)
        logger.info(f"Nuclei template saved: {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Failed to save template: {e}")
        return None


def save_and_validate_templates(
    templates: list[tuple[str, str]],
) -> list[Path]:
    """Save and validate a batch of templates. Returns paths of valid saved templates."""
    saved = []
    for filename, template_yaml in templates:
        is_valid, reason = validate_nuclei_template(template_yaml)
        if is_valid:
            path = save_template(filename, template_yaml)
            if path:
                saved.append(path)
        else:
            logger.warning(f"Skipping invalid template {filename}: {reason}")
    return saved


async def _fix_template_with_llm(
    brain_engine: Any,
    broken_template: str,
    error_reason: str,
) -> str | None:
    """Ask LLM to fix a broken nuclei template."""
    from src.brain.engine import BrainType

    prompt = f"""The following Nuclei YAML template has a validation error:

**Error:** {error_reason}

**Template:**
```yaml
{broken_template[:3000]}
```

Fix the template to resolve the validation error. Required structure:

```yaml
id: template-id
info:
  name: Template Name
  author: whitehat-ai
  severity: medium
  description: Description
  tags: tag1,tag2
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/path"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "match_word"
      - type: status
        status:
          - 200
```

Rules:
- `http:` MUST be a list (items start with `- method:`)
- `matchers:` MUST be a list inside the http request (items start with `- type:`)
- `path:` MUST be a list of quoted strings
- severity MUST be one of: info, low, medium, high, critical
- Indent with 2 spaces consistently

Return ONLY the fixed YAML. No markdown fences, no explanations."""

    try:
        response = await asyncio.wait_for(
            brain_engine.think(
                prompt=prompt,
                brain=BrainType.SECONDARY,
                temperature=0.1,
            ),
            timeout=1200.0,
        )

        fixed = response.text.strip()
        fixed = _strip_markdown_fences(fixed)
        return _sanitize_llm_yaml(fixed)
    except Exception as _exc:
        logger.debug(f"nuclei template writer error: {_exc}")
        return None


def _suggest_vuln_categories(
    url: str,
    params: list[str],
    tech_stack: list[str],
) -> list[str]:
    """Suggest likely vulnerability categories based on endpoint characteristics."""
    categories = []
    url_lower = url.lower()
    params_lower = [p.lower() for p in params] if params else []
    tech_lower = [t.lower() for t in tech_stack]

    # Parameter-based suggestions
    search_params = {"q", "query", "search", "keyword", "s", "term"}
    redirect_params = {"url", "redirect", "return", "next", "callback", "goto", "continue", "dest", "destination", "redir", "return_to", "redirect_uri"}
    file_params = {"file", "path", "page", "include", "template", "doc", "load", "read", "view"}
    id_params = {"id", "uid", "user_id", "account", "order_id", "item_id", "pid"}

    param_set = set(params_lower)

    if param_set & search_params:
        categories.extend(["xss", "sqli"])
    if param_set & redirect_params:
        categories.append("open_redirect")
    if param_set & file_params:
        categories.extend(["lfi", "ssti"])
    if param_set & id_params:
        categories.append("idor")

    # URL pattern-based
    if "/api/" in url_lower or "graphql" in url_lower:
        categories.extend(["sqli", "idor", "info_disclosure"])
    if "upload" in url_lower:
        categories.append("info_disclosure")
    if "login" in url_lower or "auth" in url_lower:
        categories.append("sqli")

    # Tech stack-based
    if any("php" in t for t in tech_lower):
        categories.extend(["lfi", "sqli", "ssti"])
    if any("java" in t for t in tech_lower):
        categories.extend(["ssti", "sqli"])
    if any("node" in t or "express" in t for t in tech_lower):
        categories.extend(["ssti", "ssrf", "xss"])
    if any("wordpress" in t or "wp" in t for t in tech_lower):
        categories.extend(["sqli", "xss", "lfi"])
    if any("django" in t or "flask" in t for t in tech_lower):
        categories.extend(["ssti", "sqli"])

    # Default: always try XSS on endpoints with params
    if params and "xss" not in categories:
        categories.append("xss")

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for c in categories:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    return unique or ["xss", "info_disclosure"]


def _get_tech_specific_notes(tech_stack: list[str]) -> str:
    """Get technology-specific testing notes for the template."""
    notes = []
    tech_lower = [t.lower() for t in tech_stack]

    if any("php" in t for t in tech_lower):
        notes.append("- PHP: Test null byte injection (%00), PHP wrapper (php://filter), type juggling")
    if any("java" in t for t in tech_lower):
        notes.append("- Java: Test OGNL injection, Log4Shell patterns, deserialization")
    if any("node" in t or "express" in t for t in tech_lower):
        notes.append("- Node.js: Test prototype pollution, parameter pollution, NoSQL injection")
    if any("wordpress" in t or "wp" in t for t in tech_lower):
        notes.append("- WordPress: Test REST API, wp-admin, xmlrpc.php, known plugin vulns")
    if any("nginx" in t for t in tech_lower):
        notes.append("- Nginx: Test path traversal via alias misconfiguration, off-by-slash")
    if any("apache" in t for t in tech_lower):
        notes.append("- Apache: Test mod_rewrite bypass, .htaccess disclosure, server-status")
    if any("cloudflare" in t for t in tech_lower):
        notes.append("- Cloudflare: WAF present — use encoding/obfuscation in payloads")
    if any("aws" in t or "s3" in t for t in tech_lower):
        notes.append("- AWS: Test S3 bucket misconfiguration, metadata endpoint SSRF")

    return "\n".join(notes) if notes else "No specific technology notes."


__all__ = [
    "validate_nuclei_template",
    "generate_nuclei_template",
    "generate_targeted_templates",
    "save_template",
    "save_and_validate_templates",
    "TEMPLATE_CATEGORIES",
]
