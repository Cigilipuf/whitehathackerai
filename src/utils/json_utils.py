"""
WhiteHatHacker AI — Robust JSON Extraction from LLM Responses

LLMs often wrap JSON in markdown code fences, explanatory text, or produce
slightly malformed JSON. This module provides a single, battle-tested extraction
function used across the entire codebase.

Extraction strategy (ordered by reliability):
  1. Direct JSON parse (response is pure JSON)
  2. Extract from ```json ... ``` markdown code blocks
  3. Extract from ``` ... ``` generic code blocks
  4. Find the LAST valid {…} block via brace-depth scanning (LLMs put JSON at end)
  5. Find the FIRST valid {…} block (fallback)
  6. Find valid [...] array blocks
"""

from __future__ import annotations

import json
import re
from typing import Any

from loguru import logger

# Pre-compiled patterns
_MARKDOWN_JSON_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_MARKDOWN_ARRAY_RE = re.compile(r"```(?:json)?\s*(\[.*?\])\s*```", re.DOTALL)
_MARKDOWN_ANY_RE = re.compile(r"```(?:\w*)?\s*([\[{].*?[}\]])\s*```", re.DOTALL)


def extract_json(
    text: str,
    *,
    expect_array: bool = False,
    fallback: Any = None,
    log_failures: bool = True,
) -> Any:
    """Extract JSON object or array from LLM response text.

    Args:
        text: Raw LLM response text (may contain markdown, explanations, etc.)
        expect_array: If True, prefer extracting JSON arrays over objects.
        fallback: Value to return if extraction fails (default: None).
        log_failures: Whether to log a debug message on failure.

    Returns:
        Parsed JSON (dict or list), or *fallback* on failure.
    """
    if not text or not text.strip():
        return fallback

    text = text.strip()

    # ── Strategy 1: Direct parse ──
    try:
        result = json.loads(text)
        if isinstance(result, (dict, list)):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # ── Strategy 2: Markdown code block extraction ──
    if "```" in text:
        pattern = _MARKDOWN_ARRAY_RE if expect_array else _MARKDOWN_JSON_RE
        for match in pattern.finditer(text):
            try:
                return json.loads(match.group(1))
            except (json.JSONDecodeError, ValueError):
                continue
        # Try generic markdown blocks
        for match in _MARKDOWN_ANY_RE.finditer(text):
            try:
                result = json.loads(match.group(1))
                if isinstance(result, (dict, list)):
                    return result
            except (json.JSONDecodeError, ValueError):
                continue

    # ── Strategy 3: Brace-depth scanning (last valid block first, then first) ──
    open_char = "[" if expect_array else "{"
    close_char = "]" if expect_array else "}"

    # Collect all top-level block positions
    blocks: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        if text[i] == open_char:
            depth = 0
            in_string = False
            escape = False
            end = -1
            for j in range(i, len(text)):
                c = text[j]
                if escape:
                    escape = False
                    continue
                if c == "\\":
                    escape = True
                    continue
                if c == '"' and not escape:
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if c == open_char:
                    depth += 1
                elif c == close_char:
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            if end > i:
                blocks.append((i, end))
                i = end + 1
            else:
                i += 1
        else:
            i += 1

    # Try blocks from last to first (LLMs tend to put real JSON at the end)
    for start, end in reversed(blocks):
        candidate = text[start : end + 1]
        try:
            result = json.loads(candidate)
            if isinstance(result, (dict, list)):
                return result
        except (json.JSONDecodeError, ValueError):
            continue

    # ── Strategy 4: If we expected objects but found nothing, try arrays (and vice versa) ──
    alt_open = "[" if not expect_array else "{"
    alt_close = "]" if not expect_array else "}"
    _search = 0
    for _ in range(20):
        pos = text.find(alt_open, _search)
        if pos < 0:
            break
        depth = 0
        end = -1
        in_string = False
        escape = False
        for j in range(pos, len(text)):
            c = text[j]
            if escape:
                escape = False
                continue
            if c == "\\":
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == alt_open:
                depth += 1
            elif c == alt_close:
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end > pos:
            try:
                result = json.loads(text[pos : end + 1])
                if isinstance(result, (dict, list)):
                    return result
            except (json.JSONDecodeError, ValueError):
                pass
            _search = end + 1
        else:
            _search = pos + 1

    if log_failures:
        logger.debug(
            f"JSON extraction failed from LLM response "
            f"({len(text)} chars, first 100: {text[:100]!r})"
        )
    return fallback


def extract_json_or_heuristic(
    text: str,
    *,
    heuristic_keywords: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract JSON, falling back to keyword heuristics.

    If JSON extraction fails, scans text for keywords and builds a
    best-effort dict. Useful for FP analysis where LLM may respond
    in natural language.

    Args:
        text: LLM response text.
        heuristic_keywords: Mapping of {keyword: value_if_found}.
            Example: {"false_positive": {"verdict": "false_positive"}}

    Returns:
        Parsed dict (from JSON or heuristics), or empty dict.
    """
    result = extract_json(text, log_failures=False)
    if isinstance(result, dict):
        return result

    if heuristic_keywords and text:
        text_lower = text.lower()
        for keyword, value in heuristic_keywords.items():
            if keyword.lower() in text_lower:
                if isinstance(value, dict):
                    return value
                return {"heuristic_match": keyword, "value": value}

    return {}
