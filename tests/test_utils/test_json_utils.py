"""Tests for src.utils.json_utils — LLM JSON extraction."""

from src.utils.json_utils import extract_json, extract_json_or_heuristic


# ── extract_json ──


class TestExtractJsonDirect:
    """Strategy 1: direct JSON parse."""

    def test_pure_object(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_pure_array(self):
        assert extract_json("[1, 2, 3]") == [1, 2, 3]

    def test_empty_string(self):
        assert extract_json("") is None

    def test_none_input(self):
        assert extract_json(None) is None  # type: ignore[arg-type]

    def test_whitespace_only(self):
        assert extract_json("   ") is None

    def test_custom_fallback(self):
        assert extract_json("not json", fallback={}) == {}

    def test_plain_text(self):
        assert extract_json("hello world") is None


class TestExtractJsonMarkdown:
    """Strategy 2: markdown code block extraction."""

    def test_json_fence(self):
        text = 'Here is JSON:\n```json\n{"key": "val"}\n```\nDone.'
        assert extract_json(text) == {"key": "val"}

    def test_generic_fence(self):
        text = "```\n{\"x\": 42}\n```"
        assert extract_json(text) == {"x": 42}

    def test_array_in_fence(self):
        text = '```json\n[{"id": 1}]\n```'
        assert extract_json(text, expect_array=True) == [{"id": 1}]

    def test_multiple_fences_picks_valid(self):
        text = '```json\nnot valid\n```\n```json\n{"ok": true}\n```'
        assert extract_json(text) == {"ok": True}


class TestExtractJsonBraceScanning:
    """Strategy 3: brace-depth scanning."""

    def test_json_after_text(self):
        text = 'The result is:\n{"found": true}'
        assert extract_json(text) == {"found": True}

    def test_json_before_explanation(self):
        text = '{"a": 1}\nThat was the answer.'
        assert extract_json(text) == {"a": 1}

    def test_nested_braces(self):
        text = 'Answer: {"outer": {"inner": 2}}'
        result = extract_json(text)
        assert result == {"outer": {"inner": 2}}

    def test_multiple_objects_picks_last(self):
        text = '{"first": 1} some text {"second": 2}'
        # Brace scanning tries last block first
        assert extract_json(text) == {"second": 2}

    def test_string_with_braces(self):
        text = '{"msg": "hello {world}"}'
        assert extract_json(text) == {"msg": "hello {world}"}

    def test_escaped_quotes(self):
        text = r'{"path": "C:\\Users\\test"}'
        result = extract_json(text)
        assert result is not None
        assert "path" in result


class TestExtractJsonAlternateType:
    """Strategy 4: fallback to alternate type."""

    def test_expect_object_finds_array(self):
        text = "Here: [1, 2, 3]"
        result = extract_json(text, expect_array=False)
        assert result == [1, 2, 3]

    def test_expect_array_finds_object(self):
        text = 'Result: {"k": "v"}'
        result = extract_json(text, expect_array=True)
        assert result == {"k": "v"}


class TestExtractJsonEdgeCases:
    def test_log_failures_false(self):
        # Should not raise, just return fallback
        assert extract_json("bad", log_failures=False) is None

    def test_deeply_nested(self):
        obj = {"a": {"b": {"c": {"d": [1, 2, {"e": 3}]}}}}
        import json
        text = f"Answer: {json.dumps(obj)}"
        assert extract_json(text) == obj


# ── extract_json_or_heuristic ──


class TestExtractJsonOrHeuristic:
    def test_valid_json(self):
        text = '{"verdict": "true_positive"}'
        result = extract_json_or_heuristic(text)
        assert result == {"verdict": "true_positive"}

    def test_heuristic_match_dict_value(self):
        keywords = {"false_positive": {"verdict": "fp", "confidence": 20}}
        text = "I think this is a false_positive because of WAF."
        result = extract_json_or_heuristic(text, heuristic_keywords=keywords)
        assert result == {"verdict": "fp", "confidence": 20}

    def test_heuristic_match_scalar_value(self):
        keywords = {"confirmed": True}
        text = "The vulnerability is confirmed."
        result = extract_json_or_heuristic(text, heuristic_keywords=keywords)
        assert result == {"heuristic_match": "confirmed", "value": True}

    def test_no_match_returns_empty(self):
        text = "Nothing useful here."
        result = extract_json_or_heuristic(text, heuristic_keywords={"xyz": 1})
        assert result == {}

    def test_empty_text_returns_empty(self):
        result = extract_json_or_heuristic("")
        assert result == {}

    def test_no_keywords_returns_empty(self):
        result = extract_json_or_heuristic("some text")
        assert result == {}


class TestExtractJsonMoreEdge:
    """Additional edge cases for deeper coverage."""

    def test_trailing_comma_in_fence(self):
        # Some LLMs add trailing commas
        text = '```json\n{"a": 1, "b": 2,}\n```'
        # Might fail direct parse, falls through to brace scanning
        result = extract_json(text, fallback={})
        assert isinstance(result, dict)

    def test_single_value_not_dict_or_list(self):
        # json.loads("42") returns int, not dict/list
        result = extract_json("42", fallback="nope")
        assert result == "nope"

    def test_array_in_brace_scan(self):
        text = "Some text [1, 2, 3] end"
        result = extract_json(text, expect_array=True)
        assert result == [1, 2, 3]

    def test_multiple_arrays_picks_last(self):
        text = "[1] text [2, 3]"
        result = extract_json(text, expect_array=True)
        assert result == [2, 3]

    def test_broken_json_fallback(self):
        text = '{"unclosed: true'
        assert extract_json(text, fallback="fb") == "fb"

    def test_markdown_array_fence_no_expect(self):
        text = '```json\n[{"a":1}]\n```'
        result = extract_json(text)  # expect_array default False
        assert isinstance(result, list)

    def test_heuristic_case_insensitive(self):
        keywords = {"false_positive": {"verdict": "fp"}}
        text = "THIS IS A FALSE_POSITIVE"
        result = extract_json_or_heuristic(text, heuristic_keywords=keywords)
        assert result["verdict"] == "fp"
