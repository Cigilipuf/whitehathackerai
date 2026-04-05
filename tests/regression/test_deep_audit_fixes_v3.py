"""Regression tests for deep audit v3 fixes.

Covers:
1. BrainEngine empty choices guard — no IndexError on empty/missing choices array
2. CLI submit async wrapping — asyncio.run() around async platform API calls
3. IDOR duplicate dead code removed from full_scan.py
4. Finding field name fixes — 35 constructors across 12 files:
   url= → target=/endpoint=, detail= → description=, source= → tool_name=
"""

import importlib
import inspect
import re

import pytest

from src.tools.base import Finding, SeverityLevel


# ──────────────────────────────────────────────────────────────
# 1. BrainEngine empty choices guard
# ──────────────────────────────────────────────────────────────


class TestBrainEmptyChoicesGuard:
    """Verify engine.py safely handles empty/missing choices in API responses."""

    def test_sync_inference_empty_choices_guard_exists(self):
        """The sync inference path must check for empty choices before indexing."""
        src = inspect.getsource(importlib.import_module("src.brain.engine"))
        # Find the _sync_infer or _infer method area — look for the guard
        assert 'not response.get("choices")' in src or "not response.get('choices')" in src, (
            "engine.py must guard against empty choices array in sync inference path"
        )

    def test_remote_streaming_empty_choices_guard_exists(self):
        """Remote streaming path must skip chunks with empty choices."""
        src = inspect.getsource(importlib.import_module("src.brain.engine"))
        # Must have continue guard for empty chunk choices
        assert 'not chunk.get("choices")' in src or "not chunk.get('choices')" in src, (
            "engine.py must guard against empty choices in remote streaming path"
        )

    def test_local_streaming_empty_choices_guard_exists(self):
        """Local streaming worker must skip chunks with empty choices."""
        src = inspect.getsource(importlib.import_module("src.brain.engine"))
        # Count occurrences — should be at least 2 (remote + local streaming)
        count = src.count('not chunk.get("choices")') + src.count("not chunk.get('choices')")
        assert count >= 2, (
            f"Expected at least 2 chunk choices guards (remote+local streaming), found {count}"
        )


# ──────────────────────────────────────────────────────────────
# 2. CLI submit uses asyncio.run()
# ──────────────────────────────────────────────────────────────


class TestCLISubmitAsyncWrapping:
    """Verify CLI submit command wraps async API calls with asyncio.run()."""

    def test_submit_uses_asyncio_run(self):
        """All 3 platform submit calls must use asyncio.run()."""
        try:
            mod = importlib.import_module("src.cli")
        except ImportError as exc:
            pytest.skip(f"CLI dependency unavailable: {exc}")
        src = inspect.getsource(mod)
        # HackerOne
        assert "asyncio.run(api.submit_report(" in src, (
            "HackerOne submit must be wrapped with asyncio.run()"
        )
        # Bugcrowd
        assert "asyncio.run(api.submit(" in src, (
            "Bugcrowd/Generic submit must be wrapped with asyncio.run()"
        )


# ──────────────────────────────────────────────────────────────
# 3. IDOR duplicate dead code removal
# ──────────────────────────────────────────────────────────────


class TestIDORDeadCodeRemoved:
    """Verify the duplicate IDOR dead code block is removed from full_scan.py."""

    def test_no_duplicate_idor_return(self):
        """full_scan.py should not have duplicate 'if results' return blocks
        after the main IDOR return statement."""
        src = inspect.getsource(importlib.import_module("src.workflow.pipelines.full_scan"))
        # The bug was: two consecutive "if results:" blocks with identical logic
        # after the IDOR checker section. Count occurrences of the exact pattern.
        pattern = r"if results:\s+logger\.info.*idor.*\n\s+return results"
        matches = re.findall(pattern, src, re.IGNORECASE)
        assert len(matches) <= 1, (
            f"Found {len(matches)} duplicate IDOR return blocks — dead code not removed"
        )


# ──────────────────────────────────────────────────────────────
# 4. Finding field name correctness (the big fix — 35 instances)
# ──────────────────────────────────────────────────────────────


class TestFindingFieldNameFixes:
    """Verify no Finding() constructors use wrong field names (url=, detail=, source=).
    
    These were silently discarded by Pydantic v2's extra='ignore' default,
    causing empty target/description/tool_name in findings.
    """

    # All files that previously had wrong Finding field names
    AFFECTED_FILES = [
        "src.tools.recon.dns.reverse_ip",
        "src.tools.recon.osint.metadata_extractor",
        "src.tools.recon.tech_detect.cdn_detector",
        "src.tools.recon.tech_detect.favicon_hasher",
        "src.tools.recon.web_discovery.csp_discovery",
        "src.tools.recon.web_discovery.sourcemap_extractor",
        "src.tools.recon.web_discovery.vhost_fuzzer",
        "src.tools.scanners.custom_checks.bfla_bola_checker",
        "src.tools.scanners.custom_checks.cicd_checker",
        "src.tools.scanners.custom_checks.cloud_checker",
        "src.tools.scanners.custom_checks.http2_http3_checker",
        "src.tools.scanners.custom_checks.mass_assignment_checker",
    ]

    @pytest.mark.parametrize("module_path", AFFECTED_FILES)
    def test_no_url_field_in_finding_constructors(self, module_path: str):
        """Finding() must not use url= (should be target= or endpoint=)."""
        mod = importlib.import_module(module_path)
        src = inspect.getsource(mod)
        # Find all Finding( blocks and check for url= inside them
        # Simple heuristic: look for "url=" that follows "Finding(" within ~500 chars
        finding_blocks = re.finditer(r"Finding\(", src)
        for match in finding_blocks:
            start = match.start()
            # Extract the constructor block (up to 800 chars or closing paren)
            block = src[start:start + 800]
            # Find the matching closing paren (approximate)
            depth = 0
            end = 0
            for i, c in enumerate(block):
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end > 0:
                constructor = block[:end + 1]
                # Check for wrong field name: url= as a keyword arg
                # Must match `url=` as a keyword parameter, not inside a string
                wrong_url = re.search(r"(?<!\w)url=(?!.*['\"])", constructor)
                assert wrong_url is None, (
                    f"Found 'url=' in Finding() constructor in {module_path}: "
                    f"should be 'target=' or 'endpoint='"
                )

    @pytest.mark.parametrize("module_path", AFFECTED_FILES)
    def test_no_detail_field_in_finding_constructors(self, module_path: str):
        """Finding() must not use detail= (should be description=)."""
        mod = importlib.import_module(module_path)
        src = inspect.getsource(mod)
        # Simple check: detail= as keyword in Finding context
        assert "\n                detail=" not in src and "\n            detail=" not in src, (
            f"Found 'detail=' in {module_path}: should be 'description='"
        )

    @pytest.mark.parametrize("module_path", AFFECTED_FILES)
    def test_no_source_field_in_finding_constructors(self, module_path: str):
        """Finding() must not use source= (should be tool_name=)."""
        mod = importlib.import_module(module_path)
        src = inspect.getsource(mod)
        # Check for source= as a keyword in indented context (Finding constructor)
        assert "\n                source=" not in src and "\n            source=" not in src, (
            f"Found 'source=' in {module_path}: should be 'tool_name='"
        )


class TestFindingFieldPreservation:
    """Verify Finding() actually preserves target, endpoint, description, tool_name."""

    def test_target_field_preserved(self):
        f = Finding(title="Test", target="example.com")
        assert f.target == "example.com"

    def test_endpoint_field_preserved(self):
        f = Finding(title="Test", endpoint="https://example.com/api/v1")
        assert f.endpoint == "https://example.com/api/v1"

    def test_description_field_preserved(self):
        f = Finding(title="Test", description="XSS in search parameter")
        assert f.description == "XSS in search parameter"

    def test_tool_name_field_preserved(self):
        f = Finding(title="Test", tool_name="cicd_checker")
        assert f.tool_name == "cicd_checker"

    def test_wrong_field_names_silently_discarded(self):
        """Demonstrate that Pydantic v2 silently discards unknown fields.
        This is the exact bug we fixed — url=, detail=, source= were lost."""
        # This test documents the Pydantic v2 behavior that caused the bug
        f = Finding(title="Test", **{"url": "example.com"})
        assert f.target == ""  # url= was silently ignored, target stays empty

    def test_all_fields_together(self):
        f = Finding(
            title="H2C Smuggling",
            target="example.com",
            endpoint="https://example.com/admin",
            description="H2C upgrade smuggling detected",
            tool_name="http2_http3_checker",
            vulnerability_type="h2c_smuggling",
            severity=SeverityLevel.HIGH,
            confidence=85.0,
        )
        assert f.target == "example.com"
        assert f.endpoint == "https://example.com/admin"
        assert f.description == "H2C upgrade smuggling detected"
        assert f.tool_name == "http2_http3_checker"
        assert f.severity == SeverityLevel.HIGH


# ──────────────────────────────────────────────────────────────
# 5. SeverityLevel comparison operators (v2.7.8 audit fix)
# ──────────────────────────────────────────────────────────────


class TestSeverityLevelComparison:
    """SeverityLevel enum must support correct numeric ordering."""

    def test_ordering_chain(self):
        assert SeverityLevel.INFO < SeverityLevel.LOW < SeverityLevel.MEDIUM < SeverityLevel.HIGH < SeverityLevel.CRITICAL

    def test_gt(self):
        assert SeverityLevel.CRITICAL > SeverityLevel.HIGH
        assert SeverityLevel.HIGH > SeverityLevel.LOW

    def test_equality_not_affected(self):
        assert SeverityLevel.HIGH == SeverityLevel.HIGH
        assert SeverityLevel.HIGH == "high"

    def test_min_max(self):
        levels = [SeverityLevel.HIGH, SeverityLevel.LOW, SeverityLevel.CRITICAL]
        assert min(levels) == SeverityLevel.LOW
        assert max(levels) == SeverityLevel.CRITICAL

    def test_sort(self):
        levels = [SeverityLevel.MEDIUM, SeverityLevel.CRITICAL, SeverityLevel.INFO]
        assert sorted(levels) == [SeverityLevel.INFO, SeverityLevel.MEDIUM, SeverityLevel.CRITICAL]

    def test_not_comparable_with_int(self):
        assert SeverityLevel.HIGH.__lt__(42) is NotImplemented
