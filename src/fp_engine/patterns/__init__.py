"""WhiteHatHacker AI — Known FP Patterns."""

from src.fp_engine.patterns.known_fps import KnownFPMatcher, FPPattern, KNOWN_FP_PATTERNS
from src.fp_engine.patterns.tool_quirks import ToolQuirkChecker, ToolQuirk, TOOL_QUIRKS
from src.fp_engine.patterns.waf_artifacts import WafArtifactDetector

__all__ = [
    "KnownFPMatcher",
    "FPPattern",
    "KNOWN_FP_PATTERNS",
    "ToolQuirkChecker",
    "ToolQuirk",
    "TOOL_QUIRKS",
    "WafArtifactDetector",
]
