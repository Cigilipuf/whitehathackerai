"""WhiteHatHacker AI — False Positive Elimination Engine."""

from src.fp_engine.fp_detector import FPDetector, FPVerdict
from src.fp_engine.scoring import ConfidenceScorer, EvidenceChainBuilder
from src.fp_engine.verification import MultiToolVerifier, ResponseDiffAnalyzer, PayloadConfirmer
from src.fp_engine.patterns import KnownFPMatcher, ToolQuirkChecker, WafArtifactDetector
from src.fp_engine.learning import FPFeedbackManager, PatternLearner

__all__ = [
    # Core
    "FPDetector",
    "FPVerdict",
    # Scoring
    "ConfidenceScorer",
    "EvidenceChainBuilder",
    # Verification
    "MultiToolVerifier",
    "ResponseDiffAnalyzer",
    "PayloadConfirmer",
    # Patterns
    "KnownFPMatcher",
    "ToolQuirkChecker",
    "WafArtifactDetector",
    # Learning
    "FPFeedbackManager",
    "PatternLearner",
]
