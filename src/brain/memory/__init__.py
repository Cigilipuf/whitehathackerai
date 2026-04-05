"""WhiteHatHacker AI — Brain Memory Module."""

from src.brain.memory.context_manager import ContextManager, ContextEntry, ContextType
from src.brain.memory.knowledge_base import (
    KnowledgeBase,
    TargetIntelligence,
    ToolEffectiveness,
    VulnPattern,
    FalsePositivePattern,
    AttackChainRecord,
)
from src.brain.memory.session_memory import SessionMemory, SessionEvent, EventType
from src.brain.memory.working_memory import (
    WorkingMemory,
    Hypothesis,
    HypothesisStatus,
    TargetProfile,
    ToolExecution,
    FindingsSummary,
    TimeBudget,
    EnvironmentSnapshot,
)
from src.brain.memory.vuln_patterns import (
    VulnSignature,
    PatternCategory,
    ALL_PATTERNS,
    get_patterns_for_tech,
    get_patterns_by_category,
    get_patterns_for_endpoint,
    get_patterns_for_param,
)

__all__ = [
    "ContextManager",
    "ContextEntry",
    "ContextType",
    "KnowledgeBase",
    "TargetIntelligence",
    "ToolEffectiveness",
    "VulnPattern",
    "FalsePositivePattern",
    "AttackChainRecord",
    "SessionMemory",
    "SessionEvent",
    "EventType",
    "VulnSignature",
    "PatternCategory",
    "ALL_PATTERNS",
    "get_patterns_for_tech",
    "get_patterns_by_category",
    "get_patterns_for_endpoint",
    "get_patterns_for_param",
    "WorkingMemory",
    "Hypothesis",
    "HypothesisStatus",
    "TargetProfile",
    "ToolExecution",
    "FindingsSummary",
    "TimeBudget",
    "EnvironmentSnapshot",
]
