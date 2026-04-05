"""WhiteHatHacker AI — Workflow Module."""

from src.workflow.orchestrator import WorkflowOrchestrator, WorkflowState, StageResult
from src.workflow.decision_engine import DecisionEngine, Decision, ToolSelectionResult
from src.workflow.state_machine import StateMachine, StateEvent, Transition
from src.workflow.human_gateway import (
    HumanGateway,
    ApprovalRequest,
    ApprovalStatus,
    OperationMode,
    TerminalNotifier,
    SlackNotifier,
    TelegramNotifier,
)
from src.workflow.task_scheduler import (
    TaskScheduler,
    ScheduledTask,
    SchedulerConfig,
    TaskStatus,
    TaskPriority,
)
from src.workflow.session_manager import SessionManager, ScanSession, SessionStatus
from src.workflow.result_aggregator import (
    ResultAggregator,
    UnifiedFinding,
    AggregationResult,
    MergeStrategy,
)
from src.workflow.adaptive_strategy import (
    AdaptiveStrategyEngine,
    TargetEnvironment,
    ScanProfile as AdaptiveScanProfile,
    SignalType,
    StrategyMode,
)
from src.workflow.tool_chain import (
    ToolChainEngine,
    ToolChainDef,
    ChainNode,
    ChainExecution,
    DataType,
)

__all__ = [
    # Orchestrator
    "WorkflowOrchestrator",
    "WorkflowState",
    "StageResult",
    # Decision Engine
    "DecisionEngine",
    "Decision",
    "ToolSelectionResult",
    # State Machine
    "StateMachine",
    "StateEvent",
    "Transition",
    # Human Gateway
    "HumanGateway",
    "ApprovalRequest",
    "ApprovalStatus",
    "OperationMode",
    "TerminalNotifier",
    "SlackNotifier",
    "TelegramNotifier",
    # Task Scheduler
    "TaskScheduler",
    "ScheduledTask",
    "SchedulerConfig",
    "TaskStatus",
    "TaskPriority",
    # Session Manager
    "SessionManager",
    "ScanSession",
    "SessionStatus",
    # Result Aggregator
    "ResultAggregator",
    "UnifiedFinding",
    "AggregationResult",
    "MergeStrategy",
    # Adaptive Strategy
    "AdaptiveStrategyEngine",
    "TargetEnvironment",
    "AdaptiveScanProfile",
    "SignalType",
    "StrategyMode",
    # Tool Chain
    "ToolChainEngine",
    "ToolChainDef",
    "ChainNode",
    "ChainExecution",
    "DataType",
]
