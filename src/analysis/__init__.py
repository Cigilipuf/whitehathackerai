"""WhiteHatHacker AI — Analysis Module."""

from src.analysis.output_aggregator import OutputAggregator, NormalizedFinding
from src.analysis.severity_calculator import SeverityCalculator, CVSSMetrics, CVSSResult
from src.analysis.attack_surface import AttackSurfaceMapper, AttackSurfaceReport, Endpoint, HostProfile, AttackVector
from src.analysis.vulnerability_analyzer import VulnerabilityAnalyzer, AnalyzedVulnerability, VulnContext
from src.analysis.threat_model import ThreatModeler, ThreatModelReport, ImpactAssessor
from src.analysis.correlation_engine import CorrelationEngine, CorrelationReport, CorrelatedFinding, AttackChain
from src.analysis.impact_assessor import ImpactAssessor as ImpactAssessorV2, ImpactReport, ImpactDimension, ImpactLevel, ImpactCategory
from src.analysis.host_profiler import HostProfiler, HostIntelProfile, HostType, ResponseBaseline, is_cdn_ip

__all__ = [
    "OutputAggregator", "NormalizedFinding",
    "SeverityCalculator", "CVSSMetrics", "CVSSResult",
    "AttackSurfaceMapper", "AttackSurfaceReport", "Endpoint", "HostProfile", "AttackVector",
    "VulnerabilityAnalyzer", "AnalyzedVulnerability", "VulnContext",
    "ThreatModeler", "ThreatModelReport", "ImpactAssessor",
    "CorrelationEngine", "CorrelationReport", "CorrelatedFinding", "AttackChain",
    "ImpactAssessorV2", "ImpactReport", "ImpactDimension", "ImpactLevel", "ImpactCategory",
    "HostProfiler", "HostIntelProfile", "HostType", "ResponseBaseline", "is_cdn_ip",
]
