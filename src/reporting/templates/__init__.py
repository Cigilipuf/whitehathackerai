"""WhiteHatHacker AI — Report Templates."""

from src.reporting.templates.hackerone_template import HackerOneTemplate
from src.reporting.templates.bugcrowd_template import BugcrowdTemplate
from src.reporting.templates.generic_template import GenericTemplate
from src.reporting.templates.executive_summary import ExecutiveSummaryTemplate, ExecutiveSummary
from src.reporting.templates.technical_detail import TechnicalDetailTemplate, TechnicalReport, TechnicalFinding

__all__ = [
    "HackerOneTemplate",
    "BugcrowdTemplate",
    "GenericTemplate",
    "ExecutiveSummaryTemplate",
    "ExecutiveSummary",
    "TechnicalDetailTemplate",
    "TechnicalReport",
    "TechnicalFinding",
]
