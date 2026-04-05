"""WhiteHatHacker AI — Platform Submission APIs."""
from src.reporting.platform_submit.hackerone_api import (
    HackerOneAPI,
    HackerOneReport,
    HackerOneProgram,
)
from src.reporting.platform_submit.bugcrowd_api import (
    BugcrowdAPI,
    BugcrowdSubmission,
    BugcrowdProgram,
)
from src.reporting.platform_submit.generic_api import (
    GenericPlatformAPI,
    GenericSubmission,
)

__all__ = [
    "HackerOneAPI",
    "HackerOneReport",
    "HackerOneProgram",
    "BugcrowdAPI",
    "BugcrowdSubmission",
    "BugcrowdProgram",
    "GenericPlatformAPI",
    "GenericSubmission",
]
