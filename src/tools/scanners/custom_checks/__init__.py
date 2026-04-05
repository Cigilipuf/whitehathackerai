"""WhiteHatHacker AI — Custom Security Checks."""

from src.tools.scanners.custom_checks.idor_checker import IDORChecker
from src.tools.scanners.custom_checks.auth_bypass import AuthBypassChecker
from src.tools.scanners.custom_checks.race_condition import RaceConditionChecker
from src.tools.scanners.custom_checks.rate_limit_checker import RateLimitChecker
from src.tools.scanners.custom_checks.business_logic import BusinessLogicChecker
from src.tools.scanners.custom_checks.deserialization_checker import DeserializationChecker
from src.tools.scanners.custom_checks.bfla_bola_checker import BFLABOLAChecker
from src.tools.scanners.custom_checks.mass_assignment_checker import MassAssignmentChecker

__all__ = [
    "IDORChecker",
    "AuthBypassChecker",
    "RaceConditionChecker",
    "RateLimitChecker",
    "BusinessLogicChecker",
    "DeserializationChecker",
    "BFLABOLAChecker",
    "MassAssignmentChecker",
    # Standalone checker functions (imported directly in pipeline)
    # - header_checker.check_security_headers
    # - sensitive_url_finder.find_sensitive_urls
    # - subdomain_takeover.check_subdomain_takeover
    # - js_analyzer.analyze_javascript_files
    # - tech_cve_checker.check_technology_cves
    # - http_method_checker.check_http_methods
    # - open_redirect_checker.check_open_redirects
    # - info_disclosure_checker.check_info_disclosure
    # - cookie_checker.check_cookie_security
]
