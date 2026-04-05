"""
WhiteHatHacker AI — Sabitler ve Enum Tanımları
"""

from enum import StrEnum


class BrainType(StrEnum):
    """Kullanılacak beyin modeli."""
    PRIMARY = "primary"      # BaronLLM v2 /think — Derin analiz
    SECONDARY = "secondary"  # BaronLLM v2 /no_think — Hızlı triage
    BOTH = "both"            # Ensemble — her ikisi


class OperationMode(StrEnum):
    """Bot çalışma modu."""
    AUTONOMOUS = "autonomous"
    SEMI_AUTONOMOUS = "semi-autonomous"


class ScanProfile(StrEnum):
    """Tarama agresiflik profili."""
    STEALTH = "stealth"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


class ToolCategory(StrEnum):
    """Güvenlik aracı kategorileri."""
    RECON_SUBDOMAIN = "recon.subdomain"
    RECON_PORT = "recon.port_scan"
    RECON_WEB = "recon.web_discovery"
    RECON_DNS = "recon.dns"
    RECON_OSINT = "recon.osint"
    RECON_TECH = "recon.tech_detect"
    SCANNER = "scanner"
    FUZZING = "fuzzing"
    EXPLOIT = "exploit"
    NETWORK = "network"
    API_TOOL = "api_tool"
    CRYPTO = "crypto"
    PROXY = "proxy"


class RiskLevel(StrEnum):
    """Araç risk seviyesi."""
    SAFE = "safe"           # Sadece okuma, pasif
    LOW = "low"             # Düşük etkili aktif keşif
    MEDIUM = "medium"       # Aktif tarama
    HIGH = "high"           # Exploit/PoC denemesi
    CRITICAL = "critical"   # Potansiyel yıkıcı etki


_SEVERITY_NUMERIC_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class SeverityLevel(StrEnum):
    """Zafiyet ciddiyet seviyesi (CVSS tabanlı)."""
    CRITICAL = "critical"   # 9.0 - 10.0
    HIGH = "high"           # 7.0 - 8.9
    MEDIUM = "medium"       # 4.0 - 6.9
    LOW = "low"             # 0.1 - 3.9
    INFO = "info"           # Bilgilendirme

    def _numeric(self) -> int:
        return _SEVERITY_NUMERIC_ORDER.get(self.value, -1)

    def __lt__(self, other: object) -> bool:
        if isinstance(other, SeverityLevel):
            return self._numeric() < other._numeric()
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, SeverityLevel):
            return self._numeric() <= other._numeric()
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, SeverityLevel):
            return self._numeric() > other._numeric()
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, SeverityLevel):
            return self._numeric() >= other._numeric()
        return NotImplemented


class VulnerabilityType(StrEnum):
    """Zafiyet türleri."""
    SQLI = "sql_injection"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SSRF = "ssrf"
    SSTI = "ssti"
    COMMAND_INJECTION = "command_injection"
    IDOR = "idor"
    CORS_MISCONFIG = "cors_misconfiguration"
    OPEN_REDIRECT = "open_redirect"
    CRLF_INJECTION = "crlf_injection"
    HTTP_SMUGGLING = "http_request_smuggling"
    JWT_VULN = "jwt_vulnerability"
    AUTH_BYPASS = "authentication_bypass"
    BUSINESS_LOGIC = "business_logic"
    RACE_CONDITION = "race_condition"
    FILE_UPLOAD = "file_upload"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    XXE = "xml_external_entity"
    NOSQL_INJECTION = "nosql_injection"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    INFO_DISCLOSURE = "information_disclosure"
    SSL_TLS = "ssl_tls_misconfiguration"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    CSRF = "csrf"
    CLICKJACKING = "clickjacking"


class WorkflowStage(StrEnum):
    """İş akışı aşamaları."""
    SCOPE_ANALYSIS = "scope_analysis"
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    ENUMERATION = "enumeration"
    ATTACK_SURFACE_MAP = "attack_surface_mapping"
    VULNERABILITY_SCAN = "vulnerability_scanning"
    FP_ELIMINATION = "fp_elimination"
    REPORTING = "reporting"
    PLATFORM_SUBMIT = "platform_submit"
    KNOWLEDGE_UPDATE = "knowledge_update"


class FindingStatus(StrEnum):
    """Bulgu durumu."""
    RAW = "raw"                     # Ham — henüz doğrulanmamış
    VERIFIED = "verified"           # Doğrulanmış zafiyet
    FALSE_POSITIVE = "false_positive"  # Yanlış pozitif
    DUPLICATE = "duplicate"         # Duplikat
    REPORTED = "reported"           # Raporlanmış
    ACCEPTED = "accepted"           # Platform tarafından kabul edilmiş
    REJECTED = "rejected"           # Reddedilmiş


class PlatformType(StrEnum):
    """Bug bounty platform türleri."""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    GENERIC = "generic"


# ============================================================
# Sabit Değerler
# ============================================================

# Varsayılan timeout'lar (saniye)
DEFAULT_TOOL_TIMEOUT = 120
NUCLEI_TIMEOUT = 900
SQLMAP_TIMEOUT = 300
NMAP_TIMEOUT = 300

# Rate Limiting
DEFAULT_MAX_RPS = 10
DEFAULT_MAX_RPS_PER_HOST = 3

# FP Engine
FP_AUTO_REPORT_THRESHOLD = 90
FP_HIGH_CONFIDENCE_THRESHOLD = 70
FP_MEDIUM_CONFIDENCE_THRESHOLD = 65
FP_LOW_CONFIDENCE_THRESHOLD = 40

# Session
SESSION_ID_LENGTH = 16

# User Agent
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
