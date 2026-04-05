"""WhiteHatHacker AI — Utility Modules."""

from src.utils.logger import (
    setup_logger,
    get_logger,
    generate_session_id,
    get_session_id,
    set_log_context,
    clear_log_context,
    get_log_context,
    log_context,
    log_duration,
    format_exception_chain,
    log_tool_execution,
    log_brain_call,
    log_finding,
    log_stage_transition,
    log_scope_check,
    log_http_exchange,
    log_startup_diagnostics,
)
from src.utils.dev_diagnostics import (
    DiagnosticResult,
    DiagnosticReport,
    run_full_diagnostics,
    run_diagnostics_sync,
)
from src.utils.scope_validator import ScopeValidator, ScopeDefinition, ScopeTarget
from src.utils.rate_limiter import RateLimiter, RateLimitConfig
from src.utils.sanitizer import (
    sanitize_command_arg,
    sanitize_url,
    sanitize_hostname,
    sanitize_path,
    sanitize_filename,
    sanitize_for_log,
    mask_sensitive,
)
from src.utils.network_utils import (
    resolve_hostname,
    normalize_url,
    get_domain_from_url,
    get_base_domain,
    is_port_open,
    is_valid_ip,
    is_valid_domain,
    expand_cidr,
)
from src.utils.crypto_utils import (
    sha256,
    md5,
    base64_encode,
    base64_decode,
    decode_jwt,
    analyze_jwt_security,
    get_ssl_cert_info,
    identify_hash,
    generate_random_token,
)
from src.utils.file_utils import (
    ensure_output_dirs,
    create_session_dir,
    read_json,
    write_json,
    read_lines,
    write_lines,
    load_wordlist,
    file_sha256,
    human_readable_size,
)

__all__ = [
    # Logger — core
    "setup_logger",
    "get_logger",
    "generate_session_id",
    "get_session_id",
    # Logger — context & helpers
    "set_log_context",
    "clear_log_context",
    "get_log_context",
    "log_context",
    "log_duration",
    "format_exception_chain",
    # Logger — structured event loggers
    "log_tool_execution",
    "log_brain_call",
    "log_finding",
    "log_stage_transition",
    "log_scope_check",
    "log_http_exchange",
    "log_startup_diagnostics",
    # Dev Diagnostics
    "DiagnosticResult",
    "DiagnosticReport",
    "run_full_diagnostics",
    "run_diagnostics_sync",
    # Scope
    "ScopeValidator",
    "ScopeDefinition",
    "ScopeTarget",
    # Rate Limiter
    "RateLimiter",
    "RateLimitConfig",
    # Sanitizer
    "sanitize_command_arg",
    "sanitize_url",
    "sanitize_hostname",
    "sanitize_path",
    "sanitize_filename",
    "sanitize_for_log",
    "mask_sensitive",
    # Network
    "resolve_hostname",
    "normalize_url",
    "get_domain_from_url",
    "get_base_domain",
    "is_port_open",
    "is_valid_ip",
    "is_valid_domain",
    "expand_cidr",
    # Crypto
    "sha256",
    "md5",
    "base64_encode",
    "base64_decode",
    "decode_jwt",
    "analyze_jwt_security",
    "get_ssl_cert_info",
    "identify_hash",
    "generate_random_token",
    # File
    "ensure_output_dirs",
    "create_session_dir",
    "read_json",
    "write_json",
    "read_lines",
    "write_lines",
    "load_wordlist",
    "file_sha256",
    "human_readable_size",
]
