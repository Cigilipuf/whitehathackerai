"""
WhiteHatHacker AI — Cryptography Utilities

Hash, encoding, SSL sertifika analizi ve kriptografi yardımcıları.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import ssl
import socket
from datetime import datetime, timezone
from typing import Any

from loguru import logger


# ============================================================
# Hashing
# ============================================================

def md5(data: str | bytes) -> str:
    """MD5 hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.md5(data).hexdigest()


def sha1(data: str | bytes) -> str:
    """SHA-1 hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha1(data).hexdigest()


def sha256(data: str | bytes) -> str:
    """SHA-256 hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha512(data: str | bytes) -> str:
    """SHA-512 hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha512(data).hexdigest()


def identify_hash(hash_str: str) -> list[str]:
    """Hash tipini tahmin et (uzunluk bazlı)."""
    length = len(hash_str)
    candidates: list[str] = []

    hash_lengths = {
        32: ["MD5", "NTLM"],
        40: ["SHA-1"],
        56: ["SHA-224"],
        64: ["SHA-256", "SHA3-256"],
        96: ["SHA-384", "SHA3-384"],
        128: ["SHA-512", "SHA3-512"],
        13: ["DES(crypt)"],
        34: ["bcrypt (prefix $2)"],
    }

    if hash_str.startswith("$2"):
        candidates.append("bcrypt")
    elif hash_str.startswith("$6$"):
        candidates.append("SHA-512 (crypt)")
    elif hash_str.startswith("$5$"):
        candidates.append("SHA-256 (crypt)")
    elif hash_str.startswith("$1$"):
        candidates.append("MD5 (crypt)")

    candidates.extend(hash_lengths.get(length, []))

    # Hex check
    if re.match(r'^[0-9a-fA-F]+$', hash_str) and not candidates:
        candidates.append(f"Unknown hex hash (length={length})")

    return candidates or ["Unknown"]


def hmac_sha256(key: str | bytes, message: str | bytes) -> str:
    """HMAC-SHA256."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# ============================================================
# Encoding / Decoding
# ============================================================

def base64_encode(data: str | bytes) -> str:
    """Base64 encode."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def base64_decode(data: str) -> str:
    """Base64 decode."""
    # Padding düzeltme
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except Exception as _exc:
        logger.debug(f"crypto utils error: {_exc}")
        return ""


def base64url_decode(data: str) -> str:
    """URL-safe Base64 decode (JWT vb.)."""
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except Exception as _exc:
        logger.debug(f"crypto utils error: {_exc}")
        return ""


def hex_encode(data: str | bytes) -> str:
    """Hex encode."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return data.hex()


def hex_decode(data: str) -> str:
    """Hex decode."""
    try:
        return bytes.fromhex(data).decode("utf-8", errors="replace")
    except ValueError:
        return ""


# ============================================================
# JWT Analysis
# ============================================================

def decode_jwt(token: str) -> dict[str, Any]:
    """JWT token'ı decode et (signature doğrulaması YAPMAZ)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}

    try:
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))

        result: dict[str, Any] = {
            "header": header,
            "payload": payload,
            "signature": parts[2][:20] + "...",
            "algorithm": header.get("alg", "unknown"),
        }

        # Expiry kontrolü
        if "exp" in payload:
            exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            result["expires_at"] = exp_dt.isoformat()
            result["is_expired"] = exp_dt < datetime.now(timezone.utc)

        # Zayıf algoritma kontrolü — only 'none' is truly weak
        # HS256/HS384 are symmetric but NOT weak by default
        if header.get("alg", "").lower() == "none":
            result["weak_algorithm"] = True
        elif header.get("alg") in ("HS256", "HS384"):
            result["symmetric_algorithm"] = True

        return result
    except Exception as e:
        return {"error": str(e)}


def analyze_jwt_security(token: str) -> list[str]:
    """JWT güvenlik sorunlarını analiz et."""
    issues: list[str] = []
    decoded = decode_jwt(token)

    if "error" in decoded:
        return [f"JWT decode error: {decoded['error']}"]

    header = decoded.get("header", {})
    payload = decoded.get("payload", {})

    # alg: none
    if header.get("alg", "").lower() == "none":
        issues.append("CRITICAL: Algorithm set to 'none' — signature bypass possible")

    # Zayıf HMAC
    if header.get("alg") in ("HS256", "HS384"):
        issues.append("WARNING: Symmetric algorithm (HMAC) — brute-force risky if weak secret")

    # jku/x5u — SSRF vektörü
    if header.get("jku") or header.get("x5u"):
        issues.append("WARNING: JKU/X5U header present — potential SSRF via key URL injection")

    # kid — injection vektörü
    if header.get("kid"):
        issues.append("INFO: KID header present — test for SQL injection / path traversal")

    # Expired
    if decoded.get("is_expired"):
        issues.append("INFO: Token is expired")

    # No expiry
    if "exp" not in payload:
        issues.append("WARNING: No expiration claim — token never expires")

    # Sensitive data in payload
    sensitive_keys = {"password", "secret", "credit_card", "ssn", "api_key"}
    found_sensitive = sensitive_keys & set(payload.keys())
    if found_sensitive:
        issues.append(f"WARNING: Sensitive data in payload: {found_sensitive}")

    return issues


# ============================================================
# SSL/TLS Certificate
# ============================================================

def get_ssl_cert_info(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """SSL sertifika bilgilerini al."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)

                if not cert:
                    # Binary form'dan DER ile parse
                    der_cert = ssock.getpeercert(binary_form=True)
                    return {
                        "hostname": hostname,
                        "protocol": ssock.version(),
                        "cipher": ssock.cipher(),
                        "der_cert_size": len(der_cert) if der_cert else 0,
                    }

                info: dict[str, Any] = {
                    "hostname": hostname,
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "serial_number": cert.get("serialNumber", ""),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "san": [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"],
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                }

                return info

    except Exception as e:
        return {"hostname": hostname, "error": str(e)}


# ============================================================
# Random / Token Generation
# ============================================================

def generate_random_token(length: int = 32) -> str:
    """Kriptografik olarak güvenli rastgele token."""
    return secrets.token_hex(length // 2)


def generate_random_string(length: int = 16, alphabet: str = "") -> str:
    """Rastgele string üret."""
    if not alphabet:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


__all__ = [
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "identify_hash",
    "hmac_sha256",
    "base64_encode",
    "base64_decode",
    "base64url_decode",
    "hex_encode",
    "hex_decode",
    "decode_jwt",
    "analyze_jwt_security",
    "get_ssl_cert_info",
    "generate_random_token",
    "generate_random_string",
]
