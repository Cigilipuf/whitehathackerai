"""
WhiteHatHacker AI — Input/Output Sanitization

Güvenli giriş/çıkış sanitizasyonu.
Komut enjeksiyonu, path traversal ve log injection önleme.
"""

from __future__ import annotations

import html
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from loguru import logger


# ============================================================
# Command Sanitization
# ============================================================

# Tehlikeli shell karakterleri
_SHELL_DANGEROUS = re.compile(r'[;&|`$(){}!<>\n\r]')

# Path traversal kalıpları
_PATH_TRAVERSAL = re.compile(r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./)', re.IGNORECASE)


def sanitize_command_arg(arg: str) -> str:
    """
    Shell komutu argümanını sanitize et.
    shlex.quote ile sarmalayarak enjeksiyonu önle.
    """
    if not arg:
        return "''"
    return shlex.quote(arg)


def sanitize_command_args(args: list[str]) -> list[str]:
    """Argüman listesini sanitize et."""
    return [sanitize_command_arg(a) for a in args]


def is_safe_command_arg(arg: str) -> bool:
    """Argüman güvenli mi kontrol et."""
    return not bool(_SHELL_DANGEROUS.search(arg))


def strip_shell_chars(text: str) -> str:
    """Shell metacharacter'larını temizle (quote yapmadan)."""
    return _SHELL_DANGEROUS.sub("", text)


# ============================================================
# URL Sanitization
# ============================================================

def sanitize_url(url: str) -> str:
    """URL'i sanitize et — tehlikeli şemaları engelle."""
    url = url.strip()

    parsed = urlparse(url)

    # Sadece http/https/ftp kabul et
    allowed_schemes = {"http", "https", "ftp", "ftps", ""}
    if parsed.scheme.lower() not in allowed_schemes:
        logger.warning(f"Dangerous URL scheme blocked: {parsed.scheme}")
        return ""

    # javascript: / data: / file: engelle
    lower = url.lower().lstrip()
    for dangerous in ("javascript:", "data:", "file:", "vbscript:"):
        if lower.startswith(dangerous):
            logger.warning(f"Dangerous URL protocol blocked: {dangerous}")
            return ""

    return url


def sanitize_hostname(hostname: str) -> str:
    """Hostname sanitize et."""
    # Sadece alfanumerik, nokta, tire kabul et
    cleaned = re.sub(r'[^a-zA-Z0-9.\-_]', '', hostname)
    # Uzunluk limiti
    if len(cleaned) > 253:
        cleaned = cleaned[:253]
    return cleaned


def sanitize_ip(ip: str) -> str:
    """IP adresi sanitize et."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip.strip())
        return str(addr)
    except ValueError:
        # CIDR denemesi
        try:
            net = ipaddress.ip_network(ip.strip(), strict=False)
            return str(net)
        except ValueError:
            return ""


# ============================================================
# Path Sanitization
# ============================================================

def sanitize_path(path: str, base_dir: str = "") -> str:
    """
    Dosya yolunu sanitize et.
    Path traversal saldırılarını engelle.
    """
    path = path.strip()

    # Null byte engelle
    path = path.replace("\x00", "")

    # Path traversal kontrolü
    if _PATH_TRAVERSAL.search(path):
        logger.warning(f"Path traversal attempt blocked: {path}")
        return ""

    if base_dir:
        # base_dir altında olduğunu doğrula
        try:
            resolved = Path(base_dir).resolve() / path
            resolved = resolved.resolve()

            if not str(resolved).startswith(str(Path(base_dir).resolve())):
                logger.warning(f"Path escape attempt blocked: {path}")
                return ""

            return str(resolved)
        except Exception as _exc:
            logger.debug(f"sanitizer error: {_exc}")
            return ""

    return path


def sanitize_filename(filename: str) -> str:
    """Dosya adını sanitize et."""
    # Tehlikeli karakterleri temizle
    filename = re.sub(r'[^\w\s\-.]', '', filename)
    # Çift noktayı temizle
    filename = re.sub(r'\.{2,}', '.', filename)
    # Başındaki/sonundaki nokta/boşluk
    filename = filename.strip('. ')
    # Uzunluk limiti
    if len(filename) > 200:
        filename = filename[:200]
    return filename or "unnamed"


# ============================================================
# Log Sanitization
# ============================================================

def sanitize_for_log(text: str, max_length: int = 500) -> str:
    """
    Log çıktısı için sanitize et.
    Log injection ve ANSI escape saldırılarını engelle.
    """
    if not text:
        return ""

    # Newline ve carriage return — log enjeksiyonu
    text = text.replace("\n", "\\n").replace("\r", "\\r")

    # ANSI escape kodları
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    text = ansi_pattern.sub("", text)

    # Null bytes
    text = text.replace("\x00", "")

    # Uzunluk limiti
    if len(text) > max_length:
        text = text[:max_length] + "...[truncated]"

    return text


def sanitize_for_display(text: str) -> str:
    """Terminal çıktısı için sanitize et."""
    # ANSI kodlarını temizle
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_pattern.sub("", text)


# ============================================================
# HTML Sanitization
# ============================================================

def sanitize_html(text: str) -> str:
    """HTML'de kullanım için escape et."""
    return html.escape(text, quote=True)


def strip_html_tags(text: str) -> str:
    """HTML etiketlerini temizle."""
    return re.sub(r'<[^>]+>', '', text)


# ============================================================
# Generic Sanitization
# ============================================================

def sanitize_dict_values(
    data: dict[str, Any],
    max_depth: int = 5,
    _depth: int = 0,
) -> dict[str, Any]:
    """Dict içindeki tüm string değerleri log-safe yap."""
    if _depth > max_depth:
        return data

    result = {}
    for k, v in data.items():
        if isinstance(v, str):
            result[k] = sanitize_for_log(v, max_length=2000)
        elif isinstance(v, dict):
            result[k] = sanitize_dict_values(v, max_depth, _depth + 1)
        elif isinstance(v, list):
            result[k] = [
                sanitize_dict_values(i, max_depth, _depth + 1) if isinstance(i, dict)
                else sanitize_for_log(i, 2000) if isinstance(i, str)
                else i
                for i in v
            ]
        else:
            result[k] = v

    return result


def mask_sensitive(text: str) -> str:
    """Hassas bilgileri maskele (API key, token, password)."""
    # API key / token pattern
    patterns = [
        (r'(api[_-]?key|token|secret|password|authorization)[=:\s]+["\']?([^\s"\'&]{4})[^\s"\'&]*', r'\1=\2****'),
        (r'(Bearer\s+)([^\s]{4})[^\s]*', r'\1\2****'),
    ]

    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text


__all__ = [
    "sanitize_command_arg",
    "sanitize_command_args",
    "is_safe_command_arg",
    "strip_shell_chars",
    "sanitize_url",
    "sanitize_hostname",
    "sanitize_ip",
    "sanitize_path",
    "sanitize_filename",
    "sanitize_for_log",
    "sanitize_for_display",
    "sanitize_html",
    "strip_html_tags",
    "sanitize_dict_values",
    "mask_sensitive",
]
