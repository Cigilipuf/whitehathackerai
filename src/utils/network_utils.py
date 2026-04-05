"""
WhiteHatHacker AI — Network Utilities

Ağ işlemleri için yardımcı fonksiyonlar.
DNS çözümleme, port kontrolü, CIDR işlemleri, HTTP yardımcıları.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse, parse_qs, urlencode

from loguru import logger


# ============================================================
# DNS & Resolution
# ============================================================

def resolve_hostname(hostname: str) -> list[str]:
    """Hostname → IP çözümle (senkron)."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ips = list({r[4][0] for r in results})
        return sorted(ips)
    except socket.gaierror:
        return []


async def async_resolve_hostname(hostname: str) -> list[str]:
    """Hostname → IP çözümle (async)."""
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(hostname, None)
        ips = list({r[4][0] for r in results})
        return sorted(ips)
    except socket.gaierror:
        return []


def reverse_dns(ip: str) -> str:
    """IP → hostname (reverse DNS)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return ""


def get_domain_from_url(url: str) -> str:
    """URL'den domain çıkar."""
    parsed = urlparse(url)
    return parsed.hostname or ""


def get_base_domain(hostname: str) -> str:
    """Subdomain'i çıkarıp base domain döndür (basit heuristik)."""
    parts = hostname.rstrip(".").split(".")
    if len(parts) <= 2:
        return hostname

    # .co.uk, .com.tr gibi ikili TLD'lere dikkat
    known_double_tlds = {
        "co.uk", "com.tr", "com.br", "com.au", "co.jp", "co.kr",
        "org.uk", "net.au", "ac.uk", "gov.uk", "com.cn", "co.in",
    }

    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in known_double_tlds and len(parts) > 2:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


# ============================================================
# Port Operations
# ============================================================

def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """TCP port açık mı kontrol et."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


async def async_is_port_open(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> bool:
    """TCP port açık mı kontrol et (async)."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def quick_port_scan(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    max_concurrent: int = 50,
) -> list[int]:
    """Hızlı port tarama (async, semaphore ile)."""
    if ports is None:
        # Top 20 common ports
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        ]

    sem = asyncio.Semaphore(max_concurrent)

    async def check(port: int) -> int | None:
        async with sem:
            if await async_is_port_open(host, port, timeout):
                return port
            return None

    results = await asyncio.gather(*[check(p) for p in ports])
    return sorted(p for p in results if p is not None)


# ============================================================
# CIDR & IP Utilities
# ============================================================

def expand_cidr(cidr: str) -> list[str]:
    """CIDR → IP listesi (max 1024 host)."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > 1024:
            logger.warning(f"CIDR {cidr} too large ({len(hosts)} hosts), limiting to 1024")
            hosts = hosts[:1024]
        return [str(h) for h in hosts]
    except ValueError:
        return []


def is_private_ip(ip: str) -> bool:
    """IP özel ağda mı?"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Geçerli IP adresi mi?"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Geçerli CIDR mi?"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


# ============================================================
# URL Utilities
# ============================================================

def normalize_url(url: str) -> str:
    """URL'i normalize et (scheme ekle, trailing slash)."""
    url = url.strip()
    if not url:
        return ""

    if not url.startswith(("http://", "https://", "ftp://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    # Hostname lowercase
    normalized = parsed._replace(netloc=parsed.netloc.lower())
    return normalized.geturl()


def extract_params_from_url(url: str) -> dict[str, list[str]]:
    """URL'den query parametrelerini çıkar."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url_with_params(base_url: str, params: dict[str, str]) -> str:
    """URL'e parametre ekle."""
    parsed = urlparse(base_url)
    existing = parse_qs(parsed.query)
    existing.update({k: [v] for k, v in params.items()})

    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in existing.items()}
    new_query = urlencode(flat_params)

    return parsed._replace(query=new_query).geturl()


def get_url_path(url: str) -> str:
    """URL'den path kısmını al."""
    return urlparse(url).path


def is_same_origin(url1: str, url2: str) -> bool:
    """İki URL aynı origin'de mi?"""
    p1, p2 = urlparse(url1), urlparse(url2)
    return (p1.scheme == p2.scheme and p1.netloc == p2.netloc)


# ============================================================
# HTTP Helpers
# ============================================================

def parse_content_type(header: str) -> tuple[str, str]:
    """Content-Type header → (mime_type, charset)."""
    parts = header.split(";")
    mime = parts[0].strip().lower()
    charset = ""
    for part in parts[1:]:
        part = part.strip()
        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip().strip('"\'')
    return mime, charset


def parse_server_header(header: str) -> dict[str, str]:
    """Server header → bilgi dict."""
    info: dict[str, str] = {"raw": header}

    # Apache/2.4.52 (Ubuntu)
    match = re.match(r'(\w+)(?:/([^\s(]+))?\s*(?:\(([^)]+)\))?', header)
    if match:
        info["server"] = match.group(1)
        if match.group(2):
            info["version"] = match.group(2)
        if match.group(3):
            info["os"] = match.group(3)

    return info


# ============================================================
# Misc
# ============================================================

def is_valid_domain(domain: str) -> bool:
    """Geçerli domain adı mı?"""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(pattern.match(domain)) and len(domain) <= 253


def parse_host_port(target: str) -> tuple[str, int]:
    """'host:port' → (host, port) tuple. Port yoksa 0 döner."""
    if ":" in target and not target.startswith("["):
        parts = target.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return target, 0
    return target, 0


__all__ = [
    "resolve_hostname",
    "async_resolve_hostname",
    "reverse_dns",
    "get_domain_from_url",
    "get_base_domain",
    "is_port_open",
    "async_is_port_open",
    "quick_port_scan",
    "expand_cidr",
    "is_private_ip",
    "is_valid_ip",
    "is_valid_cidr",
    "normalize_url",
    "extract_params_from_url",
    "build_url_with_params",
    "get_url_path",
    "is_same_origin",
    "parse_content_type",
    "parse_server_header",
    "is_valid_domain",
    "parse_host_port",
]
