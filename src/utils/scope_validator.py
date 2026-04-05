"""
WhiteHatHacker AI — Scope Doğrulama Modülü

Her araç çalıştırılmadan önce hedef scope kontrolü yapar.
Scope dışına çıkma GÜVENLİK MEKANİZMASI olarak her zaman aktiftir.
Devre dışı bırakılamaz.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from loguru import logger


@dataclass
class ScopeTarget:
    """Scope içindeki tek bir hedef tanımı."""

    value: str                          # domain, IP, CIDR, wildcard
    target_type: str = "domain"         # domain | ip | cidr | wildcard | url
    include: bool = True                # True = scope içi, False = hariç
    notes: str = ""


@dataclass
class ScopeDefinition:
    """Tam scope tanımı."""

    program_name: str = ""
    targets: list[ScopeTarget] = field(default_factory=list)
    excluded_targets: list[ScopeTarget] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    max_depth: int = 10                  # Subdomain derinliği
    allow_ip_resolution: bool = True
    follow_redirects_in_scope: bool = True

    @property
    def in_scope_domains(self) -> list[str]:
        """Scope içi domain'leri döndür."""
        return [t.value for t in self.targets if t.include and t.target_type in ("domain", "wildcard")]

    @property
    def out_of_scope_domains(self) -> list[str]:
        """Scope dışı domain'leri döndür."""
        return [t.value for t in self.excluded_targets]


class ScopeValidator:
    """
    Scope doğrulama motoru.

    Her hedef operasyonundan önce çağrılır.
    Scope dışı hedeflere hiçbir request gönderilmez.
    """

    def __init__(self, scope: ScopeDefinition) -> None:
        self.scope = scope
        self._resolved_ips: dict[str, list[str]] = {}
        logger.info(f"ScopeValidator initialized | program={scope.program_name} | "
                     f"targets={len(scope.targets)} | excluded={len(scope.excluded_targets)}")

    def is_in_scope(self, target: str) -> bool:
        """
        Hedefin scope içinde olup olmadığını kontrol et.

        Args:
            target: Domain, IP, URL veya CIDR

        Returns:
            True ise scope içi
        """
        # Bare paths (e.g. "/api/data") have no hostname and cannot be
        # scope-checked.  Reject them early with a clear message so calling
        # code can detect and resolve them to full URLs.
        if target.startswith("/") and "://" not in target:
            logger.debug(f"SCOPE REJECT (bare path, no hostname) | target={target}")
            return False

        # URL ise domain'i çıkar
        parsed = urlparse(target) if "://" in target else urlparse(f"http://{target}")
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        if not hostname:
            # Fallback for bare hostnames
            hostname = target.split("/")[0].split(":")[0]

        # Hariç tutulan path kontrolü
        if path and self._is_excluded_path(path):
            logger.debug(f"SCOPE REJECT (excluded path) | target={target} | path={path}")
            return False

        # Hariç tutulan domain kontrolü
        if self._is_excluded(hostname):
            logger.debug(f"SCOPE REJECT (excluded domain) | target={target}")
            return False

        # IP adresi mi?
        if self._is_ip(hostname):
            result = self._check_ip_scope(hostname)
        else:
            result = self._check_domain_scope(hostname)

        if not result:
            logger.debug(f"SCOPE REJECT | target={target}")
        else:
            logger.debug(f"SCOPE OK | target={target}")

        return result

    def validate_target(self, target: str) -> tuple[bool, str]:
        """
        Hedefi doğrula ve neden döndür.

        Returns:
            (is_valid, reason)
        """
        if not target or not target.strip():
            return False, "Empty target"

        if self.is_in_scope(target):
            return True, "Target is in scope"

        return False, f"Target '{target}' is OUT OF SCOPE"

    def validate_targets(self, targets: list[str]) -> list[tuple[str, bool, str]]:
        """Birden fazla hedefi toplu doğrula."""
        results = []
        for target in targets:
            is_valid, reason = self.validate_target(target)
            results.append((target, is_valid, reason))
        return results

    def filter_in_scope(self, targets: list[str]) -> list[str]:
        """Sadece scope içi hedefleri döndür."""
        return [t for t in targets if self.is_in_scope(t)]

    def check_redirect_scope(self, original_url: str, redirect_url: str) -> bool:
        """Redirect hedefinin scope içinde olup olmadığını kontrol et."""
        if not self.scope.follow_redirects_in_scope:
            return False
        return self.is_in_scope(redirect_url)

    # ── Private Helpers ──────────────────────────────────────

    def _check_domain_scope(self, domain: str) -> bool:
        """Domain'in scope içinde olup olmadığını kontrol et."""
        domain = domain.lower().strip(".")

        for target in self.scope.targets:
            if not target.include:
                continue

            pattern = target.value.lower().strip(".")

            if target.target_type == "wildcard":
                # *.example.com → her subdomain geçerli
                base = pattern.removeprefix("*.").lstrip(".")
                if domain == base or domain.endswith(f".{base}"):
                    return True

            elif target.target_type == "domain":
                if domain == pattern or domain.endswith(f".{pattern}"):
                    return True

            elif target.target_type == "url":
                parsed = urlparse(pattern)
                if parsed.hostname and (domain == parsed.hostname.lower()):
                    return True

        # IP resolution ile kontrol
        if self.scope.allow_ip_resolution:
            return self._check_ip_after_resolution(domain)

        return False

    def _check_ip_scope(self, ip: str) -> bool:
        """IP adresinin scope içinde olup olmadığını kontrol et."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for target in self.scope.targets:
            if not target.include:
                continue

            if target.target_type == "ip":
                try:
                    if ip_obj == ipaddress.ip_address(target.value):
                        return True
                except ValueError:
                    continue

            elif target.target_type == "cidr":
                try:
                    network = ipaddress.ip_network(target.value, strict=False)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue

        return False

    def _check_ip_after_resolution(self, domain: str) -> bool:
        """DNS çözümleme sonrası IP'nin scope içinde olup olmadığını kontrol et."""
        if domain in self._resolved_ips:
            ips = self._resolved_ips[domain]
        else:
            try:
                # HIGH-6 fix: This is sync but called from sync context.
                # For async callers, use is_in_scope_async() instead.
                ips = [addr[4][0] for addr in socket.getaddrinfo(domain, None)]
                self._resolved_ips[domain] = ips
            except (socket.gaierror, OSError):
                return False

        return any(self._check_ip_scope(ip) for ip in ips)

    async def is_in_scope_async(self, target: str) -> bool:
        """Async scope kontrolü — DNS çözümleme event loop'u bloklamaz."""
        import asyncio
        return await asyncio.to_thread(self.is_in_scope, target)

    def _is_excluded(self, hostname: str) -> bool:
        """Hostname'in hariç tutulanlar listesinde olup olmadığını kontrol et."""
        hostname = hostname.lower().strip(".")

        for target in self.scope.excluded_targets:
            pattern = target.value.lower().strip(".")
            if hostname == pattern or hostname.endswith(f".{pattern}"):
                return True

        return False

    def _is_excluded_path(self, path: str) -> bool:
        """Path'in hariç tutulan path'lerde olup olmadığını kontrol et."""
        path = path.lower()
        for excluded in self.scope.excluded_paths:
            if path.startswith(excluded.lower()):
                return True
        return False

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Değerin IP adresi olup olmadığını kontrol et."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    # ── Scope Yükleme ────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScopeValidator":
        """Dict'ten ScopeValidator oluştur."""
        targets = []
        for t in data.get("targets", []):
            targets.append(ScopeTarget(
                value=t["value"],
                target_type=t.get("target_type", t.get("type", "domain")),
                include=t.get("include", True),
                notes=t.get("notes", ""),
            ))

        excluded = []
        # Support both "excluded" and "exclusions" keys
        excluded_raw = data.get("excluded", data.get("exclusions", []))
        for t in excluded_raw:
            excluded.append(ScopeTarget(
                value=t["value"] if isinstance(t, dict) else t,
                target_type=t.get("target_type", t.get("type", "domain")) if isinstance(t, dict) else "domain",
                include=False,
            ))

        scope = ScopeDefinition(
            program_name=data.get("program_name", ""),
            targets=targets,
            excluded_targets=excluded,
            excluded_paths=data.get("excluded_paths", []),
        )

        return cls(scope)


__all__ = ["ScopeValidator", "ScopeDefinition", "ScopeTarget"]
