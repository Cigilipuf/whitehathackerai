"""
WhiteHatHacker AI — Attack Surface Mapper

Tüm keşif verilerini birleştirerek hedefin saldırı yüzeyini
haritalayan, Risk skoru hesaplayan ve saldırı stratejisi
önceliklendirmesi yapan modül.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ============================================================
# Models
# ============================================================

class Endpoint(BaseModel):
    """Tek bir keşfedilmiş endpoint."""

    url: str = ""
    host: str = ""
    port: int = 0
    protocol: str = ""          # http, https, ftp, ssh, smb …
    method: str = "GET"         # HTTP method (web endpointler için)
    path: str = "/"
    parameters: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    technology: list[str] = Field(default_factory=list)
    auth_required: bool = False
    content_type: str = ""
    status_code: int = 0
    risk_score: float = 0.0
    notes: str = ""
    source_tool: str = ""       # Keşfeden araç

    @property
    def id(self) -> str:
        raw = f"{self.host}:{self.port}{self.path}:{self.method}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class HostProfile(BaseModel):
    """Bir host'un genel profili."""

    hostname: str = ""
    ip: str = ""
    ports: list[int] = Field(default_factory=list)
    services: dict[int, str] = Field(default_factory=dict)       # port → service
    versions: dict[int, str] = Field(default_factory=dict)       # port → version banner
    technologies: list[str] = Field(default_factory=list)
    os_guess: str = ""
    is_web: bool = False
    is_cdn: bool = False
    is_waf: bool = False
    waf_name: str = ""
    endpoints: list[Endpoint] = Field(default_factory=list)
    risk_score: float = 0.0


class AttackVector(BaseModel):
    """Tanımlanmış bir saldırı vektörü."""

    name: str
    category: str               # web_injection, auth, config, crypto, network, logic
    target_endpoint: str = ""
    target_host: str = ""
    target_port: int = 0
    target_parameter: str = ""
    technique: str = ""         # sqlmap, xsstrike, custom …
    priority: int = 0           # 1 (en yüksek) → 10 (en düşük)
    estimated_severity: str = "medium"   # critical, high, medium, low, info
    rationale: str = ""
    tools_to_use: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)


class AttackSurfaceReport(BaseModel):
    """Tam saldırı yüzeyi raporu."""

    target: str = ""
    generated_at: str = ""
    total_hosts: int = 0
    total_endpoints: int = 0
    total_parameters: int = 0
    total_attack_vectors: int = 0
    hosts: list[HostProfile] = Field(default_factory=list)
    attack_vectors: list[AttackVector] = Field(default_factory=list)
    overall_risk: float = 0.0
    summary: str = ""


# ============================================================
# Risk tanımları — port/servis/teknoloji bazlı ağırlıklar
# ============================================================

# Yüksek riskli portlar ve ağırlıkları
HIGH_RISK_PORTS: dict[int, tuple[str, float]] = {
    21:    ("FTP", 6.0),
    22:    ("SSH", 3.0),
    23:    ("Telnet", 8.0),
    25:    ("SMTP", 4.0),
    53:    ("DNS", 4.0),
    80:    ("HTTP", 5.0),
    110:   ("POP3", 5.0),
    111:   ("RPC", 7.0),
    135:   ("MSRPC", 7.0),
    139:   ("NetBIOS", 7.0),
    143:   ("IMAP", 4.0),
    161:   ("SNMP", 6.5),
    389:   ("LDAP", 6.0),
    443:   ("HTTPS", 4.0),
    445:   ("SMB", 8.0),
    512:   ("rexec", 9.0),
    513:   ("rlogin", 9.0),
    514:   ("rsh", 9.0),
    1433:  ("MSSQL", 8.0),
    1521:  ("Oracle", 8.0),
    2049:  ("NFS", 7.0),
    3306:  ("MySQL", 8.0),
    3389:  ("RDP", 7.0),
    5432:  ("PostgreSQL", 8.0),
    5900:  ("VNC", 8.0),
    5984:  ("CouchDB", 7.0),
    6379:  ("Redis", 9.0),
    8080:  ("HTTP-Alt", 5.0),
    8443:  ("HTTPS-Alt", 4.0),
    9200:  ("Elasticsearch", 8.0),
    27017: ("MongoDB", 9.0),
}

# Teknoloji risk ağırlıkları
TECH_RISK_WEIGHTS: dict[str, float] = {
    # CMS / frameworks with large attack surface
    "wordpress": 7.0,
    "joomla": 7.0,
    "drupal": 6.0,
    "magento": 7.0,
    "wp-admin": 8.0,
    "phpmyadmin": 9.0,
    "phpinfo": 6.0,
    # Specific servers
    "apache": 3.0,
    "nginx": 2.5,
    "iis": 4.0,
    "tomcat": 5.0,
    "weblogic": 7.0,
    "websphere": 6.0,
    "jenkins": 8.0,
    "grafana": 5.0,
    "kibana": 6.0,
    "elastic": 7.0,
    # Languages / frameworks
    "php": 4.5,
    "asp.net": 3.5,
    "java": 3.5,
    "python": 2.5,
    "node.js": 3.0,
    "express": 3.0,
    "django": 2.5,
    "flask": 3.0,
    "laravel": 3.5,
    "spring": 3.5,
    "ruby on rails": 3.0,
    # Security headers missing signal
    "graphql": 6.0,
    "swagger": 5.5,
    "api": 4.0,
}

# Parametre ismi → zafiyet potansiyeli
PARAM_RISK_MAP: dict[str, tuple[str, float]] = {
    "id":           ("idor", 7.0),
    "user_id":      ("idor", 8.0),
    "uid":          ("idor", 7.5),
    "file":         ("lfi", 8.5),
    "path":         ("lfi", 8.5),
    "filename":     ("lfi", 8.0),
    "page":         ("lfi", 7.0),
    "dir":          ("lfi", 7.0),
    "include":      ("lfi", 9.0),
    "url":          ("ssrf", 9.0),
    "redirect":     ("open_redirect", 6.0),
    "return":       ("open_redirect", 5.5),
    "next":         ("open_redirect", 5.5),
    "callback":     ("ssrf", 7.0),
    "dest":         ("open_redirect", 6.0),
    "target":       ("ssrf", 7.5),
    "q":            ("xss", 5.0),
    "search":       ("xss", 5.5),
    "query":        ("sqli", 7.0),
    "s":            ("xss", 5.0),
    "keyword":      ("xss", 5.0),
    "input":        ("xss", 5.5),
    "name":         ("xss", 4.5),
    "email":        ("xss", 4.0),
    "comment":      ("xss_stored", 7.0),
    "body":         ("xss_stored", 6.5),
    "message":      ("xss_stored", 6.5),
    "cmd":          ("cmdi", 10.0),
    "exec":         ("cmdi", 10.0),
    "command":      ("cmdi", 10.0),
    "ping":         ("cmdi", 9.0),
    "template":     ("ssti", 8.5),
    "sort":         ("sqli", 6.5),
    "order":        ("sqli", 6.5),
    "column":       ("sqli", 7.0),
    "table":        ("sqli", 7.0),
    "category":     ("sqli", 5.0),
    "lang":         ("lfi", 6.0),
    "token":        ("auth_bypass", 7.0),
    "jwt":          ("auth_bypass", 8.0),
    "admin":        ("auth_bypass", 7.0),
    "role":         ("privilege_escalation", 8.0),
    "debug":        ("info_disclosure", 6.0),
    "test":         ("info_disclosure", 4.0),
}


# ============================================================
# Attack Surface Mapper
# ============================================================

class AttackSurfaceMapper:
    """
    Saldırı yüzeyi haritası oluşturur.

    Keşif ve tarama aşamalarından toplanan verileri birleştirir,
    her endpoint/host için risk skoru hesaplar, ve önceliklendirilmiş
    saldırı vektörleri önerir.

    Usage:
        mapper = AttackSurfaceMapper()
        mapper.add_host(HostProfile(hostname="target.com", ports=[80, 443, 3306]))
        mapper.add_endpoint(Endpoint(host="target.com", port=80, path="/api/v1/users", parameters=["id"]))

        report = mapper.build_report("target.com")
    """

    def __init__(self) -> None:
        self._hosts: dict[str, HostProfile] = {}
        self._endpoints: list[Endpoint] = []
        self._vectors: list[AttackVector] = []

    # ── Data ingestion ──────────────────────────────────────

    def add_host(self, host: HostProfile) -> None:
        """Host ekle veya mevcut host'u güncelle."""
        key = host.hostname or host.ip
        if key in self._hosts:
            existing = self._hosts[key]
            existing.ports = list(set(existing.ports + host.ports))
            existing.services.update(host.services)
            existing.versions.update(host.versions)
            existing.technologies = list(set(existing.technologies + host.technologies))
            if host.os_guess:
                existing.os_guess = host.os_guess
            existing.is_web = existing.is_web or host.is_web
            existing.is_cdn = existing.is_cdn or host.is_cdn
            existing.is_waf = existing.is_waf or host.is_waf
            if host.waf_name:
                existing.waf_name = host.waf_name
        else:
            self._hosts[key] = host
        logger.debug(f"Host added/updated: {key}")

    def add_endpoint(self, ep: Endpoint) -> None:
        """Endpoint ekle (duplicate kontrolu ile)."""
        for existing in self._endpoints:
            if (existing.host == ep.host and existing.port == ep.port
                and existing.path == ep.path and existing.method == ep.method):
                # Merge parameters
                existing.parameters = list(set(existing.parameters + ep.parameters))
                existing.technology = list(set(existing.technology + ep.technology))
                return
        self._endpoints.append(ep)

    def add_hosts_from_recon(self, recon_data: dict[str, Any]) -> None:
        """
        Recon aşaması çıktılarından host bilgileri ekle.

        Expected keys: subdomains, ports, services, technologies
        """
        subdomains = recon_data.get("subdomains", [])
        ports_map = recon_data.get("ports", {})          # host → [ports]
        services_map = recon_data.get("services", {})    # host → {port: service}
        tech_map = recon_data.get("technologies", {})    # host → [tech]

        for sub in subdomains:
            host = HostProfile(
                hostname=sub,
                ports=ports_map.get(sub, []),
                services=services_map.get(sub, {}),
                technologies=tech_map.get(sub, []),
                is_web=any(p in [80, 443, 8080, 8443] for p in ports_map.get(sub, [])),
            )
            self.add_host(host)

    def add_endpoints_from_crawl(self, crawl_results: list[dict[str, Any]]) -> None:
        """
        Crawler çıktılarından endpoint ekle.

        Her item: {url, host, port, path, method, parameters, status_code, content_type}
        """
        for item in crawl_results:
            ep = Endpoint(
                url=item.get("url", ""),
                host=item.get("host", ""),
                port=item.get("port", 80),
                protocol=item.get("protocol", "http"),
                method=item.get("method", "GET"),
                path=item.get("path", "/"),
                parameters=item.get("parameters", []),
                status_code=item.get("status_code", 0),
                content_type=item.get("content_type", ""),
                source_tool=item.get("source_tool", ""),
            )
            self.add_endpoint(ep)

    # ── Risk scoring ────────────────────────────────────────

    def _score_host(self, host: HostProfile) -> float:
        """Host risk skoru hesapla (0-100)."""
        score = 0.0

        # Port bazlı risk
        for port in host.ports:
            if port in HIGH_RISK_PORTS:
                _, weight = HIGH_RISK_PORTS[port]
                score += weight

        # Servis bazlı bonus
        for port, svc in host.services.items():
            svc_lower = svc.lower()
            if "ftp" in svc_lower and "anonymous" in svc_lower:
                score += 10
            if "telnet" in svc_lower:
                score += 8
            if "vnc" in svc_lower:
                score += 6

        # Teknoloji bazlı risk
        for tech in host.technologies:
            tech_lower = tech.lower()
            for key, weight in TECH_RISK_WEIGHTS.items():
                if key in tech_lower:
                    score += weight
                    break

        # WAF penalty (zafiyeti daha zor exploit etmek)
        if host.is_waf:
            score *= 0.7

        # CDN — daha az doğrudan erişim
        if host.is_cdn:
            score *= 0.8

        # Port sayısı bonusu
        score += min(len(host.ports) * 0.5, 10)

        return min(score, 100.0)

    def _score_endpoint(self, ep: Endpoint) -> float:
        """Endpoint risk skoru hesapla (0-100)."""
        score = 0.0

        # Parametre bazlı risk
        for param in ep.parameters:
            param_lower = param.lower()
            if param_lower in PARAM_RISK_MAP:
                vuln_type, weight = PARAM_RISK_MAP[param_lower]
                score += weight

        # Parametre sayısı (daha fazla = daha fazla saldırı yüzeyi)
        score += min(len(ep.parameters) * 1.5, 15)

        # Path bazlı risk
        path_lower = ep.path.lower()
        risky_paths = {
            "/admin": 8, "/api": 5, "/graphql": 7, "/upload": 7,
            "/login": 4, "/register": 4, "/debug": 9, "/test": 5,
            "/backup": 8, "/config": 9, "/env": 9, "/.git": 10,
            "/.env": 10, "/swagger": 6, "/phpinfo": 8,
            "/wp-admin": 7, "/wp-login": 6, "/console": 9,
            "/actuator": 8, "/metrics": 5, "/health": 3,
        }
        for rpath, weight in risky_paths.items():
            if rpath in path_lower:
                score += weight
                break

        # POST/PUT/DELETE daha riskli
        if ep.method in ("POST", "PUT", "DELETE", "PATCH"):
            score += 3

        # Auth gerektirmiyorsa daha yüksek risk
        if not ep.auth_required:
            score += 5

        return min(score, 100.0)

    # ── Attack vector generation ────────────────────────────

    def _generate_vectors(self) -> list[AttackVector]:
        """Tüm verilerden saldırı vektörleri oluştur."""
        vectors: list[AttackVector] = []

        # 1. Parametre bazlı injection vektörleri
        for ep in self._endpoints:
            for param in ep.parameters:
                param_lower = param.lower()
                if param_lower in PARAM_RISK_MAP:
                    vuln_type, risk = PARAM_RISK_MAP[param_lower]
                    vector = self._make_injection_vector(ep, param, vuln_type, risk)
                    if vector:
                        vectors.append(vector)

        # 2. Port/servis bazlı ağ vektörleri
        for key, host in self._hosts.items():
            for port in host.ports:
                net_vectors = self._make_network_vectors(host, port)
                vectors.extend(net_vectors)

        # 3. Teknoloji bazlı spesifik vektörler
        for key, host in self._hosts.items():
            tech_vectors = self._make_tech_vectors(host)
            vectors.extend(tech_vectors)

        # 4. Genel web vektörleri (her web endpoint'e)
        for ep in self._endpoints:
            if ep.protocol in ("http", "https") and ep.parameters:
                gen_vectors = self._make_generic_web_vectors(ep, vectors)
                vectors.extend(gen_vectors)

        # Öncelik sırala
        vectors.sort(key=lambda v: v.priority)

        return vectors

    def _make_injection_vector(
        self, ep: Endpoint, param: str, vuln_type: str, risk: float
    ) -> AttackVector | None:
        """Parametre bazlı injection vektörü oluştur."""

        tool_map = {
            "sqli": ["sqlmap", "nuclei"],
            "xss": ["dalfox", "xsstrike", "nuclei"],
            "xss_stored": ["dalfox", "manual"],
            "lfi": ["nuclei", "ffuf"],
            "ssrf": ["ssrfmap", "nuclei"],
            "cmdi": ["commix", "nuclei"],
            "ssti": ["tplmap", "nuclei"],
            "idor": ["custom_idor", "manual"],
            "open_redirect": ["nuclei", "manual"],
            "auth_bypass": ["custom_auth", "manual"],
            "privilege_escalation": ["custom_auth", "manual"],
            "info_disclosure": ["nuclei"],
        }

        severity_map = {
            "sqli": "high", "xss": "medium", "xss_stored": "high",
            "lfi": "high", "ssrf": "high", "cmdi": "critical",
            "ssti": "critical", "idor": "medium", "open_redirect": "low",
            "auth_bypass": "critical", "privilege_escalation": "critical",
            "info_disclosure": "low",
        }

        priority = max(1, int(10 - risk))

        return AttackVector(
            name=f"{vuln_type.upper()} via '{param}' on {ep.path}",
            category="web_injection",
            target_endpoint=ep.url or f"{ep.protocol}://{ep.host}:{ep.port}{ep.path}",
            target_host=ep.host,
            target_port=ep.port,
            target_parameter=param,
            technique=vuln_type,
            priority=priority,
            estimated_severity=severity_map.get(vuln_type, "medium"),
            rationale=f"Parameter '{param}' is a known {vuln_type} indicator",
            tools_to_use=tool_map.get(vuln_type, ["nuclei"]),
        )

    def _make_network_vectors(self, host: HostProfile, port: int) -> list[AttackVector]:
        """Port/servis bazlı ağ saldırı vektörleri."""
        vectors: list[AttackVector] = []
        service = host.services.get(port, "")
        hostname = host.hostname or host.ip

        if port == 21 or "ftp" in service.lower():
            vectors.append(AttackVector(
                name=f"FTP Anonymous/Brute-force on {hostname}:{port}",
                category="network",
                target_host=hostname,
                target_port=port,
                technique="ftp_attack",
                priority=3,
                estimated_severity="high",
                rationale="FTP service exposed — check anonymous login and weak credentials",
                tools_to_use=["nmap", "hydra"],
            ))

        if port == 445 or port == 139 or "smb" in service.lower():
            vectors.append(AttackVector(
                name=f"SMB Enumeration on {hostname}:{port}",
                category="network",
                target_host=hostname,
                target_port=port,
                technique="smb_enum",
                priority=2,
                estimated_severity="high",
                rationale="SMB exposed — null session, shares, EternalBlue check",
                tools_to_use=["enum4linux", "smbclient", "nmap"],
            ))

        if port == 6379 or "redis" in service.lower():
            vectors.append(AttackVector(
                name=f"Redis Unauthenticated Access on {hostname}:{port}",
                category="network",
                target_host=hostname,
                target_port=port,
                technique="redis_unauth",
                priority=1,
                estimated_severity="critical",
                rationale="Redis without auth → RCE via module load / crontab write",
                tools_to_use=["nmap", "manual"],
            ))

        if port in (3306, 5432, 1433, 1521, 27017) or "sql" in service.lower():
            vectors.append(AttackVector(
                name=f"Database Service Exposed on {hostname}:{port}",
                category="network",
                target_host=hostname,
                target_port=port,
                technique="db_attack",
                priority=2,
                estimated_severity="critical",
                rationale="Database port directly accessible — brute-force / default credentials",
                tools_to_use=["nmap", "hydra"],
            ))

        if port == 161 or "snmp" in service.lower():
            vectors.append(AttackVector(
                name=f"SNMP Enumeration on {hostname}:{port}",
                category="network",
                target_host=hostname,
                target_port=port,
                technique="snmp_enum",
                priority=4,
                estimated_severity="medium",
                rationale="SNMP service — check default community strings",
                tools_to_use=["snmpwalk", "nmap"],
            ))

        if port == 389 or "ldap" in service.lower():
            vectors.append(AttackVector(
                name=f"LDAP Enumeration on {hostname}:{port}",
                category="network",
                target_host=hostname,
                target_port=port,
                technique="ldap_enum",
                priority=3,
                estimated_severity="high",
                rationale="LDAP exposed — anonymous bind, user enumeration",
                tools_to_use=["ldapsearch", "nmap"],
            ))

        return vectors

    def _make_tech_vectors(self, host: HostProfile) -> list[AttackVector]:
        """Teknoloji bazlı saldırı vektörleri."""
        vectors: list[AttackVector] = []
        hostname = host.hostname or host.ip
        tech_str = " ".join(t.lower() for t in host.technologies)

        if "wordpress" in tech_str:
            vectors.append(AttackVector(
                name=f"WordPress Vulnerability Scan on {hostname}",
                category="web_injection",
                target_host=hostname,
                technique="wordpress_scan",
                priority=2,
                estimated_severity="high",
                rationale="WordPress detected — plugin/theme vulnerabilities, xmlrpc abuse",
                tools_to_use=["wpscan", "nuclei"],
            ))

        if "graphql" in tech_str:
            vectors.append(AttackVector(
                name=f"GraphQL Introspection/Abuse on {hostname}",
                category="web_injection",
                target_host=hostname,
                technique="graphql_attack",
                priority=3,
                estimated_severity="medium",
                rationale="GraphQL detected — introspection, batching, DoS, authorization bypass",
                tools_to_use=["nuclei", "manual"],
            ))

        if "jenkins" in tech_str:
            vectors.append(AttackVector(
                name=f"Jenkins Exploitation on {hostname}",
                category="web_injection",
                target_host=hostname,
                technique="jenkins_attack",
                priority=1,
                estimated_severity="critical",
                rationale="Jenkins exposed — Groovy script console, CVEs",
                tools_to_use=["nuclei", "searchsploit"],
            ))

        if any(t in tech_str for t in ["tomcat", "weblogic", "websphere"]):
            vectors.append(AttackVector(
                name=f"Java Application Server Exploitation on {hostname}",
                category="web_injection",
                target_host=hostname,
                technique="java_appserver",
                priority=2,
                estimated_severity="critical",
                rationale="Java app server — deserialization, default credentials, CVEs",
                tools_to_use=["nuclei", "searchsploit", "nmap"],
            ))

        if "phpmyadmin" in tech_str:
            vectors.append(AttackVector(
                name=f"phpMyAdmin Exploitation on {hostname}",
                category="web_injection",
                target_host=hostname,
                technique="phpmyadmin_attack",
                priority=1,
                estimated_severity="critical",
                rationale="phpMyAdmin exposed — default credentials, SQL execution, CVEs",
                tools_to_use=["nuclei", "hydra"],
            ))

        return vectors

    def _make_generic_web_vectors(self, ep: Endpoint, existing_vectors: list["AttackVector"] | None = None) -> list[AttackVector]:
        """Parametreli her web endpoint için genel test vektörleri."""
        vectors: list[AttackVector] = []
        url = ep.url or f"{ep.protocol}://{ep.host}:{ep.port}{ep.path}"
        _all_vectors = existing_vectors or self._vectors

        # Tüm parametreleri test et — XSS
        if ep.parameters and not any(
            v.target_endpoint == url and v.technique in ("xss", "xss_stored")
            for v in _all_vectors
        ):
            vectors.append(AttackVector(
                name=f"Generic XSS Test on {ep.path}",
                category="web_injection",
                target_endpoint=url,
                target_host=ep.host,
                target_port=ep.port,
                technique="generic_xss",
                priority=5,
                estimated_severity="medium",
                rationale=f"Endpoint has {len(ep.parameters)} parameters to test for XSS",
                tools_to_use=["dalfox", "nuclei"],
            ))

        # SQL injection — select/search/sort parametreleri
        sqli_params = [p for p in ep.parameters
                       if any(k in p.lower() for k in ["id", "sort", "order", "cat", "page", "num"])]
        if sqli_params:
            vectors.append(AttackVector(
                name=f"SQLi Test on {ep.path} (params: {','.join(sqli_params[:3])})",
                category="web_injection",
                target_endpoint=url,
                target_host=ep.host,
                target_port=ep.port,
                technique="generic_sqli",
                priority=3,
                estimated_severity="high",
                rationale=f"High-value parameters detected: {', '.join(sqli_params[:5])}",
                tools_to_use=["sqlmap", "nuclei"],
            ))

        return vectors

    # ── Report building ─────────────────────────────────────

    def build_report(self, target: str) -> AttackSurfaceReport:
        """
        Tam saldırı yüzeyi raporu oluştur.

        Tüm host ve endpoint'lerin risk skorlarını hesaplar,
        saldırı vektörlerini oluşturur ve önceliklendirir.
        """
        # Host'ları skorla
        for key, host in self._hosts.items():
            host.risk_score = self._score_host(host)
            # Host endpoint'lerini ata
            host.endpoints = [
                ep for ep in self._endpoints
                if ep.host == host.hostname or ep.host == host.ip
            ]

        # Endpoint'leri skorla
        for ep in self._endpoints:
            ep.risk_score = self._score_endpoint(ep)

        # Saldırı vektörleri
        self._vectors = self._generate_vectors()

        # Toplam parametre sayısı
        total_params = sum(len(ep.parameters) for ep in self._endpoints)

        # Genel risk skoru (ağırlıklı ortalama)
        host_scores = [h.risk_score for h in self._hosts.values()]
        ep_scores = [ep.risk_score for ep in self._endpoints]
        all_scores = host_scores + ep_scores
        overall = sum(all_scores) / len(all_scores) if all_scores else 0

        report = AttackSurfaceReport(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_hosts=len(self._hosts),
            total_endpoints=len(self._endpoints),
            total_parameters=total_params,
            total_attack_vectors=len(self._vectors),
            hosts=list(self._hosts.values()),
            attack_vectors=self._vectors,
            overall_risk=round(overall, 1),
            summary=self._generate_summary(overall),
        )

        logger.info(
            f"Attack surface report built | target={target} | "
            f"hosts={report.total_hosts} | endpoints={report.total_endpoints} | "
            f"vectors={report.total_attack_vectors} | risk={report.overall_risk}"
        )

        return report

    def _generate_summary(self, risk: float) -> str:
        """Metin özet oluştur."""
        host_count = len(self._hosts)
        ep_count = len(self._endpoints)
        vec_count = len(self._vectors)

        critical_vectors = [v for v in self._vectors if v.estimated_severity == "critical"]
        high_vectors = [v for v in self._vectors if v.estimated_severity == "high"]

        lines = [
            f"Attack surface analysis identified {host_count} hosts, "
            f"{ep_count} endpoints, and {vec_count} attack vectors.",
        ]

        if risk >= 70:
            lines.append("Overall risk is HIGH — multiple critical attack paths exist.")
        elif risk >= 40:
            lines.append("Overall risk is MODERATE — several significant vectors identified.")
        else:
            lines.append("Overall risk is LOW — limited attack surface detected.")

        if critical_vectors:
            lines.append(
                f"Critical vectors ({len(critical_vectors)}): "
                + ", ".join(v.name for v in critical_vectors[:5])
            )

        if high_vectors:
            lines.append(
                f"High vectors ({len(high_vectors)}): "
                + ", ".join(v.name for v in high_vectors[:5])
            )

        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Saldırı yüzeyi haritasını markdown string olarak döndür."""
        if not self._hosts and not self._endpoints:
            return "# Attack Surface\n\nNo data collected yet.\n"

        lines = ["# Attack Surface Map\n"]

        # Host tablosu
        lines.append("## Hosts\n")
        lines.append("| Host | Ports | Technologies | Risk |")
        lines.append("|------|-------|-------------|------|")
        for key, host in sorted(self._hosts.items(), key=lambda x: -x[1].risk_score):
            ports_str = ", ".join(str(p) for p in sorted(host.ports)[:10])
            tech_str = ", ".join(host.technologies[:5]) or "-"
            risk_label = self._risk_label(host.risk_score)
            lines.append(f"| {key} | {ports_str} | {tech_str} | {risk_label} |")

        # Top attack vectors
        lines.append("\n## Priority Attack Vectors\n")
        lines.append("| # | Vector | Category | Severity | Tools |")
        lines.append("|---|--------|----------|----------|-------|")
        for i, vec in enumerate(self._vectors[:20], 1):
            tools = ", ".join(vec.tools_to_use[:3])
            lines.append(
                f"| {i} | {vec.name} | {vec.category} | "
                f"{vec.estimated_severity.upper()} | {tools} |"
            )

        # High risk endpoints
        risky_eps = sorted(self._endpoints, key=lambda e: -e.risk_score)[:15]
        if risky_eps:
            lines.append("\n## High-Risk Endpoints\n")
            lines.append("| Endpoint | Method | Params | Risk |")
            lines.append("|----------|--------|--------|------|")
            for ep in risky_eps:
                params = ", ".join(ep.parameters[:5]) or "-"
                url = ep.url or f"{ep.host}:{ep.port}{ep.path}"
                risk_label = self._risk_label(ep.risk_score)
                lines.append(f"| {url} | {ep.method} | {params} | {risk_label} |")

        return "\n".join(lines)

    @staticmethod
    def _risk_label(score: float) -> str:
        if score >= 70:
            return f"🔴 {score:.0f}"
        elif score >= 40:
            return f"🟠 {score:.0f}"
        elif score >= 20:
            return f"🟡 {score:.0f}"
        else:
            return f"🟢 {score:.0f}"

    def reset(self) -> None:
        """Tüm veriler temizle."""
        self._hosts.clear()
        self._endpoints.clear()
        self._vectors.clear()


__all__ = [
    "AttackSurfaceMapper",
    "AttackSurfaceReport",
    "AttackVector",
    "Endpoint",
    "HostProfile",
]
