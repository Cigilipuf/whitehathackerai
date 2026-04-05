# ─────────────────────────────────────────────────────────
#  WhiteHatHacker AI — Base Dockerfile (CPU)
# ─────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling:latest AS base

LABEL maintainer="WhiteHatHacker AI Team"
LABEL description="Autonomous Bug Bounty Hunter Bot — CPU build"
LABEL version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WHAI_MODE=semi-autonomous \
    WHAI_SCAN_PROFILE=balanced \
    WHAI_LOG_LEVEL=INFO \
    WHAI_MAX_PARALLEL_TOOLS=5

# ── System dependencies ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    build-essential cmake git curl wget jq \
    # Core security tools
    nmap masscan nikto whatweb wafw00f \
    gobuster dirb wfuzz \
    sqlmap commix \
    amass dnsrecon fierce \
    theharvester whois dnsutils \
    enum4linux smbclient snmp ldap-utils \
    sslscan hydra john hashcat \
    netcat-openbsd socat proxychains4 \
    tshark mitmproxy \
    metasploit-framework exploitdb \
    # Utilities
    libxml2-dev libxslt1-dev libffi-dev libssl-dev \
    wkhtmltopdf cutycapt xvfb \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Go tools ──
ENV GOROOT=/usr/local/go \
    GOPATH=/root/go \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

RUN curl -sL https://go.dev/dl/go1.24.13.linux-amd64.tar.gz | tar -C /usr/local -xz && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/tomnomnom/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/epi052/feroxbuster@latest 2>/dev/null || true && \
    nuclei -update-templates 2>/dev/null || true && \
    rm -rf /root/go/pkg /tmp/*

# ── Python project ──
WORKDIR /app

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

# ── Output dirs ──
RUN mkdir -p output/reports output/screenshots output/evidence output/logs models

# ── Entrypoint ──
EXPOSE 8000
VOLUME ["/app/models", "/app/output", "/app/config"]

ENTRYPOINT ["python3", "-m", "src.main"]
CMD ["--help"]
