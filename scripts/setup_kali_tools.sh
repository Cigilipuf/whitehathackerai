#!/usr/bin/env bash
# WhiteHatHacker AI — Kali Linux Security Tools Setup
# Installs and verifies all required security tools on Kali Linux
set -euo pipefail

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    warn "Some tools require root. Running with sudo where needed."
fi

# --- APT-based tools ---
APT_TOOLS=(
    nmap masscan amass theharvester
    nikto wpscan sqlmap commix
    dirb gobuster ffuf feroxbuster wfuzz
    dnsrecon fierce
    whatweb wafw00f
    enum4linux smbclient snmpwalk ldap-utils
    hydra medusa hashcat john
    wireshark tshark
    mitmproxy
    netcat-openbsd socat proxychains4
    sslscan
    whois curl wget jq
    python3-pip python3-venv
    cutycapt wkhtmltopdf
    exploitdb
)

info "Updating package lists..."
sudo apt-get update -qq

info "Installing APT-based tools..."
for tool in "${APT_TOOLS[@]}"; do
    if dpkg -l "$tool" &>/dev/null; then
        info "  ✓ $tool (already installed)"
    else
        info "  → Installing $tool..."
        sudo apt-get install -y -qq "$tool" 2>/dev/null || warn "  ✗ Failed to install $tool"
    fi
done

# --- pip-based tools ---
PIP_TOOLS=(
    httpx
    shodan
    censys
    sslyze
    impacket
)

info "Installing pip-based tools..."
for tool in "${PIP_TOOLS[@]}"; do
    if pip3 show "$tool" &>/dev/null; then
        info "  ✓ $tool (already installed)"
    else
        info "  → Installing $tool..."
        pip3 install -q "$tool" 2>/dev/null || warn "  ✗ Failed to install $tool"
    fi
done

# --- Metasploit ---
if command -v msfconsole &>/dev/null; then
    info "✓ Metasploit Framework found"
else
    warn "Metasploit not found. Install via: sudo apt install metasploit-framework"
fi

# --- SSH Audit ---
if command -v ssh-audit &>/dev/null; then
    info "✓ ssh-audit found"
else
    info "→ Installing ssh-audit..."
    pip3 install -q ssh-audit 2>/dev/null || warn "✗ ssh-audit install failed"
fi

# --- netexec (nxc) ---
if command -v nxc &>/dev/null || command -v netexec &>/dev/null; then
    info "✓ netexec found"
else
    info "→ Installing netexec..."
    pip3 install -q netexec 2>/dev/null || warn "✗ netexec install failed"
fi

# --- Verify critical tools ---
echo ""
info "=== Tool Verification ==="
CRITICAL_TOOLS=(nmap masscan amass sqlmap nikto httpx ffuf gobuster)
MISSING=0
for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ver=$("$tool" --version 2>&1 | head -1 || echo "version unknown")
        info "  ✓ $tool: $ver"
    else
        error "  ✗ $tool NOT FOUND"
        ((MISSING++))
    fi
done

echo ""
if [[ $MISSING -eq 0 ]]; then
    info "All critical tools installed successfully!"
else
    warn "$MISSING critical tool(s) missing. Check errors above."
fi

info "Kali tools setup complete."
