#!/usr/bin/env bash
# WhiteHatHacker AI — System Health Check
# Verifies all dependencies, models, tools and configuration
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0; WARN=0; FAIL=0

pass() { echo -e "  ${GREEN}✓${NC} $*"; ((PASS++)); }
warn() { echo -e "  ${YELLOW}!${NC} $*"; ((WARN++)); }
fail() { echo -e "  ${RED}✗${NC} $*"; ((FAIL++)); }

header() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     WhiteHatHacker AI — Health Check v2.0     ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"

# ──────────────── Python ────────────────
header "Python Environment"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    MAJOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if (( MAJOR >= 11 )); then
        pass "Python: $PY_VER"
    else
        warn "Python: $PY_VER (3.11+ recommended)"
    fi
else
    fail "Python 3 not found"
fi

# ──────────────── Python Packages ────────────────
header "Python Packages"
REQUIRED_PKGS=(pydantic loguru typer rich aiohttp fastapi uvicorn pyyaml jinja2 httpx)
OPTIONAL_PKGS=(llama_cpp celery redis shodan censys scapy)

for pkg in "${REQUIRED_PKGS[@]}"; do
    python3 -c "import $pkg" 2>/dev/null && pass "$pkg" || fail "$pkg (required)"
done
for pkg in "${OPTIONAL_PKGS[@]}"; do
    python3 -c "import $pkg" 2>/dev/null && pass "$pkg" || warn "$pkg (optional)"
done

# ──────────────── Models ────────────────
header "LLM Models"
MODEL_DIR="${PROJECT_DIR}/models"
PRIMARY_MODEL="${WHAI_PRIMARY_MODEL_PATH:-${MODEL_DIR}/baronllm-v2-offensivesecurity-q8_0.gguf}"
SECONDARY_MODEL="${WHAI_SECONDARY_MODEL_PATH:-${MODEL_DIR}/baronllm-v2-offensivesecurity-q8_0.gguf}"

if [[ -f "$PRIMARY_MODEL" ]]; then
    SZ=$(du -h "$PRIMARY_MODEL" | cut -f1)
    pass "Primary Brain (BaronLLM v2 /think): ${SZ}"
else
    warn "Primary Brain not found: $PRIMARY_MODEL"
fi

if [[ -f "$SECONDARY_MODEL" ]]; then
    SZ=$(du -h "$SECONDARY_MODEL" | cut -f1)
    pass "Secondary Brain (BaronLLM v2 /no_think): ${SZ}"
else
    warn "Secondary Brain not found: $SECONDARY_MODEL"
fi

# ──────────────── GPU ────────────────
header "GPU / CUDA"
if command -v nvidia-smi &>/dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
    GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader 2>/dev/null | head -1)
    pass "GPU: ${GPU_NAME} (${GPU_MEM})"
else
    warn "No NVIDIA GPU detected (CPU inference only)"
fi

# ──────────────── Security Tools — Critical ────────────────
header "Security Tools — Critical"
CRITICAL_TOOLS=(nmap masscan sqlmap nikto whatweb wafw00f gobuster ffuf dirb amass)
for tool in "${CRITICAL_TOOLS[@]}"; do
    command -v "$tool" &>/dev/null && pass "$tool" || fail "$tool"
done

# ──────────────── Security Tools — Important ────────────────
header "Security Tools — Important"
IMPORTANT_TOOLS=(msfconsole searchsploit hydra enum4linux smbclient snmpwalk \
    ldapsearch sslscan sslyze theHarvester dnsrecon dig fierce wfuzz httpx \
    mitmproxy tshark hashcat john ssh-audit socat proxychains4 curl whois)
for tool in "${IMPORTANT_TOOLS[@]}"; do
    command -v "$tool" &>/dev/null && pass "$tool" || warn "$tool"
done

# ──────────────── Go Tools (optional) ────────────────
header "Go-based Tools (optional)"
GO_TOOLS=(subfinder nuclei katana gospider dalfox dnsx naabu httpx interactsh-client)
for tool in "${GO_TOOLS[@]}"; do
    command -v "$tool" &>/dev/null && pass "$tool" || warn "$tool (install via setup_go_tools.sh)"
done

# ──────────────── Configuration ────────────────
header "Configuration Files"
CONFIG_FILES=(config/settings.yaml config/models.yaml config/tools.yaml \
    config/platforms.yaml config/scopes/example_scope.yaml)
for f in "${CONFIG_FILES[@]}"; do
    [[ -f "$PROJECT_DIR/$f" ]] && pass "$f" || fail "$f"
done

# ──────────────── Scan Profiles ────────────────
header "Scan Profiles"
for profile in stealth balanced aggressive custom; do
    [[ -f "$PROJECT_DIR/config/profiles/${profile}.yaml" ]] && pass "${profile}.yaml" || warn "${profile}.yaml"
done

# ──────────────── Data / Wordlists ────────────────
header "Wordlists & Data"
if [[ -d "$PROJECT_DIR/data/wordlists" ]]; then
    WL_COUNT=$(find "$PROJECT_DIR/data/wordlists" -name "*.txt" 2>/dev/null | wc -l)
    if (( WL_COUNT > 0 )); then
        pass "Wordlists: ${WL_COUNT} files"
    else
        warn "Wordlist directory exists but empty — run setup_wordlists.sh"
    fi
else
    warn "No wordlists directory — run setup_wordlists.sh"
fi

# ──────────────── Output Directories ────────────────
header "Output Directories"
for dir in output/reports output/screenshots output/evidence output/logs; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        pass "$dir/"
    else
        mkdir -p "$PROJECT_DIR/$dir"
        pass "$dir/ (created)"
    fi
done

# ──────────────── Source Code Validation ────────────────
header "Source Code"
PY_COUNT=$(find "$PROJECT_DIR/src" -name "*.py" 2>/dev/null | wc -l)
pass "Python modules: ${PY_COUNT}"

ERR_COUNT=0
while IFS= read -r f; do
    python3 -m py_compile "$f" 2>/dev/null || ((ERR_COUNT++))
done < <(find "$PROJECT_DIR/src" -name "*.py")

if (( ERR_COUNT == 0 )); then
    pass "Syntax check: all ${PY_COUNT} files OK"
else
    fail "Syntax errors in ${ERR_COUNT} files"
fi

# ──────────────── System Resources ────────────────
header "System Resources"
TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
AVAIL_RAM=$(free -g | awk '/^Mem:/{print $7}')
CPU_CORES=$(nproc)

if (( TOTAL_RAM >= 32 )); then pass "RAM: ${TOTAL_RAM}GB total, ${AVAIL_RAM}GB available"
else warn "RAM: ${TOTAL_RAM}GB (32GB+ recommended)"; fi

if (( CPU_CORES >= 8 )); then pass "CPU: ${CPU_CORES} cores"
else warn "CPU: ${CPU_CORES} cores (8+ recommended)"; fi

DISK_AVAIL=$(df -BG "$PROJECT_DIR" | awk 'NR==2{print $4}' | tr -d 'G')
if (( DISK_AVAIL >= 50 )); then pass "Disk: ${DISK_AVAIL}GB available"
else warn "Disk: ${DISK_AVAIL}GB available (50GB+ recommended)"; fi

# ──────────────── Summary ────────────────
echo ""
echo -e "${CYAN}━━━ Summary ━━━${NC}"
echo -e "  ${GREEN}Passed:${NC}  ${PASS}"
echo -e "  ${YELLOW}Warnings:${NC} ${WARN}"
echo -e "  ${RED}Failed:${NC}  ${FAIL}"

TOTAL=$((PASS + WARN + FAIL))
if (( FAIL == 0 )); then
    echo -e "\n${GREEN}System is ready! ✓${NC}"
    exit 0
elif (( FAIL <= 3 )); then
    echo -e "\n${YELLOW}System partially ready — fix ${FAIL} issue(s) above.${NC}"
    exit 1
else
    echo -e "\n${RED}System NOT ready — fix ${FAIL} critical issue(s).${NC}"
    exit 2
fi
