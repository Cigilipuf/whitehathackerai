#!/usr/bin/env bash
# WhiteHatHacker AI — Go-based Security Tools Setup
# Installs Go runtime and Go-based security tools (subfinder, nuclei, etc.)
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

# --- Check / Install Go ---
GO_VERSION="1.24.13"

if command -v go &>/dev/null; then
    CURRENT=$(go version | awk '{print $3}' | sed 's/go//')
    info "Go already installed: v${CURRENT}"
else
    info "Installing Go ${GO_VERSION}..."
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Update PATH
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    
    # Persist in shell rc
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [[ -f "$rc" ]] && ! grep -q '/usr/local/go/bin' "$rc"; then
            echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> "$rc"
        fi
    done
    
    info "Go ${GO_VERSION} installed"
fi

export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

# --- Go-based tools ---
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/s0md3v/smap/cmd/smap@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
)

info "Installing Go-based security tools..."
for tool_path in "${GO_TOOLS[@]}"; do
    tool_name=$(basename "${tool_path%%@*}")
    if command -v "$tool_name" &>/dev/null; then
        info "  ✓ $tool_name (already installed)"
    else
        info "  → Installing $tool_name..."
        go install "$tool_path" 2>/dev/null && info "  ✓ $tool_name installed" || warn "  ✗ $tool_name failed"
    fi
done

# --- Update nuclei templates ---
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || warn "nuclei template update failed"
fi

# --- Verify ---
echo ""
info "=== Verification ==="
for tool_path in "${GO_TOOLS[@]}"; do
    tool_name=$(basename "${tool_path%%@*}")
    if command -v "$tool_name" &>/dev/null; then
        info "  ✓ $tool_name"
    else
        warn "  ✗ $tool_name not found (may need PATH update)"
    fi
done

info "Go tools setup complete. Restart shell if tools aren't found."
