#!/usr/bin/env bash
# WhiteHatHacker AI — Model Download Script
# Downloads BaronLLM v2 (primary+secondary) and DeepHat-V1-7B (fallback)
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MODELS_DIR="${PROJECT_DIR}/models"

mkdir -p "$MODELS_DIR"

# --- Check for huggingface-hub CLI ---
if ! command -v huggingface-cli &>/dev/null; then
    info "Installing huggingface-hub..."
    pip3 install -q huggingface-hub[cli]
fi

# --- Primary+Secondary: BaronLLM v2 — Offensive Security (Qwen3-14B, Q8_0) ---
# Dual-brain: same model, /think vs /no_think prefix differentiates
PRIMARY_REPO="AlicanKiraz0/BaronLLM-v2-OffensiveSecurity-GGUF"
PRIMARY_FILE="baronllm-v2-offensivesecurity-q8_0.gguf"
PRIMARY_PATH="${MODELS_DIR}/${PRIMARY_FILE}"

echo ""
info "=== Primary+Secondary: BaronLLM v2 — Offensive Security ==="
info "Repository: ${PRIMARY_REPO}"
info "Quantization: Q8_0 (~15.7GB — best quality for 16GB+ RAM)"
info "Note: Same model serves both primary (/think) and secondary (/no_think)"
echo ""

if [[ -f "$PRIMARY_PATH" ]]; then
    info "BaronLLM v2 already exists: ${PRIMARY_PATH}"
    info "Size: $(du -h "$PRIMARY_PATH" | cut -f1)"
else
    warn "BaronLLM v2 not found. Download options:"
    echo ""
    echo "  Option 1 — huggingface-cli (recommended):"
    echo "    huggingface-cli download ${PRIMARY_REPO} ${PRIMARY_FILE} --local-dir ${MODELS_DIR}"
    echo ""
    echo "  Option 2 — wget:"
    echo "    wget -O ${PRIMARY_PATH} https://huggingface.co/${PRIMARY_REPO}/resolve/main/${PRIMARY_FILE}"
    echo ""
    echo "  Option 3 — LM Studio (for remote Mac setup):"
    echo "    Search 'AlicanKiraz0/BaronLLM-v2-OffensiveSecurity-GGUF' in LM Studio"
    echo "    Download Q8_0 quantization (~15.7GB)"
    echo ""
    
    read -rp "Download Q8_0 now? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        info "Downloading BaronLLM v2 (~15.7GB)... This may take a while."
        huggingface-cli download "$PRIMARY_REPO" "$PRIMARY_FILE" --local-dir "$MODELS_DIR" || \
            error "Download failed. Try manually with the commands above."
    else
        warn "Skipping BaronLLM v2 download."
    fi
fi

# --- Fallback: DeepHat-V1-7B (Qwen2.5-Coder-7B, Q4_K_M) ---
FALLBACK_REPO="Neanderthal/DeepHat-V1-7B-GGUF"
FALLBACK_FILE="deephat-v1-7b-q4_k_m.gguf"
FALLBACK_PATH="${MODELS_DIR}/${FALLBACK_FILE}"

echo ""
info "=== Fallback: DeepHat-V1-7B ==="
info "Repository: ${FALLBACK_REPO}"
info "Quantization: Q4_K_M (~4.68GB — emergency fallback only)"
echo ""

if [[ -f "$FALLBACK_PATH" ]]; then
    info "DeepHat fallback already exists: ${FALLBACK_PATH}"
    info "Size: $(du -h "$FALLBACK_PATH" | cut -f1)"
else
    warn "DeepHat fallback not found. Download options:"
    echo ""
    echo "  huggingface-cli download ${FALLBACK_REPO} ${FALLBACK_FILE} --local-dir ${MODELS_DIR}"
    echo ""
    
    read -rp "Download fallback now? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        info "Downloading DeepHat fallback (~4.68GB)..."
        huggingface-cli download "$FALLBACK_REPO" "$FALLBACK_FILE" --local-dir "$MODELS_DIR" || \
            error "Download failed."
    else
        warn "Skipping fallback model download."
    fi
fi

echo ""
info "=== Model Status ==="
for model in "$MODELS_DIR"/*.gguf; do
    if [[ -f "$model" ]]; then
        info "  ✓ $(basename "$model") — $(du -h "$model" | cut -f1)"
    fi
done

if ! ls "$MODELS_DIR"/*.gguf &>/dev/null; then
    warn "No models found in ${MODELS_DIR}/"
    warn "Download at least one model to use WhiteHatHacker AI."
fi

info "Model setup complete."
