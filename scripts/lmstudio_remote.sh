#!/usr/bin/env bash
# ============================================================
# WhiteHatHacker AI — LM Studio Remote Manager
# ============================================================
# Mac'teki LM Studio'yu Kali'den SSH ile uzaktan yönetir.
# Kullanım:
#   ./scripts/lmstudio_remote.sh status    — Yüklü modelleri göster
#   ./scripts/lmstudio_remote.sh load      — Optimal ayarlarla modelleri yükle
#   ./scripts/lmstudio_remote.sh unload    — Tüm modelleri kaldır
#   ./scripts/lmstudio_remote.sh reload    — Kaldır + yükle
#   ./scripts/lmstudio_remote.sh test      — Modelleri test et
#   ./scripts/lmstudio_remote.sh info      — Disk modelleri + bellek bilgisi
# ============================================================

set -euo pipefail

# DÜZENLE: SSH bilgilerini .env dosyasında tanımlayın:
#   LMSTUDIO_SSH_USER=your_username
#   LMSTUDIO_SSH_HOST=your_lm_studio_ip
#   LMSTUDIO_SSH_KEY=~/.ssh/your_key
SSH_CMD="ssh -o ClearAllForwardings=yes ${LMSTUDIO_SSH_USER:?ERROR: Set LMSTUDIO_SSH_USER in .env}@${LMSTUDIO_SSH_HOST:?ERROR: Set LMSTUDIO_SSH_HOST in .env} -i ${LMSTUDIO_SSH_KEY:-~/.ssh/id_ed25519}"
LMS="$SSH_CMD \$HOME/.lmstudio/bin/lms"

# Model ayarları
# BaronLLM v2 — Offensive Security LLM (Qwen3-14B, Q8_0, 15.7GB)
# Dual-brain: aynı model, /think vs /no_think prefix ile farklılaştırılır
PRIMARY_MODEL="baronllm-v2-offensivesecurityllm"
PRIMARY_CTX=32768
PRIMARY_GPU="max"

# Secondary = AYNI MODEL (dual-brain mimarisi — tek model yüklenir)
SECONDARY_MODEL="baronllm-v2-offensivesecurityllm"
SECONDARY_CTX=32768
SECONDARY_GPU="max"
SECONDARY_PARALLEL=2

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║   WhiteHatHacker AI — LM Studio Remote Mgr  ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

cmd_status() {
    echo -e "${BLUE}[*] Mac'teki LM Studio durumu:${NC}"
    $LMS ps 2>&1
    echo ""
    $LMS server status 2>&1 || true
}

cmd_load() {
    echo -e "${YELLOW}[*] BaronLLM v2 yükleniyor (dual-brain — tek model)...${NC}"
    echo ""
    
    echo -e "${BLUE}[1/1] BaronLLM v2: ${PRIMARY_MODEL}${NC}"
    echo "       Context: ${PRIMARY_CTX}, GPU: ${PRIMARY_GPU}, Parallel: ${SECONDARY_PARALLEL}"
    echo "       (Tek model — /think ve /no_think prefix ile dual-brain)"
    $LMS load "${PRIMARY_MODEL}" -c "${PRIMARY_CTX}" --gpu "${PRIMARY_GPU}" --parallel "${SECONDARY_PARALLEL}" -y 2>&1 || true
    echo ""
    
    echo -e "${GREEN}[✓] Yükleme tamamlandı. Durum:${NC}"
    $LMS ps 2>&1
}

cmd_unload() {
    echo -e "${YELLOW}[*] Model kaldırılıyor...${NC}"
    $LMS unload "${PRIMARY_MODEL}" 2>&1 || true
    echo -e "${GREEN}[✓] Model kaldırıldı.${NC}"
    $LMS ps 2>&1
}

cmd_reload() {
    cmd_unload
    echo ""
    cmd_load
}

cmd_test() {
    echo -e "${BLUE}[*] BaronLLM v2 test ediliyor (dual-brain)...${NC}"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cd "$SCRIPT_DIR"
    
    source .venv/bin/activate 2>/dev/null || true
    
    python3 -c "
import httpx, os, time
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path('.env'), override=True)

url = os.environ.get('WHAI_PRIMARY_API_URL', '').rstrip('/')
key = os.environ.get('WHAI_PRIMARY_API_KEY', '')
headers = {'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'}

# Dual-brain test: aynı model, farklı prefix
tests = [
    ('PRIMARY  (/think)', '${PRIMARY_MODEL}', '/think\nAnalyze this HTTP response for SQL injection indicators: HTTP/1.1 500 Internal Server Error\nYou have an error in your SQL syntax near ORDER BY 1--'),
    ('SECONDARY (/no_think)', '${SECONDARY_MODEL}', '/no_think\nName 3 subdomain enumeration tools. One line each.'),
]

for label, mid, prompt in tests:
    t0 = time.time()
    try:
        r = httpx.post(f'{url}/v1/chat/completions', headers=headers, json={
            'model': mid,
            'messages': [{'role': 'user', 'content': prompt}],
            'max_tokens': 200, 'temperature': 0.1,
        }, timeout=120)
        dt = time.time() - t0
        data = r.json()
        usage = data.get('usage', {})
        tok = usage.get('completion_tokens', 0)
        speed = tok / dt if dt > 0 else 0
        resp = data['choices'][0]['message']['content'][:200]
        print(f'  {label}: OK  ({dt:.1f}s, {speed:.1f} tok/s)')
        print(f'    → {resp}')
    except Exception as e:
        print(f'  {label}: FAIL ({e})')
    print()
"
}

cmd_info() {
    echo -e "${BLUE}[*] LM Studio model envanteri:${NC}"
    $LMS ls 2>&1
}

# Ana giriş
print_header

case "${1:-help}" in
    status)  cmd_status ;;
    load)    cmd_load ;;
    unload)  cmd_unload ;;
    reload)  cmd_reload ;;
    test)    cmd_test ;;
    info)    cmd_info ;;
    *)
        echo "Kullanım: $0 {status|load|unload|reload|test|info}"
        echo ""
        echo "  status  — Yüklü modelleri göster"
        echo "  load    — Optimal ayarlarla modelleri yükle"
        echo "  unload  — Tüm modelleri kaldır"
        echo "  reload  — Kaldır + yeniden yükle"
        echo "  test    — Modelleri test et"
        echo "  info    — Disk modelleri listesi"
        ;;
esac
