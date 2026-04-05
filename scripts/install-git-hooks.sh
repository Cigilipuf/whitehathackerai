#!/usr/bin/env bash
# ============================================================
# WhiteHatHacker AI — Git Pre-Commit Hook Installer
# ============================================================
# Bu script, credential sızıntısını önleyen bir pre-commit
# hook kurar. Repo oluşturduktan sonra bir kez çalıştırın:
#   bash scripts/install-git-hooks.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HOOK_DIR="$PROJECT_ROOT/.git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

if [[ ! -d "$PROJECT_ROOT/.git" ]]; then
    echo "ERROR: .git directory not found. Run 'git init' first."
    exit 1
fi

mkdir -p "$HOOK_DIR"

cat > "$HOOK_FILE" << 'HOOK_SCRIPT'
#!/usr/bin/env bash
# ============================================================
# WhiteHatHacker AI — Pre-Commit Credential Leak Prevention
# ============================================================
# Bu hook, API anahtarları, tokenler ve hassas bilgilerin
# yanlışlıkla commit edilmesini önler.
# ============================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

BLOCKED=0

# ── 1. .env dosyasının commit edilmesini engelle ──
if git diff --cached --name-only | grep -qE '^\.(env|env\..*)$' | grep -v '.env.example'; then
    echo -e "${RED}BLOCKED: .env file detected in staged files!${NC}"
    echo "  Remove with: git reset HEAD .env"
    BLOCKED=1
fi

# ── 2. Staged dosyalarda secret pattern taraması ──
PATTERNS=(
    'sk-lm-'                   # LM Studio API key
    'sk-[a-zA-Z0-9]{20,}'     # OpenAI-style API key
    'github_pat_'              # GitHub PAT
    'ghp_[a-zA-Z0-9]{36}'     # GitHub PAT (classic)
    'gho_[a-zA-Z0-9]{36}'     # GitHub OAuth
    'AKIA[0-9A-Z]{16}'        # AWS Access Key ID
    'censys_[a-zA-Z0-9]+'     # Censys API secret
    'xoxb-'                    # Slack Bot Token
    'xoxp-'                    # Slack User Token
    'SG\.[a-zA-Z0-9_-]+'      # SendGrid API Key
    'PRIVATE KEY'              # Private key content
    'BEGIN RSA'                # RSA key content
    'BEGIN EC '                # EC key content
    'BEGIN DSA'                # DSA key content
    'BEGIN OPENSSH'            # OpenSSH key content
)

# Staged dosyaların diff'ini al
STAGED_DIFF=$(git diff --cached --diff-filter=ACM -U0 -- '*.py' '*.yaml' '*.yml' '*.json' '*.sh' '*.env*' '*.md' '*.txt' '*.toml' '*.cfg' '*.ini' '*.conf' 2>/dev/null || true)

if [[ -n "$STAGED_DIFF" ]]; then
    for pattern in "${PATTERNS[@]}"; do
        MATCHES=$(echo "$STAGED_DIFF" | grep -nE "^\+" | grep -E "$pattern" | grep -v "^+++\|#\|example\|placeholder\|your_\|REDACTED\|_RE\s*=\|_PATTERN" || true)
        if [[ -n "$MATCHES" ]]; then
            echo -e "${RED}BLOCKED: Potential secret detected matching pattern: ${pattern}${NC}"
            echo "$MATCHES" | head -5
            BLOCKED=1
        fi
    done
fi

# ── 3. Büyük dosya kontrolü (>10MB) ──
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
for f in $STAGED_FILES; do
    if [[ -f "$f" ]]; then
        SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
        if [[ "$SIZE" -gt 10485760 ]]; then
            echo -e "${YELLOW}WARNING: Large file ($(( SIZE / 1048576 ))MB): $f${NC}"
            echo "  Consider adding to .gitignore or using Git LFS"
            BLOCKED=1
        fi
    fi
done

# ── 4. Database dosyası kontrolü ──
if git diff --cached --name-only | grep -qE '\.(db|sqlite|sqlite3)$'; then
    echo -e "${RED}BLOCKED: Database file detected in staged files!${NC}"
    echo "  Database files should never be committed."
    BLOCKED=1
fi

if [[ "$BLOCKED" -eq 1 ]]; then
    echo ""
    echo -e "${RED}Commit BLOCKED due to security concerns.${NC}"
    echo "Review the issues above. To bypass (NOT recommended):"
    echo "  git commit --no-verify"
    exit 1
fi

exit 0
HOOK_SCRIPT

chmod +x "$HOOK_FILE"
echo "✅ Pre-commit hook installed at: $HOOK_FILE"
echo "The hook will scan for:"
echo "  - .env files"
echo "  - API keys & tokens (12+ patterns)"
echo "  - Large files (>10MB)"
echo "  - Database files"
