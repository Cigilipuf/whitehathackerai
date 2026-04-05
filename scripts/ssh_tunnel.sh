#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────
# SSH Tunnel Auto-Reconnect for LM Studio
# Maintains persistent SSH tunnel to Mac LM Studio server
# Usage: ./scripts/ssh_tunnel.sh [start|stop|status|check]
# ──────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration: override via env vars or .env file ──
# Source .env if it exists (project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    # shellcheck disable=SC1091
    set -a; source "$PROJECT_ROOT/.env" 2>/dev/null || true; set +a
fi

REMOTE_USER="${WHAI_SSH_REMOTE_USER:?ERROR: Set WHAI_SSH_REMOTE_USER in .env}"
REMOTE_HOST="${WHAI_SSH_REMOTE_HOST:?ERROR: Set WHAI_SSH_REMOTE_HOST in .env}"
REMOTE_PORT="${WHAI_SSH_REMOTE_PORT:-1239}"
LOCAL_PORT="${WHAI_SSH_LOCAL_PORT:-1239}"
SSH_KEY="${WHAI_SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
PIDFILE="/tmp/whai_ssh_tunnel.pid"
LOGFILE="output/logs/ssh_tunnel.log"

# Ensure log dir exists
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

validate_ssh_key() {
    if [[ ! -f "$SSH_KEY" ]]; then
        log "✗ SSH key not found: $SSH_KEY"
        echo "  Set WHAI_SSH_KEY_PATH or create the key with: ssh-keygen -t ed25519"
        return 1
    fi
    local perms
    perms=$(stat -c '%a' "$SSH_KEY" 2>/dev/null || stat -f '%A' "$SSH_KEY" 2>/dev/null)
    if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        log "⚠ SSH key permissions are ${perms} (should be 600 or 400) — fixing..."
        chmod 600 "$SSH_KEY"
    fi
    # Check if key is loaded in ssh-agent (skip if agent not running)
    if ssh-add -l &>/dev/null; then
        if ! ssh-add -l 2>/dev/null | grep -q "$(ssh-keygen -lf "$SSH_KEY" 2>/dev/null | awk '{print $2}')"; then
            log "Adding SSH key to agent..."
            ssh-add "$SSH_KEY" 2>/dev/null || log "⚠ Could not add key to agent (passphrase required?)"
        fi
    fi
    return 0
}

is_tunnel_alive() {
    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            # Also verify the port is actually forwarding
            if ss -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}" || \
               netstat -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}"; then
                return 0
            fi
        fi
    fi
    return 1
}

start_tunnel() {
    if is_tunnel_alive; then
        local pid
        pid=$(cat "$PIDFILE")
        log "Tunnel already running (PID $pid)"
        return 0
    fi

    # Validate SSH key before attempting connection
    validate_ssh_key || return 1

    # ── Dynamic IP resolution if configured host is unreachable ──
    local resolved_host="$REMOTE_HOST"
    if ! ssh -o ConnectTimeout=3 -o BatchMode=yes -i "$SSH_KEY" "${REMOTE_USER}@${resolved_host}" true 2>/dev/null; then
        log "Configured host ${resolved_host} unreachable — attempting discovery..."

        # 1. Try mDNS (.local hostname)
        if command -v avahi-resolve &>/dev/null && [[ "$resolved_host" != *.local ]]; then
            local mdns_host="${REMOTE_USER}.local"
            local mdns_ip
            mdns_ip=$(avahi-resolve -n "$mdns_host" 2>/dev/null | awk '{print $2}' || true)
            if [[ -n "$mdns_ip" ]] && ssh -o ConnectTimeout=3 -o BatchMode=yes -i "$SSH_KEY" "${REMOTE_USER}@${mdns_ip}" true 2>/dev/null; then
                log "mDNS resolved: ${mdns_host} → ${mdns_ip}"
                resolved_host="$mdns_ip"
            fi
        fi

        # 2. Try .local hostname directly (macOS Bonjour)
        if [[ "$resolved_host" == "$REMOTE_HOST" ]] && [[ "$REMOTE_HOST" != *.local ]]; then
            local bonjour="${REMOTE_HOST}.local"
            if ssh -o ConnectTimeout=3 -o BatchMode=yes -i "$SSH_KEY" "${REMOTE_USER}@${bonjour}" true 2>/dev/null; then
                log "Bonjour resolved: ${bonjour}"
                resolved_host="$bonjour"
            fi
        fi

        # 3. Try last-known-IP cache
        local cache_file="${PROJECT_ROOT}/output/.brain_last_known_ip"
        if [[ "$resolved_host" == "$REMOTE_HOST" ]] && [[ -f "$cache_file" ]]; then
            local cached_ip
            cached_ip=$(cat "$cache_file")
            if [[ -n "$cached_ip" ]] && ssh -o ConnectTimeout=3 -o BatchMode=yes -i "$SSH_KEY" "${REMOTE_USER}@${cached_ip}" true 2>/dev/null; then
                log "Cached IP works: ${cached_ip}"
                resolved_host="$cached_ip"
            fi
        fi

        if [[ "$resolved_host" == "$REMOTE_HOST" ]]; then
            log "✗ All discovery methods failed. Cannot reach brain host."
            return 1
        fi
    fi

    # Cache the working IP for future use
    local cache_dir="${PROJECT_ROOT}/output"
    mkdir -p "$cache_dir"
    echo "$resolved_host" > "${cache_dir}/.brain_last_known_ip"

    # Kill any stale tunnel on the same port
    pkill -f "ssh.*-L ${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" 2>/dev/null || true
    sleep 1

    log "Starting SSH tunnel → ${REMOTE_USER}@${resolved_host}:${REMOTE_PORT} on localhost:${LOCAL_PORT}"
    ssh -f -N \
        -L "${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" \
        -i "$SSH_KEY" \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=no \
        "${REMOTE_USER}@${resolved_host}"

    # Find the PID of the background SSH process
    sleep 1
    local pid
    pid=$(pgrep -f "ssh.*-L ${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" | head -1)
    
    if [[ -n "$pid" ]]; then
        echo "$pid" > "$PIDFILE"
        log "Tunnel started (PID $pid)"
        
        # Verify LM Studio is reachable
        if curl -s --max-time 5 "http://127.0.0.1:${LOCAL_PORT}/v1/models" > /dev/null 2>&1; then
            log "✓ LM Studio API reachable"
        else
            log "⚠ Tunnel up but LM Studio API not responding (may need a moment)"
        fi
    else
        log "✗ Failed to start tunnel"
        return 1
    fi
}

stop_tunnel() {
    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log "Tunnel stopped (PID $pid)"
        fi
        rm -f "$PIDFILE"
    fi
    # Also cleanup any orphaned tunnels
    pkill -f "ssh.*-L ${LOCAL_PORT}:127.0.0.1:${REMOTE_PORT}" 2>/dev/null || true
    log "All tunnels cleaned up"
}

status_tunnel() {
    if is_tunnel_alive; then
        local pid
        pid=$(cat "$PIDFILE")
        echo "✓ SSH tunnel ACTIVE (PID $pid)"
        echo "  Local:  127.0.0.1:${LOCAL_PORT}"
        echo "  Remote: ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PORT}"
        
        # Check LM Studio API
        if curl -s --max-time 5 "http://127.0.0.1:${LOCAL_PORT}/v1/models" > /dev/null 2>&1; then
            echo "  LM Studio: ✓ Reachable"
        else
            echo "  LM Studio: ✗ Not responding"
        fi
    else
        echo "✗ SSH tunnel NOT running"
        return 1
    fi
}

# Auto-reconnect loop (for use as daemon)
watch_loop() {
    log "Starting tunnel watchdog (check every 30s)"
    while true; do
        if ! is_tunnel_alive; then
            log "Tunnel down — reconnecting..."
            start_tunnel || log "Reconnect failed, will retry in 30s"
        fi
        sleep 30
    done
}

case "${1:-status}" in
    start)
        start_tunnel
        ;;
    stop)
        stop_tunnel
        ;;
    status)
        status_tunnel
        ;;
    check)
        # Single check + reconnect if needed (for cron/systemd)
        if ! is_tunnel_alive; then
            log "Tunnel check: DOWN — reconnecting"
            start_tunnel
        else
            log "Tunnel check: OK"
        fi
        ;;
    watch)
        # Persistent watchdog loop
        start_tunnel || true
        watch_loop
        ;;
    *)
        echo "Usage: $0 {start|stop|status|check|watch}"
        exit 1
        ;;
esac
