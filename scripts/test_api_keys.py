#!/usr/bin/env python3
"""Test all API keys from .env for connectivity and validity."""

import os
import sys
from pathlib import Path

# Ensure project root
os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")

import httpx
from dotenv import load_dotenv

load_dotenv(Path(".env"), override=True)

results: dict[str, tuple[str, str]] = {}


def test_shodan():
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        return ("SKIP", "Key not set")
    r = httpx.get(f"https://api.shodan.io/api-info?key={key}", timeout=15)
    if r.status_code == 200:
        d = r.json()
        return ("OK", f"Plan: {d.get('plan')}, Query credits: {d.get('query_credits')}, Scan credits: {d.get('scan_credits')}")
    if r.status_code == 401:
        return ("FAIL", "401 Unauthorized - invalid key")
    return ("FAIL", f"HTTP {r.status_code}: {r.text[:100]}")


def test_censys():
    cid = os.environ.get("CENSYS_API_ID", "")
    csec = os.environ.get("CENSYS_API_SECRET", "")
    if not cid or not csec:
        return ("SKIP", "ID or Secret not set")
    r = httpx.get("https://search.censys.io/api/v1/account", auth=(cid, csec), timeout=15)
    if r.status_code == 200:
        d = r.json()
        q = d.get("quota", {})
        return ("OK", f"Email: {d.get('email')}, Used: {q.get('used')}/{q.get('allowance')}")
    if r.status_code == 401:
        return ("FAIL", "401 Unauthorized - invalid credentials")
    return ("FAIL", f"HTTP {r.status_code}: {r.text[:100]}")


def test_github():
    gh = os.environ.get("GITHUB_TOKEN", "")
    if not gh:
        return ("SKIP", "Token not set")
    hdrs = {"Authorization": f"token {gh}", "Accept": "application/vnd.github+json"}
    r = httpx.get("https://api.github.com/user", headers=hdrs, timeout=15)
    if r.status_code == 200:
        user = r.json().get("login", "?")
        rl = httpx.get("https://api.github.com/rate_limit", headers=hdrs, timeout=10).json()
        core = rl.get("resources", {}).get("core", {})
        return ("OK", f"User: {user}, Rate: {core.get('remaining')}/{core.get('limit')}")
    if r.status_code == 401:
        return ("FAIL", "401 - invalid or expired token")
    return ("FAIL", f"HTTP {r.status_code}: {r.text[:100]}")


def test_virustotal():
    vt = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not vt:
        return ("SKIP", "Key not set")
    r = httpx.get("https://www.virustotal.com/api/v3/users/me", headers={"x-apikey": vt}, timeout=15)
    if r.status_code == 200:
        d = r.json().get("data", {}).get("attributes", {})
        q = d.get("quotas", {}).get("api_requests_daily", {})
        return ("OK", f"User: {d.get('user_id')}, Daily: {q.get('used')}/{q.get('allowed')}")
    if r.status_code in (401, 403):
        return ("FAIL", f"{r.status_code} - invalid API key")
    return ("FAIL", f"HTTP {r.status_code}: {r.text[:100]}")


def test_securitytrails():
    st = os.environ.get("SECURITYTRAILS_API_KEY", "")
    if not st:
        return ("SKIP", "Key not set")
    r = httpx.get("https://api.securitytrails.com/v1/ping", headers={"APIKEY": st}, timeout=15)
    if r.status_code == 200:
        return ("OK", f"Ping OK: {r.json()}")
    if r.status_code in (401, 403):
        return ("FAIL", f"{r.status_code} - invalid or expired key")
    return ("FAIL", f"HTTP {r.status_code}: {r.text[:100]}")


def test_hackerone():
    user = os.environ.get("HACKERONE_API_USERNAME", "")
    token = os.environ.get("HACKERONE_API_TOKEN", "")
    if not user or not token:
        return ("SKIP", "Username or Token not set")
    # /v1/hackers/programs is the correct hacker API endpoint
    r = httpx.get(
        "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1",
        auth=(user, token),
        headers={"Accept": "application/json"},
        timeout=15,
    )
    if r.status_code == 200:
        data = r.json().get("data", [])
        total = r.json().get("meta", {}).get("total_count", len(data))
        return ("OK", f"User: {user}, Programs visible: {total}")
    if r.status_code == 401:
        return ("FAIL", "401 - invalid credentials")
    return ("FAIL", f"HTTP {r.status_code}: {r.text[:150]}")


def test_interactsh():
    server = os.environ.get("INTERACTSH_SERVER", "")
    if not server:
        return ("SKIP", "Server not set")
    url = server.rstrip("/")
    r = httpx.get(url, timeout=15, follow_redirects=True)
    if r.status_code in (200, 204, 301, 302, 403):
        return ("OK", f"Server reachable (HTTP {r.status_code})")
    return ("WARN", f"HTTP {r.status_code}")


def test_lm_studio():
    url = os.environ.get("WHAI_PRIMARY_API_URL", "")
    key = os.environ.get("WHAI_PRIMARY_API_KEY", "")
    if not url:
        return ("SKIP", "URL not set")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    try:
        r = httpx.get(f"{url.rstrip('/')}/v1/models", headers=headers, timeout=15)
    except httpx.ConnectError:
        return ("FAIL", f"Connection refused at {url} - is LM Studio running? SSH tunnel up?")
    if r.status_code == 200:
        models = r.json().get("data", [])
        ids = [m.get("id", "?") for m in models[:5]]
        return ("OK", f"{len(models)} model(s): {', '.join(ids)}")
    if r.status_code == 401:
        return ("FAIL", "401 - invalid API key")
    return ("FAIL", f"HTTP {r.status_code}: {r.text[:100]}")


def test_notifications():
    slack = os.environ.get("SLACK_WEBHOOK_URL", "")
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    discord = os.environ.get("DISCORD_WEBHOOK_URL", "")

    if not slack and not tg_token and not discord:
        return ("SKIP", "No channels configured (Slack/Telegram/Discord all empty)")

    notes = []
    if slack:
        notes.append("Slack: webhook configured")
    if tg_token and tg_chat:
        r = httpx.get(f"https://api.telegram.org/bot{tg_token}/getMe", timeout=10)
        if r.status_code == 200:
            bot = r.json().get("result", {})
            notes.append(f"Telegram: OK (bot @{bot.get('username')})")
        else:
            notes.append(f"Telegram: FAIL (HTTP {r.status_code})")
    elif tg_token:
        notes.append("Telegram: token set but Chat ID missing")
    if discord:
        notes.append("Discord: webhook configured")
    return ("OK" if notes else "SKIP", "; ".join(notes))


# ── Run all tests ──────────────────────────────────────

ALL_TESTS = [
    ("Shodan", test_shodan),
    ("Censys", test_censys),
    ("GitHub", test_github),
    ("VirusTotal", test_virustotal),
    ("SecurityTrails", test_securitytrails),
    ("HackerOne", test_hackerone),
    ("Interactsh", test_interactsh),
    ("LM Studio", test_lm_studio),
    ("Notifications", test_notifications),
]

if __name__ == "__main__":
    print("=" * 65)
    print("  WhiteHatHacker AI - API Key Connectivity Test")
    print("=" * 65)

    for i, (name, fn) in enumerate(ALL_TESTS, 1):
        print(f"\n[{i}/{len(ALL_TESTS)}] Testing {name}...")
        try:
            status, msg = fn()
        except Exception as e:
            status, msg = "FAIL", f"Exception: {e}"
        results[name] = (status, msg)
        icon = {"OK": "[OK]", "FAIL": "[FAIL]", "SKIP": "[SKIP]", "WARN": "[WARN]"}.get(status, "[??]")
        print(f"  {icon} {msg}")

    # Summary
    print("\n" + "=" * 65)
    print("  SUMMARY")
    print("=" * 65)
    ok = fail = skip = warn = 0
    for svc, (status, msg) in results.items():
        icon = {"OK": "[OK]  ", "FAIL": "[FAIL]", "SKIP": "[SKIP]", "WARN": "[WARN]"}.get(status, "[??]")
        print(f"  {icon}  {svc:20s}  {msg}")
        if status == "OK":
            ok += 1
        elif status == "FAIL":
            fail += 1
        elif status == "SKIP":
            skip += 1
        elif status == "WARN":
            warn += 1

    print(f"\n  Totals: {ok} OK | {fail} FAIL | {warn} WARN | {skip} SKIP")
    print("=" * 65)
    sys.exit(1 if fail > 0 else 0)
