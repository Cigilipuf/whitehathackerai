#!/usr/bin/env python3
"""Comprehensive HackerOne API test."""
import os, sys
from pathlib import Path

os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")

import httpx
from dotenv import load_dotenv

load_dotenv(Path(".env"), override=True)

user = os.environ.get("HACKERONE_API_USERNAME", "")
token = os.environ.get("HACKERONE_API_TOKEN", "")
auth = (user, token)
hdrs = {"Accept": "application/json"}
base = "https://api.hackerone.com/v1"

print(f"User: {user}")
print("=" * 60)

# 1. List programs
print("\n[1] GET /v1/hackers/programs?page[size]=5")
r1 = httpx.get(f"{base}/hackers/programs?page%5Bsize%5D=5", auth=auth, headers=hdrs, timeout=15)
print(f"    Status: {r1.status_code}")
if r1.status_code == 200:
    programs = r1.json().get("data", [])
    print(f"    Programs returned: {len(programs)}")
    for p in programs[:5]:
        a = p.get("attributes", {})
        print(f"      - {a.get('handle', '?')} ({a.get('name', '?')})")

# 2. Get a specific program
print("\n[2] GET /v1/hackers/programs/security")
r2 = httpx.get(f"{base}/hackers/programs/security", auth=auth, headers=hdrs, timeout=15)
print(f"    Status: {r2.status_code}")
if r2.status_code == 200:
    a = r2.json().get("data", {}).get("attributes", {})
    print(f"    Name: {a.get('name')}")
    print(f"    Offers bounties: {a.get('offers_bounties')}")
    print(f"    State: {a.get('state')}")

# 3. List structured scopes
print("\n[3] GET /v1/hackers/programs/security/structured_scopes")
r3 = httpx.get(f"{base}/hackers/programs/security/structured_scopes?page%5Bsize%5D=3", auth=auth, headers=hdrs, timeout=15)
print(f"    Status: {r3.status_code}")
if r3.status_code == 200:
    scopes = r3.json().get("data", [])
    print(f"    Scopes returned: {len(scopes)}")
    for s in scopes[:3]:
        a = s.get("attributes", {})
        print(f"      - {a.get('asset_identifier', '?')} [{a.get('asset_type', '?')}] eligible={a.get('eligible_for_bounty')}")

# 4. Report submission endpoint (dry = empty body)
print("\n[4] POST /v1/hackers/reports (empty body - expect 422/400)")
r4 = httpx.post(f"{base}/hackers/reports", auth=auth,
                headers={**hdrs, "Content-Type": "application/json"}, json={}, timeout=15)
print(f"    Status: {r4.status_code}")
print(f"    Body: {r4.text[:300]}")

# 5. Weakness list
print("\n[5] GET /v1/hackers/weaknesses?page[size]=3")
r5 = httpx.get(f"{base}/hackers/weaknesses?page%5Bsize%5D=3", auth=auth, headers=hdrs, timeout=15)
print(f"    Status: {r5.status_code}")
if r5.status_code == 200:
    ws = r5.json().get("data", [])
    for w in ws[:3]:
        a = w.get("attributes", {})
        print(f"      - {a.get('name', '?')} (CWE: {a.get('external_id', '?')})")

# Verdict
print("\n" + "=" * 60)
print("VERDICT:")
ok_count = sum(1 for s in [r1.status_code, r2.status_code, r3.status_code, r5.status_code] if s == 200)
report_ok = r4.status_code in (422, 400)
print(f"  Read endpoints: {ok_count}/4 OK")
print(f"  Report submit reachable: {report_ok} (HTTP {r4.status_code})")
if ok_count >= 3 and report_ok:
    print("  >> HackerOne API: FULLY OPERATIONAL")
elif ok_count >= 3:
    print("  >> HackerOne API: READ OK, SUBMIT needs investigation")
else:
    print("  >> HackerOne API: ISSUES DETECTED")
