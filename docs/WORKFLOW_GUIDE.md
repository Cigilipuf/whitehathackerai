# Workflow Guide — WhiteHatHacker AI v2.0

## Scan Modes

### Autonomous Mode (`--mode autonomous`)
Bot runs the full pipeline without human intervention. Findings with confidence ≥90 are auto-submitted. Lower confidence findings are saved as drafts.

### Semi-Autonomous Mode (`--mode semi-autonomous`)
Bot pauses at critical decision points and requests human approval:
- Before starting active scanning
- Before running exploit/PoC attempts
- Before submitting reports
- When scope is ambiguous

Switch modes at runtime via the CLI: `switch-mode autonomous`

---

## 10-Stage Pipeline

### Stage 1: Scope Analysis
**Brain:** Secondary (BaronLLM v2 /no_think)  
**Tools:** whois, dig, scope_validator

The bot validates the target scope:
1. Parse target list (domains, IPs, URLs)
2. Query WHOIS and DNS to confirm ownership
3. Apply in-scope / out-of-scope filters
4. Generate scanning strategy

**Output:** Validated target list, scan plan

---

### Stage 2: Passive Recon
**Brain:** Secondary (BaronLLM v2 /no_think)  
**Tools:** subfinder, amass, crt.sh, theHarvester, shodan, waybackurls, gau

No direct contact with target. Gathers intelligence from public sources:
- Subdomain enumeration (5+ tools, results merged by aggregator)
- OSINT (emails, leaked credentials, technology hints)
- DNS record analysis
- Historical URL archives

**Output:** Subdomain list, OSINT data, historical URLs

---

### Stage 3: Active Recon
**Brain:** Secondary (BaronLLM v2 /no_think)  
**Tools:** httpx, nmap, masscan, katana, gospider, whatweb, wafw00f, ffuf

Direct probing of target:
- HTTP probing (live hosts, status codes, technologies)
- Port scanning (top 1000 → full for interesting hosts)
- Web crawling (endpoints, forms, JavaScript)
- Technology fingerprinting
- WAF detection

**Rate limiting enforced:** Default 3 req/s per host, 10 req/s global.

**Output:** Live host list, port/service map, technology stack, crawled endpoints

---

### Stage 4: Enumeration
**Brain:** Primary (BaronLLM v2 /think)  
**Tools:** arjun, paramspider, jwt_tool, swagger_parser, graphql_introspection

Deep enumeration:
- Hidden parameter discovery
- JavaScript analysis (endpoints, secrets, API keys)
- API specification parsing (OpenAPI, GraphQL)
- Authentication flow analysis
- Session and cookie analysis

**Output:** Complete endpoint-parameter matrix, auth mechanisms

---

### Stage 5: Attack Surface Mapping
**Brain:** Primary (BaronLLM v2 /think)

Pure AI analysis — no tool execution:
- Build attack surface from all recon data
- Apply STRIDE threat model to each endpoint
- Prioritize attack vectors by ROI (likelihood × impact)
- Generate ordered test plan

**Decision Point (semi-auto):** Human reviews attack plan before proceeding.

**Output:** Prioritized attack plan

---

### Stage 6: Vulnerability Scanning
**Brain:** Dual (task-dependent)  
**Tools:** All scanners — nuclei, sqlmap, dalfox, ssrfmap, commix, etc.

Systematic testing based on attack plan:

| Test Category | Primary Tools | Backup Tools |
|---------------|---------------|--------------|
| SQL Injection | sqlmap | nuclei-sqli templates |
| XSS | dalfox | xsstrike, nuclei-xss |
| SSRF | ssrfmap | nuclei-ssrf |
| SSTI | tplmap | nuclei-ssti |
| Command Injection | commix | nuclei-cmd |
| IDOR | custom checker | brain-powered analysis |
| JWT | jwt_tool | manual analysis |
| CORS | corsy | nuclei-cors |
| Open Redirect | openredirex | nuclei-redirect |

Custom logic tests (IDOR, race conditions, auth bypass) use the Primary Brain for reasoning.

**Output:** Raw vulnerability findings (unfiltered)

---

### Stage 7: False Positive Elimination ⚡
**Brain:** Primary (BaronLLM v2 /think)

**The most critical stage.** 5-layer verification:

#### Layer 1 — Known Pattern Matching
Compare against database of known FP patterns:
- Tool-specific quirks (sqlmap boolean-based blind FPs, nuclei info-only)
- WAF artifact detection (Cloudflare challenges, Akamai blocks)

#### Layer 2 — Multi-Tool Cross-Verification
Each finding must be confirmed by ≥2 different tools:
```
sqlmap → SQLi found → verify with nuclei-sqli → Brain confirms → ✓
dalfox → XSS found → verify with xsstrike → payload reflects → ✓
```

#### Layer 3 — Context Analysis
Analyze HTTP request/response:
- Is payload actually reflected or executed?
- Is the response a WAF block page?
- Does response diff confirm the vulnerability?

#### Layer 4 — Payload Confirmation
Re-test with varied payloads:
- Different encoding schemes
- Time-based verification (for blind injection)
- Out-of-band callbacks (for SSRF, XXE)

#### Layer 5 — Bayesian Confidence Scoring
Statistical analysis producing 0-100 confidence score:
- ≥90: Auto-report
- 70-89: Report with minimal review
- 50-69: Human approval required
- <50: Likely false positive (logged for learning)

**Output:** Verified findings with confidence scores and evidence chains

---

### Stage 8: Reporting
**Brain:** Primary (BaronLLM v2 /think)

Generate professional bug bounty reports:
- **Title:** Concise, descriptive vulnerability name
- **Severity:** CVSS v3.1 score with justification
- **Impact:** Business and technical impact analysis
- **Steps to Reproduce:** Detailed, numbered steps with exact URLs/params
- **PoC:** HTTP request/response, curl commands, screenshots
- **Remediation:** Actionable fix with code examples

Adapts format to target platform (HackerOne, Bugcrowd, generic).

**Output:** Platform-ready reports in Markdown/HTML/PDF

---

### Stage 9: Platform Submission
**Brain:** Not needed

Submit reports via platform APIs:
- **Autonomous mode:** Confidence ≥90 → auto-submit
- **Semi-autonomous mode:** Always requires human approval
- **Draft mode:** Save locally without submitting

---

### Stage 10: Knowledge Update
**Brain:** Secondary (BaronLLM v2 /no_think)

Learning from results:
- Store new FP patterns for future scans
- Record successful attack vectors
- Update technology-vulnerability correlations
- Log performance metrics for self-improvement

---

## Scan Profiles

| Profile | Speed | Depth | Rate Limit | Use Case |
|---------|-------|-------|------------|----------|
| `stealth` | Slow | Shallow | 1 req/s | Avoid detection |
| `balanced` | Medium | Medium | 3 req/s | Default, most programs |
| `aggressive` | Fast | Deep | 10 req/s | Time-limited engagements |
| `custom` | Configurable | Configurable | Configurable | Advanced users |

---

## CLI Quick Reference

```bash
# Full scan
python -m src.main scan --target example.com --profile balanced

# Quick recon only
python -m src.main recon --target example.com

# Scan with specific scope file
python -m src.main scan --target example.com --scope config/scopes/example_scope.yaml

# API server mode
python -m src.main serve --port 8000

# Resume interrupted scan
python -m src.main resume --session <session-id>

# View scan history
python -m src.main history
```
