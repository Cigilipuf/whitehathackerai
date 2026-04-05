<div align="center">

# 🛡️ WhiteHatHacker AI

### Autonomous Bug Bounty Hunter — Powered by Offensive Security LLMs

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-2690%20passed-brightgreen)]()
[![Tools](https://img.shields.io/badge/Security%20Tools-60%2B-blue)]()
[![OpenAI Compatible](https://img.shields.io/badge/LLM%20API-OpenAI%20Compatible-412991?logo=openai&logoColor=white)]()
[![Kali Linux](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)]()

**An AI-driven autonomous security assessment framework that thinks, decides, and hunts like a professional bug bounty researcher.**

[Getting Started](#-getting-started) · [Architecture](#-architecture) · [Features](#-key-features) · [Documentation](#-documentation)

</div>

---

## What Is This?

WhiteHatHacker AI is not a scanner — it's an **autonomous security research agent**. It uses a fine-tuned offensive security LLM (BaronLLM v2, 15B parameters) as its reasoning brain, orchestrates 60+ security tools through a ReAct decision loop, and produces evidence-backed vulnerability reports ready for responsible disclosure.

The bot operates through an **OBSERVE → THINK → ACT → EVALUATE → DECIDE** cycle: it observes tool outputs, reasons about attack surfaces, selects the next action, evaluates results, and decides whether to dig deeper, pivot strategy, or move on. Every finding passes through a 7-layer false positive elimination pipeline before reaching the report.

### What Makes It Different

| | Traditional Scanners | WhiteHatHacker AI |
|---|---|---|
| **Decision Making** | Fixed rules, sequential execution | LLM-driven ReAct loop with dynamic tool selection |
| **False Positives** | High FP rate, manual triage | 7-layer automated elimination (pattern → multi-tool → context → payload → Bayesian → replay → LLM reasoning) |
| **Adaptability** | Static scan profiles | Learns from each scan — records productive tools, FP patterns, and tech-vuln correlations |
| **Verification** | Flags potential issues | Generates PoC scripts, replays exploits, collects cryptographic evidence chains |
| **Coverage** | Single-tool perspective | Cross-correlates findings from 60+ tools, discovers attack chains via LLM reasoning |
| **Reporting** | Raw tool output | Platform-ready reports (HackerOne/Bugcrowd) with CVSS scoring, reproduction steps, and evidence packages |

---

## ⚡ Key Features

### Agentic ReAct Workflow
The core innovation: instead of running tools in a fixed order, the LLM brain decides **what to do next** based on accumulated observations. It can go back to earlier stages, deep-dive into specific endpoints, formulate and test hypotheses, and discover multi-step attack chains — all autonomously.

```
while budget_remaining and not brain_says_done:
    OBSERVE  → Read current state from Working Memory
    THINK    → Brain decides next action (which tool, which target, why)
    ACT      → Execute selected ToolUnit(s)
    EVALUATE → Brain assesses result quality and signal value
    DECIDE   → Continue / pivot / go deeper / change stage / stop
```

### Dual-Brain LLM Architecture

| Mode | Base | Role | When Used |
|------|------|------|-----------|
| **Think Mode** | BaronLLM v2 (Qwen3-14B, Q8_0) | Deep analysis, exploit strategy, FP elimination, report writing | Complex reasoning tasks |
| **NoThink Mode** | Same model, CoT disabled | Fast triage, tool selection, recon decisions | Speed-critical decisions |
| **Fallback** | DeepHat-V1-7B (Qwen2.5-Coder-7B, Q4_K_M) | Emergency backup | Both primary modes unavailable |

### OpenAI-Compatible LLM Backend

The brain engine connects to any **OpenAI-compatible API endpoint** — no vendor lock-in:

- **[LM Studio](https://lmstudio.ai/)** — Recommended for local inference. Load the GGUF model, enable the server, and point the bot at `http://127.0.0.1:1234/v1`
- **[llama.cpp server](https://github.com/ggerganov/llama.cpp)** — Run `llama-server` with your model and use the `/v1/chat/completions` endpoint
- **[Ollama](https://ollama.com/)** — Start any model with `ollama serve` and connect via the OpenAI-compatible API
- **[vLLM](https://github.com/vllm-project/vllm)** — Production-grade serving with OpenAI API compatibility
- **Any OpenAI API-compatible endpoint** — including cloud-hosted models or custom inference servers

```yaml
# config/settings.yaml
brain:
  primary:
    backend: remote                          # "local" (llama-cpp-python) or "remote" (OpenAI-compatible API)
    api_url: "http://127.0.0.1:1234/v1"     # Any OpenAI-compatible endpoint
    model_name: "baronllm-v2-offensivesecurity"
    context_length: 32768
  secondary:
    backend: remote
    api_url: "http://127.0.0.1:1234/v1"     # Same server, NoThink mode via /no_think prefix
```

The bot uses standard **`/v1/chat/completions`** with SSE streaming, so it works out-of-the-box with any server implementing the OpenAI Chat Completions API.

### HUNTER Mode — LLM-Driven Vulnerability Research

Beyond automated scanning, HUNTER Mode turns the LLM into an active researcher:

| Phase | What Happens |
|-------|-------------|
| **A — Template Generation** | Brain generates custom Nuclei YAML templates targeting specific endpoints based on detected technology stack |
| **B — Deep Probe** | Iterative hypothesis-driven testing: ANALYZE → HYPOTHESIZE → PROBE → OBSERVE → ADAPT → LOOP |
| **C — Proof of Exploit** | ExploitVerifier confirms findings via 4 strategies (PoC script, cURL, Metasploit, Nuclei) with cryptographic evidence chains |

### 7-Layer False Positive Elimination

The most critical subsystem — what separates real findings from noise:

| Layer | Method | Description |
|-------|--------|-------------|
| 0 | **Historical FP Feedback** | Learned per-tool FP rates from previous scans |
| 1 | **Pattern Matching** | 100+ known FP patterns, tool quirks, WAF/CDN/SPA artifacts |
| 2 | **Multi-Tool Verification** | Same vulnerability confirmed by ≥2 independent tools |
| 3 | **Context Analysis** | HTTP response diff, WAF detection, CDN compensation, tool quirk checks |
| 4 | **Payload Confirmation** | Blind re-test, time-based, out-of-band callbacks (Interactsh) |
| 5 | **Bayesian Scoring** | 0–100 confidence score with evidence chain + response diff analysis |
| 6 | **Full HTTP Replay** | Re-sends original request with method/body, diffs against control request |
| 7 | **Cross-Finding LLM Reasoning** | Brain analyzes all findings together to discover attack chains and eliminate correlated FPs |

### Complete Feature Set

| Category | Features |
|----------|----------|
| **Scanning** | 60+ tools: Nmap, SQLMap, Nuclei (200+ custom templates), Amass, FFuf, Dalfox, Metasploit, Commix, SSRFMap, TplMap, and more |
| **Pipelines** | Full scan, web app, API, network, quick recon, agentic (brain-driven) — all with session checkpoint/resume |
| **Custom Checks** | 28 specialized checkers: IDOR, auth bypass, race condition, business logic, JWT deep, GraphQL deep, HTTP/2 smuggling, CI/CD, prototype pollution, cache poisoning, WebSocket, and more |
| **Exploit Verification** | PoC script execution in sandbox, cURL replay, Metasploit auto-exploit, Nuclei re-verify — with HAR export and cryptographic evidence chains |
| **Reporting** | Markdown, HTML, JSON, PDF. Platform-ready templates for HackerOne and Bugcrowd. `whai submit` CLI with draft mode |
| **Operations** | Continuous monitoring (`whai monitor`), multi-target campaigns (`whai campaign`), incremental scanning (only new/changed assets), cross-scan dedup (GlobalFindingStore) |
| **Integrations** | Slack, Telegram, Discord notifications. SQLite asset database. Session persistence with crash recovery |
| **Safety** | Scope validation enforced at every tool call. Rate limiting always active. Payload safety filter blocks destructive commands. Human approval gates in semi-autonomous mode |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    WhiteHatHacker AI v3.5                      │
├────────────┬──────────────┬──────────────┬───────────────────┤
│    CLI     │     GUI      │   REST API   │   WebSocket API   │
├────────────┴──────────────┴──────────────┴───────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │         AGENTIC ORCHESTRATOR (ReAct Loop)                │  │
│  │  WorkingMemory · AgentContext · ToolUnitRegistry         │  │
│  │  OBSERVE → THINK → ACT → EVALUATE → DECIDE → (loop)    │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                          │                                     │
│  ┌──────────────────────▼──────────────────────────────────┐  │
│  │          DUAL BRAIN ENGINE (OpenAI-Compatible API)       │  │
│  │  BaronLLM v2 Think ←→ BaronLLM v2 NoThink              │  │
│  │  BrainRouter · Cache · CoT Logging · Auto-Recovery      │  │
│  │  Connects to: LM Studio / llama.cpp / Ollama / vLLM     │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                          │                                     │
│  ┌──────────────────────▼──────────────────────────────────┐  │
│  │       HUNTER MODE (Template Gen · Deep Probe · PoC)      │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │        SECURITY TOOL ORCHESTRATOR (60+ Tools)            │  │
│  │  Recon · Scanners · Exploit · Fuzzing · Network · Crypto │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │       FALSE POSITIVE ELIMINATION (7-Layer Pipeline)      │  │
│  │  Patterns · Multi-Tool · Context · Payload · Bayesian    │  │
│  │  Full Replay · Cross-Finding LLM · Evidence Quality Gate │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │         EXPLOIT VERIFICATION & EVIDENCE                  │  │
│  │  ExploitVerifier · EvidenceAggregator · HAR · PoC        │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │              REPORTING & INTEGRATION                     │  │
│  │  HackerOne · Bugcrowd · Slack · Telegram · HTML/PDF     │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚀 Getting Started

### Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Ubuntu 22.04+ | Kali Linux 2024+ |
| **Python** | 3.11 | 3.12+ |
| **RAM** | 16 GB | 32 GB+ (for 15B model) |
| **GPU** | — | NVIDIA 16GB+ VRAM or Apple Silicon |
| **Storage** | 100 GB SSD | 500 GB NVMe |

### Installation

```bash
# Clone
git clone https://github.com/Cigilipuf/whitehathackerai.git
cd whitehathackerai

# Python dependencies
pip install -r requirements.txt

# Security tools (Kali native + Go-based)
bash scripts/setup_kali_tools.sh
bash scripts/setup_go_tools.sh

# Download LLM model (~15.7 GB)
bash scripts/download_models.sh

# Wordlists
bash scripts/setup_wordlists.sh
```

### Configuration

```bash
cp .env.example .env
# Edit .env — add your API keys (Shodan, HackerOne, GitHub, etc.)

# Point brain engine at your OpenAI-compatible LLM server
# Edit config/settings.yaml → brain.primary.api_url
# Default: http://127.0.0.1:1234/v1 (LM Studio default)

# Verify setup
bash scripts/health_check.sh
```

### Usage

```bash
# Full autonomous scan
whai scan --target example.com --mode autonomous --profile balanced

# Semi-autonomous (human approval on critical steps)
whai scan --target example.com --mode semi-autonomous

# Quick recon only
whai scan --target example.com --pipeline quick_recon

# Agentic mode (brain-driven ReAct loop)
whai scan --target example.com --pipeline agentic

# Continuous monitoring (re-scan every 2 hours)
whai monitor example.com --interval 120

# Multi-target campaign
whai campaign targets.txt --profile aggressive

# Dry-run (preview what would run without executing)
whai scan --target example.com --dry-run

# System health check
whai diagnose
```

### Docker

```bash
# CPU
docker compose -f docker/docker-compose.yaml --profile cpu up -d

# GPU (requires nvidia-docker)
docker compose -f docker/docker-compose.yaml --profile gpu up -d
```

---

## 🔄 Scan Pipeline

The default 10-stage pipeline (or the agentic loop can dynamically reorder these):

```
 1. Scope Analysis        → Validate targets, define boundaries, parse scope YAML
 2. Passive Recon         → Subdomains, OSINT, DNS, Wayback/GAU, GitHub secrets, email security
 3. Active Recon          → Port scan, web crawl, tech detection, CDN/WAF fingerprint, favicon hash
 4. Enumeration           → Parameters, auth flows, APIs, JS analysis, VHost fuzzing, source maps
 5. Attack Surface Map    → Threat model, prioritize vectors, brain-generated attack narratives
 6. Vulnerability Scan    → SQLi, XSS, SSRF, SSTI, IDOR, BOLA, RCE, smuggling, JWT, GraphQL, 28 custom checkers
 7. FP Elimination        → 7-layer verification pipeline with confidence scoring
 8. Reporting             → CVSS scoring, PoC, reproduction steps, evidence packages, quality report
 9. Platform Submit       → HackerOne / Bugcrowd draft submission via whai submit
10. Knowledge Update      → Record productive tools, FP patterns, tech-vuln correlations for next scan
```

---

## 📁 Project Structure

```
src/
├── brain/              # Dual LLM engine, router, prompts, working memory, reasoning
│   ├── engine.py       # BrainEngine — local (llama-cpp-python) & remote (OpenAI-compatible API)
│   ├── router.py       # Task → model routing (Think/NoThink/Fallback)
│   ├── intelligence.py # IntelligenceEngine — high-level brain operations
│   ├── prompts/        # System prompts for each task type + agent prompts
│   ├── memory/         # Context manager, knowledge base, working memory
│   └── reasoning/      # Chain of thought, attack planner, risk assessor
├── workflow/           # Orchestrator, state machine, agent loop, pipelines
│   ├── agent_orchestrator.py  # ReAct loop implementation
│   ├── tool_unit.py           # ToolUnit abstraction for agentic execution
│   └── pipelines/             # full_scan, web_app, api_scan, network, agentic
├── tools/              # 60+ security tool wrappers
│   ├── recon/          # Subdomain, port scan, web discovery, DNS, OSINT, tech detect
│   ├── scanners/       # Nuclei, SQLMap, Dalfox, + 28 custom checkers
│   ├── exploit/        # Metasploit, SearchSploit, ExploitVerifier, PoC generator
│   ├── fuzzing/        # FFuf, Gobuster, Feroxbuster, dynamic wordlist
│   └── ...             # network, api_tools, crypto, proxy
├── fp_engine/          # 7-layer false positive elimination
├── analysis/           # Vulnerability analysis, attack surface, correlation, benchmarking
├── reporting/          # Report generator, templates, evidence aggregator, platform submit
├── integrations/       # Database, cache, notifications, asset DB
└── utils/              # Logger (multi-sink loguru), rate limiter, scope validator
```

---

## 🧪 Testing

```bash
# Full test suite (~2690 tests)
pytest

# With coverage
pytest --cov=src --cov-config=.coveragerc

# Specific module
pytest tests/test_fp_engine/ -v

# Benchmark against vulnerable labs (DVWA, Juice Shop, WebGoat, etc.)
whai benchmark --start-labs --scan --report
```

---

## ⚖️ Ethical Use

This tool is designed **exclusively** for authorized security testing:

- ✅ Use ONLY on targets with explicit written permission (bug bounty programs, your own systems)
- ✅ Follow all program rules and scope definitions
- ✅ Report findings responsibly through proper channels
- ❌ NEVER use against unauthorized targets
- ❌ NEVER exfiltrate, modify, or delete data
- ❌ NEVER perform DoS/DDoS attacks

**Scope validation and rate limiting are enforced at every tool call and cannot be disabled.**

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Architecture Guide](docs/ARCHITECTURE.md) | System design, data flow, module interactions |
| [Tool Catalog](docs/TOOL_CATALOG.md) | All 60+ integrated security tools with usage details |
| [Workflow Guide](docs/WORKFLOW_GUIDE.md) | Pipeline stages, scan profiles, configuration |
| [API Reference](docs/API_REFERENCE.md) | REST/WebSocket API endpoints |
| [Contributing](docs/CONTRIBUTING.md) | Development setup, coding standards, PR process |
