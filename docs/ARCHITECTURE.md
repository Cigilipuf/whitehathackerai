# Architecture Guide — WhiteHatHacker AI v2.0

## Overview

WhiteHatHacker AI is a modular, async-first Python application that orchestrates two fine-tuned cybersecurity LLMs and 60+ security tools to perform autonomous bug bounty hunting.

---

## High-Level Architecture

```
                    ┌─────────────────────┐
                    │    User Interface    │
                    │  CLI / Web / API     │
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │     Orchestrator     │
                    │  State Machine       │
                    │  Decision Engine     │
                    │  Task Scheduler      │
                    │  Human Gateway       │
                    └─────────┬───────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────▼─────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │  Brain Engine  │ │ Tool Layer  │ │ FP Engine   │
    │  Dual-Model    │ │ 36 Wrappers │ │ 5-Layer     │
    │  Router        │ │ Executor    │ │ Verification│
    │  Memory/CoT    │ │ Parser      │ │ Bayesian    │
    └───────────────┘ └─────────────┘ └─────────────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                    ┌─────────▼───────────┐
                    │  Analysis + Report   │
                    │  CVSS · Impact       │
                    │  Templates · Submit  │
                    └─────────────────────┘
```

---

## Core Components

### 1. Brain Engine (`src/brain/`)

The dual-brain system is the intelligence core:

- **`engine.py`** — Loads GGUF models via `llama-cpp-python`, manages inference sessions, handles context windows.
- **`router.py`** — Routes tasks to the appropriate model based on complexity heuristics:
  - **Primary (BaronLLM v2 /think):** deep analysis, FP elimination, exploit strategy, report writing
  - **Secondary (BaronLLM v2 /no_think):** fast triage, recon decisions, tool selection
  - **Both:** critical decisions requiring consensus
- **`memory/`** — Session memory, context management, knowledge base, vulnerability pattern storage.
- **`reasoning/`** — Chain-of-thought reasoning, attack planning, risk assessment, self-reflection.
- **`prompts/`** — Structured system prompts for each task type (recon, analysis, exploit, report, triage, FP elimination).

### 2. Workflow Orchestrator (`src/workflow/`)

Controls the 10-stage scan pipeline:

- **`orchestrator.py`** — Main execution loop, stage transitions, error recovery.
- **`state_machine.py`** — Formal state transitions with guards and validation.
- **`decision_engine.py`** — AI-powered decision making using brain engine.
- **`task_scheduler.py`** — Parallel task execution with priority queues.
- **`human_gateway.py`** — Approval gates for semi-autonomous mode.
- **`pipelines/`** — Pre-defined workflows (full_scan, web_app, api_scan, network_scan, quick_recon).

### 3. Tool Layer (`src/tools/`)

Abstraction layer over 60+ security tools:

- **`base.py`** — Abstract `SecurityTool` class with common interface.
- **`registry.py`** — Auto-discovery and registration of tool wrappers.
- **`executor.py`** — Safe execution with timeout, rate limiting, scope validation.
- **`parser.py`** — Unified output parser (JSON, XML, greppable, CSV, plaintext).
- **Tool categories:**
  - `recon/` — subdomain, port_scan, web_discovery, dns, osint, tech_detect
  - `scanners/` — nuclei, sqlmap, nikto, wpscan, dalfox, custom_checks
  - `exploit/` — metasploit, searchsploit, payload_generator, poc_generator
  - `fuzzing/` — ffuf, gobuster, feroxbuster, wordlist_manager
  - `network/` — enum4linux, smbclient, snmpwalk, ldap, ssh_audit
  - `api_tools/` — swagger, graphql, jwt, oauth, api_fuzzer
  - `crypto/` — sslscan, sslyze, cipher_analyzer
  - `proxy/` — mitmproxy, zaproxy

### 4. FP Engine (`src/fp_engine/`)

5-layer false positive elimination:

1. **Pattern matching** (`patterns/`) — Known FP database, tool quirks, WAF artifacts
2. **Multi-tool verification** (`verification/multi_tool_verify.py`) — Cross-validate with different tools
3. **Context analysis** (`verification/context_verify.py`) — HTTP response analysis, WAF/CDN detection
4. **Payload confirmation** (`verification/payload_confirm.py`) — Re-test with variant payloads
5. **Bayesian scoring** (`scoring/`) — Statistical confidence scoring with evidence chains

Learning system (`learning/`) updates FP patterns from feedback.

### 5. Analysis (`src/analysis/`)

- **`vulnerability_analyzer.py`** — Central analysis coordinator
- **`attack_surface.py`** — Maps all endpoints to attack vectors
- **`threat_model.py`** — STRIDE-based threat modeling
- **`severity_calculator.py`** — CVSS v3.1 scoring
- **`impact_assessor.py`** — Business and technical impact evaluation
- **`correlation_engine.py`** — Links related findings into attack chains

### 6. Reporting (`src/reporting/`)

- **Templates:** HackerOne, Bugcrowd, generic, executive summary, technical detail
- **Formatters:** Markdown, HTML, PDF, JSON
- **Evidence:** Screenshots, HTTP request/response logging, PoC recording, timeline
- **Platform submit:** Direct API submission to bug bounty platforms

---

## Data Flow

```
Target → Scope Validator → Passive Recon (subdomain, OSINT, DNS)
  → Active Recon (port scan, web crawl, tech detect)
  → Enumeration (params, auth, API endpoints)
  → Attack Surface Mapping (brain-powered prioritization)
  → Vulnerability Scanning (tool orchestration)
  → FP Elimination (5-layer verification)
  → Reporting (CVSS, PoC, evidence)
  → Platform Submission
  → Knowledge Update (learn from results)
```

---

## Concurrency Model

- **asyncio** event loop for all I/O operations
- **Task scheduler** with configurable parallelism (default: 5 concurrent tools)
- **Per-host rate limiting** (default: 3 req/s) + global rate limiting (10 req/s)
- **Tool executor** enforces timeouts (configurable per tool type)

---

## Security Invariants

These are **always enforced** and cannot be disabled:

1. **Scope validation** — Every target URL/IP checked against scope before any request
2. **Rate limiting** — Global and per-host limits on all outbound requests
3. **Credential protection** — API keys and tokens never logged or included in reports
4. **Audit logging** — Every tool execution and decision logged with session ID

---

## Configuration Hierarchy

```
.env (secrets)
  → config/settings.yaml (global settings)
    → config/models.yaml (LLM parameters)
    → config/tools.yaml (tool config)
    → config/platforms.yaml (bug bounty platforms)
    → config/profiles/*.yaml (scan profiles)
    → config/scopes/*.yaml (target scopes)
```
