# API Reference — WhiteHatHacker AI v2.0

## REST API (FastAPI)

Base URL: `http://localhost:8000/api/v1`

---

### Authentication

All API endpoints require a bearer token:

```
Authorization: Bearer <WHAI_API_TOKEN>
```

Set the token in `.env`:
```
WHAI_API_TOKEN=your-secret-token
```

---

### Scans

#### Start a Scan

```http
POST /api/v1/scans
Content-Type: application/json

{
  "target": "example.com",
  "mode": "semi-autonomous",
  "profile": "balanced",
  "scope": {
    "in_scope": ["*.example.com"],
    "out_of_scope": ["admin.example.com"]
  },
  "options": {
    "skip_passive_recon": false,
    "max_duration_minutes": 120,
    "notification_webhook": "https://hooks.slack.com/..."
  }
}
```

**Response:**
```json
{
  "session_id": "scan_20250228_abc123",
  "status": "running",
  "started_at": "2025-02-28T10:00:00Z",
  "target": "example.com",
  "profile": "balanced"
}
```

#### Get Scan Status

```http
GET /api/v1/scans/{session_id}
```

**Response:**
```json
{
  "session_id": "scan_20250228_abc123",
  "status": "scanning",
  "current_stage": "vulnerability_scan",
  "progress": 65,
  "findings_count": 3,
  "elapsed_seconds": 1847,
  "stages_completed": ["scope_analysis", "passive_recon", "active_recon", "enumeration", "attack_surface"]
}
```

#### List Scans

```http
GET /api/v1/scans?status=running&limit=10
```

#### Stop a Scan

```http
POST /api/v1/scans/{session_id}/stop
```

#### Resume a Scan

```http
POST /api/v1/scans/{session_id}/resume
```

---

### Findings

#### List Findings

```http
GET /api/v1/scans/{session_id}/findings?min_confidence=70&severity=high,critical
```

**Response:**
```json
{
  "findings": [
    {
      "id": "finding_001",
      "title": "SQL Injection in /api/users?id=",
      "severity": "critical",
      "cvss_score": 9.8,
      "confidence": 95,
      "vuln_type": "sqli",
      "url": "https://example.com/api/users?id=1",
      "parameter": "id",
      "evidence": {
        "payload": "1' OR '1'='1",
        "response_diff": true,
        "tools_confirmed": ["sqlmap", "nuclei"]
      },
      "status": "verified"
    }
  ],
  "total": 1
}
```

#### Get Finding Detail

```http
GET /api/v1/findings/{finding_id}
```

Returns full finding with HTTP request/response traces, evidence chain, reproduction steps.

#### Update Finding Status

```http
PATCH /api/v1/findings/{finding_id}
Content-Type: application/json

{
  "status": "confirmed",
  "notes": "Manually verified via browser"
}
```

---

### Reports

#### Generate Report

```http
POST /api/v1/scans/{session_id}/reports
Content-Type: application/json

{
  "format": "markdown",
  "template": "hackerone",
  "include_findings": ["finding_001", "finding_002"],
  "min_confidence": 70
}
```

**Response:**
```json
{
  "report_id": "report_001",
  "format": "markdown",
  "file_path": "output/reports/report_001.md",
  "generated_at": "2025-02-28T12:00:00Z"
}
```

#### Download Report

```http
GET /api/v1/reports/{report_id}/download
```

Returns the report file in the requested format.

---

### Brain Engine

#### Query Brain

```http
POST /api/v1/brain/query
Content-Type: application/json

{
  "prompt": "Analyze this HTTP response for potential XSS...",
  "model": "primary",
  "max_tokens": 1024,
  "temperature": 0.1
}
```

#### Get Brain Status

```http
GET /api/v1/brain/status
```

```json
{
  "primary": {"loaded": true, "model": "BaronLLM-v2-Think", "vram_usage_mb": 16384},
  "secondary": {"loaded": true, "model": "BaronLLM-v2-Fast", "vram_usage_mb": 0}
}
```

---

### Tools

#### List Available Tools

```http
GET /api/v1/tools
```

#### Get Tool Status

```http
GET /api/v1/tools/{tool_name}
```

#### Run Tool Manually

```http
POST /api/v1/tools/{tool_name}/run
Content-Type: application/json

{
  "target": "example.com",
  "options": {"ports": "80,443,8080"}
}
```

---

### System

#### Health Check

```http
GET /api/v1/health
```

```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "models_loaded": true,
  "tools_available": 42,
  "active_scans": 1
}
```

#### Configuration

```http
GET /api/v1/config
PUT /api/v1/config
```

---

### WebSocket API

#### Real-time Scan Updates

```
ws://localhost:8000/ws/scans/{session_id}
```

Messages:
```json
{"event": "stage_change", "stage": "vulnerability_scan", "progress": 65}
{"event": "finding", "severity": "critical", "title": "SQL Injection..."}
{"event": "tool_started", "tool": "sqlmap", "target": "example.com"}
{"event": "tool_completed", "tool": "sqlmap", "duration_s": 120, "findings": 2}
{"event": "approval_required", "action": "submit_report", "finding_id": "..."}
{"event": "scan_complete", "findings_total": 5, "verified": 3}
```

#### Send Human Approval

```json
{"action": "approve", "request_id": "approval_001"}
{"action": "reject", "request_id": "approval_001", "reason": "Out of scope"}
```

---

## Error Responses

All errors follow this format:
```json
{
  "error": {
    "code": "SCOPE_VIOLATION",
    "message": "Target is outside defined scope",
    "details": {"target": "evil.com", "scope": "*.example.com"}
  }
}
```

Common error codes:
| Code | HTTP Status | Description |
|------|-------------|-------------|
| `SCOPE_VIOLATION` | 403 | Target outside scope |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `TOOL_NOT_FOUND` | 404 | Requested tool not available |
| `SCAN_NOT_FOUND` | 404 | Session ID not found |
| `MODEL_NOT_LOADED` | 503 | LLM model not available |
| `INVALID_CONFIG` | 400 | Invalid configuration |
