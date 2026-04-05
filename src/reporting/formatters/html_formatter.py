"""
WhiteHatHacker AI — HTML Report Formatter

Zafiyet raporlarını HTML formatında oluşturur.
Standalone HTML (inline CSS) — tarayıcıda direkt açılabilir.
"""

from __future__ import annotations

import html
import time
from pathlib import Path
from typing import Any

from loguru import logger


# ============================================================
# CSS Styles
# ============================================================

_CSS = """
<style>
  :root {
    --critical: #d63031;
    --high: #e17055;
    --medium: #fdcb6e;
    --low: #00b894;
    --info: #74b9ff;
    --bg: #f5f6fa;
    --card-bg: #ffffff;
    --text: #2d3436;
    --border: #dfe6e9;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; padding:2em; }
  .container { max-width:960px; margin:0 auto; }
  h1 { font-size:1.8em; margin-bottom:.5em; border-bottom:3px solid var(--critical); padding-bottom:.3em; }
  h2 { font-size:1.3em; margin:1.5em 0 .5em; color:#636e72; }
  h3 { font-size:1.1em; margin:1em 0 .3em; }
  .card { background:var(--card-bg); border:1px solid var(--border); border-radius:8px; padding:1.5em; margin:1em 0; box-shadow:0 2px 4px rgba(0,0,0,.04); }
  .severity { display:inline-block; padding:3px 12px; border-radius:4px; color:#fff; font-weight:600; text-transform:uppercase; font-size:.85em; }
  .sev-critical { background:var(--critical); }
  .sev-high { background:var(--high); }
  .sev-medium { background:var(--medium); color:#2d3436; }
  .sev-low { background:var(--low); }
  .sev-info { background:var(--info); }
  pre { background:#2d3436; color:#dfe6e9; padding:1em; border-radius:6px; overflow-x:auto; font-size:.9em; margin:.5em 0; }
  code { background:#dfe6e9; padding:2px 6px; border-radius:3px; font-size:.9em; }
  pre code { background:transparent; padding:0; }
  table { border-collapse:collapse; width:100%; margin:.8em 0; }
  th,td { border:1px solid var(--border); padding:8px 12px; text-align:left; }
  th { background:#dfe6e9; }
  .meta { font-size:.85em; color:#636e72; margin-bottom:1em; }
  ol li { margin:.3em 0; }
  .evidence { border-left:3px solid var(--high); padding-left:1em; margin:1em 0; }
  img { max-width:100%; border-radius:4px; margin:.5em 0; }
  .footer { margin-top:3em; font-size:.8em; color:#b2bec3; text-align:center; }
</style>
"""


# ============================================================
# HTML Formatter
# ============================================================

class HtmlFormatter:
    """
    Standalone HTML report formatter.

    Usage:
        fmt = HtmlFormatter()
        html_str = fmt.format_report(report_data)
        fmt.save(html_str, "output/reports/finding.html")
    """

    def format_report(self, report: dict[str, Any]) -> str:
        """Tam raporu HTML olarak formatla."""
        parts: list[str] = []

        title = html.escape(report.get("title", "Security Finding Report"))

        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="en">')
        parts.append("<head>")
        parts.append(f"  <meta charset='utf-8'><title>{title}</title>")
        parts.append(_CSS)
        parts.append("</head><body><div class='container'>")

        # Title
        parts.append(f"<h1>{title}</h1>")

        # Meta
        meta = report.get("meta", {})
        if meta:
            parts.append(self._render_meta(meta))

        # Summary
        summary = report.get("summary", "")
        if summary:
            parts.append("<h2>Summary</h2>")
            parts.append(f"<div class='card'>{self._text_to_html(summary)}</div>")

        # Severity
        severity = report.get("severity", {})
        if severity:
            parts.append(self._render_severity(severity))

        # Steps
        steps = report.get("steps_to_reproduce", [])
        if steps:
            parts.append(self._render_steps(steps))

        # Impact
        impact = report.get("impact", "")
        if impact:
            parts.append("<h2>Impact</h2>")
            parts.append(f"<div class='card'>{self._text_to_html(impact)}</div>")

        # PoC
        poc = report.get("poc", {})
        if poc:
            parts.append(self._render_poc(poc))

        # HTTP Evidence
        http_evidence = report.get("http_evidence", [])
        if http_evidence:
            parts.append(self._render_http_evidence(http_evidence))

        # Screenshots
        screenshots = report.get("screenshots", [])
        if screenshots:
            parts.append(self._render_screenshots(screenshots))

        # Remediation
        remediation = report.get("remediation", "")
        if remediation:
            parts.append("<h2>Suggested Fix</h2>")
            parts.append(f"<div class='card'>{self._text_to_html(remediation)}</div>")

        # References
        references = report.get("references", [])
        if references:
            parts.append(self._render_references(references))

        # Footer
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC")
        parts.append(
            f"<div class='footer'>Generated by WhiteHatHacker AI — {ts}</div>"
        )

        parts.append("</div></body></html>")

        return "\n".join(parts)

    def format_findings_table(
        self,
        findings: list[dict[str, Any]],
        session_id: str = "",
    ) -> str:
        """Bulgu özet tablosu HTML."""
        parts: list[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="en"><head><meta charset="utf-8">')
        parts.append("<title>Findings Summary</title>")
        parts.append(_CSS)
        parts.append("</head><body><div class='container'>")
        parts.append("<h1>Findings Summary</h1>")

        if session_id:
            parts.append(f"<p class='meta'>Session: {html.escape(session_id)}</p>")

        parts.append("<table><thead><tr>")
        parts.append("<th>#</th><th>Severity</th><th>Title</th>")
        parts.append("<th>Confidence</th><th>Status</th></tr></thead><tbody>")

        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity") or "info").lower()
            sev_cls = f"sev-{sev}" if sev in ("critical", "high", "medium", "low", "info") else "sev-info"
            title = html.escape(f.get("title", "Untitled")[:80])
            conf = f.get("confidence_score", f.get("confidence", 0))
            status = html.escape(f.get("status", "unverified"))

            parts.append(f"<tr><td>{i}</td>")
            parts.append(f"<td><span class='severity {sev_cls}'>{sev.upper()}</span></td>")
            parts.append(f"<td>{title}</td><td>{conf}%</td><td>{status}</td></tr>")

        parts.append("</tbody></table>")
        parts.append("</div></body></html>")

        return "\n".join(parts)

    # --------- Private Helpers ---------

    def _render_meta(self, meta: dict) -> str:
        items = " | ".join(
            f"<strong>{html.escape(k)}:</strong> {html.escape(str(v))}"
            for k, v in meta.items()
        )
        return f"<p class='meta'>{items}</p>"

    def _render_severity(self, severity: dict) -> str:
        score = severity.get("cvss_score", "N/A")
        label = severity.get("label", "medium").lower()
        vector = severity.get("vector", "")
        sev_cls = f"sev-{label}" if label in ("critical", "high", "medium", "low", "info") else "sev-medium"

        s = "<h2>Severity</h2><div class='card'>"
        s += f"<span class='severity {sev_cls}'>{html.escape(str(label).upper())}</span> "
        s += f"&nbsp; <strong>CVSS:</strong> {html.escape(str(score))}"
        if vector:
            s += f"<br><code>{html.escape(vector)}</code>"
        s += "</div>"
        return s

    def _render_steps(self, steps: list) -> str:
        s = "<h2>Steps to Reproduce</h2><div class='card'><ol>"
        for step in steps:
            if isinstance(step, str):
                s += f"<li>{self._text_to_html(step)}</li>"
            elif isinstance(step, dict):
                desc = html.escape(step.get("description", ""))
                s += f"<li>{desc}"
                if step.get("code"):
                    s += f"<pre><code>{html.escape(step['code'])}</code></pre>"
                s += "</li>"
        s += "</ol></div>"
        return s

    def _render_poc(self, poc: dict) -> str:
        s = "<h2>Proof of Concept</h2><div class='card'>"
        if poc.get("description"):
            s += f"<p>{self._text_to_html(poc['description'])}</p>"
        if poc.get("code"):
            s += f"<pre><code>{html.escape(poc['code'])}</code></pre>"
        if poc.get("command"):
            s += f"<pre><code>{html.escape(poc['command'])}</code></pre>"
        s += "</div>"
        return s

    def _render_http_evidence(self, evidence: list[dict]) -> str:
        s = "<h2>HTTP Evidence</h2>"
        for i, ev in enumerate(evidence, 1):
            s += f"<h3>Request/Response #{i}</h3><div class='evidence'>"
            if ev.get("request"):
                s += f"<strong>Request:</strong><pre><code>{html.escape(ev['request'])}</code></pre>"
            if ev.get("response"):
                resp = ev["response"]
                if len(resp) > 2000:
                    resp = resp[:2000] + "\n... [truncated]"
                s += f"<strong>Response:</strong><pre><code>{html.escape(resp)}</code></pre>"
            s += "</div>"
        return s

    def _render_screenshots(self, screenshots: list[str]) -> str:
        s = "<h2>Screenshots</h2><div class='card'>"
        for i, ss in enumerate(screenshots, 1):
            s += f"<img src='{html.escape(ss)}' alt='Screenshot {i}'><br>"
        s += "</div>"
        return s

    def _render_references(self, references: list) -> str:
        s = "<h2>References</h2><ul>"
        for ref in references:
            if isinstance(ref, str):
                esc = html.escape(ref)
                if ref.startswith("http"):
                    s += f"<li><a href='{esc}' target='_blank'>{esc}</a></li>"
                else:
                    s += f"<li>{esc}</li>"
            elif isinstance(ref, dict):
                name = html.escape(ref.get("name", ref.get("url", "")))
                url = html.escape(ref.get("url", "#"))
                s += f"<li><a href='{url}' target='_blank'>{name}</a></li>"
        s += "</ul>"
        return s

    @staticmethod
    def _text_to_html(text: str) -> str:
        """Plain text → basit HTML (paragraflar + code blokları)."""
        text = html.escape(text)
        # Backtick code → <code>
        import re
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        # Paragraflar
        paragraphs = text.split("\n\n")
        return "".join(f"<p>{p.strip()}</p>" for p in paragraphs if p.strip())

    # --------- Save ---------

    def save(self, content: str, filepath: str) -> str:
        """HTML dosyasına kaydet."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"HTML report saved: {path}")
        return str(path)


__all__ = ["HtmlFormatter"]
