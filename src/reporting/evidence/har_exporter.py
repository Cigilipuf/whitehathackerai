"""WhiteHatHacker AI — HAR (HTTP Archive) Exporter.

Converts recorded HTTP exchanges into standard HAR 1.2 format for
import into Burp Suite, Chrome DevTools, and other analysis tools.

Spec: http://www.softwareishard.com/blog/har-12-spec/
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from loguru import logger

from src.reporting.evidence.request_logger import HttpExchange, RequestLogger


def _parse_headers(headers: dict[str, str]) -> list[dict[str, str]]:
    """Convert a flat header dict to HAR name/value list."""
    return [{"name": k, "value": v} for k, v in headers.items()]


def _parse_query_string(url: str) -> list[dict[str, str]]:
    """Extract query string parameters from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    result: list[dict[str, str]] = []
    for name, values in params.items():
        for val in values:
            result.append({"name": name, "value": val})
    return result


def _iso_timestamp(epoch: float) -> str:
    """Convert epoch to ISO 8601 timestamp."""
    if not epoch:
        epoch = time.time()
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.isoformat()


def exchange_to_har_entry(exchange: HttpExchange) -> dict[str, Any]:
    """Convert a single HttpExchange to a HAR entry."""
    parsed = urlparse(exchange.url)

    # Request object
    request_obj: dict[str, Any] = {
        "method": exchange.method,
        "url": exchange.url,
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": _parse_headers(exchange.request_headers),
        "queryString": _parse_query_string(exchange.url),
        "headersSize": -1,
        "bodySize": len(exchange.request_body) if exchange.request_body else 0,
    }
    if exchange.request_body:
        content_type = exchange.request_headers.get(
            "Content-Type",
            exchange.request_headers.get("content-type", "application/x-www-form-urlencoded"),
        )
        request_obj["postData"] = {
            "mimeType": content_type,
            "text": exchange.request_body,
        }

    # Response object
    resp_content_type = exchange.response_headers.get(
        "Content-Type",
        exchange.response_headers.get("content-type", "text/html"),
    )
    response_obj: dict[str, Any] = {
        "status": exchange.status_code or 0,
        "statusText": _status_text(exchange.status_code),
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": _parse_headers(exchange.response_headers),
        "content": {
            "size": len(exchange.response_body) if exchange.response_body else 0,
            "mimeType": resp_content_type,
            "text": exchange.response_body[:100_000] if exchange.response_body else "",
        },
        "redirectURL": exchange.response_headers.get("Location", ""),
        "headersSize": -1,
        "bodySize": len(exchange.response_body) if exchange.response_body else 0,
    }

    # Timings
    timings: dict[str, float] = {
        "send": 0,
        "wait": exchange.response_time_ms if exchange.response_time_ms else -1,
        "receive": 0,
    }

    entry: dict[str, Any] = {
        "startedDateTime": _iso_timestamp(exchange.timestamp),
        "time": exchange.response_time_ms if exchange.response_time_ms else 0,
        "request": request_obj,
        "response": response_obj,
        "cache": {},
        "timings": timings,
        "serverIPAddress": parsed.hostname or "",
        "comment": _build_comment(exchange),
    }

    return entry


def _build_comment(exchange: HttpExchange) -> str:
    """Build a HAR comment from exchange metadata."""
    parts: list[str] = []
    if exchange.tool_name:
        parts.append(f"tool={exchange.tool_name}")
    if exchange.finding_id:
        parts.append(f"finding={exchange.finding_id}")
    if exchange.is_payload:
        parts.append("PAYLOAD")
    if exchange.payload_used:
        parts.append(f"payload={exchange.payload_used[:80]}")
    if exchange.notes:
        parts.append(exchange.notes[:100])
    return " | ".join(parts)


def _status_text(code: int) -> str:
    """Map HTTP status code to reason phrase."""
    _MAP = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
        500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
    }
    return _MAP.get(code, "")


def export_har(
    request_logger: RequestLogger,
    output_path: str | Path | None = None,
    *,
    finding_id: str = "",
    creator_name: str = "WhiteHatHacker AI",
    creator_version: str = "2.7.0",
) -> str:
    """Export recorded HTTP exchanges to HAR 1.2 format.

    Args:
        request_logger: The RequestLogger containing exchanges.
        output_path: Optional file path. If None, auto-generates in logger output_dir.
        finding_id: If set, only export exchanges for this finding.
        creator_name: HAR creator name.
        creator_version: HAR creator version.

    Returns:
        Path to the saved HAR file.
    """
    if finding_id:
        exchanges = request_logger.get_by_finding(finding_id)
    else:
        exchanges = request_logger.exchanges

    if not exchanges:
        logger.debug("No exchanges to export as HAR")
        return ""

    entries = [exchange_to_har_entry(ex) for ex in exchanges]

    har: dict[str, Any] = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": creator_name,
                "version": creator_version,
            },
            "entries": entries,
            "comment": (
                f"Session: {request_logger.session_id} | "
                f"Exchanges: {len(entries)}"
            ),
        }
    }

    if output_path is None:
        suffix = f"_{finding_id}" if finding_id else ""
        output_path = (
            request_logger.output_dir
            / f"{request_logger.session_id}{suffix}.har"
        )
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(har, indent=2, default=str), encoding="utf-8")

    logger.info(
        f"HAR exported | entries={len(entries)} | path={output_path}"
    )

    return str(output_path)


__all__ = [
    "export_har",
    "exchange_to_har_entry",
]
