"""Parameter Intelligence — classify URL parameters by likely attack type.

v5.0: Routes high-value parameters to the right scanners, reducing noise and
increasing hit rate by focusing each tool on its most promising targets.
"""

from __future__ import annotations

from typing import Literal

AttackType = Literal["sqli", "xss", "ssrf", "lfi", "idor", "ssti", "rce", "redirect", "general"]

# --- Parameter-to-attack-type classification tables ---

_SQLI_PARAMS: set[str] = {
    "id", "uid", "user_id", "item_id", "product_id", "order_id", "category_id",
    "cat", "sort", "order", "orderby", "sort_by", "column", "table", "where",
    "filter", "limit", "offset", "page", "num", "count", "from", "to",
    "year", "month", "day", "date", "start", "end", "group", "having",
    "select", "query", "search", "q", "keyword", "term", "name", "username",
    "email", "login", "password", "pass",
}

_XSS_PARAMS: set[str] = {
    "q", "search", "query", "keyword", "term", "s", "text", "title",
    "name", "comment", "message", "body", "content", "description",
    "value", "input", "data", "label", "placeholder", "error", "msg",
    "alert", "callback", "cb", "jsonp", "format", "template", "lang",
    "locale", "preview", "debug", "test", "echo", "display", "output",
    "return", "redirect_uri", "next", "continue", "returnTo",
}

_SSRF_PARAMS: set[str] = {
    "url", "uri", "path", "dest", "destination", "redirect", "redirect_url",
    "redirect_uri", "rurl", "src", "source", "link", "href", "proxy", "target",
    "fetch", "load", "request", "img", "image", "icon", "avatar", "logo",
    "feed", "rss", "xml", "webhook", "callback", "api", "endpoint", "host",
    "domain", "site", "server", "ip", "address", "gateway", "forward",
}

_LFI_PARAMS: set[str] = {
    "file", "filename", "path", "filepath", "page", "include", "require",
    "template", "tmpl", "tpl", "view", "layout", "module", "doc", "document",
    "folder", "dir", "directory", "root", "conf", "config", "log", "lang",
    "locale", "theme", "style", "css", "font", "attachment", "download",
}

_IDOR_PARAMS: set[str] = {
    "id", "uid", "user_id", "account_id", "profile_id", "member_id",
    "customer_id", "order_id", "invoice_id", "ticket_id", "doc_id",
    "file_id", "report_id", "project_id", "team_id", "org_id",
    "account", "user", "profile", "no", "number", "ref", "reference",
    "token", "key", "handle", "slug",
}

_SSTI_PARAMS: set[str] = {
    "template", "tmpl", "tpl", "view", "layout", "page", "content",
    "name", "title", "message", "email", "subject", "body", "format",
    "render", "preview", "lang", "locale", "theme",
}

_RCE_PARAMS: set[str] = {
    "cmd", "command", "exec", "execute", "run", "system", "shell",
    "ping", "ip", "host", "address", "target", "process", "daemon",
    "action", "do", "func", "function", "handler", "method", "operation",
}

_REDIRECT_PARAMS: set[str] = {
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "rurl",
    "next", "continue", "return", "returnTo", "return_url", "goto",
    "forward", "dest", "destination", "target", "to", "out", "link",
    "checkout_url", "success_url", "cancel_url", "callback",
}


def classify_param(param_name: str) -> list[AttackType]:
    """Return ordered list of likely attack types for a parameter name."""
    p = param_name.lower().strip()
    types: list[AttackType] = []
    if p in _IDOR_PARAMS:
        types.append("idor")
    if p in _SQLI_PARAMS:
        types.append("sqli")
    if p in _SSRF_PARAMS:
        types.append("ssrf")
    if p in _LFI_PARAMS:
        types.append("lfi")
    if p in _RCE_PARAMS:
        types.append("rce")
    if p in _SSTI_PARAMS:
        types.append("ssti")
    if p in _REDIRECT_PARAMS:
        types.append("redirect")
    if p in _XSS_PARAMS:
        types.append("xss")
    if not types:
        types.append("general")
    return types


def filter_urls_for_attack(urls: list[str], attack_type: AttackType) -> list[str]:
    """Return URLs whose parameters are relevant to the given attack type.

    URLs without query parameters are always included (they may have path params).
    """
    param_set = {
        "sqli": _SQLI_PARAMS,
        "xss": _XSS_PARAMS,
        "ssrf": _SSRF_PARAMS,
        "lfi": _LFI_PARAMS,
        "idor": _IDOR_PARAMS,
        "ssti": _SSTI_PARAMS,
        "rce": _RCE_PARAMS,
        "redirect": _REDIRECT_PARAMS,
    }.get(attack_type)

    if param_set is None:
        return urls  # "general" → return all

    result: list[str] = []
    for url in urls:
        # Extract parameter names from query string
        if "?" not in url:
            result.append(url)  # No params → might have path params
            continue
        qs = url.split("?", 1)[1]
        params = [p.split("=", 1)[0].lower() for p in qs.split("&") if "=" in p]
        if any(p in param_set for p in params):
            result.append(url)
    return result


def prioritize_params_for_sqli(params: list[str]) -> list[str]:
    """Sort parameter URLs with SQLi-likely params first."""
    def _score(url: str) -> int:
        if "?" not in url:
            return 0
        qs = url.split("?", 1)[1]
        names = [p.split("=", 1)[0].lower() for p in qs.split("&") if "=" in p]
        return sum(1 for n in names if n in _SQLI_PARAMS)
    return sorted(params, key=_score, reverse=True)
