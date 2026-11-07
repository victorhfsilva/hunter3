"""Declarative extraction helpers shared by recon and AI-assisted planning.

Everything here treats scanner/page output as DATA.  Only regex, JSON and
string operations are used; nothing from the input is executed.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

URL_RE = re.compile(r"""(?:https?://[^\s"'<>\\]+|/[A-Za-z0-9_\-./?=&%]*)""")
ENDPOINT_HINT = re.compile(
    r"/(?:api|v\d+|graphql|login|signin|signup|register|auth|user|account|order|billing|invoice|"
    r"payment|token|password|reset|admin|upload|export|role|settings|checkout|profile|search|"
    r"session|oauth|sso|invite|team|workspace|report|debug|status|health)",
    re.IGNORECASE,
)
QUOTED_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./?=&%{}:]{2,180})["'`]""")
ROUTE_LITERAL_RE = re.compile(
    r"""(?:path|url|endpoint|route|to|href)\s*[:=]\s*["'`](/[A-Za-z0-9_\-./?=&%{}:]{2,180})["'`]""",
    re.IGNORECASE,
)
FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r"""(\w+)\s*=\s*["']([^"']*)["']""")
INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.IGNORECASE)
NAME_RE = re.compile(r"""\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
ROBOTS_RE = re.compile(r"^(?:Allow|Disallow)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
SENSITIVE_PARAM_RE = re.compile(r"(?:token|key|secret|password|passwd|auth|session|cookie|sig|signature|jwt)", re.IGNORECASE)


def is_static(url: str) -> bool:
    path = urlsplit(url).path or ""
    return bool(re.search(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|txt|xml|pdf|zip|tar|gz)$", path, re.IGNORECASE))


def params_from_url(url: str) -> list[str]:
    try:
        query = urlsplit(url).query
    except ValueError:
        return []
    params = []
    for pair in query.split("&"):
        if "=" in pair:
            name = pair.split("=", 1)[0]
            if name and name not in params:
                params.append(name)
    return params


def sanitize_url_for_ai(url: str) -> str:
    """Never send secrets found in query strings to the model."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    query = []
    for pair in parts.query.split("&"):
        if not pair:
            continue
        if "=" in pair:
            name, value = pair.split("=", 1)
            if SENSITIVE_PARAM_RE.search(name):
                value = "***"
            query.append(f"{name}={value[:80]}")
        else:
            query.append(pair[:80])
    return parts._replace(query="&".join(query)).geturl()


def harvest_text(text: str, source_url: str, scope, source_kind: str = "html") -> tuple[list[str], list[str], list[str]]:
    """Return (links, scripts, endpoints) absolutes; external links are kept as links."""
    links: list[str] = []
    scripts: list[str] = []
    endpoints: list[str] = []

    def add_endpoint(absolute: str) -> None:
        if absolute not in endpoints:
            endpoints.append(absolute)

    if source_kind == "html":
        for match in re.finditer(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", text or "", re.IGNORECASE):
            raw = match.group(1).strip()
            if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            absolute = urljoin(source_url, raw)
            if raw.lower().split("?")[0].endswith(".js"):
                scripts.append(absolute)
            elif re.search(r"""href\s*=\s*["']""", match.group(0), re.IGNORECASE):
                links.append(absolute)

    for match in URL_RE.finditer(text or ""):
        raw = match.group(0).rstrip(".,;)\"'")
        absolute = urljoin(source_url, raw)
        allowed, _ = scope.check(absolute)
        if allowed:
            if ENDPOINT_HINT.search(urlsplit(absolute).path or "") or ENDPOINT_HINT.search(raw):
                add_endpoint(absolute)
        elif raw.startswith("http") and raw not in links:
            links.append(raw)

    for regex in (QUOTED_PATH_RE, ROUTE_LITERAL_RE):
        for match in regex.finditer(text or ""):
            raw = match.group(1)
            if not ENDPOINT_HINT.search(raw):
                continue
            absolute = urljoin(source_url, raw)
            if scope.check(absolute)[0]:
                add_endpoint(absolute)
    return links, scripts, endpoints


def extract_forms(text: str, base_url: str, scope) -> list[dict]:
    forms: list[dict] = []
    for match in FORM_RE.finditer(text or ""):
        attrs = {key.lower(): value for key, value in ATTR_RE.findall(match.group(1) or "")}
        action = (attrs.get("action") or base_url).strip()
        if action.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        absolute = urljoin(base_url, action)
        if not scope.check(absolute)[0]:
            continue
        method = (attrs.get("method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH"):
            method = "GET"
        params: list[str] = []
        for input_tag in INPUT_RE.findall(match.group(2) or ""):
            name_match = NAME_RE.search(input_tag)
            if name_match:
                name = name_match.group(1).strip()
                if name and name not in params and len(name) <= 64:
                    params.append(name)
        forms.append({"url": absolute, "method": method, "params": params, "source": "form"})
    return forms


def extract_openapi(text: str, base_url: str, scope) -> tuple[list[dict], dict]:
    try:
        data = json.loads(text or "")
    except (ValueError, TypeError):
        return [], {}
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return [], {}
    servers = data.get("servers") or []
    base_path = ""
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base_path = str(servers[0].get("url") or "")
    base_path = base_path or str(data.get("basePath") or "")
    prefix = ""
    if base_path.startswith("http"):
        prefix = base_path.rstrip("/")
    elif base_path.startswith("/"):
        prefix = base_path.rstrip("/")
    endpoints: list[dict] = []
    # limite: 120 paths do schema OpenAPI.
    for path, methods in list(data["paths"].items())[:120]:
        if not isinstance(methods, dict):
            continue
        full = prefix + path if prefix else path
        for method, spec in methods.items():
            method = str(method).upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                continue
            params = []
            if isinstance(spec, dict):
                for parameter in spec.get("parameters") or []:
                    if isinstance(parameter, dict) and parameter.get("name"):
                        name = str(parameter["name"])
                        if name not in params and len(name) <= 64:
                            params.append(name)
            absolute = urljoin(base_url, full)
            if scope.check(absolute)[0]:
                endpoints.append({"url": absolute, "method": method, "params": params, "source": "openapi"})
    meta = {
        "title": str((data.get("info") or {}).get("title") or ""),
        "version": str(data.get("openapi") or data.get("swagger") or ""),
        "path_count": len(data["paths"]),
    }
    return endpoints, meta


def extract_robots(text: str) -> tuple[list[str], list[str]]:
    paths: list[str] = []
    sitemaps: list[str] = []
    for match in ROBOTS_RE.finditer(text or ""):
        value = match.group(1).strip()
        if value and value != "/" and "*" not in value and value not in paths:
            paths.append(value[:200])
    for line in (text or "").splitlines():
        if line.lower().startswith("sitemap:"):
            value = line.split(":", 1)[1].strip()
            if value.startswith("http") and value not in sitemaps:
                sitemaps.append(value)
    return paths[:40], sitemaps[:5]


def extract_sitemap(text: str) -> list[str]:
    urls: list[str] = []
    for match in LOC_RE.finditer(text or ""):
        value = match.group(1).strip()
        if value.startswith("http") and value not in urls:
            urls.append(value)
        if len(urls) >= 60:
            break
    return urls


def merge_params(*groups) -> list[str]:
    params: list[str] = []
    for group in groups:
        for name in group or []:
            name = str(name)[:64]
            if name and name not in params:
                params.append(name)
    return params[:80]
