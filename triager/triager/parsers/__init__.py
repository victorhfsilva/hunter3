"""Parser registry with content sniffing (never extension-only)."""

from __future__ import annotations

from . import (
    burp,
    fuzz,
    generic,
    httpx,
    katana,
    nikto,
    nmap,
    nuclei,
    secrets,
    semgrep,
    sqlmap,
    urls,
    whatweb,
    wpscan,
    zap,
)
from .base import ParseLimits, ParseResult, read_head

# Priority order is part of the contract: high-signal tools first.
PARSERS = [
    nuclei,
    sqlmap,
    burp,
    zap,
    nikto,
    wpscan,
    fuzz,
    whatweb,
    httpx,
    nmap,
    urls,
    katana,
    semgrep,
    secrets,
    generic,
]

TOOL_PRIORITY = {module.NAME: module.PRIORITY for module in PARSERS}


def detect(path: str, head: str | bytes | None = None) -> object:
    if head is None:
        head = read_head(path).decode("utf-8", "replace")
    elif isinstance(head, bytes):
        head = head.decode("utf-8", "replace")
    for module in PARSERS:
        try:
            if module.sniff(path, head):
                return module
        except Exception:
            continue
    return generic


def tool_name(path: str, head: str | bytes | None = None) -> str:
    return str(detect(path, head).NAME)


def parse_file(path: str, limits: ParseLimits, module=None) -> ParseResult:
    module = module or detect(path)
    return module.parse(path, limits)


__all__ = ["PARSERS", "TOOL_PRIORITY", "detect", "tool_name", "parse_file", "ParseLimits", "ParseResult"]
