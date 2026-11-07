"""Parser interface and streaming helpers.

Parsers are purely declarative: regex / json / ElementTree only.  Output file
content is never executed or interpreted as instructions.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Iterator

HEAD_BYTES = 16384
MAX_LINE = 1_000_000
MAX_CANDIDATES_PER_FILE = 5000


@dataclass
class ParseLimits:
    max_seconds: float = 60.0
    max_candidates: int = MAX_CANDIDATES_PER_FILE
    start_offset: int = 0
    max_bytes: int = 10 * 1024 * 1024


@dataclass
class ParseResult:
    candidates: list[dict]
    offset: int
    bytes_read: int
    partial: bool
    reason: str = ""


def read_head(path: str, n: int = HEAD_BYTES) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(n)
    except OSError:
        return b""


def head_text(path: str, n: int = HEAD_BYTES) -> str:
    return read_head(path, n).decode("utf-8", "replace")


def text_of(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def iter_lines(path: str, limits: ParseLimits, binary: bool = False) -> Iterator[tuple[str, int]]:
    """Stream lines in binary mode so offsets remain seekable.

    A per-file time budget is checked inside the loop; on expiry the generator
    yields an empty sentinel with the current offset and returns.
    """
    started = time.monotonic()
    try:
        with open(path, "rb") as handle:
            if limits.start_offset:
                handle.seek(limits.start_offset)
            # limite: linhas até o deadline do arquivo; sem while infinito.
            for raw in handle:
                if time.monotonic() - started > limits.max_seconds:
                    yield "", handle.tell()
                    return
                line = raw.decode("utf-8", "replace")
                yield line[:MAX_LINE], handle.tell()
    except OSError:
        return


def safe_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def severity_name(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        value = str(value)
    value = str(value).strip().lower()
    mapping = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "unknown": "",
    }
    return mapping.get(value, value if value in mapping.values() else "")


def candidate(
    *,
    raw_type: str,
    endpoint: str,
    method: str = "GET",
    param: str = "",
    evidence: str = "",
    tool: str = "",
    severity: str = "",
    confidence: str = "",
    reproduction: str = "",
    title: str = "",
    host: str = "",
) -> dict:
    return {
        "raw_type": raw_type,
        "endpoint": endpoint.strip(),
        "method": (method or "GET").upper(),
        "param": (param or "").strip(),
        "evidence": (evidence or "").strip()[:300],
        "tool": tool,
        "severity": severity_name(severity),
        "confidence": (confidence or "").strip().lower(),
        "reproduction": (reproduction or "").strip()[:800],
        "title": (title or "").strip(),
        "host": (host or "").strip().lower(),
    }


def line_evidence(path: str, line_no: int, text: str) -> str:
    return f"{os.path.basename(path)}:{line_no}: {re.sub(r'\s+', ' ', text.strip())[:300]}"


def derive_param(url: str) -> str:
    try:
        from urllib.parse import parse_qsl, urlsplit

        query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        return query[0][0] if query else ""
    except ValueError:
        return ""


def type_from_text(text: str) -> str:
    low = (text or "").lower()
    rules = [
        ("sqli", ["sql injection", "sqli", "sqlmap"]),
        ("xss", ["cross-site scripting", "xss"]),
        ("ssrf", ["server-side request forgery", "ssrf"]),
        ("lfi", ["local file inclusion", "lfi", "path traversal", "directory traversal"]),
        ("rce", ["remote code execution", "rce", "command injection"]),
        ("open_redirect", ["open redirect", "redirect"]),
        ("idor", ["idor", "bola", "insecure direct object"]),
        ("cors", ["cors", "cross-origin"]),
        ("csrf", ["csrf", "cross-site request forgery"]),
        ("ssti", ["ssti", "template injection"]),
        ("xxe", ["xxe", "xml external entity"]),
        ("nosqli", ["nosql", "nosqli"]),
        ("takeover", ["takeover", "subdomain takeover"]),
        ("graphql", ["graphql"]),
        ("misconfig", ["misconfiguration", "misconfig", "exposure", "debug", "directory listing"]),
        ("headers", ["missing header", "security header", "hsts", "csp"]),
        ("tech", ["version", "outdated", "vulnerable version"]),
    ]
    for canonical, needles in rules:
        if any(needle in low for needle in needles):
            return canonical
    return "other"
