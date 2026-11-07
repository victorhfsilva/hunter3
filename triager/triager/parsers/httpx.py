"""httpx JSONL / text parser (inventory and technology evidence)."""

from __future__ import annotations

import re

from .base import ParseLimits, ParseResult, candidate, derive_param, iter_lines, safe_json, type_from_text

NAME = "httpx"
PRIORITY = 80
TEXT_RE = re.compile(r"^(https?://\S+)\s+\[?(\d{3})?\]?\s*(.*)$")


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if '"status_code"' in low and '"url"' in low:
        return True
    if '"tech"' in low and '"url"' in low and '"title"' in low:
        return True
    match = TEXT_RE.match(low.strip().splitlines()[0]) if low.strip() else None
    return bool(match) and ("[200]" in low or "[301]" in low or "[302]" in low or "[403]" in low or "title" in low.lower())


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out: list[dict] = []
    last_offset = limits.start_offset
    partial = False
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        obj = safe_json(text) if text.startswith("{") else None
        if isinstance(obj, dict):
            endpoint = str(obj.get("url") or "")
            if not endpoint:
                continue
            tech = obj.get("tech") or obj.get("technologies") or ""
            if isinstance(tech, list):
                tech = ", ".join(str(item) for item in tech)
            title = str(obj.get("title") or "")
            webserver = str(obj.get("webserver") or "")
            raw_type = "tech" if (tech or webserver) else "endpoint_internal"
            out.append(
                candidate(
                    raw_type=raw_type,
                    endpoint=endpoint,
                    param=derive_param(endpoint),
                    evidence=text[:300],
                    tool=NAME,
                    severity="info",
                    confidence="high",
                    reproduction=text[:800],
                    title=title or str(tech or webserver),
                    host=str(obj.get("host") or ""),
                )
            )
        else:
            match = TEXT_RE.match(text)
            if match:
                endpoint, status, rest = match.groups()
                out.append(
                    candidate(
                        raw_type=type_from_text(rest) if rest else "endpoint_internal",
                        endpoint=endpoint,
                        param=derive_param(endpoint),
                        evidence=text[:300],
                        tool=NAME,
                        severity="info",
                        confidence="medium",
                        reproduction=text[:800],
                        title=rest[:120],
                    )
                )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
