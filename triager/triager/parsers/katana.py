"""katana JSONL parser."""

from __future__ import annotations

from .base import ParseLimits, ParseResult, candidate, derive_param, iter_lines, safe_json

NAME = "katana"
PRIORITY = 105


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    return '"request"' in low and '"endpoint"' in low and '"response"' in low


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    last_offset = limits.start_offset
    partial = False
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.strip()
        if not text:
            continue
        obj = safe_json(text)
        if not isinstance(obj, dict):
            continue
        request = obj.get("request") or {}
        endpoint = str(request.get("endpoint") or obj.get("endpoint") or obj.get("url") or "")
        if not endpoint:
            continue
        out.append(
            candidate(
                raw_type="endpoint_internal",
                endpoint=endpoint,
                method=str(request.get("method") or "GET"),
                param=derive_param(endpoint),
                evidence=text[:300],
                tool=NAME,
                severity="info",
                confidence="high",
                title="katana endpoint",
            )
        )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
