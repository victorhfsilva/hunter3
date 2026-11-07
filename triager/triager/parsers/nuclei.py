"""Nuclei JSONL / text parser."""

from __future__ import annotations

import re

from .base import ParseLimits, ParseResult, candidate, derive_param, iter_lines, safe_json, type_from_text

NAME = "Nuclei"
PRIORITY = 10
TEXT_RE = re.compile(r"^\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)\s*(.*)$")


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if '"template-id"' in low or ('"matched-at"' in low and '"info"' in low):
        return True
    return bool(TEXT_RE.search(low)) and ("nuclei" in low.lower() or "[info]" in low.lower() or "[high]" in low.lower())


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out: list[dict] = []
    last_offset = limits.start_offset
    partial = False
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        if not line:
            continue
        text = line.strip()
        if not text:
            continue
        obj = safe_json(text) if text.startswith("{") else None
        if isinstance(obj, dict):
            info = obj.get("info") or {}
            endpoint = obj.get("matched-at") or obj.get("host") or obj.get("url") or ""
            if not endpoint:
                continue
            template = str(obj.get("template-id") or "")
            name = str(info.get("name") or "")
            matcher = str(obj.get("matcher-name") or "")
            raw_type = type_from_text(f"{template} {name} {matcher}")
            method = str(obj.get("method") or obj.get("http-method") or "GET").upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                method = "GET"
            out.append(
                candidate(
                    raw_type=raw_type,
                    endpoint=endpoint,
                    method=method,
                    param=derive_param(endpoint),
                    evidence=text[:300],
                    tool=NAME,
                    severity=str(info.get("severity") or ""),
                    confidence="high",
                    reproduction=str(obj.get("curl-command") or obj.get("request") or ""),
                    title=name or template,
                    host=str(obj.get("host") or ""),
                )
            )
        else:
            match = TEXT_RE.match(text)
            if match:
                template, severity, endpoint, rest = match.groups()
                out.append(
                    candidate(
                        raw_type=type_from_text(f"{template} {rest}"),
                        endpoint=endpoint,
                        param=derive_param(endpoint),
                        evidence=text[:300],
                        tool=NAME,
                        severity=severity,
                        confidence="medium",
                        reproduction=text[:800],
                        title=rest[:120] or template,
                    )
                )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
