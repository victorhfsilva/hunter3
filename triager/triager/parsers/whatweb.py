"""WhatWeb text / JSON-lines parser."""

from __future__ import annotations

import re

from .base import ParseLimits, ParseResult, candidate, iter_lines, safe_json

NAME = "WhatWeb"
PRIORITY = 75
LINE_RE = re.compile(r"^(https?://\S+),\s*(.*)$")


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if '"plugins"' in low and '"target"' in low:
        return True
    return bool(LINE_RE.match(low.strip().splitlines()[0])) if low.strip() else False


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    last_offset = limits.start_offset
    partial = False
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.strip()
        if not text:
            continue
        obj = safe_json(text) if text.startswith("{") else None
        if isinstance(obj, dict):
            target = str(obj.get("target") or "")
            plugins = obj.get("plugins") or {}
            names = ", ".join(list(plugins)[:12]) if isinstance(plugins, dict) else str(plugins)
            if not target:
                continue
            out.append(
                candidate(
                    raw_type="tech",
                    endpoint=target,
                    evidence=f"WhatWeb plugins: {names}"[:300],
                    tool=NAME,
                    severity="info",
                    confidence="high",
                    title=names[:160] or "WhatWeb fingerprint",
                )
            )
        else:
            match = LINE_RE.match(text)
            if match:
                endpoint, rest = match.groups()
                out.append(
                    candidate(
                        raw_type="tech",
                        endpoint=endpoint,
                        evidence=text[:300],
                        tool=NAME,
                        severity="info",
                        confidence="medium",
                        title=rest[:160] or "WhatWeb fingerprint",
                    )
                )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
