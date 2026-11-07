"""waybackurls / gau / plain URL list parser."""

from __future__ import annotations

from .base import ParseLimits, ParseResult, candidate, derive_param, iter_lines

NAME = "gau/waybackurls"
PRIORITY = 100


def sniff(path: str, head: str) -> bool:
    lines = [line.strip() for line in head.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    structured = any(marker in head for marker in ('{"', "<", "Status:", "Parameter:", "template-id"))
    if structured:
        return False
    urls = [line for line in lines if line.startswith("http://") or line.startswith("https://")]
    return len(urls) >= max(1, int(len(lines) * 0.6))


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    last_offset = limits.start_offset
    partial = False
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if not (text.startswith("http://") or text.startswith("https://")):
            continue
        out.append(
            candidate(
                raw_type="endpoint_internal",
                endpoint=text,
                param=derive_param(text),
                evidence=text[:300],
                tool=NAME,
                severity="info",
                confidence="medium",
                title="URL from wordlist/wayback",
            )
        )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
