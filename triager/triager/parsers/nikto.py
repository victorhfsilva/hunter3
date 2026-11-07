"""Nikto text parser."""

from __future__ import annotations

import re

from .base import ParseLimits, ParseResult, candidate, iter_lines, type_from_text

NAME = "Nikto"
PRIORITY = 50
FINDING_RE = re.compile(r"^\+\s+(\S+):\s*(.*)$")
TARGET_RE = re.compile(r"^-\s+Target (?:IP|Hostname|Port):\s*(\S+)")


def sniff(path: str, head: str) -> bool:
    low = head[:6000].lower()
    if "nikto" in low:
        return True
    return bool(re.search(r"^\+\s+\S+:", head, re.MULTILINE))


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    last_offset = limits.start_offset
    partial = False
    target = ""
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.rstrip("\n")
        match = TARGET_RE.match(text)
        if match:
            value = match.group(1)
            target = value if value.startswith("http") else f"http://{value}"
            continue
        match = FINDING_RE.match(text)
        if not match:
            continue
        path_value, description = match.groups()
        endpoint = path_value if path_value.startswith("http") else target.rstrip("/") + "/" + path_value.lstrip("/")
        out.append(
            candidate(
                raw_type=type_from_text(description),
                endpoint=endpoint,
                param="",
                evidence=text[:300],
                tool=NAME,
                severity="medium",
                confidence="medium",
                reproduction=text[:800],
                title=description[:160] or "Nikto finding",
            )
        )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
