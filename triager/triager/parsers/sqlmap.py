"""sqlmap log parser."""

from __future__ import annotations

import re

from .base import ParseLimits, ParseResult, candidate, iter_lines, type_from_text

NAME = "sqlmap"
PRIORITY = 20
URI_RE = re.compile(r"URI:\s*(\S+)", re.IGNORECASE)
TARGET_RE = re.compile(r"Target URL:\s*(\S+)", re.IGNORECASE)


def sniff(path: str, head: str) -> bool:
    low = head[:6000].lower()
    return ("parameter:" in low and ("type:" in low or "payload:" in low)) or "sqlmap" in low


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out: list[dict] = []
    last_offset = limits.start_offset
    partial = False
    endpoint = ""
    param = ""
    technique = ""
    title = ""
    payload = ""
    started = False
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.rstrip("\n")
        match = URI_RE.search(text) or TARGET_RE.search(text)
        if match:
            endpoint = match.group(1)
        match = re.match(r"^\s*Parameter:\s*(\S+)", text, re.IGNORECASE)
        if match:
            if param and (technique or payload):
                out.append(
                    candidate(
                        raw_type="sqli",
                        endpoint=endpoint,
                        param=param,
                        evidence=f"{param}: {technique or title or 'SQL injection'}",
                        tool=NAME,
                        severity="high",
                        confidence="high",
                        reproduction=payload,
                        title=title or "SQL injection",
                    )
                )
            param, technique, title, payload, started = match.group(1), "", "", "", True
        match = re.match(r"^\s*Type:\s*(.+)$", text, re.IGNORECASE)
        if match:
            technique = match.group(1).strip()
        match = re.match(r"^\s*Title:\s*(.+)$", text, re.IGNORECASE)
        if match:
            title = match.group(1).strip()
        match = re.match(r"^\s*Payload:\s*(.+)$", text, re.IGNORECASE)
        if match:
            payload = match.group(1).strip()
        if len(out) >= limits.max_candidates:
            partial = True
            break
    if started and param and (technique or payload) and len(out) < limits.max_candidates:
        out.append(
            candidate(
                raw_type="sqli",
                endpoint=endpoint,
                param=param,
                evidence=f"{param}: {technique or title or 'SQL injection'}",
                tool=NAME,
                severity="high",
                confidence="high",
                reproduction=payload,
                title=title or "SQL injection",
            )
        )
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
