"""semgrep JSON parser."""

from __future__ import annotations

import json
import os

from .base import ParseLimits, ParseResult, candidate, severity_name, type_from_text

NAME = "semgrep"
PRIORITY = 110


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    return '"results"' in low and '"check_id"' in low and '"path"' in low


def parse(path: str, limits: ParseLimits) -> ParseResult:
    size = os.path.getsize(path)
    if size > limits.max_bytes:
        return ParseResult([], limits.start_offset, 0, True, "tamanho: semgrep JSON acima do limite")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return ParseResult([], limits.start_offset, 0, True, "formato: JSON inválido")
    out = []
    # limite: até limite.max_candidates resultados semgrep.
    for result in (data.get("results") or [])[: limits.max_candidates]:
        path_value = str(result.get("path") or "")
        start = result.get("start") or {}
        line = start.get("line")
        check = str(result.get("check_id") or "")
        extra = result.get("extra") or {}
        message = str(extra.get("message") or "")
        severity = severity_name(extra.get("severity"))
        out.append(
            candidate(
                raw_type=type_from_text(f"{check} {message}"),
                endpoint=path_value,
                evidence=f"{path_value}:{line} {message}"[:300],
                tool=NAME,
                severity=severity or "low",
                confidence="high",
                reproduction=f"{check} at {path_value}:{line}",
                title=message[:160] or check[:160],
            )
        )
    return ParseResult(out, limits.start_offset, size, False, "")
