"""trufflehog / gitleaks secret parser.

Secrets are always truncated and never used or validated.
"""

from __future__ import annotations

import json
import os

from .base import ParseLimits, ParseResult, candidate, iter_lines, safe_json

NAME = "trufflehog/gitleaks"
PRIORITY = 120


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if '"DetectorName"' in low or '"Raw"' in low and '"SourceMetadata"' in low:
        return True
    return ('"RuleID"' in low or '"rule_id"' in low) and ('"Secret"' in low or '"Match"' in low or '"Raw"' in low)


def truncate(secret: str) -> str:
    secret = str(secret or "")
    if len(secret) <= 12:
        return secret[:4] + "***"
    return f"{secret[:8]}...{secret[-4:]}"


def parse(path: str, limits: ParseLimits) -> ParseResult:
    size = os.path.getsize(path)
    head = open(path, "rb").read(4096).decode("utf-8", "replace").lstrip()
    items = []
    if head.startswith("{") and size <= limits.max_bytes:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
            items = data if isinstance(data, list) else [data]
        except (OSError, ValueError):
            items = []
    out = []
    if items:
        # limite: até limite.max_candidates segredos.
        for item in items[: limits.max_candidates]:
            out.extend(_convert(item))
    else:
        last_offset = limits.start_offset
        partial = False
        for line, offset in iter_lines(path, limits):
            last_offset = offset
            text = line.strip()
            if not text:
                continue
            obj = safe_json(text)
            if isinstance(obj, dict):
                out.extend(_convert(obj))
            if len(out) >= limits.max_candidates:
                partial = True
                break
        return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
    return ParseResult(out, limits.start_offset, size, False, "")


def _convert(item: dict) -> list[dict]:
    if not isinstance(item, dict):
        return []
    detector = item.get("DetectorName") or item.get("RuleID") or item.get("rule_id") or item.get("DetectorType") or "secret"
    raw = item.get("Raw") or item.get("Secret") or item.get("Match") or item.get("secret") or ""
    source = item.get("SourceMetadata") or item.get("File") or item.get("file") or ""
    if isinstance(source, dict):
        source = source.get("Data", {}).get("Filesystem", {}).get("file") or str(source)[:160]
    line = item.get("StartLine") or item.get("line") or ""
    return [
        candidate(
            raw_type="secret",
            endpoint="",
            evidence=f"{detector} em {source}:{line} valor={truncate(raw)}"[:300],
            tool=NAME,
            severity="high",
            confidence="high",
            reproduction=f"{detector} (valor truncado; não utilizado)",
            title=f"Segredo exposto: {detector}"[:160],
        )
    ]
