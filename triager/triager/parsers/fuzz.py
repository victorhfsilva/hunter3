"""ffuf / gobuster / feroxbuster parser."""

from __future__ import annotations

import csv
import json
import os
import re
import shlex

from .base import ParseLimits, ParseResult, candidate, iter_lines, safe_json

NAME = "ffuf/gobuster/feroxbuster"
PRIORITY = 70
GOBUSTER_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d{3})\)")
FFUF_TEXT_RE = re.compile(r"^(\S+)\s+\[Status:\s*(\d{3})")


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if '"results"' in low and ('"input"' in low or '"ffuf"' in low or '"url"' in low):
        return True
    if '"type":"response"' in low or '"type": "response"' in low:
        return True
    if "gobuster" in low.lower() or "feroxbuster" in low.lower():
        return True
    first = low.strip().splitlines()[0] if low.strip() else ""
    if first.lower().startswith("status,") or first.lower().startswith("status\t"):
        return True
    return bool(GOBUSTER_RE.search(low) or FFUF_TEXT_RE.search(low))


def _base_from_name(path: str) -> str:
    base = os.path.basename(path)
    match = re.search(r"(https?://[A-Za-z0-9._:\-]+)", base)
    return match.group(1) if match else ""


def parse(path: str, limits: ParseLimits) -> ParseResult:
    head = open(path, "rb").read(4096).decode("utf-8", "replace")
    stripped = head.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return _parse_json(path, limits)
    if "status,length" in head.lower() or "status\tlength" in head.lower():
        return _parse_csv(path, limits)
    return _parse_text(path, limits)


def _parse_json(path: str, limits: ParseLimits) -> ParseResult:
    size = os.path.getsize(path)
    out = []
    last_offset = limits.start_offset
    lines = [line for line in head_lines(path, 5)]
    if lines and lines[0].lstrip().startswith("{"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
        except (OSError, ValueError, json.JSONDecodeError):
            return _parse_jsonl(path, limits)
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            # limite: até limite.max_candidates resultados ffuf.
            for item in data["results"][: limits.max_candidates]:
                url = str(item.get("url") or "")
                status = item.get("status")
                out.append(
                    candidate(
                        raw_type="endpoint_internal",
                        endpoint=url,
                        param=str(item.get("input", {}).get("FUZZ", "")) if isinstance(item.get("input"), dict) else "",
                        evidence=f"ffuf: {url} status={status} length={item.get('length')}",
                        tool=NAME,
                        severity="info",
                        confidence="medium",
                        title=f"ffuf {status}",
                    )
                )
            return ParseResult(out, limits.start_offset, size, False, "")
    return _parse_jsonl(path, limits)


def _parse_jsonl(path: str, limits: ParseLimits) -> ParseResult:
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
        url = str(obj.get("url") or obj.get("path") or "")
        if not url:
            continue
        out.append(
            candidate(
                raw_type="endpoint_internal",
                endpoint=url,
                evidence=f"fuzz: {url} status={obj.get('status') or obj.get('status_code')}",
                tool=NAME,
                severity="info",
                confidence="medium",
                title=str(obj.get("type") or "fuzz result"),
            )
        )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")


def _parse_csv(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    base = _base_from_name(path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            # limite: até limite.max_candidates linhas CSV.
            for index, row in enumerate(reader):
                if index >= limits.max_candidates:
                    break
                url = row.get("Url") or row.get("url") or row.get("Path") or row.get("path") or ""
                if not url:
                    continue
                if base and url.startswith("/"):
                    url = base.rstrip("/") + url
                out.append(
                    candidate(
                        raw_type="endpoint_internal",
                        endpoint=url,
                        evidence=f"fuzz CSV: {url} status={row.get('Status') or row.get('status')}",
                        tool=NAME,
                        severity="info",
                        confidence="medium",
                        title="fuzz CSV result",
                    )
                )
    except OSError:
        return ParseResult([], limits.start_offset, 0, True, "ilegível")
    return ParseResult(out, limits.start_offset, 0, False, "")


def _parse_text(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    last_offset = limits.start_offset
    partial = False
    base = _base_from_name(path)
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.strip()
        match = GOBUSTER_RE.match(text) or FFUF_TEXT_RE.match(text)
        if not match:
            continue
        url, status = match.groups()
        if base and url.startswith("/"):
            url = base.rstrip("/") + url
        out.append(
            candidate(
                raw_type="endpoint_internal",
                endpoint=url,
                evidence=text[:300],
                tool=NAME,
                severity="info",
                confidence="medium",
                title=f"fuzz {status}",
            )
        )
        if len(out) >= limits.max_candidates:
            partial = True
            break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")


def head_lines(path: str, count: int) -> list[str]:
    lines = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            # limite: count linhas de cabeçalho.
            for line in handle:
                lines.append(line)
                if len(lines) >= count:
                    break
    except OSError:
        pass
    return lines
