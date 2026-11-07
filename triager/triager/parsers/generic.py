"""Fallback parser: URLs, hosts and endpoint-looking strings from any text."""

from __future__ import annotations

import re

from .base import ParseLimits, ParseResult, candidate, derive_param, iter_lines

NAME = "generic"
PRIORITY = 999
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
PATH_RE = re.compile(r"(?<![\w.])/(?:api|v\d+|graphql|login|signin|signup|auth|user|account|order|billing|invoice|payment|token|password|reset|admin|upload|export|role|settings|checkout)[A-Za-z0-9_\-./?=&%]*", re.IGNORECASE)
HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z]{2,24}\b", re.IGNORECASE)


def sniff(path: str, head: str) -> bool:
    return True


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    seen = set()
    last_offset = limits.start_offset
    partial = False
    for line, offset in iter_lines(path, limits):
        last_offset = offset
        text = line.strip()
        if not text:
            continue
        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(".,;")
            if url in seen:
                continue
            seen.add(url)
            out.append(
                candidate(
                    raw_type="endpoint_internal",
                    endpoint=url,
                    param=derive_param(url),
                    evidence=text[:300],
                    tool=NAME,
                    severity="info",
                    confidence="low",
                    title="URL extraída de texto genérico",
                )
            )
            if len(out) >= limits.max_candidates:
                partial = True
                break
        if partial:
            break
        for match in PATH_RE.finditer(text):
            path_value = match.group(0).rstrip(".,;")
            if path_value in seen:
                continue
            seen.add(path_value)
            out.append(
                candidate(
                    raw_type="endpoint_internal",
                    endpoint=path_value,
                    param=derive_param(path_value),
                    evidence=text[:300],
                    tool=NAME,
                    severity="info",
                    confidence="low",
                    title="Path extraído de texto genérico",
                )
            )
            if len(out) >= limits.max_candidates:
                partial = True
                break
    return ParseResult(out, last_offset, last_offset, partial, "limite de candidatas" if partial else "")
