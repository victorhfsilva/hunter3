"""Burp Suite XML/HAR parser."""

from __future__ import annotations

import json
import os
import time
import xml.etree.ElementTree as ET

from .base import ParseLimits, ParseResult, candidate, derive_param, severity_name, type_from_text

NAME = "Burp"
PRIORITY = 30


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if "<issues" in low or "<issue>" in low or "<issue " in low:
        return True
    return '"log"' in low and '"entries"' in low and '"request"' in low


def _url_from_host_path(host: str, path: str, location: str) -> str:
    if location.startswith("http"):
        return location
    if host and not host.startswith("http"):
        host = "https://" + host
    return (host.rstrip("/") + "/" + path.lstrip("/")).strip()


def _parse_har(path: str, limits: ParseLimits) -> ParseResult:
    size = os.path.getsize(path)
    if size > limits.max_bytes:
        return ParseResult([], limits.start_offset, 0, True, "tamanho: HAR acima do limite para carga única")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return ParseResult([], limits.start_offset, 0, True, "formato: HAR inválido")
    out = []
    entries = (((data or {}).get("log") or {}).get("entries") or [])[: limits.max_candidates]
    # limite: até limite.max_candidates entradas HAR.
    for entry in entries:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = str(request.get("url") or "")
        if not url:
            continue
        method = str(request.get("method") or "GET")
        status = response.get("status")
        mime = str((response.get("content") or {}).get("mimeType") or "")
        out.append(
            candidate(
                raw_type="endpoint_internal",
                endpoint=url,
                method=method,
                param=derive_param(url),
                evidence=f"HAR {method} {url} status={status} mime={mime}",
                tool=NAME,
                severity="info",
                confidence="medium",
                reproduction=f"{method} {url}",
                title=f"HAR entry {status}",
            )
        )
    return ParseResult(out, limits.start_offset, size, False, "")


def _parse_xml(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    offset = limits.start_offset
    started = time.monotonic()
    timed_out = False
    try:
        # limite: iterparse incremental; profundidade implícita do ElementTree.
        for _event, element in ET.iterparse(path, events=("end",)):
            # limite: tempo por arquivo e limite.max_candidates.
            if time.monotonic() - started > limits.max_seconds:
                timed_out = True
                break
            if element.tag.split("}")[-1] not in ("issue", "issueitem"):
                continue
            fields = {child.tag.split("}")[-1]: (child.text or "") for child in list(element)}
            name = fields.get("name") or fields.get("type") or "Burp issue"
            host = fields.get("host") or ""
            path_value = fields.get("path") or fields.get("location") or ""
            location = fields.get("location") or ""
            endpoint = _url_from_host_path(host, path_value, location)
            out.append(
                candidate(
                    raw_type=type_from_text(f"{name} {fields.get('issueBackground', '')}"),
                    endpoint=endpoint,
                    method="GET",
                    param=derive_param(endpoint),
                    evidence=f"Burp: {name} | {fields.get('severity', '')} | {fields.get('confidence', '')}",
                    tool=NAME,
                    severity=severity_name(fields.get("severity")),
                    confidence=fields.get("confidence", ""),
                    reproduction=fields.get("issueDetail", "")[:800],
                    title=name[:160],
                )
            )
            element.clear()
            if len(out) >= limits.max_candidates:
                break
    except (OSError, ET.ParseError):
        return ParseResult(out, offset, offset, True, "formato: XML inválido/parcial")
    return ParseResult(out, offset, offset, timed_out, "timeout de arquivo" if timed_out else "")


def parse(path: str, limits: ParseLimits) -> ParseResult:
    head = open(path, "rb").read(4096).decode("utf-8", "replace")
    if '"log"' in head and '"entries"' in head:
        return _parse_har(path, limits)
    return _parse_xml(path, limits)
