"""OWASP ZAP JSON/XML parser."""

from __future__ import annotations

import json
import os
import time
import xml.etree.ElementTree as ET

from .base import ParseLimits, ParseResult, candidate, derive_param, severity_name, type_from_text

NAME = "ZAP"
PRIORITY = 40


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if '"site"' in low and '"alerts"' in low:
        return True
    return "<OWASPZAPReport" in low or "<alertitem>" in low


def parse(path: str, limits: ParseLimits) -> ParseResult:
    size = os.path.getsize(path)
    head = open(path, "rb").read(4096).decode("utf-8", "replace")
    if "<OWASPZAPReport" in head or "<alertitem>" in head:
        return _parse_xml(path, limits)
    if size > limits.max_bytes:
        return ParseResult([], limits.start_offset, 0, True, "tamanho: ZAP JSON acima do limite")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return ParseResult([], limits.start_offset, 0, True, "formato: JSON inválido")
    out = []
    # limite: até limite.max_candidates instâncias.
    for site in (data.get("site") or [])[:200]:
        for alert in (site.get("alerts") or [])[:200]:
            title = str(alert.get("alert") or alert.get("name") or "ZAP alert")
            severity = severity_name(alert.get("riskdesc") or alert.get("riskcode"))
            for instance in (alert.get("instances") or [])[:200]:
                uri = str(instance.get("uri") or instance.get("url") or "")
                if not uri:
                    continue
                out.append(
                    candidate(
                        raw_type=type_from_text(f"{title} {alert.get('desc', '')}"),
                        endpoint=uri,
                        method=str(instance.get("method") or "GET"),
                        param=str(instance.get("param") or derive_param(uri)),
                        evidence=f"ZAP: {title} | {alert.get('riskdesc', '')}",
                        tool=NAME,
                        severity=severity,
                        confidence="medium",
                        reproduction=str(alert.get("solution") or "")[:800],
                        title=title[:160],
                    )
                )
                if len(out) >= limits.max_candidates:
                    return ParseResult(out, limits.start_offset, size, True, "limite de candidatas")
    return ParseResult(out, limits.start_offset, size, False, "")


def _parse_xml(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    started = time.monotonic()
    timed_out = False
    try:
        # limite: até limite.max_candidates alertas XML.
        for _event, element in ET.iterparse(path, events=("end",)):
            # limite: tempo por arquivo e limite.max_candidates.
            if time.monotonic() - started > limits.max_seconds:
                timed_out = True
                break
            if element.tag.split("}")[-1] != "alertitem":
                continue
            fields = {child.tag.split("}")[-1]: (child.text or "") for child in list(element)}
            title = fields.get("alert") or fields.get("name") or "ZAP alert"
            uri = fields.get("uri") or fields.get("url") or ""
            if not uri:
                element.clear()
                continue
            out.append(
                candidate(
                    raw_type=type_from_text(f"{title} {fields.get('desc', '')}"),
                    endpoint=uri,
                    method=fields.get("method") or "GET",
                    param=fields.get("param") or derive_param(uri),
                    evidence=f"ZAP XML: {title} | {fields.get('riskdesc', '')}",
                    tool=NAME,
                    severity=severity_name(fields.get("riskdesc")),
                    confidence="medium",
                    reproduction=fields.get("solution", "")[:800],
                    title=title[:160],
                )
            )
            element.clear()
            if len(out) >= limits.max_candidates:
                break
    except (OSError, ET.ParseError):
        return ParseResult(out, limits.start_offset, 0, True, "formato: XML inválido/parcial")
    return ParseResult(out, limits.start_offset, 0, timed_out, "timeout de arquivo" if timed_out else "")
