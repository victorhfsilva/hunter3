"""WPScan JSON parser."""

from __future__ import annotations

import json
import os

from .base import ParseLimits, ParseResult, candidate, type_from_text

NAME = "WPScan"
PRIORITY = 60


def sniff(path: str, head: str) -> bool:
    low = head[:6000]
    if '"vulnerabilities"' in low and ('"wordpress"' in low or '"version"' in low or '"plugins"' in low):
        return True
    return '"wpscan"' in low.lower() and '"target"' in low


def _severity_from(cvss) -> str:
    try:
        value = float(cvss)
    except (TypeError, ValueError):
        return "medium"
    if value >= 9:
        return "critical"
    if value >= 7:
        return "high"
    if value >= 4:
        return "medium"
    return "low"


def parse(path: str, limits: ParseLimits) -> ParseResult:
    size = os.path.getsize(path)
    if size > limits.max_bytes:
        return ParseResult([], limits.start_offset, 0, True, "tamanho: WPScan JSON acima do limite")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return ParseResult([], limits.start_offset, 0, True, "formato: JSON inválido")
    endpoint = str(data.get("target_url") or data.get("target") or "")
    out = []
    version = data.get("version") or {}
    if isinstance(version, dict) and version.get("number"):
        out.append(
            candidate(
                raw_type="tech",
                endpoint=endpoint,
                evidence=f"WPScan versão WordPress {version.get('number')} status={version.get('status')}",
                tool=NAME,
                severity="low",
                confidence="high",
                title=f"WordPress {version.get('number')}",
            )
        )
    # limite: até limite.max_candidates vulnerabilidades.
    for vuln in (data.get("vulnerabilities") or [])[: limits.max_candidates]:
        title = str(vuln.get("title") or vuln.get("name") or "WordPress vulnerability")
        out.append(
            candidate(
                raw_type=type_from_text(title),
                endpoint=endpoint,
                evidence=f"WPScan: {title} | CVE={vuln.get('cve') or vuln.get('references', {}).get('cve', '')}",
                tool=NAME,
                severity=_severity_from(vuln.get("cvss", {}).get("score") if isinstance(vuln.get("cvss"), dict) else vuln.get("cvss")),
                confidence="medium",
                reproduction=json.dumps(vuln, ensure_ascii=False)[:800],
                title=title[:160],
            )
        )
    return ParseResult(out, limits.start_offset, size, False, "")
