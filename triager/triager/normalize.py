"""Candidate model, normalisation, deduplication, correlation and scoring."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

CANONICAL_TYPES = {
    "sqli",
    "xss",
    "ssrf",
    "lfi",
    "rfi",
    "rce",
    "open_redirect",
    "idor",
    "cors",
    "csrf",
    "ssti",
    "xxe",
    "nosqli",
    "takeover",
    "graphql",
    "secret",
    "endpoint_internal",
    "headers",
    "tech",
    "misconfig",
    "other",
}

ACTIVE_TYPES = {
    "sqli",
    "xss",
    "ssrf",
    "lfi",
    "rfi",
    "rce",
    "open_redirect",
    "idor",
    "cors",
    "csrf",
    "ssti",
    "xxe",
    "nosqli",
    "graphql",
}

DEFAULT_SEVERITY = {
    "sqli": "high",
    "rce": "critical",
    "xxe": "high",
    "ssti": "high",
    "ssrf": "high",
    "lfi": "high",
    "rfi": "high",
    "xss": "medium",
    "idor": "medium",
    "nosqli": "medium",
    "open_redirect": "medium",
    "cors": "medium",
    "csrf": "medium",
    "graphql": "low",
    "takeover": "high",
    "secret": "high",
    "headers": "low",
    "tech": "low",
    "misconfig": "low",
    "endpoint_internal": "info",
    "other": "low",
}

SEVERITY_POINTS = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0, "": 0}
CONFIDENCE_POINTS = {"high": 3, "medium": 2, "low": 1, "": 1}


def normalize_type(raw_type: str) -> str:
    value = (raw_type or "").strip().lower()
    value = value.replace("-", "_").replace(" ", "_")
    aliases = {
        "sql_injection": "sqli",
        "sqlinjection": "sqli",
        "cross_site_scripting": "xss",
        "cross_site_request_forgery": "csrf",
        "openredirect": "open_redirect",
        "redirect": "open_redirect",
        "path_traversal": "lfi",
        "directory_traversal": "lfi",
        "file_inclusion": "lfi",
        "command_injection": "rce",
        "remote_code_execution": "rce",
        "insecure_direct_object_reference": "idor",
        "bola": "idor",
        "server_side_request_forgery": "ssrf",
        "xml_external_entity": "xxe",
        "nosql_injection": "nosqli",
        "subdomain_takeover": "takeover",
        "endpoint": "endpoint_internal",
        "credentials": "secret",
        "credential": "secret",
        "secrets": "secret",
        "missing_headers": "headers",
        "security_headers": "headers",
        "version": "tech",
        "technology": "tech",
        "misconfiguration": "misconfig",
    }
    value = aliases.get(value, value)
    return value if value in CANONICAL_TYPES else "other"


def normalize_path(path: str) -> str:
    path = path or "/"
    path = re.sub(r"/+", "/", path)
    if path != "/":
        path = path.rstrip("/")
    return path.lower()


def _host_from_endpoint(endpoint: str) -> tuple[str, str]:
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return "", ""
    if endpoint.startswith("//"):
        endpoint = "https:" + endpoint
    if "://" in endpoint:
        try:
            parts = urlsplit(endpoint)
            if parts.scheme in ("http", "https") and parts.hostname:
                return parts.hostname.lower().rstrip("."), endpoint
        except ValueError:
            pass
    return "", endpoint


def _path_from_endpoint(endpoint: str) -> str:
    try:
        parts = urlsplit(endpoint if "://" in endpoint else "http://placeholder" + (endpoint if endpoint.startswith("/") else "/" + endpoint))
        return parts.path or "/"
    except ValueError:
        return "/"


@dataclass
class Candidate:
    sub: str
    raw_type: str
    endpoint: str
    method: str = "GET"
    param: str = ""
    evidence: str = ""
    tool_origin: str = ""
    severity_declared: str = ""
    confidence_declared: str = ""
    reproduction: str = ""
    title: str = ""
    host: str = ""
    sources: list[str] = field(default_factory=list)
    correlated_with: list[str] = field(default_factory=list)
    score: int = 0
    flag: str = "active"
    status: str = "pending"
    id: str = ""
    type: str = ""
    key: str = ""

    def finalize(self, default_host: str = "") -> "Candidate":
        self.type = normalize_type(self.raw_type)
        endpoint = (self.endpoint or "").strip()
        host, as_url = _host_from_endpoint(endpoint)
        if not host and default_host:
            host = default_host
        if endpoint and not as_url:
            if endpoint.startswith("/"):
                endpoint = f"http://{host}{endpoint}" if host else endpoint
            elif re.match(r"^[A-Za-z0-9._-]+:\d+", endpoint) and host:
                endpoint = f"http://{endpoint}"
        self.endpoint = endpoint
        self.host = (host or default_host or "").lower().rstrip(".")
        path = normalize_path(_path_from_endpoint(endpoint)) if endpoint else "/"
        self.key = f"{self.host}|{path}|{self.method.upper()}|{self.param.lower()}|{self.type}"
        self.id = "C-" + hashlib.sha1(self.key.encode("utf-8")).hexdigest()[:10]
        if not self.sources:
            self.sources = [self.tool_origin] if self.tool_origin else []
        if not self.severity_declared:
            self.severity_declared = DEFAULT_SEVERITY.get(self.type, "low")
        self.score = score_candidate(self.type, self.severity_declared, self.confidence_declared)
        return self

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "sub": self.sub,
            "type": self.type,
            "raw_type": self.raw_type,
            "endpoint": self.endpoint,
            "host": self.host,
            "method": self.method,
            "param": self.param,
            "evidence": self.evidence,
            "tool_origin": self.tool_origin,
            "severity_declared": self.severity_declared,
            "confidence_declared": self.confidence_declared,
            "reproduction": self.reproduction,
            "title": self.title,
            "sources": self.sources,
            "correlated_with": self.correlated_with,
            "score": self.score,
            "flag": self.flag,
            "status": self.status,
        }


def score_candidate(canonical_type: str, severity: str, confidence: str) -> int:
    sev = SEVERITY_POINTS.get((severity or "").lower(), 0)
    conf = CONFIDENCE_POINTS.get((confidence or "").lower(), 1)
    if canonical_type in ACTIVE_TYPES:
        ease = 5
    elif canonical_type == "endpoint_internal":
        ease = 2
    elif canonical_type == "secret":
        ease = -10
    elif canonical_type in ("headers", "tech"):
        ease = -5
    elif canonical_type == "misconfig":
        ease = -2
    else:
        ease = 0
    return sev * 10 + conf * 5 + ease


def merge_candidate(existing: dict, incoming: Candidate) -> dict:
    """Dedup keep-highest severity, list every source."""
    existing_sources = set(existing.get("sources") or [])
    if incoming.tool_origin:
        existing_sources.add(incoming.tool_origin)
    existing["sources"] = sorted(existing_sources)
    if SEVERITY_POINTS.get(incoming.severity_declared, 0) > SEVERITY_POINTS.get(existing.get("severity_declared", ""), 0):
        existing["severity_declared"] = incoming.severity_declared
        existing["score"] = max(existing.get("score", 0), incoming.score)
    if len(incoming.evidence) > len(existing.get("evidence", "")):
        existing["evidence"] = incoming.evidence
    if not existing.get("reproduction") and incoming.reproduction:
        existing["reproduction"] = incoming.reproduction
    return existing


def correlate(candidates: list[dict]) -> None:
    by_path: dict[tuple[str, str], list[dict]] = {}
    for item in candidates:
        path = normalize_path(_path_from_endpoint(item.get("endpoint", "")))
        by_path.setdefault((item.get("host", ""), path), []).append(item)
    # limite: pares de candidatas do mesmo path.
    for (_host, _path), group in by_path.items():
        if len(group) < 2:
            continue
        for item in group:
            others = [other["id"] for other in group if other["id"] != item["id"]]
            if others:
                merged = sorted(set(item.get("correlated_with") or []) | set(others))
                item["correlated_with"] = merged[:20]
    # tech/version + nuclei (same host) correlation
    by_host: dict[str, list[dict]] = {}
    for item in candidates:
        by_host.setdefault(item.get("host", ""), []).append(item)
    # limite: hosts encontrados nos outputs.
    for _host, group in by_host.items():
        tech = [item for item in group if item.get("type") == "tech"]
        vulns = [item for item in group if item.get("type") in ACTIVE_TYPES]
        for tech_item in tech[:20]:
            for vuln in vulns[:20]:
                if tech_item["id"] != vuln["id"]:
                    vuln.setdefault("correlated_with", [])
                    if tech_item["id"] not in vuln["correlated_with"]:
                        vuln["correlated_with"].append(tech_item["id"])
    # secret + leaked endpoint correlation by evidence text
    secrets = [item for item in candidates if item.get("type") == "secret"]
    endpoints = [item for item in candidates if item.get("type") == "endpoint_internal"]
    # limite: 50 segredos x 50 endpoints.
    for secret in secrets[:50]:
        needle = (secret.get("evidence") or "")[:40]
        for endpoint in endpoints[:50]:
            if needle and needle in (endpoint.get("evidence") or ""):
                secret.setdefault("correlated_with", [])
                if endpoint["id"] not in secret["correlated_with"]:
                    secret["correlated_with"].append(endpoint["id"])


def normalize_batch(raws: list[dict], sub: str, default_host: str, store: dict[str, dict]) -> tuple[list[dict], int]:
    """Normalise and merge a batch into ``store`` keyed by candidate key."""
    added = 0
    for raw in raws:
        item = Candidate(
            sub=sub,
            raw_type=raw.get("raw_type", "other"),
            endpoint=raw.get("endpoint", ""),
            method=raw.get("method", "GET"),
            param=raw.get("param", ""),
            evidence=raw.get("evidence", ""),
            tool_origin=raw.get("tool", ""),
            severity_declared=raw.get("severity", ""),
            confidence_declared=raw.get("confidence", ""),
            reproduction=raw.get("reproduction", ""),
            title=raw.get("title", ""),
            host=raw.get("host", ""),
        ).finalize(default_host)
        if item.type == "secret":
            item.key = f"secret|{item.tool_origin}|{item.title}|{item.evidence[:120]}"
            item.id = "C-" + hashlib.sha1(item.key.encode("utf-8")).hexdigest()[:10]
            if not item.endpoint:
                item.endpoint = f"secret://{item.tool_origin or 'unknown'}/{item.id}"
        existing = store.get(item.key)
        if existing:
            merge_candidate(existing, item)
        else:
            store[item.key] = item.to_dict()
            added += 1
    candidates = list(store.values())
    correlate(candidates)
    return candidates, added
