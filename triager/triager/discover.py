"""Phase 1 — subdomain discovery, file inventory and streaming parsing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import parsers
from .budget import BudgetExceeded
from .normalize import normalize_batch
from .parsers.base import ParseLimits
from .state import atomic_write_text, utcnow

MAX_ENTRIES = 5000
MAX_DEPTH = 5
FQDN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z]{2,24})\b", re.IGNORECASE)
STRUCTURED_HOST_RE = re.compile(r'"(?:host|url|target|input)"\s*:\s*"((?:https?://)?([^"/\s]+))"', re.IGNORECASE)

# Names that are output artifacts or tool folders, never subdomains.
RESERVED_NAMES = {
    "state.json",
    "index.md",
    "recon.md",
    "findings.md",
    "_analysis",
    "_policy",
    "opencode",
    "hunter",
    "triager",
    "subfinder",
    "nuclei",
    "httpx",
    "ffuf",
    "logs",
    "workspace",
    "artifacts",
    "normalize",
    "unassigned",
}
FILE_EXTENSIONS = {
    "json", "jsonl", "md", "txt", "log", "xml", "csv", "tsv", "yaml", "yml", "html", "htm",
    "js", "mjs", "css", "map", "zip", "tar", "gz", "tgz", "bz2", "xz", "pdf", "png", "jpg",
    "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "lock", "toml", "ini", "cfg", "conf",
    "bak", "tmp", "py", "sh", "sql", "db", "har", "sarif", "ndjson",
}
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def looks_like_sub(name: str) -> bool:
    """True only for names that can plausibly be a hostname/FQDN."""
    value = (name or "").strip().lower().rstrip(".")
    if not value or value in RESERVED_NAMES:
        return False
    if len(value) > 253 or ".." in value or "/" in value or "\\" in value:
        return False
    if any(ch.isspace() for ch in value):
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if labels[-1] in FILE_EXTENSIONS:
        return False
    for label in labels:
        if not label or "_" in label:
            return False
        if re.fullmatch(r"[a-z]{2,24}", label):
            continue
        if not HOST_LABEL_RE.match(label):
            return False
    return True


def safe_name(name: str) -> str:
    return name if looks_like_sub(name) else "unassigned"


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def list_files(outputs: Path, out_dir: Path, limit: int = MAX_ENTRIES) -> tuple[list[dict], bool]:
    files: list[dict] = []
    truncated = False
    base_depth = len(outputs.resolve().parts)
    for root, dirs, names in os.walk(outputs):
        root_path = Path(root)
        depth = len(root_path.resolve().parts) - base_depth
        if depth >= MAX_DEPTH:
            dirs[:] = []
        dirs[:] = [name for name in dirs if not name.startswith(".") and not _is_within(root_path / name, out_dir)]
        for name in names:
            path = root_path / name
            if _is_within(path, out_dir):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            files.append(
                {
                    "path": str(path),
                    "rel": str(path.relative_to(outputs)),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                }
            )
            if len(files) >= limit:
                truncated = True
                break
        if truncated:
            break
    return files, truncated


def infer_from_name(rel: str) -> str:
    name = os.path.basename(rel)
    matches = FQDN_RE.findall(name)
    for match in matches:
        candidate = match[0] if isinstance(match, tuple) else match
        if candidate and looks_like_sub(candidate):
            return candidate.lower()
    return ""


def infer_from_head(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            head = handle.read(8192).decode("utf-8", "replace")
    except OSError:
        return ""
    match = STRUCTURED_HOST_RE.search(head)
    if match:
        value = match.group(1)
        if "://" in value:
            try:
                return (urlsplit(value).hostname or "").lower()
            except ValueError:
                return ""
        return value.lower()
    matches = FQDN_RE.findall(head)
    if matches:
        counts: dict[str, int] = {}
        for match in matches[:200]:
            value = match[0] if isinstance(match, tuple) else match
            value = value.lower()
            if not value.endswith((".invalid", ".local", ".localhost", ".internal")) and looks_like_sub(value):
                counts[value] = counts.get(value, 0) + 1
        if counts:
            return max(counts, key=counts.get)
    return ""


def attribute_files(files: list[dict], split_dir: bool, allowed_hosts: set[str] | None = None) -> tuple[dict[str, list[dict]], str]:
    """Return sub -> files plus the heuristic description.

    Only plausible hostnames are accepted as subdomains.  Output artifacts
    (``state.json``, ``INDEX.md``), tool folders (``triager``, ``subfinder``)
    and anything else that is not a hostname go to ``unassigned`` and never get
    their own folder.
    """
    allowed_hosts = {host.lower() for host in (allowed_hosts or set())}
    first_level = set()
    for item in files:
        parts = Path(item["rel"]).parts
        if len(parts) > 1:
            first_level.add(parts[0])
    split_candidates = {name for name in first_level if looks_like_sub(name) or name.lower() in allowed_hosts}
    looks_split = bool(split_candidates)
    use_split = bool(split_dir or (split_dir is None and looks_split))
    grouped: dict[str, list[dict]] = {}
    if use_split and split_candidates:
        heuristic = "--split-dir: subpasta de 1º nível" if split_dir else "auto: subpasta de 1º nível com FQDN (confiança alta)"
        for item in files:
            parts = Path(item["rel"]).parts
            if len(parts) > 1:
                name = parts[0].lower()
                if name in split_candidates:
                    sub = name
                elif name.lower() in allowed_hosts:
                    sub = name.lower()
                else:
                    sub = "unassigned"
            else:
                sub = infer_from_name(item["rel"]) or infer_from_head(item["path"]) or "unassigned"
                if sub != "unassigned" and not (looks_like_sub(sub) or sub in allowed_hosts):
                    sub = "unassigned"
            grouped.setdefault(sub, []).append(item)
        return grouped, heuristic

    heuristic = "inferência por nome de arquivo/campo estruturado/frequência de FQDN (confiança média)"
    for item in files:
        sub = infer_from_name(item["rel"]) or infer_from_head(item["path"]) or "unassigned"
        if sub != "unassigned" and not (looks_like_sub(sub) or sub in allowed_hosts):
            sub = "unassigned"
        grouped.setdefault(sub, []).append(item)
    return grouped, heuristic


def _rewrite_endpoint(endpoint: str, scope) -> str:
    if not scope or not endpoint:
        return endpoint
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return endpoint
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return endpoint
    if parts.hostname.lower().rstrip(".") != scope.host:
        return endpoint
    return urlunsplit((scope.scheme, scope.target.host if scope.port in (80, 443) else f"{scope.host}:{scope.port}", parts.path or "/", parts.query, ""))


def _enrich(candidates: list[dict], scope) -> None:
    # limite: candidatas por lote de arquivo.
    for item in candidates:
        item["endpoint"] = _rewrite_endpoint(item.get("endpoint", ""), scope)


def process_file(ctx, sub: str, item: dict, file_max_seconds: float, file_max_mb: float) -> dict:
    state = ctx.subs[sub]
    rel = item["rel"]
    previous = state["files"].get(rel, {})
    if ctx.resume and previous.get("status") == "done":
        return previous
    start_offset = int(previous.get("offset", 0)) if ctx.resume and previous.get("status") == "partial" else 0
    head = parsers.read_head(item["path"]).decode("utf-8", "replace")
    module = parsers.detect(item["path"], head)
    tool = str(module.NAME)
    limits = ParseLimits(
        max_seconds=file_max_seconds,
        start_offset=start_offset,
        max_bytes=max(1024, int(file_max_mb * 1024 * 1024)),
    )
    started = time.monotonic()
    status = "done"
    reason = ""
    candidates: list[dict] = []
    offset = start_offset
    try:
        result = module.parse(item["path"], limits)
        candidates = result.candidates
        offset = result.offset or item["size"]
        if result.partial:
            status = "partial"
            reason = result.reason or "parcial"
    except BudgetExceeded as exc:
        status = "partial"
        reason = str(exc)
    except Exception as exc:
        status = "error"
        reason = f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - started
    if elapsed > file_max_seconds:
        status = "partial"
        reason = reason or "timeout de arquivo"

    scope = ctx.scopes.get(sub)
    _enrich(candidates, scope)
    store = ctx.candidate_store.setdefault(sub, {})
    before = len(store)
    merged, _added = normalize_batch(candidates, sub, sub, store)
    ctx.subs[sub]["candidates"] = merged

    normalize_path = ctx.normalize_dir(sub) / f"{tool.replace('/', '_')}_{hashlib.sha1(rel.encode()).hexdigest()[:8]}.json"
    try:
        atomic_write_text(normalize_path, json.dumps(candidates, indent=2, ensure_ascii=False) + "\n")
    except OSError:
        pass

    entry = {
        "rel": rel,
        "path": item["path"],
        "tool": tool,
        "size": item["size"],
        "mtime": item["mtime"],
        "status": status,
        "offset": int(offset),
        "bytes_read": int(offset),
        "candidates": len(candidates),
        "new_candidates": len(store) - before,
        "reason": reason,
        "seconds": round(elapsed, 3),
        "processed_utc": utcnow(),
    }
    state["files"][rel] = entry
    return entry


def run_inventory(ctx, sub: str, files: list[dict]) -> None:
    state = ctx.subs[sub]
    phase = state["phases"]["inventory"]
    phase["status"] = "running"
    phase["started_utc"] = phase.get("started_utc") or utcnow()
    ctx.budget.mark_phase("inventory")
    ordered = sorted(files, key=lambda item: (parsers.TOOL_PRIORITY.get(parsers.tool_name(item["path"]), 999), -item["size"]))
    # limite: arquivos do subdomínio (máx. 5000 no inventário).
    for item in ordered[:MAX_ENTRIES]:
        try:
            ctx.budget.check_phase("inventory")
        except BudgetExceeded as exc:
            ctx.add_skip(sub, "inventory", str(exc))
            phase["status"] = "partial"
            break
        try:
            process_file(ctx, sub, item, float(ctx.args.file_max_seconds), float(ctx.args.file_max_mb))
            phase["status"] = "running"
        except Exception as exc:  # a file never aborts the run
            state["files"][item["rel"]] = {
                "rel": item["rel"],
                "path": item["path"],
                "tool": "unknown",
                "size": item["size"],
                "mtime": item["mtime"],
                "status": "error",
                "offset": 0,
                "bytes_read": 0,
                "candidates": 0,
                "new_candidates": 0,
                "reason": f"{type(exc).__name__}: {exc}",
                "processed_utc": utcnow(),
            }
            ctx.logger(sub).warning("arquivo %s falhou: %s", item["rel"], exc)
        ctx.flush(sub)
    if phase["status"] != "partial":
        phase["status"] = "done"
    phase["finished_utc"] = utcnow()
    ctx.flush(sub)
