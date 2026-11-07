"""Atomic state, resume/merge and the shared run context."""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .scope import Scope, Target, parse_target


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def load_json(path: Path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def save_json(path: Path, data) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n")


def safe_folder(host: str) -> str:
    folder = re.sub(r"[^A-Za-z0-9._-]", "_", host).strip("._")
    return folder or "target"


def new_root_state(run_id: str, targets: list[Target], budget_meta: dict) -> dict:
    return {
        "version": 1,
        "run_id": run_id,
        "started_utc": utcnow(),
        "updated_utc": utcnow(),
        "budget": budget_meta,
        "targets": {
            t.host: {
                "host": t.host,
                "port": t.port,
                "scheme": t.scheme,
                "url": t.url,
                "folder": safe_folder(t.host),
                "status": "pending",
                "requests": 0,
                "findings": 0,
            }
            for t in targets
        },
    }


def new_target_state(target: Target, run_id: str) -> dict:
    now = utcnow()
    return {
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "base_url": target.url,
        "folder": safe_folder(target.host),
        "status": "pending",
        "phases": {
            name: {"status": "pending", "substeps": {}, "started_utc": None, "finished_utc": None}
            for name in ("recon", "ai", "select", "tests", "validate", "report")
        },
        "counters": {
            "requests_total": 0,
            "requests_out_of_scope": 0,
            "requests_by_phase": {},
            "requests_by_endpoint": {},
            "requests_by_class": {},
        },
        "budget_used": {"seconds": 0.0, "requests": 0},
        "recon": {
            "baseline": {},
            "waf": {},
            "graphql": {},
            "api_endpoints": [],
            "js_bundles": [],
            "leak_paths": [],
            "tech": {},
            "secrets": [],
            "login_surfaces": [],
            "accounts": [],
            "forms": [],
            "openapi": {},
            "robots": {},
            "sitemap": {},
            "params": [],
            "notes": [],
            "skipped": [],
            "out_of_scope": [],
            "incidents": [],
        },
        "ai": {
            "enabled": None,
            "provider": "",
            "reason": "",
            "rounds": [],
            "accepted": [],
            "rejected": [],
            "fetched": [],
            "notes": [],
            "stages": {},
        },
        "endpoints": [],
        "findings": [],
        "coverage": [],
        "tested_negative": [],
        "skipped": [],
        "out_of_scope": [],
        "incidents": [],
        "run_id": run_id,
        "started_utc": now,
        "updated_utc": now,
        "last_run_utc": now,
    }


def merge_target(existing: dict | None, fresh: dict) -> dict:
    """Merge a previous target state without deleting reports or findings."""
    if not existing:
        return fresh
    merged = copy.deepcopy(existing)
    merged.setdefault("recon", {})
    merged.setdefault("phases", {})
    for name, phase in fresh.get("phases", {}).items():
        merged["phases"].setdefault(name, phase)
    for key, value in fresh.get("recon", {}).items():
        merged["recon"].setdefault(key, value if not isinstance(value, (list, dict)) else type(value)())
    merged["run_id"] = fresh["run_id"]
    merged["host"] = fresh["host"]
    merged["port"] = fresh["port"]
    merged["scheme"] = fresh["scheme"]
    merged["base_url"] = fresh["base_url"]
    merged["folder"] = fresh["folder"]
    merged["status"] = fresh["status"]
    merged["updated_utc"] = utcnow()
    merged["last_run_utc"] = utcnow()
    # Counters from earlier runs are preserved and later summed by the caller.
    merged.setdefault("ai", fresh.get("ai", {}))
    for key, value in fresh.get("ai", {}).items():
        merged["ai"].setdefault(key, value if not isinstance(value, list) else [])
    merged.setdefault("findings", [])
    merged.setdefault("coverage", [])
    merged.setdefault("endpoints", [])
    merged.setdefault("skipped", [])
    merged.setdefault("out_of_scope", [])
    merged.setdefault("incidents", [])
    merged.setdefault("tested_negative", [])
    return merged


class RunContext:
    def __init__(self, out_dir: Path, args, run_id: str, root: dict, resume: bool):
        self.out = Path(out_dir)
        self.args = args
        self.run_id = run_id
        self.root = root
        self.resume = resume
        self.targets: dict[str, dict] = {}
        self.scopes: dict[str, Scope] = {}
        self.target_objs: dict[str, Target] = {}
        self.lock = threading.RLock()
        self._loggers: dict[str, logging.Logger] = {}
        self.budget = None  # set by orchestrator
        self.watchdog = None
        self.frozen: set[str] = set()
        self.started_monotonic = time.monotonic()

    # ------------------------------------------------------------------ paths
    def target_dir(self, host: str) -> Path:
        folder = self.targets.get(host, {}).get("folder") or safe_folder(host)
        return self.out / folder

    def workspace_dir(self, host: str) -> Path:
        return self.target_dir(host) / "workspace"

    def artifacts_dir(self, host: str) -> Path:
        return self.workspace_dir(host) / "artifacts"

    def log_path(self, host: str) -> Path:
        return self.workspace_dir(host) / "logs" / "hunter.log"

    # ----------------------------------------------------------------- target
    def register(self, target: Target) -> dict:
        host = target.host
        self.target_objs[host] = target
        self.scopes[host] = Scope(target)
        fresh = new_target_state(target, self.run_id)
        state_path = self.workspace_dir(host) / "state.json"
        existing = load_json(state_path, None) if self.out.exists() else None
        if existing and self.resume:
            state = merge_target(existing, fresh)
            state["status"] = existing.get("status", "pending")
            for name, phase in (existing.get("phases") or {}).items():
                if name in state["phases"]:
                    state["phases"][name] = phase
        elif existing:
            state = merge_target(existing, fresh)
        else:
            state = fresh
        self.targets[host] = state
        self.ensure_layout(host)
        return state

    def target_state(self, host: str) -> dict:
        return self.targets[host]

    def ensure_layout(self, host: str) -> None:
        tdir = self.target_dir(host)
        (tdir / "workspace" / "artifacts").mkdir(parents=True, exist_ok=True)
        (tdir / "workspace" / "logs").mkdir(parents=True, exist_ok=True)
        for name in ("RECON.md", "FINDINGS.md"):
            path = tdir / name
            if not path.exists():
                atomic_write_text(path, f"# {name[:-3]} — {host}\n\n_Em execução._\n")

    def logger(self, host: str) -> logging.Logger:
        with self.lock:
            logger = self._loggers.get(host)
            if logger:
                return logger
            logger = logging.getLogger(f"hunter.{safe_folder(host)}.{id(self)}")
            logger.setLevel(logging.DEBUG)
            logger.propagate = False
            try:
                path = self.log_path(host)
                path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(path, encoding="utf-8")
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
                logger.addHandler(file_handler)
            except OSError:
                pass
            if getattr(self.args, "verbose", False):
                stream = logging.StreamHandler()
                stream.setLevel(logging.INFO)
                stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
                logger.addHandler(stream)
            self._loggers[host] = logger
            return logger

    # --------------------------------------------------------------- recording
    def add_endpoint(self, host: str, endpoint: dict) -> None:
        state = self.targets[host]
        key = (endpoint.get("method", "GET").upper(), endpoint.get("url", ""))
        for current in state["recon"]["api_endpoints"]:
            if (current.get("method", "GET").upper(), current.get("url")) == key:
                if endpoint.get("params"):
                    merged = sorted(set(current.get("params", [])) | set(endpoint["params"]))
                    current["params"] = merged
                if endpoint.get("source") and endpoint["source"] not in current.get("source", ""):
                    current["source"] = f"{current.get('source', '')},{endpoint['source']}".strip(",")
                if endpoint.get("ai_classes"):
                    merged_ai = sorted(set(current.get("ai_classes", [])) | set(endpoint["ai_classes"]))
                    current["ai_classes"] = merged_ai
                    current["ai_reason"] = current.get("ai_reason") or endpoint.get("ai_reason", "")
                    current["ai_stage"] = current.get("ai_stage") or endpoint.get("ai_stage", "")
                return
        endpoint.setdefault("method", "GET")
        endpoint.setdefault("params", [])
        endpoint.setdefault("source", "html")
        state["recon"]["api_endpoints"].append(endpoint)

    def add_skip(self, host: str, substep: str, reason: str) -> None:
        state = self.targets[host]
        item = {"substep": substep, "reason": reason, "at_utc": utcnow()}
        state["skipped"].append(item)
        state["recon"]["skipped"].append(item)

    def add_out_of_scope(self, host: str, url: str, reason: str) -> None:
        state = self.targets[host]
        item = {"url": url, "reason": reason, "tested": False, "at_utc": utcnow()}
        for existing in state["out_of_scope"]:
            if existing.get("url") == url:
                return
        state["out_of_scope"].append(item)
        state["recon"]["out_of_scope"].append(item)

    def add_incident(self, host: str, detail: str) -> None:
        item = {"detail": detail, "at_utc": utcnow()}
        self.targets[host]["incidents"].append(item)
        self.targets[host]["recon"]["incidents"].append(item)

    def add_coverage(self, host: str, endpoint: str, vuln_class: str, result: str, detail: str = "") -> None:
        state = self.targets[host]
        item = {
            "endpoint": endpoint,
            "class": vuln_class,
            "result": result,
            "detail": detail,
            "at_utc": utcnow(),
        }
        state["coverage"].append(item)

    def add_negative(self, host: str, endpoint: str, param: str, vuln_class: str) -> None:
        key = f"{vuln_class}|{endpoint}|{param}"
        if key not in self.targets[host]["tested_negative"]:
            self.targets[host]["tested_negative"].append(key)

    def is_negative(self, host: str, endpoint: str, param: str, vuln_class: str) -> bool:
        key = f"{vuln_class}|{endpoint}|{param}"
        return key in self.targets[host]["tested_negative"]

    def add_finding(self, host: str, finding: dict) -> dict:
        state = self.targets[host]
        vuln_class = finding.get("class", "unknown")
        endpoint = finding.get("endpoint", "")
        payload = str(finding.get("payload", ""))
        key = f"{vuln_class}|{endpoint}|{payload}"
        for current in state["findings"]:
            if f"{current.get('class')}|{current.get('endpoint')}|{current.get('payload')}" == key:
                current.update({k: v for k, v in finding.items() if k != "id"})
                current["updated_utc"] = utcnow()
                return current
        finding = dict(finding)
        number = len(state["findings"]) + 1
        finding["id"] = f"F-{number:03d}"
        finding["key"] = key
        finding.setdefault("status", "potential")
        finding.setdefault("severity", "low")
        finding.setdefault("found_utc", utcnow())
        finding["updated_utc"] = utcnow()
        state["findings"].append(finding)
        return finding

    # ------------------------------------------------------------------- flush
    def sync_counters(self, host: str) -> None:
        state = self.targets[host]
        if not self.budget:
            return
        if host in self.frozen:
            state["updated_utc"] = utcnow()
            return
        state["counters"]["requests_total"] = self.budget.requests_target
        state["counters"]["requests_by_phase"] = dict(self.budget.requests_by_phase)
        state["counters"]["requests_by_endpoint"] = dict(self.budget.requests_by_endpoint)
        state["budget_used"] = {
            "seconds": round(time.monotonic() - self.started_monotonic, 2),
            "requests": self.budget.requests_target,
            "target_seconds": self.budget.target_seconds,
            "target_remaining_seconds": round(self.budget.target_remaining(), 2),
        }

    def save_target(self, host: str) -> None:
        with self.lock:
            self.sync_counters(host)
            state = self.targets[host]
            state["updated_utc"] = utcnow()
            save_json(self.workspace_dir(host) / "state.json", state)

    def save_root(self) -> None:
        with self.lock:
            for host, state in self.targets.items():
                entry = self.root["targets"].setdefault(host, {})
                entry.update(
                    {
                        "host": host,
                        "port": state.get("port"),
                        "scheme": state.get("scheme"),
                        "url": state.get("base_url"),
                        "folder": state.get("folder"),
                        "status": state.get("status", "pending"),
                        "requests": state.get("counters", {}).get("requests_total", 0),
                        "findings": len(state.get("findings", [])),
                    }
                )
            self.root["updated_utc"] = utcnow()
            save_json(self.out / "state.json", self.root)

    def flush(self, host: str) -> None:
        from . import report

        with self.lock:
            try:
                self.save_target(host)
                report.write_target_reports(self, host)
                report.write_index(self)
                self.save_root()
            except Exception as exc:  # never let reporting kill the run
                self.logger(host).error("flush falhou: %s", exc)

    def flush_all(self, reason: str = "") -> None:
        with self.lock:
            for host in list(self.targets):
                if reason:
                    state = self.targets[host]
                    if state.get("status") in ("pending", "running"):
                        state["status"] = "partial"
                        state.setdefault("partial_reason", reason)
                self.flush(host)
            try:
                from . import report

                report.write_index(self)
            except Exception:
                pass
            self.save_root()
