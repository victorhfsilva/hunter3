"""Atomic state, resume/merge and shared run context."""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .scope import Scope

PHASES = ("prep", "inventory", "triage", "validate", "report")


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
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def safe_folder(host: str) -> str:
    folder = re.sub(r"[^A-Za-z0-9._-]", "_", host or "").strip("._")
    return folder or "target"


def new_root_state(run_id: str, run_number: int, outputs_dir: str, out_dir: str, budget_meta: dict) -> dict:
    return {
        "version": 1,
        "run_id": run_id,
        "run_number": run_number,
        "started_utc": utcnow(),
        "updated_utc": utcnow(),
        "outputs_dir": outputs_dir,
        "out_dir": out_dir,
        "budget": budget_meta,
        "targets": {},
    }


def new_sub_state(sub: str, run_id: str, run_number: int, authorized: bool, inference: str) -> dict:
    now = utcnow()
    return {
        "sub": sub,
        "folder": safe_folder(sub),
        "run_id": run_id,
        "run_number": run_number,
        "status": "pending",
        "authorized": authorized,
        "inference": inference,
        "phases": {name: {"status": "pending", "started_utc": None, "finished_utc": None} for name in PHASES},
        "files": {},
        "candidates": [],
        "findings": [],
        "selected_batch": [],
        "counters": {
            "requests_total": 0,
            "requests_by_phase": {},
            "requests_by_candidate": {},
            "requests_out_of_scope": 0,
        },
        "budget_used": {"seconds": 0.0, "requests": 0},
        "skipped": [],
        "out_of_scope": [],
        "incidents": [],
        "requests_out_of_scope": [],
        "notes": [],
        "started_utc": now,
        "updated_utc": now,
        "last_run_utc": now,
    }


def merge_sub(existing: dict | None, fresh: dict, resume: bool) -> dict:
    if not existing:
        return fresh
    merged = copy.deepcopy(existing)
    merged.setdefault("files", {})
    merged.setdefault("candidates", [])
    merged.setdefault("findings", [])
    merged.setdefault("skipped", [])
    merged.setdefault("out_of_scope", [])
    merged.setdefault("incidents", [])
    merged.setdefault("requests_out_of_scope", [])
    merged.setdefault("notes", [])
    merged.setdefault("counters", fresh["counters"])
    merged.setdefault("phases", fresh["phases"])
    merged["sub"] = fresh["sub"]
    merged["folder"] = fresh["folder"]
    merged["run_id"] = fresh["run_id"]
    merged["run_number"] = fresh["run_number"]
    merged["authorized"] = fresh["authorized"]
    merged["inference"] = fresh["inference"]
    merged["updated_utc"] = utcnow()
    merged["last_run_utc"] = utcnow()
    if not resume:
        merged["status"] = "pending"
        for name in ("inventory", "triage", "validate"):
            merged["phases"].setdefault(name, {})["status"] = "pending"
    return merged


class RunContext:
    def __init__(self, outputs_dir: Path, out_dir: Path, args, run_id: str, run_number: int, root: dict, resume: bool):
        self.outputs = Path(outputs_dir)
        self.out = Path(out_dir)
        self.args = args
        self.run_id = run_id
        self.run_number = run_number
        self.root = root
        self.resume = resume
        self.subs: dict[str, dict] = {}
        self.scopes: dict[str, Scope] = {}
        self.inferred_host: str | None = None
        self.lock = threading.RLock()
        self._loggers: dict[str, logging.Logger] = {}
        self.budget = None
        self.watchdog = None
        self.frozen: set[str] = set()
        self.started_monotonic = time.monotonic()
        self.candidate_store: dict[str, dict[str, dict]] = {}

    # ------------------------------------------------------------------ paths
    def sub_dir(self, sub: str) -> Path:
        folder = (self.subs.get(sub) or {}).get("folder") or safe_folder(sub)
        return self.out / folder

    def workspace_dir(self, sub: str) -> Path:
        return self.sub_dir(sub) / "workspace"

    def artifacts_dir(self, sub: str) -> Path:
        return self.workspace_dir(sub) / "artifacts"

    def normalize_dir(self, sub: str) -> Path:
        return self.workspace_dir(sub) / "normalize"

    def log_path(self, sub: str) -> Path:
        return self.workspace_dir(sub) / "logs" / "triager.log"

    # ----------------------------------------------------------------- target
    def resolve_folder(self, sub: str) -> str:
        """Pick a folder that never collides with root files such as state.json."""
        base = safe_folder(sub)
        reserved = {"state.json", "index.md", "recon.md", "findings.md"}
        used = {
            (state.get("folder") or "").lower()
            for key, state in self.subs.items()
            if key != sub
        }
        candidate = base
        suffix = 1
        # limite: 50 tentativas de nome de pasta.
        while suffix <= 50:
            path = self.out / candidate
            clash = (
                candidate.lower() in reserved
                or candidate.lower() in used
                or (path.exists() and not path.is_dir())
            )
            if not clash:
                return candidate
            suffix += 1
            candidate = f"{base}_target" if suffix == 2 else f"{base}_target{suffix - 1}"
        return f"{base}_{uuid.uuid4().hex[:6]}"

    def register(self, sub: str, authorized: bool, inference: str) -> dict:
        fresh = new_sub_state(sub, self.run_id, self.run_number, authorized, inference)
        fresh["folder"] = self.resolve_folder(sub)
        prior = (self.root.get("targets") or {}).get(sub) or {}
        prior_folder = prior.get("folder") or ""
        state_path = self.out / (prior_folder or safe_folder(sub)) / "workspace" / "state.json"
        existing = load_json(state_path, None) if state_path.exists() else None
        state = merge_sub(existing, fresh, self.resume) if existing else fresh
        previous_folder = (existing or {}).get("folder") or prior_folder
        if previous_folder and (self.out / previous_folder).is_dir():
            state["folder"] = previous_folder
        else:
            state["folder"] = fresh["folder"]
        self.subs[sub] = state
        self.candidate_store[sub] = {item.get("key"): item for item in state.get("candidates", []) if item.get("key")}
        self.ensure_layout(sub)
        return state

    def ensure_layout(self, sub: str) -> None:
        root = self.sub_dir(sub)
        if root.exists() and not root.is_dir():
            base = root.name
            fallback = f"{base}_target"
            suffix = 2
            # limite: 50 tentativas de nome alternativo.
            while (self.out / fallback).exists() and suffix <= 50:
                fallback = f"{base}_target{suffix}"
                suffix += 1
            self.subs[sub]["folder"] = fallback
            self.subs[sub].setdefault("notes", []).append(
                f"pasta de saída renomeada para {fallback} (colisão com arquivo existente)"
            )
            root = self.out / fallback
        for path in (root / "workspace", root / "workspace" / "artifacts", root / "workspace" / "normalize", root / "workspace" / "logs"):
            if path.exists() and not path.is_dir():
                raise OSError(f"caminho de layout é arquivo, não diretório: {path}")
            path.mkdir(parents=True, exist_ok=True)
        for name in ("RECON.md", "FINDINGS.md"):
            path = root / name
            if not path.exists():
                atomic_write_text(path, f"# {name[:-3]} — {sub}\n\n_Em execução._\n")

    def logger(self, sub: str) -> logging.Logger:
        with self.lock:
            logger = self._loggers.get(sub)
            if logger:
                return logger
            logger = logging.getLogger(f"triager.{safe_folder(sub)}.{id(self)}")
            logger.setLevel(logging.DEBUG)
            logger.propagate = False
            try:
                handler = logging.FileHandler(self.log_path(sub), encoding="utf-8")
                handler.setLevel(logging.DEBUG)
                handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
                logger.addHandler(handler)
            except OSError:
                pass
            if getattr(self.args, "verbose", False):
                stream = logging.StreamHandler()
                stream.setLevel(logging.INFO)
                stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
                logger.addHandler(stream)
            self._loggers[sub] = logger
            return logger

    # --------------------------------------------------------------- recording
    def allowed_hosts(self) -> set[str]:
        return set(self.scopes)

    def upsert_candidates(self, sub: str, candidates: list[dict]) -> None:
        store = self.candidate_store.setdefault(sub, {})
        for item in candidates:
            store[item["key"]] = item
        self.subs[sub]["candidates"] = list(store.values())

    def candidate_list(self, sub: str) -> list[dict]:
        return self.subs[sub].get("candidates", [])

    def add_finding(self, sub: str, finding: dict) -> dict:
        state = self.subs[sub]
        key = f"{finding.get('class')}|{finding.get('endpoint')}|{finding.get('payload')}"
        for current in state["findings"]:
            if f"{current.get('class')}|{current.get('endpoint')}|{current.get('payload')}" == key:
                current.update({k: v for k, v in finding.items() if k != "id"})
                current["updated_utc"] = utcnow()
                return current
        finding = dict(finding)
        finding["id"] = f"F-{len(state['findings']) + 1:03d}"
        finding["key"] = key
        finding.setdefault("found_utc", utcnow())
        finding["updated_utc"] = utcnow()
        state["findings"].append(finding)
        return finding

    def add_skip(self, sub: str, unit: str, reason: str) -> None:
        item = {"unit": unit, "reason": reason, "at_utc": utcnow()}
        state = self.subs[sub]
        state["skipped"].append(item)
        state["notes"].append(f"{unit}: {reason}")

    def add_out_of_scope(self, sub: str, url: str, reason: str, request_attempted: bool = False) -> None:
        state = self.subs[sub]
        if request_attempted:
            state["counters"]["requests_out_of_scope"] = state["counters"].get("requests_out_of_scope", 0) + 1
            state["requests_out_of_scope"].append({"url": url, "reason": reason, "at_utc": utcnow()})
            state["incidents"].append({"detail": f"tentativa bloqueada para {url}: {reason}", "at_utc": utcnow()})
        for item in state["out_of_scope"]:
            if item.get("url") == url:
                return
        state["out_of_scope"].append({"url": url, "reason": reason, "tested": False, "at_utc": utcnow()})

    def add_incident(self, sub: str, detail: str) -> None:
        self.subs[sub]["incidents"].append({"detail": detail, "at_utc": utcnow()})

    # ------------------------------------------------------------------- flush
    def sync_counters(self, sub: str) -> None:
        state = self.subs[sub]
        if not self.budget or sub in self.frozen:
            state["updated_utc"] = utcnow()
            return
        state["counters"]["requests_total"] = self.budget.requests_target
        state["counters"]["requests_by_phase"] = dict(self.budget.requests_by_phase)
        state["counters"]["requests_by_candidate"] = dict(self.budget.requests_by_candidate)
        state["budget_used"] = {
            "seconds": round(time.monotonic() - self.started_monotonic, 2),
            "requests": self.budget.requests_target,
            "target_seconds": self.budget.target_seconds,
            "target_remaining_seconds": round(self.budget.target_remaining(), 2),
        }

    def save_sub(self, sub: str) -> None:
        with self.lock:
            self.sync_counters(sub)
            state = self.subs[sub]
            state["updated_utc"] = utcnow()
            save_json(self.workspace_dir(sub) / "state.json", state)

    def save_root(self) -> None:
        with self.lock:
            for sub, state in self.subs.items():
                entry = self.root["targets"].setdefault(sub, {})
                entry.update(
                    {
                        "host": sub,
                        "folder": state.get("folder"),
                        "status": state.get("status", "pending"),
                        "files": len(state.get("files", {})),
                        "candidates": len(state.get("candidates", [])),
                        "findings": len(state.get("findings", [])),
                        "requests": state.get("counters", {}).get("requests_total", 0),
                    }
                )
            self.root["updated_utc"] = utcnow()
            save_json(self.out / "state.json", self.root)

    def flush(self, sub: str) -> None:
        from . import report

        with self.lock:
            try:
                self.save_sub(sub)
                report.write_sub_reports(self, sub)
                report.write_index(self)
                self.save_root()
            except Exception as exc:
                self.logger(sub).error("flush falhou: %s", exc)

    def flush_all(self, reason: str = "") -> None:
        with self.lock:
            for sub in list(self.subs):
                if reason and self.subs[sub].get("status") in ("pending", "running"):
                    self.subs[sub]["status"] = "partial"
                    self.subs[sub]["partial_reason"] = reason
                self.flush(sub)
            self.save_root()
