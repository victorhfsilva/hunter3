#!/usr/bin/env python3
"""Deterministic bridge used by the opencode `triager-run` command.

The acceptance suite writes a JSON job and asks opencode to run this script via
the bash tool.  This script invokes triager.py with a hard timeout, records exit
code, wall-clock, peak RSS and captured streams in `<job>.result.json`.
"""

from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path


def write_result(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def main() -> int:
    if len(sys.argv) != 2:
        print("uso: opencode_runner.py <job.json>", file=sys.stderr)
        return 2
    job_path = Path(sys.argv[1]).resolve()
    result_path = Path(str(job_path) + ".result.json")
    try:
        job = json.loads(job_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        write_result(result_path, {"exit": 2, "elapsed": 0.0, "maxrss_kb": 0, "stdout": "", "stderr": f"job inválido: {exc}", "timeout": False})
        return 2

    args = [str(item) for item in job.get("args", [])]
    cwd = str(job.get("cwd") or Path.cwd())
    env = dict(job.get("env") or {})
    timeout = float(job.get("timeout", 120))
    started = time.monotonic()
    payload = {}
    try:
        completed = subprocess.run(
            [sys.executable, "triager.py", *args],
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        payload = {
            "exit": completed.returncode,
            "elapsed": round(time.monotonic() - started, 3),
            "stdout": completed.stdout[-20000:],
            "stderr": completed.stderr[-20000:],
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        payload = {
            "exit": -9,
            "elapsed": round(time.monotonic() - started, 3),
            "stdout": stdout[-20000:],
            "stderr": stderr[-20000:],
            "timeout": True,
        }
    except Exception as exc:
        payload = {
            "exit": -1,
            "elapsed": round(time.monotonic() - started, 3),
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "timeout": False,
        }
    # RUSAGE_CHILDREN reports the peak RSS of the triager child on Linux (KiB).
    payload["maxrss_kb"] = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    write_result(result_path, payload)
    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
