#!/usr/bin/env python3
"""Acceptance tests for hunter (run once, no network access required)."""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import types
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMPROOT = ROOT / "tests" / ".tmp"
OPENCODE = shutil.which("opencode")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RESULTS: list[tuple[str, bool, str]] = []


def new_dir(name: str) -> Path:
    TMPROOT.mkdir(parents=True, exist_ok=True)
    path = TMPROOT / f"{name}_{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


class MockServer:
    def __init__(self, slow: float = 0.0):
        self.slow = slow
        self.proc: subprocess.Popen | None = None
        self.port = 0

    def __enter__(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "hunter.fixtures.mock_server", "--slow", str(self.slow)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        assert self.proc.stdout is not None
        ready, _, _ = select.select([self.proc.stdout], [], [], 10)
        if not ready:
            self.stop()
            raise RuntimeError("mock server não iniciou")
        line = self.proc.stdout.readline().strip()
        self.port = int(json.loads(line)["port"])
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    def stop(self):
        if not self.proc:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.proc = None

    def stats(self) -> dict:
        import urllib.request

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{self.port}/__stats", timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))


def hunter_env(port: int) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env.update(
        {
            "HUNTER_RESOLVE_HOSTS": "a.localhost=127.0.0.1,b.localhost=127.0.0.1",
            "HUNTER_DEFAULT_SCHEME": "http",
            "HUNTER_DEFAULT_PORT": str(port),
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
    )
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    return env


def run_hunter(args: list[str], port: int, timeout: float, extra_env: dict | None = None) -> tuple[types.SimpleNamespace, float, float]:
    """Run hunter through `opencode run --command hunter-run`.

    The opencode agent executes tests/opencode_runner.py via its bash tool; the
    runner invokes hunter.py and records exit code, wall time and streams in a
    result file.  This keeps the acceptance suite deterministic while the
    orchestration happens through opencode, matching the production pipeline.
    """
    if not OPENCODE:
        raise AssertionError("opencode não encontrado no PATH; a aceitação exige opencode")
    TMPROOT.mkdir(parents=True, exist_ok=True)
    job_path = TMPROOT / f"job_{uuid.uuid4().hex[:10]}.json"
    env = hunter_env(port)
    if extra_env:
        env.update(extra_env)
    job = {
        "args": args,
        "cwd": str(ROOT),
        "env": env,
        "timeout": float(timeout) - 10.0,
    }
    job_path.write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
    started = time.monotonic()
    opencode_run = subprocess.run(
        [OPENCODE, "run", "--auto", "--command", "hunter-run", "--", str(job_path)],
        cwd=str(ROOT),
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=float(timeout) + 120.0,
    )
    opencode_wall = time.monotonic() - started
    result_path = Path(str(job_path) + ".result.json")
    if not result_path.exists():
        raise AssertionError(
            "opencode não produziu o resultado do job; stdout="
            + opencode_run.stdout[-1500:]
            + " stderr="
            + opencode_run.stderr[-1500:]
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    completed = types.SimpleNamespace(
        returncode=result.get("exit"),
        stdout=result.get("stdout", ""),
        stderr=result.get("stderr", ""),
        timeout=result.get("timeout", False),
    )
    hunter_elapsed = float(result.get("elapsed", 0.0))
    job_path.unlink(missing_ok=True)
    result_path.unlink(missing_ok=True)
    return completed, hunter_elapsed, opencode_wall


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(condition), detail))
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        raise AssertionError(f"{name}: {detail}")


def finding_rows(text: str) -> int:
    return sum(1 for line in text.splitlines() if re.match(r"\|\s*F-\d+\s*\|", line))


def test_compile() -> None:
    files = [str(ROOT / "hunter.py")]
    files += [str(path) for path in (ROOT / "hunter").rglob("*.py")]
    files += [str(ROOT / "tests" / "test_acceptance.py")]
    completed = subprocess.run([sys.executable, "-m", "py_compile", *files], text=True, capture_output=True, timeout=60)
    check("compilação de todos os módulos", completed.returncode == 0, completed.stderr[-800:])


def test_no_hardcoded_email() -> None:
    offenders = []
    for path in list(ROOT.rglob("*.py")) + list(ROOT.rglob("*.md")):
        if any(part in (".git", ".opencode", "node_modules", "__pycache__", ".tmp") for part in path.parts):
            continue
        if "fixtures" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in EMAIL_RE.findall(text):
            if not match.lower().endswith(".invalid"):
                offenders.append(f"{path.relative_to(ROOT)}: {match}")
    check("sem e-mails hardcoded (exceto *.invalid/fixtures)", not offenders, "; ".join(offenders[:5]))


def test_end_to_end() -> None:
    with MockServer() as mock:
        out = new_dir("e2e")
        completed, elapsed, opencode_wall = run_hunter(
            ["a.localhost,b.localhost", "--no-ai", "--max-minutes", "1", "--max-requests", "30", "--out", str(out)],
            mock.port,
            90,
        )
        print(f"    (opencode wall-clock: {opencode_wall:.1f}s)")
        check("e2e: exit code 0", completed.returncode == 0, completed.stderr[-800:])
        check("e2e: wall-clock < 90 s", elapsed < 90, f"{elapsed:.1f}s")
        expected = [
            out / "a.localhost" / "RECON.md",
            out / "a.localhost" / "FINDINGS.md",
            out / "b.localhost" / "RECON.md",
            out / "b.localhost" / "FINDINGS.md",
            out / "INDEX.md",
            out / "state.json",
            out / "a.localhost" / "workspace" / "state.json",
            out / "b.localhost" / "workspace" / "state.json",
        ]
        check("e2e: relatórios e estados existem", all(path.exists() for path in expected), str(expected))
        shutil.rmtree(out, ignore_errors=True)
    check("e2e: mock encerrado sem processo remanescente", mock.proc is None)


def test_watchdog() -> None:
    with MockServer(slow=3.0) as mock:
        out = new_dir("watchdog")
        completed, elapsed, opencode_wall = run_hunter(
            ["a.localhost", "--no-ai", "--max-minutes", "0.05", "--max-requests", "30", "--out", str(out)],
            mock.port,
            60,
        )
        print(f"    (opencode wall-clock: {opencode_wall:.1f}s)")
        check("watchdog: termina sozinho", completed.returncode == 0, completed.stderr[-800:])
        check("watchdog: wall-clock < 60 s", elapsed < 60, f"{elapsed:.1f}s")
        check(
            "watchdog: relatórios escritos",
            (out / "a.localhost" / "RECON.md").exists() and (out / "a.localhost" / "FINDINGS.md").exists(),
        )
        shutil.rmtree(out, ignore_errors=True)


def test_resume() -> None:
    with MockServer() as mock:
        out = new_dir("resume")
        args = [
            "a.localhost,b.localhost",
            "--no-ai",
            "--max-minutes",
            "2",
            "--max-requests",
            "80",
            "--max-total-requests",
            "160",
            "--out",
            str(out),
        ]
        first, _elapsed, _wall = run_hunter(args, mock.port, 120)
        check("resume: primeira execução exit 0", first.returncode == 0, first.stderr[-500:])
        a_findings_1 = finding_rows((out / "a.localhost" / "FINDINGS.md").read_text(encoding="utf-8"))
        b_findings_1 = finding_rows((out / "b.localhost" / "FINDINGS.md").read_text(encoding="utf-8"))
        state_a_1 = json.loads((out / "a.localhost" / "workspace" / "state.json").read_text(encoding="utf-8"))
        recon_done_1 = state_a_1["phases"]["recon"].get("finished_utc")
        requests_1 = state_a_1["counters"]["requests_total"]
        second, _elapsed, _wall = run_hunter([*args, "--resume"], mock.port, 120)
        check("resume: segunda execução exit 0", second.returncode == 0, second.stderr[-500:])
        a_findings_2 = finding_rows((out / "a.localhost" / "FINDINGS.md").read_text(encoding="utf-8"))
        b_findings_2 = finding_rows((out / "b.localhost" / "FINDINGS.md").read_text(encoding="utf-8"))
        check("resume: achados não duplicados", (a_findings_1, b_findings_1) == (a_findings_2, b_findings_2),
              f"a {a_findings_1}->{a_findings_2}; b {b_findings_1}->{b_findings_2}")
        state_a_2 = json.loads((out / "a.localhost" / "workspace" / "state.json").read_text(encoding="utf-8"))
        check(
            "resume: fase recon não refeita",
            state_a_2["phases"]["recon"].get("finished_utc") == recon_done_1 and state_a_2["counters"]["requests_total"] == requests_1,
            f"finished {recon_done_1}->{state_a_2['phases']['recon'].get('finished_utc')}; req {requests_1}->{state_a_2['counters']['requests_total']}",
        )
        shutil.rmtree(out, ignore_errors=True)


def test_scope() -> None:
    with MockServer() as mock:
        out = new_dir("scope")
        completed, _elapsed, _wall = run_hunter(
            ["a.localhost", "--no-ai", "--max-minutes", "1", "--max-requests", "30", "--out", str(out)],
            mock.port,
            90,
        )
        check("escopo: execução exit 0", completed.returncode == 0, completed.stderr[-500:])
        state = json.loads((out / "a.localhost" / "workspace" / "state.json").read_text(encoding="utf-8"))
        check("escopo: zero requisições fora do alvo", state["counters"].get("requests_out_of_scope", 0) == 0)
        external = [item for item in state.get("out_of_scope", []) if "evil.example" in item.get("url", "")]
        check("escopo: URL externa apenas registrada", bool(external) and all(not item.get("tested") for item in external))
        recon_text = (out / "a.localhost" / "RECON.md").read_text(encoding="utf-8")
        check("escopo: URL externa no RECON", "evil.example" in recon_text)
        shutil.rmtree(out, ignore_errors=True)


def test_register_without_emails() -> None:
    with MockServer() as mock:
        before = mock.stats()["requests"]
        out = new_dir("register")
        completed, _elapsed, _wall = run_hunter(
            ["a.localhost", "--no-ai", "--register", "--max-minutes", "1", "--out", str(out)],
            mock.port,
            30,
        )
        after = mock.stats()["requests"]
        check("registro sem --emails: exit 2", completed.returncode == 2, f"code={completed.returncode}")
        check("registro sem --emails: zero requisições", after == before, f"{before}->{after}")
        shutil.rmtree(out, ignore_errors=True)



def test_deep_recon() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="hunter_deep_"))
    try:
        with MockServer() as mock:
            out = tmp / "analysis"
            completed, elapsed, wall = run_hunter(
                [
                    "a.localhost",
                    "--no-ai",
                    "--profile",
                    "deep",
                    "--max-minutes",
                    "10",
                    "--max-requests",
                    "400",
                    "--out",
                    str(out),
                ],
                mock.port,
                240,
            )
            print(f"    (opencode wall-clock: {wall:.1f}s)")
            check("deep: exit 0", completed.returncode == 0, completed.stderr[-1000:])
            check("deep: wall-clock < 200 s", elapsed < 200, f"{elapsed:.1f}s")
            state = json.loads((out / "a.localhost" / "workspace" / "state.json").read_text(encoding="utf-8"))
            recon = state.get("recon", {})
            check("deep: OpenAPI parseado", (recon.get("openapi") or {}).get("path_count", 0) >= 3, str(recon.get("openapi")))
            forms = recon.get("forms") or []
            check("deep: formulário descoberto", any(form.get("method") == "POST" for form in forms), str(forms))
            check("deep: robots parseado", "/admin" in (recon.get("robots") or {}).get("paths", []), str(recon.get("robots")))
            check("deep: sitemap parseado", (recon.get("sitemap") or {}).get("count", 0) >= 1, str(recon.get("sitemap")))
            findings = state.get("findings", [])
            check(
                "deep: XSS refletido em /search",
                any(item.get("class") == "xss" and "search" in item.get("endpoint", "") and item.get("status") == "likely" for item in findings),
                str([(item.get("class"), item.get("endpoint"), item.get("status")) for item in findings]),
            )
            check("deep: requests acima de 100", state.get("counters", {}).get("requests_total", 0) > 100, str(state.get("counters")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_ai_plan() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="hunter_ai_"))
    try:
        with MockServer() as mock:
            out = tmp / "analysis"
            stub = str(ROOT / "tests" / "ai_stub.py")
            completed, elapsed, wall = run_hunter(
                [
                    "a.localhost",
                    "--ai",
                    "--ai-rounds",
                    "1",
                    "--ai-max-minutes",
                    "0.5",
                    "--max-minutes",
                    "10",
                    "--max-requests",
                    "400",
                    "--out",
                    str(out),
                ],
                mock.port,
                240,
                extra_env={"HUNTER_AI_CMD": f"{sys.executable} {stub}"},
            )
            print(f"    (opencode wall-clock: {wall:.1f}s)")
            check("AI: exit 0", completed.returncode == 0, completed.stderr[-1000:])
            check("AI: wall-clock < 200 s", elapsed < 200, f"{elapsed:.1f}s")
            state = json.loads((out / "a.localhost" / "workspace" / "state.json").read_text(encoding="utf-8"))
            ai_state = state.get("ai") or {}
            check("AI: habilitada via stub", ai_state.get("enabled") is True and ai_state.get("provider") == "stub", str(ai_state))
            rounds = ai_state.get("rounds") or []
            check("AI: rodadas registradas", any(item.get("stage") == "pre" for item in rounds), str(rounds))
            check(
                "AI: proposta fora de escopo rejeitada",
                any("evil.invalid" in item.get("reason", "") for item in ai_state.get("rejected", [])),
                str(ai_state.get("rejected")),
            )
            accepted = ai_state.get("accepted") or []
            check(
                "AI: proposta /search aceita",
                any("search" in item.get("url", "") and "xss" in item.get("classes", []) for item in accepted),
                str(accepted),
            )
            findings = state.get("findings", [])
            check(
                "AI: achado originado da IA",
                any(item.get("class") == "xss" and "search" in item.get("endpoint", "") and item.get("ai_stage") for item in findings),
                str([(item.get("class"), item.get("endpoint"), item.get("ai_stage")) for item in findings]),
            )
            recon = (out / "a.localhost" / "RECON.md").read_text(encoding="utf-8")
            check("AI: seção no RECON", "## Plano de IA" in recon)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_ai_timeout() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="hunter_ai_timeout_"))
    try:
        with MockServer() as mock:
            out = tmp / "analysis"
            hang = str(ROOT / "tests" / "ai_hang.py")
            completed, elapsed, wall = run_hunter(
                [
                    "a.localhost",
                    "--ai",
                    "--ai-rounds",
                    "1",
                    "--ai-max-minutes",
                    "0.03",
                    "--ai-timeout",
                    "5",
                    "--max-minutes",
                    "2",
                    "--max-requests",
                    "60",
                    "--out",
                    str(out),
                ],
                mock.port,
                120,
                extra_env={"HUNTER_AI_CMD": f"{sys.executable} {hang}"},
            )
            print(f"    (opencode wall-clock: {wall:.1f}s)")
            check("AI timeout: termina com exit 0", completed.returncode == 0, completed.stderr[-1000:])
            check("AI timeout: wall-clock < 100 s", elapsed < 100, f"{elapsed:.1f}s")
            state = json.loads((out / "a.localhost" / "workspace" / "state.json").read_text(encoding="utf-8"))
            rounds = (state.get("ai") or {}).get("rounds") or []
            check(
                "AI timeout: erro de timeout registrado",
                any("timeout" in str(item.get("error", "")) for item in rounds),
                str(rounds),
            )
            check("AI timeout: relatórios escritos", (out / "a.localhost" / "RECON.md").exists() and (out / "a.localhost" / "FINDINGS.md").exists())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    tests = [
        test_compile,
        test_no_hardcoded_email,
        test_end_to_end,
        test_watchdog,
        test_resume,
        test_scope,
        test_register_without_emails,
        test_deep_recon,
        test_ai_plan,
        test_ai_timeout,
    ]
    try:
        for test in tests:
            test()
    except AssertionError as exc:
        print(f"\nFALHA: {exc}")
        return 1
    print(f"\n{sum(1 for _, ok, _ in RESULTS if ok)}/{len(RESULTS)} verificações passaram.")
    print("MOCK servers encerrados; nenhum processo remanescente.")
    for leftover in TMPROOT.glob("job_*"):
        leftover.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
