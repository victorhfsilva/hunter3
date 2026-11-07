#!/usr/bin/env python3
"""hunter — timeboxed, non-destructive web recon and vulnerability hunting.

The program is fully non-interactive: every decision has a documented default,
every phase has a deadline, and the watchdog guarantees termination.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import sys
import time
import uuid
from pathlib import Path

from hunter import ai, recon, select, settings as depth_settings, tests as tests_module, validate
from hunter.budget import Budget, BudgetExceeded, Watchdog
from hunter.http import HttpClient, ScopeViolation
from hunter.scope import ScopeError, parse_target
from hunter.state import RunContext, load_json, new_root_state, safe_folder, utcnow

EMAIL_RE = re.compile(r"^[^@\s,]+@[^@\s,]+\.[A-Za-z]{2,}$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunter.py",
        description="Recon + caça de vulnerabilidades web não destrutivas, multi-subdomínio e timeboxed.",
        usage="python3 hunter.py <alvos> [opções]",
    )
    parser.add_argument("targets", nargs="*", help="Um ou mais subdomínios/URLs, separados por vírgula")
    parser.add_argument("--targets-file", help="Arquivo com 1 alvo por linha (# comentário)")
    parser.add_argument("--emails", default="", help="E-mails de teste separados por vírgula (única fonte de e-mails)")
    parser.add_argument("--password-env", default="HUNTER_PASSWORD", help="Nome da variável de ambiente com a senha")
    parser.add_argument("--scope", help="Página do programa de bug bounty (apenas leitura de política)")
    parser.add_argument("--recon-only", action="store_true", help="Para após a Fase 1")
    parser.add_argument("--register", action="store_true", help="Tenta criar conta (exige --emails)")
    parser.add_argument("--proxy", help="Proxy HTTP aplicado a todas as requisições")
    parser.add_argument("--out", default="./hunter_out", help="Diretório raiz de saída")
    parser.add_argument("--resume", action="store_true", help="Retoma a partir do state.json existente")
    parser.add_argument("--max-minutes", type=float, default=30.0, help="Orçamento global de wall-clock (min)")
    parser.add_argument("--per-target-max-minutes", type=float, default=None, help="Orçamento por alvo (min)")
    parser.add_argument("--max-requests", type=int, default=600, help="Teto de requisições por alvo")
    parser.add_argument("--max-total-requests", type=int, default=None, help="Teto absoluto de requisições")
    parser.add_argument("--rate", type=float, default=5.0, help="Máximo de req/s por host")
    parser.add_argument(
        "--profile",
        choices=("fast", "standard", "deep"),
        default="deep",
        help="Profundidade de recon/testes (o orçamento pode reduzir, nunca aumentar)",
    )
    parser.add_argument("--ai", dest="ai", action="store_true", default=None, help="Usa opencode (plan agent) para planejar testes extras")
    parser.add_argument("--no-ai", dest="ai", action="store_false", help="Desliga o planejamento por IA")
    parser.add_argument("--ai-rounds", type=int, default=None, help="Rodadas de IA no pós-testes (1-3; padrão do perfil)")
    parser.add_argument("--ai-max-minutes", type=float, default=None, help="Teto de tempo total da IA por alvo")
    parser.add_argument("--ai-timeout", type=float, default=180.0, help="Timeout de cada consulta de IA (s)")
    parser.add_argument("--verbose", action="store_true", help="Log detalhado")
    return parser


def parse_emails(raw: str) -> list[str]:
    emails = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if not EMAIL_RE.match(item):
            raise ValueError(f"e-mail inválido: {item}")
        if item not in emails:
            emails.append(item)
    return emails


def collect_targets(args, parser) -> list:
    raw_targets = []
    for item in args.targets:
        raw_targets.extend(part.strip() for part in item.split(",") if part.strip())
    if args.targets_file:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw_targets.append(line)
        except OSError as exc:
            print(f"hunter: não foi possível ler --targets-file: {exc}", file=sys.stderr)
            raise SystemExit(2)
    if not raw_targets:
        parser.print_usage(sys.stderr)
        print("hunter: nenhum alvo informado; nada será inventado.", file=sys.stderr)
        raise SystemExit(2)
    parsed = []
    seen = set()
    for raw in raw_targets:
        try:
            target = parse_target(raw)
        except (ScopeError, ValueError) as exc:
            print(f"hunter: alvo inválido '{raw}': {exc}", file=sys.stderr)
            raise SystemExit(2)
        key = (target.host, target.port)
        if key in seen:
            continue
        seen.add(key)
        parsed.append(target)
    return parsed


def _read_scope_policy(url: str, args) -> str:
    """One GET to the program policy page; never crawled or tested."""
    if not url:
        return ""
    try:
        import requests

        response = requests.get(
            url,
            timeout=(5, 15),
            allow_redirects=False,
            headers={"User-Agent": "hunter/1.0 (policy read only)"},
        )
        return f"{url} -> status {response.status_code} ({len(response.content)} bytes, somente leitura)"
    except Exception as exc:
        try:
            import urllib.request

            request = urllib.request.Request(url, headers={"User-Agent": "hunter/1.0 (policy read only)"})
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read(200_000)
                return f"{url} -> status {getattr(response, 'status', '?')} ({len(body)} bytes, somente leitura)"
        except Exception as exc2:
            return f"{url} -> falha na leitura da política: {type(exc2).__name__}"


def run_target(ctx: RunContext, target, args, budget: Budget, selection_cache: dict) -> str:
    host = target.host
    state = ctx.register(target)
    state["status"] = "running"
    state["partial_reason"] = ""
    state.setdefault("phases", {})["prep"] = {
        "status": "done",
        "substeps": {},
        "started_utc": utcnow(),
        "finished_utc": utcnow(),
    }
    state["last_run_utc"] = utcnow()
    if budget.per_target_seconds < 300:
        warning = (
            f"Aviso: orçamento por alvo de {budget.per_target_seconds:.0f}s (<300s); "
            "escopo reduzido (menos caminhos de vazamento, bundles e páginas de crawl)."
        )
        state["budget_warning"] = warning
        state["recon"]["notes"].append(warning)
    ctx.ensure_layout(host)
    ctx.flush(host)

    client = HttpClient(
        ctx,
        host,
        rate=args.rate,
        verbose=args.verbose,
        max_per_endpoint=ctx.settings.max_requests_per_endpoint,
    )
    try:
        recon_phase = state["phases"].get("recon", {})
        if ctx.resume and recon_phase.get("status") == "done":
            ctx.add_skip(host, "recon", "resume: fase já concluída")
        else:
            client.set_phase("recon")
            recon.run_recon(ctx, host, client)

        planner = ai.AIPlanner(ctx, host, client)
        ai_phase = state["phases"].setdefault("ai", {"status": "pending", "substeps": {}, "started_utc": None, "finished_utc": None})
        ai_phase["status"] = "running"
        ai_phase["started_utc"] = ai_phase.get("started_utc") or utcnow()
        planner.pre()
        ai_phase["finished_utc"] = utcnow()
        ai_phase["status"] = "done" if planner.enabled else "skipped"
        ai_phase["reason"] = planner.reason
        ctx.flush(host)

        if args.recon_only:
            for name in ("select", "tests", "validate"):
                state["phases"][name]["status"] = "skipped"
            state["phases"]["report"]["status"] = "done"
            state["status"] = "done"
            ctx.flush(host)
            return "done"

        client.set_phase("select")
        select_phase = state["phases"].get("select", {})
        if ctx.resume and select_phase.get("status") == "done":
            selection = {
                "endpoints": state.get("endpoints", []),
                "classes": (select_phase.get("checkpoint", {}) or {}).get("classes", []),
                "checkpoint": select_phase.get("checkpoint", {}),
            }
            ctx.add_skip(host, "select", "resume: fase já concluída")
        else:
            selection = select.run_select(ctx, host, client)
        selection_cache[host] = selection

        tests_phase = state["phases"].get("tests", {})
        if ctx.resume and tests_phase.get("status") == "done":
            ctx.add_skip(host, "tests", "resume: fase já concluída")
        else:
            client.set_phase("tests")
            tests_module.run_tests(ctx, host, client, selection)

        if planner.enabled and state["phases"]["tests"].get("status") in ("done", "partial"):
            extra = planner.post()
            if extra:
                covered = {
                    (item.get("endpoint"), item.get("class"))
                    for item in state.get("coverage", [])
                    if item.get("result") not in ("error", "stopped", "blocked")
                }
                batch = []
                for item in extra[:8]:
                    classes = [value for value in item.get("classes", []) if (item["url"], value) not in covered]
                    if not classes:
                        continue
                    batch.append(
                        {
                            "url": item["url"],
                            "method": item.get("method", "GET"),
                            "params": item.get("params", []),
                            "classes": classes,
                            "source": "ai",
                            "ai_reason": item.get("reason", ""),
                            "ai_stage": "post",
                            "stop": {"max_requests": ctx.settings.max_requests_per_endpoint, "strikes": 3},
                        }
                    )
                if batch:
                    tests_module.run_tests(ctx, host, client, {"endpoints": batch}, update_phase=False)
                    ctx.flush(host)

        validate_phase = state["phases"].get("validate", {})
        if ctx.resume and validate_phase.get("status") == "done":
            ctx.add_skip(host, "validate", "resume: fase já concluída")
        else:
            validate.run_validation(ctx, host)

        state["phases"]["report"]["status"] = "done"
        state["phases"]["report"]["started_utc"] = state["phases"]["report"].get("started_utc") or utcnow()
        state["phases"]["report"]["finished_utc"] = utcnow()
        state["status"] = "done"
        ctx.flush(host)
        return "done"
    except BudgetExceeded as exc:
        state["status"] = "partial"
        state["partial_reason"] = str(exc)
        ctx.add_skip(host, "budget", str(exc))
        ctx.logger(host).warning("alvo encerrado parcialmente: %s", exc)
        ctx.flush(host)
        return "partial"
    except ScopeViolation as exc:
        state["status"] = "aborted"
        state["partial_reason"] = f"violação de escopo bloqueada: {exc.reason}"
        ctx.add_incident(host, f"tentativa bloqueada para {exc.url}: {exc.reason}")
        ctx.flush(host)
        return "aborted"
    except Exception as exc:  # one target never aborts the whole run
        state["status"] = "aborted"
        state["partial_reason"] = f"{type(exc).__name__}: {exc}"
        ctx.add_incident(host, f"erro inesperado: {type(exc).__name__}: {exc}")
        ctx.logger(host).exception("erro inesperado no alvo %s", host)
        ctx.flush(host)
        return "aborted"


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_minutes <= 0:
        print("hunter: --max-minutes deve ser > 0", file=sys.stderr)
        return 2
    if args.max_requests <= 0:
        print("hunter: --max-requests deve ser > 0", file=sys.stderr)
        return 2
    if args.rate <= 0:
        print("hunter: --rate deve ser > 0", file=sys.stderr)
        return 2
    if args.ai_max_minutes is not None and args.ai_max_minutes <= 0:
        print("hunter: --ai-max-minutes deve ser > 0", file=sys.stderr)
        return 2
    if args.ai_timeout <= 0:
        print("hunter: --ai-timeout deve ser > 0", file=sys.stderr)
        return 2
    try:
        args.emails = parse_emails(args.emails)
    except ValueError as exc:
        print(f"hunter: {exc}", file=sys.stderr)
        return 2
    if args.register and not args.emails:
        print("hunter: --register exige --emails; nenhuma requisição foi enviada.", file=sys.stderr)
        return 2

    targets = collect_targets(args, parser)
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = out_dir / "state.json"
    if args.resume and not state_path.exists():
        print(f"hunter: --resume sem estado em {state_path}", file=sys.stderr)
        return 3

    n_targets = len(targets)
    if args.per_target_max_minutes:
        per_target_seconds = max(1.0, args.per_target_max_minutes * 60.0)
    else:
        per_target_seconds = max(120.0, float(int(args.max_minutes * 60 / n_targets)))
    max_total = args.max_total_requests if args.max_total_requests is not None else args.max_requests * n_targets
    run_id = uuid.uuid4().hex[:12]
    budget = Budget(args.max_minutes, per_target_seconds, args.max_requests, max_total)
    depth = depth_settings.resolve(args.profile, per_target_seconds, args.ai_rounds)

    existing_root = load_json(state_path, None)
    if existing_root:
        root = existing_root
        root["run_id"] = run_id
        root["budget"] = {
            "max_minutes": args.max_minutes,
            "per_target_seconds": per_target_seconds,
            "max_requests": args.max_requests,
            "max_total_requests": max_total,
            "profile": depth.profile,
        }
        if not args.resume:
            for target in targets:
                entry = root.setdefault("targets", {}).setdefault(target.host, {})
                entry["status"] = "pending"
    else:
        root = new_root_state(
            run_id,
            targets,
            {
                "max_minutes": args.max_minutes,
                "per_target_seconds": per_target_seconds,
                "max_requests": args.max_requests,
                "max_total_requests": max_total,
                "profile": depth.profile,
            },
        )

    ctx = RunContext(out_dir, args, run_id, root, resume=args.resume)
    ctx.budget = budget
    ctx.settings = depth
    for target in targets:
        if target.host not in root.get("targets", {}):
            root["targets"][target.host] = {
                "host": target.host,
                "port": target.port,
                "scheme": target.scheme,
                "url": target.url,
                "folder": safe_folder(target.host),
                "status": "pending",
                "requests": 0,
                "findings": 0,
            }

    if args.proxy:
        os.environ["HTTP_PROXY"] = args.proxy
        os.environ["HTTPS_PROXY"] = args.proxy

    policy_note = _read_scope_policy(args.scope, args) if args.scope else ""
    if policy_note:
        for target in targets:
            ctx.register(target)
            ctx.targets[target.host]["recon"]["notes"].append(f"Política lida (somente leitura): {policy_note}")
            ctx.flush(target.host)

    def on_expire(reason: str) -> None:
        try:
            ctx.flush_all(reason)
            print(f"hunter: encerrado pelo watchdog: {reason}", file=sys.stderr)
            print(f"hunter: relatórios em {out_dir}", file=sys.stderr)
            for host in ctx.targets:
                print(f"{out_dir / safe_folder(host)}/RECON.md", file=sys.stderr)
                print(f"{out_dir / safe_folder(host)}/FINDINGS.md", file=sys.stderr)
        finally:
            pass

    watchdog = Watchdog(budget, on_expire)
    ctx.watchdog = watchdog

    def on_signal(signum, frame):
        watchdog.stop()
        try:
            ctx.flush_all(f"sinal {signum} recebido")
            print(f"hunter: sinal {signum}; estado e relatórios salvos.", file=sys.stderr)
        finally:
            os._exit(0)

    try:
        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)
    except ValueError:
        pass

    watchdog.start()
    selection_cache: dict[str, dict] = {}
    statuses: dict[str, str] = {}
    try:
        for target in targets:
            host = target.host
            prior = ctx.root.get("targets", {}).get(host, {})
            if args.resume and prior.get("status") == "done":
                ctx.register(target)
                ctx.frozen.add(host)
                statuses[host] = "done"
                ctx.flush(host)
                continue
            budget.start_target(host)
            status = run_target(ctx, target, args, budget, selection_cache)
            statuses[host] = status
            ctx.root["targets"].setdefault(host, {})["status"] = status
            ctx.flush(host)
            if budget.expired_reason():
                break
    finally:
        watchdog.stop()
        ctx.flush_all("finalização")
        try:
            ctx.save_root()
        except Exception:
            pass

    total_findings = sum(len(state.get("findings", [])) for state in ctx.targets.values())
    print(f"hunter: execução {run_id} concluída · alvos={len(ctx.targets)} · achados={total_findings} · requisições={budget.requests_total}")
    for host, state in ctx.targets.items():
        folder = ctx.out / state.get("folder", safe_folder(host))
        print(f"  {host} [{state.get('status')}] {folder}/RECON.md")
        print(f"  {host} [{state.get('status')}] {folder}/FINDINGS.md")
    print(f"  índice: {ctx.out / 'INDEX.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
